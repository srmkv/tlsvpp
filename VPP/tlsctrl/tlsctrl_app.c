/* SPDX-License-Identifier: Apache-2.0 */

#include <tlsctrl/tlsctrl.h>
#include <tlsctrl/tlsctrl_vpn.h>

#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <vppinfra/unix.h>

static inline u64
tlsctrl_now_unix_ns (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  return ((u64) ts.tv_sec * 1000000000ULL) + (u64) ts.tv_nsec;
}

static inline tlsctrl_conn_t *
tlsctrl_conn_get (clib_thread_index_t thread_index, u32 conn_index)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_conn_t *pool;

  if (thread_index >= vec_len (tm->conn_pool_by_thread))
    return 0;

  pool = tm->conn_pool_by_thread[thread_index];
  if (!pool || pool_is_free_index (pool, conn_index))
    return 0;

  return pool_elt_at_index (pool, conn_index);
}

static inline tlsctrl_conn_t *
tlsctrl_conn_alloc (clib_thread_index_t thread_index)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_conn_t *conn;

  vec_validate (tm->conn_pool_by_thread, thread_index);
  pool_get_zero (tm->conn_pool_by_thread[thread_index], conn);
  conn->session_index = conn - tm->conn_pool_by_thread[thread_index];
  return conn;
}

static inline void
tlsctrl_conn_free (clib_thread_index_t thread_index, u32 conn_index)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_conn_t *conn;

  conn = tlsctrl_conn_get (thread_index, conn_index);
  if (!conn)
    return;

  vec_free (conn->request_data);
  vec_free (conn->response_data);
  pool_put (tm->conn_pool_by_thread[thread_index], conn);
}


static void
tlsctrl_vpn_detach_by_session_handle (u64 session_handle)
{
  tlsctrl_vpn_stream_session_t *s;
  u64 tunnel_id = 0;

  clib_spinlock_lock_if_init (&tlsctrl_vpn_main.lock);
  vec_foreach (s, tlsctrl_vpn_main.stream_sessions)
    {
      if (s->session_handle == session_handle)
        {
          tunnel_id = s->tunnel_id;
          break;
        }
    }
  clib_spinlock_unlock_if_init (&tlsctrl_vpn_main.lock);

  if (tunnel_id)
    tlsctrl_vpn_stream_detach (tunnel_id);
}

static void
tlsctrl_disconnect_session (session_t *s, tlsctrl_conn_t *conn)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  if (conn && conn->close_requested)
    return;

  if (conn)
    conn->close_requested = 1;

  a->handle = session_handle (s);
  a->app_index = tm->app_index;
  vnet_disconnect_session (a);
}

static u8 *
tlsctrl_dup_c_string (const u8 *src, u32 len)
{
  u8 *dst = 0;

  if (!src)
    return 0;

  vec_validate (dst, len);
  if (len)
    clib_memcpy_fast (dst, src, len);
  dst[len] = 0;
  return dst;
}

static u8 *
tlsctrl_dup_string0 (u8 *src)
{
  u32 len;

  if (!src)
    return 0;
  len = strlen ((char *) src);
  return tlsctrl_dup_c_string (src, len);
}

static u8 *
tlsctrl_get_peer_cert_serial (session_t *s)
{
  transport_endpt_attr_t attr = {
    .type = TRANSPORT_ENDPT_ATTR_TLS_PEER_CERT,
  };
  X509 *cert;
  ASN1_INTEGER *serial;
  BIGNUM *bn = 0;
  char *hex = 0;
  u8 *out = 0;
  u8 *p;

  if (!s)
    return 0;

  if (session_transport_attribute (s, 1 /* is_get */, &attr) != 0)
    return 0;

  cert = (X509 *) attr.tls_peer_cert.cert;
  if (!cert)
    return 0;

  serial = X509_get_serialNumber (cert);
  if (!serial)
    goto done;

  bn = ASN1_INTEGER_to_BN (serial, 0);
  if (!bn)
    goto done;

  hex = BN_bn2hex (bn);
  if (!hex)
    goto done;

  out = tlsctrl_dup_c_string ((const u8 *) hex, strlen (hex));
  for (p = out; p && *p; p++)
    if (*p >= 'A' && *p <= 'Z')
      *p = (u8) (*p - 'A' + 'a');

done:
  if (hex)
    OPENSSL_free (hex);
  if (bn)
    BN_free (bn);
  X509_free (cert);
  return out;
}

static int
tlsctrl_case_equal_n (const u8 *a, const char *b, u32 len)
{
  return strncasecmp ((const char *) a, b, len) == 0;
}

static u32
tlsctrl_find_header_end (u8 *data)
{
  u32 i;

  if (!data || vec_len (data) < 4)
    return ~0;

  for (i = 0; i + 3 < vec_len (data); i++)
    {
      if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' &&
          data[i + 3] == '\n')
        return i;
    }
  return ~0;
}

static u32
tlsctrl_parse_content_length (u8 *data, u32 header_end)
{
  u32 pos = 0;

  while (pos < header_end)
    {
      u32 line_end = pos;
      u8 *line;
      while (line_end + 1 < header_end &&
             !(data[line_end] == '\r' && data[line_end + 1] == '\n'))
        line_end++;

      line = data + pos;
      if ((line_end - pos) > 15 && tlsctrl_case_equal_n (line, "Content-Length:", 15))
        {
          u32 value = 0;
          u32 i = pos + 15;
          while (i < line_end && (data[i] == ' ' || data[i] == '\t'))
            i++;
          while (i < line_end && data[i] >= '0' && data[i] <= '9')
            {
              value = value * 10 + (data[i] - '0');
              i++;
            }
          return value;
        }

      pos = line_end + 2;
    }

  return 0;
}

static int
tlsctrl_request_complete (tlsctrl_conn_t *conn, u32 *header_end, u32 *body_offset,
                          u32 *content_length)
{
  u32 hdr_end;

  hdr_end = tlsctrl_find_header_end (conn->request_data);
  if (hdr_end == ~0)
    return 0;

  *header_end = hdr_end;
  *body_offset = hdr_end + 4;
  *content_length = tlsctrl_parse_content_length (conn->request_data, hdr_end);

  if (vec_len (conn->request_data) < (*body_offset + *content_length))
    return 0;

  return 1;
}

static u8 *
tlsctrl_header_value_dup (u8 *data, u32 header_end, const char *name)
{
  u32 pos = 0;
  u32 name_len = strlen (name);

  while (pos < header_end)
    {
      u32 line_end = pos;
      u32 value_start;
      while (line_end + 1 < header_end &&
             !(data[line_end] == '\r' && data[line_end + 1] == '\n'))
        line_end++;

      if ((line_end - pos) > name_len && tlsctrl_case_equal_n (data + pos, name, name_len))
        {
          value_start = pos + name_len;
          while (value_start < line_end &&
                 (data[value_start] == ' ' || data[value_start] == '\t'))
            value_start++;
          return tlsctrl_dup_c_string (data + value_start, line_end - value_start);
        }

      pos = line_end + 2;
    }

  return 0;
}

static u8 *
tlsctrl_json_extract_string (u8 *json, const char *key)
{
  char pattern[128];
  char *start;
  char *p;
  char *end;
  size_t pattern_len;

  if (!json || !key)
    return 0;

  clib_memset (pattern, 0, sizeof (pattern));
  snprintf (pattern, sizeof (pattern) - 1, "\"%s\"", key);
  pattern_len = strlen (pattern);

  start = strstr ((char *) json, pattern);
  if (!start)
    return 0;

  p = start + pattern_len;
  while (*p && *p != ':')
    p++;
  if (*p != ':')
    return 0;
  p++;
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    p++;
  if (*p != '"')
    return 0;
  p++;

  end = p;
  while (*end)
    {
      if (*end == '"' && (end == p || *(end - 1) != '\\'))
        break;
      end++;
    }
  if (*end != '"')
    return 0;

  return tlsctrl_dup_c_string ((u8 *) p, end - p);
}

static u8 *
tlsctrl_json_extract_value (u8 *json, const char *key)
{
  char pattern[128];
  char *start;
  char *p;
  char *end;
  size_t pattern_len;
  int depth = 0;
  int in_string = 0;

  if (!json || !key)
    return 0;

  clib_memset (pattern, 0, sizeof (pattern));
  snprintf (pattern, sizeof (pattern) - 1, "\"%s\"", key);
  pattern_len = strlen (pattern);

  start = strstr ((char *) json, pattern);
  if (!start)
    return 0;

  p = start + pattern_len;
  while (*p && *p != ':')
    p++;
  if (*p != ':')
    return 0;
  p++;
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    p++;

  if (*p == '[' || *p == '{')
    {
      char open = *p;
      char close = (open == '[') ? ']' : '}';
      end = p;
      for (; *end; end++)
        {
          if (*end == '"' && (end == p || *(end - 1) != '\\'))
            in_string = !in_string;
          if (in_string)
            continue;
          if (*end == open)
            depth++;
          else if (*end == close)
            {
              depth--;
              if (depth == 0)
                {
                  end++;
                  break;
                }
            }
        }
      if (depth != 0)
        return 0;
      return tlsctrl_dup_c_string ((u8 *) p, end - p);
    }

  if (*p == '"')
    {
      p++;
      end = p;
      while (*end)
        {
          if (*end == '"' && (end == p || *(end - 1) != '\\'))
            break;
          end++;
        }
      if (*end != '"')
        return 0;
      return tlsctrl_dup_c_string ((u8 *) p, end - p);
    }

  end = p;
  while (*end && *end != ',' && *end != '}' && *end != ']' && *end != '\n' && *end != '\r')
    end++;
  while (end > p && (*(end - 1) == ' ' || *(end - 1) == '\t'))
    end--;
  if (end <= p)
    return 0;
  return tlsctrl_dup_c_string ((u8 *) p, end - p);
}

static u8
tlsctrl_hex_value (u8 c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return 0;
}

static u8 *
tlsctrl_url_decode_dup (const u8 *src, u32 len)
{
  u8 *dst = 0;
  u32 i;

  if (!src)
    return 0;

  for (i = 0; i < len; i++)
    {
      if (src[i] == '+')
        vec_add1 (dst, ' ');
      else if (src[i] == '%' && i + 2 < len)
        {
          u8 value = (tlsctrl_hex_value (src[i + 1]) << 4) |
                     tlsctrl_hex_value (src[i + 2]);
          vec_add1 (dst, value);
          i += 2;
        }
      else
        vec_add1 (dst, src[i]);
    }

  vec_add1 (dst, 0);
  return dst;
}

static u8 *
tlsctrl_query_value_dup (u8 *target, const char *key)
{
  u8 *query;
  char *p;
  u32 key_len;

  if (!target || !key)
    return 0;

  query = (u8 *) strchr ((char *) target, '?');
  if (!query)
    return 0;
  query++;

  p = (char *) query;
  key_len = strlen (key);
  while (*p)
    {
      char *amp = strchr (p, '&');
      char *eq = strchr (p, '=');
      if (!amp)
        amp = p + strlen (p);
      if (eq && eq < amp)
        {
          if ((u32) (eq - p) == key_len && !strncmp (p, key, key_len))
            return tlsctrl_url_decode_dup ((u8 *) (eq + 1), amp - eq - 1);
        }
      if (*amp == 0)
        break;
      p = amp + 1;
    }

  return 0;
}

static void
tlsctrl_client_set_string (u8 **dst, u8 *src);

static tlsctrl_client_t *
tlsctrl_client_find_internal (u8 *username, int create)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;

  pool_foreach (client, tm->clients)
    {
      if (client->username && username &&
          !strcmp ((char *) client->username, (char *) username))
        return client;
    }

  if (!create)
    return 0;

  pool_get_zero (tm->clients, client);
  tlsctrl_client_set_string (&client->username, username);
  client->enabled = 1;
  client->generation = 0;
  return client;
}

static void
tlsctrl_client_set_string (u8 **dst, u8 *src)
{
  u32 len;
  vec_free (*dst);
  *dst = 0;
  if (!src)
    return;
  len = strlen ((char *) src);
  vec_validate (*dst, len);
  if (len)
    clib_memcpy_fast (*dst, src, len);
  (*dst)[len] = 0;
}

static void
tlsctrl_client_set_disconnect_command_locked (tlsctrl_client_t *client)
{
  if (!client)
    return;
  tlsctrl_client_set_string (&client->command_type, (u8 *) "disconnect");
  tlsctrl_client_set_string (&client->command_payload,
                             (u8 *) "{\"reason\":\"admin_disconnect\"}");
}

static void
tlsctrl_client_clear_disconnect_state_locked (tlsctrl_client_t *client)
{
  if (!client)
    return;
  client->admin_disconnected = 0;
  if (client->command_type &&
      !strcmp ((char *) client->command_type, "disconnect"))
    {
      vec_free (client->command_type);
      client->command_type = 0;
      vec_free (client->command_payload);
      client->command_payload = 0;
    }
}

static void
tlsctrl_client_touch_heartbeat_locked (tlsctrl_client_t *client, u8 *cert_serial,
                                       u8 *body, u8 *mac_hdr,
                                       u8 *sys_user_hdr, u8 *os_type_hdr,
                                       u8 *os_version_hdr, u8 *uptime_hdr,
                                       u8 *interfaces_json,
                                       u8 *connect_intent,
                                       int manual_connect)
{
  u64 now = tlsctrl_now_unix_ns ();
  u8 *v;

  if (client->connected_at_unix_ns == 0)
    client->connected_at_unix_ns = now;
  client->last_seen_unix_ns = now;
  client->user_last_seen = now;
  client->heartbeat_count += 1;

  if (manual_connect)
    tlsctrl_client_clear_disconnect_state_locked (client);

  if (cert_serial && vec_len (cert_serial))
    tlsctrl_client_set_string (&client->cert_serial, cert_serial);

  v = tlsctrl_json_extract_string (body, "system_user");
  if (v)
    {
      tlsctrl_client_set_string (&client->system_user, v);
      vec_free (v);
    }
  else if (sys_user_hdr)
    tlsctrl_client_set_string (&client->system_user, sys_user_hdr);

  v = tlsctrl_json_extract_string (body, "os_name");
  if (v)
    {
      tlsctrl_client_set_string (&client->os_name, v);
      vec_free (v);
    }
  else if (os_type_hdr)
    tlsctrl_client_set_string (&client->os_name, os_type_hdr);

  v = tlsctrl_json_extract_string (body, "os_version");
  if (v)
    {
      tlsctrl_client_set_string (&client->os_version, v);
      vec_free (v);
    }
  else if (os_version_hdr)
    tlsctrl_client_set_string (&client->os_version, os_version_hdr);

  v = tlsctrl_json_extract_string (body, "system_uptime");
  if (v)
    {
      tlsctrl_client_set_string (&client->system_uptime, v);
      vec_free (v);
    }
  else if (uptime_hdr)
    tlsctrl_client_set_string (&client->system_uptime, uptime_hdr);

  v = tlsctrl_json_extract_string (body, "ip");
  if (v)
    {
      tlsctrl_client_set_string (&client->ip, v);
      vec_free (v);
    }

  v = tlsctrl_json_extract_string (body, "mac");
  if (v)
    {
      tlsctrl_client_set_string (&client->mac, v);
      vec_free (v);
    }
  else if (mac_hdr)
    tlsctrl_client_set_string (&client->mac, mac_hdr);

  v = tlsctrl_json_extract_string (body, "source");
  if (v)
    {
      tlsctrl_client_set_string (&client->source, v);
      vec_free (v);
    }

  v = tlsctrl_json_extract_string (body, "connect_intent");
  if (v)
    {
      tlsctrl_client_set_string (&client->connect_intent, v);
      vec_free (v);
    }
  else if (connect_intent)
    tlsctrl_client_set_string (&client->connect_intent, connect_intent);

  v = tlsctrl_json_extract_value (body, "interfaces");
  if (v)
    {
      tlsctrl_client_set_string (&client->interfaces_json, v);
      vec_free (v);
    }
  else if (interfaces_json)
    tlsctrl_client_set_string (&client->interfaces_json, interfaces_json);
}

static void
tlsctrl_client_touch_apps_locked (tlsctrl_client_t *client, u32 count, u8 *body)
{
  u64 now = tlsctrl_now_unix_ns ();
  if (client->connected_at_unix_ns == 0)
    client->connected_at_unix_ns = now;
  client->last_seen_unix_ns = now;
  client->user_last_seen = now;
  client->apps_report_count += 1;
  client->apps_count = count;
  client->apps_updated_at_unix_ns = now;
  tlsctrl_client_set_string (&client->last_apps_json, body);
}

int
tlsctrl_user_add_or_update (u8 *username, u8 *cert_serial, u8 enabled)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;

  if (!username || !vec_len (username))
    return -1;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  client = tlsctrl_client_find_internal (username, 1);
  if (cert_serial && vec_len (cert_serial))
    tlsctrl_client_set_string (&client->cert_serial, cert_serial);
  client->enabled = enabled ? 1 : 0;
  client->generation += 1;
  clib_spinlock_unlock_if_init (&tm->clients_lock);
  return 0;
}

int
tlsctrl_user_delete (u8 *username)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;

  if (!username || !vec_len (username))
    return -1;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  pool_foreach (client, tm->clients)
    {
      if (client->username && !strcmp ((char *) client->username, (char *) username))
        {
          tlsctrl_client_free_fields (client);
          pool_put (tm->clients, client);
          break;
        }
    }
  clib_spinlock_unlock_if_init (&tm->clients_lock);
  return 0;
}

int
tlsctrl_user_reissue (u8 *username, u8 *cert_serial)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;

  if (!username || !vec_len (username))
    return -1;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  client = tlsctrl_client_find_internal (username, 1);
  if (cert_serial && vec_len (cert_serial))
    tlsctrl_client_set_string (&client->cert_serial, cert_serial);
  client->enabled = 1;
  client->generation += 1;
  tlsctrl_client_clear_disconnect_state_locked (client);
  clib_spinlock_unlock_if_init (&tm->clients_lock);
  return 0;
}

int
tlsctrl_phase3b_client_set_disconnected (u8 *username, u8 is_disconnected)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;

  if (!username || !vec_len (username))
    return -1;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  client = tlsctrl_client_find_internal (username, 1);
  client->admin_disconnected = is_disconnected ? 1 : 0;
  if (is_disconnected)
    tlsctrl_client_set_disconnect_command_locked (client);
  else
    tlsctrl_client_clear_disconnect_state_locked (client);
  clib_spinlock_unlock_if_init (&tm->clients_lock);
  return 0;
}

int
tlsctrl_session_disconnect_username (u8 *username)
{
  return tlsctrl_phase3b_client_set_disconnected (username, 1);
}

int
tlsctrl_client_command_set (u8 *username, u8 *command_type, u8 *payload)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;

  if (!username || !vec_len (username))
    return -1;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  client = tlsctrl_client_find_internal (username, 1);
  tlsctrl_client_set_string (&client->command_type, command_type);
  tlsctrl_client_set_string (&client->command_payload, payload);
  if (command_type && !strcmp ((char *) command_type, "disconnect"))
    client->admin_disconnected = 1;
  clib_spinlock_unlock_if_init (&tm->clients_lock);
  return 0;
}

void
tlsctrl_client_command_get (u8 *username, u8 **command_type, u8 **payload)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;

  *command_type = 0;
  *payload = 0;
  if (!username || !vec_len (username))
    return;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  client = tlsctrl_client_find_internal (username, 0);
  if (client)
    {
      if (client->command_type)
        *command_type = tlsctrl_dup_string0 (client->command_type);
      if (client->command_payload)
        *payload = tlsctrl_dup_string0 (client->command_payload);
    }
  clib_spinlock_unlock_if_init (&tm->clients_lock);
}

int
tlsctrl_client_heartbeat_api (u8 *username, u8 *cert_serial, u8 *system_user,
                              u8 *os_name, u8 *os_version, u8 *system_uptime,
                              u8 *ip, u8 *mac, u8 *source,
                              u8 *interfaces_json, u8 *connect_intent)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;
  u64 now = tlsctrl_now_unix_ns ();

  if (!username || !vec_len (username))
    return -1;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  client = tlsctrl_client_find_internal (username, 1);
  if (client->connected_at_unix_ns == 0)
    client->connected_at_unix_ns = now;
  client->last_seen_unix_ns = now;
  client->user_last_seen = now;
  client->heartbeat_count += 1;
  if (cert_serial && vec_len (cert_serial))
    tlsctrl_client_set_string (&client->cert_serial, cert_serial);
  if (system_user)
    tlsctrl_client_set_string (&client->system_user, system_user);
  if (os_name)
    tlsctrl_client_set_string (&client->os_name, os_name);
  if (os_version)
    tlsctrl_client_set_string (&client->os_version, os_version);
  if (system_uptime)
    tlsctrl_client_set_string (&client->system_uptime, system_uptime);
  if (ip)
    tlsctrl_client_set_string (&client->ip, ip);
  if (mac)
    tlsctrl_client_set_string (&client->mac, mac);
  if (source)
    tlsctrl_client_set_string (&client->source, source);
  if (interfaces_json)
    tlsctrl_client_set_string (&client->interfaces_json, interfaces_json);
  if (connect_intent)
    tlsctrl_client_set_string (&client->connect_intent, connect_intent);
  clib_spinlock_unlock_if_init (&tm->clients_lock);
  return 0;
}

void
tlsctrl_client_apps_get (u8 *username, u32 *count, u64 *generated_at_unix_ns,
                         u8 **payload)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;

  if (count)
    *count = 0;
  if (generated_at_unix_ns)
    *generated_at_unix_ns = 0;
  if (payload)
    *payload = 0;
  if (!username || !vec_len (username))
    return;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  client = tlsctrl_client_find_internal (username, 0);
  if (client)
    {
      if (count)
        *count = client->apps_count;
      if (generated_at_unix_ns)
        *generated_at_unix_ns = client->apps_updated_at_unix_ns;
      if (payload && client->last_apps_json)
        *payload = tlsctrl_dup_string0 (client->last_apps_json);
    }
  clib_spinlock_unlock_if_init (&tm->clients_lock);
}

int
tlsctrl_client_apps_set_api (u8 *username, u32 count, u8 *payload)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;

  if (!username || !vec_len (username))
    return -1;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  client = tlsctrl_client_find_internal (username, 1);
  tlsctrl_client_touch_apps_locked (client, count, payload);
  clib_spinlock_unlock_if_init (&tm->clients_lock);
  return 0;
}

static u32
tlsctrl_count_apps_in_report (u8 *body)
{
  char *p;
  u32 count = 0;
  if (!body)
    return 0;
  p = (char *) body;
  while ((p = strstr (p, "\"pid\"")) != 0)
    {
      count++;
      p += 5;
    }
  return count;
}

static int
tlsctrl_http_authorize_user (u8 *username, u8 *peer_cert_serial,
                             int manual_connect, int *status_code)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;
  int rv = 0;

  *status_code = 401;
  if (!username || !vec_len (username))
    return -1;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  client = tlsctrl_client_find_internal (username, 0);
  if (!client || !client->enabled)
    goto done;
  if (client->cert_serial && vec_len (client->cert_serial))
    {
      if (!peer_cert_serial || !vec_len (peer_cert_serial) ||
          strcmp ((char *) client->cert_serial, (char *) peer_cert_serial))
        goto done;
    }
  if (client->admin_disconnected && !manual_connect)
    {
      *status_code = 423;
      goto done;
    }
  rv = 1;

done:
  clib_spinlock_unlock_if_init (&tm->clients_lock);
  return rv;
}

static void
tlsctrl_build_response (tlsctrl_conn_t *conn, int code, const char *status,
                        const char *ctype, u8 *payload)
{
  tlsctrl_main_t *tm = &tlsctrl_main;

  vec_free (conn->response_data);
  conn->response_data = format (
    0,
    "HTTP/1.1 %d %s\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %u\r\n"
    "Connection: close\r\n"
    "Server: tlsctrl-phase3b\r\n"
    "\r\n"
    "%v",
    code, status, ctype, payload ? vec_len (payload) : 0, payload);
  conn->response_ready = 1;
  conn->response_complete = 0;
  conn->tx_offset = 0;

  if (code >= 200 && code < 300)
    tm->http_2xx_responses += 1;
  else if (code >= 400 && code < 500)
    tm->http_4xx_responses += 1;
  else if (code >= 500)
    tm->http_5xx_responses += 1;
}

static void
tlsctrl_build_json_response (tlsctrl_conn_t *conn, int code,
                             const char *status, const char *json_text)
{
  u8 *payload = 0;
  if (json_text)
    payload = format (0, "%s", json_text);
  tlsctrl_build_response (conn, code, status, "application/json", payload);
  vec_free (payload);
}

static int
tlsctrl_try_send_response (session_t *s, tlsctrl_conn_t *conn)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  u32 remaining;
  int rv;

  if (!conn || !conn->response_ready)
    return -1;

  if (conn->response_complete)
    return 0;

  if (conn->tx_offset >= vec_len (conn->response_data))
    {
      conn->response_complete = 1;
      return 0;
    }

  remaining = vec_len (conn->response_data) - conn->tx_offset;
  if (remaining == 0)
    {
      conn->response_complete = 1;
      return 0;
    }

  rv = svm_fifo_enqueue (s->tx_fifo, remaining,
                         conn->response_data + conn->tx_offset);
  if (rv < 0)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  if (rv == 0)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  conn->tx_offset += rv;
  conn->tx_bytes += rv;
  tm->tx_bytes += rv;

  if (conn->tx_offset >= vec_len (conn->response_data))
    conn->response_complete = 1;
  else
    svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);

  return 0;
}

static int
tlsctrl_parse_request_line (u8 *data, u32 header_end, u8 **method, u8 **target)
{
  u32 line_end = 0;
  u32 i;
  u32 first_sp = ~0, second_sp = ~0;

  while (line_end + 1 < header_end &&
         !(data[line_end] == '\r' && data[line_end + 1] == '\n'))
    line_end++;

  for (i = 0; i < line_end; i++)
    {
      if (data[i] == ' ' && first_sp == ~0)
        first_sp = i;
      else if (data[i] == ' ' && second_sp == ~0)
        {
          second_sp = i;
          break;
        }
    }

  if (first_sp == ~0 || second_sp == ~0 || first_sp == 0 ||
      second_sp <= first_sp + 1)
    return -1;

  *method = tlsctrl_dup_c_string (data, first_sp);
  *target = tlsctrl_dup_c_string (data + first_sp + 1, second_sp - first_sp - 1);
  return 0;
}

static void
tlsctrl_build_commands_json (u8 **out, u8 *command_type, u8 *payload)
{
  u8 *cmd_id = 0;

  if (!command_type || !vec_len (command_type))
    {
      *out = format (0, "{\"commands\":[]}");
      return;
    }

  if (payload && vec_len (payload))
    cmd_id = tlsctrl_json_extract_string (payload, "id");

  if (payload && vec_len (payload) && cmd_id && vec_len (cmd_id))
    *out = format (0,
                   "{\"commands\":[{\"id\":\"%s\",\"type\":\"%s\",\"payload\":%s}]}",
                   cmd_id, command_type, payload);
  else if (payload && vec_len (payload))
    *out = format (0,
                   "{\"commands\":[{\"type\":\"%s\",\"payload\":%s}]}",
                   command_type, payload);
  else if (cmd_id && vec_len (cmd_id))
    *out = format (0,
                   "{\"commands\":[{\"id\":\"%s\",\"type\":\"%s\"}]}",
                   cmd_id, command_type);
  else
    *out = format (0, "{\"commands\":[{\"type\":\"%s\"}]}", command_type);

  vec_free (cmd_id);
}

static void
tlsctrl_handle_request (tlsctrl_conn_t *conn)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  u32 header_end = 0, body_offset = 0, content_length = 0;
  u8 *method = 0, *target = 0, *body = 0;
  u8 *username = 0, *cert_serial = 0, *peer_cert_serial = 0;
  u8 *mac_hdr = 0, *sys_user_hdr = 0, *os_type_hdr = 0, *os_version_hdr = 0,
     *uptime_hdr = 0;
  u8 *command_type = 0, *payload = 0, *json = 0;
  u8 *profile = 0, *client_ip = 0;
  u8 *assigned_ip = 0, *gateway = 0, *dns_servers = 0;
  u8 *include_routes = 0, *exclude_routes = 0;
  u8 full_tunnel = 0;
  u16 mtu = 0, mss = 0;
  u32 lease_seconds = 0, tunnel_id = 0;
  int auth_status = 401;
  int manual_connect = 0;
  tlsctrl_client_t *client;

  if (!tlsctrl_request_complete (conn, &header_end, &body_offset, &content_length))
    return;

  if (tlsctrl_parse_request_line (conn->request_data, header_end, &method, &target))
    {
      tm->parse_errors += 1;
      tlsctrl_build_json_response (conn, 400, "Bad Request",
                                   "{\"ok\":false,\"error\":\"bad request line\"}");
      goto done;
    }

  body = tlsctrl_dup_c_string (conn->request_data + body_offset, content_length);
  mac_hdr = tlsctrl_header_value_dup (conn->request_data, header_end, "X-Client-MAC:");
  sys_user_hdr = tlsctrl_header_value_dup (conn->request_data, header_end, "X-System-User:");
  os_type_hdr = tlsctrl_header_value_dup (conn->request_data, header_end, "X-OS-Type:");
  os_version_hdr = tlsctrl_header_value_dup (conn->request_data, header_end, "X-OS-Version:");
  uptime_hdr = tlsctrl_header_value_dup (conn->request_data, header_end, "X-System-Uptime:");
  peer_cert_serial = tlsctrl_get_peer_cert_serial (session_get_from_handle (conn->session_handle));

  if (!strcmp ((char *) method, "POST") &&
      !strncmp ((char *) target, "/api/client/heartbeat", 21))
    {
      username = tlsctrl_json_extract_string (body, "username");
      cert_serial = tlsctrl_json_extract_string (body, "cert_serial");
      if (body)
        {
          u8 *intent = tlsctrl_json_extract_string (body, "connect_intent");
          if (intent && !strcmp ((char *) intent, "manual_connect"))
            manual_connect = 1;
          vec_free (intent);
        }
      if (!username || !vec_len (username))
        {
          tm->parse_errors += 1;
          tlsctrl_build_json_response (conn, 400, "Bad Request",
                                       "{\"ok\":false,\"error\":\"username required\"}");
          goto done;
        }
      if (tlsctrl_http_authorize_user (username, peer_cert_serial, manual_connect, &auth_status) <= 0)
        {
          if (auth_status == 423)
            tlsctrl_build_json_response (conn, 423, "Locked",
                                         "{\"ok\":false,\"error\":\"disconnected by admin\"}");
          else
            tlsctrl_build_json_response (conn, 401, "Unauthorized",
                                         "{\"ok\":false,\"error\":\"unauthorized\"}");
          goto done;
        }

      clib_spinlock_lock_if_init (&tm->clients_lock);
      client = tlsctrl_client_find_internal (username, 1);
      tlsctrl_client_touch_heartbeat_locked (client,
                                             (peer_cert_serial && vec_len (peer_cert_serial)) ? peer_cert_serial : cert_serial,
                                             body, mac_hdr,
                                             sys_user_hdr, os_type_hdr,
                                             os_version_hdr, uptime_hdr,
                                             0, 0,
                                             manual_connect);
      clib_spinlock_unlock_if_init (&tm->clients_lock);
      tlsctrl_build_json_response (conn, 200, "OK",
                                   "{\"ok\":true,\"status\":\"connected\"}");
    }
  else if (!strcmp ((char *) method, "GET") &&
           !strncmp ((char *) target, "/api/client/command", 19))
    {
      username = tlsctrl_query_value_dup (target, "username");
      if (!username || !vec_len (username))
        {
          tm->parse_errors += 1;
          tlsctrl_build_json_response (conn, 400, "Bad Request",
                                       "{\"ok\":false,\"error\":\"username query required\"}");
          goto done;
        }
      if (tlsctrl_http_authorize_user (username, peer_cert_serial, 0, &auth_status) <= 0)
        {
          if (auth_status == 423)
            tlsctrl_build_json_response (conn, 423, "Locked",
                                         "{\"ok\":false,\"error\":\"disconnected by admin\"}");
          else
            tlsctrl_build_json_response (conn, 401, "Unauthorized",
                                         "{\"ok\":false,\"error\":\"unauthorized\"}");
          goto done;
        }
      tlsctrl_client_command_get (username, &command_type, &payload);
      tlsctrl_build_commands_json (&json, command_type, payload);
      tlsctrl_build_response (conn, 200, "OK", "application/json", json);
    }
  else if (!strcmp ((char *) method, "POST") &&
           !strncmp ((char *) target, "/api/client/vpn-bind", 20))
    {
      username = tlsctrl_json_extract_string (body, "username");
      profile = tlsctrl_json_extract_string (body, "profile");
      client_ip = tlsctrl_json_extract_string (body, "client_ip");

      if (!username || !vec_len (username))
        {
          vec_free (username);
          username = tlsctrl_header_value_dup (conn->request_data, header_end,
                                               "X-Username:");
        }
      if (!profile || !vec_len (profile))
        {
          vec_free (profile);
          profile = tlsctrl_header_value_dup (conn->request_data, header_end,
                                              "X-Profile:");
        }
      if (!client_ip || !vec_len (client_ip))
        {
          vec_free (client_ip);
          client_ip = tlsctrl_header_value_dup (conn->request_data, header_end,
                                                "X-Client-IP:");
        }

      if (!username || !vec_len (username))
        {
          tm->parse_errors += 1;
          tlsctrl_build_json_response (conn, 400, "Bad Request",
                                       "{\"ok\":false,\"error\":\"username required\"}");
          goto done;
        }

      if (!profile || !vec_len (profile))
        {
          vec_free (profile);
          profile = format (0, "default");
        }

      if (!client_ip || !vec_len (client_ip))
        {
          vec_free (client_ip);
          client_ip = format (0, "0.0.0.0");
        }

      if (tlsctrl_http_authorize_user (username, peer_cert_serial, 1, &auth_status) <= 0)
        {
          if (auth_status == 423)
            tlsctrl_build_json_response (conn, 423, "Locked",
                                         "{\"ok\":false,\"error\":\"disconnected by admin\"}");
          else
            tlsctrl_build_json_response (conn, 401, "Unauthorized",
                                         "{\"ok\":false,\"error\":\"unauthorized\"}");
          goto done;
        }

      if (tlsctrl_vpn_tunnel_open ((char *) username, (char *) profile,
                                   (char *) client_ip, &tunnel_id,
                                   &assigned_ip, &gateway,
                                   &dns_servers, &include_routes,
                                   &exclude_routes, &full_tunnel,
                                   &mtu, &mss, &lease_seconds) != 0)
        {
          tlsctrl_build_json_response (conn, 500, "Internal Server Error",
                                       "{\"ok\":false,\"error\":\"vpn tunnel open failed\"}");
          goto done;
        }

      tlsctrl_vpn_stream_attach (tunnel_id, conn->session_handle);

      json = format (
        0,
        "{\"ok\":true,\"tunnel_id\":%u,"
        "\"assigned_ip\":\"%s\",\"gateway\":\"%s\",\"dns_servers\":\"%s\","
        "\"include_routes\":\"%s\",\"exclude_routes\":\"%s\","
        "\"full_tunnel\":%s,\"mtu\":%u,\"mss\":%u,\"lease_seconds\":%u}",
        tunnel_id,
        assigned_ip ? (char *) assigned_ip : "",
        gateway ? (char *) gateway : "",
        dns_servers ? (char *) dns_servers : "",
        include_routes ? (char *) include_routes : "",
        exclude_routes ? (char *) exclude_routes : "",
        full_tunnel ? "true" : "false",
        mtu, mss, lease_seconds);
      tlsctrl_build_response (conn, 200, "OK", "application/json", json);
    }
  else if (!strcmp ((char *) method, "POST") &&
           !strncmp ((char *) target, "/api/client/apps", 16))
    {
      u32 count = 0;
      username = tlsctrl_json_extract_string (body, "username");
      if (!username || !vec_len (username))
        {
          tm->parse_errors += 1;
          tlsctrl_build_json_response (conn, 400, "Bad Request",
                                       "{\"ok\":false,\"error\":\"username required\"}");
          goto done;
        }
      if (tlsctrl_http_authorize_user (username, peer_cert_serial, 0, &auth_status) <= 0)
        {
          if (auth_status == 423)
            tlsctrl_build_json_response (conn, 423, "Locked",
                                         "{\"ok\":false,\"error\":\"disconnected by admin\"}");
          else
            tlsctrl_build_json_response (conn, 401, "Unauthorized",
                                         "{\"ok\":false,\"error\":\"unauthorized\"}");
          goto done;
        }
      count = tlsctrl_count_apps_in_report (body);
      clib_spinlock_lock_if_init (&tm->clients_lock);
      client = tlsctrl_client_find_internal (username, 1);
      tlsctrl_client_touch_apps_locked (client, count, body);
      clib_spinlock_unlock_if_init (&tm->clients_lock);
      tlsctrl_build_json_response (conn, 200, "OK", "{\"ok\":true}");
    }
  else
    {
      tlsctrl_build_json_response (conn, 404, "Not Found",
                                   "{\"ok\":false,\"error\":\"not found\"}");
    }

done:
  vec_free (method);
  vec_free (target);
  vec_free (body);
  vec_free (username);
  vec_free (cert_serial);
  vec_free (peer_cert_serial);
  vec_free (mac_hdr);
  vec_free (sys_user_hdr);
  vec_free (os_type_hdr);
  vec_free (os_version_hdr);
  vec_free (uptime_hdr);
  vec_free (command_type);
  vec_free (payload);
  vec_free (json);
  vec_free (profile);
  vec_free (client_ip);
  vec_free (assigned_ip);
  vec_free (gateway);
  vec_free (dns_servers);
  vec_free (include_routes);
  vec_free (exclude_routes);
}

static int
tlsctrl_session_accept_callback (session_t *s)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_conn_t *conn;

  conn = tlsctrl_conn_alloc (s->thread_index);
  conn->session_handle = session_handle (s);

  s->opaque = conn->session_index;
  s->session_state = SESSION_STATE_READY;

  tm->accepted_connections += 1;
  return 0;
}

static void
tlsctrl_session_disconnect_callback (session_t *s)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_conn_t *conn = tlsctrl_conn_get (s->thread_index, s->opaque);

  tm->disconnected_connections += 1;
  tlsctrl_vpn_detach_by_session_handle (session_handle (s));
  if (conn)
    conn->close_requested = 1;
}

static void
tlsctrl_session_reset_callback (session_t *s)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_conn_t *conn = tlsctrl_conn_get (s->thread_index, s->opaque);

  tm->reset_connections += 1;
  tlsctrl_vpn_detach_by_session_handle (session_handle (s));
  if (conn)
    conn->close_requested = 1;
}

static void
tlsctrl_session_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  tlsctrl_conn_free (s->thread_index, s->opaque);
}

static int
tlsctrl_session_connected_callback (u32 app_index, u32 api_context, session_t *s,
                                    session_error_t err)
{
  (void) app_index;
  (void) api_context;
  (void) s;
  (void) err;
  return -1;
}

static int
tlsctrl_add_segment_callback (u32 app_wrk_index, u64 segment_handle)
{
  (void) app_wrk_index;
  (void) segment_handle;
  return 0;
}

static int
tlsctrl_del_segment_callback (u32 app_wrk_index, u64 segment_handle)
{
  (void) app_wrk_index;
  (void) segment_handle;
  return 0;
}

static int
tlsctrl_builtin_rx_callback (session_t *s)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_conn_t *conn;
  u32 max_deq;
  int rv;

  if (PREDICT_FALSE (s->flags & SESSION_F_APP_CLOSED))
    return 0;

  conn = tlsctrl_conn_get (s->thread_index, s->opaque);
  if (!conn)
    return 0;

  tm->rx_callbacks += 1;

  max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
  while (max_deq)
    {
      u8 tmp[4096];
      u32 chunk = clib_min (max_deq, (u32) sizeof (tmp));
      rv = svm_fifo_dequeue (s->rx_fifo, chunk, tmp);
      if (rv <= 0)
        break;
      vec_add (conn->request_data, tmp, rv);
      conn->rx_bytes += rv;
      tm->rx_bytes += rv;
      max_deq -= rv;
    }

  if (!conn->response_ready)
    tlsctrl_handle_request (conn);

  if (conn->response_ready)
    tlsctrl_try_send_response (s, conn);

  if (conn->response_complete && !conn->close_requested)
    tlsctrl_disconnect_session (s, conn);

  return 0;
}

static int
tlsctrl_builtin_tx_callback (session_t *s)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_conn_t *conn;

  if (PREDICT_FALSE (s->flags & SESSION_F_APP_CLOSED))
    return 0;

  conn = tlsctrl_conn_get (s->thread_index, s->opaque);
  if (!conn)
    return 0;

  tm->tx_callbacks += 1;

  if (conn->close_requested)
    return 0;

  if (conn->response_ready && !conn->response_complete)
    tlsctrl_try_send_response (s, conn);

  if (conn->response_complete && !conn->close_requested)
    tlsctrl_disconnect_session (s, conn);

  return 0;
}

static session_cb_vft_t tlsctrl_phase3b_session_cb_vft = {
  .add_segment_callback = tlsctrl_add_segment_callback,
  .del_segment_callback = tlsctrl_del_segment_callback,
  .session_accept_callback = tlsctrl_session_accept_callback,
  .session_connected_callback = tlsctrl_session_connected_callback,
  .session_disconnect_callback = tlsctrl_session_disconnect_callback,
  .session_cleanup_callback = tlsctrl_session_cleanup_callback,
  .session_reset_callback = tlsctrl_session_reset_callback,
  .builtin_app_rx_callback = tlsctrl_builtin_rx_callback,
  .builtin_app_tx_callback = tlsctrl_builtin_tx_callback,
};

static int
tlsctrl_load_file (u8 *path, u8 **data)
{
  clib_error_t *error;
  error = clib_file_contents ((char *) path, data);
  if (error)
    {
      clib_error_free (error);
      return -1;
    }
  return 0;
}

int
tlsctrl_phase3b_load_pem_files (u8 *cert_file, u8 *key_file, u8 *ca_file)
{
  u8 *cert = 0, *key = 0, *ca = 0;
  int rv = 0;

  if (!cert_file || !key_file || !ca_file)
    return -1;
  if (tlsctrl_load_file (cert_file, &cert))
    return -2;
  if (tlsctrl_load_file (key_file, &key))
    {
      vec_free (cert);
      return -3;
    }
  if (tlsctrl_load_file (ca_file, &ca))
    {
      vec_free (cert);
      vec_free (key);
      return -4;
    }
  rv = tlsctrl_phase3b_set_listener_pem (cert, key, ca);
  vec_free (cert);
  vec_free (key);
  vec_free (ca);
  return rv;
}

static int
tlsctrl_phase3b_prepare_crypto (void)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vnet_app_add_cert_key_pair_args_t ck_args = { 0 };
  app_ca_trust_add_args_t ca_args = { 0 };
  int rv = 0;

  if (tm->crypto_is_configured)
    return 0;

  if (!tm->server_cert_pem || !vec_len (tm->server_cert_pem) ||
      !tm->server_key_pem || !vec_len (tm->server_key_pem) ||
      !tm->ca_cert_pem || !vec_len (tm->ca_cert_pem))
    return -1;

  ck_args.cert = tm->server_cert_pem;
  ck_args.key = tm->server_key_pem;
  ck_args.cert_len = vec_len (tm->server_cert_pem);
  ck_args.key_len = vec_len (tm->server_key_pem);
  rv = vnet_app_add_cert_key_pair (&ck_args);
  if (rv)
    return rv;

  ca_args.ca_chain = tlsctrl_dup_string0 (tm->ca_cert_pem);
  ca_args.crl = 0;
  rv = app_crypto_add_ca_trust (tm->app_index, &ca_args);
  if (rv)
    {
      vnet_app_del_cert_key_pair (ck_args.index);
      vec_free (ca_args.ca_chain);
      return rv;
    }

  tm->ckpair_index = ck_args.index;
  tm->ca_trust_index = ca_args.index;
  tm->crypto_is_configured = 1;
  return 0;
}

int
tlsctrl_phase3b_attach (void)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vnet_app_attach_args_t _a = { 0 }, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS] = { 0 };
  int rv;

  if (!tm->enabled)
    return -1;
  if (tm->attached)
    return 0;

  a->api_client_index = ~0;
  a->name = format (0, "%s", TLSCTRL_PHASE3B_APP_NAME);
  a->session_cb_vft = &tlsctrl_phase3b_session_cb_vft;
  a->options = options;

  a->options[APP_OPTIONS_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 128 << 20;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = 64 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = 64 << 10;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 0;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN |
                                  APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE |
                                  APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  a->options[APP_OPTIONS_TLS_ENGINE] = tm->tls_engine;

  rv = vnet_application_attach (a);
  if (rv)
    {
      vec_free (a->name);
      return rv;
    }

  tm->app_index = a->app_index;
  tm->attached = 1;
  vec_free (a->name);
  return 0;
}

int
tlsctrl_phase3b_detach (void)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vnet_app_detach_args_t _a = { 0 }, *a = &_a;
  int rv;

  if (!tm->attached)
    return 0;

  if (tm->listening)
    {
      rv = tlsctrl_phase3b_listen_disable ();
      if (rv)
        return rv;
    }

  a->app_index = tm->app_index;
  a->api_client_index = ~0;
  rv = vnet_application_detach (a);
  if (rv)
    return rv;

  if (tm->ckpair_index)
    vnet_app_del_cert_key_pair (tm->ckpair_index);

  tm->app_index = APP_INVALID_INDEX;
  tm->listener_handle = SESSION_INVALID_HANDLE;
  tm->attached = 0;
  tm->crypto_is_configured = 0;
  tm->ckpair_index = 0;
  tm->ca_trust_index = 0;
  tlsctrl_reset_conn_pools ();
  return 0;
}

static int
tlsctrl_phase3b_build_listen_uri (u8 **uri)
{
  tlsctrl_main_t *tm = &tlsctrl_main;

  if (!tm->runtime_is_configured || !tm->runtime_addr || !vec_len (tm->runtime_addr) ||
      tm->runtime_port == 0)
    return -1;

  *uri = format (0, "tls://%s/%u%c", tm->runtime_addr, tm->runtime_port, 0);
  return 0;
}

int
tlsctrl_phase3b_listen_enable (void)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vnet_listen_args_t _a = { 0 }, *a = &_a;
  transport_endpt_ext_cfg_t *ext_cfg;
  u8 *uri = 0;
  int rv;

  if (!tm->attached)
    return -1;
  if (tm->listening)
    return 0;

  rv = tlsctrl_phase3b_prepare_crypto ();
  if (rv)
    return rv;

  rv = tlsctrl_phase3b_build_listen_uri (&uri);
  if (rv)
    return rv;

  a->app_index = tm->app_index;
  rv = parse_uri ((char *) uri, &a->sep_ext);
  vec_free (uri);
  if (rv)
    return rv;

  ext_cfg =
    session_endpoint_add_ext_cfg (&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
                                  sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = tm->ckpair_index;
  ext_cfg->crypto.ca_trust_index = tm->ca_trust_index;
  ext_cfg->crypto.tls_profile_index = ~0;
  ext_cfg->crypto.crypto_engine = tm->tls_engine;
  ext_cfg->crypto.verify_cfg = TLS_VERIFY_F_PEER | TLS_VERIFY_F_PEER_CERT;

  rv = vnet_listen (a);
  session_endpoint_free_ext_cfgs (&a->sep_ext);
  if (rv)
    return rv;

  tm->listener_handle = a->handle;
  tm->listening = 1;
  return 0;
}

int
tlsctrl_phase3b_listen_disable (void)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vnet_unlisten_args_t _a = { 0 }, *a = &_a;
  int rv;

  if (!tm->listening)
    return 0;

  a->app_index = tm->app_index;
  a->handle = tm->listener_handle;
  rv = vnet_unlisten (a);
  if (rv)
    return rv;

  tm->listener_handle = SESSION_INVALID_HANDLE;
  tm->listening = 0;
  return 0;
}

int
tlsctrl_phase3b_apply_listener_config (u8 *addr, u16 port,
                                       u8 *server_cert_pem,
                                       u8 *server_key_pem, u8 *ca_cert_pem)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  int rv;

  if (tm->listening)
    {
      rv = tlsctrl_phase3b_listen_disable ();
      if (rv)
        return rv;
    }

  if (tm->ckpair_index)
    {
      vnet_app_del_cert_key_pair (tm->ckpair_index);
      tm->ckpair_index = 0;
    }
  tm->ca_trust_index = 0;
  tm->crypto_is_configured = 0;

  {
    u8 *default_server_name = format (0, "localhost");
    rv = tlsctrl_phase3b_set_runtime (addr, port, default_server_name);
    vec_free (default_server_name);
    if (rv)
      return rv;
  }
  rv = tlsctrl_phase3b_set_listener_pem (server_cert_pem, server_key_pem, ca_cert_pem);
  if (rv)
    return rv;

  if (!tm->enabled)
    {
      rv = tlsctrl_phase3b_enable ();
      if (rv)
        return rv;
    }
  if (!tm->attached)
    {
      rv = tlsctrl_phase3b_attach ();
      if (rv)
        return rv;
    }

  return tlsctrl_phase3b_listen_enable ();
}
