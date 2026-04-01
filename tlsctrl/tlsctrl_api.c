/* SPDX-License-Identifier: Apache-2.0 */

#include <tlsctrl/tlsctrl.h>

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <string.h>

#include <tlsctrl/tlsctrl.api_enum.h>
#include <tlsctrl/tlsctrl.api_types.h>

#define REPLY_MSG_ID_BASE (tlsctrl_main.msg_id_base)
#include <vlibapi/api_helper_macros.h>

static u8 *
tlsctrl_api_str_dup (const u8 *src, u32 max_len)
{
  u32 len = strnlen ((const char *) src, max_len);
  u8 *dst = 0;
  vec_validate (dst, len);
  if (len)
    clib_memcpy_fast (dst, src, len);
  dst[len] = 0;
  return dst;
}

static void
tlsctrl_api_str_free (u8 **v)
{
  if (*v)
    vec_free (*v);
  *v = 0;
}

static void
vl_api_tlsctrl_user_add_del_t_handler (vl_api_tlsctrl_user_add_del_t *mp)
{
  vl_api_tlsctrl_user_add_del_reply_t *rmp;
  u8 *username = tlsctrl_api_str_dup (mp->username, sizeof (mp->username));
  u8 *cert_serial = tlsctrl_api_str_dup (mp->cert_serial, sizeof (mp->cert_serial));
  int rv;

  if (mp->is_add)
    rv = tlsctrl_user_add_or_update (username, cert_serial, mp->enabled);
  else
    rv = tlsctrl_user_delete (username);

  tlsctrl_api_str_free (&username);
  tlsctrl_api_str_free (&cert_serial);
  REPLY_MACRO (VL_API_TLSCTRL_USER_ADD_DEL_REPLY);
}

static void
vl_api_tlsctrl_user_reissue_t_handler (vl_api_tlsctrl_user_reissue_t *mp)
{
  vl_api_tlsctrl_user_reissue_reply_t *rmp;
  u8 *username = tlsctrl_api_str_dup (mp->username, sizeof (mp->username));
  u8 *cert_serial = tlsctrl_api_str_dup (mp->cert_serial, sizeof (mp->cert_serial));
  int rv = tlsctrl_user_reissue (username, cert_serial);

  tlsctrl_api_str_free (&username);
  tlsctrl_api_str_free (&cert_serial);
  REPLY_MACRO (VL_API_TLSCTRL_USER_REISSUE_REPLY);
}

typedef struct
{
  vl_api_registration_t *rp;
  u32 context;
} tlsctrl_dump_walk_ctx_t;

typedef struct
{
  u8 username[128];
  u8 cert_serial[256];
  u8 enabled;
  u64 generation;
  u64 last_seen_unix_ns;
} tlsctrl_user_snapshot_t;

typedef struct
{
  u8 username[128];
  u8 cert_serial[256];
  u8 system_user[128];
  u8 os_name[64];
  u8 os_version[128];
  u8 system_uptime[128];
  u8 ip[64];
  u8 mac[64];
  u8 source[64];
  u8 interfaces_json[8192];
  u8 status;
  u64 connected_at_unix_ns;
  u64 last_seen_unix_ns;
  u64 apps_updated_at_unix_ns;
  u32 apps_count;
} tlsctrl_session_snapshot_t;

static void
tlsctrl_copy_cstr_field (u8 *dst, u32 dst_len, u8 *src)
{
  if (!dst || dst_len == 0)
    return;
  clib_memset (dst, 0, dst_len);
  if (!src)
    return;
  strncpy ((char *) dst, (char *) src, dst_len - 1);
}

static void
tlsctrl_make_user_snapshot (tlsctrl_user_snapshot_t *snap, tlsctrl_client_t *client)
{
  clib_memset (snap, 0, sizeof (*snap));
  tlsctrl_copy_cstr_field (snap->username, sizeof (snap->username), client->username);
  tlsctrl_copy_cstr_field (snap->cert_serial, sizeof (snap->cert_serial), client->cert_serial);
  snap->enabled = client->enabled;
  snap->generation = client->generation;
  snap->last_seen_unix_ns = client->user_last_seen;
}

static void
tlsctrl_make_session_snapshot (tlsctrl_session_snapshot_t *snap,
                               tlsctrl_client_t *client)
{
  clib_memset (snap, 0, sizeof (*snap));
  tlsctrl_copy_cstr_field (snap->username, sizeof (snap->username), client->username);
  tlsctrl_copy_cstr_field (snap->cert_serial, sizeof (snap->cert_serial), client->cert_serial);
  tlsctrl_copy_cstr_field (snap->system_user, sizeof (snap->system_user), client->system_user);
  tlsctrl_copy_cstr_field (snap->os_name, sizeof (snap->os_name), client->os_name);
  tlsctrl_copy_cstr_field (snap->os_version, sizeof (snap->os_version), client->os_version);
  tlsctrl_copy_cstr_field (snap->system_uptime, sizeof (snap->system_uptime), client->system_uptime);
  tlsctrl_copy_cstr_field (snap->ip, sizeof (snap->ip), client->ip);
  tlsctrl_copy_cstr_field (snap->mac, sizeof (snap->mac), client->mac);
  tlsctrl_copy_cstr_field (snap->source, sizeof (snap->source), client->source);
  tlsctrl_copy_cstr_field (snap->interfaces_json, sizeof (snap->interfaces_json), client->interfaces_json);
  snap->status = (client->enabled && client->last_seen_unix_ns && !client->admin_disconnected) ? 1 : 0;
  snap->connected_at_unix_ns = client->connected_at_unix_ns;
  snap->last_seen_unix_ns = client->last_seen_unix_ns;
  snap->apps_updated_at_unix_ns = client->apps_updated_at_unix_ns;
  snap->apps_count = client->apps_count;
}

static void
vl_api_tlsctrl_user_dump_t_handler (vl_api_tlsctrl_user_dump_t *mp)
{
  tlsctrl_client_t *client;
  tlsctrl_dump_walk_ctx_t ctx;
  tlsctrl_main_t *tm = &tlsctrl_main;
  vl_api_registration_t *rp;
  tlsctrl_user_snapshot_t *snaps = 0, *snap;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (!rp)
    return;

  ctx.rp = rp;
  ctx.context = mp->context;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  pool_foreach (client, tm->clients)
    {
      vec_add2 (snaps, snap, 1);
      tlsctrl_make_user_snapshot (snap, client);
    }
  clib_spinlock_unlock_if_init (&tm->clients_lock);

  vec_foreach (snap, snaps)
    {
      vl_api_tlsctrl_user_details_t *rmp = vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id = ntohs (VL_API_TLSCTRL_USER_DETAILS + tm->msg_id_base);
      rmp->context = ctx.context;
      strncpy ((char *) rmp->username, (char *) snap->username,
               sizeof (rmp->username) - 1);
      strncpy ((char *) rmp->cert_serial, (char *) snap->cert_serial,
               sizeof (rmp->cert_serial) - 1);
      rmp->enabled = snap->enabled;
      rmp->generation = clib_host_to_net_u64 (snap->generation);
      rmp->last_seen_unix_ns = clib_host_to_net_u64 (snap->last_seen_unix_ns);
      vl_api_send_msg (rp, (u8 *) rmp);
    }
  vec_free (snaps);
}

static void
vl_api_tlsctrl_session_dump_t_handler (vl_api_tlsctrl_session_dump_t *mp)
{
  tlsctrl_client_t *client;
  tlsctrl_dump_walk_ctx_t ctx;
  tlsctrl_main_t *tm = &tlsctrl_main;
  vl_api_registration_t *rp;
  tlsctrl_session_snapshot_t *snaps = 0, *snap;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (!rp)
    return;

  ctx.rp = rp;
  ctx.context = mp->context;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  pool_foreach (client, tm->clients)
    {
      vec_add2 (snaps, snap, 1);
      tlsctrl_make_session_snapshot (snap, client);
    }
  clib_spinlock_unlock_if_init (&tm->clients_lock);

  vec_foreach (snap, snaps)
    {
      vl_api_tlsctrl_session_details_t *rmp = vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id = ntohs (VL_API_TLSCTRL_SESSION_DETAILS + tm->msg_id_base);
      rmp->context = ctx.context;
      strncpy ((char *) rmp->username, (char *) snap->username,
               sizeof (rmp->username) - 1);
      strncpy ((char *) rmp->cert_serial, (char *) snap->cert_serial,
               sizeof (rmp->cert_serial) - 1);
      strncpy ((char *) rmp->system_user, (char *) snap->system_user,
               sizeof (rmp->system_user) - 1);
      strncpy ((char *) rmp->os_name, (char *) snap->os_name,
               sizeof (rmp->os_name) - 1);
      strncpy ((char *) rmp->os_version, (char *) snap->os_version,
               sizeof (rmp->os_version) - 1);
      strncpy ((char *) rmp->system_uptime, (char *) snap->system_uptime,
               sizeof (rmp->system_uptime) - 1);
      strncpy ((char *) rmp->ip, (char *) snap->ip,
               sizeof (rmp->ip) - 1);
      strncpy ((char *) rmp->mac, (char *) snap->mac,
               sizeof (rmp->mac) - 1);
      strncpy ((char *) rmp->source, (char *) snap->source,
               sizeof (rmp->source) - 1);
      strncpy ((char *) rmp->interfaces_json, (char *) snap->interfaces_json,
               sizeof (rmp->interfaces_json) - 1);
      rmp->status = snap->status;
      rmp->connected_at_unix_ns = clib_host_to_net_u64 (snap->connected_at_unix_ns);
      rmp->last_seen_unix_ns = clib_host_to_net_u64 (snap->last_seen_unix_ns);
      rmp->apps_updated_at_unix_ns = clib_host_to_net_u64 (snap->apps_updated_at_unix_ns);
      rmp->apps_count = clib_host_to_net_u32 (snap->apps_count);
      vl_api_send_msg (rp, (u8 *) rmp);
    }
  vec_free (snaps);
}

static void
vl_api_tlsctrl_session_disconnect_t_handler (vl_api_tlsctrl_session_disconnect_t *mp)
{
  vl_api_tlsctrl_session_disconnect_reply_t *rmp;
  u8 *username = tlsctrl_api_str_dup (mp->username, sizeof (mp->username));
  int rv = tlsctrl_session_disconnect_username (username);
  tlsctrl_api_str_free (&username);
  REPLY_MACRO (VL_API_TLSCTRL_SESSION_DISCONNECT_REPLY);
}

static void
vl_api_tlsctrl_client_command_set_t_handler (vl_api_tlsctrl_client_command_set_t *mp)
{
  vl_api_tlsctrl_client_command_set_reply_t *rmp;
  u8 *username = tlsctrl_api_str_dup (mp->username, sizeof (mp->username));
  u8 *command_type = tlsctrl_api_str_dup (mp->command_type, sizeof (mp->command_type));
  u8 *payload = tlsctrl_api_str_dup (mp->payload, sizeof (mp->payload));
  int rv = tlsctrl_client_command_set (username, command_type, payload);
  tlsctrl_api_str_free (&username);
  tlsctrl_api_str_free (&command_type);
  tlsctrl_api_str_free (&payload);
  REPLY_MACRO (VL_API_TLSCTRL_CLIENT_COMMAND_SET_REPLY);
}

static void
vl_api_tlsctrl_client_command_get_t_handler (vl_api_tlsctrl_client_command_get_t *mp)
{
  vl_api_tlsctrl_client_command_get_reply_t *rmp;
  u8 *username = tlsctrl_api_str_dup (mp->username, sizeof (mp->username));
  u8 *command_type = 0, *payload = 0;
  int rv = 0;

  tlsctrl_client_command_get (username, &command_type, &payload);
  tlsctrl_api_str_free (&username);

  REPLY_MACRO2 (VL_API_TLSCTRL_CLIENT_COMMAND_GET_REPLY,
                ({
                  if (command_type)
                    strncpy ((char *) rmp->command_type, (char *) command_type,
                             sizeof (rmp->command_type) - 1);
                  if (payload)
                    strncpy ((char *) rmp->payload, (char *) payload,
                             sizeof (rmp->payload) - 1);
                }));
  tlsctrl_api_str_free (&command_type);
  tlsctrl_api_str_free (&payload);
}

static void
vl_api_tlsctrl_client_heartbeat_t_handler (vl_api_tlsctrl_client_heartbeat_t *mp)
{
  vl_api_tlsctrl_client_heartbeat_reply_t *rmp;
  u8 *username = tlsctrl_api_str_dup (mp->username, sizeof (mp->username));
  u8 *cert_serial = tlsctrl_api_str_dup (mp->cert_serial, sizeof (mp->cert_serial));
  u8 *system_user = tlsctrl_api_str_dup (mp->system_user, sizeof (mp->system_user));
  u8 *os_name = tlsctrl_api_str_dup (mp->os_name, sizeof (mp->os_name));
  u8 *os_version = tlsctrl_api_str_dup (mp->os_version, sizeof (mp->os_version));
  u8 *system_uptime = tlsctrl_api_str_dup (mp->system_uptime, sizeof (mp->system_uptime));
  u8 *ip = tlsctrl_api_str_dup (mp->ip, sizeof (mp->ip));
  u8 *mac = tlsctrl_api_str_dup (mp->mac, sizeof (mp->mac));
  u8 *source = tlsctrl_api_str_dup (mp->source, sizeof (mp->source));
  u8 *interfaces_json = tlsctrl_api_str_dup (mp->interfaces_json, sizeof (mp->interfaces_json));
  u8 *connect_intent = tlsctrl_api_str_dup (mp->connect_intent, sizeof (mp->connect_intent));
  int rv = tlsctrl_client_heartbeat_api (username, cert_serial, system_user,
                                         os_name, os_version, system_uptime,
                                         ip, mac, source, interfaces_json,
                                         connect_intent);

  tlsctrl_api_str_free (&username);
  tlsctrl_api_str_free (&cert_serial);
  tlsctrl_api_str_free (&system_user);
  tlsctrl_api_str_free (&os_name);
  tlsctrl_api_str_free (&os_version);
  tlsctrl_api_str_free (&system_uptime);
  tlsctrl_api_str_free (&ip);
  tlsctrl_api_str_free (&mac);
  tlsctrl_api_str_free (&source);
  tlsctrl_api_str_free (&interfaces_json);
  tlsctrl_api_str_free (&connect_intent);
  REPLY_MACRO (VL_API_TLSCTRL_CLIENT_HEARTBEAT_REPLY);
}

static void
vl_api_tlsctrl_client_apps_set_t_handler (vl_api_tlsctrl_client_apps_set_t *mp)
{
  vl_api_tlsctrl_client_apps_set_reply_t *rmp;
  u8 *username = tlsctrl_api_str_dup (mp->username, sizeof (mp->username));
  u8 *payload = tlsctrl_api_str_dup (mp->payload, sizeof (mp->payload));
  int rv = tlsctrl_client_apps_set_api (username, clib_net_to_host_u32 (mp->count),
                                        payload);
  tlsctrl_api_str_free (&username);
  tlsctrl_api_str_free (&payload);
  REPLY_MACRO (VL_API_TLSCTRL_CLIENT_APPS_SET_REPLY);
}

static void
vl_api_tlsctrl_client_apps_get_t_handler (vl_api_tlsctrl_client_apps_get_t *mp)
{
  vl_api_tlsctrl_client_apps_get_reply_t *rmp;
  u8 *username = tlsctrl_api_str_dup (mp->username, sizeof (mp->username));
  u8 *payload = 0;
  u32 count = 0;
  u64 generated_at_unix_ns = 0;
  int rv = 0;

  tlsctrl_client_apps_get (username, &count, &generated_at_unix_ns, &payload);
  tlsctrl_api_str_free (&username);

  REPLY_MACRO2 (VL_API_TLSCTRL_CLIENT_APPS_GET_REPLY,
                ({
                  rmp->count = clib_host_to_net_u32 (count);
                  rmp->generated_at_unix_ns = clib_host_to_net_u64 (generated_at_unix_ns);
                  if (payload)
                    strncpy ((char *) rmp->payload, (char *) payload,
                             sizeof (rmp->payload) - 1);
                }));
  tlsctrl_api_str_free (&payload);
}

static void
vl_api_tlsctrl_listener_config_set_t_handler (vl_api_tlsctrl_listener_config_set_t *mp)
{
  vl_api_tlsctrl_listener_config_set_reply_t *rmp;
  u8 *listen_addr = tlsctrl_api_str_dup (mp->listen_addr, sizeof (mp->listen_addr));
  u8 *server_cert = tlsctrl_api_str_dup (mp->server_cert_pem, sizeof (mp->server_cert_pem));
  u8 *server_key = tlsctrl_api_str_dup (mp->server_key_pem, sizeof (mp->server_key_pem));
  u8 *ca_cert = tlsctrl_api_str_dup (mp->ca_cert_pem, sizeof (mp->ca_cert_pem));
  int rv = tlsctrl_phase3b_apply_listener_config (listen_addr,
                                                  clib_net_to_host_u16 (mp->listen_port),
                                                  server_cert, server_key,
                                                  ca_cert);
  tlsctrl_api_str_free (&listen_addr);
  tlsctrl_api_str_free (&server_cert);
  tlsctrl_api_str_free (&server_key);
  tlsctrl_api_str_free (&ca_cert);
  REPLY_MACRO (VL_API_TLSCTRL_LISTENER_CONFIG_SET_REPLY);
}

#include <tlsctrl/tlsctrl.api.c>

static clib_error_t *
tlsctrl_api_init (vlib_main_t *vm)
{
  (void) vm;
  tlsctrl_main.msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_INIT_FUNCTION (tlsctrl_api_init);
