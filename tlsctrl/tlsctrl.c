/* SPDX-License-Identifier: Apache-2.0 */

#include <tlsctrl/tlsctrl.h>

#include <string.h>
#include <vpp/app/version.h>

tlsctrl_main_t tlsctrl_main;

static void
_tlsctrl_vec_reset (u8 **v)
{
  if (*v)
    vec_free (*v);
  *v = 0;
}

void
tlsctrl_client_free_fields (tlsctrl_client_t *client)
{
  _tlsctrl_vec_reset (&client->username);
  _tlsctrl_vec_reset (&client->cert_serial);
  _tlsctrl_vec_reset (&client->command_type);
  _tlsctrl_vec_reset (&client->command_payload);
  _tlsctrl_vec_reset (&client->system_user);
  _tlsctrl_vec_reset (&client->os_name);
  _tlsctrl_vec_reset (&client->os_version);
  _tlsctrl_vec_reset (&client->system_uptime);
  _tlsctrl_vec_reset (&client->ip);
  _tlsctrl_vec_reset (&client->mac);
  _tlsctrl_vec_reset (&client->source);
  _tlsctrl_vec_reset (&client->connect_intent);
  _tlsctrl_vec_reset (&client->interfaces_json);
  _tlsctrl_vec_reset (&client->last_apps_json);
}

void
tlsctrl_reset_counters (void)
{
  tlsctrl_main_t *tm = &tlsctrl_main;

  tm->accepted_connections = 0;
  tm->disconnected_connections = 0;
  tm->reset_connections = 0;
  tm->rx_callbacks = 0;
  tm->tx_callbacks = 0;
  tm->rx_bytes = 0;
  tm->tx_bytes = 0;
  tm->http_2xx_responses = 0;
  tm->http_4xx_responses = 0;
  tm->http_5xx_responses = 0;
  tm->parse_errors = 0;
}

void
tlsctrl_reset_conn_pools (void)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_conn_t **poolp;
  tlsctrl_conn_t *conn;

  vec_foreach (poolp, tm->conn_pool_by_thread)
    {
      if (!*poolp)
        continue;
      pool_foreach (conn, *poolp)
        {
          vec_free (conn->request_data);
          vec_free (conn->response_data);
        }
      pool_free (*poolp);
    }

  vec_free (tm->conn_pool_by_thread);
  tm->conn_pool_by_thread = 0;
}

void
tlsctrl_reset_clients (void)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tlsctrl_client_t *client;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  if (tm->clients)
    {
      pool_foreach (client, tm->clients)
        { tlsctrl_client_free_fields (client); }
      pool_free (tm->clients);
      tm->clients = 0;
    }
  clib_spinlock_unlock_if_init (&tm->clients_lock);
}

u8 *
format_tlsctrl_phase3b_state (u8 *s, va_list *args)
{
  tlsctrl_main_t *tm = va_arg (*args, tlsctrl_main_t *);

  s = format (s, "enabled: %s\n", tm->enabled ? "yes" : "no");
  s = format (s, "attached: %s\n", tm->attached ? "yes" : "no");
  s = format (s, "listening: %s\n", tm->listening ? "yes" : "no");
  s = format (s, "session-layer-enabled: %s\n",
              tm->session_layer_enabled ? "yes" : "no");
  s = format (s, "runtime-configured: %s\n",
              tm->runtime_is_configured ? "yes" : "no");
  s = format (s, "crypto-configured: %s\n",
              tm->crypto_is_configured ? "yes" : "no");
  s = format (s, "app-index: %u\n", tm->app_index);
  s = format (s, "listener-handle: 0x%llx\n",
              (unsigned long long) tm->listener_handle);
  s = format (s, "tls-engine: %U\n", format_crypto_engine, tm->tls_engine);
  s = format (s, "ckpair-index: %u\n", tm->ckpair_index);
  s = format (s, "ca-trust-index: %u\n", tm->ca_trust_index);
  s = format (s, "runtime-addr: %s\n",
              tm->runtime_addr ? (char *) tm->runtime_addr : "-");
  s = format (s, "runtime-port: %u\n", tm->runtime_is_configured ? tm->runtime_port : 0);
  s = format (s, "server-name: %s\n",
              tm->server_name ? (char *) tm->server_name : "-");
  s = format (s, "server-cert-pem-len: %u\n",
              tm->server_cert_pem ? vec_len (tm->server_cert_pem) : 0);
  s = format (s, "server-key-pem-len: %u\n",
              tm->server_key_pem ? vec_len (tm->server_key_pem) : 0);
  s = format (s, "ca-cert-pem-len: %u\n",
              tm->ca_cert_pem ? vec_len (tm->ca_cert_pem) : 0);
  s = format (s, "accepted-connections: %llu\n",
              (unsigned long long) tm->accepted_connections);
  s = format (s, "disconnected-connections: %llu\n",
              (unsigned long long) tm->disconnected_connections);
  s = format (s, "reset-connections: %llu\n",
              (unsigned long long) tm->reset_connections);
  s = format (s, "rx-callbacks: %llu\n",
              (unsigned long long) tm->rx_callbacks);
  s = format (s, "tx-callbacks: %llu\n",
              (unsigned long long) tm->tx_callbacks);
  s = format (s, "rx-bytes: %llu\n",
              (unsigned long long) tm->rx_bytes);
  s = format (s, "tx-bytes: %llu\n",
              (unsigned long long) tm->tx_bytes);
  s = format (s, "http-2xx-responses: %llu\n",
              (unsigned long long) tm->http_2xx_responses);
  s = format (s, "http-4xx-responses: %llu\n",
              (unsigned long long) tm->http_4xx_responses);
  s = format (s, "http-5xx-responses: %llu\n",
              (unsigned long long) tm->http_5xx_responses);
  s = format (s, "parse-errors: %llu\n",
              (unsigned long long) tm->parse_errors);
  s = format (s, "known-users: %u\n",
              tm->clients ? pool_elts (tm->clients) : 0);

  return s;
}

u8 *
format_tlsctrl_phase3b_clients (u8 *s, va_list *args)
{
  tlsctrl_main_t *tm = va_arg (*args, tlsctrl_main_t *);
  tlsctrl_client_t *client;

  clib_spinlock_lock_if_init (&tm->clients_lock);

  if (!tm->clients || !pool_elts (tm->clients))
    {
      s = format (s, "no clients\n");
      goto done;
    }

  pool_foreach (client, tm->clients)
    {
      s = format (s,
                  "username=%s enabled=%u status=%s heartbeat=%llu apps=%u last_seen_ns=%llu ip=%s command=%s\n",
                  client->username ? (char *) client->username : "-",
                  client->enabled,
                  (client->enabled && client->last_seen_unix_ns &&
                   !client->admin_disconnected)
                    ? "connected"
                    : (client->admin_disconnected ? "admin-blocked"
                                                  : "disconnected"),
                  (unsigned long long) client->heartbeat_count,
                  client->apps_count,
                  (unsigned long long) client->last_seen_unix_ns,
                  client->ip ? (char *) client->ip : "-",
                  client->command_type ? (char *) client->command_type : "-");
    }

done:
  clib_spinlock_unlock_if_init (&tm->clients_lock);
  return s;
}

u8 *
format_tlsctrl_phase3b_users (u8 *s, va_list *args)
{
  tlsctrl_main_t *tm = va_arg (*args, tlsctrl_main_t *);
  tlsctrl_client_t *client;

  clib_spinlock_lock_if_init (&tm->clients_lock);
  if (!tm->clients || !pool_elts (tm->clients))
    {
      s = format (s, "no users\n");
      goto done;
    }

  pool_foreach (client, tm->clients)
    {
      s = format (s,
                  "username=%s enabled=%u generation=%llu cert_serial=%s admin_blocked=%u command=%s last_seen_ns=%llu\n",
                  client->username ? (char *) client->username : "-",
                  client->enabled,
                  (unsigned long long) client->generation,
                  client->cert_serial ? (char *) client->cert_serial : "-",
                  client->admin_disconnected,
                  client->command_type ? (char *) client->command_type : "-",
                  (unsigned long long) client->user_last_seen);
    }

done:
  clib_spinlock_unlock_if_init (&tm->clients_lock);
  return s;
}

int
tlsctrl_phase3b_enable (void)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  session_enable_disable_args_t args = { 0 };
  clib_error_t *error;

  tm->enabled = 1;
  if (tm->session_layer_enabled)
    return 0;

  args.is_en = 1;
  args.rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE;
  error = vnet_session_enable_disable (tm->vlib_main, &args);
  if (error)
    {
      clib_error_free (error);
      return -1;
    }
  tm->session_layer_enabled = 1;
  return 0;
}

int
tlsctrl_phase3b_disable (void)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  int rv;

  if (tm->listening)
    {
      rv = tlsctrl_phase3b_listen_disable ();
      if (rv)
        return rv;
    }

  if (tm->attached)
    {
      rv = tlsctrl_phase3b_detach ();
      if (rv)
        return rv;
    }

  tm->enabled = 0;
  return 0;
}

static void
_tlsctrl_set_vec_from_vec (u8 **dst, const u8 *src)
{
  u32 len;
  _tlsctrl_vec_reset (dst);
  if (!src)
    return;
  len = vec_len ((u8 *) src);
  *dst = 0;
  vec_validate (*dst, len);
  if (len)
    clib_memcpy_fast (*dst, src, len);
  (*dst)[len] = 0;
}


int
tlsctrl_phase3b_set_runtime (u8 *addr, u16 port, u8 *server_name)
{
  tlsctrl_main_t *tm = &tlsctrl_main;

  if (!addr || !vec_len (addr) || port == 0)
    return -1;

  _tlsctrl_set_vec_from_vec (&tm->runtime_addr, addr);
  _tlsctrl_set_vec_from_vec (&tm->server_name, server_name);
  tm->runtime_port = port;
  tm->runtime_is_configured = 1;
  return 0;
}

int
tlsctrl_phase3b_set_listener_pem (u8 *server_cert_pem, u8 *server_key_pem,
                                  u8 *ca_cert_pem)
{
  tlsctrl_main_t *tm = &tlsctrl_main;

  if (!server_cert_pem || !vec_len (server_cert_pem) || !server_key_pem ||
      !vec_len (server_key_pem) || !ca_cert_pem || !vec_len (ca_cert_pem))
    return -1;

  _tlsctrl_set_vec_from_vec (&tm->server_cert_pem, server_cert_pem);
  _tlsctrl_set_vec_from_vec (&tm->server_key_pem, server_key_pem);
  _tlsctrl_set_vec_from_vec (&tm->ca_cert_pem, ca_cert_pem);
  tm->crypto_is_configured = 0;
  return 0;
}

static clib_error_t *
tlsctrl_init (vlib_main_t *vm)
{
  tlsctrl_main_t *tm = &tlsctrl_main;

  tm->vlib_main = vm;
  tm->app_index = APP_INVALID_INDEX;
  tm->listener_handle = SESSION_INVALID_HANDLE;
  tm->tls_engine = CRYPTO_ENGINE_OPENSSL;
  clib_spinlock_init (&tm->clients_lock);
  tlsctrl_reset_counters ();
  return 0;
}

VLIB_INIT_FUNCTION (tlsctrl_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "TLSCTRL phase3b GovPP runtime PEM",
  .default_disabled = 1,
};
