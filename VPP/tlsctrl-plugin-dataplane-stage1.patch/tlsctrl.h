/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_tlsctrl_h
#define included_tlsctrl_h

#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/application_crypto.h>
#include <vnet/session/session.h>

#define TLSCTRL_PHASE3B_APP_NAME "tlsctrl_phase3b"

#define TLSCTRL_HTTP_HDR_END "\r\n\r\n"

typedef struct
{
  session_handle_t session_handle;
  u32 session_index;
  u8 close_requested;
  u8 response_ready;
  u8 response_complete;
  u32 tx_offset;
  u64 rx_bytes;
  u64 tx_bytes;
  u8 *request_data;
  u8 *response_data;
} tlsctrl_conn_t;

typedef struct
{
  u8 *username;
  u8 *cert_serial;
  u8 enabled;
  u64 generation;
  u64 user_last_seen;

  u8 *command_type;
  u8 *command_payload;
  u8 admin_disconnected;

  u8 *system_user;
  u8 *os_name;
  u8 *os_version;
  u8 *system_uptime;
  u8 *ip;
  u8 *mac;
  u8 *source;
  u8 *connect_intent;
  u8 *interfaces_json;
  u8 *last_apps_json;

  u64 heartbeat_count;
  u64 apps_report_count;
  u32 apps_count;
  u64 connected_at_unix_ns;
  u64 last_seen_unix_ns;
  u64 apps_updated_at_unix_ns;
} tlsctrl_client_t;

typedef struct
{
  vlib_main_t *vlib_main;

  u8 enabled;
  u8 attached;
  u8 listening;
  u8 session_layer_enabled;
  u8 runtime_is_configured;
  u8 crypto_is_configured;

  u32 app_index;
  session_handle_t listener_handle;
  u32 ckpair_index;
  u32 ca_trust_index;
  u8 tls_engine;
  u16 msg_id_base;

  u8 *runtime_addr;
  u16 runtime_port;
  u8 *server_name;

  u8 *server_cert_pem;
  u8 *server_key_pem;
  u8 *ca_cert_pem;

  tlsctrl_conn_t **conn_pool_by_thread;
  tlsctrl_client_t *clients;
  clib_spinlock_t clients_lock;

  u64 accepted_connections;
  u64 disconnected_connections;
  u64 reset_connections;
  u64 rx_callbacks;
  u64 tx_callbacks;
  u64 rx_bytes;
  u64 tx_bytes;
  u64 http_2xx_responses;
  u64 http_4xx_responses;
  u64 http_5xx_responses;
  u64 parse_errors;
} tlsctrl_main_t;

extern tlsctrl_main_t tlsctrl_main;

void tlsctrl_client_free_fields (tlsctrl_client_t *client);
void tlsctrl_reset_counters (void);
void tlsctrl_reset_conn_pools (void);
void tlsctrl_reset_clients (void);

int tlsctrl_phase3b_enable (void);
int tlsctrl_phase3b_disable (void);
int tlsctrl_phase3b_set_runtime (u8 *addr, u16 port, u8 *server_name);
int tlsctrl_phase3b_set_listener_pem (u8 *server_cert_pem, u8 *server_key_pem,
                                      u8 *ca_cert_pem);
int tlsctrl_phase3b_load_pem_files (u8 *cert_file, u8 *key_file, u8 *ca_file);
int tlsctrl_phase3b_apply_listener_config (u8 *addr, u16 port,
                                           u8 *server_cert_pem,
                                           u8 *server_key_pem,
                                           u8 *ca_cert_pem);
int tlsctrl_phase3b_attach (void);
int tlsctrl_phase3b_detach (void);
int tlsctrl_phase3b_listen_enable (void);
int tlsctrl_phase3b_listen_disable (void);

int tlsctrl_user_add_or_update (u8 *username, u8 *cert_serial, u8 enabled);
int tlsctrl_user_delete (u8 *username);
int tlsctrl_user_reissue (u8 *username, u8 *cert_serial);
int tlsctrl_session_disconnect_username (u8 *username);
int tlsctrl_client_command_set (u8 *username, u8 *command_type, u8 *payload);
void tlsctrl_client_command_get (u8 *username, u8 **command_type, u8 **payload);
int tlsctrl_client_heartbeat_api (u8 *username, u8 *cert_serial,
                                  u8 *system_user, u8 *os_name,
                                  u8 *os_version, u8 *system_uptime, u8 *ip,
                                  u8 *mac, u8 *source, u8 *interfaces_json,
                                  u8 *connect_intent);
int tlsctrl_client_apps_set_api (u8 *username, u32 count, u8 *payload);
void tlsctrl_client_apps_get (u8 *username, u32 *count, u64 *generated_at_unix_ns,
                              u8 **payload);
int tlsctrl_phase3b_client_set_disconnected (u8 *username, u8 is_disconnected);

u8 *format_tlsctrl_phase3b_state (u8 *s, va_list *args);
u8 *format_tlsctrl_phase3b_clients (u8 *s, va_list *args);
u8 *format_tlsctrl_phase3b_users (u8 *s, va_list *args);

#endif /* included_tlsctrl_h */
