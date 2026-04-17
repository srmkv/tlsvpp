#ifndef included_radius_h
#define included_radius_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vppinfra/time.h>

#include "radius_service.h"

typedef struct {
  u8 name[64];
  ip46_address_t ip;
  ip46_address_t src_ip;
  u32 fib_index;
  u32 sw_if_index;
  u16 port;
  u16 timeout_sec;
  u16 retries;
  u8 secret[128];
  u8 nas_id[128];
  u8 enabled;
} radius_server_t;

typedef struct {
  u64 txn_id;
  u32 provider_index;
  u32 consumer_index;
  u64 opaque_cookie;
  f64 created_at;
  f64 deadline_at;
  u8 identifier;
  u8 request_authenticator[16];
  u8 *username;
  u8 *state;
} radius_pending_req_t;

typedef struct {
  u8 *name;
  radius_consumer_vft_t vft;
} radius_consumer_t;

typedef struct {
  radius_result_code_t result_code;
  f64 at;
  u8 provider_name[64];
  u8 username[128];
  u8 reply_message[256];
  u8 filter_id[128];
  u32 session_timeout;
  u32 idle_timeout;
  u32 state_len;
} radius_last_event_t;

typedef struct {
  u64 requests;
  u64 accepts;
  u64 rejects;
  u64 challenges;
  u64 timeouts;
  u64 errors;
} radius_stats_t;

typedef struct {
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  radius_server_t *servers;
  radius_pending_req_t *pending;
  uword *pending_by_txn;
  radius_consumer_t *consumers;

  radius_stats_t stats;
  radius_last_event_t last_event;
  u64 next_txn_id;
  u16 local_src_port;
  u16 msg_id_base;
  u8 plugin_enabled;
} radius_main_t;

extern radius_main_t radius_main;

void radius_dispatch_result(radius_auth_res_t *res);
int radius_find_provider_by_name(const u8 *name);
int radius_provider_set(radius_server_t *server);
void radius_record_event(radius_pending_req_t *pr, radius_auth_res_t *res);
int radius_transport_send_access_request(radius_pending_req_t *pr,
                                         radius_server_t *provider,
                                         const u8 *password,
                                         const u8 *nas_id);
void radius_check_timeouts(vlib_main_t *vm);

#endif
