#include <vlib/unix/plugin.h>
#include <vnet/udp/udp.h>
#include "radius.h"
#include "radius_pending.h"
#include "radius_transport.h"

radius_main_t radius_main;
extern vlib_node_registration_t radius_reply_node;

static int
radius_find_provider_by_fixed_name(const u8 *name)
{
  radius_main_t *rm = &radius_main;
  radius_server_t *s;
  int i;
  uword want;

  if (!name)
    return -1;

  want = strnlen((const char *) name, 64);
  if (want == 0)
    return -1;

  vec_foreach_index(i, rm->servers) {
    uword have;
    s = vec_elt_at_index(rm->servers, i);
    have = strnlen((char *) s->name, sizeof(s->name));
    if (have == want && clib_memcmp(s->name, name, want) == 0)
      return i;
  }
  return -1;
}

int
radius_find_provider_by_name(const u8 *name)
{
  radius_main_t *rm = &radius_main;
  radius_server_t *s;
  int i;
  uword want;

  if (!name)
    return -1;

  want = vec_len((u8 *) name);
  if (want == 0)
    return -1;
  if (((u8 *) name)[want - 1] == 0)
    want--;
  if (want == 0)
    return -1;

  vec_foreach_index(i, rm->servers) {
    uword have;
    s = vec_elt_at_index(rm->servers, i);
    have = strnlen((char *) s->name, sizeof(s->name));
    if (have == want && clib_memcmp(s->name, name, want) == 0)
      return i;
  }
  return -1;
}

int
radius_provider_set(radius_server_t *server)
{
  radius_main_t *rm = &radius_main;
  int idx = radius_find_provider_by_fixed_name(server->name);
  if (idx >= 0) {
    clib_memcpy(vec_elt_at_index(rm->servers, idx), server, sizeof(*server));
    return idx;
  }
  vec_add1(rm->servers, *server);
  return vec_len(rm->servers) - 1;
}

static void
radius_timeout_walk(vlib_main_t *vm)
{
  radius_main_t *rm = &radius_main;
  radius_pending_req_t *pr;
  f64 now = vlib_time_now(vm);
  pool_foreach(pr, rm->pending) {
    if (pr->deadline_at <= now) {
      radius_auth_res_t res = {
        .result_code = RADIUS_RESULT_TIMEOUT,
        .opaque_cookie = pr->opaque_cookie,
        .txn_id = pr->txn_id,
      };
      rm->stats.timeouts++;
      res.reply_message = (u8 *) "timeout";
      radius_record_event(pr, &res);
      radius_dispatch_result(&res);
      radius_pending_remove(pr->txn_id);
      break;
    }
  }
}

void
radius_check_timeouts(vlib_main_t *vm)
{
  radius_timeout_walk(vm);
}

int
radius_register_consumer(const char *name, radius_consumer_vft_t *vft,
                         u32 *consumer_index)
{
  radius_main_t *rm = &radius_main;
  radius_consumer_t c = {0};
  c.name = format(0, "%s%c", name, 0);
  c.vft = *vft;
  vec_add1(rm->consumers, c);
  if (consumer_index)
    *consumer_index = vec_len(rm->consumers) - 1;
  return 0;
}

void
radius_record_event(radius_pending_req_t *pr, radius_auth_res_t *res)
{
  radius_main_t *rm = &radius_main;
  radius_server_t *provider = 0;
  uword username_len = 0;
  uword reply_len = 0;
  uword filter_len = 0;

  clib_memset(&rm->last_event, 0, sizeof(rm->last_event));
  rm->last_event.result_code = res ? res->result_code : RADIUS_RESULT_ERROR;
  rm->last_event.at = 1.0;

  if (pr) {
    if (pr->provider_index < vec_len(rm->servers))
      provider = vec_elt_at_index(rm->servers, pr->provider_index);
    if (provider)
      clib_memcpy(rm->last_event.provider_name, provider->name, sizeof(rm->last_event.provider_name));
    if (pr->username) {
      username_len = vec_len(pr->username);
      if (username_len && pr->username[username_len - 1] == 0)
        username_len--;
      clib_memcpy(rm->last_event.username, pr->username,
                  clib_min(username_len, (uword)(sizeof(rm->last_event.username) - 1)));
    }
  }

  if (res) {
    if (res->reply_message) {
      reply_len = vec_len(res->reply_message);
      clib_memcpy(rm->last_event.reply_message, res->reply_message,
                  clib_min(reply_len, (uword)(sizeof(rm->last_event.reply_message) - 1)));
    }
    if (res->filter_id) {
      filter_len = vec_len(res->filter_id);
      clib_memcpy(rm->last_event.filter_id, res->filter_id,
                  clib_min(filter_len, (uword)(sizeof(rm->last_event.filter_id) - 1)));
    }
    rm->last_event.session_timeout = res->session_timeout;
    rm->last_event.idle_timeout = res->idle_timeout;
    rm->last_event.state_len = res->state ? vec_len(res->state) : 0;
  }
}

void
radius_dispatch_result(radius_auth_res_t *res)
{
  radius_main_t *rm = &radius_main;
  if (res->txn_id == 0)
    return;
  /* opaque consumer resolution can be extended if needed */
  if (vec_len(rm->consumers) == 0)
    return;
  /* scaffold: fan-out by consumer_index would be cleaner after embedding */
  if (rm->consumers[0].vft.auth_result_fn)
    rm->consumers[0].vft.auth_result_fn(res);
}

int
radius_auth_start(radius_auth_req_t *req, u64 *txn_id)
{
  radius_main_t *rm = &radius_main;
  radius_pending_req_t *pr;
  radius_server_t *provider;

  if (!req)
    return -1;
  if (req->provider_index >= vec_len(rm->servers))
    return -2;

  provider = vec_elt_at_index(rm->servers, req->provider_index);
  pr = radius_pending_add(req, txn_id);
  pr->deadline_at = vlib_time_now(rm->vlib_main) + provider->timeout_sec;

  rm->stats.requests++;
  return radius_transport_send_access_request(pr, provider, req->password,
                                              req->nas_id);
}

int
radius_auth_continue(radius_auth_req_t *req, u64 txn_id)
{
  if (!radius_pending_get(txn_id))
    return -1;
  req->state = vec_dup(req->state);
  return radius_auth_start(req, 0);
}

static clib_error_t *
radius_init(vlib_main_t *vm)
{
  radius_main_t *rm = &radius_main;
  rm->vlib_main = vm;
  rm->vnet_main = vnet_get_main();
  rm->next_txn_id = 1000;
  rm->local_src_port = 49152;
  rm->plugin_enabled = 1;
  udp_register_dst_port(vm, rm->local_src_port, radius_reply_node.index, 1 /* is_ip4 */);
  return 0;
}

VLIB_INIT_FUNCTION(radius_init);

static uword
radius_process(vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  while (1) {
    vlib_process_wait_for_event_or_clock(vm, 1.0);
    radius_check_timeouts(vm);
  }
  return 0;
}

VLIB_REGISTER_NODE(radius_process_node) = {
  .function = radius_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "radius-process",
};

VLIB_PLUGIN_REGISTER () = {
  .version = "0.1.0",
  .description = "Standalone RADIUS AAA service",
};
