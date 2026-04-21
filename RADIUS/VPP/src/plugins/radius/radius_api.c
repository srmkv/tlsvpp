#include "radius.h"
#include "radius_pending.h"

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/api_errno.h>

#include <radius/radius.api_enum.h>
#include <radius/radius.api_types.h>

static u16 setup_message_id_table (void);

static void
send_radius_provider_set_reply (u32 client_index, u32 context, i32 retval)
{
  vl_api_registration_t *reg;
  vl_api_radius_provider_set_reply_t *rmp;

  reg = vl_api_client_index_to_registration (client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id = htons ((u16) (VL_API_RADIUS_PROVIDER_SET_REPLY + radius_main.msg_id_base));
  rmp->context = context;
  rmp->retval = htonl (retval);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_radius_test_auth_reply (u32 client_index, u32 context, i32 retval,
                             u32 result_code, const char *msg)
{
  vl_api_registration_t *reg;
  vl_api_radius_test_auth_reply_t *rmp;

  reg = vl_api_client_index_to_registration (client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id = htons ((u16) (VL_API_RADIUS_TEST_AUTH_REPLY + radius_main.msg_id_base));
  rmp->context = context;
  rmp->retval = htonl (retval);
  rmp->result_code = htonl (result_code);
  if (msg)
    clib_memcpy (rmp->reply_message, msg,
                 clib_min ((uword) strlen (msg), sizeof (rmp->reply_message)));
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_radius_stats_dump_reply (u32 client_index, u32 context)
{
  radius_main_t *rm = &radius_main;
  vl_api_registration_t *reg;
  vl_api_radius_stats_dump_reply_t *rmp;

  reg = vl_api_client_index_to_registration (client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id = htons ((u16) (VL_API_RADIUS_STATS_DUMP_REPLY + radius_main.msg_id_base));
  rmp->context = context;
  rmp->retval = 0;
  rmp->requests = clib_host_to_net_u64 (rm->stats.requests);
  rmp->accepts = clib_host_to_net_u64 (rm->stats.accepts);
  rmp->rejects = clib_host_to_net_u64 (rm->stats.rejects);
  rmp->challenges = clib_host_to_net_u64 (rm->stats.challenges);
  rmp->timeouts = clib_host_to_net_u64 (rm->stats.timeouts);
  rmp->errors = clib_host_to_net_u64 (rm->stats.errors);
  rmp->pending = clib_host_to_net_u64 (pool_elts (rm->pending));
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_provider_details (radius_server_t *s, vl_api_registration_t *reg, u32 context)
{
  vl_api_radius_provider_details_t *mp;

  mp = vl_msg_api_alloc_zero (sizeof (*mp));
  mp->_vl_msg_id = htons ((u16) (VL_API_RADIUS_PROVIDER_DETAILS + radius_main.msg_id_base));
  mp->context = context;
  clib_memcpy (mp->name, s->name, sizeof (mp->name));
  mp->fib_index = htonl (s->fib_index);
  mp->sw_if_index = htonl (s->sw_if_index);
  mp->port = htons (s->port);
  mp->timeout_sec = htons (s->timeout_sec);
  mp->retries = htons (s->retries);
  clib_memcpy (mp->secret, s->secret, sizeof (mp->secret));
  clib_memcpy (mp->nas_id, s->nas_id, sizeof (mp->nas_id));
  clib_memcpy (mp->ip4, &s->ip.ip4, 4);
  clib_memcpy (mp->src_ip4, &s->src_ip.ip4, 4);
  mp->enabled = s->enabled;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_radius_provider_set_t_handler (vl_api_radius_provider_set_t *mp)
{
  radius_server_t s = { 0 };
  int rv;

  clib_memcpy (s.name, mp->name, sizeof (s.name));
  s.fib_index = clib_net_to_host_u32 (mp->fib_index);
  s.sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  s.port = clib_net_to_host_u16 (mp->port);
  s.timeout_sec = clib_net_to_host_u16 (mp->timeout_sec);
  s.retries = clib_net_to_host_u16 (mp->retries);
  clib_memcpy (s.secret, mp->secret, sizeof (s.secret));
  clib_memcpy (s.nas_id, mp->nas_id, sizeof (s.nas_id));
  s.enabled = mp->enabled;
  clib_memcpy (&s.ip.ip4, mp->ip4, 4);
  clib_memcpy (&s.src_ip.ip4, mp->src_ip4, 4);

  rv = radius_provider_set (&s);
  send_radius_provider_set_reply (mp->client_index, mp->context,
                                  rv < 0 ? rv : 0);
}

static void
vl_api_radius_provider_dump_t_handler (vl_api_radius_provider_dump_t *mp)
{
  radius_main_t *rm = &radius_main;
  vl_api_registration_t *reg;
  radius_server_t *s;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (s, rm->servers)
    send_provider_details (s, reg, mp->context);
}

static void
vl_api_radius_test_auth_t_handler (vl_api_radius_test_auth_t *mp)
{
  radius_auth_req_t req = { 0 };
  int provider_index;
  int rv;
  u64 txn_id = 0;

  provider_index = radius_find_provider_by_name ((u8 *) mp->provider_name);
  if (provider_index < 0)
    {
      send_radius_test_auth_reply (mp->client_index, mp->context, -1,
                                   RADIUS_RESULT_ERROR,
                                   "provider_not_found");
      return;
    }

  req.provider_index = provider_index;
  req.username = format (0, "%s", mp->username);
  req.password = format (0, "%s", mp->password);
  req.nas_id = format (0, "radius-test");

  rv = radius_auth_start (&req, &txn_id);
  vec_free (req.username);
  vec_free (req.password);
  vec_free (req.nas_id);

  send_radius_test_auth_reply (mp->client_index, mp->context, rv,
                               rv == 0 ? 0 : RADIUS_RESULT_ERROR,
                               rv == 0 ? "request_sent" : "request_failed");
}

static void
vl_api_radius_stats_dump_t_handler (vl_api_radius_stats_dump_t *mp)
{
  send_radius_stats_dump_reply (mp->client_index, mp->context);
}

static clib_error_t *
radius_api_init (vlib_main_t *vm)
{
  radius_main_t *rm = &radius_main;
  rm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_INIT_FUNCTION (radius_api_init);

#include <radius/radius.api.c>
