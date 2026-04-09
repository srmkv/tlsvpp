#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>

#include <tlsctrl/tlsctrl.h>
#include <tlsctrl/tlsctrl_vpn.h>

typedef enum
{
  TLSCTRL_VPN_STAGE16_NEXT_LOOKUP,
  TLSCTRL_VPN_STAGE16_NEXT_DROP,
  TLSCTRL_VPN_STAGE16_N_NEXT,
} tlsctrl_vpn_stage16_next_t;

typedef enum
{
  TLSCTRL_VPN_STAGE16_ERROR_INTERCEPTED,
  TLSCTRL_VPN_STAGE16_ERROR_ENQUEUE_FAIL,
  TLSCTRL_VPN_STAGE16_ERROR_CHAINED_SKIP,
  TLSCTRL_VPN_STAGE16_N_ERROR,
} tlsctrl_vpn_stage16_error_t;

static char *tlsctrl_vpn_stage16_error_strings[] = {
  "reply packet intercepted to VPN client",
  "reply packet matched VIP but reverse delivery enqueue/frame build failed",
  "chained packet skipped by VPN reverse hook",
};

typedef struct
{
  u32 sw_if_index;
  ip4_address_t dst;
  u64 tunnel_id;
  u8 intercepted;
} tlsctrl_vpn_stage16_trace_t;

static u8 *
format_tlsctrl_vpn_stage16_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  tlsctrl_vpn_stage16_trace_t *t = va_arg (*args, tlsctrl_vpn_stage16_trace_t *);

  s = format (s, "tlsctrl-stage16 sw_if_index=%u dst=%U tunnel=%llu intercepted=%u",
              t->sw_if_index, format_ip4_address, &t->dst,
              (unsigned long long) t->tunnel_id, t->intercepted);
  return s;
}

static_always_inline int
_tlsctrl_vpn_stage16_try_intercept (vlib_main_t *vm, vlib_buffer_t *b0,
                                    ip4_header_t *ip4, u64 *out_tunnel_id)
{
  u8 *frame = 0;
  u32 payload_len;
  int rv;

  if (out_tunnel_id)
    *out_tunnel_id = 0;

  if (PREDICT_FALSE (!ip4))
    return 0;

  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_NEXT_PRESENT))
    return -11;

  payload_len = vlib_buffer_length_in_chain (vm, b0);
  if (PREDICT_FALSE (payload_len < sizeof (*ip4)))
    return 0;

  rv = tlsctrl_vpn_dp_tx_ipv4_by_vip (&ip4->dst_address, (const u8 *) ip4,
                                      payload_len, &frame);
  if (rv || !frame)
    return rv;

  if (out_tunnel_id)
    {
      tlsctrl_vpn_dp_session_t *s = 0;
      if (!tlsctrl_vpn_dp_lookup_vip (&ip4->dst_address, &s) && s)
        *out_tunnel_id = s->tunnel_id;
    }

  if (out_tunnel_id && *out_tunnel_id)
    rv = tlsctrl_vpn_dp_enqueue_frame (*out_tunnel_id, frame);
  else
    rv = -22;

  if (rv)
    {
      if (out_tunnel_id && *out_tunnel_id)
        {
          tlsctrl_vpn_dp_session_t *qs = 0;
          if (!tlsctrl_vpn_dp_find_session (*out_tunnel_id, &qs) && qs)
            {
              qs->queue_dropped_frames += 1;
              qs->queue_drop_bytes += vec_len (frame);
            }
        }
      vec_free (frame);
      return rv;
    }

  return 1;
}

VLIB_NODE_FN (tlsctrl_vpn_stage16_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from;
  u32 next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next, *to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t *b0;
          ip4_header_t *ip40;
          u32 next0 = TLSCTRL_VPN_STAGE16_NEXT_LOOKUP;
          int irv;
          u64 tunnel_id = 0;

          bi0 = from[0];
          b0 = vlib_get_buffer (vm, bi0);
          ip40 = vlib_buffer_get_current (b0);

          irv = _tlsctrl_vpn_stage16_try_intercept (vm, b0, ip40, &tunnel_id);
          if (irv == 1)
            {
              next0 = TLSCTRL_VPN_STAGE16_NEXT_DROP;
              b0->error = node->errors[TLSCTRL_VPN_STAGE16_ERROR_INTERCEPTED];
            }
          else if (irv == -11)
            {
              b0->error = node->errors[TLSCTRL_VPN_STAGE16_ERROR_CHAINED_SKIP];
              next0 = TLSCTRL_VPN_STAGE16_NEXT_LOOKUP;
            }
          else if (irv < 0 && irv != -2)
            {
              if (tunnel_id)
                (void) tlsctrl_vpn_dp_stage7_note_drop (tunnel_id);
              b0->error = node->errors[TLSCTRL_VPN_STAGE16_ERROR_ENQUEUE_FAIL];
              next0 = TLSCTRL_VPN_STAGE16_NEXT_DROP;
            }

          if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              tlsctrl_vpn_stage16_trace_t *tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
              clib_memset (tr, 0, sizeof (*tr));
              tr->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
              if (ip40)
                tr->dst = ip40->dst_address;
              tr->tunnel_id = tunnel_id;
              tr->intercepted = (irv == 1);
            }

          to_next[0] = bi0;
          to_next += 1;
          from += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (tlsctrl_vpn_stage16_node) = {
  .name = "tlsctrl-vpn-stage16",
  .vector_size = sizeof (u32),
  .format_trace = format_tlsctrl_vpn_stage16_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (tlsctrl_vpn_stage16_error_strings),
  .error_strings = tlsctrl_vpn_stage16_error_strings,
  .n_next_nodes = TLSCTRL_VPN_STAGE16_N_NEXT,
  .next_nodes = {
    [TLSCTRL_VPN_STAGE16_NEXT_LOOKUP] = "ip4-lookup",
    [TLSCTRL_VPN_STAGE16_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (tlsctrl_vpn_stage16_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "tlsctrl-vpn-stage16",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

void
tlsctrl_vpn_stage16_feature_sync (void)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im;
  vnet_sw_interface_t *si;

  if (!vnm)
    return;

  /*
   * vnet_feature_enable_disable() may allocate graph edges and must run on the
   * main thread. Stage16 used to call this from dp_attach/configure(), which can
   * execute from a session worker and crash with
   * vlib_node_add_next_with_slot: vlib_get_thread_index()==0 assertion.
   *
   * Keep this function safe and idempotent: if we are not on thread 0, do nothing.
   * The feature is synced from plugin init on the main thread.
   */
  if (vlib_get_thread_index () != 0)
    return;

  im = &vnm->interface_main;
  pool_foreach (si, im->sw_interfaces)
    {
      if (si->sw_if_index == ~0)
        continue;
      (void) vnet_feature_enable_disable ("ip4-unicast",
                                          "tlsctrl-vpn-stage16",
                                          si->sw_if_index,
                                          1 /* enable */, 0, 0);
    }
}


static uword
tlsctrl_vpn_stage16_sync_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
                                  vlib_frame_t *f)
{
  while (1)
    {
      tlsctrl_vpn_stage16_feature_sync ();
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      vlib_process_get_events (vm, 0);
    }
  return 0;
}

VLIB_REGISTER_NODE (tlsctrl_vpn_stage16_sync_process_node) = {
  .function = tlsctrl_vpn_stage16_sync_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "tlsctrl-vpn-stage16-sync",
};
