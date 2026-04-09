#include <vlib/vlib.h>
#include <vppinfra/format.h>
#include <vppinfra/string.h>
#include <vnet/ip/ip.h>
#include "tlsctrl_vpn.h"

typedef tlsctrl_vpn_main_t tvpn_main_t;

static u8 *
tvpn_dup_str (const char *s)
{
  if (!s)
    return 0;
  return format (0, "%s%c", s, 0);
}

static void
tvpn_set_str (u8 **dst, const char *src)
{
  vec_free (*dst);
  *dst = tvpn_dup_str (src);
}

static u8 *
tvpn_make_if_name (u64 tunnel_id)
{
  return format (0, "tlsvpn-%llu%c", (unsigned long long) tunnel_id, 0);
}


static tlsctrl_vpn_dp_session_t *
tvpn_dp_find (u64 tunnel_id)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  vec_foreach (s, m->dp_sessions)
    if (s->tunnel_id == tunnel_id)
      return s;
  return 0;
}

static void
tvpn_dp_free_pending_frames (tlsctrl_vpn_dp_session_t *s, u8 account_drop)
{
  u8 **pf;
  if (!s || !s->pending_frames)
    return;
  vec_foreach (pf, s->pending_frames)
    {
      if (account_drop && *pf)
        {
          s->queue_dropped_frames += 1;
          s->queue_drop_bytes += vec_len (*pf);
        }
      vec_free (*pf);
    }
  vec_free (s->pending_frames);
  s->pending_frames = 0;
  s->tx_queue_depth = 0;
}

static void
tvpn_dp_reset_runtime_counters (tlsctrl_vpn_dp_session_t *s)
{
  if (!s)
    return;
  s->seq_tx = 0;
  s->rx_frames = 0;
  s->tx_frames = 0;
  s->rx_bytes = 0;
  s->tx_bytes = 0;
  s->keepalives_rx = 0;
  s->keepalives_tx = 0;
  s->ipv4_rx = 0;
  s->ipv4_tx = 0;
  s->last_rx_unix_ns = 0;
  s->last_tx_unix_ns = 0;
  s->last_seen_unix_ns = 0;
  s->tx_queue_depth = 0;
  s->last_drop_reason = 0;
  s->queue_enqueued_frames = 0;
  s->queue_dequeued_frames = 0;
  s->queue_dropped_frames = 0;
  s->queue_enqueue_bytes = 0;
  s->queue_dequeue_bytes = 0;
  s->queue_drop_bytes = 0;
  s->tx_inject_pkts = 0;
  s->tx_inject_bytes = 0;
  s->tx_lookup_hits = 0;
  s->tx_lookup_misses = 0;
  s->tx_lookup_drops = 0;
  s->tx_probe_pkts = 0;
  s->tx_probe_bytes = 0;
  s->rx_probe_pkts = 0;
  s->rx_probe_bytes = 0;
  s->auto_probe_pkts = 0;
  s->auto_probe_bytes = 0;
  s->auto_bridge_pkts = 0;
  s->auto_bridge_bytes = 0;
  s->auto_hook_pkts = 0;
  s->auto_hook_bytes = 0;
}

static int
tvpn_parse_ip4 (const char *s, ip4_address_t *out)
{
  u8 a=0,b=0,c=0,d=0;
  if (!s || !out)
    return -1;
  if (sscanf (s, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4)
    return -1;
  out->as_u8[0] = a;
  out->as_u8[1] = b;
  out->as_u8[2] = c;
  out->as_u8[3] = d;
  return 0;
}

int
tlsctrl_vpn_dp_find_session (u64 tunnel_id, tlsctrl_vpn_dp_session_t **out)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  if (out)
    *out = 0;
  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (s && out)
    *out = s;
  clib_spinlock_unlock (&m->lock);
  return s ? 0 : -1;
}


int
tlsctrl_vpn_dp_enqueue_frame (u64 tunnel_id, u8 *frame)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (!frame)
    return -1;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -2;
  vec_add1 (s->pending_frames, frame);
  s->tx_queue_depth = vec_len (s->pending_frames);
  s->queue_enqueued_frames += 1;
  s->queue_enqueue_bytes += vec_len (frame);
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_dequeue_frame (u64 tunnel_id, u8 **out_frame)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (out_frame)
    *out_frame = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  if (!s->pending_frames || vec_len (s->pending_frames) == 0)
    return -2;
  if (out_frame)
    *out_frame = s->pending_frames[0];
  s->queue_dequeued_frames += 1;
  s->queue_dequeue_bytes += vec_len (s->pending_frames[0]);
  vec_delete (s->pending_frames, 1, 0);
  s->tx_queue_depth = vec_len (s->pending_frames);
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_dequeue_frame_by_username (const char *username, u64 *out_tunnel_id, u8 **out_frame)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  if (out_tunnel_id)
    *out_tunnel_id = 0;
  if (out_frame)
    *out_frame = 0;
  if (!username || !*username)
    return -1;
  clib_spinlock_lock (&m->lock);
  vec_foreach (s, m->dp_sessions)
    {
      if (!s->username || strcmp ((char *) s->username, username) != 0)
        continue;
      if (!s->pending_frames || vec_len (s->pending_frames) == 0)
        continue;
      if (out_tunnel_id)
        *out_tunnel_id = s->tunnel_id;
      if (out_frame)
        *out_frame = s->pending_frames[0];
      s->queue_dequeued_frames += 1;
      s->queue_dequeue_bytes += vec_len (s->pending_frames[0]);
      vec_delete (s->pending_frames, 1, 0);
      s->tx_queue_depth = vec_len (s->pending_frames);
      s->last_seen_unix_ns = clib_cpu_time_now ();
      clib_spinlock_unlock (&m->lock);
      return 0;
    }
  clib_spinlock_unlock (&m->lock);
  return -2;
}

int
tlsctrl_vpn_dp_lookup_vip (const ip4_address_t *vip, tlsctrl_vpn_dp_session_t **out)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s, *found = 0;
  ip4_address_t parsed;
  if (out)
    *out = 0;
  if (!vip)
    return -1;
  clib_spinlock_lock (&m->lock);
  vec_foreach (s, m->dp_sessions)
    {
      if (!s->assigned_ip)
        continue;
      if (!tvpn_parse_ip4 ((char *) s->assigned_ip, &parsed)
          && parsed.as_u32 == vip->as_u32)
        {
          found = s;
          break;
        }
    }
  if (found && out)
    *out = found;
  clib_spinlock_unlock (&m->lock);
  return found ? 0 : -1;
}

int
tlsctrl_vpn_dp_attach (u64 tunnel_id, u64 session_handle)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  u8 had_runtime = 0;
  u64 now = clib_cpu_time_now ();

  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (!s)
    {
      vec_add2 (m->dp_sessions, s, 1);
      clib_memset (s, 0, sizeof (*s));
      s->tunnel_id = tunnel_id;
      s->sw_if_index = ~0;
      s->fib_index = ~0;
      s->route_bound = 0;
      s->tx_ready = 0;
    }

  had_runtime = s->running || s->session_handle || s->connected_at_unix_ns ||
                s->rx_frames || s->tx_frames || s->tx_queue_depth ||
                (s->pending_frames && vec_len (s->pending_frames));

  if (had_runtime)
    {
      tvpn_dp_free_pending_frames (s, 1 /* account_drop */);
      tvpn_dp_reset_runtime_counters (s);
      s->session_reset_count += 1;
    }

  s->session_open_count += 1;
  s->connect_generation += 1;
  s->connected_at_unix_ns = now;
  s->session_handle = session_handle;
  s->running = 1;
  s->is_up = 1;
  s->route_bound = 0;
  s->tx_hook_armed = 0;
  s->tx_ready = session_handle ? 1 : 0;
  s->stage8_output_enabled = session_handle ? 1 : 0;
  s->stage9_input_enabled = session_handle ? 1 : 0;
  s->stage10_bridge_enabled = session_handle ? 1 : 0;
  s->stage11_auto_enabled = session_handle ? 1 : 0;
  s->stage13_auto_hook_enabled = 0; /* stage13 synthetic autohook is debug-only */
  s->last_tx_unix_ns = now;
  s->last_seen_unix_ns = now;
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_set_session_handle (u64 tunnel_id, u64 session_handle)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (!s)
    {
      clib_spinlock_unlock (&m->lock);
      return -1;
    }
  s->session_handle = session_handle;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_configure (u64 tunnel_id, const char *assigned_ip,
                          const char *gateway, const char *username,
                          const char *profile_name)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (!s)
    {
      vec_add2 (m->dp_sessions, s, 1);
      clib_memset (s, 0, sizeof (*s));
      s->tunnel_id = tunnel_id;
      s->sw_if_index = ~0;
      s->fib_index = ~0;
      s->route_bound = 0;
      s->tx_ready = 0;
    }
  tvpn_set_str (&s->assigned_ip, assigned_ip);
  if (!s->if_name)
    s->if_name = tvpn_make_if_name (tunnel_id);
  if (s->sw_if_index == ~0)
    s->sw_if_index = (u32) (tunnel_id & 0x7fffffff);
  if (s->fib_index == ~0)
    s->fib_index = 0;
  tvpn_set_str (&s->gateway, gateway);
  tvpn_set_str (&s->username, username);
  tvpn_set_str (&s->profile_name, profile_name);
  s->last_seen_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_detach (u64 tunnel_id)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  u64 now = clib_cpu_time_now ();

  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (!s)
    {
      clib_spinlock_unlock (&m->lock);
      return -1;
    }

  if (s->running || s->session_handle || s->connected_at_unix_ns)
    s->session_close_count += 1;

  tvpn_dp_free_pending_frames (s, 1 /* account_drop */);
  s->running = 0;
  s->is_up = 0;
  s->session_handle = 0;
  s->tx_ready = 0;
  s->tx_hook_armed = 0;
  s->route_bound = 0;
  s->stage8_output_enabled = 0;
  s->stage9_input_enabled = 0;
  s->stage10_bridge_enabled = 0;
  s->stage11_auto_enabled = 0;
  s->stage13_auto_hook_enabled = 0;
  s->last_tx_unix_ns = now;
  s->last_seen_unix_ns = now;
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_set_queue_depth (u64 tunnel_id, u32 depth)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (!s)
    {
      clib_spinlock_unlock (&m->lock);
      return -1;
    }
  s->tx_queue_depth = depth;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_note_drop (u64 tunnel_id, u32 reason)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (!s)
    {
      clib_spinlock_unlock (&m->lock);
      return -1;
    }
  s->last_drop_reason = reason;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_touch_keepalive (u64 tunnel_id, int outbound)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (!s)
    {
      clib_spinlock_unlock (&m->lock);
      return -1;
    }
  if (outbound)
    {
      s->keepalives_tx += 1;
      s->tx_frames += 1;
      s->seq_tx += 1;
      s->last_tx_unix_ns = clib_cpu_time_now ();
    }
  else
    {
      s->keepalives_rx += 1;
      s->rx_frames += 1;
      s->last_rx_unix_ns = clib_cpu_time_now ();
    }
  s->last_seen_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_note_ipv4 (u64 tunnel_id, u32 bytes, int outbound)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (!s)
    {
      clib_spinlock_unlock (&m->lock);
      return -1;
    }
  if (outbound)
    {
      s->ipv4_tx += 1;
      s->tx_frames += 1;
      s->tx_bytes += bytes;
      s->seq_tx += 1;
      s->last_tx_unix_ns = clib_cpu_time_now ();
    }
  else
    {
      s->ipv4_rx += 1;
      s->rx_frames += 1;
      s->rx_bytes += bytes;
      s->last_rx_unix_ns = clib_cpu_time_now ();
    }
  s->last_seen_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_stage5_bind_identity (u64 tunnel_id)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (!s)
    {
      clib_spinlock_unlock (&m->lock);
      return -1;
    }
  if (!s->if_name)
    s->if_name = tvpn_make_if_name (tunnel_id);
  if (s->sw_if_index == ~0)
    s->sw_if_index = (u32) (tunnel_id & 0x7fffffff);
  if (s->fib_index == ~0)
    s->fib_index = 0;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_stage5_mark_route_bound (u64 tunnel_id, u8 bound)
{
  tvpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  clib_spinlock_lock (&m->lock);
  s = tvpn_dp_find (tunnel_id);
  if (!s)
    {
      clib_spinlock_unlock (&m->lock);
      return -1;
    }
  s->route_bound = bound ? 1 : 0;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_tx_ipv4_from_vpp (u64 tunnel_id, const u8 *payload, u32 payload_len, u8 **out_frame)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (out_frame)
    *out_frame = 0;
  if (!payload || payload_len < sizeof (ip4_header_t))
    return -1;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -2;
  tlsctrl_vpn_dp_stage6_reconcile (tunnel_id);
  tlsctrl_vpn_dp_stage5_bind_identity (tunnel_id);
  tlsctrl_vpn_dp_stage5_mark_route_bound (tunnel_id, 1);
  tlsctrl_vpn_dp_stage7_arm_output (tunnel_id);
  if (!s->tx_ready)
    {
      tlsctrl_vpn_dp_note_drop (tunnel_id, 2001);
      return -3;
    }
  s->tx_inject_pkts += 1;
  s->tx_inject_bytes += payload_len;
  return tlsctrl_vpn_frame_tx_ipv4 (tunnel_id, payload, payload_len, out_frame);
}

static int
tvpn_enqueue_ip4_input (vlib_main_t *vm, u32 bi)
{
  static u32 ip4_input_node_index = ~0;
  vlib_node_t *n;
  vlib_frame_t *f;
  u32 *to_next;

  if (ip4_input_node_index == ~0)
    {
      n = vlib_get_node_by_name (vm, (u8 *) "ip4-input");
      if (!n)
        return -10;
      ip4_input_node_index = n->index;
    }

  f = vlib_get_frame_to_node (vm, ip4_input_node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, ip4_input_node_index, f);
  return 0;
}



int
tlsctrl_vpn_dp_tx_ipv4_by_vip (const ip4_address_t *vip, const u8 *payload, u32 payload_len, u8 **out_frame)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (!vip)
    return -1;
  if (tlsctrl_vpn_dp_lookup_vip (vip, &s) || !s)
    return -2;
  tlsctrl_vpn_dp_stage7_note_lookup (s->tunnel_id, 1);
  tlsctrl_vpn_dp_stage8_enable_output (s->tunnel_id, 1);
  return tlsctrl_vpn_dp_tx_ipv4_from_vpp (s->tunnel_id, payload, payload_len, out_frame);
}


int
tlsctrl_vpn_dp_stage7_arm_output (u64 tunnel_id)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  if (!s->if_name)
    s->if_name = tvpn_make_if_name (tunnel_id);
  if (s->sw_if_index == ~0)
    s->sw_if_index = (u32) (tunnel_id & 0x7fffffff);
  s->tx_hook_armed = 1;
  s->stage8_output_enabled = 1;
  s->stage9_input_enabled = 1;
  s->stage10_bridge_enabled = 1;
  /* keep stage13 synthetic autohook disabled by default; enable only via CLI */
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_stage7_note_lookup (u64 tunnel_id, int hit)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  if (hit)
    s->tx_lookup_hits += 1;
  else
    s->tx_lookup_misses += 1;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_stage7_note_drop (u64 tunnel_id)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  s->tx_lookup_drops += 1;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_stage8_enable_output (u64 tunnel_id, u8 enable)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  s->stage8_output_enabled = enable ? 1 : 0;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_stage10_enable_bridge (u64 tunnel_id, u8 enable)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  s->stage10_bridge_enabled = enable ? 1 : 0;
  if (enable)
    {
      s->stage8_output_enabled = 1;
      s->stage9_input_enabled = 1;
      s->stage11_auto_enabled = 1;
      s->tx_hook_armed = 1;
    }
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_stage8_probe_ip4_packet (const u8 *payload, u32 payload_len, u8 **out_frame, u64 *out_tunnel_id)
{
  const ip4_header_t *ip4;
  tlsctrl_vpn_dp_session_t *s = 0;
  int rv;

  if (out_frame)
    *out_frame = 0;
  if (out_tunnel_id)
    *out_tunnel_id = 0;
  if (!payload || payload_len < sizeof (ip4_header_t))
    return -1;

  ip4 = (const ip4_header_t *) payload;
  rv = tlsctrl_vpn_dp_lookup_vip (&ip4->dst_address, &s);
  if (rv || !s)
    return -2;

  tlsctrl_vpn_dp_stage7_note_lookup (s->tunnel_id, 1);
  tlsctrl_vpn_dp_stage7_arm_output (s->tunnel_id);
  tlsctrl_vpn_dp_stage8_enable_output (s->tunnel_id, 1);
  tlsctrl_vpn_dp_stage10_enable_bridge (s->tunnel_id, 1);
  tlsctrl_vpn_dp_stage11_enable_auto (s->tunnel_id, 1);

  if (out_tunnel_id)
    *out_tunnel_id = s->tunnel_id;

  rv = tlsctrl_vpn_dp_tx_ipv4_from_vpp (s->tunnel_id, payload, payload_len, out_frame);
  if (!rv)
    {
      s->tx_probe_pkts += 1;
      s->tx_probe_bytes += payload_len;
      s->last_seen_unix_ns = clib_cpu_time_now ();
    }
  return rv;
}

int
tlsctrl_vpn_dp_stage9_enable_input (u64 tunnel_id, u8 enable)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  s->stage9_input_enabled = enable ? 1 : 0;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_stage9_probe_rx_ipv4 (u64 tunnel_id, const u8 *payload, u32 payload_len)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  int rv;
  if (!payload || payload_len < sizeof (ip4_header_t))
    return -1;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -2;
  tlsctrl_vpn_dp_stage9_enable_input (tunnel_id, 1);
  tlsctrl_vpn_dp_stage10_enable_bridge (tunnel_id, 1);
  rv = tlsctrl_vpn_dp_rx_ipv4_to_vpp (tunnel_id, payload, payload_len);
  if (!rv)
    {
      s->rx_probe_pkts += 1;
      s->rx_probe_bytes += payload_len;
      s->last_seen_unix_ns = clib_cpu_time_now ();
    }
  return rv;
}



int
tlsctrl_vpn_dp_stage13_enable_hook (u64 tunnel_id, u8 enable)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  s->stage13_auto_hook_enabled = enable ? 1 : 0;
  if (enable)
    {
      s->stage11_auto_enabled = 1;
      s->stage10_bridge_enabled = 1;
      s->stage9_input_enabled = 1;
      s->stage8_output_enabled = 1;
    }
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_stage13_note_auto (u64 tunnel_id, u32 bytes)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  s->auto_hook_pkts += 1;
  s->auto_hook_bytes += bytes;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_stage11_enable_auto (u64 tunnel_id, u8 enable)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  s->stage11_auto_enabled = enable ? 1 : 0;
  if (enable)
    {
      s->stage10_bridge_enabled = 1;
      s->stage8_output_enabled = 1;
      s->stage9_input_enabled = 1;
    }
  return 0;
}

int
tlsctrl_vpn_dp_stage11_tick (u64 tunnel_id, const u8 *payload, u32 payload_len, u8 **out_frame)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  tlsctrl_vpn_dp_stage11_enable_auto (tunnel_id, 1);
  s->auto_bridge_pkts++;
  s->auto_bridge_bytes += payload_len;
  if (payload && payload_len)
    (void) tlsctrl_vpn_dp_stage9_probe_rx_ipv4 (tunnel_id, payload, payload_len);
  if (payload && payload_len)
    return tlsctrl_vpn_dp_stage10_autoprobe (tunnel_id, payload, payload_len, payload, payload_len, out_frame);
  return 0;
}
int
tlsctrl_vpn_dp_stage10_autoprobe (u64 tunnel_id, const u8 *rx_payload, u32 rx_payload_len,
                                  const u8 *tx_payload, u32 tx_payload_len, u8 **out_frame)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  int rv = 0;
  if (out_frame)
    *out_frame = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  tlsctrl_vpn_dp_stage10_enable_bridge (tunnel_id, 1);
  if (rx_payload && rx_payload_len >= sizeof (ip4_header_t))
    {
      rv = tlsctrl_vpn_dp_rx_ipv4_to_vpp (tunnel_id, rx_payload, rx_payload_len);
      if (rv)
        return rv;
      s->auto_probe_pkts += 1;
      s->auto_probe_bytes += rx_payload_len;
    }
  if (tx_payload && tx_payload_len >= sizeof (ip4_header_t))
    {
      rv = tlsctrl_vpn_dp_tx_ipv4_from_vpp (tunnel_id, tx_payload, tx_payload_len, out_frame);
      if (rv)
        return rv;
      s->auto_probe_pkts += 1;
      s->auto_probe_bytes += tx_payload_len;
    }
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_stage6_reconcile (u64 tunnel_id)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -1;
  if (!s->if_name)
    s->if_name = tvpn_make_if_name (tunnel_id);
  if (s->sw_if_index == ~0)
    s->sw_if_index = (u32) (tunnel_id & 0x7fffffff);
  if (s->fib_index == ~0)
    s->fib_index = 0;
  if (s->assigned_ip)
    s->route_bound = 1;
  if (s->session_handle)
    {
      s->tx_ready = 1;
      s->stage9_input_enabled = 1;
    }
  if (s->route_bound && s->tx_ready)
    s->tx_hook_armed = 1;
  s->last_seen_unix_ns = clib_cpu_time_now ();
  return 0;
}

int
tlsctrl_vpn_dp_rx_ipv4_to_vpp (u64 tunnel_id, const u8 *payload, u32 payload_len)
{
  vlib_main_t *vm = vlib_get_main ();
  tlsctrl_vpn_dp_session_t *s = 0;
  vlib_buffer_t *b;
  u32 bi = ~0;
  int rv;

  if (!payload || payload_len < sizeof (ip4_header_t))
    return -1;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s) || !s)
    return -2;
  tlsctrl_vpn_dp_stage6_reconcile (tunnel_id);
  tlsctrl_vpn_dp_stage5_bind_identity (tunnel_id);
  tlsctrl_vpn_dp_stage5_mark_route_bound (tunnel_id, 1);
  tlsctrl_vpn_dp_stage7_arm_output (tunnel_id);
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      tlsctrl_vpn_dp_note_drop (tunnel_id, 1001);
      return -3;
    }

  b = vlib_get_buffer (vm, bi);
  vlib_buffer_reset (b);
  clib_memcpy_fast (vlib_buffer_get_current (b), payload, payload_len);
  vlib_buffer_put_uninit (b, payload_len);
  vnet_buffer (b)->sw_if_index[VLIB_RX] = s->sw_if_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;

  rv = tvpn_enqueue_ip4_input (vm, bi);
  if (rv)
    {
      vlib_buffer_free (vm, &bi, 1);
      tlsctrl_vpn_dp_note_drop (tunnel_id, 1002);
      return rv;
    }
  return 0;
}
