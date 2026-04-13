#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include "tlsctrl_vpn.h"

static clib_error_t *
show_tlsctrl_vpn_dataplane_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  (void) input;
  (void) cmd;

  clib_spinlock_lock (&m->lock);
  vlib_cli_output (vm, "vpn dataplane(path-a real txlookup): sessions=%u", vec_len (m->dp_sessions));
  vec_foreach (s, m->dp_sessions)
    {
      vlib_cli_output (
        vm,
        "  tunnel=%llu running=%u up=%u sh=0x%llx owner=%u bind=%u sw_if_index=%u fib=%u if=%s vip=%s gw=%s user=%s profile=%s q=%u drop=%u route=%u txready=%u txhook=%u stage8=%u stage10=%u stage11=%u stage13=%u",
        (unsigned long long) s->tunnel_id, s->running, s->is_up,
        (unsigned long long) s->session_handle, s->owner_thread_index, s->last_bind_thread_index, s->sw_if_index,
        s->fib_index, s->if_name ? (char *) s->if_name : "-", s->assigned_ip ? (char *) s->assigned_ip : "-",
        s->gateway ? (char *) s->gateway : "-",
        s->username ? (char *) s->username : "-",
        s->profile_name ? (char *) s->profile_name : "-",
        s->tx_queue_depth, s->last_drop_reason, s->route_bound, s->tx_ready, s->tx_hook_armed, s->stage8_output_enabled, s->stage10_bridge_enabled, s->stage11_auto_enabled, s->stage13_auto_hook_enabled);
      vlib_cli_output (
        vm,
        "    seq=%llu rxf=%llu txf=%llu rxb=%llu txb=%llu krx=%llu ktx=%llu ip4rx=%llu ip4tx=%llu qstat=%llu/%llu/%llu qb=%llu/%llu/%llu txinj=%llu/%llu txprobe=%llu/%llu rxprobe=%llu/%llu autoprobe=%llu/%llu autobridge=%llu/%llu autohook=%llu/%llu txlookup=%llu/%llu/%llu stage9=%u connected=%llu last=%llu",
        (unsigned long long) s->seq_tx,
        (unsigned long long) s->rx_frames,
        (unsigned long long) s->tx_frames,
        (unsigned long long) s->rx_bytes,
        (unsigned long long) s->tx_bytes,
        (unsigned long long) s->keepalives_rx,
        (unsigned long long) s->keepalives_tx,
        (unsigned long long) s->ipv4_rx,
        (unsigned long long) s->ipv4_tx,
        (unsigned long long) s->queue_enqueued_frames,
        (unsigned long long) s->queue_dequeued_frames,
        (unsigned long long) s->queue_dropped_frames,
        (unsigned long long) s->queue_enqueue_bytes,
        (unsigned long long) s->queue_dequeue_bytes,
        (unsigned long long) s->queue_drop_bytes,
        (unsigned long long) s->tx_inject_pkts,
        (unsigned long long) s->tx_inject_bytes,
        (unsigned long long) s->tx_probe_pkts,
        (unsigned long long) s->tx_probe_bytes,
        (unsigned long long) s->rx_probe_pkts,
        (unsigned long long) s->rx_probe_bytes,
        (unsigned long long) s->auto_probe_pkts,
        (unsigned long long) s->auto_probe_bytes,
        (unsigned long long) s->auto_bridge_pkts,
        (unsigned long long) s->auto_bridge_bytes,
        (unsigned long long) s->auto_hook_pkts,
        (unsigned long long) s->auto_hook_bytes,
        (unsigned long long) s->tx_lookup_hits,
        (unsigned long long) s->tx_lookup_misses,
        (unsigned long long) s->tx_lookup_drops,
        (unsigned) s->stage9_input_enabled,
        (unsigned long long) s->connected_at_unix_ns,
        (unsigned long long) s->last_seen_unix_ns);
      vlib_cli_output (
        vm,
        "    life gen=%llu open=%llu close=%llu reset=%llu reopen=%llu stale=%llu forced=%llu wrong=%llu handoff=%llu drop=%llu",
        (unsigned long long) s->connect_generation,
        (unsigned long long) s->session_open_count,
        (unsigned long long) s->session_close_count,
        (unsigned long long) s->session_reset_count,
        (unsigned long long) s->reopen_count,
        (unsigned long long) s->stale_reap_count,
        (unsigned long long) s->forced_close_count,
        (unsigned long long) s->wrong_worker_hits,
        (unsigned long long) s->handoff_count,
        (unsigned long long) s->handoff_drops);
    }
  clib_spinlock_unlock (&m->lock);
  return 0;
}


static clib_error_t *
show_tlsctrl_vpn_health_fn (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  int detail = 0;
  u32 sessions = 0, running = 0, up = 0, routes = 0, txready = 0;
  u32 queue_sessions = 0, stale_sessions = 0, transport_missing = 0;
  u64 queue_frames = 0, txlookup_hit = 0, txlookup_miss = 0, txlookup_drop = 0;
  u64 reopen = 0, stale_reap = 0, forced_close = 0;
  u64 stale_timeout_ns = 0;
  u8 force_close_stale = 0;

  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "detail"))
        detail = 1;
      else
        break;
    }

  tlsctrl_vpn_policy_get (&stale_timeout_ns, &force_close_stale);
  clib_spinlock_lock (&m->lock);
  sessions = vec_len (m->dp_sessions);
  vec_foreach (s, m->dp_sessions)
    {
      tlsctrl_vpn_transport_session_t *ts = 0;
      sessions += 0;
      if (s->running)
        running += 1;
      if (s->is_up)
        up += 1;
      if (s->route_bound)
        routes += 1;
      if (s->tx_ready)
        txready += 1;
      if (s->tx_queue_depth)
        {
          queue_sessions += 1;
          queue_frames += s->tx_queue_depth;
        }
      if (!s->running && (s->is_up || s->route_bound || s->tx_ready ||
                          s->tx_hook_armed || s->tx_queue_depth ||
                          (s->pending_frames && vec_len (s->pending_frames))))
        stale_sessions += 1;
      txlookup_hit += s->tx_lookup_hits;
      txlookup_miss += s->tx_lookup_misses;
      txlookup_drop += s->tx_lookup_drops;
      reopen += s->reopen_count;
      stale_reap += s->stale_reap_count;
      forced_close += s->forced_close_count;
      if (tlsctrl_vpn_transport_find_session (s->tunnel_id, &ts) != 0 || !ts)
        transport_missing += 1;

      if (detail)
        vlib_cli_output (
          vm,
          "  tunnel=%llu run=%u up=%u route=%u txready=%u q=%u txlookup=%llu/%llu/%llu life=%llu/%llu/%llu/%llu reopen=%llu stale=%llu forced=%llu transport=%s",
          (unsigned long long) s->tunnel_id,
          s->running, s->is_up, s->route_bound, s->tx_ready, s->tx_queue_depth,
          (unsigned long long) s->tx_lookup_hits,
          (unsigned long long) s->tx_lookup_misses,
          (unsigned long long) s->tx_lookup_drops,
          (unsigned long long) s->connect_generation,
          (unsigned long long) s->session_open_count,
          (unsigned long long) s->session_close_count,
          (unsigned long long) s->session_reset_count,
          (unsigned long long) s->reopen_count,
          (unsigned long long) s->stale_reap_count,
          (unsigned long long) s->forced_close_count,
          ts ? "ok" : "missing");
    }
  clib_spinlock_unlock (&m->lock);

  vlib_cli_output (
    vm,
    "vpn health: sessions=%u running=%u up=%u routes=%u txready=%u queue-sessions=%u queue-frames=%llu stale-sessions=%u transport-missing=%u txlookup=%llu/%llu/%llu reopen=%llu stale-reap=%llu forced-close=%llu policy-timeout-sec=%llu force-close-stale=%u",
    sessions, running, up, routes, txready, queue_sessions,
    (unsigned long long) queue_frames, stale_sessions, transport_missing,
    (unsigned long long) txlookup_hit,
    (unsigned long long) txlookup_miss,
    (unsigned long long) txlookup_drop,
    (unsigned long long) reopen,
    (unsigned long long) stale_reap,
    (unsigned long long) forced_close,
    (unsigned long long) (stale_timeout_ns / 1000000000ULL),
    (unsigned) force_close_stale);
  return 0;
}

static clib_error_t *
clear_tlsctrl_vpn_counters_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  u64 tunnel_id = 0;
  u64 *ids = 0;
  int all = 0;
  int full = 0;
  int rv = 0;
  (void) vm;
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "all"))
        all = 1;
      else if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else if (unformat (input, "full"))
        full = 1;
      else
        break;
    }

  if (!all && !tunnel_id)
    return clib_error_return (0, "usage: clear tlsctrl vpn counters [all|tunnel-id <id>] [full]");

  if (all)
    {
      clib_spinlock_lock (&m->lock);
      vec_foreach (s, m->dp_sessions)
        vec_add1 (ids, s->tunnel_id);
      clib_spinlock_unlock (&m->lock);
      vec_foreach_index (rv, ids)
        tlsctrl_vpn_dp_clear_runtime_counters (ids[rv], full ? 0 : 1);
      vec_free (ids);
      return 0;
    }

  rv = tlsctrl_vpn_dp_clear_runtime_counters (tunnel_id, full ? 0 : 1);
  if (rv)
    return clib_error_return (0, "clear counters failed rv=%d", rv);
  return 0;
}

static clib_error_t *
show_tlsctrl_vpn_users_fn (vlib_main_t *vm, unformat_input_t *input,
                          vlib_cli_command_t *cmd)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  int detail = 0;
  u64 now = clib_cpu_time_now ();
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "detail"))
        detail = 1;
      else
        break;
    }

  clib_spinlock_lock (&m->lock);
  vlib_cli_output (vm, "vpn users: sessions=%u", vec_len (m->dp_sessions));
  vec_foreach (s, m->dp_sessions)
    {
      u64 age_ms = 0;
      u64 conn_ms = 0;
      if (s->last_seen_unix_ns && now > s->last_seen_unix_ns)
        age_ms = (now - s->last_seen_unix_ns) / 1000000ULL;
      if (s->connected_at_unix_ns && now > s->connected_at_unix_ns)
        conn_ms = (now - s->connected_at_unix_ns) / 1000000ULL;

      if (detail)
        vlib_cli_output (
          vm,
          "  user=%s tunnel=%llu vip=%s profile=%s run=%u up=%u route=%u q=%u txlookup=%llu/%llu/%llu life=%llu/%llu/%llu/%llu reopen=%llu stale=%llu forced=%llu age-ms=%llu conn-ms=%llu",
          s->username ? (char *) s->username : "-",
          (unsigned long long) s->tunnel_id,
          s->assigned_ip ? (char *) s->assigned_ip : "-",
          s->profile_name ? (char *) s->profile_name : "-",
          s->running, s->is_up, s->route_bound, s->tx_queue_depth,
          (unsigned long long) s->tx_lookup_hits,
          (unsigned long long) s->tx_lookup_misses,
          (unsigned long long) s->tx_lookup_drops,
          (unsigned long long) s->connect_generation,
          (unsigned long long) s->session_open_count,
          (unsigned long long) s->session_close_count,
          (unsigned long long) s->session_reset_count,
          (unsigned long long) s->reopen_count,
          (unsigned long long) s->stale_reap_count,
          (unsigned long long) s->forced_close_count,
          (unsigned long long) age_ms,
          (unsigned long long) conn_ms);
      else
        vlib_cli_output (
          vm,
          "  user=%s tunnel=%llu vip=%s profile=%s run=%u up=%u q=%u forced=%llu",
          s->username ? (char *) s->username : "-",
          (unsigned long long) s->tunnel_id,
          s->assigned_ip ? (char *) s->assigned_ip : "-",
          s->profile_name ? (char *) s->profile_name : "-",
          s->running, s->is_up, s->tx_queue_depth,
          (unsigned long long) s->forced_close_count,
        (unsigned long long) s->wrong_worker_hits,
        (unsigned long long) s->handoff_count,
        (unsigned long long) s->handoff_drops);
    }
  clib_spinlock_unlock (&m->lock);
  return 0;
}

static clib_error_t *
show_tlsctrl_vpn_policy_fn (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  u64 stale_timeout_ns = 0;
  u8 force_close_stale = 0;
  (void) input;
  (void) cmd;
  tlsctrl_vpn_policy_get (&stale_timeout_ns, &force_close_stale);
  vlib_cli_output (vm,
                   "vpn policy: stale-timeout-sec=%llu force-close-stale=%u",
                   (unsigned long long) (stale_timeout_ns / 1000000000ULL),
                   (unsigned) force_close_stale);
  return 0;
}

static clib_error_t *
set_tlsctrl_vpn_policy_fn (vlib_main_t *vm, unformat_input_t *input,
                           vlib_cli_command_t *cmd)
{
  u32 stale_timeout_sec = 0;
  u32 force_close_stale = ~0;
  u64 current_timeout_ns = 0;
  u8 current_force = 0;
  (void) vm;
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "stale-timeout %u", &stale_timeout_sec))
        ;
      else if (unformat (input, "force-close %u", &force_close_stale))
        ;
      else
        break;
    }

  tlsctrl_vpn_policy_get (&current_timeout_ns, &current_force);
  if (!stale_timeout_sec)
    stale_timeout_sec = (u32) (current_timeout_ns / 1000000000ULL);
  if (force_close_stale == ~0)
    force_close_stale = current_force;

  tlsctrl_vpn_policy_set ((u64) stale_timeout_sec * 1000000000ULL,
                         force_close_stale ? 1 : 0);
  return 0;
}

static clib_error_t *
reap_tlsctrl_vpn_stale_fn (vlib_main_t *vm, unformat_input_t *input,
                           vlib_cli_command_t *cmd)
{
  u64 stale_timeout_ns = 0;
  u8 policy_force = 0;
  u32 timeout_sec = 0;
  u32 stale = 0, forced = 0;
  int force = -1;
  int rv;
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "timeout %u", &timeout_sec))
        ;
      else if (unformat (input, "force"))
        force = 1;
      else if (unformat (input, "no-force"))
        force = 0;
      else
        break;
    }

  tlsctrl_vpn_policy_get (&stale_timeout_ns, &policy_force);
  if (timeout_sec)
    stale_timeout_ns = (u64) timeout_sec * 1000000000ULL;
  if (force < 0)
    force = policy_force ? 1 : 0;

  rv = tlsctrl_vpn_dp_reap_stale_sessions (stale_timeout_ns, force ? 1 : 0,
                                           &stale, &forced);
  if (rv)
    return clib_error_return (0, "stale reap failed rv=%d", rv);

  vlib_cli_output (vm,
                   "vpn stale reap: found=%u forced-close=%u timeout-sec=%llu force=%u",
                   stale, forced,
                   (unsigned long long) (stale_timeout_ns / 1000000000ULL),
                   (unsigned) (force ? 1 : 0));
  return 0;
}


static clib_error_t *
show_tlsctrl_vpn_routes_fn (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  (void) input;
  (void) cmd;
  clib_spinlock_lock (&m->lock);
  vlib_cli_output (vm, "vpn route ownership(path-a real txlookup):");
  vec_foreach (s, m->dp_sessions)
    {
      if (!s->assigned_ip)
        continue;
      vlib_cli_output (vm, "  %s/32 -> tunnel=%llu sw_if_index=%u if=%s profile=%s user=%s route=%u",
                       (char *) s->assigned_ip,
                       (unsigned long long) s->tunnel_id,
                       s->sw_if_index,
                       s->if_name ? (char *) s->if_name : "-",
                       s->profile_name ? (char *) s->profile_name : "-",
                       s->username ? (char *) s->username : "-",
                       s->route_bound);
    }
  clib_spinlock_unlock (&m->lock);
  return 0;
}

static clib_error_t *
tlsctrl_vpn_dp_keepalive_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0;
  int outbound = 1;
  int rv;
  (void) vm;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else if (unformat (input, "rx"))
        outbound = 0;
      else if (unformat (input, "tx"))
        outbound = 1;
      else
        break;
    }
  if (!tunnel_id)
    return clib_error_return (0, "usage: tlsctrl vpn dataplane keepalive tunnel-id <id> [rx|tx]");
  rv = tlsctrl_vpn_dp_touch_keepalive (tunnel_id, outbound);
  if (rv)
    return clib_error_return (0, "keepalive update failed rv=%d", rv);
  return 0;
}

static clib_error_t *
tlsctrl_vpn_dp_ipv4_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0;
  u32 bytes = 0;
  int outbound = 1;
  int rv;
  (void) vm;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else if (unformat (input, "bytes %u", &bytes))
        ;
      else if (unformat (input, "rx"))
        outbound = 0;
      else if (unformat (input, "tx"))
        outbound = 1;
      else
        break;
    }
  if (!tunnel_id || !bytes)
    return clib_error_return (0, "usage: tlsctrl vpn dataplane ipv4 tunnel-id <id> bytes <n> [rx|tx]");
  rv = tlsctrl_vpn_dp_note_ipv4 (tunnel_id, bytes, outbound);
  if (rv)
    return clib_error_return (0, "ipv4 update failed rv=%d", rv);
  return 0;
}


static clib_error_t *
tlsctrl_vpn_dp_probe_tx_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0, out_tunnel_id = 0;
  u8 *dst = 0;
  u32 payload_len = 64;
  u8 *payload = 0, *frame = 0;
  ip4_header_t *ip4;
  int rv;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else if (unformat (input, "vip %s", &dst))
        ;
      else if (unformat (input, "bytes %u", &payload_len))
        ;
      else
        break;
    }
  if (!dst && !tunnel_id)
    return clib_error_return (0, "usage: tlsctrl vpn dataplane probe-tx [vip <a.b.c.d>|tunnel-id <id>] [bytes <n>]");
  if (payload_len < sizeof (ip4_header_t))
    payload_len = sizeof (ip4_header_t);
  vec_validate (payload, payload_len - 1);
  clib_memset (payload, 0, payload_len);
  ip4 = (ip4_header_t *) payload;
  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 64;
  ip4->protocol = IP_PROTOCOL_ICMP;
  ip4->length = clib_host_to_net_u16 ((u16) payload_len);
  if (dst)
    {
      if (sscanf ((char *) dst, "%hhu.%hhu.%hhu.%hhu", &ip4->dst_address.as_u8[0], &ip4->dst_address.as_u8[1], &ip4->dst_address.as_u8[2], &ip4->dst_address.as_u8[3]) != 4)
        { vec_free (dst); vec_free (payload); return clib_error_return (0, "bad vip"); }
      rv = tlsctrl_vpn_dp_stage8_probe_ip4_packet (payload, payload_len, &frame, &out_tunnel_id);
    }
  else
    {
      rv = tlsctrl_vpn_dp_tx_ipv4_from_vpp (tunnel_id, payload, payload_len, &frame);
      out_tunnel_id = tunnel_id;
    }
  if (rv)
    return clib_error_return (0, "probe-tx failed rv=%d", rv);
  vlib_cli_output (vm, "probe-tx ok tunnel=%llu frame-bytes=%u", (unsigned long long) out_tunnel_id, frame ? vec_len (frame) : 0);
  vec_free (dst); vec_free (payload); vec_free (frame);
  return 0;
}


static clib_error_t *
tlsctrl_vpn_dp_probe_rx_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0;
  u8 *dst = 0;
  u32 payload_len = 64;
  u8 *payload = 0;
  ip4_header_t *ip4;
  int rv;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else if (unformat (input, "dst %s", &dst))
        ;
      else if (unformat (input, "bytes %u", &payload_len))
        ;
      else
        break;
    }
  if (!tunnel_id)
    return clib_error_return (0, "usage: tlsctrl vpn dataplane probe-rx tunnel-id <id> [dst <a.b.c.d>] [bytes <n>]");
  if (payload_len < sizeof (ip4_header_t))
    payload_len = sizeof (ip4_header_t);
  vec_validate (payload, payload_len - 1);
  clib_memset (payload, 0, payload_len);
  ip4 = (ip4_header_t *) payload;
  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 64;
  ip4->protocol = IP_PROTOCOL_ICMP;
  ip4->length = clib_host_to_net_u16 ((u16) payload_len);
  if (dst)
    {
      if (sscanf ((char *) dst, "%hhu.%hhu.%hhu.%hhu", &ip4->dst_address.as_u8[0], &ip4->dst_address.as_u8[1], &ip4->dst_address.as_u8[2], &ip4->dst_address.as_u8[3]) != 4)
        { vec_free (dst); vec_free (payload); return clib_error_return (0, "bad dst"); }
    }
  rv = tlsctrl_vpn_dp_stage9_probe_rx_ipv4 (tunnel_id, payload, payload_len);
  if (rv)
    return clib_error_return (0, "probe-rx failed rv=%d", rv);
  vlib_cli_output (vm, "probe-rx ok tunnel=%llu bytes=%u", (unsigned long long) tunnel_id, payload_len);
  vec_free (dst);
  vec_free (payload);
  return 0;
}

static clib_error_t *
tlsctrl_vpn_dp_autoprobe_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0;
  u32 payload_len = 128;
  u8 *dst = 0;
  u8 *rx_payload = 0;
  u8 *tx_payload = 0;
  u8 *frame = 0;
  ip4_header_t *ip4;
  int rv;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else if (unformat (input, "dst %s", &dst))
        ;
      else if (unformat (input, "bytes %u", &payload_len))
        ;
      else
        break;
    }
  if (!tunnel_id)
    return clib_error_return (0, "usage: tlsctrl vpn dataplane autoprobe tunnel-id <id> [dst <a.b.c.d>] [bytes <n>]");
  if (payload_len < sizeof (ip4_header_t))
    payload_len = sizeof (ip4_header_t);
  vec_validate (rx_payload, payload_len - 1);
  vec_validate (tx_payload, payload_len - 1);
  clib_memset (rx_payload, 0, payload_len);
  clib_memset (tx_payload, 0, payload_len);
  ip4 = (ip4_header_t *) rx_payload;
  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 64;
  ip4->protocol = IP_PROTOCOL_ICMP;
  ip4->length = clib_host_to_net_u16 ((u16) payload_len);
  if (dst)
    {
      if (sscanf ((char *) dst, "%hhu.%hhu.%hhu.%hhu", &ip4->dst_address.as_u8[0], &ip4->dst_address.as_u8[1], &ip4->dst_address.as_u8[2], &ip4->dst_address.as_u8[3]) != 4)
        { vec_free (dst); vec_free (rx_payload); vec_free (tx_payload); return clib_error_return (0, "bad dst"); }
    }
  ip4 = (ip4_header_t *) tx_payload;
  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 64;
  ip4->protocol = IP_PROTOCOL_ICMP;
  ip4->length = clib_host_to_net_u16 ((u16) payload_len);
  rv = tlsctrl_vpn_dp_stage10_autoprobe (tunnel_id, rx_payload, payload_len, tx_payload, payload_len, &frame);
  if (rv)
    {
      vec_free (dst); vec_free (rx_payload); vec_free (tx_payload); vec_free (frame);
      return clib_error_return (0, "autoprobe failed rv=%d", rv);
    }
  vlib_cli_output (vm, "autoprobe ok tunnel=%llu tx-frame-bytes=%u", (unsigned long long) tunnel_id, frame ? vec_len (frame) : 0);
  vec_free (dst); vec_free (rx_payload); vec_free (tx_payload); vec_free (frame);
  return 0;
}

VLIB_CLI_COMMAND (show_tlsctrl_vpn_dataplane_cmd, static) = {
  .path = "show tlsctrl vpn dataplane",
  .short_help = "show tlsctrl vpn dataplane",
  .function = show_tlsctrl_vpn_dataplane_fn,
};

VLIB_CLI_COMMAND (show_tlsctrl_vpn_routes_cmd, static) = {
  .path = "show tlsctrl vpn routes",
  .short_help = "show tlsctrl vpn routes",
  .function = show_tlsctrl_vpn_routes_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_dp_keepalive_command, static) = {
  .path = "tlsctrl vpn dataplane keepalive",
  .short_help = "tlsctrl vpn dataplane keepalive tunnel-id <id> [rx|tx]",
  .function = tlsctrl_vpn_dp_keepalive_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_dp_ipv4_command, static) = {
  .path = "tlsctrl vpn dataplane ipv4",
  .short_help = "tlsctrl vpn dataplane ipv4 tunnel-id <id> bytes <n> [rx|tx]",
  .function = tlsctrl_vpn_dp_ipv4_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_dp_probe_rx_command, static) = {
  .path = "tlsctrl vpn dataplane probe-rx",
  .short_help = "tlsctrl vpn dataplane probe-rx tunnel-id <id> [dst <a.b.c.d>] [bytes <n>]",
  .function = tlsctrl_vpn_dp_probe_rx_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_dp_probe_tx_command, static) = {
  .path = "tlsctrl vpn dataplane probe-tx",
  .short_help = "tlsctrl vpn dataplane probe-tx [vip <a.b.c.d>|tunnel-id <id>] [bytes <n>]",
  .function = tlsctrl_vpn_dp_probe_tx_command_fn,
};


VLIB_CLI_COMMAND (tlsctrl_vpn_dp_autoprobe_command, static) = {
  .path = "tlsctrl vpn dataplane autoprobe",
  .short_help = "tlsctrl vpn dataplane autoprobe tunnel-id <id> [dst <a.b.c.d>] [bytes <n>]",
  .function = tlsctrl_vpn_dp_autoprobe_command_fn,
};

static clib_error_t *
tlsctrl_vpn_dp_autobridge_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                      vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0;
  ip4_address_t dst = {0};
  u32 payload_len = 128;
  u8 *payload = 0;
  u8 *frame = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else if (unformat (input, "dst %U", unformat_ip4_address, &dst))
        ;
      else if (unformat (input, "bytes %u", &payload_len))
        ;
      else
        return clib_error_return (0, "usage: tlsctrl vpn dataplane autobridge tunnel-id <id> [dst <a.b.c.d>] [bytes <n>]");
    }

  if (!tunnel_id)
    return clib_error_return (0, "usage: tlsctrl vpn dataplane autobridge tunnel-id <id> [dst <a.b.c.d>] [bytes <n>]");

  vec_validate (payload, payload_len - 1);
  clib_memset (payload, 0, payload_len);
  if (payload_len >= 20)
    {
      payload[0] = 0x45;
      payload[2] = (payload_len >> 8) & 0xff;
      payload[3] = payload_len & 0xff;
      clib_memcpy_fast (payload + 16, &dst.as_u8, sizeof (dst.as_u8));
    }

  rv = tlsctrl_vpn_dp_stage11_tick (tunnel_id, payload, payload_len, &frame);
  vec_free (payload);
  vec_free (frame);
  if (rv)
    return clib_error_return (0, "autobridge failed rv=%d", rv);

  vlib_cli_output (vm, "autobridge ok tunnel=%llu bytes=%u", (unsigned long long) tunnel_id, payload_len);
  return 0;
}

static clib_error_t *
tlsctrl_vpn_dp_autohook_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0;
  u8 enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else if (unformat (input, "enable"))
        enable = 1;
      else if (unformat (input, "disable"))
        enable = 0;
      else
        return clib_error_return (0, "usage: tlsctrl vpn dataplane autohook tunnel-id <id> [enable|disable]");
    }

  if (!tunnel_id)
    return clib_error_return (0, "usage: tlsctrl vpn dataplane autohook tunnel-id <id> [enable|disable]");

  if (tlsctrl_vpn_dp_stage13_enable_hook (tunnel_id, enable))
    return clib_error_return (0, "autohook failed");

  vlib_cli_output (vm, "autohook %s tunnel=%llu", enable ? "enabled" : "disabled", (unsigned long long) tunnel_id);
  return 0;
}

VLIB_CLI_COMMAND (tlsctrl_vpn_dp_autobridge_command, static) = {
  .path = "tlsctrl vpn dataplane autobridge",
  .short_help = "tlsctrl vpn dataplane autobridge tunnel-id <id> [dst <a.b.c.d>] [bytes <n>]",
  .function = tlsctrl_vpn_dp_autobridge_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_dp_autohook_command, static) = {
  .path = "tlsctrl vpn dataplane autohook",
  .short_help = "tlsctrl vpn dataplane autohook tunnel-id <id> [enable|disable]",
  .function = tlsctrl_vpn_dp_autohook_command_fn,
};

VLIB_CLI_COMMAND (show_tlsctrl_vpn_health_cmd, static) = {
  .path = "show tlsctrl vpn health",
  .short_help = "show tlsctrl vpn health [detail]",
  .function = show_tlsctrl_vpn_health_fn,
};

VLIB_CLI_COMMAND (show_tlsctrl_vpn_users_cmd, static) = {
  .path = "show tlsctrl vpn users",
  .short_help = "show tlsctrl vpn users [detail]",
  .function = show_tlsctrl_vpn_users_fn,
};

VLIB_CLI_COMMAND (show_tlsctrl_vpn_policy_cmd, static) = {
  .path = "show tlsctrl vpn policy",
  .short_help = "show tlsctrl vpn policy",
  .function = show_tlsctrl_vpn_policy_fn,
};

VLIB_CLI_COMMAND (set_tlsctrl_vpn_policy_cmd, static) = {
  .path = "set tlsctrl vpn policy",
  .short_help = "set tlsctrl vpn policy stale-timeout <sec> [force-close <0|1>]",
  .function = set_tlsctrl_vpn_policy_fn,
};

VLIB_CLI_COMMAND (reap_tlsctrl_vpn_stale_cmd, static) = {
  .path = "tlsctrl vpn reap stale",
  .short_help = "tlsctrl vpn reap stale [timeout <sec>] [force|no-force]",
  .function = reap_tlsctrl_vpn_stale_fn,
};

VLIB_CLI_COMMAND (clear_tlsctrl_vpn_counters_cmd, static) = {
  .path = "clear tlsctrl vpn counters",
  .short_help = "clear tlsctrl vpn counters [all|tunnel-id <id>] [full]",
  .function = clear_tlsctrl_vpn_counters_fn,
};


static clib_error_t *
show_tlsctrl_vpn_workers_fn (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *cmd)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_dp_session_t *s;
  (void) input;
  (void) cmd;

  clib_spinlock_lock (&m->lock);
  vlib_cli_output (vm, "vpn workers: sessions=%u", vec_len (m->dp_sessions));
  vec_foreach (s, m->dp_sessions)
    vlib_cli_output (vm,
                     "  tunnel=%llu user=%s owner=%u bind=%u wrong=%llu handoff=%llu drop=%llu",
                     (unsigned long long) s->tunnel_id,
                     s->username ? (char *) s->username : "-",
                     s->owner_thread_index, s->last_bind_thread_index,
                     (unsigned long long) s->wrong_worker_hits,
                     (unsigned long long) s->handoff_count,
                     (unsigned long long) s->handoff_drops);
  clib_spinlock_unlock (&m->lock);
  return 0;
}

VLIB_CLI_COMMAND (show_tlsctrl_vpn_workers_cmd, static) = {
  .path = "show tlsctrl vpn workers",
  .short_help = "show tlsctrl vpn workers",
  .function = show_tlsctrl_vpn_workers_fn,
};
