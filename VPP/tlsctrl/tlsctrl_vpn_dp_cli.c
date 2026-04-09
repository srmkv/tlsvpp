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
        "  tunnel=%llu running=%u up=%u sh=0x%llx sw_if_index=%u fib=%u if=%s vip=%s gw=%s user=%s profile=%s q=%u drop=%u route=%u txready=%u txhook=%u stage8=%u stage10=%u stage11=%u stage13=%u",
        (unsigned long long) s->tunnel_id, s->running, s->is_up,
        (unsigned long long) s->session_handle, s->sw_if_index,
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
        "    life gen=%llu open=%llu close=%llu reset=%llu",
        (unsigned long long) s->connect_generation,
        (unsigned long long) s->session_open_count,
        (unsigned long long) s->session_close_count,
        (unsigned long long) s->session_reset_count);
    }
  clib_spinlock_unlock (&m->lock);
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
