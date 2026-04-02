#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <vppinfra/format.h>
#include <tlsctrl/tlsctrl_vpn.h>

extern int tlsctrl_vpn_transport_find_session (u64 tunnel_id, tlsctrl_vpn_transport_session_t **out);
extern int tlsctrl_vpn_transport_attach (u64 tunnel_id, const char *tun_if_name);
extern int tlsctrl_vpn_transport_detach (u64 tunnel_id);
extern int tlsctrl_vpn_transport_note_packet (u64 tunnel_id, u32 bytes, int outbound);
extern int tlsctrl_vpn_transport_note_drop (u64 tunnel_id, u32 reason, int outbound);
extern int tlsctrl_vpn_transport_set_queue_depth (u64 tunnel_id, u32 depth);

static clib_error_t *
show_tlsctrl_vpn_transport_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  tlsctrl_vpn_transport_session_t *s;
  vlib_cli_output (vm, "vpn transport: sessions=%u", vec_len (tlsctrl_vpn_transport_main.sessions));
  vec_foreach (s, tlsctrl_vpn_transport_main.sessions)
    {
      vlib_cli_output (vm,
                       "  tunnel=%llu tun=%s running=%u txp=%llu rxp=%llu txd=%llu rxd=%llu q=%llu err=%llu ip=%s gw=%s dns=%s mtu=%u mss=%u",
                       (unsigned long long) s->tunnel_id,
                       s->tun_if_name ? (char *) s->tun_if_name : "-",
                       s->running,
                       (unsigned long long) s->tx_packets,
                       (unsigned long long) s->rx_packets,
                       (unsigned long long) s->tx_drops,
                       (unsigned long long) s->rx_drops,
                       (unsigned long long) s->queue_depth,
                       (unsigned long long) s->last_error_code,
                       s->assigned_ip ? (char *) s->assigned_ip : "-",
                       s->gateway ? (char *) s->gateway : "-",
                       s->dns_servers ? (char *) s->dns_servers : "-",
                       s->mtu, s->mss_clamp);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_tlsctrl_vpn_transport_cmd, static) = {
  .path = "show tlsctrl vpn transport",
  .short_help = "show tlsctrl vpn transport",
  .function = show_tlsctrl_vpn_transport_fn,
};

static clib_error_t *
set_tlsctrl_vpn_transport_attach_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 tunnel_id = 0;
  u8 *tun = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %u", &tunnel_id)) ;
      else if (unformat (input, "tun %s", &tun)) ;
      else break;
    }
  if (!tunnel_id)
    return clib_error_return (0, "tunnel-id required");
  if (tlsctrl_vpn_transport_attach (tunnel_id, (char *) tun))
    return clib_error_return (0, "attach failed");
  vec_free (tun);
  return 0;
}

VLIB_CLI_COMMAND (set_tlsctrl_vpn_transport_attach_cmd, static) = {
  .path = "tlsctrl vpn transport attach",
  .short_help = "tlsctrl vpn transport attach tunnel-id <id> tun <name>",
  .function = set_tlsctrl_vpn_transport_attach_fn,
};

static clib_error_t *
set_tlsctrl_vpn_transport_detach_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 tunnel_id = 0;
  if (!unformat (input, "tunnel-id %u", &tunnel_id))
    return clib_error_return (0, "tunnel-id required");
  if (tlsctrl_vpn_transport_detach (tunnel_id))
    return clib_error_return (0, "detach failed");
  return 0;
}

VLIB_CLI_COMMAND (set_tlsctrl_vpn_transport_detach_cmd, static) = {
  .path = "tlsctrl vpn transport detach",
  .short_help = "tlsctrl vpn transport detach tunnel-id <id>",
  .function = set_tlsctrl_vpn_transport_detach_fn,
};

static clib_error_t *
set_tlsctrl_vpn_transport_packet_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 tunnel_id = 0, bytes = 0;
  int outbound = 1;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %u", &tunnel_id)) ;
      else if (unformat (input, "bytes %u", &bytes)) ;
      else if (unformat (input, "rx")) outbound = 0;
      else if (unformat (input, "tx")) outbound = 1;
      else break;
    }
  if (!tunnel_id)
    return clib_error_return (0, "tunnel-id required");
  if (tlsctrl_vpn_transport_note_packet (tunnel_id, bytes, outbound))
    return clib_error_return (0, "packet note failed");
  return 0;
}

VLIB_CLI_COMMAND (set_tlsctrl_vpn_transport_packet_cmd, static) = {
  .path = "tlsctrl vpn transport packet",
  .short_help = "tlsctrl vpn transport packet tunnel-id <id> bytes <n> [rx|tx]",
  .function = set_tlsctrl_vpn_transport_packet_fn,
};

static clib_error_t *
set_tlsctrl_vpn_transport_drop_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 tunnel_id = 0, reason = 0;
  int outbound = 1;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %u", &tunnel_id)) ;
      else if (unformat (input, "reason %u", &reason)) ;
      else if (unformat (input, "rx")) outbound = 0;
      else if (unformat (input, "tx")) outbound = 1;
      else break;
    }
  if (!tunnel_id)
    return clib_error_return (0, "tunnel-id required");
  if (tlsctrl_vpn_transport_note_drop (tunnel_id, reason, outbound))
    return clib_error_return (0, "drop note failed");
  return 0;
}

VLIB_CLI_COMMAND (set_tlsctrl_vpn_transport_drop_cmd, static) = {
  .path = "tlsctrl vpn transport drop",
  .short_help = "tlsctrl vpn transport drop tunnel-id <id> reason <code> [rx|tx]",
  .function = set_tlsctrl_vpn_transport_drop_fn,
};

static clib_error_t *
set_tlsctrl_vpn_transport_queue_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 tunnel_id = 0, depth = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %u", &tunnel_id)) ;
      else if (unformat (input, "depth %u", &depth)) ;
      else break;
    }
  if (!tunnel_id)
    return clib_error_return (0, "tunnel-id required");
  if (tlsctrl_vpn_transport_set_queue_depth (tunnel_id, depth))
    return clib_error_return (0, "queue depth set failed");
  return 0;
}

VLIB_CLI_COMMAND (set_tlsctrl_vpn_transport_queue_cmd, static) = {
  .path = "tlsctrl vpn transport queue",
  .short_help = "tlsctrl vpn transport queue tunnel-id <id> depth <n>",
  .function = set_tlsctrl_vpn_transport_queue_fn,
};
