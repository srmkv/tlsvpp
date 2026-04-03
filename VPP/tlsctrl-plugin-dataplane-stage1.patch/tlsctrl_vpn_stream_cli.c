
#include <vlib/vlib.h>
#include "tlsctrl_vpn.h"

static clib_error_t *
show_tlsctrl_vpn_stream_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  tlsctrl_vpn_stream_session_t *s;
  (void) input; (void) cmd;
  vlib_cli_output (vm, "vpn stream: sessions=%u", vec_len (tlsctrl_vpn_main.stream_sessions));
  vec_foreach (s, tlsctrl_vpn_main.stream_sessions)
    vlib_cli_output (vm, "  tunnel=%llu bound=%u running=%u sh=0x%llx rxf=%llu txf=%llu rxb=%llu txb=%llu krx=%llu ktx=%llu ip4rx=%llu ip4tx=%llu lrx=%llu ltx=%llu",
                     (unsigned long long) s->tunnel_id,
                     s->bound, s->running,
                     (unsigned long long) s->session_handle,
                     (unsigned long long) s->rx_frames,
                     (unsigned long long) s->tx_frames,
                     (unsigned long long) s->rx_bytes,
                     (unsigned long long) s->tx_bytes,
                     (unsigned long long) s->keepalives_rx,
                     (unsigned long long) s->keepalives_tx,
                     (unsigned long long) s->ipv4_rx,
                     (unsigned long long) s->ipv4_tx,
                     (unsigned long long) s->last_rx_unix_ns,
                     (unsigned long long) s->last_tx_unix_ns);
  return 0;
}

static clib_error_t *
tlsctrl_vpn_stream_attach_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0, sh = 0;
  (void) vm; (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id)) ;
      else if (unformat (input, "session-handle %llu", &sh)) ;
      else break;
    }
  if (!tunnel_id)
    return clib_error_return (0, "tunnel-id required");
  return tlsctrl_vpn_stream_attach (tunnel_id, sh)
    ? clib_error_return (0, "stream attach failed") : 0;
}

static clib_error_t *
tlsctrl_vpn_stream_detach_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0;
  (void) vm; (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    if (unformat (input, "tunnel-id %llu", &tunnel_id)) ; else break;
  if (!tunnel_id)
    return clib_error_return (0, "tunnel-id required");
  return tlsctrl_vpn_stream_detach (tunnel_id)
    ? clib_error_return (0, "stream detach failed") : 0;
}

static clib_error_t *
tlsctrl_vpn_stream_keepalive_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0; int outbound = 0;
  (void) vm; (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id)) ;
      else if (unformat (input, "tx")) outbound = 1;
      else if (unformat (input, "rx")) outbound = 0;
      else break;
    }
  if (!tunnel_id)
    return clib_error_return (0, "tunnel-id required");
  return tlsctrl_vpn_stream_note_keepalive (tunnel_id, outbound)
    ? clib_error_return (0, "stream keepalive failed") : 0;
}

static clib_error_t *
tlsctrl_vpn_stream_ipv4_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0; u32 bytes = 0; int outbound = 0;
  (void) vm; (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id)) ;
      else if (unformat (input, "bytes %u", &bytes)) ;
      else if (unformat (input, "tx")) outbound = 1;
      else if (unformat (input, "rx")) outbound = 0;
      else break;
    }
  if (!tunnel_id)
    return clib_error_return (0, "tunnel-id required");
  return tlsctrl_vpn_stream_note_ipv4 (tunnel_id, bytes, outbound)
    ? clib_error_return (0, "stream ipv4 failed") : 0;
}

VLIB_CLI_COMMAND (show_tlsctrl_vpn_stream_cmd, static) = {
  .path = "show tlsctrl vpn stream",
  .short_help = "show tlsctrl vpn stream",
  .function = show_tlsctrl_vpn_stream_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_stream_attach_cmd, static) = {
  .path = "tlsctrl vpn stream attach",
  .short_help = "tlsctrl vpn stream attach tunnel-id <id> [session-handle <h>]",
  .function = tlsctrl_vpn_stream_attach_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_stream_detach_cmd, static) = {
  .path = "tlsctrl vpn stream detach",
  .short_help = "tlsctrl vpn stream detach tunnel-id <id>",
  .function = tlsctrl_vpn_stream_detach_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_stream_keepalive_cmd, static) = {
  .path = "tlsctrl vpn stream keepalive",
  .short_help = "tlsctrl vpn stream keepalive tunnel-id <id> [rx|tx]",
  .function = tlsctrl_vpn_stream_keepalive_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_stream_ipv4_cmd, static) = {
  .path = "tlsctrl vpn stream ipv4",
  .short_help = "tlsctrl vpn stream ipv4 tunnel-id <id> bytes <n> [rx|tx]",
  .function = tlsctrl_vpn_stream_ipv4_command_fn,
};
