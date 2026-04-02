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
  vlib_cli_output (vm, "vpn dataplane: sessions=%u", vec_len (m->dp_sessions));
  vec_foreach (s, m->dp_sessions)
    vlib_cli_output (vm,
                     "  tunnel=%llu running=%u sh=0x%llx seq=%llu rxf=%llu txf=%llu rxb=%llu txb=%llu krx=%llu ktx=%llu ip4rx=%llu ip4tx=%llu lrx=%llu ltx=%llu",
                     (unsigned long long) s->tunnel_id, s->running,
                     (unsigned long long) s->session_handle,
                     (unsigned long long) s->seq_tx,
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

VLIB_CLI_COMMAND (show_tlsctrl_vpn_dataplane_cmd, static) = {
  .path = "show tlsctrl vpn dataplane",
  .short_help = "show tlsctrl vpn dataplane",
  .function = show_tlsctrl_vpn_dataplane_fn,
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
