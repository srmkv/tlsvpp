#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include "tlsctrl_vpn.h"

static clib_error_t *
tlsctrl_vpn_frame_tx_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0;
  u32 bytes = 0;
  int keepalive = 0;
  int rv;
  u8 *frame = 0;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else if (unformat (input, "keepalive"))
        keepalive = 1;
      else if (unformat (input, "ipv4 bytes %u", &bytes))
        ;
      else
        break;
    }
  if (!tunnel_id || (!keepalive && !bytes))
    return clib_error_return (0, "usage: tlsctrl vpn frame tx tunnel-id <id> keepalive|ipv4 bytes <n>");
  if (keepalive)
    rv = tlsctrl_vpn_frame_tx_keepalive (tunnel_id, &frame);
  else
    {
      u8 *payload = 0;
      if (bytes)
        vec_validate (payload, bytes - 1);
      rv = tlsctrl_vpn_frame_tx_ipv4 (tunnel_id, payload, bytes, &frame);
      vec_free (payload);
    }
  if (rv)
    {
      vec_free (frame);
      return clib_error_return (0, "frame tx failed rv=%d", rv);
    }
  vlib_cli_output (vm, "frame tx ok tunnel=%llu len=%u",
                   (unsigned long long)tunnel_id, frame ? vec_len (frame) : 0);
  vec_free (frame);
  return 0;
}

static clib_error_t *
tlsctrl_vpn_frame_rx_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *cmd)
{
  u64 tunnel_id = 0;
  u32 bytes = 0;
  int keepalive = 0;
  int rv;
  u8 *frame = 0, *payload = 0;
  tlsctrl_vpn_frame_meta_t meta;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else if (unformat (input, "keepalive"))
        keepalive = 1;
      else if (unformat (input, "ipv4 bytes %u", &bytes))
        ;
      else
        break;
    }
  if (!tunnel_id || (!keepalive && !bytes))
    return clib_error_return (0, "usage: tlsctrl vpn frame rx tunnel-id <id> keepalive|ipv4 bytes <n>");
  if (keepalive)
    tlsctrl_vpn_frame_tx_keepalive (tunnel_id, &frame);
  else
    {
      u8 *p = 0;
      if (bytes)
        vec_validate (p, bytes - 1);
      tlsctrl_vpn_frame_tx_ipv4 (tunnel_id, p, bytes, &frame);
      vec_free (p);
    }
  rv = tlsctrl_vpn_frame_rx (tunnel_id, frame, frame ? vec_len (frame) : 0, &meta, &payload);
  if (rv)
    {
      vec_free (frame);
      vec_free (payload);
      return clib_error_return (0, "frame rx failed rv=%d", rv);
    }
  vlib_cli_output (vm, "frame rx ok tunnel=%llu type=%u seq=%llu payload=%u",
                   (unsigned long long)meta.tunnel_id, meta.type,
                   (unsigned long long)meta.seq, meta.payload_len);
  vec_free (frame);
  vec_free (payload);
  return 0;
}

VLIB_CLI_COMMAND (tlsctrl_vpn_frame_tx_command, static) = {
  .path = "tlsctrl vpn frame tx",
  .short_help = "tlsctrl vpn frame tx tunnel-id <id> keepalive|ipv4 bytes <n>",
  .function = tlsctrl_vpn_frame_tx_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_frame_rx_command, static) = {
  .path = "tlsctrl vpn frame rx",
  .short_help = "tlsctrl vpn frame rx tunnel-id <id> keepalive|ipv4 bytes <n>",
  .function = tlsctrl_vpn_frame_rx_command_fn,
};
