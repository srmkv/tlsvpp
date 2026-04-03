#include <vlib/vlib.h>
#include <vppinfra/string.h>
#include "tlsctrl_vpn.h"

static void
_tlsctrl_vpn_frame_put_hdr (u8 **b, u8 type, u8 flags, u32 payload_len,
                            u64 tunnel_id, u64 seq)
{
  tlsctrl_vpn_frame_hdr_t h = {
    .type = type,
    .flags = flags,
    .reserved = 0,
    .len = payload_len,
    .tunnel_id = tunnel_id,
    .seq = seq,
  };
  vec_add (*b, (u8 *)&h, sizeof (h));
}

int
tlsctrl_vpn_frame_tx_keepalive (u64 tunnel_id, u8 **out_frame)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  u64 seq = 1;
  if (out_frame)
    *out_frame = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s))
    return -1;
  if (s)
    seq = s->seq_tx + 1;
  if (out_frame)
    _tlsctrl_vpn_frame_put_hdr (out_frame, TLSCTRL_VPN_FRAME_TYPE_KEEPALIVE, 0, 0, tunnel_id, seq);
  tlsctrl_vpn_stream_note_keepalive (tunnel_id, 1);
  return tlsctrl_vpn_dp_touch_keepalive (tunnel_id, 1);
}

int
tlsctrl_vpn_frame_tx_ipv4 (u64 tunnel_id, const u8 *payload, u32 payload_len,
                           u8 **out_frame)
{
  tlsctrl_vpn_dp_session_t *s = 0;
  u64 seq = 1;
  if (out_frame)
    *out_frame = 0;
  if (tlsctrl_vpn_dp_find_session (tunnel_id, &s))
    return -1;
  if (s)
    seq = s->seq_tx + 1;
  if (out_frame)
    {
      _tlsctrl_vpn_frame_put_hdr (out_frame, TLSCTRL_VPN_FRAME_TYPE_IPV4, 0, payload_len, tunnel_id, seq);
      if (payload && payload_len)
        vec_add (*out_frame, (u8 *)payload, payload_len);
    }
  tlsctrl_vpn_stream_note_ipv4 (tunnel_id, payload_len, 1);
  tlsctrl_vpn_transport_note_packet (tunnel_id, payload_len, 1);
  return tlsctrl_vpn_dp_note_ipv4 (tunnel_id, payload_len, 1);
}

int
tlsctrl_vpn_frame_rx (u64 tunnel_id, const u8 *frame, u32 frame_len,
                      tlsctrl_vpn_frame_meta_t *meta, u8 **out_payload)
{
  const tlsctrl_vpn_frame_hdr_t *h;
  u32 payload_len;
  if (meta)
    clib_memset (meta, 0, sizeof (*meta));
  if (out_payload)
    *out_payload = 0;
  if (!frame || frame_len < sizeof (tlsctrl_vpn_frame_hdr_t))
    return -1;
  h = (const tlsctrl_vpn_frame_hdr_t *)frame;
  payload_len = h->len;
  if (frame_len < sizeof (*h) + payload_len)
    return -2;
  if (h->tunnel_id != tunnel_id)
    return -3;
  if (meta)
    {
      meta->tunnel_id = h->tunnel_id;
      meta->type = h->type;
      meta->flags = h->flags;
      meta->seq = h->seq;
      meta->payload_len = payload_len;
    }
  if (payload_len && out_payload)
    vec_add (*out_payload, frame + sizeof (*h), payload_len);
  switch (h->type)
    {
    case TLSCTRL_VPN_FRAME_TYPE_KEEPALIVE:
      tlsctrl_vpn_stream_note_keepalive (tunnel_id, 0);
      return tlsctrl_vpn_dp_touch_keepalive (tunnel_id, 0);
    case TLSCTRL_VPN_FRAME_TYPE_IPV4:
      tlsctrl_vpn_stream_note_ipv4 (tunnel_id, payload_len, 0);
      tlsctrl_vpn_transport_note_packet (tunnel_id, payload_len, 0);
      return tlsctrl_vpn_dp_note_ipv4 (tunnel_id, payload_len, 0);
    default:
      return 0;
    }
}
