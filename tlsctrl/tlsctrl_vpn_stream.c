#include <vlib/vlib.h>
#include <vppinfra/format.h>
#include "tlsctrl_vpn.h"

static tlsctrl_vpn_stream_session_t *
tvpn_stream_find (u64 tunnel_id)
{
  tlsctrl_vpn_stream_session_t *s;
  vec_foreach (s, tlsctrl_vpn_main.stream_sessions)
    if (s->tunnel_id == tunnel_id)
      return s;
  return 0;
}

int
tlsctrl_vpn_stream_find_session (u64 tunnel_id, tlsctrl_vpn_stream_session_t **out)
{
  tlsctrl_vpn_stream_session_t *s;
  if (out)
    *out = 0;
  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_find (tunnel_id);
  if (s && out)
    *out = s;
  clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
  return s ? 0 : -1;
}

static tlsctrl_vpn_stream_session_t *
tvpn_stream_ensure (u64 tunnel_id)
{
  tlsctrl_vpn_stream_session_t *s = tvpn_stream_find (tunnel_id);
  if (s)
    return s;
  vec_add2 (tlsctrl_vpn_main.stream_sessions, s, 1);
  clib_memset (s, 0, sizeof (*s));
  s->tunnel_id = tunnel_id;
  return s;
}

clib_error_t *
tlsctrl_vpn_stream_init (vlib_main_t * vm)
{
  (void) vm;
  return 0;
}

int
tlsctrl_vpn_stream_attach (u64 tunnel_id, u64 session_handle)
{
  tlsctrl_vpn_stream_session_t *s;
  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_ensure (tunnel_id);
  s->session_handle = session_handle;
  s->bound = 1;
  s->running = 1;
  s->last_tx_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
  return 0;
}

int
tlsctrl_vpn_stream_detach (u64 tunnel_id)
{
  tlsctrl_vpn_stream_session_t *s;
  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_find (tunnel_id);
  if (!s)
    {
      clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
      return -1;
    }
  s->running = 0;
  s->bound = 0;
  s->session_handle = 0;
  s->last_tx_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
  return 0;
}

int
tlsctrl_vpn_stream_note_keepalive (u64 tunnel_id, int outbound)
{
  tlsctrl_vpn_stream_session_t *s;
  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_ensure (tunnel_id);
  if (outbound)
    {
      s->keepalives_tx += 1;
      s->tx_frames += 1;
      s->last_tx_unix_ns = clib_cpu_time_now ();
    }
  else
    {
      s->keepalives_rx += 1;
      s->rx_frames += 1;
      s->last_rx_unix_ns = clib_cpu_time_now ();
    }
  clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
  return 0;
}

int
tlsctrl_vpn_stream_note_ipv4 (u64 tunnel_id, u32 bytes, int outbound)
{
  tlsctrl_vpn_stream_session_t *s;
  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_ensure (tunnel_id);
  if (outbound)
    {
      s->ipv4_tx += 1;
      s->tx_frames += 1;
      s->tx_bytes += bytes;
      s->last_tx_unix_ns = clib_cpu_time_now ();
    }
  else
    {
      s->ipv4_rx += 1;
      s->rx_frames += 1;
      s->rx_bytes += bytes;
      s->last_rx_unix_ns = clib_cpu_time_now ();
    }
  clib_spinlock_unlock (&tlsctrl_vpn_main.lock);

  /* reflect IPv4 tunnel traffic into transport counters on the stable base */
  tlsctrl_vpn_transport_note_packet (tunnel_id, bytes, outbound);
  return 0;
}
