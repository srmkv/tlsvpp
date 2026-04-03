#include <vlib/vlib.h>
#include <vppinfra/format.h>
#include "tlsctrl_vpn.h"

typedef tlsctrl_vpn_main_t tvpn_main_t;

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
tlsctrl_vpn_dp_attach (u64 tunnel_id, u64 session_handle)
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
    }
  s->session_handle = session_handle;
  s->running = 1;
  s->last_tx_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int
tlsctrl_vpn_dp_detach (u64 tunnel_id)
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
  s->running = 0;
  s->session_handle = 0;
  s->last_tx_unix_ns = clib_cpu_time_now ();
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
  clib_spinlock_unlock (&m->lock);
  return 0;
}
