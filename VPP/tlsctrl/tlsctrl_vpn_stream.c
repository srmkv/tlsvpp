#include <vlib/vlib.h>
#include <vppinfra/format.h>
#include <vnet/session/session.h>
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




u32
tlsctrl_vpn_thread_index_from_session_handle (u64 session_handle)
{
  session_t *sess;

  if (!session_handle)
    return ~0;

  sess = session_get_from_handle (session_handle);
  if (!sess)
    return ~0;

  return sess->thread_index;
}

int
tlsctrl_vpn_stream_attach_by_username (const char *username, u64 session_handle)
{
  u64 tunnel_id = 0;

  if (!username || !session_handle)
    return -1;

  if (tlsctrl_vpn_find_tunnel_id_by_username (username, &tunnel_id) != 0 || !tunnel_id)
    return -1;

  return tlsctrl_vpn_stream_attach (tunnel_id, session_handle);
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
  s->owner_thread_index = ~0;
  s->last_bind_thread_index = ~0;
  s->duplex_anchor = 0;
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
  u32 bind_thread = tlsctrl_vpn_thread_index_from_session_handle (session_handle);
  int do_dp_attach = 0;

  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_ensure (tunnel_id);
  s->last_bind_thread_index = bind_thread;

  if (bind_thread != ~0 && s->owner_thread_index == ~0)
    s->owner_thread_index = bind_thread;

  if (bind_thread != ~0 && s->owner_thread_index != ~0
      && s->owner_thread_index != bind_thread && s->bound)
    {
      s->wrong_worker_hits += 1;
      s->handoff_count += 1;
      s->running = 1;
      s->last_tx_unix_ns = clib_cpu_time_now ();
      clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
      return 1;
    }

  if (s->duplex_anchor && s->session_handle && s->session_handle != session_handle)
    {
      s->last_tx_unix_ns = clib_cpu_time_now ();
      s->running = 1;
      clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
      return 1;
    }

  s->session_handle = session_handle;
  s->bound = session_handle ? 1 : 0;
  s->running = 1;
  s->last_tx_unix_ns = clib_cpu_time_now ();
  do_dp_attach = 1;
  clib_spinlock_unlock (&tlsctrl_vpn_main.lock);

  if (do_dp_attach)
    tlsctrl_vpn_dp_attach (tunnel_id, session_handle);
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
  s->duplex_anchor = 0;
  s->last_tx_unix_ns = clib_cpu_time_now ();
  clib_spinlock_unlock (&tlsctrl_vpn_main.lock);

  /* New: stream loss/bind removal also drops dataplane running/session-handle state. */
  tlsctrl_vpn_dp_detach (tunnel_id);
  return 0;
}

int
tlsctrl_vpn_stream_note_keepalive (u64 tunnel_id, int outbound)
{
  tlsctrl_vpn_stream_session_t *s;
  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_ensure (tunnel_id);
  s->running = 1;
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

  tlsctrl_vpn_dp_touch_keepalive (tunnel_id, outbound);
  return 0;
}

int
tlsctrl_vpn_stream_note_ipv4 (u64 tunnel_id, u32 bytes, int outbound)
{
  tlsctrl_vpn_stream_session_t *s;
  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_ensure (tunnel_id);
  s->running = 1;
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

  tlsctrl_vpn_dp_note_ipv4 (tunnel_id, bytes, outbound);
  tlsctrl_vpn_transport_note_packet (tunnel_id, bytes, outbound);
  return 0;
}

int
tlsctrl_vpn_stream_mark_duplex_anchor (u64 tunnel_id, u64 session_handle)
{
  tlsctrl_vpn_stream_session_t *s;
  u32 bind_thread = tlsctrl_vpn_thread_index_from_session_handle (session_handle);

  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_ensure (tunnel_id);
  if (bind_thread != ~0 && s->owner_thread_index == ~0)
    s->owner_thread_index = bind_thread;
  s->last_bind_thread_index = bind_thread;
  s->session_handle = session_handle;
  s->bound = session_handle ? 1 : 0;
  s->running = 1;
  s->duplex_anchor = 1;
  s->last_rx_unix_ns = clib_cpu_time_now ();
  s->last_tx_unix_ns = s->last_rx_unix_ns;
  clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
  return 0;
}

int
tlsctrl_vpn_stream_clear_duplex_anchor (u64 tunnel_id, u64 session_handle)
{
  tlsctrl_vpn_stream_session_t *s;

  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_find (tunnel_id);
  if (!s)
    {
      clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
      return -1;
    }
  if (s->duplex_anchor && (!session_handle || s->session_handle == session_handle))
    {
      s->duplex_anchor = 0;
      if (session_handle && s->session_handle == session_handle)
        s->session_handle = 0;
      s->bound = 0;
      s->running = 0;
      s->last_tx_unix_ns = clib_cpu_time_now ();
    }
  clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
  return 0;
}

int
tlsctrl_vpn_stream_is_duplex_anchored (u64 tunnel_id, u64 session_handle)
{
  tlsctrl_vpn_stream_session_t *s;
  int rv = 0;

  clib_spinlock_lock (&tlsctrl_vpn_main.lock);
  s = tvpn_stream_find (tunnel_id);
  if (s && s->duplex_anchor && s->session_handle && s->session_handle != session_handle)
    rv = 1;
  clib_spinlock_unlock (&tlsctrl_vpn_main.lock);
  return rv;
}
