#include <vppinfra/format.h>
#include <vppinfra/time.h>
#include <tlsctrl/tlsctrl_vpn.h>

tlsctrl_vpn_transport_main_t tlsctrl_vpn_transport_main;

static tlsctrl_vpn_tunnel_t *
tlsctrl_vpn_find_tunnel_by_id (u64 tunnel_id)
{
  tlsctrl_vpn_main_t *vm = &tlsctrl_vpn_main;
  tlsctrl_vpn_tunnel_t *t;
  vec_foreach (t, vm->tunnels)
    {
      if (t->tunnel_id == tunnel_id)
        return t;
    }
  return 0;
}

int
tlsctrl_vpn_transport_find_session (u64 tunnel_id,
                                    tlsctrl_vpn_transport_session_t **out)
{
  tlsctrl_vpn_transport_session_t *s;
  if (out)
    *out = 0;
  vec_foreach (s, tlsctrl_vpn_transport_main.sessions)
    {
      if (s->tunnel_id == tunnel_id)
        {
          if (out)
            *out = s;
          return 0;
        }
    }
  return -1;
}

static void
tlsctrl_vpn_transport_fill_from_tunnel (tlsctrl_vpn_transport_session_t *s,
                                        tlsctrl_vpn_tunnel_t *t)
{
  vec_free (s->assigned_ip);
  vec_free (s->gateway);
  vec_free (s->dns_servers);
  s->assigned_ip = t->assigned_ip ? vec_dup (t->assigned_ip) : 0;
  s->gateway = t->gateway ? vec_dup (t->gateway) : 0;
  s->dns_servers = t->dns_servers ? vec_dup (t->dns_servers) : 0;
  s->mtu = t->mtu;
  s->mss_clamp = t->mss_clamp;
  s->running = t->running;
}

static void
tlsctrl_vpn_transport_sync_lifecycle_from_dp (tlsctrl_vpn_transport_session_t *s)
{
  tlsctrl_vpn_dp_session_t *dp = 0;
  if (!s)
    return;
  if (tlsctrl_vpn_dp_find_session (s->tunnel_id, &dp) == 0 && dp)
    {
      s->session_open_count = dp->session_open_count;
      s->session_close_count = dp->session_close_count;
      s->session_reset_count = dp->session_reset_count;
      s->connect_generation = dp->connect_generation;
      s->reopen_count = dp->reopen_count;
      s->stale_reap_count = dp->stale_reap_count;
      s->forced_close_count = dp->forced_close_count;
      s->running = dp->running;
    }
}

static void
tlsctrl_vpn_transport_reset_runtime (tlsctrl_vpn_transport_session_t *s)
{
  if (!s)
    return;
  s->tx_packets = 0;
  s->rx_packets = 0;
  s->tx_drops = 0;
  s->rx_drops = 0;
  s->queue_depth = 0;
  s->last_error_code = 0;
}

static int
tlsctrl_vpn_transport_ensure_session (u64 tunnel_id,
                                      tlsctrl_vpn_transport_session_t **out)
{
  tlsctrl_vpn_transport_session_t *s = 0;
  tlsctrl_vpn_tunnel_t *t = tlsctrl_vpn_find_tunnel_by_id (tunnel_id);

  if (tlsctrl_vpn_transport_find_session (tunnel_id, &s) == 0)
    {
      tlsctrl_vpn_transport_sync_lifecycle_from_dp (s);
      if (out)
        *out = s;
      return 0;
    }

  if (!t)
    return -1;

  vec_add2 (tlsctrl_vpn_transport_main.sessions, s, 1);
  clib_memset (s, 0, sizeof (*s));
  s->tunnel_id = tunnel_id;
  s->tun_if_name = 0; /* no manual attach yet */
  tlsctrl_vpn_transport_fill_from_tunnel (s, t);
  tlsctrl_vpn_transport_sync_lifecycle_from_dp (s);

  if (out)
    *out = s;
  return 0;
}

int
tlsctrl_vpn_transport_attach (u64 tunnel_id, const char *tun_if_name)
{
  tlsctrl_vpn_transport_session_t *s = 0;
  tlsctrl_vpn_tunnel_t *t = tlsctrl_vpn_find_tunnel_by_id (tunnel_id);
  if (!t)
    return -1;

  if (tlsctrl_vpn_transport_find_session (tunnel_id, &s) == 0)
    {
      vec_free (s->tun_if_name);
      s->tun_if_name = tun_if_name ? format (0, "%s", tun_if_name) : 0;
      tlsctrl_vpn_transport_fill_from_tunnel (s, t);
      if (s->running || s->tx_packets || s->rx_packets || s->tx_drops ||
          s->rx_drops || s->queue_depth || s->last_error_code)
        tlsctrl_vpn_transport_reset_runtime (s);
      tlsctrl_vpn_transport_sync_lifecycle_from_dp (s);
      s->running = 1;
      return 0;
    }

  vec_add2 (tlsctrl_vpn_transport_main.sessions, s, 1);
  clib_memset (s, 0, sizeof (*s));
  s->tunnel_id = tunnel_id;
  s->tun_if_name = tun_if_name ? format (0, "%s", tun_if_name) : 0;
  tlsctrl_vpn_transport_fill_from_tunnel (s, t);
  tlsctrl_vpn_transport_sync_lifecycle_from_dp (s);
  if (!s->connect_generation)
    {
      s->session_open_count = 1;
      s->connect_generation = 1;
    }
  s->running = 1;
  return 0;
}

int
tlsctrl_vpn_transport_detach (u64 tunnel_id)
{
  tlsctrl_vpn_transport_session_t *s;
  vec_foreach (s, tlsctrl_vpn_transport_main.sessions)
    {
      if (s->tunnel_id == tunnel_id)
        {
          vec_free (s->tun_if_name);
          vec_free (s->assigned_ip);
          vec_free (s->gateway);
          vec_free (s->dns_servers);
          vec_delete (tlsctrl_vpn_transport_main.sessions, 1,
                      s - tlsctrl_vpn_transport_main.sessions);
          return 0;
        }
    }
  return -1;
}

int
tlsctrl_vpn_transport_note_packet (u64 tunnel_id, u32 bytes, int outbound)
{
  tlsctrl_vpn_transport_session_t *s = 0;
  if (tlsctrl_vpn_transport_ensure_session (tunnel_id, &s))
    return -1;

  tlsctrl_vpn_transport_sync_lifecycle_from_dp (s);

  if (outbound)
    s->tx_packets++;
  else
    s->rx_packets++;

  /* queue depth is owned by dataplane enqueue/dequeue paths, not by generic
     packet accounting. keep the mirror in transport untouched here. */
  (void) bytes;
  return 0;
}

int
tlsctrl_vpn_transport_note_drop (u64 tunnel_id, u32 reason, int outbound)
{
  tlsctrl_vpn_transport_session_t *s = 0;
  if (tlsctrl_vpn_transport_ensure_session (tunnel_id, &s))
    return -1;

  if (outbound)
    s->tx_drops++;
  else
    s->rx_drops++;

  s->last_error_code = reason;
  tlsctrl_vpn_dp_note_drop (tunnel_id, reason);
  tlsctrl_vpn_transport_sync_lifecycle_from_dp (s);
  return 0;
}

int
tlsctrl_vpn_transport_set_queue_depth (u64 tunnel_id, u32 depth)
{
  tlsctrl_vpn_transport_session_t *s = 0;
  if (tlsctrl_vpn_transport_ensure_session (tunnel_id, &s))
    return -1;
  s->queue_depth = depth;
  tlsctrl_vpn_dp_set_queue_depth (tunnel_id, depth);
  tlsctrl_vpn_transport_sync_lifecycle_from_dp (s);
  return 0;
}


int
tlsctrl_vpn_transport_clear_runtime_counters (u64 tunnel_id, int preserve_lifecycle)
{
  tlsctrl_vpn_transport_session_t *s = 0;
  if (tlsctrl_vpn_transport_ensure_session (tunnel_id, &s))
    return -1;

  tlsctrl_vpn_transport_reset_runtime (s);
  if (!preserve_lifecycle)
    {
      s->session_open_count = 0;
      s->session_close_count = 0;
      s->session_reset_count = 0;
      s->connect_generation = 0;
      s->reopen_count = 0;
      s->stale_reap_count = 0;
      s->forced_close_count = 0;
    }
  return 0;
}

int
tlsctrl_vpn_transport_on_tunnel_close (u64 tunnel_id)
{
  tlsctrl_vpn_transport_session_t *s = 0;
  if (tlsctrl_vpn_transport_ensure_session (tunnel_id, &s))
    return -1;
  tlsctrl_vpn_transport_sync_lifecycle_from_dp (s);
  if (s->running || s->session_open_count)
    s->session_close_count += 1;
  s->running = 0;
  s->queue_depth = 0;
  tlsctrl_vpn_dp_set_queue_depth (tunnel_id, 0);
  tlsctrl_vpn_transport_sync_lifecycle_from_dp (s);
  return 0;
}
