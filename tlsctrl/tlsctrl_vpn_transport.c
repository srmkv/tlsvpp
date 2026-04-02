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
      return 0;
    }
  vec_add2 (tlsctrl_vpn_transport_main.sessions, s, 1);
  clib_memset (s, 0, sizeof (*s));
  s->tunnel_id = tunnel_id;
  s->tun_if_name = tun_if_name ? format (0, "%s", tun_if_name) : 0;
  tlsctrl_vpn_transport_fill_from_tunnel (s, t);
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
  if (tlsctrl_vpn_transport_find_session (tunnel_id, &s))
    return -1;
  if (outbound)
    s->tx_packets++;
  else
    s->rx_packets++;
  if (bytes)
    s->queue_depth += 1;
  return 0;
}

int
tlsctrl_vpn_transport_note_drop (u64 tunnel_id, u32 reason, int outbound)
{
  tlsctrl_vpn_transport_session_t *s = 0;
  if (tlsctrl_vpn_transport_find_session (tunnel_id, &s))
    return -1;
  if (outbound)
    s->tx_drops++;
  else
    s->rx_drops++;
  s->last_error_code = reason;
  return 0;
}

int
tlsctrl_vpn_transport_set_queue_depth (u64 tunnel_id, u32 depth)
{
  tlsctrl_vpn_transport_session_t *s = 0;
  if (tlsctrl_vpn_transport_find_session (tunnel_id, &s))
    return -1;
  s->queue_depth = depth;
  return 0;
}


int
tlsctrl_vpn_transport_on_tunnel_close (u64 tunnel_id)
{
  tlsctrl_vpn_transport_session_t *s = 0;
  if (tlsctrl_vpn_transport_find_session (tunnel_id, &s))
    return -1;
  s->running = 0;
  s->queue_depth = 0;
  return 0;
}
