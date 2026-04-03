#include <vlib/vlib.h>
#include <vppinfra/format.h>
#include <vppinfra/lock.h>
#include "tlsctrl_vpn.h"

tlsctrl_vpn_main_t tlsctrl_vpn_main;

static u8 *tvpn_dup_cstr (const char *s)
{
  if (!s)
    return 0;
  return format (0, "%s%c", s, 0);
}

static void tvpn_set_vec (u8 **dst, const char *src)
{
  vec_free (*dst);
  *dst = tvpn_dup_cstr (src);
}

static tlsctrl_vpn_pool_t *tvpn_find_pool (const char *name)
{
  tlsctrl_vpn_main_t *vm = &tlsctrl_vpn_main;
  tlsctrl_vpn_pool_t *p;
  vec_foreach (p, vm->pools)
    if (p->name && name && !strcmp ((char *) p->name, name))
      return p;
  return 0;
}

static tlsctrl_vpn_profile_t *tvpn_find_profile (const char *name)
{
  tlsctrl_vpn_main_t *vm = &tlsctrl_vpn_main;
  tlsctrl_vpn_profile_t *p;
  vec_foreach (p, vm->profiles)
    if (p->name && name && !strcmp ((char *) p->name, name))
      return p;
  return 0;
}

static tlsctrl_vpn_tunnel_t *tvpn_find_tunnel_user (const char *username)
{
  tlsctrl_vpn_main_t *vm = &tlsctrl_vpn_main;
  tlsctrl_vpn_tunnel_t *t;
  vec_foreach (t, vm->tunnels)
    if (t->username && username && !strcmp ((char *) t->username, username))
      return t;
  return 0;
}

static u8 *tvpn_ip_from_cursor (tlsctrl_vpn_pool_t *pool)
{
  u8 a = 0, b = 0, c = 0, d = 0, prefix = 24;
  if (!pool || !pool->subnet)
    return 0;
  if (sscanf ((char *) pool->subnet, "%hhu.%hhu.%hhu.%hhu/%hhu", &a, &b, &c,
              &d, &prefix)
      != 5)
    return 0;
  return format (0, "%u.%u.%u.%u", a, b, c, pool->lease_cursor);
}

clib_error_t *tlsctrl_vpn_init (vlib_main_t *vm)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  clib_memset (m, 0, sizeof (*m));
  clib_spinlock_init (&m->lock);
  m->next_tunnel_id = 1;
  tlsctrl_vpn_stream_init (vm);
  return 0;
}

int tlsctrl_vpn_pool_set (const char *name, const char *subnet,
                          const char *gateway, u32 lease_seconds)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_pool_t *p;
  clib_spinlock_lock (&m->lock);
  p = tvpn_find_pool (name);
  if (!p)
    {
      vec_add2 (m->pools, p, 1);
      clib_memset (p, 0, sizeof (*p));
      p->lease_cursor = 10;
    }
  tvpn_set_vec (&p->name, name);
  tvpn_set_vec (&p->subnet, subnet);
  tvpn_set_vec (&p->gateway, gateway);
  p->lease_seconds = lease_seconds;
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int tlsctrl_vpn_profile_set (const char *name, const char *pool, u8 full_tunnel,
                             const char *dns, const char *include_routes,
                             const char *exclude_routes, u16 mtu, u16 mss)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_profile_t *p;
  clib_spinlock_lock (&m->lock);
  p = tvpn_find_profile (name);
  if (!p)
    {
      vec_add2 (m->profiles, p, 1);
      clib_memset (p, 0, sizeof (*p));
    }
  tvpn_set_vec (&p->name, name);
  tvpn_set_vec (&p->pool_name, pool);
  tvpn_set_vec (&p->dns_servers, dns);
  tvpn_set_vec (&p->include_routes, include_routes);
  tvpn_set_vec (&p->exclude_routes, exclude_routes);
  p->full_tunnel = full_tunnel;
  p->mtu = mtu;
  p->mss_clamp = mss;
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int tlsctrl_vpn_connect_config_get (const char *username, const char *profile,
                                    const char *client_ip, u32 *tunnel_id,
                                    u8 **assigned_ip, u8 **gateway,
                                    u8 **dns_servers, u8 **include_routes,
                                    u8 **exclude_routes, u8 *full_tunnel,
                                    u16 *mtu, u16 *mss, u32 *lease_seconds,
                                    int create_tunnel)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_profile_t *prof;
  tlsctrl_vpn_pool_t *pool;
  tlsctrl_vpn_tunnel_t *tun;

  clib_spinlock_lock (&m->lock);
  prof = tvpn_find_profile (profile);
  if (!prof)
    {
      clib_spinlock_unlock (&m->lock);
      return -1;
    }
  pool = tvpn_find_pool ((char *) prof->pool_name);
  if (!pool)
    {
      clib_spinlock_unlock (&m->lock);
      return -2;
    }

  tun = tvpn_find_tunnel_user (username);
  if (!tun && create_tunnel)
    {
      vec_add2 (m->tunnels, tun, 1);
      clib_memset (tun, 0, sizeof (*tun));
      tun->tunnel_id = m->next_tunnel_id++;
      tun->assigned_ip = tvpn_ip_from_cursor (pool);
      pool->lease_cursor += 1;
      pool->active_leases += 1;
      tvpn_set_vec (&tun->username, username);
    }
  if (!tun)
    {
      clib_spinlock_unlock (&m->lock);
      return -3;
    }

  tun->running = create_tunnel ? 1 : tun->running;
  tun->last_seen_unix_ns = clib_cpu_time_now ();
  tvpn_set_vec (&tun->profile_name, profile);
  tvpn_set_vec (&tun->client_ip, client_ip);
  vec_free (tun->gateway);
  tun->gateway = vec_dup (pool->gateway);
  vec_free (tun->dns_servers);
  tun->dns_servers = vec_dup (prof->dns_servers);
  vec_free (tun->include_routes);
  tun->include_routes = vec_dup (prof->include_routes);
  vec_free (tun->exclude_routes);
  tun->exclude_routes = vec_dup (prof->exclude_routes);
  tun->full_tunnel = prof->full_tunnel;
  tun->mtu = prof->mtu;
  tun->mss_clamp = prof->mss_clamp;
  tun->lease_seconds = pool->lease_seconds;

  if (tunnel_id)
    *tunnel_id = tun->tunnel_id;
  if (assigned_ip)
    *assigned_ip = vec_dup (tun->assigned_ip);
  if (gateway)
    *gateway = vec_dup (tun->gateway);
  if (dns_servers)
    *dns_servers = vec_dup (tun->dns_servers);
  if (include_routes)
    *include_routes = vec_dup (tun->include_routes);
  if (exclude_routes)
    *exclude_routes = vec_dup (tun->exclude_routes);
  if (full_tunnel)
    *full_tunnel = tun->full_tunnel;
  if (mtu)
    *mtu = tun->mtu;
  if (mss)
    *mss = tun->mss_clamp;
  if (lease_seconds)
    *lease_seconds = tun->lease_seconds;
  clib_spinlock_unlock (&m->lock);
  return 0;
}

int tlsctrl_vpn_tunnel_open (const char *username, const char *profile,
                             const char *client_ip, u32 *tunnel_id,
                             u8 **assigned_ip, u8 **gateway,
                             u8 **dns_servers, u8 **include_routes,
                             u8 **exclude_routes, u8 *full_tunnel,
                             u16 *mtu, u16 *mss, u32 *lease_seconds)
{
  int rv;
  u32 tid = 0;
  rv = tlsctrl_vpn_connect_config_get (
      username, profile, client_ip, &tid, assigned_ip, gateway,
      dns_servers, include_routes, exclude_routes, full_tunnel, mtu, mss,
      lease_seconds, 1);
  if (rv)
    return rv;
  tlsctrl_vpn_dp_attach (tid, 0);
  tlsctrl_vpn_stream_attach (tid, 0);
  if (tunnel_id)
    *tunnel_id = tid;
  return 0;
}

int tlsctrl_vpn_tunnel_close (const char *username)
{
  tlsctrl_vpn_tunnel_t *tun;
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  u64 tunnel_id = 0;
  clib_spinlock_lock (&m->lock);
  tun = tvpn_find_tunnel_user (username);
  if (tun)
    tunnel_id = tun->tunnel_id;
  clib_spinlock_unlock (&m->lock);
  if (tunnel_id)
    {
      tlsctrl_vpn_dp_detach (tunnel_id);
      tlsctrl_vpn_stream_detach (tunnel_id);
      tlsctrl_vpn_transport_on_tunnel_close (tunnel_id);
      tlsctrl_vpn_transport_set_queue_depth (tunnel_id, 0);
    }
  return tlsctrl_vpn_lease_release (username, 0);
}

int tlsctrl_vpn_lease_acquire (const char *username, const char *profile,
                               const char *client_ip, u64 now_ns,
                               tlsctrl_vpn_lease_result_t *result)
{
  int rv;
  if (result)
    clib_memset (result, 0, sizeof (*result));
  (void) now_ns;
  rv = tlsctrl_vpn_connect_config_get (
      username, profile, client_ip, result ? (u32 *) &result->tunnel_id : 0,
      result ? &result->assigned_ip : 0, result ? &result->gateway : 0,
      result ? &result->dns_servers : 0, result ? &result->include_routes : 0,
      result ? &result->exclude_routes : 0, result ? &result->full_tunnel : 0,
      result ? &result->mtu : 0, result ? &result->mss_clamp : 0,
      result ? &result->lease_seconds : 0, 1);
  return rv;
}

int tlsctrl_vpn_lease_release (const char *username, u64 tunnel_id)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_tunnel_t *tun = 0, *t;
  tlsctrl_vpn_profile_t *prof = 0;
  tlsctrl_vpn_pool_t *pool = 0;
  clib_spinlock_lock (&m->lock);
  if (username)
    tun = tvpn_find_tunnel_user (username);
  if (!tun && tunnel_id)
    vec_foreach (t, m->tunnels)
      if (t->tunnel_id == (u32) tunnel_id)
        {
          tun = t;
          break;
        }
  if (!tun)
    {
      clib_spinlock_unlock (&m->lock);
      return -1;
    }
  tun->running = 0;
  tun->last_seen_unix_ns = clib_cpu_time_now ();
  prof = tvpn_find_profile ((char *) tun->profile_name);
  if (prof)
    pool = tvpn_find_pool ((char *) prof->pool_name);
  if (pool && pool->active_leases)
    pool->active_leases -= 1;
  clib_spinlock_unlock (&m->lock);
  return 0;
}

void tlsctrl_vpn_lease_result_free (tlsctrl_vpn_lease_result_t *r)
{
  if (!r)
    return;
  vec_free (r->assigned_ip);
  vec_free (r->gateway);
  vec_free (r->dns_servers);
  vec_free (r->include_routes);
  vec_free (r->exclude_routes);
  clib_memset (r, 0, sizeof (*r));
}
