
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/format_fns.h>
#include <vppinfra/string.h>
#include "tlsctrl_vpn.h"
#include <tlsctrl/tlsctrl_vpn.api_enum.h>
#include <tlsctrl/tlsctrl_vpn.api_types.h>

static u32 tlsctrl_vpn_msg_id_base;
#define REPLY_MSG_ID_BASE tlsctrl_vpn_msg_id_base
#include <vlibapi/api_helper_macros.h>

static void vl_api_tlsctrl_vpn_connect_config_get_t_handler (vl_api_tlsctrl_vpn_connect_config_get_t *mp);
static void vl_api_tlsctrl_vpn_tunnel_open_t_handler (vl_api_tlsctrl_vpn_tunnel_open_t *mp);
static void vl_api_tlsctrl_vpn_tunnel_close_t_handler (vl_api_tlsctrl_vpn_tunnel_close_t *mp);
static void vl_api_tlsctrl_vpn_pool_dump_t_handler (vl_api_tlsctrl_vpn_pool_dump_t *mp);
static void vl_api_tlsctrl_vpn_profile_dump_t_handler (vl_api_tlsctrl_vpn_profile_dump_t *mp);
static void vl_api_tlsctrl_vpn_tunnel_dump_t_handler (vl_api_tlsctrl_vpn_tunnel_dump_t *mp);

#include <tlsctrl/tlsctrl_vpn.api.c>

static u8 *
dup_api_str_fixed (const u8 *s, uword max_len)
{
  uword n = 0;
  while (n < max_len && s[n])
    n++;
  u8 *v = vec_new (u8, n + 1);
  if (n)
    clib_memcpy (v, s, n);
  v[n] = 0;
  return v;
}

static void
set_api_str_fixed (u8 *dst, uword dst_len, const u8 *src)
{
  uword n = 0;
  clib_memset (dst, 0, dst_len);
  if (!src)
    return;
  n = vec_len ((u8 *) src);
  if (n >= dst_len)
    n = dst_len - 1;
  if (n)
    clib_memcpy (dst, src, n);
}

static void
vl_api_tlsctrl_vpn_connect_config_get_t_handler (vl_api_tlsctrl_vpn_connect_config_get_t *mp)
{
  vl_api_tlsctrl_vpn_connect_config_get_reply_t *rmp;
  u8 *username = dup_api_str_fixed (mp->username, sizeof (mp->username));
  u8 *profile = dup_api_str_fixed (mp->profile, sizeof (mp->profile));
  u8 *client_ip = dup_api_str_fixed (mp->client_ip, sizeof (mp->client_ip));
  u8 *assigned_ip = 0, *gateway = 0, *dns = 0, *inc = 0, *exc = 0;
  u32 tunnel_id = 0, lease_seconds = 0;
  u8 full = 0;
  u16 mtu = 0, mss = 0;
  int rv = tlsctrl_vpn_connect_config_get ((char *) username, (char *) profile,
                                           (char *) client_ip, &tunnel_id,
                                           &assigned_ip, &gateway, &dns,
                                           &inc, &exc, &full, &mtu, &mss,
                                           &lease_seconds, 0);
  REPLY_MACRO2 (VL_API_TLSCTRL_VPN_CONNECT_CONFIG_GET_REPLY, ({
    rmp->tunnel_id = htonl (tunnel_id);
    set_api_str_fixed (rmp->assigned_ip, sizeof (rmp->assigned_ip), assigned_ip);
    set_api_str_fixed (rmp->gateway, sizeof (rmp->gateway), gateway);
    set_api_str_fixed (rmp->dns_servers, sizeof (rmp->dns_servers), dns);
    set_api_str_fixed (rmp->include_routes, sizeof (rmp->include_routes), inc);
    set_api_str_fixed (rmp->exclude_routes, sizeof (rmp->exclude_routes), exc);
    rmp->full_tunnel = full;
    rmp->mtu = htons (mtu);
    rmp->mss_clamp = htons (mss);
    rmp->lease_seconds = htonl (lease_seconds);
  }));
  vec_free (username);
  vec_free (profile);
  vec_free (client_ip);
  vec_free (assigned_ip);
  vec_free (gateway);
  vec_free (dns);
  vec_free (inc);
  vec_free (exc);
}

static void
vl_api_tlsctrl_vpn_tunnel_open_t_handler (vl_api_tlsctrl_vpn_tunnel_open_t *mp)
{
  vl_api_tlsctrl_vpn_tunnel_open_reply_t *rmp;
  u8 *username = dup_api_str_fixed (mp->username, sizeof (mp->username));
  u8 *profile = dup_api_str_fixed (mp->profile, sizeof (mp->profile));
  u8 *client_ip = dup_api_str_fixed (mp->client_ip, sizeof (mp->client_ip));
  u8 *assigned_ip = 0, *gateway = 0, *dns = 0, *inc = 0, *exc = 0;
  u32 tunnel_id = 0, lease_seconds = 0;
  u8 full = 0;
  u16 mtu = 0, mss = 0;
  int rv = tlsctrl_vpn_tunnel_open ((char *) username, (char *) profile,
                                    (char *) client_ip, &tunnel_id,
                                    &assigned_ip, &gateway, &dns, &inc,
                                    &exc, &full, &mtu, &mss,
                                    &lease_seconds);
  REPLY_MACRO2 (VL_API_TLSCTRL_VPN_TUNNEL_OPEN_REPLY, ({
    rmp->tunnel_id = htonl (tunnel_id);
    set_api_str_fixed (rmp->assigned_ip, sizeof (rmp->assigned_ip), assigned_ip);
    set_api_str_fixed (rmp->gateway, sizeof (rmp->gateway), gateway);
    set_api_str_fixed (rmp->dns_servers, sizeof (rmp->dns_servers), dns);
    set_api_str_fixed (rmp->include_routes, sizeof (rmp->include_routes), inc);
    set_api_str_fixed (rmp->exclude_routes, sizeof (rmp->exclude_routes), exc);
    rmp->full_tunnel = full;
    rmp->mtu = htons (mtu);
    rmp->mss_clamp = htons (mss);
    rmp->lease_seconds = htonl (lease_seconds);
  }));
  vec_free (username);
  vec_free (profile);
  vec_free (client_ip);
  vec_free (assigned_ip);
  vec_free (gateway);
  vec_free (dns);
  vec_free (inc);
  vec_free (exc);
}

static void
vl_api_tlsctrl_vpn_tunnel_close_t_handler (vl_api_tlsctrl_vpn_tunnel_close_t *mp)
{
  vl_api_tlsctrl_vpn_tunnel_close_reply_t *rmp;
  u8 *username = dup_api_str_fixed (mp->username, sizeof (mp->username));
  int rv = tlsctrl_vpn_tunnel_close ((char *) username);
  REPLY_MACRO (VL_API_TLSCTRL_VPN_TUNNEL_CLOSE_REPLY);
  vec_free (username);
}

static void
send_pool_details (vl_api_registration_t *rp, u32 context,
                   tlsctrl_vpn_pool_t *p)
{
  vl_api_tlsctrl_vpn_pool_details_t *mp = vl_msg_api_alloc_zero (sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_TLSCTRL_VPN_POOL_DETAILS + tlsctrl_vpn_msg_id_base);
  mp->context = context;
  set_api_str_fixed (mp->name, sizeof (mp->name), p->name);
  set_api_str_fixed (mp->subnet, sizeof (mp->subnet), p->subnet);
  set_api_str_fixed (mp->gateway, sizeof (mp->gateway), p->gateway);
  mp->lease_seconds = htonl (p->lease_seconds);
  mp->active_leases = htonl (p->active_leases);
  mp->lease_cursor = htonl (p->lease_cursor);
  vl_api_send_msg (rp, (u8 *) mp);
}

static void
send_profile_details (vl_api_registration_t *rp, u32 context,
                      tlsctrl_vpn_profile_t *p)
{
  vl_api_tlsctrl_vpn_profile_details_t *mp = vl_msg_api_alloc_zero (sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_TLSCTRL_VPN_PROFILE_DETAILS + tlsctrl_vpn_msg_id_base);
  mp->context = context;
  set_api_str_fixed (mp->name, sizeof (mp->name), p->name);
  set_api_str_fixed (mp->pool, sizeof (mp->pool), p->pool_name);
  mp->full_tunnel = p->full_tunnel;
  mp->mtu = htons (p->mtu);
  mp->mss_clamp = htons (p->mss_clamp);
  set_api_str_fixed (mp->dns_servers, sizeof (mp->dns_servers), p->dns_servers);
  set_api_str_fixed (mp->include_routes, sizeof (mp->include_routes), p->include_routes);
  set_api_str_fixed (mp->exclude_routes, sizeof (mp->exclude_routes), p->exclude_routes);
  vl_api_send_msg (rp, (u8 *) mp);
}

static void
send_tunnel_details (vl_api_registration_t *rp, u32 context,
                     tlsctrl_vpn_tunnel_t *t)
{
  vl_api_tlsctrl_vpn_tunnel_details_t *mp = vl_msg_api_alloc_zero (sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_TLSCTRL_VPN_TUNNEL_DETAILS + tlsctrl_vpn_msg_id_base);
  mp->context = context;
  mp->tunnel_id = htonl (t->tunnel_id);
  set_api_str_fixed (mp->username, sizeof (mp->username), t->username);
  set_api_str_fixed (mp->profile, sizeof (mp->profile), t->profile_name);
  set_api_str_fixed (mp->assigned_ip, sizeof (mp->assigned_ip), t->assigned_ip);
  set_api_str_fixed (mp->client_ip, sizeof (mp->client_ip), t->client_ip);
  mp->running = t->running;
  mp->last_seen_unix_ns = clib_host_to_net_u64 (t->last_seen_unix_ns);
  vl_api_send_msg (rp, (u8 *) mp);
}

static void
vl_api_tlsctrl_vpn_pool_dump_t_handler (vl_api_tlsctrl_vpn_pool_dump_t *mp)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  vl_api_registration_t *rp = vl_api_client_index_to_registration (mp->client_index);
  tlsctrl_vpn_pool_t *p;
  if (!rp)
    return;
  clib_spinlock_lock (&m->lock);
  vec_foreach (p, m->pools)
    send_pool_details (rp, mp->context, p);
  clib_spinlock_unlock (&m->lock);
}

static void
vl_api_tlsctrl_vpn_profile_dump_t_handler (vl_api_tlsctrl_vpn_profile_dump_t *mp)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  vl_api_registration_t *rp = vl_api_client_index_to_registration (mp->client_index);
  tlsctrl_vpn_profile_t *p;
  if (!rp)
    return;
  clib_spinlock_lock (&m->lock);
  vec_foreach (p, m->profiles)
    send_profile_details (rp, mp->context, p);
  clib_spinlock_unlock (&m->lock);
}

static void
vl_api_tlsctrl_vpn_tunnel_dump_t_handler (vl_api_tlsctrl_vpn_tunnel_dump_t *mp)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  vl_api_registration_t *rp = vl_api_client_index_to_registration (mp->client_index);
  tlsctrl_vpn_tunnel_t *t;
  if (!rp)
    return;
  clib_spinlock_lock (&m->lock);
  vec_foreach (t, m->tunnels)
    send_tunnel_details (rp, mp->context, t);
  clib_spinlock_unlock (&m->lock);
}

static clib_error_t *
tlsctrl_vpn_api_init (vlib_main_t *vm)
{
  tlsctrl_vpn_msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_INIT_FUNCTION (tlsctrl_vpn_api_init);
