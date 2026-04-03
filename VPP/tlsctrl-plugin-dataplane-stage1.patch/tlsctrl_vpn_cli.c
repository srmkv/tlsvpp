#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <vppinfra/time.h>
#include "tlsctrl_vpn.h"

static clib_error_t *show_tlsctrl_vpn_fn (vlib_main_t *vm, unformat_input_t *input,
                                          vlib_cli_command_t *cmd)
{
  tlsctrl_vpn_main_t *m = &tlsctrl_vpn_main;
  tlsctrl_vpn_pool_t *p;
  tlsctrl_vpn_profile_t *pr;
  tlsctrl_vpn_tunnel_t *t;
  int detail = 0;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "detail"))
        detail = 1;
      else
        break;
    }
  vlib_cli_output (vm, "vpn: pools=%u profiles=%u tunnels=%u next-tunnel-id=%u",
                   vec_len (m->pools), vec_len (m->profiles),
                   vec_len (m->tunnels), m->next_tunnel_id);
  clib_spinlock_lock (&m->lock);
  vec_foreach (p, m->pools)
    vlib_cli_output (vm,
                     "  pool name=%s subnet=%s gw=%s lease=%u active=%u cursor=%u",
                     p->name ? (char *) p->name : "-",
                     p->subnet ? (char *) p->subnet : "-",
                     p->gateway ? (char *) p->gateway : "-", p->lease_seconds,
                     p->active_leases, p->lease_cursor);
  vec_foreach (pr, m->profiles)
    vlib_cli_output (vm,
                     "  profile name=%s pool=%s full=%u mtu=%u mss=%u dns=%s inc=%s exc=%s",
                     pr->name ? (char *) pr->name : "-",
                     pr->pool_name ? (char *) pr->pool_name : "-",
                     pr->full_tunnel, pr->mtu, pr->mss_clamp,
                     pr->dns_servers ? (char *) pr->dns_servers : "-",
                     pr->include_routes ? (char *) pr->include_routes : "-",
                     pr->exclude_routes ? (char *) pr->exclude_routes : "-");
  vec_foreach (t, m->tunnels)
    {
      vlib_cli_output (vm,
                       "  tunnel id=%u user=%s profile=%s vip=%s cip=%s running=%u last=%llu",
                       t->tunnel_id,
                       t->username ? (char *) t->username : "-",
                       t->profile_name ? (char *) t->profile_name : "-",
                       t->assigned_ip ? (char *) t->assigned_ip : "-",
                       t->client_ip ? (char *) t->client_ip : "-", t->running,
                       (unsigned long long) t->last_seen_unix_ns);
      if (detail)
        vlib_cli_output (vm,
                         "    gw=%s dns=%s inc=%s exc=%s full=%u mtu=%u mss=%u lease=%u",
                         t->gateway ? (char *) t->gateway : "-",
                         t->dns_servers ? (char *) t->dns_servers : "-",
                         t->include_routes ? (char *) t->include_routes : "-",
                         t->exclude_routes ? (char *) t->exclude_routes : "-",
                         t->full_tunnel, t->mtu, t->mss_clamp,
                         t->lease_seconds);
    }
  clib_spinlock_unlock (&m->lock);
  return 0;
}

static clib_error_t *tlsctrl_vpn_pool_set_command_fn (vlib_main_t *vm,
                                                      unformat_input_t *input,
                                                      vlib_cli_command_t *cmd)
{
  u8 *name = 0, *subnet = 0, *gateway = 0;
  u32 lease = 3600;
  int rv;
  (void) vm;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &name))
        ;
      else if (unformat (input, "subnet %s", &subnet))
        ;
      else if (unformat (input, "gateway %s", &gateway))
        ;
      else if (unformat (input, "lease %u", &lease))
        ;
      else
        break;
    }
  rv = tlsctrl_vpn_pool_set ((char *) name, (char *) subnet, (char *) gateway,
                             lease);
  vec_free (name);
  vec_free (subnet);
  vec_free (gateway);
  if (rv)
    return clib_error_return (0, "failed to set vpn pool");
  return 0;
}

static clib_error_t *tlsctrl_vpn_profile_set_command_fn (
    vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 *name = 0, *pool = 0, *dns = 0, *inc = 0, *exc = 0;
  u32 full = 0, mtu = 1400, mss = 1360;
  int rv;
  (void) vm;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &name))
        ;
      else if (unformat (input, "pool %s", &pool))
        ;
      else if (unformat (input, "full-tunnel"))
        full = 1;
      else if (unformat (input, "dns %s", &dns))
        ;
      else if (unformat (input, "include %s", &inc))
        ;
      else if (unformat (input, "exclude %s", &exc))
        ;
      else if (unformat (input, "mtu %u", &mtu))
        ;
      else if (unformat (input, "mss %u", &mss))
        ;
      else
        break;
    }
  rv = tlsctrl_vpn_profile_set ((char *) name, (char *) pool, (u8) full,
                                (char *) dns, (char *) inc, (char *) exc,
                                (u16) mtu, (u16) mss);
  vec_free (name);
  vec_free (pool);
  vec_free (dns);
  vec_free (inc);
  vec_free (exc);
  if (rv)
    return clib_error_return (0, "failed to set vpn profile");
  return 0;
}

static clib_error_t *tlsctrl_vpn_lease_acquire_command_fn (
    vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 *username = 0, *profile = 0, *client_ip = 0;
  tlsctrl_vpn_lease_result_t result;
  int rv;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "username %s", &username))
        ;
      else if (unformat (input, "profile %s", &profile))
        ;
      else if (unformat (input, "client-ip %s", &client_ip))
        ;
      else
        break;
    }
  rv = tlsctrl_vpn_lease_acquire ((char *) username, (char *) profile,
                                  (char *) client_ip,
                                  (u64) unix_time_now_nsec (), &result);
  if (rv)
    {
      vec_free (username);
      vec_free (profile);
      vec_free (client_ip);
      return clib_error_return (0, "lease acquire failed rv=%d", rv);
    }
  vlib_cli_output (vm,
                   "lease acquired user=%s tunnel=%llu vip=%s gw=%s dns=%s full=%u mtu=%u mss=%u lease=%u",
                   username ? (char *) username : "-",
                   (unsigned long long) result.tunnel_id,
                   result.assigned_ip ? (char *) result.assigned_ip : "-",
                   result.gateway ? (char *) result.gateway : "-",
                   result.dns_servers ? (char *) result.dns_servers : "-",
                   result.full_tunnel, result.mtu, result.mss_clamp,
                   result.lease_seconds);
  tlsctrl_vpn_lease_result_free (&result);
  vec_free (username);
  vec_free (profile);
  vec_free (client_ip);
  return 0;
}

static clib_error_t *tlsctrl_vpn_lease_release_command_fn (
    vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 *username = 0;
  u64 tunnel_id = 0;
  int rv;
  (void) vm;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "username %s", &username))
        ;
      else if (unformat (input, "tunnel-id %llu", &tunnel_id))
        ;
      else
        break;
    }
  rv = tlsctrl_vpn_lease_release ((char *) username, tunnel_id);
  vec_free (username);
  if (rv)
    return clib_error_return (0, "lease release failed rv=%d", rv);
  return 0;
}

static clib_error_t *tlsctrl_vpn_tunnel_open_command_fn (
    vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 *username = 0, *profile = 0, *client_ip = 0;
  tlsctrl_vpn_lease_result_t result;
  int rv;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "username %s", &username))
        ;
      else if (unformat (input, "profile %s", &profile))
        ;
      else if (unformat (input, "client-ip %s", &client_ip))
        ;
      else
        break;
    }
  clib_memset (&result, 0, sizeof (result));
  rv = tlsctrl_vpn_tunnel_open (
      (char *) username, (char *) profile, (char *) client_ip,
      (u32 *) &result.tunnel_id, &result.assigned_ip, &result.gateway,
      &result.dns_servers, &result.include_routes, &result.exclude_routes,
      &result.full_tunnel, &result.mtu, &result.mss_clamp,
      &result.lease_seconds);
  if (rv)
    {
      vec_free (username);
      vec_free (profile);
      vec_free (client_ip);
      return clib_error_return (0, "tunnel open failed rv=%d", rv);
    }
  vlib_cli_output (vm,
                   "tunnel open user=%s tunnel=%llu vip=%s gw=%s dns=%s full=%u mtu=%u mss=%u lease=%u",
                   username ? (char *) username : "-",
                   (unsigned long long) result.tunnel_id,
                   result.assigned_ip ? (char *) result.assigned_ip : "-",
                   result.gateway ? (char *) result.gateway : "-",
                   result.dns_servers ? (char *) result.dns_servers : "-",
                   result.full_tunnel, result.mtu, result.mss_clamp,
                   result.lease_seconds);
  tlsctrl_vpn_lease_result_free (&result);
  vec_free (username);
  vec_free (profile);
  vec_free (client_ip);
  return 0;
}

static clib_error_t *tlsctrl_vpn_tunnel_close_command_fn (
    vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 *username = 0;
  int rv;
  (void) vm;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "username %s", &username))
        ;
      else
        break;
    }
  if (!username)
    return clib_error_return (0,
                              "usage: tlsctrl vpn tunnel close username <u>");
  rv = tlsctrl_vpn_tunnel_close ((char *) username);
  vec_free (username);
  if (rv)
    return clib_error_return (0, "close failed rv=%d", rv);
  return 0;
}

VLIB_CLI_COMMAND (show_tlsctrl_vpn_cmd, static) = {
  .path = "show tlsctrl vpn",
  .short_help = "show tlsctrl vpn [detail]",
  .function = show_tlsctrl_vpn_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_pool_set_command, static) = {
  .path = "tlsctrl vpn pool set",
  .short_help =
      "tlsctrl vpn pool set name <name> subnet <cidr> gateway <ip> [lease <sec>]",
  .function = tlsctrl_vpn_pool_set_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_profile_set_command, static) = {
  .path = "tlsctrl vpn profile set",
  .short_help =
      "tlsctrl vpn profile set name <name> pool <pool> [full-tunnel] [dns <csv>] [include <csv>] [exclude <csv>] [mtu <n>] [mss <n>]",
  .function = tlsctrl_vpn_profile_set_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_lease_acquire_command, static) = {
  .path = "tlsctrl vpn lease acquire",
  .short_help =
      "tlsctrl vpn lease acquire username <user> profile <profile> [client-ip <ip>]",
  .function = tlsctrl_vpn_lease_acquire_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_lease_release_command, static) = {
  .path = "tlsctrl vpn lease release",
  .short_help = "tlsctrl vpn lease release [username <user>] [tunnel-id <id>]",
  .function = tlsctrl_vpn_lease_release_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_tunnel_open_command, static) = {
  .path = "tlsctrl vpn tunnel open",
  .short_help =
      "tlsctrl vpn tunnel open username <u> profile <p> client-ip <ip>",
  .function = tlsctrl_vpn_tunnel_open_command_fn,
};

VLIB_CLI_COMMAND (tlsctrl_vpn_tunnel_close_command, static) = {
  .path = "tlsctrl vpn tunnel close",
  .short_help = "tlsctrl vpn tunnel close username <u>",
  .function = tlsctrl_vpn_tunnel_close_command_fn,
};
