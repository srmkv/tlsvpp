#include "radius.h"

static const char *
format_radius_result_code(radius_result_code_t rc)
{
  switch (rc) {
    case RADIUS_RESULT_ACCEPT: return "accept";
    case RADIUS_RESULT_REJECT: return "reject";
    case RADIUS_RESULT_CHALLENGE: return "challenge";
    case RADIUS_RESULT_TIMEOUT: return "timeout";
    default: return "error";
  }
}

static clib_error_t *
show_radius_fn(vlib_main_t *vm, unformat_input_t *input,
               vlib_cli_command_t *cmd)
{
  radius_main_t *rm = &radius_main;
  radius_server_t *s;
  vlib_cli_output(vm,
                  "requests=%llu accepts=%llu rejects=%llu challenges=%llu timeouts=%llu errors=%llu pending=%u",
                  rm->stats.requests, rm->stats.accepts, rm->stats.rejects,
                  rm->stats.challenges, rm->stats.timeouts, rm->stats.errors,
                  pool_elts(rm->pending));
  if (rm->last_event.at > 0) {
    vlib_cli_output(vm,
                    "last_result=%s provider=%s username=%s reply=\"%s\" filter_id=\"%s\" session_timeout=%u idle_timeout=%u state_len=%u",
                    format_radius_result_code(rm->last_event.result_code),
                    rm->last_event.provider_name,
                    rm->last_event.username,
                    rm->last_event.reply_message[0] ? rm->last_event.reply_message : (u8 *) "-",
                    rm->last_event.filter_id[0] ? rm->last_event.filter_id : (u8 *) "-",
                    rm->last_event.session_timeout,
                    rm->last_event.idle_timeout,
                    rm->last_event.state_len);
  }
  vec_foreach(s, rm->servers) {
    vlib_cli_output(vm,
                    "provider name=%s fib=%u sw_if_index=%u port=%u timeout=%u retries=%u enabled=%u",
                    s->name, s->fib_index, s->sw_if_index, s->port,
                    s->timeout_sec, s->retries, s->enabled);
  }
  return 0;
}

VLIB_CLI_COMMAND(show_radius_cmd, static) = {
  .path = "show radius",
  .short_help = "show radius",
  .function = show_radius_fn,
};

static clib_error_t *
radius_server_add_fn(vlib_main_t *vm, unformat_input_t *input,
                     vlib_cli_command_t *cmd)
{
  radius_server_t s = {0};
  u8 *name = 0, *secret = 0;
  ip4_address_t ip4 = {0}, src4 = {0};
  s.port = 1812;
  s.timeout_sec = 5;
  s.retries = 1;
  s.enabled = 1;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "name %s", &name)) ;
    else if (unformat(input, "ip %U", unformat_ip4_address, &ip4)) ;
    else if (unformat(input, "src %U", unformat_ip4_address, &src4)) ;
    else if (unformat(input, "fib %u", &s.fib_index)) ;
    else if (unformat(input, "sw_if_index %u", &s.sw_if_index)) ;
    else if (unformat(input, "port %u", &s.port)) ;
    else if (unformat(input, "timeout %u", &s.timeout_sec)) ;
    else if (unformat(input, "retries %u", &s.retries)) ;
    else if (unformat(input, "secret %s", &secret)) ;
    else return clib_error_return(0, "unknown input: %U", format_unformat_error, input);
  }

  if (!name || !secret)
    return clib_error_return(0, "name and secret are required");

  clib_memcpy(s.name, name, clib_min(vec_len(name), (uword)sizeof(s.name)));
  clib_memcpy(s.secret, secret, clib_min(vec_len(secret), (uword)sizeof(s.secret)));
  s.ip.ip4 = ip4;
  s.src_ip.ip4 = src4;
  radius_provider_set(&s);
  vec_free(name);
  vec_free(secret);
  return 0;
}

VLIB_CLI_COMMAND(radius_server_add_cmd, static) = {
  .path = "radius server add",
  .short_help = "radius server add name <n> ip <a.b.c.d> src <a.b.c.d> fib <n> sw_if_index <n> port <1812> timeout <5> retries <1> secret <s>",
  .function = radius_server_add_fn,
};

static clib_error_t *
radius_test_auth_fn(vlib_main_t *vm, unformat_input_t *input,
                    vlib_cli_command_t *cmd)
{
  u8 *provider = 0, *username = 0, *password = 0;
  radius_auth_req_t req = {0};
  u64 txn_id = 0;
  int rv;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "provider %s", &provider)) ;
    else if (unformat(input, "username %s", &username)) ;
    else if (unformat(input, "password %s", &password)) ;
    else return clib_error_return(0, "unknown input: %U", format_unformat_error, input);
  }

  if (!provider || !username || !password)
    return clib_error_return(0, "provider/username/password are required");

  req.provider_index = radius_find_provider_by_name(provider);
  if ((int)req.provider_index < 0)
    return clib_error_return(0, "provider not found");

  req.username = username;
  req.password = password;
  req.nas_id = format(0, "radius-cli-test");
  rv = radius_auth_start(&req, &txn_id);
  vlib_cli_output(vm, "rv=%d txn_id=%llu", rv, txn_id);

  vec_free(provider);
  vec_free(username);
  vec_free(password);
  vec_free(req.nas_id);
  return 0;
}

VLIB_CLI_COMMAND(radius_test_auth_cmd, static) = {
  .path = "radius test-auth",
  .short_help = "radius test-auth provider <name> username <u> password <p>",
  .function = radius_test_auth_fn,
};
