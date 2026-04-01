/* SPDX-License-Identifier: Apache-2.0 */

#include <tlsctrl/tlsctrl.h>

static clib_error_t *
tlsctrl_phase3b_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd)
{
  int rv;
  (void) vm;
  (void) cmd;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input: %U", format_unformat_error,
                              input);

  rv = tlsctrl_phase3b_enable ();
  if (rv)
    return clib_error_return (0, "enable failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (tlsctrl_phase3b_enable_command, static) = {
  .path = "tlsctrl phase3b enable",
  .short_help = "tlsctrl phase3b enable",
  .function = tlsctrl_phase3b_enable_command_fn,
};

static clib_error_t *
tlsctrl_phase3b_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
  int rv;
  (void) vm;
  (void) cmd;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input: %U", format_unformat_error,
                              input);

  rv = tlsctrl_phase3b_disable ();
  if (rv)
    return clib_error_return (0, "disable failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (tlsctrl_phase3b_disable_command, static) = {
  .path = "tlsctrl phase3b disable",
  .short_help = "tlsctrl phase3b disable",
  .function = tlsctrl_phase3b_disable_command_fn,
};

static clib_error_t *
tlsctrl_phase3b_runtime_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
  u8 *addr = 0, *server_name = 0;
  u32 port = 0;
  int have_addr = 0, have_port = 0;
  int rv;
  (void) vm;
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "addr %s", &addr))
        have_addr = 1;
      else if (unformat (input, "port %u", &port))
        have_port = 1;
      else if (unformat (input, "server-name %s", &server_name))
        ;
      else
        {
          vec_free (addr);
          vec_free (server_name);
          return clib_error_return (0, "unknown input: %U",
                                    format_unformat_error, input);
        }
    }

  if (!have_addr || !have_port || port > 65535)
    {
      vec_free (addr);
      vec_free (server_name);
      return clib_error_return (0,
                                "usage: tlsctrl phase3b runtime addr <ip> port <p> [server-name <name>]");
    }

  if (!server_name)
    server_name = format (0, "localhost");

  rv = tlsctrl_phase3b_set_runtime (addr, (u16) port, server_name);
  vec_free (addr);
  vec_free (server_name);
  if (rv)
    return clib_error_return (0, "runtime set failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (tlsctrl_phase3b_runtime_command, static) = {
  .path = "tlsctrl phase3b runtime",
  .short_help = "tlsctrl phase3b runtime addr <ip> port <p> [server-name <name>]",
  .function = tlsctrl_phase3b_runtime_command_fn,
};

static clib_error_t *
tlsctrl_phase3b_load_pem_files_command_fn (vlib_main_t *vm,
                                           unformat_input_t *input,
                                           vlib_cli_command_t *cmd)
{
  u8 *cert = 0, *key = 0, *ca = 0;
  int rv;
  (void) vm;
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "cert %s", &cert))
        ;
      else if (unformat (input, "key %s", &key))
        ;
      else if (unformat (input, "ca %s", &ca))
        ;
      else
        {
          vec_free (cert);
          vec_free (key);
          vec_free (ca);
          return clib_error_return (0, "unknown input: %U",
                                    format_unformat_error, input);
        }
    }

  if (!cert || !key || !ca)
    {
      vec_free (cert);
      vec_free (key);
      vec_free (ca);
      return clib_error_return (0,
                                "usage: tlsctrl phase3b load-pem-files cert <file> key <file> ca <file>");
    }

  rv = tlsctrl_phase3b_load_pem_files (cert, key, ca);
  vec_free (cert);
  vec_free (key);
  vec_free (ca);
  if (rv)
    return clib_error_return (0, "load-pem-files failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (tlsctrl_phase3b_load_pem_files_command, static) = {
  .path = "tlsctrl phase3b load-pem-files",
  .short_help = "tlsctrl phase3b load-pem-files cert <file> key <file> ca <file>",
  .function = tlsctrl_phase3b_load_pem_files_command_fn,
};

static clib_error_t *
tlsctrl_phase3b_attach_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd)
{
  int rv;
  (void) vm;
  (void) cmd;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input: %U", format_unformat_error,
                              input);

  rv = tlsctrl_phase3b_attach ();
  if (rv)
    return clib_error_return (0, "attach failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (tlsctrl_phase3b_attach_command, static) = {
  .path = "tlsctrl phase3b attach",
  .short_help = "tlsctrl phase3b attach",
  .function = tlsctrl_phase3b_attach_command_fn,
};

static clib_error_t *
tlsctrl_phase3b_detach_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd)
{
  int rv;
  (void) vm;
  (void) cmd;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input: %U", format_unformat_error,
                              input);

  rv = tlsctrl_phase3b_detach ();
  if (rv)
    return clib_error_return (0, "detach failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (tlsctrl_phase3b_detach_command, static) = {
  .path = "tlsctrl phase3b detach",
  .short_help = "tlsctrl phase3b detach",
  .function = tlsctrl_phase3b_detach_command_fn,
};

static clib_error_t *
tlsctrl_phase3b_listen_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd)
{
  int do_enable = -1;
  int rv;
  (void) vm;
  (void) cmd;

  if (unformat (input, "enable"))
    do_enable = 1;
  else if (unformat (input, "disable"))
    do_enable = 0;

  if (do_enable < 0 || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0,
                              "usage: tlsctrl phase3b listen <enable|disable>");

  rv = do_enable ? tlsctrl_phase3b_listen_enable ()
                 : tlsctrl_phase3b_listen_disable ();
  if (rv)
    return clib_error_return (0, "listen operation failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (tlsctrl_phase3b_listen_command, static) = {
  .path = "tlsctrl phase3b listen",
  .short_help = "tlsctrl phase3b listen <enable|disable>",
  .function = tlsctrl_phase3b_listen_command_fn,
};

static clib_error_t *
tlsctrl_phase3b_client_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *cmd)
{
  u8 *username = 0;
  int do_disconnect = -1;
  int rv;
  (void) vm;
  (void) cmd;

  if (unformat (input, "disconnect %s", &username))
    do_disconnect = 1;
  else if (unformat (input, "reconnect %s", &username))
    do_disconnect = 0;

  if (do_disconnect < 0 ||
      unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vec_free (username);
      return clib_error_return (
        0,
        "usage: tlsctrl phase3b client <disconnect|reconnect> <username>");
    }

  rv = tlsctrl_phase3b_client_set_disconnected (username, do_disconnect);
  vec_free (username);
  if (rv)
    return clib_error_return (0, "client state update failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (tlsctrl_phase3b_client_command, static) = {
  .path = "tlsctrl phase3b client",
  .short_help = "tlsctrl phase3b client <disconnect|reconnect> <username>",
  .function = tlsctrl_phase3b_client_command_fn,
};

static clib_error_t *
show_tlsctrl_phase3b_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *cmd)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  (void) cmd;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input: %U", format_unformat_error,
                              input);

  vlib_cli_output (vm, "%U", format_tlsctrl_phase3b_state, tm);
  return 0;
}

VLIB_CLI_COMMAND (show_tlsctrl_phase3b_command, static) = {
  .path = "show tlsctrl phase3b",
  .short_help = "show tlsctrl phase3b",
  .function = show_tlsctrl_phase3b_command_fn,
};

static clib_error_t *
show_tlsctrl_clients_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *cmd)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  (void) cmd;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input: %U", format_unformat_error,
                              input);

  vlib_cli_output (vm, "%U", format_tlsctrl_phase3b_clients, tm);
  return 0;
}

VLIB_CLI_COMMAND (show_tlsctrl_clients_command, static) = {
  .path = "show tlsctrl clients",
  .short_help = "show tlsctrl clients",
  .function = show_tlsctrl_clients_command_fn,
};

static clib_error_t *
show_tlsctrl_users_command_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  (void) cmd;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input: %U", format_unformat_error,
                              input);

  vlib_cli_output (vm, "%U", format_tlsctrl_phase3b_users, tm);
  return 0;
}

VLIB_CLI_COMMAND (show_tlsctrl_users_command, static) = {
  .path = "show tlsctrl users",
  .short_help = "show tlsctrl users",
  .function = show_tlsctrl_users_command_fn,
};
