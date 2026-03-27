#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <tlsctrl/tlsctrl.h>

static clib_error_t *show_tlsctrl_users_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
  tlsctrl_main_t *tm = &tlsctrl_main; int i; vlib_cli_output(vm, "tlsctrl users:"); clib_spinlock_lock(&tm->lock);
  vec_foreach_index(i, tm->users) { u8 *u = tlsctrl_format_cstr(tm->users[i].username, sizeof(tm->users[i].username)); u8 *cs = tlsctrl_format_cstr(tm->users[i].cert_serial, sizeof(tm->users[i].cert_serial)); vlib_cli_output(vm, "  user=%v enabled=%u generation=%llu cert=%v", u, tm->users[i].enabled, tm->users[i].generation, cs); vec_free(u); vec_free(cs); }
  clib_spinlock_unlock(&tm->lock); return 0; }
VLIB_CLI_COMMAND(show_tlsctrl_users_cmd, static) = { .path = "show tlsctrl users", .short_help = "show tlsctrl users", .function = show_tlsctrl_users_fn, };

static clib_error_t *show_tlsctrl_sessions_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
  tlsctrl_main_t *tm = &tlsctrl_main; int i; vlib_cli_output(vm, "tlsctrl sessions:"); clib_spinlock_lock(&tm->lock);
  vec_foreach_index(i, tm->sessions) { u8 *u = tlsctrl_format_cstr(tm->sessions[i].username, sizeof(tm->sessions[i].username)); u8 *ip = tlsctrl_format_cstr(tm->sessions[i].ip, sizeof(tm->sessions[i].ip)); u8 *mac = tlsctrl_format_cstr(tm->sessions[i].mac, sizeof(tm->sessions[i].mac)); vlib_cli_output(vm, "  user=%v status=%u ip=%v mac=%v apps=%u", u, tm->sessions[i].status, ip, mac, tm->sessions[i].apps_count); vec_free(u); vec_free(ip); vec_free(mac); }
  clib_spinlock_unlock(&tm->lock); return 0; }
VLIB_CLI_COMMAND(show_tlsctrl_sessions_cmd, static) = { .path = "show tlsctrl sessions", .short_help = "show tlsctrl sessions", .function = show_tlsctrl_sessions_fn, };
