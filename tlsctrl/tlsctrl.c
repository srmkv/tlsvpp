#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <tlsctrl/tlsctrl.h>

tlsctrl_main_t tlsctrl_main;

void tlsctrl_string_set(u8 *dst, u32 dst_len, const u8 *src) {
  u32 n = 0;
  if (!dst || !dst_len) return;
  clib_memset(dst, 0, dst_len);
  if (!src) return;
  while (n + 1 < dst_len && src[n]) { dst[n] = src[n]; n++; }
}

u8 *tlsctrl_format_cstr(const u8 *buf, u32 len) {
  u8 *out = 0; u32 i;
  if (!buf) return format(0, "");
  for (i = 0; i < len && buf[i]; i++) out = format(out, "%c", buf[i]);
  return out;
}

tlsctrl_user_t *tlsctrl_user_find(const u8 *username) {
  tlsctrl_main_t *tm = &tlsctrl_main; int i;
  vec_foreach_index(i, tm->users) {
    if (!strncmp((char*)tm->users[i].username, (char*)username, sizeof(tm->users[i].username)))
      return &tm->users[i];
  }
  return 0;
}

tlsctrl_user_t *tlsctrl_user_find_or_create(const u8 *username) {
  tlsctrl_user_t *u = tlsctrl_user_find(username); tlsctrl_main_t *tm = &tlsctrl_main;
  if (u) return u;
  vec_add2(tm->users, u, 1); clib_memset(u, 0, sizeof(*u));
  tlsctrl_string_set(u->username, sizeof(u->username), username); u->enabled = 1; u->generation = 1; return u;
}

tlsctrl_session_t *tlsctrl_session_find(const u8 *username) {
  tlsctrl_main_t *tm = &tlsctrl_main; int i;
  vec_foreach_index(i, tm->sessions) {
    if (!strncmp((char*)tm->sessions[i].username, (char*)username, sizeof(tm->sessions[i].username)))
      return &tm->sessions[i];
  }
  return 0;
}

tlsctrl_session_t *tlsctrl_session_find_or_create(const u8 *username) {
  tlsctrl_session_t *s = tlsctrl_session_find(username); tlsctrl_main_t *tm = &tlsctrl_main;
  if (s) return s;
  vec_add2(tm->sessions, s, 1); clib_memset(s, 0, sizeof(*s));
  tlsctrl_string_set(s->username, sizeof(s->username), username); s->status = TLSCTRL_STATUS_DISCONNECTED; return s;
}

void tlsctrl_session_mark_disconnected(const u8 *username) {
  tlsctrl_session_t *s = tlsctrl_session_find(username); if (!s) return; s->status = TLSCTRL_STATUS_DISCONNECTED;
}

static clib_error_t *tlsctrl_init(vlib_main_t *vm) {
  tlsctrl_main_t *tm = &tlsctrl_main; tm->vlib_main = vm; clib_spinlock_init(&tm->lock); return 0;
}
VLIB_INIT_FUNCTION(tlsctrl_init);
VLIB_PLUGIN_REGISTER() = { .version = VPP_BUILD_VER, .description = "TLS control state plugin", .default_disabled = 1, };
