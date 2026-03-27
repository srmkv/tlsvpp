#ifndef included_tlsctrl_h
#define included_tlsctrl_h

#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>

typedef enum { TLSCTRL_STATUS_DISCONNECTED = 0, TLSCTRL_STATUS_CONNECTED = 1 } tlsctrl_status_t;

typedef struct {
  u8 username[64];
  u8 cert_serial[128];
  u8 enabled;
  u8 pad[3];
  u64 generation;
  f64 last_seen;
} tlsctrl_user_t;

typedef struct {
  u8 username[64];
  u8 cert_serial[128];
  u8 system_user[64];
  u8 os_name[64];
  u8 os_version[64];
  u8 system_uptime[64];
  u8 ip[64];
  u8 mac[32];
  u8 source[32];
  tlsctrl_status_t status;
  f64 connected_at;
  f64 last_seen;
  u32 apps_count;
  u8 command_type[32];
  u8 command_payload[256];
} tlsctrl_session_t;

typedef struct {
  vlib_main_t *vlib_main;
  api_main_t *api_main;
  u16 msg_id_base;
  tlsctrl_user_t *users;
  tlsctrl_session_t *sessions;
  clib_spinlock_t lock;
} tlsctrl_main_t;

extern tlsctrl_main_t tlsctrl_main;

tlsctrl_user_t *tlsctrl_user_find(const u8 *username);
tlsctrl_user_t *tlsctrl_user_find_or_create(const u8 *username);
tlsctrl_session_t *tlsctrl_session_find(const u8 *username);
tlsctrl_session_t *tlsctrl_session_find_or_create(const u8 *username);
void tlsctrl_session_mark_disconnected(const u8 *username);
void tlsctrl_string_set(u8 *dst, u32 dst_len, const u8 *src);
u8 *tlsctrl_format_cstr(const u8 *buf, u32 len);

#endif
