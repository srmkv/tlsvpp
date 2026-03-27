#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibapi/api_helper_macros.h>

#include <tlsctrl/tlsctrl.h>
#include <tlsctrl/tlsctrl.api_enum.h>
#include <tlsctrl/tlsctrl.api_types.h>

#undef REPLY_MSG_ID_BASE
#define REPLY_MSG_ID_BASE tlsctrl_main.msg_id_base

static void
send_user_details(vl_api_registration_t *rp, tlsctrl_user_t *u, u32 context)
{
  vl_api_tlsctrl_user_details_t *rmp;

  rmp = vl_msg_api_alloc(sizeof(*rmp));
  clib_memset(rmp, 0, sizeof(*rmp));
  rmp->_vl_msg_id = htons(VL_API_TLSCTRL_USER_DETAILS + tlsctrl_main.msg_id_base);
  rmp->context = context;
  tlsctrl_string_set(rmp->username, sizeof(rmp->username), u->username);
  tlsctrl_string_set(rmp->cert_serial, sizeof(rmp->cert_serial), u->cert_serial);
  rmp->enabled = u->enabled;
  rmp->status = TLSCTRL_STATUS_DISCONNECTED;
  rmp->generation = clib_host_to_net_u64(u->generation);
  rmp->last_seen_unix_ns = clib_host_to_net_u64((u64)(u->last_seen * 1e9));

  vl_api_send_msg(rp, (u8 *) rmp);
}

static void
send_session_details(vl_api_registration_t *rp, tlsctrl_session_t *s, u32 context)
{
  vl_api_tlsctrl_session_details_t *rmp;

  rmp = vl_msg_api_alloc(sizeof(*rmp));
  clib_memset(rmp, 0, sizeof(*rmp));
  rmp->_vl_msg_id = htons(VL_API_TLSCTRL_SESSION_DETAILS + tlsctrl_main.msg_id_base);
  rmp->context = context;
  tlsctrl_string_set(rmp->username, sizeof(rmp->username), s->username);
  tlsctrl_string_set(rmp->cert_serial, sizeof(rmp->cert_serial), s->cert_serial);
  tlsctrl_string_set(rmp->system_user, sizeof(rmp->system_user), s->system_user);
  tlsctrl_string_set(rmp->os_name, sizeof(rmp->os_name), s->os_name);
  tlsctrl_string_set(rmp->os_version, sizeof(rmp->os_version), s->os_version);
  tlsctrl_string_set(rmp->system_uptime, sizeof(rmp->system_uptime), s->system_uptime);
  tlsctrl_string_set(rmp->ip, sizeof(rmp->ip), s->ip);
  tlsctrl_string_set(rmp->mac, sizeof(rmp->mac), s->mac);
  tlsctrl_string_set(rmp->source, sizeof(rmp->source), s->source);
  rmp->status = s->status;
  rmp->connected_at_unix_ns = clib_host_to_net_u64((u64)(s->connected_at * 1e9));
  rmp->last_seen_unix_ns = clib_host_to_net_u64((u64)(s->last_seen * 1e9));
  rmp->apps_count = clib_host_to_net_u32(s->apps_count);

  vl_api_send_msg(rp, (u8 *) rmp);
}

static void
vl_api_tlsctrl_user_add_del_t_handler(vl_api_tlsctrl_user_add_del_t *mp)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vl_api_tlsctrl_user_add_del_reply_t *rmp;
  i32 rv = 0;
  tlsctrl_user_t *u = 0;
  int i;

  clib_spinlock_lock(&tm->lock);

  if (mp->is_add)
    {
      u = tlsctrl_user_find_or_create(mp->username);
      tlsctrl_string_set(u->cert_serial, sizeof(u->cert_serial), mp->cert_serial);
      u->enabled = mp->enabled ? 1 : 0;
      u->generation++;
    }
  else
    {
      vec_foreach_index(i, tm->users)
        {
          if (!strncmp((char *) tm->users[i].username, (char *) mp->username,
                       sizeof(tm->users[i].username)))
            {
              vec_del1(tm->users, i);
              tlsctrl_session_mark_disconnected(mp->username);
              goto done;
            }
        }
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
    }

done:
  clib_spinlock_unlock(&tm->lock);
  REPLY_MACRO(VL_API_TLSCTRL_USER_ADD_DEL_REPLY);
}

static void
vl_api_tlsctrl_user_dump_t_handler(vl_api_tlsctrl_user_dump_t *mp)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vl_api_registration_t *rp;
  int i;

  rp = vl_api_client_index_to_registration(mp->client_index);
  if (!rp)
    return;

  clib_spinlock_lock(&tm->lock);
  vec_foreach_index(i, tm->users)
    send_user_details(rp, &tm->users[i], mp->context);
  clib_spinlock_unlock(&tm->lock);
}

static void
vl_api_tlsctrl_user_reissue_t_handler(vl_api_tlsctrl_user_reissue_t *mp)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vl_api_tlsctrl_user_reissue_reply_t *rmp;
  i32 rv = 0;
  tlsctrl_user_t *u;

  clib_spinlock_lock(&tm->lock);
  u = tlsctrl_user_find(mp->username);
  if (!u)
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  else
    {
      tlsctrl_string_set(u->cert_serial, sizeof(u->cert_serial), mp->cert_serial);
      u->generation++;
      tlsctrl_session_mark_disconnected(mp->username);
    }
  clib_spinlock_unlock(&tm->lock);

  REPLY_MACRO(VL_API_TLSCTRL_USER_REISSUE_REPLY);
}

static void
vl_api_tlsctrl_session_disconnect_t_handler(vl_api_tlsctrl_session_disconnect_t *mp)
{
  vl_api_tlsctrl_session_disconnect_reply_t *rmp;
  i32 rv = 0;

  tlsctrl_session_mark_disconnected(mp->username);
  REPLY_MACRO(VL_API_TLSCTRL_SESSION_DISCONNECT_REPLY);
}

static void
vl_api_tlsctrl_session_dump_t_handler(vl_api_tlsctrl_session_dump_t *mp)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vl_api_registration_t *rp;
  int i;

  rp = vl_api_client_index_to_registration(mp->client_index);
  if (!rp)
    return;

  clib_spinlock_lock(&tm->lock);
  vec_foreach_index(i, tm->sessions)
    send_session_details(rp, &tm->sessions[i], mp->context);
  clib_spinlock_unlock(&tm->lock);
}

static void
vl_api_tlsctrl_client_heartbeat_t_handler(vl_api_tlsctrl_client_heartbeat_t *mp)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vl_api_tlsctrl_client_heartbeat_reply_t *rmp;
  i32 rv = 0;
  tlsctrl_user_t *u;
  tlsctrl_session_t *s;

  clib_spinlock_lock(&tm->lock);
  u = tlsctrl_user_find(mp->username);
  if (!u || !u->enabled)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto done;
    }

  if (strncmp((char *) u->cert_serial, (char *) mp->cert_serial, sizeof(u->cert_serial)))
    {
      tlsctrl_session_mark_disconnected(mp->username);
      rv = VNET_API_ERROR_SYSCALL_ERROR_1;
      goto done;
    }

  s = tlsctrl_session_find_or_create(mp->username);
  tlsctrl_string_set(s->cert_serial, sizeof(s->cert_serial), mp->cert_serial);
  tlsctrl_string_set(s->system_user, sizeof(s->system_user), mp->system_user);
  tlsctrl_string_set(s->os_name, sizeof(s->os_name), mp->os_name);
  tlsctrl_string_set(s->os_version, sizeof(s->os_version), mp->os_version);
  tlsctrl_string_set(s->system_uptime, sizeof(s->system_uptime), mp->system_uptime);
  tlsctrl_string_set(s->ip, sizeof(s->ip), mp->ip);
  tlsctrl_string_set(s->mac, sizeof(s->mac), mp->mac);
  tlsctrl_string_set(s->source, sizeof(s->source), mp->source);

  if (s->connected_at == 0.0)
    s->connected_at = vlib_time_now(tm->vlib_main);
  s->last_seen = vlib_time_now(tm->vlib_main);
  s->status = TLSCTRL_STATUS_CONNECTED;
  u->last_seen = s->last_seen;

done:
  clib_spinlock_unlock(&tm->lock);
  REPLY_MACRO(VL_API_TLSCTRL_CLIENT_HEARTBEAT_REPLY);
}

static void
vl_api_tlsctrl_client_apps_set_t_handler(vl_api_tlsctrl_client_apps_set_t *mp)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vl_api_tlsctrl_client_apps_set_reply_t *rmp;
  i32 rv = 0;
  tlsctrl_session_t *s;

  clib_spinlock_lock(&tm->lock);
  s = tlsctrl_session_find(mp->username);
  if (!s || s->status != TLSCTRL_STATUS_CONNECTED)
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  else
    s->apps_count = clib_net_to_host_u32(mp->count);
  clib_spinlock_unlock(&tm->lock);

  REPLY_MACRO(VL_API_TLSCTRL_CLIENT_APPS_SET_REPLY);
}

static void
vl_api_tlsctrl_client_command_set_t_handler(vl_api_tlsctrl_client_command_set_t *mp)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  vl_api_tlsctrl_client_command_set_reply_t *rmp;
  i32 rv = 0;
  tlsctrl_session_t *s;

  clib_spinlock_lock(&tm->lock);
  s = tlsctrl_session_find_or_create(mp->username);
  tlsctrl_string_set(s->command_type, sizeof(s->command_type), mp->command_type);
  tlsctrl_string_set(s->command_payload, sizeof(s->command_payload), mp->payload);
  clib_spinlock_unlock(&tm->lock);

  REPLY_MACRO(VL_API_TLSCTRL_CLIENT_COMMAND_SET_REPLY);
}

static void
vl_api_tlsctrl_client_command_get_t_handler(vl_api_tlsctrl_client_command_get_t *mp)
{
  tlsctrl_session_t *s = tlsctrl_session_find(mp->username);
  vl_api_tlsctrl_client_command_get_reply_t *rmp;
  i32 rv = 0;

  REPLY_MACRO2(VL_API_TLSCTRL_CLIENT_COMMAND_GET_REPLY,
  ({
    if (s)
      {
        tlsctrl_string_set(rmp->command_type, sizeof(rmp->command_type), s->command_type);
        tlsctrl_string_set(rmp->payload, sizeof(rmp->payload), s->command_payload);
      }
    else
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  }));
}

#include <tlsctrl/tlsctrl.api.c>

static clib_error_t *
tlsctrl_api_hookup(vlib_main_t *vm)
{
  tlsctrl_main_t *tm = &tlsctrl_main;
  tm->msg_id_base = setup_message_id_table();
  return 0;
}

VLIB_API_INIT_FUNCTION(tlsctrl_api_hookup);
