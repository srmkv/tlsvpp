#ifndef included_radius_service_h
#define included_radius_service_h

#include <vppinfra/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  RADIUS_RESULT_ACCEPT = 1,
  RADIUS_RESULT_REJECT = 2,
  RADIUS_RESULT_CHALLENGE = 3,
  RADIUS_RESULT_TIMEOUT = 4,
  RADIUS_RESULT_ERROR = 5,
} radius_result_code_t;

typedef struct {
  u32 provider_index;
  u32 consumer_index;
  u64 opaque_cookie;
  u64 txn_id;
  u8 *username;
  u8 *password;
  u8 *state;
  u8 *nas_id;
} radius_auth_req_t;

typedef struct {
  radius_result_code_t result_code;
  u64 opaque_cookie;
  u64 txn_id;
  u8 *reply_message;
  u8 *filter_id;
  u8 *state;
  u32 session_timeout;
  u32 idle_timeout;
} radius_auth_res_t;

typedef struct {
  void (*auth_result_fn)(radius_auth_res_t *res);
} radius_consumer_vft_t;

int radius_register_consumer(const char *name, radius_consumer_vft_t *vft,
                             u32 *consumer_index);
int radius_auth_start(radius_auth_req_t *req, u64 *txn_id);
int radius_auth_continue(radius_auth_req_t *req, u64 txn_id);

#ifdef __cplusplus
}
#endif

#endif
