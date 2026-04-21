#ifndef included_radius_codec_h
#define included_radius_codec_h

#include <vppinfra/types.h>

#define RADIUS_CODE_ACCESS_REQUEST   1
#define RADIUS_CODE_ACCESS_ACCEPT    2
#define RADIUS_CODE_ACCESS_REJECT    3
#define RADIUS_CODE_ACCOUNTING_REQ   4
#define RADIUS_CODE_ACCOUNTING_RESP  5
#define RADIUS_CODE_ACCESS_CHALLENGE 11

#define RADIUS_ATTR_USER_NAME        1
#define RADIUS_ATTR_USER_PASSWORD    2
#define RADIUS_ATTR_REPLY_MESSAGE    18
#define RADIUS_ATTR_STATE            24
#define RADIUS_ATTR_SESSION_TIMEOUT  27
#define RADIUS_ATTR_IDLE_TIMEOUT     28
#define RADIUS_ATTR_NAS_IDENTIFIER   32
#define RADIUS_ATTR_FILTER_ID        11
#define RADIUS_ATTR_MESSAGE_AUTH     80

typedef struct __attribute__((packed)) {
  u8 code;
  u8 identifier;
  u16 length;
  u8 authenticator[16];
} radius_header_t;

typedef struct {
  u8 code;
  u8 identifier;
  u8 authenticator[16];
  u8 *reply_message;
  u8 *filter_id;
  u8 *state;
  u32 session_timeout;
  u32 idle_timeout;
} radius_decoded_resp_t;

int radius_encode_access_request(u8 **out,
                                 u8 identifier,
                                 const u8 req_auth[16],
                                 const u8 *username,
                                 u32 username_len,
                                 const u8 *password,
                                 u32 password_len,
                                 const u8 *secret,
                                 u32 secret_len,
                                 const u8 *nas_id,
                                 u32 nas_id_len,
                                 const u8 *state,
                                 u32 state_len);

int radius_decode_response(const u8 *pkt, u32 len, radius_decoded_resp_t *out);
void radius_decoded_resp_free(radius_decoded_resp_t *resp);

void radius_random_authenticator(u8 out[16]);

#endif
