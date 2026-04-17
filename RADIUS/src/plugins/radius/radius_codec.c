#include "radius_codec.h"
#include "radius_md5.h"

#include <vppinfra/vec.h>
#include <vppinfra/string.h>
#include <vppinfra/random.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>

static void
radius_put_attr(u8 **b, u8 type, const u8 *data, u32 len)
{
  if (len > 253)
    len = 253;
  vec_add1(*b, type);
  vec_add1(*b, (u8) (len + 2));
  if (len)
    vec_add(*b, data, len);
}

static void
radius_hmac_md5(const u8 *key, u32 key_len, const u8 *msg, u32 msg_len,
                u8 out[16])
{
  u8 k0[64];
  u8 ipad[64];
  u8 opad[64];
  u8 inner[16];
  radius_md5_ctx_t md5;
  u32 i;

  clib_memset(k0, 0, sizeof(k0));
  if (key_len > 64)
    {
      radius_md5_init(&md5);
      radius_md5_update(&md5, key, key_len);
      radius_md5_final(&md5, k0);
    }
  else if (key_len)
    {
      clib_memcpy(k0, key, key_len);
    }

  for (i = 0; i < 64; i++)
    {
      ipad[i] = k0[i] ^ 0x36;
      opad[i] = k0[i] ^ 0x5c;
    }

  radius_md5_init(&md5);
  radius_md5_update(&md5, ipad, sizeof(ipad));
  if (msg_len)
    radius_md5_update(&md5, msg, msg_len);
  radius_md5_final(&md5, inner);

  radius_md5_init(&md5);
  radius_md5_update(&md5, opad, sizeof(opad));
  radius_md5_update(&md5, inner, sizeof(inner));
  radius_md5_final(&md5, out);
}

void
radius_random_authenticator(u8 out[16])
{
  static u32 seed = 0x13572468;
  int i;
  for (i = 0; i < 16; i++) {
    seed = 1664525u * seed + 1013904223u;
    out[i] = (u8)(seed >> 24);
  }
}

/* RFC2865 User-Password hiding for PAP.
 * c(1) = p(1) xor MD5(S + RA)
 * c(i) = p(i) xor MD5(S + c(i-1))
 */
static u8 *
radius_obfuscate_user_password(const u8 *password,
                               u32 password_len,
                               const u8 *secret,
                               u32 sec_len,
                               const u8 req_auth[16])
{
  u8 *out = 0;
  u32 padded = ((password_len + 15) / 16) * 16;
  u32 off;
  u8 digest[16];
  radius_md5_ctx_t md5;

  if (padded == 0)
    padded = 16;
  if (padded > 128)
    padded = 128;

  vec_validate(out, padded - 1);
  clib_memset(out, 0, padded);
  if (password_len)
    clib_memcpy(out, password, clib_min((uword)password_len, (uword)padded));

  for (off = 0; off < padded; off += 16)
    {
      radius_md5_init(&md5);
      if (sec_len)
        radius_md5_update(&md5, secret, sec_len);
      if (off == 0)
        radius_md5_update(&md5, req_auth, 16);
      else
        radius_md5_update(&md5, out + off - 16, 16);
      radius_md5_final(&md5, digest);

      for (u32 i = 0; i < 16; i++)
        out[off + i] ^= digest[i];
    }
  return out;
}

int
radius_encode_access_request(u8 **out,
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
                             u32 state_len)
{
  radius_header_t *h;
  u8 *pw = 0;
  u16 total_len;
  u32 msg_auth_off;
  u8 zero_ma[16] = { 0 };
  u8 msg_auth[16];

  if (!out)
    return -1;

  vec_reset_length(*out);
  vec_validate(*out, sizeof(*h) - 1);
  h = (radius_header_t *)vec_elt_at_index(*out, 0);
  h->code = RADIUS_CODE_ACCESS_REQUEST;
  h->identifier = identifier;
  clib_memcpy(h->authenticator, req_auth, 16);

  if (username && username_len)
    radius_put_attr(out, RADIUS_ATTR_USER_NAME, username, username_len);

  if (password && password_len) {
    pw = radius_obfuscate_user_password(password, password_len,
                                        secret, secret_len, req_auth);
    radius_put_attr(out, RADIUS_ATTR_USER_PASSWORD, pw, vec_len(pw));
  }

  if (nas_id && nas_id_len)
    radius_put_attr(out, RADIUS_ATTR_NAS_IDENTIFIER, nas_id, nas_id_len);

  if (state && state_len)
    radius_put_attr(out, RADIUS_ATTR_STATE, state, state_len);

  msg_auth_off = vec_len(*out);
  radius_put_attr(out, RADIUS_ATTR_MESSAGE_AUTH, zero_ma, sizeof(zero_ma));

  total_len = vec_len(*out);
  h = (radius_header_t *)vec_elt_at_index(*out, 0);
  h->length = clib_host_to_net_u16(total_len);

  radius_hmac_md5(secret, secret_len, *out, total_len, msg_auth);
  clib_memcpy(*out + msg_auth_off + 2, msg_auth, sizeof(msg_auth));

  vec_free(pw);
  return 0;
}

int
radius_decode_response(const u8 *pkt, u32 len, radius_decoded_resp_t *out)
{
  const radius_header_t *h;
  u32 off = sizeof(*h);

  if (!pkt || len < sizeof(*h) || !out)
    return -1;

  clib_memset(out, 0, sizeof(*out));

  h = (const radius_header_t *)pkt;
  if (clib_net_to_host_u16(h->length) > len)
    return -2;

  out->code = h->code;
  out->identifier = h->identifier;
  clib_memcpy(out->authenticator, h->authenticator, 16);

  while (off + 2 <= len) {
    u8 type = pkt[off];
    u8 alen = pkt[off + 1];
    const u8 *aval = pkt + off + 2;
    if (alen < 2 || off + alen > len)
      break;

    switch (type)
      {
      case RADIUS_ATTR_REPLY_MESSAGE:
        vec_add(out->reply_message, aval, alen - 2);
        break;
      case RADIUS_ATTR_FILTER_ID:
        vec_add(out->filter_id, aval, alen - 2);
        break;
      case RADIUS_ATTR_STATE:
        vec_add(out->state, aval, alen - 2);
        break;
      case RADIUS_ATTR_SESSION_TIMEOUT:
        if (alen == 6)
          {
            u32 v;
            clib_memcpy(&v, aval, sizeof(v));
            out->session_timeout = clib_net_to_host_u32(v);
          }
        break;
      case RADIUS_ATTR_IDLE_TIMEOUT:
        if (alen == 6)
          {
            u32 v;
            clib_memcpy(&v, aval, sizeof(v));
            out->idle_timeout = clib_net_to_host_u32(v);
          }
        break;
      default:
        break;
      }
    off += alen;
  }
  return 0;
}

void
radius_decoded_resp_free(radius_decoded_resp_t *resp)
{
  if (!resp)
    return;
  vec_free(resp->reply_message);
  vec_free(resp->filter_id);
  vec_free(resp->state);
  clib_memset(resp, 0, sizeof(*resp));
}
