#ifndef included_radius_md5_h
#define included_radius_md5_h

#include <vppinfra/types.h>

typedef struct {
  u32 state[4];
  u64 bitlen;
  u8 data[64];
  u32 datalen;
} radius_md5_ctx_t;

void radius_md5_init(radius_md5_ctx_t *ctx);
void radius_md5_update(radius_md5_ctx_t *ctx, const u8 *data, u32 len);
void radius_md5_final(radius_md5_ctx_t *ctx, u8 hash[16]);

#endif
