#include "radius_transport.h"
#include "radius_codec.h"

#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_packet.h>

extern vlib_node_registration_t ip4_lookup_node;

static_always_inline u32
radius_vec_text_len(const u8 *s)
{
  u32 n;
  if (!s)
    return 0;
  n = vec_len((u8 *) s);
  if (n && s[n - 1] == 0)
    n--;
  return n;
}

static_always_inline u32
radius_cstr_len(const u8 *s, u32 max_len)
{
  if (!s)
    return 0;
  return strnlen((const char *) s, max_len);
}

/*
 * TX scaffold:
 * - crafts a raw IP4/UDP/RADIUS packet
 * - intended to be injected into ip4-lookup / interface-output path
 * - exact enqueue path may require adaptation to your VPP branch
 */
int
radius_transport_send_access_request(radius_pending_req_t *pr,
                                     radius_server_t *provider,
                                     const u8 *password,
                                     const u8 *nas_id)
{
  radius_main_t *rm = &radius_main;
  u8 *radius_payload = 0;
  vlib_main_t *vm = rm->vlib_main;
  vlib_buffer_t *b;
  u32 bi = ~0;
  ip4_header_t *ip4;
  udp_header_t *udp;
  i32 rv;
  u16 udp_len;
  u32 total;
  u32 username_len, password_len, secret_len, nas_id_len, state_len;
  const u8 *nas_id_ptr;

  username_len = radius_vec_text_len(pr->username);
  password_len = radius_vec_text_len(password);
  secret_len = radius_cstr_len(provider->secret, sizeof(provider->secret));
  nas_id_ptr = nas_id ? nas_id : provider->nas_id;
  nas_id_len = nas_id ? radius_vec_text_len(nas_id)
                      : radius_cstr_len(provider->nas_id, sizeof(provider->nas_id));
  state_len = pr->state ? vec_len(pr->state) : 0;

  rv = radius_encode_access_request(&radius_payload,
                                    pr->identifier,
                                    pr->request_authenticator,
                                    pr->username,
                                    username_len,
                                    password,
                                    password_len,
                                    provider->secret,
                                    secret_len,
                                    nas_id_ptr,
                                    nas_id_len,
                                    pr->state,
                                    state_len);
  if (rv < 0)
    return rv;

  if (vlib_buffer_alloc(vm, &bi, 1) != 1) {
    vec_free(radius_payload);
    return -10;
  }

  b = vlib_get_buffer(vm, bi);
  vlib_buffer_reset(b);
  total = sizeof(*ip4) + sizeof(*udp) + vec_len(radius_payload);
  b->current_data = 0;
  b->current_length = total;

  ip4 = vlib_buffer_get_current(b);
  udp = (udp_header_t *)(ip4 + 1);
  clib_memset(ip4, 0, total);

  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 64;
  ip4->protocol = IP_PROTOCOL_UDP;
  ip4->length = clib_host_to_net_u16(total);
  ip4->src_address.as_u32 = provider->src_ip.ip4.as_u32;
  ip4->dst_address.as_u32 = provider->ip.ip4.as_u32;
  ip4->checksum = ip4_header_checksum(ip4);

  udp->src_port = clib_host_to_net_u16(rm->local_src_port);
  udp->dst_port = clib_host_to_net_u16(provider->port ? provider->port : 1812);
  udp_len = sizeof(*udp) + vec_len(radius_payload);
  udp->length = clib_host_to_net_u16(udp_len);
  clib_memcpy((u8 *)(udp + 1), radius_payload, vec_len(radius_payload));

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  vnet_buffer(b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer(b)->sw_if_index[VLIB_TX] = (u32) ~0;
  vnet_buffer(b)->ip.fib_index = provider->fib_index;

  {
    vlib_frame_t *f;
    u32 *to_next;
    f = vlib_get_frame_to_node(vm, ip4_lookup_node.index);
    to_next = vlib_frame_vector_args(f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node(vm, ip4_lookup_node.index, f);
  }

  vec_free(radius_payload);
  return 0;
}
