#ifndef included_tlsctrl_vpn_h
#define included_tlsctrl_vpn_h

#include <vlib/vlib.h>
#include <vppinfra/lock.h>

typedef struct
{
  u8 *name;
  u8 *subnet;
  u8 *gateway;
  u32 lease_seconds;
  u32 active_leases;
  u32 lease_cursor;
} tlsctrl_vpn_pool_t;

typedef struct
{
  u8 *name;
  u8 *pool_name;
  u8 *dns_servers;
  u8 *include_routes;
  u8 *exclude_routes;
  u8 full_tunnel;
  u16 mtu;
  u16 mss_clamp;
} tlsctrl_vpn_profile_t;

typedef struct
{
  u32 tunnel_id;
  u8 *username;
  u8 *profile_name;
  u8 *assigned_ip;
  u8 *client_ip;
  u8 *gateway;
  u8 *dns_servers;
  u8 *include_routes;
  u8 *exclude_routes;
  u8 full_tunnel;
  u16 mtu;
  u16 mss_clamp;
  u32 lease_seconds;
  u8 running;
  u64 last_seen_unix_ns;
} tlsctrl_vpn_tunnel_t;

typedef struct
{
  u64 tunnel_id;
  u64 session_handle;
  u64 seq_tx;
  u64 rx_frames;
  u64 tx_frames;
  u64 rx_bytes;
  u64 tx_bytes;
  u64 keepalives_rx;
  u64 keepalives_tx;
  u64 ipv4_rx;
  u64 ipv4_tx;
  u64 last_rx_unix_ns;
  u64 last_tx_unix_ns;
  u8 running;
} tlsctrl_vpn_dp_session_t;

typedef struct
{
  u64 tunnel_id;
  u8 *assigned_ip;
  u8 *gateway;
  u8 *dns_servers;
  u8 *include_routes;
  u8 *exclude_routes;
  u8 full_tunnel;
  u16 mtu;
  u16 mss_clamp;
  u32 lease_seconds;
} tlsctrl_vpn_lease_result_t;


typedef struct
{
  u64 tunnel_id;
  u64 session_handle;
  u64 rx_frames;
  u64 tx_frames;
  u64 rx_bytes;
  u64 tx_bytes;
  u64 keepalives_rx;
  u64 keepalives_tx;
  u64 ipv4_rx;
  u64 ipv4_tx;
  u64 last_rx_unix_ns;
  u64 last_tx_unix_ns;
  u8 bound;
  u8 running;
} tlsctrl_vpn_stream_session_t;

typedef struct
{
  clib_spinlock_t lock;
  tlsctrl_vpn_pool_t *pools;
  tlsctrl_vpn_profile_t *profiles;
  tlsctrl_vpn_tunnel_t *tunnels;
  tlsctrl_vpn_dp_session_t *dp_sessions;
  tlsctrl_vpn_stream_session_t *stream_sessions;
  u32 next_tunnel_id;
} tlsctrl_vpn_main_t;

extern tlsctrl_vpn_main_t tlsctrl_vpn_main;

clib_error_t *tlsctrl_vpn_stream_init (vlib_main_t * vm);
int tlsctrl_vpn_stream_attach (u64 tunnel_id, u64 session_handle);
int tlsctrl_vpn_stream_detach (u64 tunnel_id);
int tlsctrl_vpn_stream_note_keepalive (u64 tunnel_id, int outbound);
int tlsctrl_vpn_stream_note_ipv4 (u64 tunnel_id, u32 bytes, int outbound);
int tlsctrl_vpn_stream_find_session (u64 tunnel_id, tlsctrl_vpn_stream_session_t **out);

clib_error_t *tlsctrl_vpn_init (vlib_main_t * vm);

int tlsctrl_vpn_pool_set (const char *name, const char *subnet, const char *gateway,
                          u32 lease_seconds);
int tlsctrl_vpn_profile_set (const char *name, const char *pool, u8 full_tunnel,
                             const char *dns, const char *include_routes,
                             const char *exclude_routes, u16 mtu, u16 mss);
int tlsctrl_vpn_connect_config_get (const char *username, const char *profile,
                                    const char *client_ip, u32 *tunnel_id,
                                    u8 **assigned_ip, u8 **gateway,
                                    u8 **dns_servers, u8 **include_routes,
                                    u8 **exclude_routes, u8 *full_tunnel,
                                    u16 *mtu, u16 *mss, u32 *lease_seconds,
                                    int create_tunnel);
int tlsctrl_vpn_tunnel_open (const char *username, const char *profile,
                             const char *client_ip, u32 *tunnel_id,
                             u8 **assigned_ip, u8 **gateway,
                             u8 **dns_servers, u8 **include_routes,
                             u8 **exclude_routes, u8 *full_tunnel,
                             u16 *mtu, u16 *mss, u32 *lease_seconds);
int tlsctrl_vpn_tunnel_close (const char *username);
int tlsctrl_vpn_lease_acquire (const char *username, const char *profile,
                               const char *client_ip, u64 now_ns,
                               tlsctrl_vpn_lease_result_t *result);
int tlsctrl_vpn_lease_release (const char *username, u64 tunnel_id);
void tlsctrl_vpn_lease_result_free (tlsctrl_vpn_lease_result_t *r);

#endif

#define TLSCTRL_VPN_FRAME_TYPE_KEEPALIVE 1
#define TLSCTRL_VPN_FRAME_TYPE_IPV4      2
#define TLSCTRL_VPN_FRAME_TYPE_CONTROL   3

typedef struct __attribute__((packed))
{
  u8 type;
  u8 flags;
  u16 reserved;
  u32 len;
  u64 tunnel_id;
  u64 seq;
} tlsctrl_vpn_frame_hdr_t;

int tlsctrl_vpn_dp_attach (u64 tunnel_id, u64 session_handle);
int tlsctrl_vpn_dp_detach (u64 tunnel_id);
int tlsctrl_vpn_dp_touch_keepalive (u64 tunnel_id, int outbound);
int tlsctrl_vpn_dp_note_ipv4 (u64 tunnel_id, u32 bytes, int outbound);
int tlsctrl_vpn_dp_find_session (u64 tunnel_id, tlsctrl_vpn_dp_session_t **out);


typedef struct
{
  u64 tunnel_id;
  u8 type;
  u8 flags;
  u64 seq;
  u32 payload_len;
} tlsctrl_vpn_frame_meta_t;

int tlsctrl_vpn_frame_tx_keepalive (u64 tunnel_id, u8 **out_frame);
int tlsctrl_vpn_frame_tx_ipv4 (u64 tunnel_id, const u8 *payload, u32 payload_len, u8 **out_frame);
int tlsctrl_vpn_frame_rx (u64 tunnel_id, const u8 *frame, u32 frame_len, tlsctrl_vpn_frame_meta_t *meta, u8 **out_payload);


typedef struct
{
  u64 tunnel_id;
  u64 tx_packets;
  u64 rx_packets;
  u64 tx_drops;
  u64 rx_drops;
  u64 queue_depth;
  u64 last_error_code;
  u8 *tun_if_name;
  u8 *assigned_ip;
  u8 *gateway;
  u8 *dns_servers;
  u16 mtu;
  u16 mss_clamp;
  u8 running;
} tlsctrl_vpn_transport_session_t;

typedef struct
{
  tlsctrl_vpn_transport_session_t *sessions;
} tlsctrl_vpn_transport_main_t;

extern tlsctrl_vpn_transport_main_t tlsctrl_vpn_transport_main;

int tlsctrl_vpn_transport_attach (u64 tunnel_id, const char *tun_if_name);
int tlsctrl_vpn_transport_detach (u64 tunnel_id);
int tlsctrl_vpn_transport_note_packet (u64 tunnel_id, u32 bytes, int outbound);
int tlsctrl_vpn_transport_note_drop (u64 tunnel_id, u32 reason, int outbound);
int tlsctrl_vpn_transport_set_queue_depth (u64 tunnel_id, u32 depth);
int tlsctrl_vpn_transport_on_tunnel_close (u64 tunnel_id);
int tlsctrl_vpn_transport_find_session (u64 tunnel_id, tlsctrl_vpn_transport_session_t **out);
