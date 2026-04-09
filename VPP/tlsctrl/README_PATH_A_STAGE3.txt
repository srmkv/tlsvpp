TLSCTRL Path A / Stage 3 scaffold

What is included:
- per-tunnel dataplane runtime metadata in tlsctrl_vpn_dp_session_t
- explicit VIP/gateway/user/profile tracking in dataplane sessions
- CLI:
  * show tlsctrl vpn dataplane
  * show tlsctrl vpn routes
- tunnel_open now configures dataplane metadata from assigned lease/profile
- app/session attach now syncs session_handle into dataplane state
- transport queue depth / drop reason are mirrored into dataplane session

What is NOT yet implemented in this patch:
- real VPP sw_if_index creation per tunnel
- ip4-input injection for client RX payload
- FIB / adjacency programming for VIP host routes
- reverse TX path VPP -> tunnel

This patch is the compile-safe skeleton for Path A, not the final forwarding implementation.
