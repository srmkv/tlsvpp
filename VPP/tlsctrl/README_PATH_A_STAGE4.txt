Path A stage4 patch

What this patch adds:
- explicit vip->tunnel lookup helper in dataplane session table
- RX IPv4 inject helper: tlsctrl_vpn_dp_rx_ipv4_to_vpp()
- frame RX now attempts to enqueue IPv4 payload into VPP ip4-input
- tunnel_open now configures dataplane metadata (VIP/gateway/user/profile)
- transport queue/drop is mirrored into dataplane state

What is still NOT finished:
- per-tunnel sw_if_index creation is still placeholder (sw_if_index defaults to ~0)
- VIP /32 FIB programming is not yet implemented
- TX path (VPP -> tunnel/client) is not implemented yet
- RX inject is best-effort skeleton and needs real sw_if_index/adjacency wiring

Use this patch as the next step after stage3 scaffold.
