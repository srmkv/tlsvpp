Path A stage5 patch

What this patch adds:
- frame RX now actually calls tlsctrl_vpn_dp_rx_ipv4_to_vpp() for IPv4 payloads
- stage5 identity scaffold per tunnel:
  - if_name (tlsvpn-<tunnel_id>)
  - sw_if_index/fib_index placeholders populated early
  - route_bound/tx_ready flags
- tunnel_open now marks dataplane identity as bound and route-owned in plugin state
- TX dataplane scaffold helper:
  - tlsctrl_vpn_dp_tx_ipv4_from_vpp()
  - records tx inject counters and wraps packet into VPN frame
- dataplane CLI extended with if_name, route flags, tx inject counters

What is still NOT finished:
- sw_if_index is still a plugin-owned placeholder, not a real VPP-created interface
- VIP /32 is still not programmed into the real FIB/adjacency tables
- tx path is still a callable helper, but not wired into a VPP output node/feature yet
- actual transport send of VPP-originated packets still needs wiring to session TX

Use this patch as the next step after stage4 RX inject skeleton.
