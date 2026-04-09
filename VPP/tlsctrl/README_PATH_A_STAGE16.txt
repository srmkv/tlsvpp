stage16 adds a real automatic reverse delivery hook for packets destined to an active VPN VIP.

What changed:
- new VPP node/feature: tlsctrl-vpn-stage16
- feature is inserted on ip4-unicast before ip4-lookup
- for inbound IPv4 packets whose dst matches an active VPN VIP:
  - resolve VIP -> tunnel
  - build VPN IPv4 frame
  - enqueue frame to per-user pending queue
  - consume original packet inside VPP
- txlookup/txinj/txf/txb now grow from real automatic reverse interception instead of manual autobridge-only scaffolding

Notes:
- chained buffers are currently skipped and continue on normal path
- feature auto-enables on all current software interfaces at init/attach/configure time
