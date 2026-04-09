Stage13 auto-hook scaffold

What this stage adds
- stage13_auto_hook_enabled flag in dataplane session
- auto_hook counters in show tlsctrl vpn dataplane
- tlsctrl vpn dataplane autohook tunnel-id <id> [enable|disable]
- IPv4 frame RX path can auto-synthesize an outgoing frame via tx_ipv4_from_vpp when stage13 autohook is enabled

What it is not yet
- not a true VPP graph output feature node
- not a real per-tunnel sw_if_index device
- not final end-to-end data plane
