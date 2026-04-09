PATH A stage6 scaffold

What is added:
- fixed NUL-terminated dataplane if_name strings (tlsvpn-<id>)
- stage6 reconcile helper to keep route_bound/tx_ready identity in sync
- tx helper by VIP: tlsctrl_vpn_dp_tx_ipv4_by_vip()
- stage5 scaffolding remains intact, plus policy-bootstrap endpoints from merged patch

What is still NOT done:
- no real VPP-created per-tunnel interface yet
- no real FIB programming of VIP /32 yet
- no output node/feature hook from VPP graph into plugin transport yet

Goal of this stage:
- clean up runtime state before stage7 output-hook work
- make CLI/runtime less ambiguous (if names, route/tx readiness)
