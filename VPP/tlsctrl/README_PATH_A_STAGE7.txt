PATH A STAGE7

Adds output-path scaffolding counters and hook-armed state.
This is not final TX forwarding yet.

New dataplane fields:
- tx_hook_armed
- tx_lookup_hits
- tx_lookup_misses

New helpers:
- tlsctrl_vpn_dp_stage7_arm_output()
- tlsctrl_vpn_dp_stage7_note_lookup()

Expected CLI additions:
- show tlsctrl vpn dataplane now prints txhook and txlookup counters.
