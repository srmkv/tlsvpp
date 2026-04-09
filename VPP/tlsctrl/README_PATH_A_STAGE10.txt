Path A stage10 scaffold

- adds stage10 bridge flag and autoprobe counters
- adds tlsctrl_vpn_dp_stage10_enable_bridge()
- adds tlsctrl_vpn_dp_stage10_autoprobe() to exercise RX+TX in one command
- adds CLI: tlsctrl vpn dataplane autoprobe tunnel-id <id> [dst <ip>] [bytes <n>]

This is still a scaffold: no real VPP graph hook yet.
