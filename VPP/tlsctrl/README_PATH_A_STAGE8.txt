Stage8 (path A):
- added stage8_output_enabled flag and tx probe counters
- added tlsctrl_vpn_dp_stage8_probe_ip4_packet() to resolve VIP -> tunnel and build outgoing frame
- added CLI: tlsctrl vpn dataplane probe-tx [vip <ip>|tunnel-id <id>] [bytes <n>]
- CLI now shows txprobe and txlookup counters

This is still scaffolding: it exercises VIP lookup + frame generation, but it does not yet hook the packet into a real VPP output feature/node.
