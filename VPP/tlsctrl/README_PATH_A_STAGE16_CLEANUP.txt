Path-A stage16 cleanup/hardening

What changed
- dataplane CLI headline now shows path-a real txlookup instead of scaffold
- route ownership CLI headline now matches the real txlookup path
- txlookup counters now print hit/miss/drop
- reverse delivery failures after VIP match increment tx_lookup_drops
- stage13 legacy autohook remains debug-only and stays disabled by default

Expected CLI shape
- show tlsctrl vpn dataplane
  txlookup=<hits>/<misses>/<drops>

Expected steady state
- stage13=0
- autohook=0/0
- txlookup hits grow on real replies
- drop counter stays 0 during normal ping/traffic
