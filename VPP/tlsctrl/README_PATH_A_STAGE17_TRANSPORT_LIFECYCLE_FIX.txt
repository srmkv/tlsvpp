STAGE17 transport lifecycle counters fix

What changed:
- transport tunnel-open path now creates/refreshes transport session automatically
- transport lifecycle counters are synchronized from dataplane lifecycle state
- transport close path now ensures a session exists before accounting close
- show tlsctrl vpn transport prints lifecycle counters from dataplane when available

Expected result:
- show tlsctrl vpn transport and show tlsctrl vpn dataplane report matching gen/open/close/reset values
- close counter is visible after real tunnel teardown/reconnect instead of staying at 0
