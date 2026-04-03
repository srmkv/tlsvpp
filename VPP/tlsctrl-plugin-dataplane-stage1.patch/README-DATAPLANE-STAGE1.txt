This patch adds a first-stage external dataplane glue for tlsctrl VPN.

What it changes:
- Fixes vpn profile string storage to be 0-terminated.
- Attaches a transport session on /api/client/vpn-bind.
- Adds per-tunnel TX/RX frame queues in transport sessions.
- Adds client HTTP endpoints:
  POST /api/client/vpn-frame      {username,tunnel_id,frame_hex}
  GET  /api/client/vpn-poll?tunnel_id=...&username=...
  POST /api/client/vpn-keepalive  {username,tunnel_id}

What it does NOT yet do:
- inject IPv4 payloads into a real VPP interface path
- create a WireGuard-like VPP software interface
- provide a complete bidirectional packet pump on its own

This is a stage-1 patch to expose the existing frame layer externally so the client
can start using a concrete transport protocol instead of bind-only mode.
