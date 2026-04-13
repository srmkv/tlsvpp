Stage31b full-duplex owner-worker datapath

Changes:
- client attempts GET /api/client/vpn-stream after vpn-bind
- on success, datapath uses one full-duplex raw TLS stream
- if vpn-stream is unavailable, client falls back to legacy vpn-frame/vpn-poll mode

Binary stream format:
- u32 little-endian frame length
- frame bytes (existing VPN frame payload)
