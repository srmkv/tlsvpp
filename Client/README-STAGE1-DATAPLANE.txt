Клиент переведён на stage-1 dataplane transport plugin.

Что изменено:
- после vpn-bind поднимается Linux TUN tlsvpn0 через /dev/net/tun
- bind отправляет реальный client_ip
- добавлен packet pump:
  - tun -> POST /api/client/vpn-frame
  - GET /api/client/vpn-poll -> tun
  - keepalive отправляется как локальный frame через /api/client/vpn-frame
- heartbeat в /api/client/heartbeat сохранён
- для запуска нужны root или CAP_NET_ADMIN

Важно:
- этот клиент рассчитан на plugin с patch stage1 dataplane endpoints
- для сборки нужен ваш обычный fyne toolchain
