Что исправлено
- после успешного /api/client/vpn-bind клиент теперь применяет Linux runtime:
  - создает интерфейс tlsvpn0
  - назначает assigned_ip
  - поднимает link
  - выставляет mtu
  - добавляет include-routes
  - при full_tunnel ставит default route через tlsvpn0
  - пытается прописать DNS через resolvectl
- monitor loop теперь реально шлет heartbeat на /api/client/heartbeat по mTLS, а не только обновляет локальное состояние
- при disconnect runtime откатывается: интерфейс удаляется, адреса и маршруты очищаются

Важно
- для применения runtime нужны root/CAP_NET_ADMIN
- это исправляет клиентскую сторону после bind, но не заменяет полноценный data-plane протокол.
- в текущем plugin tunnel/session runtime уже создается, но если в plugin не реализован реальный transport attach / передача IPv4 кадров от клиента, одних маршрутов ОС может быть недостаточно для роста vpn dataplane counters.
