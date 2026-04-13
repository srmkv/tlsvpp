TLS Client v27 — reconnect/resume

Что добавлено:
- после 3 подряд ошибок heartbeat клиент не уходит сразу в hard disconnect
- запускается автовосстановление transport/runtime
- reconnect делает локальный teardown без connect_intent=disconnect
- затем выполняется новый vpn-bind
- при успехе UI возвращается в connected и обновляет tunnel_id

Изменённые файлы:
- internal/client/api.go
- internal/app/actions.go
- internal/app/ui.go

Ожидаемые записи в журнале:
- Проблема связи с VPN plugin: ...
- Потеряна связь с VPN plugin, запускаю автовосстановление
- Соединение с VPN plugin восстановлено, tunnel_id=...
