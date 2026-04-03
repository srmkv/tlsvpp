# TLS Client Native v12

Полноценный desktop-клиент на Go/Fyne с сохранением прежнего UI.

Что умеет сейчас:
- загрузка `bundle.zip`
- чтение `metadata.json` (`username`, `profile`, `server_url`, `server_name`)
- mTLS подключение к VPP plugin
- `POST /api/client/vpn-bind`
- удержание локального connected state в UI
- ручное отключение клиента
- раздел `Приложения` оставлен как в прошлой версии
- bundle/сертификаты сохраняются в config dir пользователя

Схема:
client -> vpp plugin -> go agent -> web ui admin

Важно:
- этот клиент уже работает как UI-клиент для `vpn-bind`
- framed traffic/TUN-path зависит от следующего шага в plugin
- UI сохранён максимально близко к прежнему варианту

Сборка:
```bash
cd tlsclient-ready-full-v12
go mod tidy
go build -o bin/tlsclient ./cmd/tlsclient
```

Запуск:
```bash
./bin/tlsclient
```
