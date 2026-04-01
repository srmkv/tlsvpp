# TLSCTRL Agent — admin only, GovPP-ready

Правильная архитектура:

## Agent
- хранит пользователей
- выпускает / перевыпускает сертификаты
- отдаёт bundle.zip
- через GovPP загружает состояние в VPP plugin:
  - username
  - cert serial
  - enabled/disabled
- даёт только admin API на `:9080`

## VPP plugin
- сам принимает клиентское подключение на `:9443`
- сам видит реальный peer IP
- сам валидирует клиента
- сам ведёт:
  - sessions
  - disconnect
  - commands
  - apps_count
  - last_seen
  - peer_ip
  - connected/disconnected

## Client
- ходит напрямую в plugin endpoint из `metadata.json`
- agent в клиентский трафик не вмешивается

## Важно
В этом архиве **на agent нет `/api/client/*` listener**.
Client mTLS traffic должен завершаться в VPP plugin.

## Build GovPP
1. Сгенерировать binapi:
   `~/bin/binapi-generator --input=/home/ngfw/vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api --output-dir=internal/vppbinapi`
2. Собрать:
   `go mod tidy`
   `go build -tags govpp -o bin/tlsctrl-agent ./cmd/tlsctrl-agent`

## Run
```bash
GOTOOLCHAIN=local TLSCTRL_ADMIN_LISTEN_ADDR=:9080 TLSCTRL_BACKEND=govpp TLSCTRL_REQUIRE_VPP=true TLSCTRL_VPP_API_SOCKET=/run/vpp/api.sock TLSCTRL_DATA_DIR=./agent-data TLSCTRL_PUBLIC_HOST=192.168.1.17 ./bin/tlsctrl-agent
```

## Web / client
С этим agent совместимы:
- web: `tlsctrl-web-vpp-bundle-settings-v4`
- client: `tlsclient-ready-full-v12`

При условии, что VPP plugin реализует клиентские endpoints на `:9443`.
