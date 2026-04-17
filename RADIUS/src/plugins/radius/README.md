# radius for VPP

Отдельный сервисный VPP plugin для RADIUS AAA без участия Linux host stack в auth path.

## Что внутри
- `radius.api` — binary API для конфигурации/статистики/test-auth
- `radius.c` — main/plugin init/consumer registry/high-level auth entry points
- `radius_api.c` — handlers для binary API
- `radius_cli.c` — CLI команды `show radius`, `radius test-auth`, `radius server add`
- `radius_codec.*` — кодек RADIUS и PAP password obfuscation
- `radius_pending.*` — pending request table
- `radius_transport.*` — VPP-native packet builder / tx scaffold
- `radius_service.h` — внутренний service API для consumer plugins (`tlsctrl`, другие)
- `CMakeLists.txt` — минимальное подключение в дерево VPP

## Важно честно
Этот bundle собран как **готовый source-level plugin skeleton** для интеграции в ваше дерево VPP.
Без вашего точного дерева/версии VPP я не могу честно гарантировать 100% compile-clean состояние под конкретные header/API, поэтому transport path и API registration сделаны максимально близко к типовой схеме VPP, но могут потребовать точечной адаптации под вашу версию.

## Предполагаемый layout
Скопировать каталог как:

```text
vpp/src/plugins/radius/
```

## Дальше в дереве VPP
1. Подключить plugin в build системы VPP.
2. Запустить `make build`.
3. При необходимости поправить include/macros под вашу точную ветку VPP.

## CLI
После загрузки plugin:

```text
radius server add name corp ip 192.17.0.10 secret testing123 src 192.17.0.1 fib 0 port 1812 timeout 5 retries 1
show radius
radius test-auth provider corp username vpnuser password vpnpass123
```

## Архитектура
- `radius` — общий AAA сервис
- consumer plugins регистрируются через `radius_register_consumer()` и получают async результат в callback
- `radius-agent` должен ходить в plugin через GovPP/binary API и не участвовать в packet path

## Следующий этап
После встройки в ваше дерево логично сразу добивать:
- реальный RX node для ответов по UDP dst port
- полноценный `Access-Challenge` flow
- accounting start/stop/interim
- agent bundle с Go GovPP bindings


## Notes for branch compatibility
- In this revision the UDP includes are normalized to `vnet/udp/udp.h` and `vnet/udp/udp_packet.h`, which matches current VPP tree layout.

- `radius_input.c` — UDP reply node для RADIUS response path

- `radius_md5.c/.h` — self-contained MD5 for RFC2865 PAP `User-Password` encoding

This revision switches `User-Password` from scaffold XOR to real RFC2865 PAP encoding.

- `show radius` now prints last_result/provider/username/reply for easier debugging

- `radius server add` updates existing provider by name instead of silently duplicating it


## v16 fixes
- string AVPs are encoded without trailing NUL
- PAP User-Password obfuscation uses explicit lengths for username/password/secret/nas_id
- provider secret and NAS-ID are treated as fixed C strings, not VPP vecs
- Access-Request now includes Message-Authenticator (attr 80)

## v17 response attributes
- response decoder now extracts Filter-Id, Session-Timeout, Idle-Timeout and State
- `show radius` prints the last accepted/rejected response attributes
- internal `radius_auth_res_t` now carries these attributes to consumers

## v18 packaging fix
- corrected archive content: updated radius_cli.c is included and `show radius` now prints filter_id/session_timeout/idle_timeout/state_len
