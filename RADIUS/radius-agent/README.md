# radius-agent SQL-first scaffold

Стартовый каркас отдельного `radius-agent` для импорта пользователей и политик из FreeRADIUS SQL backend.

## Что уже есть
- YAML config
- SQLite store
- FreeRADIUS SQL adapter
- snapshot import
- HTTP admin API
- basic resolver
- background sync scheduler

## Что специально оставлено простым
- нет write-back в FreeRADIUS
- нет auth challenge orchestration
- нет UI
- `integration/controlplane` пока заглушка

## Быстрый старт
```bash
cp configs/radius-agent.example.yaml /etc/radius-agent.yaml
export RADIUS_AGENT_CONFIG=/etc/radius-agent.yaml
go mod tidy
go build ./cmd/radius-agent
./radius-agent
```

## Основные endpoint'ы
- `GET /healthz`
- `GET /api/admin/radius/sources`
- `POST /api/admin/radius/sources`
- `POST /api/admin/radius/sources/{id}/sync`
- `GET /api/admin/radius/sources/{id}/users`
- `GET /api/admin/radius/sources/{id}/groups`
- `GET /api/admin/radius/mappings/groups`
- `POST /api/admin/radius/mappings/groups`
- `GET /api/admin/radius/mappings/attrs`
- `POST /api/admin/radius/mappings/attrs`
- `GET /api/admin/radius/resolve?source_id=...&username=...`

## Замечание
Этот каркас ориентирован на `radcheck`, `radreply`, `radgroupcheck`, `radgroupreply`, `radusergroup`.


## Toolchain note
The scaffold targets Go 1.21+ to avoid automatic Go 1.24 toolchain download on locked-down systems.


## Driver detection
`freeradius_sql` now selects DB driver by DSN: MySQL, PostgreSQL (lib/pq) or SQLite.
