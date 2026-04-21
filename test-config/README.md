# Тестовая конфигурация RADIUS + VPN профили

## Структура профилей

```
RADIUS группа     →  VPN профиль       Маршрутизация
─────────────────────────────────────────────────────────────────────
vpn-full          →  default           full-tunnel (весь трафик)
vpn-split         →  split-internal    10.0.0.0/8, 172.16/12, 192.168/16
vpn-restricted    →  restricted-host   ТОЛЬКО 192.17.0.5/32
vpn-admin         →  admin             full-tunnel, MTU 1500, без лимита
vpn-disabled      →  (заблокированы)  —
```

## Профиль restricted-host: только 192.17.0.5

```json
{
  "name":           "restricted-host",
  "full_tunnel":    false,
  "include_routes": "192.17.0.5/32",
  "pool_subnet":    "10.92.0.0/28"
}
```

Клиент получает IP из пула `10.92.0.0/28` (до 14 адресов).
Единственный маршрут, добавляемый в таблицу клиента: `192.17.0.5 via <VPN gateway>`.
Весь остальной трафик (включая интернет) идёт **напрямую**, минуя VPN.

## Быстрый старт

```bash
# 1. Применить тестовые данные в MySQL:
mysql -h 192.168.1.122 -u radius -p radius < freeradius/radius-users.sql

# 2. Или скопировать flat-file на RADIUS сервер:
scp freeradius/authorize ngfw@192.168.1.122:/etc/freeradius/3.0/mods-config/files/authorize
ssh ngfw@192.168.1.122 "sudo systemctl reload freeradius"

# 3. Настроить профили и маппинги через API:
cd api
AGENT=http://192.168.1.26:9080 RADIUS=http://192.168.1.26:9190 bash setup-api.sh
```

## Тестовые пользователи

| Пользователь | Пароль            | Группа          | Профиль          | Доступ                       |
|---|---|---|---|---|
| alice        | alice-pass-2024   | vpn-full        | default          | Весь трафик через VPN        |
| bob          | bob-pass-2024     | vpn-split       | split-internal   | 10/8, 172.16/12, 192.168/16  |
| charlie      | charlie-pass-2024 | vpn-restricted  | restricted-host  | **Только 192.17.0.5**        |
| diana        | diana-pass-2024   | vpn-admin       | admin            | Весь трафик, без лимитов     |
| eve          | —                 | vpn-disabled    | (отказ)          | Заблокирован                 |
| frank        | frank-pass-2024   | vpn-split       | split-internal   | Внутренняя сеть, 8ч          |
| guest        | guest-temp-2024   | vpn-restricted  | restricted-host  | Только 192.17.0.5, 1ч        |

## Проверка через radius-agent API

```bash
RADIUS=http://192.168.1.26:9190

# Проверить разрешение пользователя charlie
curl "$RADIUS/api/admin/radius/resolve?source_id=fr-mysql-main&username=charlie"
# Ожидаемый ответ:
# { "vpn_profile": "restricted-host", "groups": ["vpn-restricted"], ... }

# Список пользователей из источника
curl "$RADIUS/api/admin/radius/sources/fr-mysql-main/users"

# Ручной sync источника
curl -X POST "$RADIUS/api/admin/radius/sources/fr-mysql-main/sync"
```

## Проверка клиентом charlie (restricted-host)

После подключения charlie должен видеть в routing table только один VPN маршрут:

```
# Linux
ip route show | grep tun
# Ожидается: 192.17.0.5 via 10.92.0.1 dev tun0

# Windows
route print | findstr 192.17
# Ожидается: 192.17.0.5    255.255.255.255    10.92.0.1    ...

# macOS
netstat -rn | grep 192.17
# Ожидается: 192.17.0.5/32  10.92.0.1  UGSc  utun3
```

Ping 8.8.8.8 (интернет) должен идти **не** через VPN и работать в обычном режиме.
Ping 192.17.0.5 должен работать через VPN-туннель.
Ping 192.17.0.6 должен быть недоступен (нет маршрута через VPN).

## Политики приложений

| Политика                   | Профили                                | Что блокирует                     |
|---|---|---|
| deny-vpn-in-vpn            | restricted-host, split-internal        | VPN-клиенты (wg, openvpn, ...)    |
| deny-remote-for-restricted | restricted-host                        | RDP, AnyDesk, TeamViewer, ...     |
