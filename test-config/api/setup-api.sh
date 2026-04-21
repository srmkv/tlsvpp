#!/bin/bash
# Настройка тестовой конфигурации VPN-профилей и RADIUS маппингов
# Запускать после старта tlsagent и radius-agent
#
# Использование:
#   chmod +x setup-api.sh
#   AGENT=http://192.168.1.26:9080 RADIUS=http://192.168.1.26:9190 ./setup-api.sh

set -euo pipefail

AGENT="${AGENT:-http://127.0.0.1:9080}"
RADIUS="${RADIUS:-http://127.0.0.1:9190}"

info()    { echo "  ✓ $*"; }
section() { echo ""; echo "═══ $* ═══"; }
fail()    { echo "  ✗ $*" >&2; }

# ═══════════════════════════════════════════════════════════════════════════
section "1. VPN профили в tlsagent (POST $AGENT/api/admin/profiles)"
# ═══════════════════════════════════════════════════════════════════════════

# Профиль: default — full-tunnel, весь трафик
curl -sf -X POST "$AGENT/api/admin/profiles" \
  -H "Content-Type: application/json" \
  -d '{
    "name":          "default",
    "pool_name":     "pool-full",
    "pool_subnet":   "10.90.0.0/24",
    "pool_gateway":  "10.90.0.1",
    "lease_seconds": 86400,
    "full_tunnel":   true,
    "dns_servers":   "8.8.8.8,1.1.1.1",
    "include_routes": "",
    "exclude_routes": "",
    "mtu":           1400,
    "mss_clamp":     1360,
    "note":          "Full-tunnel: весь трафик через VPN"
  }' | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('ok') else d)"
info "Профиль 'default' (full-tunnel)"

# Профиль: split-internal — только внутренняя сеть 10.0.0.0/8
curl -sf -X POST "$AGENT/api/admin/profiles" \
  -H "Content-Type: application/json" \
  -d '{
    "name":          "split-internal",
    "pool_name":     "pool-split",
    "pool_subnet":   "10.91.0.0/24",
    "pool_gateway":  "10.91.0.1",
    "lease_seconds": 28800,
    "full_tunnel":   false,
    "dns_servers":   "10.0.0.1,8.8.8.8",
    "include_routes": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
    "exclude_routes": "",
    "mtu":           1400,
    "mss_clamp":     1360,
    "note":          "Split-tunnel: только RFC-1918 через VPN"
  }' | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('ok') else d)"
info "Профиль 'split-internal' (split-tunnel: 10/8, 172.16/12, 192.168/16)"

# Профиль: restricted-host — ТОЛЬКО 192.17.0.5/32
curl -sf -X POST "$AGENT/api/admin/profiles" \
  -H "Content-Type: application/json" \
  -d '{
    "name":          "restricted-host",
    "pool_name":     "pool-restricted",
    "pool_subnet":   "10.92.0.0/28",
    "pool_gateway":  "10.92.0.1",
    "lease_seconds": 14400,
    "full_tunnel":   false,
    "dns_servers":   "",
    "include_routes": "192.17.0.5/32",
    "exclude_routes": "",
    "mtu":           1400,
    "mss_clamp":     1360,
    "note":          "Restricted: доступ только к 192.17.0.5"
  }' | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('ok') else d)"
info "Профиль 'restricted-host' (include_routes: 192.17.0.5/32 ONLY)"

# Профиль: admin — full-tunnel, без таймаутов
curl -sf -X POST "$AGENT/api/admin/profiles" \
  -H "Content-Type: application/json" \
  -d '{
    "name":          "admin",
    "pool_name":     "pool-admin",
    "pool_subnet":   "10.93.0.0/28",
    "pool_gateway":  "10.93.0.1",
    "lease_seconds": 0,
    "full_tunnel":   true,
    "dns_servers":   "10.0.0.1,8.8.8.8,1.1.1.1",
    "include_routes": "",
    "exclude_routes": "",
    "mtu":           1500,
    "mss_clamp":     1460,
    "note":          "Admin: full-tunnel, без лимита аренды, повышенный MTU"
  }' | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('ok') else d)"
info "Профиль 'admin' (full-tunnel, MTU 1500, lease unlimited)"

# Проверяем результат
echo ""
echo "Текущие профили:"
curl -sf "$AGENT/api/admin/profiles" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for p in data.get('profiles', []):
    ft = 'full' if p.get('full_tunnel') else 'split'
    inc = p.get('include_routes','') or '(весь трафик)'
    print(f\"  {p['name']:20s} {ft:5s}  routes={inc}  pool={p.get('pool_subnet','')}\")
"

# ═══════════════════════════════════════════════════════════════════════════
section "2. Источник FreeRADIUS в radius-agent (POST $RADIUS/api/admin/radius/sources)"
# ═══════════════════════════════════════════════════════════════════════════
# Раскомментируйте нужный вариант:

# Вариант A: flat file через SSH
# curl -sf -X POST "$RADIUS/api/admin/radius/sources" \
#   -H "Content-Type: application/json" \
#   -d '{
#     "id":             "fr-files-main",
#     "name":           "FreeRADIUS files (SSH)",
#     "type":           "freeradius_files",
#     "enabled":        true,
#     "dsn":            "ssh://ngfw@192.168.1.122/etc/freeradius/3.0/mods-config/files/authorize",
#     "sync_every_sec": 120
#   }'

# Вариант B: MySQL
# curl -sf -X POST "$RADIUS/api/admin/radius/sources" \
#   -H "Content-Type: application/json" \
#   -d '{
#     "id":             "fr-mysql-main",
#     "name":           "FreeRADIUS MySQL",
#     "type":           "freeradius_sql",
#     "enabled":        true,
#     "dsn":            "radius:radius-pass@tcp(192.168.1.122:3306)/radius",
#     "sync_every_sec": 60
#   }'

info "Источники: настройте DSN вручную или раскомментируйте строки выше"

# ═══════════════════════════════════════════════════════════════════════════
section "3. Маппинг RADIUS групп → VPN профили в radius-agent"
# (POST $RADIUS/api/admin/radius/mappings/groups)
# ═══════════════════════════════════════════════════════════════════════════

curl -sf -X POST "$RADIUS/api/admin/radius/mappings/groups" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "group_name":  "vpn-full",
      "vpn_profile": "default",
      "policy_set":  "",
      "trust_level": "",
      "enabled":     true
    },
    {
      "group_name":  "vpn-split",
      "vpn_profile": "split-internal",
      "policy_set":  "",
      "trust_level": "",
      "enabled":     true
    },
    {
      "group_name":  "vpn-restricted",
      "vpn_profile": "restricted-host",
      "policy_set":  "",
      "trust_level": "",
      "enabled":     true
    },
    {
      "group_name":  "vpn-admin",
      "vpn_profile": "admin",
      "policy_set":  "",
      "trust_level": "",
      "enabled":     true
    },
    {
      "group_name":  "vpn-disabled",
      "vpn_profile": "",
      "policy_set":  "",
      "trust_level": "",
      "enabled":     false
    }
  ]' | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('ok') else d)"
info "Маппинги групп сохранены"

echo ""
echo "Текущие маппинги:"
curl -sf "$RADIUS/api/admin/radius/mappings/groups" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for m in data.get('items', []):
    status = '✓' if m.get('enabled') else '✗'
    print(f\"  {status} {m['group_name']:20s} → {m.get('vpn_profile','(заблокирован)'):20s}\")
"

# ═══════════════════════════════════════════════════════════════════════════
section "4. Политики приложений в tlsagent"
# ═══════════════════════════════════════════════════════════════════════════

# Политика: запрет VPN-туннелей внутри VPN (для restricted-host пользователей)
curl -sf -X POST "$AGENT/api/admin/app-policies" \
  -H "Content-Type: application/json" \
  -d '{
    "id":             "deny-vpn-in-vpn",
    "name":           "Запрет VPN-клиентов внутри туннеля",
    "enabled":        true,
    "mode":           "deny_on_match",
    "check_on_client": true,
    "check_on_server": false,
    "message":        "Использование VPN-клиентов запрещено",
    "patterns": [
      {"type": "contains", "value": "openvpn"},
      {"type": "contains", "value": "wireguard"},
      {"type": "contains", "value": "wg"},
      {"type": "contains", "value": "vpn"},
      {"type": "contains", "value": "anyconnect"},
      {"type": "contains", "value": "tailscale"},
      {"type": "contains", "value": "zerotier"}
    ],
    "scope": {
      "all_users":  false,
      "profiles":   ["restricted-host", "split-internal"],
      "users":      []
    }
  }' | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('ok') else d)"
info "Политика 'deny-vpn-in-vpn' (для restricted-host, split-internal)"

# Политика: запрет удалённого доступа для restricted пользователей
curl -sf -X POST "$AGENT/api/admin/app-policies" \
  -H "Content-Type: application/json" \
  -d '{
    "id":             "deny-remote-for-restricted",
    "name":           "Запрет RDP/SSH для ограниченного доступа",
    "enabled":        true,
    "mode":           "deny_on_match",
    "check_on_client": true,
    "check_on_server": true,
    "message":        "Удалённый доступ ограничен",
    "patterns": [
      {"type": "contains", "value": "anydesk"},
      {"type": "contains", "value": "teamviewer"},
      {"type": "contains", "value": "rustdesk"},
      {"type": "contains", "value": "mstsc"},
      {"type": "contains", "value": "rdp"}
    ],
    "scope": {
      "all_users":  false,
      "profiles":   ["restricted-host"],
      "users":      []
    }
  }' | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('ok') else d)"
info "Политика 'deny-remote-for-restricted' (только restricted-host)"

# ═══════════════════════════════════════════════════════════════════════════
section "5. Sync VPN профилей в VPP plugin"
# ═══════════════════════════════════════════════════════════════════════════

curl -sf -X POST "$AGENT/api/admin/plugin/sync-vpn" \
  -H "Content-Type: application/json" \
  -d '{}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('ok') else d)"
info "Профили синхронизированы в VPP"

# ═══════════════════════════════════════════════════════════════════════════
section "Итог"
# ═══════════════════════════════════════════════════════════════════════════
echo "
Профили VPN:
  default          full-tunnel  весь трафик          pool: 10.90.0.0/24
  split-internal   split        10.0.0.0/8 и др.     pool: 10.91.0.0/24
  restricted-host  split        ТОЛЬКО 192.17.0.5/32  pool: 10.92.0.0/28
  admin            full-tunnel  без лимитов           pool: 10.93.0.0/28

Маппинги RADIUS групп:
  vpn-full        → default
  vpn-split       → split-internal
  vpn-restricted  → restricted-host  ← доступ только к 192.17.0.5
  vpn-admin       → admin
  vpn-disabled    → (заблокированы)

Тестовые пользователи (пароль см. в authorize / SQL):
  alice   → vpn-full       → default
  bob     → vpn-split      → split-internal
  charlie → vpn-restricted → restricted-host  (только 192.17.0.5)
  diana   → vpn-admin      → admin
  eve     → vpn-disabled   → отказ
  frank   → vpn-split      → split-internal (8ч, 2FA)
  guest   → vpn-restricted → restricted-host (1ч)

Проверить профиль конкретного пользователя:
  curl $RADIUS/api/admin/radius/resolve?source_id=<id>&username=charlie
"
