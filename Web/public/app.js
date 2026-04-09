const byId = (id) => document.getElementById(id);
let users = [];
let sessions = [];
let profiles = [];
let appPolicies = [];
let healthData = null;

const POLICY_PRESETS = [
  { id:'vpn_tools', title:'VPN / туннели', meta:'OpenVPN, WireGuard, Forti, AnyConnect, GlobalProtect, WARP', patterns:[
    {type:'contains',value:'vpn'},{type:'contains',value:'openvpn'},{type:'contains',value:'wireguard'},{type:'contains',value:'wg'},{type:'contains',value:'forticlient'},{type:'contains',value:'fortivpn'},{type:'contains',value:'anyconnect'},{type:'contains',value:'globalprotect'},{type:'contains',value:'pulse secure'},{type:'contains',value:'juniper secure connect'},{type:'contains',value:'tailscale'},{type:'contains',value:'zerotier'},{type:'contains',value:'outline'},{type:'contains',value:'amnezia'},{type:'contains',value:'warp'} ] },
  { id:'messengers', title:'Мессенджеры', meta:'Mattermost, Telegram, WhatsApp, Discord, Slack', patterns:[
    {type:'contains',value:'mattermost'},{type:'contains',value:'telegram'},{type:'contains',value:'whatsapp'},{type:'contains',value:'discord'},{type:'contains',value:'slack'} ] },
  { id:'remote_admin', title:'Удалённый доступ', meta:'AnyDesk, TeamViewer, RustDesk, Radmin, mstsc, PuTTY', patterns:[
    {type:'contains',value:'anydesk'},{type:'contains',value:'teamviewer'},{type:'contains',value:'rustdesk'},{type:'contains',value:'radmin'},{type:'contains',value:'mstsc'},{type:'contains',value:'putty'},{type:'contains',value:'ssh'} ] },
  { id:'proxy_tools', title:'Прокси / обход', meta:'Proxy, Psiphon, Lantern, v2ray, clash', patterns:[
    {type:'contains',value:'proxy'},{type:'contains',value:'psiphon'},{type:'contains',value:'lantern'},{type:'contains',value:'v2ray'},{type:'contains',value:'clash'} ] }
];

function detectDefaultApiBase() {
  try {
    const proto = (location.protocol === 'https:' ? 'https:' : 'http:');
    const host = location.hostname || '';
    if (!host || host === 'localhost' || host === '127.0.0.1') return 'http://127.0.0.1:9080';
    return proto + '//' + host + ':9080';
  } catch {
    return 'http://127.0.0.1:9080';
  }
}
function resolveInitialApiBase() {
  const detected = detectDefaultApiBase();
  try {
    const saved = (localStorage.getItem('tlsctrl_api_base') || '').trim();
    const currentHost = location.hostname || '';
    const currentIsRemote = !!currentHost && currentHost !== 'localhost' && currentHost !== '127.0.0.1';
    if (!saved) return detected;
    if (currentIsRemote && /^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/i.test(saved)) return detected;
    return saved;
  } catch {
    return detected;
  }
}

let API_BASE = resolveInitialApiBase();
let appsPollTimer = null;
let appsState = { username: '', pending: false, report: null };
const HISTORY_KEY = 'tlsctrl_session_history_v10';
const DISCONNECT_REASON_KEY = 'tlsctrl_disconnect_reason_v10';

function loadJSON(key, fallback) { try { const raw = localStorage.getItem(key); return raw ? JSON.parse(raw) : fallback; } catch { return fallback; } }
function saveJSON(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch {} }
function getHistoryStore() { return loadJSON(HISTORY_KEY, {}); }
function setHistoryStore(value) { saveJSON(HISTORY_KEY, value); }
function getReasonStore() { return loadJSON(DISCONNECT_REASON_KEY, {}); }
function setReasonStore(value) { saveJSON(DISCONNECT_REASON_KEY, value); }

function syncApiBaseUI() {
  if (byId('apiBase')) byId('apiBase').value = API_BASE;
  if (byId('apiBaseText')) byId('apiBaseText').textContent = API_BASE;
}
function esc(v) {
  return String(v ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
function fmtDate(v) {
  if (!v) return '—';
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? String(v) : d.toLocaleString();
}
function normalizeBase(v) { return (v || '').trim().replace(/\/+$/, ''); }
function splitCSV(v) { return String(v || '').split(',').map(x => x.trim()).filter(Boolean); }
function csvString(v) { return Array.isArray(v) ? v.join(', ') : (v || ''); }
function escapeRegex(v) { return String(v ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function numOrZero(v) { const n = parseInt(String(v || '').trim(), 10); return Number.isFinite(n) ? n : 0; }
function formatInterfaces(interfaces) {
  if (!Array.isArray(interfaces) || !interfaces.length) return '—';
  return interfaces.map((iface) => {
    const name = iface?.name || 'iface';
    const mtu = iface?.mtu ?? '—';
    const mac = iface?.mac || '—';
    const flags = Array.isArray(iface?.flags) && iface.flags.length ? iface.flags.join(',') : '—';
    const addrs = Array.isArray(iface?.addresses) && iface.addresses.length ? iface.addresses.join('\n  ') : '—';
    return `${name}: mtu ${mtu} mac ${mac} flags ${flags}\n  ${addrs}`;
  }).join('\n\n');
}
function pill(kind, text) {
  const cls = kind === 'ok' ? 'pillOk' : kind === 'warn' ? 'pillWarn' : kind === 'info' ? 'pillInfo' : kind === 'mute' ? 'pillMute' : 'pillBad';
  return `<span class="pill ${cls}">${esc(text)}</span>`;
}
function stateIcon(kind, label, title) { return `<span class="stateDot ${kind}" title="${esc(title || label)}">${esc(label)}</span>`; }
function accountBadge(row) { return row.enabled ? stateIcon('stateOn', '✓', 'Учётка включена') : stateIcon('stateBad', '×', 'Учётка выключена'); }
function sessionBadge(row) {
  if (row.connected) return stateIcon('stateOn', 'A', 'Agent session активна');
  if (row.policy_blocked) return stateIcon('stateBad', 'A', `Подключение заблокировано политикой${row.policy_name ? ': ' + row.policy_name : ''}`);
  const reasons = getReasonStore();
  if (reasons[row.username] === 'admin_disconnect') return stateIcon('stateWarn', 'A', 'Agent session отключена сервером');
  return stateIcon('stateOff', 'A', 'Agent session неактивна');
}
function profileBadge(row) {
  if (row.profile) return stateIcon('stateInfo', 'P', `Профиль: ${row.profile}`);
  return stateIcon('stateWarn', 'P', 'Профиль не назначен');
}
function policyBadge(row) {
  if (row.policy_blocked) {
    const apps = Array.isArray(row.policy_matched_apps) && row.policy_matched_apps.length ? '\n' + row.policy_matched_apps.join(', ') : '';
    return stateIcon('stateBad', '!', `${row.policy_name || 'Политика'}${apps}`);
  }
  return '';
}
function runtimeHintBadge(row) {
  if (row.connected) return stateIcon('stateInfo', 'R', 'Runtime подтверждён');
  if (row.policy_blocked) return stateIcon('stateBad', 'R', row.policy_message || 'Подключение заблокировано политикой');
  return stateIcon('stateOff', 'R', 'Runtime не подтверждён');
}
function buildUserMenu(username, enabled) {
  return [
    `<button class="menuItem" data-action="cert" data-user="${esc(username)}">📜 Параметры сертификата</button>`,
    `<button class="menuItem" data-action="bundle" data-user="${esc(username)}">📦 Скачать bundle</button>`,
    `<button class="menuItem" data-action="reissuebundle" data-user="${esc(username)}">🔐 Перевыпустить bundle</button>`,
    '<div class="menuDivider"></div>',
    `<button class="menuItem" data-action="disconnect" data-user="${esc(username)}">⛔ Разорвать сессию</button>`,
    (enabled
      ? `<button class="menuItem" data-action="disableuser" data-user="${esc(username)}">🔒 Заблокировать пользователя</button>`
      : `<button class="menuItem" data-action="enableuser" data-user="${esc(username)}">🔓 Разблокировать пользователя</button>`),
    `<button class="menuItem" data-action="delete" data-user="${esc(username)}">🗑️ Удалить пользователя</button>`
  ].join('');
}
function closeFloatingMenu() {
  const menu = byId('userActionMenu');
  if (!menu) return;
  menu.classList.remove('open');
  menu.innerHTML = '';
  menu.removeAttribute('data-user');
}
function openFloatingMenu(anchor, username, enabled) {
  const menu = byId('userActionMenu');
  if (!menu || !anchor) return;
  menu.innerHTML = buildUserMenu(username, enabled);
  menu.classList.add('open');
  menu.dataset.user = username;
  menu.style.left = '8px';
  menu.style.top = '8px';
  const rect = anchor.getBoundingClientRect();
  const menuRect = menu.getBoundingClientRect();
  let left = rect.right - menuRect.width;
  if (left < 8) left = 8;
  let top = rect.bottom + 8;
  if (top + menuRect.height > window.innerHeight - 8) top = Math.max(8, rect.top - menuRect.height - 8);
  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;
}
async function jget(path) {
  const r = await fetch(normalizeBase(API_BASE) + path, { cache: 'no-store' });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function jpost(path, body) {
  const r = await fetch(normalizeBase(API_BASE) + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function pingApiBase() {
  const r = await fetch(normalizeBase(API_BASE) + '/api/admin/settings', { cache: 'no-store' });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function loadHealth() {
  try { healthData = await jget('/healthz'); } catch { healthData = null; }
}
async function loadSettings() {
  const st = await jget('/api/admin/settings');
  if (byId('clientPublicURL')) byId('clientPublicURL').value = st.client_public_url || '';
  if (byId('serverName')) byId('serverName').value = st.server_name || '';
  if (byId('extraSANs')) byId('extraSANs').value = Array.isArray(st.extra_sans) ? st.extra_sans.join(', ') : '';
  if (byId('pluginListenAddr')) byId('pluginListenAddr').value = st.plugin_listen_addr || '0.0.0.0';
  if (byId('pluginListenPort')) byId('pluginListenPort').value = st.plugin_listen_port ? String(st.plugin_listen_port) : '9443';
}
async function loadProfiles() {
  try {
    const p = await jget('/api/admin/profiles');
    profiles = Array.isArray(p.profiles) ? p.profiles : [];
  } catch {
    profiles = [];
  }
}
async function loadPolicies() {
  try {
    const p = await jget('/api/admin/app-policies');
    appPolicies = Array.isArray(p.policies) ? p.policies : [];
  } catch {
    appPolicies = [];
  }
  if (byId('appsBg') && byId('appsBg').style.display === 'flex' && appsState.username) {
    renderAppsView();
  }
}
function profileNameList() {
  return profiles.map(p => p?.name).filter(Boolean).sort((a, b) => a.localeCompare(b, 'ru'));
}
function refreshProfileSelects() {
  const options = ['<option value="">Без профиля</option>']
    .concat(profileNameList().map(name => `<option value="${esc(name)}">${esc(name)}</option>`)).join('');
  if (byId('userProfile')) {
    const prev = byId('userProfile').value;
    byId('userProfile').innerHTML = options;
    if (profileNameList().includes(prev)) byId('userProfile').value = prev;
  }
}
function mergedRows() {
  const map = new Map();
  for (const u of users || []) {
    map.set(u.username, {
      username: u.username || '—',
      cert_serial: u.cert_serial || '—',
      generation: u.generation || 0,
      user_last_seen: u.last_seen || '',
      enabled: !!u.enabled,
      profile: u.profile || '',
      connected: false,
      ip: '—', mac: '—', system_user: '—', os_name: '—', os_version: '—', system_uptime: '—',
      source: '—', connected_at: '', last_seen: '', apps_count: 0, apps_updated_at: '', interfaces: [],
      policy_blocked: false, policy_blocked_at: '', policy_name: '', policy_message: '', policy_matched_apps: []
    });
  }
  for (const s of sessions || []) {
    const row = map.get(s.username) || { username: s.username || '—', cert_serial: s.cert_serial || '—', generation: 0, user_last_seen: '', enabled: true, profile: '' };
    row.connected = !!s.connected;
    row.ip = s.ip || '—';
    row.mac = s.mac || '—';
    row.system_user = s.system_user || '—';
    row.os_name = s.os_name || '—';
    row.os_version = s.os_version || '—';
    row.system_uptime = s.system_uptime || '—';
    row.source = s.source || '—';
    row.connected_at = s.connected_at || '';
    row.last_seen = s.last_seen || row.last_seen || '';
    row.apps_count = s.apps_count || 0;
    row.apps_updated_at = s.apps_updated_at || '';
    row.cert_serial = s.cert_serial || row.cert_serial || '—';
    row.interfaces = Array.isArray(s.interfaces) ? s.interfaces : [];
    row.policy_blocked = !!s.policy_blocked;
    row.policy_blocked_at = s.policy_blocked_at || '';
    row.policy_name = s.policy_name || '';
    row.policy_message = s.policy_message || '';
    row.policy_matched_apps = Array.isArray(s.policy_matched_apps) ? s.policy_matched_apps : [];
    map.set(row.username, row);
  }
  return Array.from(map.values()).sort((a, b) => {
    if ((!!a.connected) !== (!!b.connected)) return a.connected ? -1 : 1;
    if ((!!a.policy_blocked) !== (!!b.policy_blocked)) return a.policy_blocked ? -1 : 1;
    return String(a.username).localeCompare(String(b.username), 'ru');
  });
}
function updateHistory(rows) {
  const history = getHistoryStore();
  const reasons = getReasonStore();
  for (const row of rows) {
    const status = row.connected ? 'connected' : (row.policy_blocked ? 'blocked_by_policy' : (reasons[row.username] === 'admin_disconnect' ? 'disconnected_by_admin' : 'disconnected'));
    const item = { at: row.policy_blocked_at || new Date().toISOString(), status, cert_serial: row.cert_serial || '', connected_at: row.connected_at || '', last_seen: row.last_seen || row.user_last_seen || '', ip: row.ip || '—', mac: row.mac || '—', source: row.source || '—', system_user: row.system_user || '—', os_name: row.os_name || '—', os_version: row.os_version || '—', system_uptime: row.system_uptime || '—', policy_name: row.policy_name || '', policy_message: row.policy_message || '', policy_matched_apps: Array.isArray(row.policy_matched_apps) ? row.policy_matched_apps.slice() : [] };

    const list = Array.isArray(history[row.username]) ? history[row.username] : [];
    const prev = list[0];
    const transition = !prev || prev.status !== item.status || prev.cert_serial !== item.cert_serial || prev.ip !== item.ip || prev.mac !== item.mac || prev.source !== item.source || prev.connected_at !== item.connected_at;
    if (transition) {
      list.unshift(item);
      history[row.username] = list.slice(0, 50);
    } else if (prev) {
      Object.assign(prev, { last_seen: item.last_seen, system_user: item.system_user, os_name: item.os_name, os_version: item.os_version, system_uptime: item.system_uptime });
    }
    if (row.connected) delete reasons[row.username];
  }
  setHistoryStore(history);
  setReasonStore(reasons);
}
function renderHealth() {
  const ok = !!healthData?.ok;
  const healthMetaText = healthData ? JSON.stringify(healthData) : 'Проверьте /healthz';
  if (byId('healthMeta')) byId('healthMeta').textContent = healthMetaText;
  if (byId('healthPill')) {
    byId('healthPill').className = 'healthPill ' + (ok ? 'ok' : 'warn');
    byId('healthPill').childNodes[0].textContent = 'Agent health: ' + (ok ? 'доступен ' : 'недоступен ');
  }
  if (byId('healthInfo')) byId('healthInfo').title = healthMetaText;
  if (byId('kpiClientUrl')) byId('kpiClientUrl').textContent = byId('clientPublicURL')?.value?.trim() || '—';
  if (byId('kpiServerName')) {
    const serverName = byId('serverName')?.value?.trim();
    byId('kpiServerName').textContent = serverName ? `Server name: ${serverName}` : 'Server name из URL / auto';
  }
  if (byId('kpiProfiles')) byId('kpiProfiles').textContent = String(profiles.length);
  if (byId('kpiProfilesMeta')) {
    const withPool = profiles.filter(p => p.pool_name || p.pool_subnet).length;
    byId('kpiProfilesMeta').textContent = `С pool: ${withPool}, full-tunnel: ${profiles.filter(p => p.full_tunnel).length}`;
  }
  if (byId('kpiUsers')) byId('kpiUsers').textContent = String(users.length);
  if (byId('kpiUsersMeta')) byId('kpiUsersMeta').textContent = `Включено: ${users.filter(u => u.enabled).length}, active session: ${sessions.filter(s => s.connected).length}, policy deny: ${sessions.filter(s => s.policy_blocked).length}`;
}
function renderProfiles() {
  const tbody = byId('profileRows');
  if (!tbody) return;
  if (!profiles.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">Нет данных</td></tr>';
    refreshProfileSelects();
    renderHealth();
    return;
  }
  tbody.innerHTML = profiles.slice().sort((a, b) => String(a.name || '').localeCompare(String(b.name || ''), 'ru')).map((p) => {
    const pool = [p.pool_name, p.pool_subnet, p.pool_gateway].filter(Boolean).join(' · ') || '—';
    const routing = `${p.full_tunnel ? 'full-tunnel' : 'split-tunnel'}${p.include_routes ? ' · in: ' + p.include_routes : ''}${p.exclude_routes ? ' · ex: ' + p.exclude_routes : ''}`;
    const dnsMtu = `${p.dns_servers || '—'} · mtu ${p.mtu || '—'} · mss ${p.mss_clamp || '—'}`;
    return '<tr>' +
      `<td><div><b>${esc(p.name || '—')}</b></div><div class="muted small">lease ${esc(String(p.lease_seconds || 0))}s</div></td>` +
      `<td>${esc(pool)}</td>` +
      `<td>${esc(routing)}</td>` +
      `<td>${esc(dnsMtu)}</td>` +
      `<td>${esc(fmtDate(p.updated_at))}</td>` +
      `<td><div class="actions"><button class="iconBtn" data-action="editprofile" data-pname="${esc(p.name || '')}" title="Редактировать">✏️</button><button class="iconBtn" data-action="deleteprofile" data-pname="${esc(p.name || '')}" title="Удалить">🗑️</button></div></td>` +
      '</tr>';
  }).join('');
  refreshProfileSelects();
  renderHealth();
}
function renderUsers() {
  const tbody = byId('rows');
  const rows = mergedRows();
  updateHistory(rows);
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="11" class="muted">Нет данных</td></tr>';
    renderHealth();
    return;
  }
  tbody.innerHTML = rows.map((r) => (
    '<tr>' +
      `<td><div class="statusIcons">${accountBadge(r)}${sessionBadge(r)}${profileBadge(r)}${policyBadge(r)}${runtimeHintBadge(r)}</div></td>` +
      `<td>${esc(r.username)}</td>` +
      `<td>${esc(r.profile || '—')}</td>` +
      `<td class="mono">${esc(r.ip)}</td>` +
      `<td class="mono">${esc(r.mac)}</td>` +
      `<td>${esc(r.system_user)}</td>` +
      `<td>${esc(r.os_name)}</td>` +
      `<td>${esc(r.os_version)}</td>` +
      `<td>${esc(String(r.apps_count || 0))}</td>` +
      `<td>${esc(fmtDate(r.last_seen || r.user_last_seen))}</td>` +
      '<td><div class="actions">' +
        `<button class="iconBtn" data-action="info" data-user="${esc(r.username)}" title="Сводная информация">ℹ️</button>` +
        `<button class="iconBtn" data-action="roadmap" data-user="${esc(r.username)}" title="Сессии подключений">🧭</button>` +
        `<button class="iconBtn" data-action="apps" data-user="${esc(r.username)}" title="Приложения">🖥️</button>` +
        `<button class="iconBtn" data-action="menu" data-user="${esc(r.username)}" data-enabled="${r.enabled ? 'true' : 'false'}" title="Ещё действия">⋯</button>` +
      '</div></td>' +
    '</tr>'
  )).join('');
  renderHealth();
}
function findProfile(name) { return profiles.find(p => (p?.name || '') === (name || '')); }
function fillProfileForm(profile) {
  if (!profile) return;
  byId('profileName').value = profile.name || '';
  byId('profilePoolName').value = profile.pool_name || '';
  byId('profilePoolSubnet').value = profile.pool_subnet || '';
  byId('profilePoolGateway').value = profile.pool_gateway || '';
  byId('profileLeaseSeconds').value = profile.lease_seconds ? String(profile.lease_seconds) : '';
  byId('profileFullTunnel').value = profile.full_tunnel ? 'true' : 'false';
  byId('profileDNSServers').value = profile.dns_servers || '';
  byId('profileIncludeRoutes').value = profile.include_routes || '';
  byId('profileExcludeRoutes').value = profile.exclude_routes || '';
  byId('profileMTU').value = profile.mtu ? String(profile.mtu) : '';
  byId('profileMSSClamp').value = profile.mss_clamp ? String(profile.mss_clamp) : '';
  byId('profileNote').value = profile.note || '';
}
function openInfo(username) {
  const row = mergedRows().find(x => x.username === username);
  if (!row) return;
  const profileText = row.profile || 'Без профиля';
  byId('infoUsername').textContent = row.username || '—';
  if (byId('infoUsername2')) byId('infoUsername2').textContent = row.username || '—';
  byId('infoStatus').innerHTML = `<div class="statusIcons">${accountBadge(row)}${sessionBadge(row)}${profileBadge(row)}${policyBadge(row)}${runtimeHintBadge(row)}</div>`;
  if (byId('infoProfilePill')) byId('infoProfilePill').textContent = `Профиль: ${profileText}`;
  if (byId('infoSourcePill')) byId('infoSourcePill').textContent = `Источник: ${row.source || '—'}`;
  if (byId('infoProfileText')) byId('infoProfileText').textContent = profileText;
  if (byId('infoRuntimeText')) byId('infoRuntimeText').textContent = row.connected ? 'Подтверждён по session API' : 'Не подтверждён';
  byId('infoIP').textContent = row.ip || '—';
  byId('infoMAC').textContent = row.mac || '—';
  byId('infoSystemUser').textContent = row.system_user || '—';
  byId('infoOSName').textContent = row.os_name || '—';
  byId('infoOSVersion').textContent = row.os_version || '—';
  byId('infoSystemUptime').textContent = row.system_uptime || '—';
  byId('infoConnectedAt').textContent = fmtDate(row.connected_at);
  byId('infoLastSeen').textContent = fmtDate(row.last_seen || row.user_last_seen);
  byId('infoCertSerial').textContent = row.cert_serial || '—';
  if (byId('infoSource')) byId('infoSource').textContent = row.source || '—';
  if (byId('infoAppsCount')) byId('infoAppsCount').textContent = String(row.apps_count || 0);
  if (byId('infoAppsUpdatedAt')) byId('infoAppsUpdatedAt').textContent = fmtDate(row.apps_updated_at);
  const interfacesEl = byId('infoInterfaces');
  if (interfacesEl) interfacesEl.textContent = formatInterfaces(row.interfaces || []);
  byId('infoBg').style.display = 'flex';
}
function closeInfo() { byId('infoBg').style.display = 'none'; }
function buildSessionGroups(username) {
  const history = getHistoryStore();
  const items = (Array.isArray(history[username]) ? history[username] : []).slice().sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime());
  const groups = [];
  let current = null;
  for (const item of items) {
    const key = item.status || 'disconnected';
    if (key === 'connected') {
      if (!current) {
        current = { id: item.connected_at || item.at, status: 'connected', ip: item.ip || '—', mac: item.mac || '—', source: item.source || '—', startedAt: item.connected_at || item.at, lastSeen: item.last_seen || item.at, endedAt: '', steps: [ { kind: 'open', title: 'Открытие session', at: item.connected_at || item.at, meta: 'Agent session зафиксирована' }, { kind: 'handshake', title: 'Session подтверждена', at: item.at, meta: 'Клиент перешёл в состояние «подключён» по данным session API' } ] };
      } else { current.lastSeen = item.last_seen || current.lastSeen; }
    } else {
      const closeTitle = key === 'disconnected_by_admin' ? 'Завершение сервером' : key === 'blocked_by_policy' ? 'Подключение заблокировано политикой' : 'Завершение session';
      const closeMeta = key === 'disconnected_by_admin' ? 'Session разорвана сервером' : key === 'blocked_by_policy' ? ((item.policy_message || 'Подключение остановлено политикой') + (item.policy_name ? ' · ' + item.policy_name : '') + (item.policy_matched_apps && item.policy_matched_apps.length ? ' · ' + item.policy_matched_apps.join(', ') : '')) : 'Session перешла в отключённое состояние';
      if (current) {
        current.lastSeen = item.last_seen || current.lastSeen;
        current.endedAt = item.at;
        current.status = key;
        current.steps.push({ kind: 'close', title: closeTitle, at: item.at, meta: closeMeta });
        groups.push(current); current = null;
      } else {
        groups.push({ id: item.at, status: key, ip: item.ip || '—', mac: item.mac || '—', source: item.source || '—', startedAt: '', lastSeen: item.last_seen || item.at, endedAt: item.at, steps: [{ kind: 'close', title: key === 'blocked_by_policy' ? 'Попытка подключения заблокирована' : (key === 'disconnected_by_admin' ? 'Завершение сервером' : 'Отключение'), at: item.at, meta: closeMeta }] });
      }
    }
  }
  if (current) groups.push(current);
  return groups.reverse().map((group) => {
    const hasActivity = group.lastSeen && group.lastSeen !== group.startedAt && group.lastSeen !== group.endedAt;
    const steps = group.steps.slice();
    if (hasActivity) {
      const closeIndex = steps.findIndex(s => s.kind === 'close');
      const activityStep = { kind: 'activity', title: 'Активность session', at: group.lastSeen, meta: 'Последняя активность по данным agent session API' };
      if (closeIndex >= 0) steps.splice(closeIndex, 0, activityStep); else steps.push(activityStep);
    }
    return { ...group, steps };
  });
}
function renderRoadmap(username) {
  const container = byId('roadmapList');
  if (!container) return;
  const groups = buildSessionGroups(username);
  if (!groups.length) {
    container.innerHTML = '<div class="roadmapEmpty">Нет данных о session</div>';
    return;
  }
  const statusBadge = (status) => status === 'connected' ? pill('ok', 'Подключен') : status === 'disconnected_by_admin' ? pill('warn', 'Отключен сервером') : status === 'blocked_by_policy' ? pill('bad', 'Заблокирован политикой') : pill('bad', 'Отключен');
  container.innerHTML = groups.map((group, idx) => (
    '<details class="roadmapCard" ' + (idx === 0 ? 'open' : '') + '>' +
      '<summary>' +
        '<div class="roadmapHead">' +
          `<div>${statusBadge(group.status)}</div>` +
          `<div class="roadmapMeta">Старт: ${esc(fmtDate(group.startedAt))} · Завершение: ${esc(fmtDate(group.endedAt))}</div>` +
          `<div class="roadmapMeta">IP: ${esc(group.ip || '—')} · MAC: ${esc(group.mac || '—')} · ${esc(group.source || '—')}</div>` +
        '</div>' +
        `<div class="roadmapMeta">Этапов: ${esc(String(group.steps.length))}</div>` +
      '</summary>' +
      '<div class="roadmapBody"><div class="timeline">' +
        group.steps.map((step) => (
          '<div class="step ' + (step.kind === 'open' ? 'stepOpen' : '') + ' ' + (step.kind === 'handshake' ? 'stepHandshake' : '') + ' ' + (step.kind === 'activity' ? 'stepActivity' : '') + ' ' + (step.kind === 'close' ? 'stepClose' : '') + '">' +
            `<div class="stepTitle">${esc(step.title)}</div><div class="stepMeta">${esc(fmtDate(step.at))}</div><div class="stepMeta">${esc(step.meta || '—')}</div>` +
          '</div>'
        )).join('') +
      '</div></div>' +
    '</details>'
  )).join('');
}
function openRoadmap(username) { if (byId('roadmapUsername')) byId('roadmapUsername').textContent = username || '—'; renderRoadmap(username); if (byId('roadmapBg')) byId('roadmapBg').style.display = 'flex'; }
function closeRoadmap() { if (byId('roadmapBg')) byId('roadmapBg').style.display = 'none'; }
async function openCert(username) {
  const cert = await jget('/api/admin/users/cert?username=' + encodeURIComponent(username));
  byId('certUsernameTitle').textContent = cert.username || '—';
  byId('certUsername').textContent = cert.username || '—';
  byId('certSerial').textContent = cert.serial || '—';
  byId('certSubject').textContent = cert.subject_cn || '—';
  byId('certIssuer').textContent = cert.issuer_cn || '—';
  byId('certNotBefore').textContent = fmtDate(cert.not_before);
  byId('certNotAfter').textContent = fmtDate(cert.not_after);
  byId('certKeyAlg').textContent = cert.key_algorithm || '—';
  byId('certKeyBits').textContent = cert.key_bits ? String(cert.key_bits) : '—';
  byId('certEKU').textContent = Array.isArray(cert.ext_key_usage) && cert.ext_key_usage.length ? cert.ext_key_usage.join(', ') : '—';
  byId('certBundleURL').textContent = cert.bundle_server_url || '—';
  byId('certBundleName').textContent = cert.bundle_server_name || '—';
  byId('certEnabled').textContent = cert.enabled === true ? 'Включен' : (cert.enabled === false ? 'Отключен' : '—');
  byId('certGeneration').textContent = cert.generation !== undefined ? String(cert.generation) : '—';
  byId('certNote').textContent = cert.note || '—';
  byId('certBg').style.display = 'flex';
}
function closeCert() { const bg = byId('certBg'); if (bg) bg.style.display = 'none'; }
function selectedProfileForUser(username) {
  const row = mergedRows().find(x => x.username === username);
  return row?.profile || '';
}
function downloadBundle(username) {
  const profile = selectedProfileForUser(username);
  const suffix = profile ? '&profile=' + encodeURIComponent(profile) : '';
  window.location.href = normalizeBase(API_BASE) + '/api/admin/bundle?username=' + encodeURIComponent(username) + suffix;
}
function downloadReissueBundle(username) {
  const profile = selectedProfileForUser(username);
  const suffix = profile ? '&profile=' + encodeURIComponent(profile) : '';
  window.location.href = normalizeBase(API_BASE) + '/api/admin/reissue-bundle?username=' + encodeURIComponent(username) + suffix;
}
async function loadUsersAndSessions() {
  const [u, s] = await Promise.all([jget('/api/admin/users'), jget('/api/admin/sessions')]);
  users = Array.isArray(u.users) ? u.users : [];
  sessions = Array.isArray(s.sessions) ? s.sessions : [];
}
async function loadAll() {
  await Promise.all([loadUsersAndSessions(), loadProfiles(), loadPolicies(), loadHealth()]);
  refreshProfileSelects();
  renderProfiles();
  renderPolicies();
  renderUsers();
}
async function disconnectSession(username) {
  const reasons = getReasonStore(); reasons[username] = 'admin_disconnect'; setReasonStore(reasons);
  await jpost('/api/admin/sessions/disconnect', { username });
  await loadAll();
}

function findUserRecord(username) {
  return (users || []).find((u) => (u?.username || '') === (username || '')) || null;
}
async function setUserEnabled(username, enabled) {
  const record = findUserRecord(username);
  if (!record) throw new Error('Пользователь не найден в текущем списке');
  await jpost('/api/admin/users', {
    username,
    cert_serial: record.cert_serial || '',
    enabled: !!enabled,
    profile: record.profile || ''
  });
  const reasons = getReasonStore();
  if (enabled) delete reasons[username];
  setReasonStore(reasons);
  await loadAll();
}
async function disableUser(username) {
  if (!confirm('Заблокировать пользователя "' + username + '" и разорвать активную session?')) return;
  await setUserEnabled(username, false);
  try { await disconnectSession(username); } catch (_) {}
}
async function enableUser(username) {
  await setUserEnabled(username, true);
}
async function deleteUser(username) {
  if (!confirm('Удалить пользователя "' + username + '"?')) return;
  const history = getHistoryStore(); delete history[username]; setHistoryStore(history);
  const reasons = getReasonStore(); delete reasons[username]; setReasonStore(reasons);
  await jpost('/api/admin/users/delete', { username });
  await loadAll();
}
async function deleteProfile(name) {
  if (!confirm('Удалить профиль "' + name + '"?')) return;
  await jpost('/api/admin/profiles/delete', { name });
  await loadAll();
}
function renderAppsView() {
  const statusInput = byId('appsStatus'); const rowsEl = byId('appsRows'); const categoryEl = byId('appsCategory');
  const searchValue = (byId('appsSearch').value || '').trim().toLowerCase();
  const categoryValue = categoryEl.value || ''; const report = appsState.report; const pending = !!appsState.pending;
  let apps = report && Array.isArray(report.apps) ? report.apps.slice() : [];
  if (appsState.last_policy_violation && Array.isArray(appsState.last_policy_violation.matched_apps)) {
    const existing = new Set(apps.map((x) => String((x && (x.name || x.exe)) || '').trim().toLowerCase()).filter(Boolean));
    for (const matched of appsState.last_policy_violation.matched_apps) {
      const name = String(matched || '').trim();
      const key = name.toLowerCase();
      if (!key || existing.has(key)) continue;
      existing.add(key);
      apps.push({ name, category: 'Заблокировано политикой', pid: '', uptime: '—', exe: '' });
    }
  }
  if (!apps.length && appsState.last_policy_violation && Array.isArray(appsState.last_policy_violation.matched_apps)) {
    apps = appsState.last_policy_violation.matched_apps.map((name) => ({ name, category: 'Заблокировано политикой', pid: '', uptime: '—', exe: '' }));
  }
  const categories = Array.from(new Set(apps.map(x => x.category || 'Другое'))).sort((a, b) => a.localeCompare(b, 'ru'));
  const currentCategory = categoryEl.value;
  categoryEl.innerHTML = '<option value="">Все категории</option>' + categories.map(c => '<option value="' + esc(c) + '">' + esc(c) + '</option>').join('');
  if (categories.includes(currentCategory)) categoryEl.value = currentCategory;
  apps = apps.filter(app => {
    const cat = app.category || 'Другое';
    if (categoryValue && cat !== categoryValue) return false;
    if (!searchValue) return true;
    const hay = [app.name, app.category, app.pid, app.uptime, app.exe].join(' ').toLowerCase();
    return hay.includes(searchValue);
  });
  const decorated = apps.map((app) => ({ app, policyMatches: getPolicyMatchesForApp(app, appsState.username) }));
  const forbiddenCount = decorated.filter((x) => x.policyMatches.length > 0).length;
  let statusText = 'Нет данных';
  if (pending && report) statusText = 'Ожидается свежий ответ клиента. Последний отчёт: ' + fmtDate(report.generated_at);
  else if (pending) statusText = 'Запрос отправлен. Ожидается ответ клиента…';
  else if (report || apps.length) statusText = 'Последний отчёт: ' + fmtDate(report && report.generated_at) + ', приложений: ' + apps.length + ', запрещённых: ' + forbiddenCount + (((appPolicies || []).length || appsState.last_policy_violation) ? '' : ' · политики не загружены');
  if (appsState.last_policy_violation && (appsState.last_policy_violation.policy_name || appsState.last_policy_violation.message)) {
    statusText += ' · последняя блокировка: ' + (appsState.last_policy_violation.policy_name || 'политика') + (appsState.last_policy_violation.message ? ' — ' + appsState.last_policy_violation.message : '');
  }
  statusInput.value = statusText;
  if (!decorated.length) { rowsEl.innerHTML = '<tr><td colspan="6" class="muted">Нет данных</td></tr>'; return; }
  rowsEl.innerHTML = decorated.map(({ app, policyMatches }) => {
    const forbidden = policyMatches.length > 0;
    const policyText = forbidden
      ? policyMatches.map((m) => '<div><span class="pill pillBad">Запрещено</span> <b>' + esc(m.name) + '</b><div class="muted small mono">' + esc(m.matchedPatterns.join(', ')) + '</div></div>').join('')
      : '<span class="muted">—</span>';
    const rowClass = forbidden ? ' class="appDeniedRow"' : '';
    const nameCell = forbidden
      ? '<div><b>' + esc(app.name || '—') + '</b> <span class="pill pillBad">Запрещено</span><div class="muted small">Совпадение с политикой доступа</div></div>'
      : esc(app.name || '—');
    return '<tr' + rowClass + '>' +
      `<td>${nameCell}</td><td>${esc(app.category || 'Другое')}</td><td class="mono">${esc(String(app.pid ?? '—'))}</td><td>${esc(app.uptime || '—')}</td><td class="mono">${esc(app.exe || '—')}</td><td>${policyText}</td>` +
      '</tr>';
  }).join('');
}
async function loadAppsView(username) {
  await loadPolicies().catch(() => {});
  const view = await jget('/api/admin/users/apps?username=' + encodeURIComponent(username));
  appsState = { username, pending: !!view.pending, report: view.report || null, last_policy_violation: view.last_policy_violation || null };
  renderAppsView();
  if (!appsState.pending && appsPollTimer) { clearInterval(appsPollTimer); appsPollTimer = null; }
}
async function requestAppsRefresh() {
  if (!appsState.username) return;
  await loadPolicies().catch(() => {});
  byId('appsStatus').value = 'Запрашиваем свежий список…';
  await jpost('/api/admin/users/request-apps', { username: appsState.username });
  if (appsPollTimer) clearInterval(appsPollTimer);
  appsPollTimer = setInterval(() => { loadAppsView(appsState.username).catch(() => {}); }, 2000);
  await loadAppsView(appsState.username);
}
async function openApps(username) {
  await loadPolicies().catch(() => {});
  appsState = { username, pending: false, report: null, last_policy_violation: null };
  byId('appsUsername').textContent = username || '—';
  byId('appsSearch').value = '';
  byId('appsCategory').innerHTML = '<option value="">Все категории</option>';
  byId('appsRows').innerHTML = '<tr><td colspan="6" class="muted">Нажмите «Обновить список», чтобы запросить приложения у клиента.</td></tr>'; 
  byId('appsStatus').value = 'Список ещё не запрашивался';
  byId('appsBg').style.display = 'flex';
  if (appsPollTimer) { clearInterval(appsPollTimer); appsPollTimer = null; }
  try { await loadAppsView(username); } catch (_) {}
}
function closeApps() { byId('appsBg').style.display = 'none'; if (appsPollTimer) { clearInterval(appsPollTimer); appsPollTimer = null; } }

function openProfileModal(isEdit = false) { if (byId('profileModalTitle')) byId('profileModalTitle').textContent = isEdit ? 'Обновить профиль' : 'Создать профиль'; byId('profileBg').style.display = 'flex'; }
function closeProfileModal() { byId('profileBg').style.display = 'none'; }
function resetProfileForm() { fillProfileForm({ name:'', pool_name:'', pool_subnet:'', pool_gateway:'', lease_seconds:'', full_tunnel:true, dns_servers:'', include_routes:'', exclude_routes:'', mtu:'', mss_clamp:'', note:'' }); }

function profilePayloadFromForm() {
  return {
    name: byId('profileName').value.trim(),
    pool_name: byId('profilePoolName').value.trim(),
    pool_subnet: byId('profilePoolSubnet').value.trim(),
    pool_gateway: byId('profilePoolGateway').value.trim(),
    lease_seconds: numOrZero(byId('profileLeaseSeconds').value),
    full_tunnel: byId('profileFullTunnel').value === 'true',
    dns_servers: byId('profileDNSServers').value.trim(),
    include_routes: byId('profileIncludeRoutes').value.trim(),
    exclude_routes: byId('profileExcludeRoutes').value.trim(),
    mtu: numOrZero(byId('profileMTU').value),
    mss_clamp: numOrZero(byId('profileMSSClamp').value),
    note: byId('profileNote').value.trim()
  };
}

function scopeLabel(scope) {
  if (!scope) return 'Все пользователи';
  if (scope.all_users) return 'Все пользователи';
  const users = Array.isArray(scope.users) ? scope.users.filter(Boolean) : [];
  const profilesList = Array.isArray(scope.profiles) ? scope.profiles.filter(Boolean) : [];
  const parts = [];
  if (profilesList.length) parts.push('Профили: ' + profilesList.join(', '));
  if (users.length) parts.push('Пользователи: ' + users.join(', '));
  return parts.length ? parts.join(' · ') : 'Все пользователи';
}
function normalizePolicyPatterns(patterns) {
  const arr = Array.isArray(patterns) ? patterns : [];
  return arr.map((p) => {
    if (typeof p === 'string') {
      const value = p.trim();
      return value ? { type: 'contains', value } : null;
    }
    if (p && typeof p === 'object') {
      const type = String(p.type || 'contains').trim() || 'contains';
      const value = String(p.value || '').trim();
      return value ? { type, value } : null;
    }
    return null;
  }).filter(Boolean);
}
function normalizePatternObject(p) {
  if (typeof p === 'string') return { type: 'contains', value: p.trim() };
  return { type: (p && p.type ? String(p.type).trim().toLowerCase() : 'contains'), value: (p && p.value ? String(p.value).trim() : '') };
}
function patternKey(p) {
  const x = normalizePatternObject(p);
  return `${x.type}:${x.value}`.toLowerCase();
}
function renderPolicyPresetList(selectedKeys = new Set()) {
  const host = byId('policyPresetList');
  if (!host) return;
  host.innerHTML = POLICY_PRESETS.map((preset) => {
    const checked = preset.patterns.some((p) => selectedKeys.has(patternKey(p)));
    return `<label class="presetItem${checked ? ' active' : ''}"><input type="checkbox" class="policyPresetCheck" value="${esc(preset.id)}" ${checked ? 'checked' : ''}><div><div class="presetTitle">${esc(preset.title)}</div><div class="presetMeta">${esc(preset.meta)}</div></div></label>`;
  }).join('');
}
function selectedPresetIds() {
  return Array.from(document.querySelectorAll('.policyPresetCheck:checked')).map((el) => el.value);
}
function selectedPresetPatterns() {
  const ids = new Set(selectedPresetIds());
  return POLICY_PRESETS.filter((p) => ids.has(p.id)).flatMap((p) => p.patterns.map(normalizePatternObject));
}
function policyPatternText(p) {
  if (!p) return '';
  if (typeof p === 'string') return p;
  const type = String(p.type || 'contains').trim() || 'contains';
  const value = String(p.value || '').trim();
  if (!value) return '';
  return type === 'contains' ? value : `${type}:${value}`;
}
function patternsPreview(patterns) {
  const arr = normalizePolicyPatterns(patterns).map(policyPatternText).filter(Boolean);
  if (!arr.length) return '—';
  if (arr.length <= 2) return arr.join(', ');
  return arr.slice(0,2).join(', ') + ' +' + (arr.length - 2);
}
function policyChecksLabel(policy) {
  const parts = [];
  if (policy && policy.check_on_client) parts.push('Клиент');
  if (policy && policy.check_on_server) parts.push('Сервер');
  return parts.length ? parts.join(' + ') : 'Клиент';
}
function getUserRow(username) {
  return (users || []).find((u) => (u?.username || '') === (username || '')) || null;
}
function normalizeSimple(v) {
  return String(v || '').toLowerCase().trim().replace(/[\s_\-]+/g, ' ');
}
function getViolationForcedMatchesForApp(app) {
  const v = appsState && appsState.last_policy_violation ? appsState.last_policy_violation : null;
  if (!v || !Array.isArray(v.matched_apps) || !v.matched_apps.length) return [];
  const parts = [app?.name, app?.category, app?.exe, app?.pid, app?.uptime].map((x) => String(x || '').trim()).filter(Boolean);
  const hayRaw = parts.join("\n");
  const hay = hayRaw.toLowerCase();
  const hayNorm = normalizeSimple(hayRaw);
  const hits = [];
  for (const raw of v.matched_apps) {
    const name = String(raw || '').trim();
    if (!name) continue;
    const needle = name.toLowerCase();
    const needleNorm = normalizeSimple(name);
    if (
      hay.includes(needle) ||
      (needleNorm && hayNorm.includes(needleNorm)) ||
      (needleNorm && hayNorm === needleNorm) ||
      (needleNorm && normalizeSimple(app?.name) === needleNorm) ||
      (needleNorm && normalizeSimple(app?.exe) === needleNorm)
    ) {
      hits.push(name);
    }
  }
  const syntheticBlocked = String(app?.category || '').trim().toLowerCase() === 'заблокировано политикой';
  if (!hits.length && !syntheticBlocked) return [];
  return [{
    id: v.policy_id || '',
    name: v.policy_name || 'Политика',
    mode: 'deny_on_match',
    matchedPatterns: hits.length ? hits : (Array.isArray(v.matched_apps) ? v.matched_apps.slice() : [])
  }];
}

function policyScopeApplies(policy, username, profileName) {
  const scope = policy && policy.scope ? policy.scope : {};
  if (!policy || policy.enabled === false) return false;
  if (scope.all_users === true || (!Array.isArray(scope.users) && !Array.isArray(scope.profiles))) return true;
  const usersList = Array.isArray(scope.users) ? scope.users.filter(Boolean) : [];
  const profilesList = Array.isArray(scope.profiles) ? scope.profiles.filter(Boolean) : [];
  if (usersList.includes(username)) return true;
  if (profileName && profilesList.includes(profileName)) return true;
  return false;
}
function wildcardToRegexText(value) {
  return escapeRegex(value).replace(/\*/g, '.*');
}
function compilePolicyPattern(pattern) {
  if (!pattern) return null;
  const type = String(pattern.type || 'contains').trim().toLowerCase() || 'contains';
  const value = String(pattern.value || '').trim();
  if (!value) return null;
  try {
    if (type === 'regex') return new RegExp(value, 'i');
    if (value.includes('*')) return new RegExp(wildcardToRegexText(value), 'i');
    return new RegExp(escapeRegex(value), 'i');
  } catch (_) {
    return null;
  }
}
function getPolicyMatchesForApp(app, username) {
  const forced = getViolationForcedMatchesForApp(app);
  if (forced.length) return forced;
  const userRow = getUserRow(username);
  const profileName = userRow && userRow.profile ? userRow.profile : '';
  const hay = [app?.name, app?.category, app?.exe, app?.pid, app?.uptime].map((v) => String(v || '')).join('\n');
  const matches = [];
  for (const policy of (appPolicies || [])) {
    if (!policyScopeApplies(policy, username, profileName)) continue;
    const patterns = normalizePolicyPatterns(policy.patterns);
    if (!patterns.length) continue;
    const hitPatterns = [];
    for (const pattern of patterns) {
      const re = compilePolicyPattern(pattern);
      if (re && re.test(hay)) hitPatterns.push(policyPatternText(pattern));
    }
    if (hitPatterns.length) {
      matches.push({
        id: policy.id || '',
        name: policy.name || policy.id || 'Политика',
        mode: policy.mode || 'deny_on_match',
        matchedPatterns: hitPatterns
      });
    }
  }
  return matches;
}
function renderPolicies() {
  const el = byId('policyRows');
  if (!el) return;
  if (!appPolicies.length) { el.innerHTML = '<tr><td colspan="8" class="muted">Нет данных</td></tr>'; return; }
  el.innerHTML = appPolicies.map((p) => {
    const status = p.enabled ? pill('ok', 'Включена') : pill('mute', 'Выключена');
    const scope = scopeLabel(p.scope);
    const msg = p.message || 'У вас обнаружено запрещенное приложение';
    return '<tr>' +
      `<td><div style="font-weight:800">${esc(p.name || p.id || '—')}</div><div class="muted small mono">${esc(p.id || '—')}</div></td>` +
      `<td><span class="mono">${esc(p.mode || 'deny_on_match')}</span></td>` +
      `<td>${esc(policyChecksLabel(p))}</td>` +
      `<td>${esc(scope)}</td>` +
      `<td class="mono">${esc(patternsPreview(p.patterns))}</td>` +
      `<td>${esc(msg)}</td>` +
      `<td>${status}</td>` +
      `<td class="actions"><button type="button" data-action="editpolicy" data-pid="${esc(p.id || '')}">Изменить</button><button type="button" class="btnDanger" data-action="deletepolicy" data-pid="${esc(p.id || '')}">Удалить</button></td>` +
      '</tr>';
  }).join('');
}
function findPolicy(id) { return (appPolicies || []).find((p) => (p?.id || '') === (id || '')) || null; }
function fillPolicyForm(policy) {
  const p = policy || {};
  byId('policyId').value = p.id || '';
  byId('policyName').value = p.name || '';
  byId('policyEnabled').value = p.enabled === false ? 'false' : 'true';
  byId('policyMode').value = p.mode || 'deny_on_match';
  const scope = p.scope || {};
  let mode = 'all';
  if (Array.isArray(scope.profiles) && scope.profiles.length) mode = 'profiles';
  if (Array.isArray(scope.users) && scope.users.length) mode = 'users';
  byId('policyScopeMode').value = scope.all_users === false ? mode : (mode === 'all' ? 'all' : mode);
  byId('policyProfiles').value = Array.isArray(scope.profiles) ? scope.profiles.join(', ') : '';
  byId('policyUsers').value = Array.isArray(scope.users) ? scope.users.join(', ') : '';
  byId('policyMessage').value = p.message || 'У вас обнаружено запрещенное приложение';
  if (byId('policyCheckOnClient')) byId('policyCheckOnClient').checked = p.check_on_client !== false || !p.check_on_server;
  if (byId('policyCheckOnServer')) byId('policyCheckOnServer').checked = !!p.check_on_server;
  const normalizedPatterns = normalizePolicyPatterns(p.patterns);
  const selectedKeys = new Set(normalizedPatterns.map(patternKey));
  renderPolicyPresetList(selectedKeys);
  const presetPatternKeys = new Set(POLICY_PRESETS.flatMap((preset) => preset.patterns.map(patternKey)));
  byId('policyPatterns').value = normalizedPatterns.filter((x) => !presetPatternKeys.has(patternKey(x))).map(policyPatternText).filter(Boolean).join('\n');
}
function resetPolicyForm() { renderPolicyPresetList(new Set()); fillPolicyForm({ enabled: true, mode: 'deny_on_match', scope: { all_users: true }, message: 'У вас обнаружено запрещенное приложение', patterns: [] }); }
function openPolicyModal(isEdit=false) { if (byId('policyModalTitle')) byId('policyModalTitle').textContent = isEdit ? 'Изменить политику приложений' : 'Создать политику приложений'; byId('policyBg').style.display = 'flex'; }
function closePolicyModal() { byId('policyBg').style.display = 'none'; }
function policyPayloadFromForm() {
  const scopeMode = byId('policyScopeMode').value;
  const profiles = splitCSV(byId('policyProfiles').value);
  const usersList = splitCSV(byId('policyUsers').value);
  const scope = { all_users: scopeMode === 'all', profiles: scopeMode === 'profiles' ? profiles : [], users: scopeMode === 'users' ? usersList : [] };
  return {
    id: byId('policyId').value.trim(),
    name: byId('policyName').value.trim(),
    enabled: byId('policyEnabled').value === 'true',
    mode: byId('policyMode').value || 'deny_on_match',
    message: byId('policyMessage').value.trim() || 'У вас обнаружено запрещенное приложение',
    check_on_client: !!byId('policyCheckOnClient')?.checked,
    check_on_server: !!byId('policyCheckOnServer')?.checked,
    patterns: (() => {
      const presetPatterns = selectedPresetPatterns();
      const customPatterns = byId('policyPatterns').value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean).map((x) => {
        const m = x.match(/^(contains|regex)\s*:\s*(.+)$/i);
        if (m) return { type: m[1].toLowerCase(), value: m[2].trim() };
        return { type: 'contains', value: x };
      }).filter((x) => x.value);
      const merged = [...presetPatterns, ...customPatterns].map(normalizePatternObject).filter((x) => x.value);
      const seen = new Set();
      return merged.filter((x) => {
        const key = patternKey(x);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    })(),
    scope
  };
}
async function deletePolicy(id) {
  if (!confirm('Удалить политику "' + id + '"?')) return;
  await jpost('/api/admin/app-policies/delete', { id });
  await loadPolicies();
  renderPolicies();
}


document.addEventListener('click', async (e) => {
  const menuBtn = e.target.closest('button[data-action="menu"]');
  if (menuBtn) {
    e.preventDefault();
    e.stopPropagation();
    const user = menuBtn.getAttribute('data-user') || '';
    const enabled = menuBtn.getAttribute('data-enabled') === 'true';
    const menu = byId('userActionMenu');
    if (menu && menu.classList.contains('open') && menu.dataset.user === user) closeFloatingMenu();
    else openFloatingMenu(menuBtn, user, enabled);
    return;
  }
  const btn = e.target.closest('button[data-action]');
  if (!btn) { closeFloatingMenu(); return; }
  const user = btn.getAttribute('data-user') || '';
  const pname = btn.getAttribute('data-pname') || '';
  const action = btn.getAttribute('data-action');
  if (action !== 'menu') closeFloatingMenu();
  if (action === 'info') openInfo(user);
  if (action === 'roadmap') openRoadmap(user);
  if (action === 'cert') await openCert(user);
  if (action === 'apps') await openApps(user);
  if (action === 'bundle') downloadBundle(user);
  if (action === 'reissuebundle') downloadReissueBundle(user);
  if (action === 'disconnect') await disconnectSession(user);
  if (action === 'disableuser') await disableUser(user);
  if (action === 'enableuser') await enableUser(user);
  if (action === 'delete') await deleteUser(user);
  if (action === 'editprofile') { fillProfileForm(findProfile(pname)); openProfileModal(true); }
  if (action === 'deleteprofile') await deleteProfile(pname);
  const pid = btn.getAttribute('data-pid') || '';
  if (action === 'editpolicy') { fillPolicyForm(findPolicy(pid)); openPolicyModal(true); }
  if (action === 'deletepolicy') await deletePolicy(pid);
});

byId('btnApplyApi').addEventListener('click', async () => {
  const previous = API_BASE;
  API_BASE = normalizeBase(byId('apiBase').value);
  localStorage.setItem('tlsctrl_api_base', API_BASE);
  syncApiBaseUI();
  try {
    await pingApiBase();
    await loadSettings();
    await loadAll();
  } catch (e) {
    API_BASE = previous; localStorage.setItem('tlsctrl_api_base', API_BASE); syncApiBaseUI();
    alert('Не удалось подключиться к API Base: ' + (e?.message || e));
  }
});
if (byId('btnSaveSettings')) {
  byId('btnSaveSettings').addEventListener('click', async () => {
    await jpost('/api/admin/settings', {
      client_public_url: byId('clientPublicURL').value.trim(),
      server_name: byId('serverName').value.trim(),
      extra_sans: splitCSV(byId('extraSANs').value),
      plugin_listen_addr: byId('pluginListenAddr') ? byId('pluginListenAddr').value.trim() : '0.0.0.0',
      plugin_listen_port: byId('pluginListenPort') ? parseInt(byId('pluginListenPort').value || '9443', 10) || 9443 : 9443
    });
    await loadSettings(); renderHealth();
    alert('Настройки сохранены. Server cert перевыпущен. Скачайте bundle заново.');
  });
}
if (byId('btnSaveProfile')) {
  byId('btnSaveProfile').addEventListener('click', async () => {
    const payload = profilePayloadFromForm();
    if (!payload.name) { alert('Укажите имя профиля'); return; }
    try {
      await jpost('/api/admin/profiles', payload);
      await loadAll();
      closeProfileModal();
      alert('Профиль сохранён');
    } catch (e) {
      alert('Не удалось сохранить профиль: ' + (e?.message || e));
    }
  });
}
if (byId('btnSyncVPN')) {
  byId('btnSyncVPN').addEventListener('click', async () => {
    await jpost('/api/admin/plugin/sync-vpn', {});
    await loadAll();
    alert('Sync профилей в plugin выполнен');
  });
}
if (byId('btnRefreshProfiles')) byId('btnRefreshProfiles').addEventListener('click', async () => { await loadProfiles(); renderProfiles(); });

if (byId('btnRefreshPolicies')) byId('btnRefreshPolicies').addEventListener('click', async () => { await loadPolicies(); renderPolicies(); });
if (byId('btnOpenPolicyModal')) byId('btnOpenPolicyModal').addEventListener('click', () => { resetPolicyForm(); openPolicyModal(false); });
if (byId('btnSavePolicy')) {
  byId('btnSavePolicy').addEventListener('click', async () => {
    const payload = policyPayloadFromForm();
    payload.patterns = (Array.isArray(payload.patterns) ? payload.patterns : []).map((p) => {
      if (typeof p === 'string') return { type: 'contains', value: p.trim() };
      return { type: (p && p.type ? String(p.type).trim() : 'contains'), value: (p && p.value ? String(p.value).trim() : '') };
    }).filter((p) => p.value);
    if (!payload.id) { alert('Укажите ID политики'); return; }
    if (!payload.name) { alert('Укажите название политики'); return; }
    if (!payload.patterns.length) { alert('Добавьте хотя бы один шаблон'); return; }
    if (!payload.check_on_client && !payload.check_on_server) { alert('Выберите хотя бы один режим проверки'); return; }
    await jpost('/api/admin/app-policies', payload);
    await loadPolicies();
    renderPolicies();
    closePolicyModal();
    alert('Политика сохранена');
  });
}
if (byId('btnClosePolicyModal')) byId('btnClosePolicyModal').addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); closePolicyModal(); });
if (byId('policyBg')) byId('policyBg').addEventListener('click', (e) => { if (e.target === byId('policyBg')) closePolicyModal(); });
byId('btnBundle').addEventListener('click', () => downloadBundle(byId('bundleUser').value.trim()));
byId('btnReissueBundle').addEventListener('click', () => downloadReissueBundle(byId('reissueUser').value.trim()));
byId('btnUpsert').addEventListener('click', async () => {
  await jpost('/api/admin/users', { username: byId('username').value.trim(), cert_serial: byId('certSerial').value.trim(), enabled: byId('enabled').value === 'true', profile: byId('userProfile') ? byId('userProfile').value : '' });
  byId('username').value = ''; byId('certSerial').value = ''; if (byId('userProfile')) byId('userProfile').value = '';
  await loadAll();
});
byId('btnRefresh').addEventListener('click', loadAll);
byId('btnCloseInfo').addEventListener('click', closeInfo);
if (byId('btnCloseRoadmap')) byId('btnCloseRoadmap').addEventListener('click', closeRoadmap);
if (byId('btnCloseCert')) byId('btnCloseCert').addEventListener('click', closeCert);
if (byId('btnCloseApps')) byId('btnCloseApps').addEventListener('click', closeApps);
if (byId('appsSearch')) byId('appsSearch').addEventListener('input', renderAppsView);
if (byId('appsCategory')) byId('appsCategory').addEventListener('change', renderAppsView);

localStorage.setItem('tlsctrl_api_base', API_BASE);
syncApiBaseUI();
renderPolicyPresetList(new Set());
Promise.all([loadSettings().catch(() => {}), loadAll().catch(console.error)]).then(() => renderHealth());
setInterval(() => { loadAll().catch(() => {}); }, 3000);

if (byId('btnOpenProfileModal')) byId('btnOpenProfileModal').addEventListener('click', () => { resetProfileForm(); openProfileModal(false); });
if (byId('btnCloseProfileModal')) byId('btnCloseProfileModal').addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); closeProfileModal(); });
if (byId('profileBg')) {
  byId('profileBg').addEventListener('click', (e) => {
    if (e.target === byId('profileBg')) closeProfileModal();
  });
}
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && byId('profileBg') && byId('profileBg').style.display === 'flex') closeProfileModal();
  if (e.key === 'Escape' && byId('policyBg') && byId('policyBg').style.display === 'flex') closePolicyModal();
});
document.addEventListener('click', (e) => {
  const closeBtn = e.target && e.target.closest ? e.target.closest('#btnCloseProfileModal') : null;
  if (closeBtn) {
    e.preventDefault();
    e.stopPropagation();
    closeProfileModal();
  }
  const closePolicyBtn = e.target && e.target.closest ? e.target.closest('#btnClosePolicyModal') : null;
  if (closePolicyBtn) {
    e.preventDefault();
    e.stopPropagation();
    closePolicyModal();
  }
});
if (byId('btnAppsRefresh')) byId('btnAppsRefresh').addEventListener('click', () => { requestAppsRefresh().catch(e => alert('Не удалось обновить список приложений: ' + (e?.message || e))); });
Array.from(document.querySelectorAll('.tabBtn')).forEach((btn) => btn.addEventListener('click', () => { const tab = btn.getAttribute('data-tab'); document.querySelectorAll('.tabBtn').forEach(x => x.classList.toggle('active', x === btn)); document.querySelectorAll('.tabPanel').forEach(p => p.classList.toggle('active', p.getAttribute('data-panel') === tab)); }));

window.addEventListener("resize", closeFloatingMenu);
window.addEventListener("scroll", closeFloatingMenu, true);

if (byId('policyPresetList')) byId('policyPresetList').addEventListener('change', (e) => { const item = e.target && e.target.closest ? e.target.closest('.presetItem') : null; if (item) item.classList.toggle('active', !!item.querySelector('input')?.checked); Array.from(document.querySelectorAll('.presetItem')).forEach((el) => { const cb = el.querySelector('input'); el.classList.toggle('active', !!cb?.checked); }); });
