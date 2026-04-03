const byId = (id) => document.getElementById(id);
let users = [];
let sessions = [];
let profiles = [];
let healthData = null;

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
function accountBadge(row) { return row.enabled ? pill('ok', 'Учётка включена') : pill('bad', 'Учётка выключена'); }
function sessionBadge(row) {
  if (row.connected) return pill('ok', 'Agent session активна');
  const reasons = getReasonStore();
  if (reasons[row.username] === 'admin_disconnect') return pill('warn', 'Отключено сервером');
  return pill('mute', 'Agent session нет');
}
function profileBadge(row) {
  if (row.profile) return pill('info', `Профиль: ${row.profile}`);
  return pill('warn', 'Профиль не назначен');
}
function runtimeHintBadge(row) {
  if (row.connected) return pill('info', 'Runtime: по agent session');
  return pill('mute', 'Runtime: bind в plugin отдельно');
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
      source: '—', connected_at: '', last_seen: '', apps_count: 0, apps_updated_at: '', interfaces: []
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
    map.set(row.username, row);
  }
  return Array.from(map.values()).sort((a, b) => {
    if ((!!a.connected) !== (!!b.connected)) return a.connected ? -1 : 1;
    return String(a.username).localeCompare(String(b.username), 'ru');
  });
}
function updateHistory(rows) {
  const history = getHistoryStore();
  const reasons = getReasonStore();
  for (const row of rows) {
    const status = row.connected ? 'connected' : (reasons[row.username] === 'admin_disconnect' ? 'disconnected_by_admin' : 'disconnected');
    const item = { at: new Date().toISOString(), status, cert_serial: row.cert_serial || '', connected_at: row.connected_at || '', last_seen: row.last_seen || row.user_last_seen || '', ip: row.ip || '—', mac: row.mac || '—', source: row.source || '—', system_user: row.system_user || '—', os_name: row.os_name || '—', os_version: row.os_version || '—', system_uptime: row.system_uptime || '—' };
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
  if (!byId('healthStatus')) return;
  const ok = !!healthData?.ok;
  byId('healthStatus').innerHTML = ok ? pill('ok', 'Agent доступен') : pill('warn', 'Health недоступен');
  byId('healthMeta').textContent = healthData ? JSON.stringify(healthData) : 'Проверьте /healthz';
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
  if (byId('kpiUsersMeta')) byId('kpiUsersMeta').textContent = `Включено: ${users.filter(u => u.enabled).length}, active session: ${sessions.filter(s => s.connected).length}`;
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
      `<td><div class="badgeRow">${accountBadge(r)}${sessionBadge(r)}${profileBadge(r)}${runtimeHintBadge(r)}</div></td>` +
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
        `<button class="iconBtn" data-action="roadmap" data-user="${esc(r.username)}" title="Сессии подключений">🗺️</button>` +
        `<button class="iconBtn" data-action="cert" data-user="${esc(r.username)}" title="Параметры сертификата">📜</button>` +
        `<button class="iconBtn" data-action="apps" data-user="${esc(r.username)}" title="Запросить и показать приложения">🖥️</button>` +
        `<button class="iconBtn" data-action="bundle" data-user="${esc(r.username)}" title="Скачать bundle">📦</button>` +
        `<button class="iconBtn" data-action="reissuebundle" data-user="${esc(r.username)}" title="Перевыпустить bundle">🔐</button>` +
        `<button class="iconBtn" data-action="disconnect" data-user="${esc(r.username)}" title="Отключить session агента">⛔</button>` +
        (r.enabled
          ? `<button class="iconBtn" data-action="disableuser" data-user="${esc(r.username)}" title="Заблокировать пользователя">🔒</button>`
          : `<button class="iconBtn" data-action="enableuser" data-user="${esc(r.username)}" title="Разблокировать пользователя">🔓</button>`) +
        `<button class="iconBtn" data-action="delete" data-user="${esc(r.username)}" title="Удалить пользователя">🗑️</button>` +
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
  byId('infoUsername').textContent = row.username || '—';
  byId('infoStatus').innerHTML = `<div class="badgeRow">${accountBadge(row)}${sessionBadge(row)}${profileBadge(row)}${runtimeHintBadge(row)}</div>`;
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
      if (current) {
        current.lastSeen = item.last_seen || current.lastSeen;
        current.endedAt = item.at;
        current.status = key;
        current.steps.push({ kind: 'close', title: key === 'disconnected_by_admin' ? 'Завершение сервером' : 'Завершение session', at: item.at, meta: key === 'disconnected_by_admin' ? 'Session разорвана сервером' : 'Session перешла в отключённое состояние' });
        groups.push(current); current = null;
      } else {
        groups.push({ id: item.at, status: key, ip: item.ip || '—', mac: item.mac || '—', source: item.source || '—', startedAt: '', lastSeen: item.last_seen || item.at, endedAt: item.at, steps: [{ kind: 'close', title: key === 'disconnected_by_admin' ? 'Завершение сервером' : 'Отключение', at: item.at, meta: 'Отключённое состояние без сохранённого старта' }] });
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
  const statusBadge = (status) => status === 'connected' ? pill('ok', 'Подключен') : status === 'disconnected_by_admin' ? pill('warn', 'Отключен сервером') : pill('bad', 'Отключен');
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
  await Promise.all([loadUsersAndSessions(), loadProfiles(), loadHealth()]);
  refreshProfileSelects();
  renderProfiles();
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
  let statusText = 'Нет данных';
  if (pending && report) statusText = 'Ожидается свежий ответ клиента. Последний отчёт: ' + fmtDate(report.generated_at);
  else if (pending) statusText = 'Запрос отправлен. Ожидается ответ клиента…';
  else if (report) statusText = 'Последний отчёт: ' + fmtDate(report.generated_at) + ', приложений: ' + ((report.apps || []).length);
  statusInput.value = statusText;
  if (!apps.length) { rowsEl.innerHTML = '<tr><td colspan="5" class="muted">Нет данных</td></tr>'; return; }
  rowsEl.innerHTML = apps.map(app => '<tr>' + `<td>${esc(app.name || '—')}</td><td>${esc(app.category || 'Другое')}</td><td class="mono">${esc(String(app.pid ?? '—'))}</td><td>${esc(app.uptime || '—')}</td><td class="mono">${esc(app.exe || '—')}</td>` + '</tr>').join('');
}
async function loadAppsView(username) {
  const view = await jget('/api/admin/users/apps?username=' + encodeURIComponent(username));
  appsState = { username, pending: !!view.pending, report: view.report || null };
  renderAppsView();
  if (!appsState.pending && appsPollTimer) { clearInterval(appsPollTimer); appsPollTimer = null; }
}
async function openApps(username) {
  byId('appsUsername').textContent = username || '—'; byId('appsSearch').value = ''; byId('appsCategory').innerHTML = '<option value="">Все категории</option>'; byId('appsRows').innerHTML = '<tr><td colspan="5" class="muted">Ожидание ответа клиента…</td></tr>'; byId('appsStatus').value = 'Отправляем запрос…'; byId('appsBg').style.display = 'flex';
  await jpost('/api/admin/users/request-apps', { username });
  if (appsPollTimer) clearInterval(appsPollTimer);
  appsPollTimer = setInterval(() => { loadAppsView(username).catch(() => {}); }, 2000);
  await loadAppsView(username);
}
function closeApps() { byId('appsBg').style.display = 'none'; if (appsPollTimer) { clearInterval(appsPollTimer); appsPollTimer = null; } }

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


document.addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const user = btn.getAttribute('data-user') || '';
  const pname = btn.getAttribute('data-pname') || '';
  const action = btn.getAttribute('data-action');
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
  if (action === 'editprofile') fillProfileForm(findProfile(pname));
  if (action === 'deleteprofile') await deleteProfile(pname);
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
    await jpost('/api/admin/profiles', payload);
    await loadAll();
    alert('Профиль сохранён');
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
Promise.all([loadSettings().catch(() => {}), loadAll().catch(console.error)]).then(() => renderHealth());
setInterval(() => { loadAll().catch(() => {}); }, 3000);
