const byId = (id) => document.getElementById(id);
let users = [];
let sessions = [];
let API_BASE = localStorage.getItem('tlsctrl_api_base') || 'http://127.0.0.1:9080';

function syncApiBaseUI() {
  byId('apiBase').value = API_BASE;
  byId('apiBaseText').textContent = API_BASE;
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
function statusText(connected) { return connected ? 'Подключен' : 'Отключен'; }
function statusPill(connected) {
  return connected
    ? '<span class="pill pillOk">Подключен</span>'
    : '<span class="pill pillBad">Отключен</span>';
}
function normalizeBase(v) {
  return (v || '').trim().replace(/\/+$/, '');
}
async function jget(path) {
  const r = await fetch(normalizeBase(API_BASE) + path, { cache: 'no-store' });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function jpost(path, body) {
  const r = await fetch(normalizeBase(API_BASE) + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {})
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
function mergedRows() {
  const map = new Map();
  for (const u of users || []) {
    map.set(u.username, {
      username: u.username || '—',
      cert_serial: u.cert_serial || '—',
      last_seen: u.last_seen || '',
      connected: false,
      ip: '—',
      mac: '—',
      system_user: '—',
      os_name: '—',
      os_version: '—',
      system_uptime: '—',
      connected_at: '',
      apps_count: 0
    });
  }
  for (const s of sessions || []) {
    const row = map.get(s.username) || {
      username: s.username || '—',
      cert_serial: s.cert_serial || '—',
      last_seen: ''
    };
    row.connected = !!s.connected;
    row.ip = s.ip || '—';
    row.mac = s.mac || '—';
    row.system_user = s.system_user || '—';
    row.os_name = s.os_name || '—';
    row.os_version = s.os_version || '—';
    row.system_uptime = s.system_uptime || '—';
    row.connected_at = s.connected_at || '';
    row.last_seen = s.last_seen || row.last_seen || '';
    row.apps_count = s.apps_count || 0;
    row.cert_serial = s.cert_serial || row.cert_serial || '—';
    map.set(row.username, row);
  }
  return Array.from(map.values()).sort((a, b) => {
    if (a.connected !== b.connected) return a.connected ? -1 : 1;
    return String(a.username).localeCompare(String(b.username), 'ru');
  });
}
function render() {
  const tbody = byId('rows');
  const rows = mergedRows();
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="11" class="muted">Нет данных</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map((r) => (
    '<tr>' +
      '<td>' + statusPill(r.connected) + '</td>' +
      '<td>' + esc(r.username) + '</td>' +
      '<td class="mono">' + esc(r.ip) + '</td>' +
      '<td class="mono">' + esc(r.mac) + '</td>' +
      '<td>' + esc(r.system_user) + '</td>' +
      '<td>' + esc(r.os_name) + '</td>' +
      '<td>' + esc(r.os_version) + '</td>' +
      '<td>' + esc(r.system_uptime) + '</td>' +
      '<td>' + esc(String(r.apps_count || 0)) + '</td>' +
      '<td>' + esc(fmtDate(r.last_seen)) + '</td>' +
      '<td><div class="actions">' +
        '<button class="iconBtn" data-action="info" data-user="' + esc(r.username) + '">ℹ️</button>' +
        '<button class="iconBtn" data-action="bundle" data-user="' + esc(r.username) + '">📦</button>' +
        '<button class="iconBtn" data-action="reissuebundle" data-user="' + esc(r.username) + '">🔐</button>' +
        '<button class="iconBtn" data-action="disconnect" data-user="' + esc(r.username) + '">⛔</button>' +
        '<button class="iconBtn" data-action="delete" data-user="' + esc(r.username) + '">🗑️</button>' +
      '</div></td>' +
    '</tr>'
  )).join('');
}
function openInfo(username) {
  const row = mergedRows().find(x => x.username === username);
  if (!row) return;
  byId('infoUsername').textContent = row.username || '—';
  byId('infoStatus').textContent = statusText(!!row.connected);
  byId('infoIP').textContent = row.ip || '—';
  byId('infoMAC').textContent = row.mac || '—';
  byId('infoSystemUser').textContent = row.system_user || '—';
  byId('infoOSName').textContent = row.os_name || '—';
  byId('infoOSVersion').textContent = row.os_version || '—';
  byId('infoSystemUptime').textContent = row.system_uptime || '—';
  byId('infoConnectedAt').textContent = fmtDate(row.connected_at);
  byId('infoLastSeen').textContent = fmtDate(row.last_seen);
  byId('infoCertSerial').textContent = row.cert_serial || '—';
  byId('infoAppsCount').textContent = String(row.apps_count || 0);
  byId('infoBg').style.display = 'flex';
}
function closeInfo() { byId('infoBg').style.display = 'none'; }
function downloadBundle(username) {
  window.location.href = normalizeBase(API_BASE) + '/api/admin/bundle?username=' + encodeURIComponent(username);
}
function downloadReissueBundle(username) {
  window.location.href = normalizeBase(API_BASE) + '/api/admin/reissue-bundle?username=' + encodeURIComponent(username);
}
async function loadAll() {
  const [u, s] = await Promise.all([jget('/api/admin/users'), jget('/api/admin/sessions')]);
  users = Array.isArray(u.users) ? u.users : [];
  sessions = Array.isArray(s.sessions) ? s.sessions : [];
  render();
}
async function disconnectSession(username) {
  await jpost('/api/admin/sessions/disconnect', { username });
  await loadAll();
}
async function deleteUser(username) {
  if (!confirm('Удалить пользователя "' + username + '"?')) return;
  await jpost('/api/admin/users/delete', { username });
  await loadAll();
}

document.addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const user = btn.getAttribute('data-user') || '';
  const action = btn.getAttribute('data-action');
  if (action === 'info') openInfo(user);
  if (action === 'bundle') downloadBundle(user);
  if (action === 'reissuebundle') downloadReissueBundle(user);
  if (action === 'disconnect') await disconnectSession(user);
  if (action === 'delete') await deleteUser(user);
});

byId('btnApplyApi').addEventListener('click', async () => {
  API_BASE = normalizeBase(byId('apiBase').value);
  localStorage.setItem('tlsctrl_api_base', API_BASE);
  syncApiBaseUI();
  await loadAll();
});
byId('btnBundle').addEventListener('click', () => downloadBundle(byId('bundleUser').value.trim()));
byId('btnReissueBundle').addEventListener('click', () => downloadReissueBundle(byId('reissueUser').value.trim()));
byId('btnUpsert').addEventListener('click', async () => {
  await jpost('/api/admin/users', {
    username: byId('username').value.trim(),
    cert_serial: byId('certSerial').value.trim(),
    enabled: byId('enabled').value === 'true'
  });
  byId('username').value = '';
  byId('certSerial').value = '';
  await loadAll();
});
byId('btnRefresh').addEventListener('click', loadAll);
byId('btnCloseInfo').addEventListener('click', closeInfo);

syncApiBaseUI();
loadAll();
setInterval(loadAll, 3000);
