/* redir — app.js */

let cfg = {};
let presets = [];

// --- Tab navigation ---

function showTab(name, btn) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  if (name === 'redirects') loadRules();
  if (name === 'rebind') loadRebind();
  if (name === 'hits') loadHits();
  if (name === 'config') loadConfig();
}

// --- Auth ---

function showAuthPane() {
  document.getElementById('auth-pane').style.display = '';
  document.getElementById('app-header').style.display = 'none';
  document.getElementById('main-nav').style.display = 'none';
  document.getElementById('main-content').style.display = 'none';
}

function showApp(me) {
  document.getElementById('auth-pane').style.display = 'none';
  document.getElementById('app-header').style.display = '';
  document.getElementById('main-nav').style.display = '';
  document.getElementById('main-content').style.display = '';

  const ui = document.getElementById('user-info');
  ui.innerHTML = `<span>${escHtml(me.email)}</span>
    <button class="btn secondary small" onclick="logout()">Logout</button>`;
}

function showLogin() {
  document.getElementById('login-card').style.display = '';
  document.getElementById('register-card').style.display = 'none';
  document.getElementById('auth-alert').innerHTML = '';
}

function showRegister() {
  document.getElementById('login-card').style.display = 'none';
  document.getElementById('register-card').style.display = '';
  document.getElementById('auth-alert').innerHTML = '';
}

async function login() {
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  if (!email || !password) { showAuthAlert('Email and password are required'); return; }
  try {
    const me = await api('/api/auth/login', 'POST', { email, password });
    showApp(me);
    initApp();
  } catch(e) { showAuthAlert(e.message); }
}

async function register() {
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  if (!email || !password) { showAuthAlert('Email and password are required'); return; }
  try {
    const me = await api('/api/auth/register', 'POST', { email, password });
    showApp(me);
    initApp();
  } catch(e) { showAuthAlert(e.message); }
}

async function logout() {
  await api('/api/auth/logout', 'POST').catch(() => {});
  showAuthPane();
  showLogin();
}

function showAuthAlert(msg) {
  document.getElementById('auth-alert').innerHTML =
    `<div class="alert error">${escHtml(msg)}</div>`;
}

// --- Init ---

async function init() {
  try {
    const me = await api('/api/auth/me');
    showApp(me);
    initApp();
  } catch(e) {
    showAuthPane();
  }
}

async function initApp() {
  try {
    const [p, c] = await Promise.all([api('/api/presets'), api('/api/config')]);
    presets = p;
    cfg = c;
    const dl = document.getElementById('presets-list');
    dl.innerHTML = '';
    presets.forEach(ps => {
      const opt = document.createElement('option');
      opt.value = ps.url;
      opt.label = ps.name;
      dl.appendChild(opt);
    });
    if (cfg.public_ip) {
      document.getElementById('rb-first-ip').value = cfg.public_ip;
    }
  } catch(e) { console.error('initApp', e); }
  loadRules();
}

// --- API helpers ---

async function api(path, method, body) {
  const opts = { method: method || 'GET', headers: {} };
  if (body) { opts.body = JSON.stringify(body); opts.headers['Content-Type'] = 'application/json'; }
  const r = await fetch(path, opts);
  if (r.status === 204) return null;
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function showAlert(containerId, msg, type) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `<div class="alert ${type}">${escHtml(msg)}</div>`;
  setTimeout(() => { el.innerHTML = ''; }, 4000);
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// --- Type change handler ---

function onTypeChange() {
  const type = document.getElementById('rule-type').value;
  document.getElementById('status-code-group').style.display = type === 'http' ? '' : 'none';
}

// --- Redirect Rules ---

async function loadRules() {
  try {
    const rules = await api('/api/rules');
    renderRules(rules);
  } catch(e) { showAlert('rule-alert', e.message, 'error'); }
}

function renderRules(rules) {
  const cont = document.getElementById('rules-container');
  if (!rules || rules.length === 0) {
    cont.innerHTML = '<div class="empty-state"><p>No rules yet. Create one above.</p></div>';
    return;
  }
  const baseURL = location.origin;
  let html = `<table>
    <thead><tr>
      <th>Label / ID</th>
      <th>Type</th>
      <th>Target URL</th>
      <th>Hits</th>
      <th>Redirect URL</th>
      <th>Actions</th>
    </tr></thead><tbody>`;
  rules.forEach(r => {
    const slug = r.label || r.id;
    const redirectURL = baseURL + '/r/' + encodeURIComponent(slug);
    const typeBadge = typeLabel(r);
    const hitClass = r.hit_count > 0 ? 'has-hits' : '';
    html += `<tr>
      <td class="mono">${escHtml(slug)}</td>
      <td>${typeBadge}</td>
      <td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(r.target_url)}">${escHtml(r.target_url)}</td>
      <td><span class="hit-count ${hitClass}">${r.hit_count}</span></td>
      <td class="mono" style="font-size:11px">${escHtml(redirectURL)} <button class="copy-btn" onclick="copyText(this,'${escHtml(redirectURL)}')">copy</button></td>
      <td><button class="btn danger small" onclick="deleteRule('${escHtml(r.id)}')">Delete</button></td>
    </tr>`;
  });
  html += '</tbody></table>';
  cont.innerHTML = html;
}

function typeLabel(r) {
  if (r.type === 'http') return `<span class="badge http">${r.status_code}</span>`;
  if (r.type === 'meta') return `<span class="badge meta">meta</span>`;
  if (r.type === 'js')   return `<span class="badge js">js</span>`;
  if (r.type === 'proxy') return `<span class="badge proxy">proxy</span>`;
  return escHtml(r.type);
}

async function createRule() {
  const label = document.getElementById('rule-label').value.trim();
  const type  = document.getElementById('rule-type').value;
  const code  = parseInt(document.getElementById('rule-status-code').value, 10);
  const target = document.getElementById('rule-target').value.trim();
  if (!target) { showAlert('rule-alert', 'Target URL is required', 'error'); return; }
  try {
    await api('/api/rules', 'POST', { label, type, status_code: code, target_url: target });
    document.getElementById('rule-label').value = '';
    document.getElementById('rule-target').value = '';
    showAlert('rule-alert', 'Rule created', 'success');
    loadRules();
  } catch(e) { showAlert('rule-alert', e.message, 'error'); }
}

async function deleteRule(id) {
  if (!confirm('Delete this rule?')) return;
  try {
    await api('/api/rules/' + id, 'DELETE');
    loadRules();
  } catch(e) { showAlert('rule-alert', e.message, 'error'); }
}

// --- Rebind Rules ---

async function loadRebind() {
  try {
    const rules = await api('/api/rebind');
    renderRebind(rules);
  } catch(e) { showAlert('rebind-alert', e.message, 'error'); }
}

function renderRebind(rules) {
  const cont = document.getElementById('rebind-container');
  if (!rules || rules.length === 0) {
    cont.innerHTML = '<div class="empty-state"><p>No rebind rules yet. Create one above.</p></div>';
    return;
  }
  let html = `<table>
    <thead><tr>
      <th>Label / ID</th>
      <th>Hostname</th>
      <th>First IP</th>
      <th>Second IP</th>
      <th>Threshold</th>
      <th>Query Count</th>
      <th>Status</th>
      <th>Actions</th>
    </tr></thead><tbody>`;
  rules.forEach(r => {
    const slug = r.label || r.id;
    const dotFlipped = r.flipped ? 'flipped' : 'waiting';
    const statusText = r.flipped ? 'Flipped → ' + r.second_ip : 'Waiting (' + r.query_count + '/' + r.threshold + ')';
    html += `<tr>
      <td class="mono">${escHtml(slug)}</td>
      <td class="mono" style="font-size:11px">${escHtml(r.hostname)} <button class="copy-btn" onclick="copyText(this,'${escHtml(r.hostname)}')">copy</button></td>
      <td class="mono">${escHtml(r.first_ip)}</td>
      <td class="mono">${escHtml(r.second_ip)}</td>
      <td>${r.threshold}</td>
      <td>${r.query_count}</td>
      <td><span class="status-dot ${dotFlipped}"></span>${escHtml(statusText)}</td>
      <td style="display:flex;gap:6px">
        <button class="btn secondary small" onclick="resetRebind('${escHtml(r.id)}')">Reset</button>
        <button class="btn danger small" onclick="deleteRebind('${escHtml(r.id)}')">Delete</button>
      </td>
    </tr>`;
  });
  html += '</tbody></table>';
  cont.innerHTML = html;
}

async function createRebind() {
  const label     = document.getElementById('rb-label').value.trim();
  const firstIP   = document.getElementById('rb-first-ip').value.trim();
  const secondIP  = document.getElementById('rb-second-ip').value.trim();
  const threshold = parseInt(document.getElementById('rb-threshold').value, 10) || 1;
  if (!firstIP || !secondIP) { showAlert('rebind-alert', 'Both IPs are required', 'error'); return; }
  try {
    await api('/api/rebind', 'POST', { label, first_ip: firstIP, second_ip: secondIP, threshold });
    document.getElementById('rb-label').value = '';
    showAlert('rebind-alert', 'Rebind rule created', 'success');
    loadRebind();
  } catch(e) { showAlert('rebind-alert', e.message, 'error'); }
}

async function resetRebind(id) {
  try {
    await api('/api/rebind/' + id + '/reset', 'POST');
    loadRebind();
  } catch(e) { showAlert('rebind-alert', e.message, 'error'); }
}

async function deleteRebind(id) {
  if (!confirm('Delete this rebind rule?')) return;
  try {
    await api('/api/rebind/' + id, 'DELETE');
    loadRebind();
  } catch(e) { showAlert('rebind-alert', e.message, 'error'); }
}

// --- Hits ---

async function loadHits() {
  try {
    const hits = await api('/api/hits');
    renderHits(hits);
  } catch(e) {}
}

function renderHits(hits) {
  const cont = document.getElementById('hits-container');
  if (!hits || hits.length === 0) {
    cont.innerHTML = '<div class="empty-state"><p>No hits recorded yet.</p></div>';
    return;
  }
  let html = `<table class="hits-table">
    <thead><tr><th>Time</th><th>Rule</th><th>Remote IP</th><th>User-Agent</th></tr></thead><tbody>`;
  hits.forEach(h => {
    const ts = new Date(h.timestamp).toLocaleString();
    html += `<tr>
      <td class="timestamp">${escHtml(ts)}</td>
      <td class="mono">${escHtml(h.rule_label || h.rule_id)}</td>
      <td class="mono">${escHtml(h.remote_ip || '')}</td>
      <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(h.user_agent || '')}</td>
    </tr>`;
  });
  html += '</tbody></table>';
  cont.innerHTML = html;
}

// --- Config ---

async function loadConfig() {
  try {
    const c = await api('/api/config');
    cfg = c;
    renderConfig(c);
  } catch(e) {}
}

function renderConfig(c) {
  const cont = document.getElementById('config-container');
  cont.innerHTML = `
    <div class="config-section">
      <h3>Server</h3>
      <div class="config-row"><span class="config-label">HTTP Port</span><span class="config-value">${c.http_port}</span></div>
      <div class="config-row"><span class="config-label">DNS Port</span><span class="config-value">${c.dns_port}</span></div>
      <div class="config-row"><span class="config-label">Bind Address</span><span class="config-value">${escHtml(c.bind_addr)}</span></div>
      <div class="config-row"><span class="config-label">Public IP</span><span class="config-value">${escHtml(c.public_ip || 'unknown')}</span></div>
      <div class="config-row"><span class="config-label">Rebind Domain</span><span class="config-value">${escHtml(c.domain)}</span></div>
    </div>
    <div class="config-section">
      <h3>DNS Rebinding Setup</h3>
      <p style="color:#94a3b8;font-size:13px;margin-bottom:8px">
        For rebinding to work in a real browser, this server must be the authoritative nameserver for <code style="color:#f97316">${escHtml(c.domain)}</code>.
        Set an NS record at your registrar pointing to this machine's IP.
      </p>
      <p style="color:#94a3b8;font-size:12px;margin-bottom:4px">macOS — redirect port 53 → ${c.dns_port} without root:</p>
      <div class="cmd-block">${escHtml(c.pf_cmd)}</div>
      <p style="color:#94a3b8;font-size:12px;margin-bottom:4px;margin-top:12px">Linux — redirect port 53 → ${c.dns_port} without root:</p>
      <div class="cmd-block">${escHtml(c.iptables_cmd)}</div>
    </div>`;
}

// --- Utilities ---

function copyText(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1500);
  });
}

// --- Boot ---
init();
