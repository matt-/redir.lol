/* redir — app.js */

let cfg = {};
let currentUserID = null;
let presets = [];
let adminPage = 1;
let adminTotal = 0;
let adminRbPage = 1;
let adminRbTotal = 0;
const ADMIN_PER_PAGE = 25;

// --- Tab navigation ---

const TAB_PATHS   = { redirects: '/', rebind: '/rebind', hits: '/hits', admin: '/admin' };
const ADMIN_PATHS = { redirects: '/admin', users: '/admin/users', logs: '/admin/logs', config: '/admin/config' };

let rebindPollInterval = null;
let hitsPollInterval = null;

function showTab(name, btn, pushHistory = true) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  if (btn) btn.classList.add('active');
  if (pushHistory) history.pushState({ tab: name }, '', TAB_PATHS[name] || '/');
  if (name === 'redirects') loadRules();
  if (name === 'rebind') { loadRebind(); startRebindPoll(); }
  if (name === 'hits') { loadHits(); loadRebindEvents(); startHitsPoll(); }
  if (name === 'admin') { showAdminPane('redirects', document.querySelector('.admin-sidebar-item'), false); }
  if (name !== 'rebind') stopRebindPoll();
  if (name !== 'hits') { stopHitsPoll(); rebindLogFilterID = null; }
}

function startRebindPoll() {
  stopRebindPoll();
  rebindPollInterval = setInterval(pollRebindCounts, 2000);
}

function stopRebindPoll() {
  if (rebindPollInterval) { clearInterval(rebindPollInterval); rebindPollInterval = null; }
}

function startHitsPoll() {
  stopHitsPoll();
  hitsPollInterval = setInterval(loadRebindEvents, 2000);
}

function stopHitsPoll() {
  if (hitsPollInterval) { clearInterval(hitsPollInterval); hitsPollInterval = null; }
}

async function pollRebindCounts() {
  let rules;
  try { rules = await api('/api/rebind'); } catch(e) { return; }
  rules.forEach(r => {
    const countEl  = document.getElementById('rb-count-'  + r.id);
    const statusEl = document.getElementById('rb-status-' + r.id);
    if (!countEl || !statusEl) return;
    countEl.textContent = r.query_count;
    statusEl.innerHTML  = rebindStatusHtml(r);
  });
}

let rebindLogFilterID = null;

function viewRebindLog(evt, ruleID) {
  if (evt) evt.preventDefault();
  rebindLogFilterID = ruleID;
  showTab('hits', tabBtnFor('hits'));
}

function clearRebindLogFilter() {
  rebindLogFilterID = null;
  renderRebindLogFilterBanner();
  loadRebindEvents();
}

function renderRebindLogFilterBanner() {
  const el = document.getElementById('rebind-log-filter');
  if (!el) return;
  el.innerHTML = rebindLogFilterID
    ? `Filtered to one rebind rule — <a href="#" onclick="clearRebindLogFilter(); return false;">clear</a>`
    : '';
}

async function loadRebindEvents() {
  let events;
  try { events = await api('/api/rebind-events'); } catch(e) { return; }
  if (rebindLogFilterID) events = events.filter(e => e.rule_id === rebindLogFilterID);
  renderRebindLogFilterBanner();
  renderRebindEvents(events);
}

function renderRebindEvents(events) {
  const cont = document.getElementById('rebind-events-container');
  if (!events || events.length === 0) {
    cont.innerHTML = '<div class="empty-state"><p>No DNS queries logged yet.</p></div>';
    return;
  }
  let html = `<table class="hits-table">
    <thead><tr><th>Time</th><th>Label</th><th>Remote</th><th>Resolved IP</th></tr></thead><tbody>`;
  events.forEach(e => {
    html += `<tr>
      <td class="timestamp">${escHtml(formatTimestamp(e.timestamp))}</td>
      <td class="mono">${escHtml(e.label || e.rule_id)}</td>
      <td class="mono">${escHtml(e.remote_addr || '')}</td>
      <td class="mono">${escHtml(e.ip)}</td>
    </tr>`;
  });
  html += '</tbody></table>';
  cont.innerHTML = html;
}

function tabBtnFor(name) {
  const path = TAB_PATHS[name];
  return document.querySelector(`nav button[onclick*="'${name}'"]`);
}

// --- Auth ---

function showAuthPane() {
  document.getElementById('auth-pane').style.display = '';
  document.getElementById('app-header').style.display = 'none';
  document.getElementById('main-nav').style.display = 'none';
  document.getElementById('main-content').style.display = 'none';
}

function showApp(me) {
  currentUserID = me.id;
  document.getElementById('auth-pane').style.display = 'none';
  document.getElementById('app-header').style.display = '';
  document.getElementById('main-nav').style.display = '';
  document.getElementById('main-content').style.display = '';
  document.getElementById('app-footer').style.display = '';

  const ui = document.getElementById('user-info');
  ui.innerHTML = `<span>${escHtml(me.email)}</span>
    <button class="btn secondary small" onclick="logout()">Logout</button>`;
  document.getElementById('admin-tab-btn').style.display = me.is_admin ? '' : 'none';
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

function setBtnLoading(btn, loading, loadingText) {
  if (!btn) return;
  if (loading) {
    btn.dataset.originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span>${loadingText || 'Loading…'}`;
  } else {
    btn.disabled = false;
    if (btn.dataset.originalText) btn.innerHTML = btn.dataset.originalText;
  }
}

async function login(btn) {
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  if (!email || !password) { showAuthAlert('Email and password are required'); return; }
  setBtnLoading(btn, true, 'Signing in…');
  try {
    await api('/api/auth/login', 'POST', { email, password });
    const me = await api('/api/auth/me');
    showApp(me);
    initApp();
  } catch(e) {
    if (e.data && e.data.unverified) {
      document.getElementById('auth-alert').innerHTML =
        `<div class="alert error">${escHtml(e.message)} — <a href="#" onclick="resendVerification(event)">resend verification email</a></div>`;
    } else {
      showAuthAlert(e.message);
    }
  } finally {
    setBtnLoading(btn, false);
  }
}

async function register(btn) {
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  if (!email || !password) { showAuthAlert('Email and password are required'); return; }
  setBtnLoading(btn, true, 'Creating account…');
  try {
    const res = await api('/api/auth/register', 'POST', { email, password });
    if (res && res.pending_verification) {
      showLogin();
      document.getElementById('login-email').value = email;
      showAuthAlert('Account created — check your email for a verification link before signing in.', 'success');
      return;
    }
    const me = await api('/api/auth/me');
    showApp(me);
    initApp();
  } catch(e) { showAuthAlert(e.message); } finally {
    setBtnLoading(btn, false);
  }
}

async function resendVerification(evt) {
  if (evt) evt.preventDefault();
  const email = document.getElementById('login-email').value.trim();
  if (!email) { showAuthAlert('Enter your email above first'); return; }
  try {
    const res = await api('/api/auth/resend', 'POST', { email });
    showAuthAlert(res.message, 'success');
  } catch(e) { showAuthAlert(e.message); }
}

async function logout() {
  await api('/api/auth/logout', 'POST').catch(() => {});
  showAuthPane();
  showLogin();
}

function showAuthAlert(msg, type) {
  document.getElementById('auth-alert').innerHTML =
    `<div class="alert ${type || 'error'}">${escHtml(msg)}</div>`;
}

// --- Init ---

async function init() {
  const params = new URLSearchParams(location.search);
  try {
    const me = await api('/api/auth/me');
    showApp(me);
    initApp(me);
    if (params.get('verified') === '1') {
      showToast('Email verified — you are now signed in.', 'success');
    }
  } catch(e) {
    showAuthPane();
    if (params.get('verify_error') === '1') {
      showAuthAlert('That verification link is invalid or expired. Enter your email and resend below.');
    }
  }
  if (params.has('verified') || params.has('verify_error')) {
    history.replaceState({}, '', location.pathname);
  }
}

function showToast(msg, type) {
  const el = document.createElement('div');
  el.className = `alert ${type || 'success'}`;
  el.style.cssText = 'position:fixed;top:16px;right:16px;z-index:1000;max-width:360px;box-shadow:0 4px 12px rgba(0,0,0,.15)';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

async function initApp(me) {
  try {
    const [p, c] = await Promise.all([api('/api/presets'), api('/api/info')]);
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
    if (cfg.build_commit) {
      document.getElementById('app-footer').textContent = cfg.build_commit;
    }
  } catch(e) { console.error('initApp', e); }

  refreshLabel();
  refreshRbLabel();

  routeFromPath(location.pathname, false);

  window.addEventListener('popstate', () => routeFromPath(location.pathname, false));
}

function routeFromPath(path, pushHistory) {
  if (path.startsWith('/admin')) {
    showTab('admin', tabBtnFor('admin'), pushHistory);
    const pane = path === '/admin/users'  ? 'users'
               : path === '/admin/logs'   ? 'logs'
               : path === '/admin/config' ? 'config'
               : 'redirects';
    showAdminPane(pane, adminPaneBtnFor(pane), pushHistory);
  } else if (path === '/rebind') {
    showTab('rebind', tabBtnFor('rebind'), pushHistory);
  } else if (path === '/hits') {
    showTab('hits', tabBtnFor('hits'), pushHistory);
  } else {
    showTab('redirects', tabBtnFor('redirects'), pushHistory);
  }
}

// --- API helpers ---

async function api(path, method, body) {
  const opts = { method: method || 'GET', headers: {} };
  if (body) { opts.body = JSON.stringify(body); opts.headers['Content-Type'] = 'application/json'; }
  const r = await fetch(path, opts);
  if (r.status === 204) return null;
  const data = await r.json();
  if (!r.ok) {
    const err = new Error(data.error || r.statusText);
    err.data = data;
    throw err;
  }
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

// Consistent MM-DD-YYYY HH:MM:SS timestamp format for all log tables.
function formatTimestamp(ts) {
  const d = new Date(ts);
  const pad = n => String(n).padStart(2, '0');
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())}-${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
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
    cont.innerHTML = '';
    return;
  }
  const baseURL = location.origin;
  const proxyBase = cfg.proxy_domain ? location.protocol + '//' + cfg.proxy_domain : baseURL;
  let html = `<table style="table-layout:fixed">
    <thead><tr>
      <th style="width:340px">Redirect URL</th>
      <th style="width:90px">Type</th>
      <th>Target URL</th>
      <th style="width:70px">Hits</th>
      <th style="width:90px">Actions</th>
    </tr></thead><tbody>`;
  rules.forEach(r => {
    const slug = r.label || r.id;
    const origin = r.type === 'proxy' && cfg.proxy_domain ? proxyBase : baseURL;
    const redirectURL = origin + '/r/' + encodeURIComponent(slug);
    const typeBadge = typeLabel(r);
    const hitClass = r.hit_count > 0 ? 'has-hits' : '';
    html += `<tr>
      <td class="mono" style="font-size:11px;white-space:nowrap">
        <span style="display:inline-block;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle" title="${escHtml(redirectURL)}">${escHtml(redirectURL)}</span>
        <button class="copy-btn" onclick="copyText(this,'${escHtml(redirectURL)}')">copy</button>
      </td>
      <td>${typeBadge}</td>
      <td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(r.target_url)}">${escHtml(r.target_url)}</td>
      <td><span class="hit-count ${hitClass}">${r.hit_count}</span></td>
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

function randomLabel() {
  return Math.random().toString(36).slice(2, 7) + Math.random().toString(36).slice(2, 7);
}

function refreshLabel() {
  document.getElementById('rule-label').value = randomLabel();
}

function refreshRbLabel() {
  document.getElementById('rb-label').value = randomLabel();
}

// Browsers filter <datalist> suggestions to substring-matches of the
// input's current value, so once it holds a full preset URL, reopening the
// list only shows that same match. Clear on focus (matches everything) and
// restore the previous value on blur if nothing was picked.
function datalistShowAll(input) {
  input.dataset.prevValue = input.value;
  input.value = '';
}

function datalistRestoreIfEmpty(input) {
  if (input.value === '' && input.dataset.prevValue) {
    input.value = input.dataset.prevValue;
  }
  delete input.dataset.prevValue;
}

async function createRule() {
  const label = document.getElementById('rule-label').value.trim();
  const type  = document.getElementById('rule-type').value;
  const code  = parseInt(document.getElementById('rule-status-code').value, 10);
  const target = document.getElementById('rule-target').value.trim();
  if (!target) { showAlert('rule-alert', 'Target URL is required', 'error'); return; }
  try {
    await api('/api/rules', 'POST', { label, type, status_code: code, target_url: target });
    refreshLabel();
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

const IP_CURRENT_COLOR = '#4ade80'; // green — currently resolved
const IP_NEXT_COLOR    = '#facc15'; // yellow — will resolve after the next flip
const IP_DONE_COLOR    = '#64748b'; // gray — latched, will never resolve again

// Arrow sits between the two IPs and points at whichever will resolve next
// (the yellow one); the current IP is green. Latch rules that have already
// flipped are permanent — no more "next", so the arrow becomes a dash and
// the other IP grays out instead of staying yellow. The fraction shows
// progress toward the next flip, or the final N/N once a latch rule is done.
function rebindStatusHtml(r) {
  const threshold = r.threshold || 1;
  const latchDone = !r.flip_flop && r.flipped;
  const arrow = latchDone ? '—' : (r.flipped ? '←' : '→');

  let frac;
  if (threshold > 1) {
    if (r.flip_flop) {
      frac = r.query_count === 0 ? 0 : (((r.query_count - 1) % threshold) + 1);
    } else {
      frac = latchDone ? threshold : Math.min(r.query_count, threshold);
    }
  }

  const nextColor = latchDone ? IP_DONE_COLOR : IP_NEXT_COLOR;
  const firstColor  = r.flipped ? nextColor : IP_CURRENT_COLOR;
  const secondColor = r.flipped ? IP_CURRENT_COLOR : nextColor;
  const fracHtml = frac !== undefined ? ` <span class="mono" style="color:#64748b">${frac}/${threshold}</span>` : '';
  const loopHtml = r.flip_flop ? ` <span title="flip-flop: alternates forever">↻</span>` : '';
  return `<span class="mono" style="white-space:nowrap">` +
    `<span style="color:${firstColor}">${escHtml(r.first_ip)}</span> ${arrow} ` +
    `<span style="color:${secondColor}">${escHtml(r.second_ip)}</span></span>${fracHtml}${loopHtml}`;
}

async function loadRebind() {
  try {
    const rules = await api('/api/rebind');
    renderRebind(rules);
  } catch(e) { showAlert('rebind-alert', e.message, 'error'); }
}

function renderRebind(rules) {
  const cont = document.getElementById('rebind-container');
  if (!rules || rules.length === 0) {
    cont.innerHTML = '';
    return;
  }
  let html = `<table>
    <thead><tr>
      <th>Hostname</th>
      <th>Status</th>
      <th>Count</th>
      <th>Actions</th>
    </tr></thead><tbody>`;
  rules.forEach(r => {
    html += `<tr>
      <td class="mono" style="font-size:11px;white-space:nowrap">${escHtml(r.hostname)} <button class="copy-btn" onclick="copyText(this,'${escHtml(r.hostname)}')">copy</button></td>
      <td id="rb-status-${escHtml(r.id)}">${rebindStatusHtml(r)}</td>
      <td><a href="#" id="rb-count-${escHtml(r.id)}" onclick="viewRebindLog(event,'${escHtml(r.id)}')">${r.query_count}</a></td>
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
  const flipFlop  = document.getElementById('rb-flip-flop').checked;
  if (!firstIP || !secondIP) { showAlert('rebind-alert', 'Both IPs are required', 'error'); return; }
  try {
    await api('/api/rebind', 'POST', { label, first_ip: firstIP, second_ip: secondIP, threshold, flip_flop: flipFlop });
    refreshRbLabel();
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

let hitsById = {};

function renderHits(hits) {
  const cont = document.getElementById('hits-container');
  hitsById = {};
  if (!hits || hits.length === 0) {
    cont.innerHTML = '<div class="empty-state"><p>No hits recorded yet.</p></div>';
    return;
  }
  let html = `<table class="hits-table">
    <thead><tr><th>Time</th><th>Label</th><th>Remote IP</th><th>User-Agent</th></tr></thead><tbody>`;
  hits.forEach(h => {
    hitsById[h.id] = h;
    html += `<tr style="cursor:pointer" onclick="showHitDetail(${h.id})">
      <td class="timestamp">${escHtml(formatTimestamp(h.timestamp))}</td>
      <td class="mono">${escHtml(h.rule_label || h.rule_id)}</td>
      <td class="mono">${escHtml(h.remote_ip || '')}</td>
      <td title="${escHtml(h.user_agent || '')}">${escHtml(h.user_agent || '')}</td>
    </tr>`;
  });
  html += '</tbody></table>';
  cont.innerHTML = html;
}

function showHitDetail(id) {
  const h = hitsById[id];
  if (!h) return;
  document.getElementById('hit-detail-meta').textContent =
    `${formatTimestamp(h.timestamp)}  ·  ${h.rule_label || h.rule_id}  ·  ${h.remote_ip || ''}`;
  document.getElementById('hit-detail-raw').textContent = h.raw_request || '(no request captured for this hit)';
  document.getElementById('hit-detail-modal').classList.add('modal-open');
}

function closeHitDetail() {
  document.getElementById('hit-detail-modal').classList.remove('modal-open');
}

// --- Config ---

async function loadConfig() {
  try {
    const c = await api('/api/config');
    cfg = { ...cfg, ...c };
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
  `;
}

// --- Utilities ---

function copyText(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1500);
  });
}

// --- Admin sub-navigation ---

function showAdminPane(name, btn, pushHistory = true) {
  document.querySelectorAll('.admin-pane').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.admin-sidebar-item').forEach(el => el.classList.remove('active'));
  document.getElementById('admin-pane-' + name).style.display = '';
  if (btn) btn.classList.add('active');
  if (pushHistory) history.pushState({ tab: 'admin', pane: name }, '', ADMIN_PATHS[name] || '/admin');
  if (name === 'redirects') { adminPage = 1; adminRbPage = 1; loadAdminRules(); loadAdminRebind(); }
  if (name === 'users')     loadAdminUsers();
  if (name === 'logs')      loadAdminHits();
  if (name === 'config')    loadConfig();
}

function adminPaneBtnFor(name) {
  return document.querySelector(`.admin-sidebar-item[onclick*="'${name}'"]`);
}

// --- Admin ---

async function loadAdminRules() {
  try {
    const data = await api(`/api/admin/rules?page=${adminPage}&per_page=${ADMIN_PER_PAGE}`);
    adminTotal = data.total;
    renderAdminRules(data);
  } catch(e) { showAlert('admin-alert', e.message, 'error'); }
}

function renderAdminRules(data) {
  const cont = document.getElementById('admin-container');
  const { rules, total, page, per_page } = data;

  const start = (page - 1) * per_page + 1;
  const end = Math.min(page * per_page, total);
  document.getElementById('admin-page-info').textContent =
    total === 0 ? 'No rules' : `${start}–${end} of ${total}`;
  document.getElementById('admin-prev-btn').disabled = page <= 1;
  document.getElementById('admin-next-btn').disabled = end >= total;

  if (!rules || rules.length === 0) {
    cont.innerHTML = '<div class="empty-state"><p>No rules found.</p></div>';
    return;
  }

  let html = `<table>
    <thead><tr>
      <th><input type="checkbox" id="admin-select-all" onchange="adminToggleAll(this)"></th>
      <th>Label / ID</th>
      <th>Type</th>
      <th>Target URL</th>
      <th>Owner</th>
      <th>Hits</th>
      <th>Created</th>
      <th>Actions</th>
    </tr></thead><tbody>`;
  rules.forEach(r => {
    const slug = r.label || r.id;
    const created = new Date(r.created_at).toLocaleDateString();
    html += `<tr>
      <td><input type="checkbox" class="admin-rule-cb" value="${escHtml(r.id)}" onchange="adminUpdateDeleteBtn()"></td>
      <td class="mono">${escHtml(slug)}</td>
      <td>${typeLabel(r)}</td>
      <td class="mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(r.target_url)}">${escHtml(r.target_url)}</td>
      <td style="font-size:12px;color:#94a3b8">${escHtml(r.owner_email || '—')}</td>
      <td><span class="hit-count ${r.hit_count > 0 ? 'has-hits' : ''}">${r.hit_count}</span></td>
      <td class="timestamp">${created}</td>
      <td><button class="btn danger small" onclick="adminDeleteRule('${escHtml(r.id)}')">Delete</button></td>
    </tr>`;
  });
  html += '</tbody></table>';
  cont.innerHTML = html;
}

async function adminDeleteRule(id) {
  if (!confirm('Delete this rule? This cannot be undone.')) return;
  try {
    await api('/api/admin/rules/' + id, 'DELETE');
    loadAdminRules();
  } catch(e) { showAlert('admin-alert', e.message, 'error'); }
}

function adminToggleAll(cb) {
  document.querySelectorAll('.admin-rule-cb').forEach(el => el.checked = cb.checked);
  adminUpdateDeleteBtn();
}

function adminUpdateDeleteBtn() {
  const any = [...document.querySelectorAll('.admin-rule-cb')].some(el => el.checked);
  document.getElementById('admin-delete-selected-btn').style.display = any ? '' : 'none';
  const all = [...document.querySelectorAll('.admin-rule-cb')].every(el => el.checked);
  const selectAll = document.getElementById('admin-select-all');
  if (selectAll) selectAll.checked = all;
}

async function adminDeleteSelected() {
  const ids = [...document.querySelectorAll('.admin-rule-cb:checked')].map(el => el.value);
  if (!ids.length) return;
  if (!confirm(`Delete ${ids.length} rule${ids.length > 1 ? 's' : ''}? This cannot be undone.`)) return;
  try {
    await Promise.all(ids.map(id => api('/api/admin/rules/' + id, 'DELETE')));
    loadAdminRules();
  } catch(e) { showAlert('admin-alert', e.message, 'error'); }
}

function adminPrevPage() {
  if (adminPage > 1) { adminPage--; loadAdminRules(); }
}

function adminNextPage() {
  if (adminPage * ADMIN_PER_PAGE < adminTotal) { adminPage++; loadAdminRules(); }
}

// --- Admin: rebind rules ---

async function loadAdminRebind() {
  try {
    const data = await api(`/api/admin/rebind?page=${adminRbPage}&per_page=${ADMIN_PER_PAGE}`);
    adminRbTotal = data.total;
    renderAdminRebind(data);
  } catch(e) { showAlert('admin-alert', e.message, 'error'); }
}

function renderAdminRebind(data) {
  const cont = document.getElementById('admin-rebind-container');
  const { rules, total, page, per_page } = data;

  const start = (page - 1) * per_page + 1;
  const end = Math.min(page * per_page, total);
  document.getElementById('admin-rb-page-info').textContent =
    total === 0 ? 'No rebind rules' : `${start}–${end} of ${total}`;
  document.getElementById('admin-rb-prev-btn').disabled = page <= 1;
  document.getElementById('admin-rb-next-btn').disabled = end >= total;

  if (!rules || rules.length === 0) {
    cont.innerHTML = '<div class="empty-state"><p>No rebind rules found.</p></div>';
    return;
  }

  let html = `<table>
    <thead><tr>
      <th><input type="checkbox" id="admin-rb-select-all" onchange="adminRbToggleAll(this)"></th>
      <th>Hostname</th>
      <th>Status</th>
      <th>Count</th>
      <th>Owner</th>
      <th>Actions</th>
    </tr></thead><tbody>`;
  rules.forEach(r => {
    html += `<tr>
      <td><input type="checkbox" class="admin-rb-cb" value="${escHtml(r.id)}" onchange="adminRbUpdateDeleteBtn()"></td>
      <td class="mono" style="font-size:11px;white-space:nowrap">${escHtml(r.hostname)}</td>
      <td>${rebindStatusHtml(r)}</td>
      <td>${r.query_count}</td>
      <td style="font-size:12px;color:#94a3b8">${escHtml(r.owner_email || '—')}</td>
      <td><button class="btn danger small" onclick="adminDeleteRebind('${escHtml(r.id)}')">Delete</button></td>
    </tr>`;
  });
  html += '</tbody></table>';
  cont.innerHTML = html;
}

async function adminDeleteRebind(id) {
  if (!confirm('Delete this rebind rule? This cannot be undone.')) return;
  try {
    await api('/api/admin/rebind/' + id, 'DELETE');
    loadAdminRebind();
  } catch(e) { showAlert('admin-alert', e.message, 'error'); }
}

function adminRbToggleAll(cb) {
  document.querySelectorAll('.admin-rb-cb').forEach(el => el.checked = cb.checked);
  adminRbUpdateDeleteBtn();
}

function adminRbUpdateDeleteBtn() {
  const any = [...document.querySelectorAll('.admin-rb-cb')].some(el => el.checked);
  document.getElementById('admin-rb-delete-selected-btn').style.display = any ? '' : 'none';
  const all = [...document.querySelectorAll('.admin-rb-cb')].every(el => el.checked);
  const selectAll = document.getElementById('admin-rb-select-all');
  if (selectAll) selectAll.checked = all;
}

async function adminRbDeleteSelected() {
  const ids = [...document.querySelectorAll('.admin-rb-cb:checked')].map(el => el.value);
  if (!ids.length) return;
  if (!confirm(`Delete ${ids.length} rebind rule${ids.length > 1 ? 's' : ''}? This cannot be undone.`)) return;
  try {
    await Promise.all(ids.map(id => api('/api/admin/rebind/' + id, 'DELETE')));
    loadAdminRebind();
  } catch(e) { showAlert('admin-alert', e.message, 'error'); }
}

// --- Admin: hit log ---

async function loadAdminHits() {
  try {
    const hits = await api('/api/admin/hits');
    renderAdminHits(hits);
  } catch(e) { showAlert('admin-alert', e.message, 'error'); }
}

function renderAdminHits(hits) {
  const cont = document.getElementById('admin-hits-container');
  if (!hits || hits.length === 0) {
    cont.innerHTML = '<div class="empty-state"><p>No hits recorded yet.</p></div>';
    return;
  }
  let html = `<table class="hits-table">
    <thead><tr><th>Time</th><th>Label</th><th>Remote IP</th><th>User-Agent</th></tr></thead><tbody>`;
  hits.forEach(h => {
    html += `<tr>
      <td class="timestamp">${escHtml(formatTimestamp(h.timestamp))}</td>
      <td class="mono">${escHtml(h.rule_label || h.rule_id)}</td>
      <td class="mono">${escHtml(h.remote_ip || '')}</td>
      <td title="${escHtml(h.user_agent || '')}">${escHtml(h.user_agent || '')}</td>
    </tr>`;
  });
  html += '</tbody></table>';
  cont.innerHTML = html;
}

// --- Admin: users ---

async function loadAdminUsers() {
  try {
    const users = await api('/api/admin/users');
    renderAdminUsers(users);
  } catch(e) { showAlert('admin-alert', e.message, 'error'); }
}

function renderAdminUsers(users) {
  const cont = document.getElementById('admin-users-container');
  if (!users || users.length === 0) {
    cont.innerHTML = '<div class="empty-state"><p>No users found.</p></div>';
    return;
  }
  let html = `<table>
    <thead><tr>
      <th><input type="checkbox" id="admin-usr-select-all" onchange="adminUsrToggleAll(this)"></th>
      <th>Email</th>
      <th>Verified</th>
      <th>Admin</th>
      <th>ID</th>
      <th>Created</th>
      <th>Actions</th>
    </tr></thead><tbody>`;
  users.forEach(u => {
    const created = new Date(u.created_at).toLocaleDateString();
    html += `<tr>
      <td><input type="checkbox" class="admin-usr-cb" value="${escHtml(u.id)}" onchange="adminUsrUpdateDeleteBtn()"></td>
      <td>${escHtml(u.email)}</td>
      <td>${u.email_verified ? '✓' : '—'}</td>
      <td>${u.is_admin ? '✓' : '—'}</td>
      <td class="mono" style="font-size:11px;color:#64748b">${escHtml(u.id)}</td>
      <td class="timestamp">${created}</td>
      <td style="display:flex;gap:6px">
        <button class="btn secondary small" onclick="openUserEdit('${escHtml(u.id)}','${escHtml(u.email)}',${!!u.is_admin})">Edit</button>
        <button class="btn danger small" onclick="adminDeleteUser('${escHtml(u.id)}')">Delete</button>
      </td>
    </tr>`;
  });
  html += '</tbody></table>';
  cont.innerHTML = html;
}

function openUserEdit(id, email, isAdmin) {
  const isSelf = id === currentUserID;
  document.getElementById('user-edit-id').value = id;
  document.getElementById('user-edit-email').value = email;
  document.getElementById('user-edit-password').value = '';
  document.getElementById('user-edit-title').textContent = `Edit: ${email}`;
  const adminCb = document.getElementById('user-edit-admin');
  adminCb.checked = !!isAdmin;
  adminCb.disabled = isSelf;
  document.getElementById('user-edit-admin-hint').style.display = isSelf ? '' : 'none';
  document.getElementById('user-edit-modal').classList.add('modal-open');
}

function closeUserEdit() {
  document.getElementById('user-edit-modal').classList.remove('modal-open');
}

async function adminSaveUser() {
  const id       = document.getElementById('user-edit-id').value;
  const email    = document.getElementById('user-edit-email').value.trim();
  const password = document.getElementById('user-edit-password').value;
  const isAdmin  = document.getElementById('user-edit-admin').checked;
  if (!email) { showAlert('admin-alert', 'Email is required', 'error'); closeUserEdit(); return; }
  try {
    await api('/api/admin/users/' + id, 'PUT', { email, password: password || undefined, is_admin: isAdmin });
    closeUserEdit();
    loadAdminUsers();
  } catch(e) { showAlert('admin-alert', e.message, 'error'); closeUserEdit(); }
}

async function adminDeleteUser(id) {
  if (!confirm('Delete this user? Their rules will be disowned but not deleted.')) return;
  try {
    await api('/api/admin/users/' + id, 'DELETE');
    loadAdminUsers();
  } catch(e) { showAlert('admin-alert', e.message, 'error'); }
}

function adminUsrToggleAll(cb) {
  document.querySelectorAll('.admin-usr-cb').forEach(el => el.checked = cb.checked);
  adminUsrUpdateDeleteBtn();
}

function adminUsrUpdateDeleteBtn() {
  const any = [...document.querySelectorAll('.admin-usr-cb')].some(el => el.checked);
  document.getElementById('admin-usr-delete-selected-btn').style.display = any ? '' : 'none';
  const all = [...document.querySelectorAll('.admin-usr-cb')].every(el => el.checked);
  const selectAll = document.getElementById('admin-usr-select-all');
  if (selectAll) selectAll.checked = all;
}

async function adminUsrDeleteSelected() {
  const ids = [...document.querySelectorAll('.admin-usr-cb:checked')].map(el => el.value);
  if (!ids.length) return;
  if (!confirm(`Delete ${ids.length} user${ids.length > 1 ? 's' : ''}? Their rules will be disowned but not deleted.`)) return;
  try {
    await Promise.all(ids.map(id => api('/api/admin/users/' + id, 'DELETE')));
    loadAdminUsers();
  } catch(e) { showAlert('admin-alert', e.message, 'error'); }
}

function adminRbPrevPage() {
  if (adminRbPage > 1) { adminRbPage--; loadAdminRebind(); }
}

function adminRbNextPage() {
  if (adminRbPage * ADMIN_PER_PAGE < adminRbTotal) { adminRbPage++; loadAdminRebind(); }
}

// --- Boot ---
init();
