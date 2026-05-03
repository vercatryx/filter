const API_BASE = window.FILTER_API_BASE || 'http://localhost:4000';
const TOKEN_KEY = 'filter.adminToken';

const PARENTAL_CATEGORIES = [
  { id: 'porn', label: 'Pornography' },
  { id: 'gambling', label: 'Gambling' },
  { id: 'dating', label: 'Dating' },
  { id: 'piracy', label: 'Piracy' },
  { id: 'social-networks', label: 'Social Networks' },
  { id: 'gaming', label: 'Gaming' },
];

const state = {
  token: localStorage.getItem(TOKEN_KEY) || null,
  admin: null,
  view: 'pending',
  authMode: 'login',
  pending: [],
  history: [],
  users: [],
  loading: false,
  error: null,
  modal: null,
  config: null,
  // v1 settings view
  settingsUser: null,
  settings: null,
  allowlist: [],
  denylist: [],
  settingsError: null,
  removalPassword: null,
  // v2 proxy state
  proxyUsers: [],
  proxyPending: [],
  proxyActivity: [],
  proxyBlocklist: [],
  proxySettingsUser: null,
  proxyProfileBlocklist: [],
  proxyProfileAllowlist: [],
  proxyCreds: null,
  proxyStatus: null,
  proxyError: null,
};

function setToken(token, admin) {
  state.token = token;
  state.admin = admin;
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(API_BASE + path, { ...opts, headers });
  if (res.status === 401) {
    setToken(null, null);
    state.view = 'login';
    render();
    throw new Error('Session expired — please log in again');
  }
  const ctype = res.headers.get('content-type') || '';
  const data = ctype.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    const msg = (data && data.error) || `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'on' && v && typeof v === 'object') {
      for (const [evt, fn] of Object.entries(v)) node.addEventListener(evt, fn);
    } else if (k === 'html') node.innerHTML = v;
    else if (v === true) node.setAttribute(k, '');
    else if (v === false || v == null) {} // skip
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

function fmtDate(s) {
  if (!s) return '—';
  const d = new Date(s.endsWith('Z') ? s : s + 'Z');
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleString();
}

function relTime(s) {
  if (!s) return '';
  const d = new Date(s.endsWith('Z') ? s : s + 'Z');
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

/* ---------- Auth (login + signup) ---------- */

function renderAuth() {
  const isSignup = state.authMode === 'signup';
  return el('div', { class: 'login-wrap' },
    el('div', { class: 'login-card' },
      el('h1', {}, isSignup ? 'Create Account' : 'Filter Admin'),
      state.error && el('div', { class: 'error' }, state.error),
      el('form', {
        on: {
          submit: async (e) => {
            e.preventDefault();
            state.error = null;
            const email = e.target.email.value.trim();
            const password = e.target.password.value;
            const name = isSignup ? e.target.name.value.trim() : null;
            const path = isSignup ? '/api/auth/register' : '/api/auth/login';
            const body = isSignup ? { name, email, password } : { email, password };
            try {
              const data = await api(path, { method: 'POST', body: JSON.stringify(body) });
              setToken(data.token, data.admin);
              state.view = 'pending';
              await loadCurrentView();
            } catch (err) {
              state.error = err.message;
              render();
            }
          },
        },
      },
        isSignup && el('div', { class: 'field' },
          el('label', { for: 'name' }, 'Name'),
          el('input', { id: 'name', name: 'name', autocomplete: 'name' }),
        ),
        el('div', { class: 'field' },
          el('label', { for: 'email' }, 'Email'),
          el('input', { id: 'email', name: 'email', type: 'email', required: true, autocomplete: 'username' }),
        ),
        el('div', { class: 'field' },
          el('label', { for: 'password' }, 'Password' + (isSignup ? ' (8+ characters)' : '')),
          el('input', { id: 'password', name: 'password', type: 'password', required: true, autocomplete: isSignup ? 'new-password' : 'current-password' }),
        ),
        el('button', { class: 'primary', type: 'submit', style: 'width:100%;margin-top:8px;' },
          isSignup ? 'Create Account' : 'Sign In'),
      ),
      el('div', { style: 'text-align:center;margin-top:16px;font-size:13px;color:#9aa0b4;' },
        isSignup
          ? el('a', { href: '#', on: { click: (e) => { e.preventDefault(); state.authMode = 'login'; state.error = null; render(); } } }, 'Already have an account? Sign in')
          : el('a', { href: '#', on: { click: (e) => { e.preventDefault(); state.authMode = 'signup'; state.error = null; render(); } } }, "Don't have an account? Sign up"),
      ),
    ),
  );
}

/* ---------- Sidebar ---------- */

function sidebar() {
  const link = (id, label, alsoActiveOn) => {
    const active = state.view === id || (alsoActiveOn || []).includes(state.view);
    return el('div', {
      class: 'nav-link' + (active ? ' active' : ''),
      on: { click: () => switchView(id) },
    }, label);
  };
  const sectionLabel = (text) => el('div', { class: 'nav-section' }, text);

  return el('div', { class: 'sidebar' },
    el('div', { class: 'brand' }, '🛡️ Filter'),

    sectionLabel('NextDNS'),
    link('pending', 'Pending Requests'),
    link('users', 'Profiles', ['settings']),
    link('history', 'Request History'),

    sectionLabel('Proxy'),
    link('proxy-pending', 'Pending Requests'),
    link('proxy-users', 'Proxy Profiles', ['proxy-settings']),
    link('proxy-activity', 'Activity'),
    link('proxy-blocklist', 'Default Blocklist'),

    el('div', { class: 'sidebar-footer' },
      state.admin ? el('div', {}, state.admin.name || state.admin.email) : null,
      el('button', {
        on: { click: () => { setToken(null, null); state.view = 'login'; render(); } },
      }, 'Sign out'),
    ),
  );
}

async function switchView(view) {
  state.view = view;
  state.error = null;
  state.proxyError = null;
  state.settingsUser = null;
  state.proxySettingsUser = null;
  render();
  await loadCurrentView();
}

async function loadCurrentView() {
  state.loading = true;
  state.error = null;
  render();
  try {
    if (state.view === 'pending') {
      state.pending = (await api('/api/requests?status=pending')).requests;
    } else if (state.view === 'history') {
      state.history = (await api('/api/requests')).requests.filter((r) => r.status !== 'pending');
    } else if (state.view === 'users') {
      state.users = (await api('/api/users')).users;
    } else if (state.view === 'proxy-pending') {
      state.proxyPending = (await api('/api/proxy-filter/requests?status=pending')).requests;
    } else if (state.view === 'proxy-activity') {
      state.proxyActivity = (await api('/api/proxy-filter/requests')).requests;
    } else if (state.view === 'proxy-users') {
      const [users, status] = await Promise.all([
        api('/api/proxy-filter/users'),
        api('/api/proxy-filter/status').catch(() => null),
      ]);
      state.proxyUsers = users.users;
      state.proxyStatus = status;
    } else if (state.view === 'proxy-blocklist') {
      const [blocklist, status] = await Promise.all([
        api('/api/proxy-filter/blocklist'),
        api('/api/proxy-filter/status').catch(() => null),
      ]);
      state.proxyBlocklist = blocklist.items || [];
      state.proxyStatus = status;
    }
  } catch (err) {
    state.error = err.message;
  } finally {
    state.loading = false;
    render();
  }
}

/* ---------- Pending Requests ---------- */

function renderPending() {
  const list = state.pending;
  return el('div', {},
    el('div', { class: 'page-header' }, el('h2', {}, 'Pending Requests')),
    state.error && el('div', { class: 'error' }, state.error),
    state.loading ? el('div', { class: 'empty' }, 'Loading…')
      : list.length === 0 ? el('div', { class: 'empty' }, 'No pending requests.')
      : el('div', {}, list.map(renderRequestCard)),
  );
}

function renderRequestCard(r) {
  return el('div', { class: 'card' },
    el('div', { class: 'row' },
      el('div', { style: 'flex:1;' },
        el('div', { style: 'font-weight:600;font-size:15px;' },
          r.user_name || '—',
          el('span', { style: 'color:#6b7290;font-weight:400;margin-left:8px;' }, '→ ' + r.domain),
        ),
        el('div', { class: 'meta' }, (r.user_email || '') + ' · ' + relTime(r.requested_at)),
        r.reason && el('div', { class: 'reason' }, r.reason),
      ),
      el('div', { class: 'actions' },
        el('button', { class: 'success', on: { click: () => decide(r.id, 'approved') } }, 'Approve'),
        el('button', { class: 'danger', on: { click: () => decide(r.id, 'denied') } }, 'Deny'),
      ),
    ),
  );
}

async function decide(id, status) {
  try {
    await api('/api/requests/' + id, { method: 'PATCH', body: JSON.stringify({ status }) });
    state.pending = state.pending.filter((r) => r.id !== id);
    render();
  } catch (err) {
    state.error = err.message;
    render();
  }
}

/* ---------- Users / Profiles ---------- */

function renderUsers() {
  return el('div', {},
    el('div', { class: 'page-header' },
      el('h2', {}, 'Profiles'),
      el('button', {
        class: 'primary',
        on: { click: () => { state.modal = 'newUser'; render(); } },
      }, 'New Profile'),
    ),
    state.error && el('div', { class: 'error' }, state.error),
    state.loading ? el('div', { class: 'empty' }, 'Loading…')
      : state.users.length === 0 ? el('div', { class: 'empty' }, 'No profiles yet. Create one to get started.')
      : el('div', { class: 'table-card' },
          el('table', {},
            el('thead', {},
              el('tr', {},
                el('th', {}, 'Name'),
                el('th', {}, 'Email'),
                el('th', {}, 'NextDNS Profile'),
                el('th', {}, 'Created'),
                el('th', {}, ''),
              ),
            ),
            el('tbody', {}, state.users.map(renderUserRow)),
          ),
        ),
    state.modal === 'newUser' && renderNewUserModal(),
  );
}

function renderUserRow(u) {
  return el('tr', {},
    el('td', {}, u.name),
    el('td', {}, u.email),
    el('td', { style: 'font-family:ui-monospace,monospace;font-size:13px;color:#9aa0b4;' }, u.nextdns_profile_id),
    el('td', {}, fmtDate(u.created_at)),
    el('td', { style: 'text-align:right;' },
      el('div', { class: 'actions', style: 'justify-content:flex-end;' },
        el('button', { class: 'ghost', on: { click: () => openSettings(u) } }, 'Settings'),
        el('button', { class: 'ghost', on: { click: () => downloadProfile(u) } }, 'Download'),
        el('button', { class: 'danger', on: { click: () => deleteUser(u) } }, 'Delete'),
      ),
    ),
  );
}

async function downloadProfile(user) {
  try {
    const res = await fetch(API_BASE + `/api/users/${user.id}/profile`, {
      headers: { Authorization: `Bearer ${state.token}` },
    });
    if (!res.ok) throw new Error(`Download failed (${res.status})`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (user.name.replace(/[^a-z0-9]+/gi, '_').toLowerCase() || 'user') + '.mobileconfig';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    state.error = err.message;
    render();
  }
}

async function deleteUser(user) {
  if (!confirm(`Delete ${user.name}? This will remove their NextDNS profile and all request history.`)) return;
  try {
    await api('/api/users/' + user.id, { method: 'DELETE' });
    state.users = state.users.filter((u) => u.id !== user.id);
    render();
  } catch (err) {
    state.error = err.message;
    render();
  }
}

function renderNewUserModal() {
  return el('div', {
    class: 'modal-overlay',
    on: { click: (e) => { if (e.target.classList.contains('modal-overlay')) { state.modal = null; render(); } } },
  },
    el('div', { class: 'modal' },
      el('h3', {}, 'New Profile'),
      el('p', { style: 'color:#9aa0b4;font-size:13px;margin:0 0 16px;' },
        'A NextDNS profile will be created with safe defaults. You can customize what is blocked from the Settings page after creation.'),
      el('form', {
        on: {
          submit: async (e) => {
            e.preventDefault();
            const name = e.target.name.value.trim();
            const email = e.target.email.value.trim();
            const submitBtn = e.target.querySelector('button[type=submit]');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating…';
            try {
              await api('/api/users', { method: 'POST', body: JSON.stringify({ name, email }) });
              state.modal = null;
              await loadCurrentView();
            } catch (err) {
              state.error = err.message;
              submitBtn.disabled = false;
              submitBtn.textContent = 'Create';
              render();
            }
          },
        },
      },
        el('div', { class: 'field' },
          el('label', { for: 'name' }, 'Profile name'),
          el('input', { id: 'name', name: 'name', required: true, placeholder: 'e.g. Sarah, Family iPad' }),
        ),
        el('div', { class: 'field' },
          el('label', { for: 'email' }, 'Email'),
          el('input', { id: 'email', name: 'email', type: 'email', required: true }),
        ),
        el('div', { class: 'modal-actions' },
          el('button', { class: 'ghost', type: 'button', on: { click: () => { state.modal = null; render(); } } }, 'Cancel'),
          el('button', { class: 'primary', type: 'submit' }, 'Create'),
        ),
      ),
    ),
  );
}

/* ---------- Profile settings view ---------- */

async function openSettings(user) {
  state.view = 'settings';
  state.settingsUser = user;
  state.settings = null;
  state.allowlist = [];
  state.denylist = [];
  state.settingsError = null;
  state.removalPassword = null;
  render();
  await loadSettings();
}

async function loadSettings() {
  if (!state.settingsUser) return;
  state.loading = true;
  render();
  try {
    const [settings, allow, deny] = await Promise.all([
      api(`/api/users/${state.settingsUser.id}/settings`),
      api(`/api/users/${state.settingsUser.id}/allowlist`),
      api(`/api/users/${state.settingsUser.id}/denylist`),
    ]);
    state.settings = settings;
    state.allowlist = allow.items || [];
    state.denylist = deny.items || [];
  } catch (err) {
    state.settingsError = err.message;
  } finally {
    state.loading = false;
    render();
  }
}

function renderSettings() {
  if (!state.settingsUser) return el('div', { class: 'empty' }, 'No profile selected.');

  return el('div', {},
    el('div', { class: 'page-header' },
      el('div', {},
        el('div', { style: 'font-size:13px;color:#9aa0b4;margin-bottom:4px;' },
          el('a', { href: '#', on: { click: (e) => { e.preventDefault(); switchView('users'); } } }, '← Back to profiles'),
        ),
        el('h2', {}, state.settingsUser.name + ' — Settings'),
        el('div', { class: 'meta' }, 'NextDNS profile: ' + state.settingsUser.nextdns_profile_id),
      ),
    ),
    state.settingsError && el('div', { class: 'error' }, state.settingsError),
    state.loading && !state.settings ? el('div', { class: 'empty' }, 'Loading…')
      : el('div', {},
          renderRequestUrlCard(),
          renderSettingsCategoriesCard(),
          renderListCard('allowlist', 'Allowlist', state.allowlist,
            'Domains here are always allowed even if they would otherwise be blocked.'),
          renderListCard('denylist', 'Denylist', state.denylist,
            'Domains here are always blocked, on top of category-based blocking.'),
          renderRemovalPasswordCard(),
        ),
  );
}

function renderSettingsCategoriesCard() {
  const parental = state.settings?.parental || {};
  const security = state.settings?.security || {};
  const blocked = new Set(state.settings?.categories || []);
  const adBlockingEnabled = !!state.settings?.adBlockingEnabled;

  const toggle = (key, label, value, onChange) =>
    el('label', { class: 'toggle-row' },
      el('input', { type: 'checkbox', checked: !!value, on: { change: (e) => onChange(e.target.checked) } }),
      el('span', {}, label),
    );

  return el('div', { class: 'card' },
    el('h3', { style: 'margin:0 0 16px;font-size:16px;' }, 'Filtering'),
    el('div', { style: 'display:grid;grid-template-columns:repeat(2,1fr);gap:8px 24px;' },
      PARENTAL_CATEGORIES.map((c) =>
        toggle('cat-' + c.id, c.label, blocked.has(c.id), async (checked) => {
          await toggleCategory(c.id, checked);
        }),
      ),
    ),
    el('div', { style: 'border-top:1px solid #2a2e3f;margin:16px 0;' }),
    el('div', { style: 'display:grid;grid-template-columns:repeat(2,1fr);gap:8px 24px;' },
      toggle('safe-search', 'Force Safe Search', parental.safeSearch, async (checked) => {
        await patchSettings({ parental: { safeSearch: checked } });
      }),
      toggle('youtube', 'YouTube Restricted Mode', parental.youtubeRestrictedMode, async (checked) => {
        await patchSettings({ parental: { youtubeRestrictedMode: checked } });
      }),
      toggle('block-bypass', 'Block VPNs / Proxy bypass', parental.blockBypass, async (checked) => {
        await patchSettings({ parental: { blockBypass: checked } });
      }),
      toggle('safe-browsing', 'Google Safe Browsing', security.googleSafeBrowsing, async (checked) => {
        await patchSettings({ security: { googleSafeBrowsing: checked } });
      }),
      toggle('threat-intel', 'Threat Intelligence Feeds', security.threatIntelligenceFeeds, async (checked) => {
        await patchSettings({ security: { threatIntelligenceFeeds: checked } });
      }),
      toggle('ad-blocking', 'Ad Blocking (NextDNS recommended list)', adBlockingEnabled, async (checked) => {
        await patchSettings({ adBlocking: checked });
      }),
    ),
  );
}

async function toggleCategory(catId, enabled) {
  state.settingsError = null;
  try {
    if (enabled) {
      await api(`/api/users/${state.settingsUser.id}/categories`, {
        method: 'POST',
        body: JSON.stringify({ id: catId }),
      });
    } else {
      await api(`/api/users/${state.settingsUser.id}/categories/${encodeURIComponent(catId)}`, {
        method: 'DELETE',
      });
    }
    const cats = new Set(state.settings.categories || []);
    if (enabled) cats.add(catId); else cats.delete(catId);
    state.settings.categories = Array.from(cats);
    render();
  } catch (err) {
    state.settingsError = err.message;
    render();
  }
}

async function patchSettings(patch) {
  state.settingsError = null;
  try {
    await api(`/api/users/${state.settingsUser.id}/settings`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    });
    state.settings = state.settings || { security: {}, parental: {} };
    if (patch.security) state.settings.security = { ...state.settings.security, ...patch.security };
    if (patch.parental) state.settings.parental = { ...state.settings.parental, ...patch.parental };
    if (typeof patch.adBlocking === 'boolean') state.settings.adBlockingEnabled = patch.adBlocking;
    render();
  } catch (err) {
    state.settingsError = err.message;
    render();
  }
}

function renderListCard(kind, title, items, helpText) {
  const inputId = 'add-' + kind;
  return el('div', { class: 'card' },
    el('div', { class: 'row' },
      el('div', { style: 'flex:1;' },
        el('h3', { style: 'margin:0 0 4px;font-size:16px;' }, title),
        el('div', { class: 'meta' }, helpText),
      ),
    ),
    el('form', {
      style: 'display:flex;gap:8px;margin-top:12px;',
      on: {
        submit: async (e) => {
          e.preventDefault();
          const inp = document.getElementById(inputId);
          const domain = inp.value.trim();
          if (!domain) return;
          await addToList(kind, domain);
          inp.value = '';
        },
      },
    },
      el('input', { id: inputId, placeholder: 'example.com', style: 'flex:1;' }),
      el('button', { class: 'primary', type: 'submit' }, 'Add'),
    ),
    items.length === 0
      ? el('div', { class: 'meta', style: 'margin-top:12px;' }, 'No domains yet.')
      : el('div', { style: 'margin-top:12px;' },
          items.map((item) => {
            const domain = item.id || item.domain || item;
            return el('div', { class: 'list-item' },
              el('span', { style: 'font-family:ui-monospace,monospace;font-size:13px;' }, domain),
              el('button', {
                class: 'danger',
                on: { click: () => removeFromList(kind, domain) },
              }, 'Remove'),
            );
          }),
        ),
  );
}

async function addToList(kind, domain) {
  state.settingsError = null;
  try {
    await api(`/api/users/${state.settingsUser.id}/${kind}`, {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
    await loadSettings();
  } catch (err) {
    state.settingsError = err.message;
    render();
  }
}

async function removeFromList(kind, domain) {
  state.settingsError = null;
  try {
    await api(`/api/users/${state.settingsUser.id}/${kind}/${encodeURIComponent(domain)}`, {
      method: 'DELETE',
    });
    await loadSettings();
  } catch (err) {
    state.settingsError = err.message;
    render();
  }
}

function renderRequestUrlCard() {
  const blockPageUrl = state.config?.blockPageUrl || 'http://localhost:5174';
  const url = `${blockPageUrl}?profile=${encodeURIComponent(state.settingsUser.nextdns_profile_id)}`;
  return el('div', { class: 'card' },
    el('div', { class: 'row' },
      el('div', { style: 'flex:1;' },
        el('h3', { style: 'margin:0 0 4px;font-size:16px;' }, 'Request Access URL'),
        el('div', { class: 'meta' },
          'Share this with the person using this profile. NextDNS shows its own block page when a site is blocked, so they should bookmark this URL and visit it to request access.'),
      ),
    ),
    el('div', { style: 'margin-top:12px;display:flex;gap:8px;align-items:center;' },
      el('code', {
        style: 'flex:1;background:#14161e;border:1px solid #2a2e3f;border-radius:8px;padding:10px 12px;font-family:ui-monospace,monospace;font-size:13px;word-break:break-all;',
      }, url),
      el('button', {
        class: 'ghost',
        on: { click: () => { navigator.clipboard.writeText(url); } },
      }, 'Copy'),
      el('a', {
        class: 'ghost',
        href: url,
        target: '_blank',
        rel: 'noopener',
        style: 'text-decoration:none;display:inline-block;line-height:18px;',
      }, 'Open'),
    ),
  );
}

function renderRemovalPasswordCard() {
  const pw = state.removalPassword;
  return el('div', { class: 'card' },
    el('div', { class: 'row' },
      el('div', { style: 'flex:1;' },
        el('h3', { style: 'margin:0 0 4px;font-size:16px;' }, 'Profile Removal Password'),
        el('div', { class: 'meta' },
          'Required to uninstall the configuration profile from a Mac/iPhone (System Settings → Profiles → Remove). Save this somewhere safe.'),
      ),
    ),
    el('div', { style: 'margin-top:12px;display:flex;gap:8px;align-items:center;' },
      pw
        ? [
            el('code', {
              style: 'flex:1;background:#14161e;border:1px solid #2a2e3f;border-radius:8px;padding:10px 12px;font-family:ui-monospace,monospace;font-size:13px;word-break:break-all;',
            }, pw),
            el('button', {
              class: 'ghost',
              on: { click: () => { navigator.clipboard.writeText(pw); } },
            }, 'Copy'),
            el('button', {
              class: 'ghost',
              on: { click: () => { state.removalPassword = null; render(); } },
            }, 'Hide'),
          ]
        : el('button', {
            class: 'primary',
            on: { click: () => revealRemovalPassword() },
          }, 'Reveal Password'),
    ),
  );
}

async function revealRemovalPassword() {
  state.settingsError = null;
  try {
    const data = await api(`/api/users/${state.settingsUser.id}/removal-password`);
    state.removalPassword = data.removal_password;
    render();
  } catch (err) {
    state.settingsError = err.message;
    render();
  }
}

/* ---------- History ---------- */

const historyFilter = { user: '', status: '' };

function renderHistory() {
  let rows = state.history;
  if (historyFilter.user) rows = rows.filter((r) => r.user_id === historyFilter.user);
  if (historyFilter.status) rows = rows.filter((r) => r.status === historyFilter.status);

  const userOptions = [...new Map(state.history.map((r) => [r.user_id, r.user_name])).entries()];

  return el('div', {},
    el('div', { class: 'page-header' }, el('h2', {}, 'Request History')),
    state.error && el('div', { class: 'error' }, state.error),
    el('div', { class: 'filters' },
      el('div', { class: 'field' },
        el('label', {}, 'Profile'),
        el('select', {
          on: { change: (e) => { historyFilter.user = e.target.value; render(); } },
        },
          el('option', { value: '' }, 'All profiles'),
          userOptions.map(([id, name]) =>
            el('option', { value: id, selected: historyFilter.user === id }, name)
          ),
        ),
      ),
      el('div', { class: 'field' },
        el('label', {}, 'Status'),
        el('select', {
          on: { change: (e) => { historyFilter.status = e.target.value; render(); } },
        },
          el('option', { value: '' }, 'All'),
          el('option', { value: 'approved', selected: historyFilter.status === 'approved' }, 'Approved'),
          el('option', { value: 'denied', selected: historyFilter.status === 'denied' }, 'Denied'),
        ),
      ),
    ),
    state.loading ? el('div', { class: 'empty' }, 'Loading…')
      : rows.length === 0 ? el('div', { class: 'empty' }, 'No matching requests.')
      : el('div', { class: 'table-card' },
          el('table', {},
            el('thead', {}, el('tr', {},
              el('th', {}, 'Profile'),
              el('th', {}, 'Domain'),
              el('th', {}, 'Status'),
              el('th', {}, 'Reason'),
              el('th', {}, 'Requested'),
              el('th', {}, 'Reviewed'),
            )),
            el('tbody', {}, rows.map((r) =>
              el('tr', {},
                el('td', {}, r.user_name),
                el('td', { style: 'font-family:ui-monospace,monospace;font-size:13px;' }, r.domain),
                el('td', {}, el('span', { class: 'badge badge-' + r.status }, r.status)),
                el('td', { style: 'max-width:300px;color:#9aa0b4;' }, r.reason),
                el('td', {}, fmtDate(r.requested_at)),
                el('td', {}, fmtDate(r.reviewed_at)),
              )
            )),
          ),
        ),
  );
}

/* ---------- v2: Proxy Profiles ---------- */

function renderProxyStatusBanner() {
  const s = state.proxyStatus;
  if (!s) return null;

  // New IKEv2 architecture status (returned by the new vpnOps router).
  if (s.architecture === 'ikev2') {
    const code = (t) => el('code', { style: 'background:#0f1115;padding:1px 6px;border-radius:4px;' }, t);
    if (!s.proxyHost) {
      return el('div', { class: 'config-banner' },
        '⚠️ PROXY_HOST not set in env. Profile downloads will fail until you set ',
        code('PROXY_HOST'), ' in backend/.env and restart the backend.');
    }
    if (!s.caCertExists) {
      return el('div', { class: 'config-banner' },
        '⚠️ CA cert missing. Run ', code('cd proxy-filter/server/ssl && ./generate-ca.sh'), '.');
    }
    if (!s.serverCertExists) {
      return el('div', { class: 'config-banner' },
        '⚠️ Server cert missing. Run ',
        code('cd proxy-filter/server && ./scripts/mint-server-cert.sh'),
        ' (or run ', code('sudo ./scripts/setup-server-mac.sh'), ' which does it for you).');
    }
    return el('div', { class: 'config-banner', style: 'background:#163a2a;border-color:#1f5c43;color:#6ee7b7;' },
      `✓ IKEv2 architecture configured. VPN host: ${s.proxyHost}. ` +
      `${s.allocations} profile(s) provisioned. Server services start with ` ,
      code('sudo proxy-filter/server/scripts/setup-server-mac.sh'), '.');
  }

  // Legacy node-proxy status (kept while old localtest still exists).
  if (!s.proxyHostConfigured) {
    return el('div', { class: 'config-banner' },
      '⚠️ PROXY_HOST not set in env.');
  }
  return null;
}

function renderProxyPending() {
  return el('div', {},
    el('div', { class: 'page-header' }, el('h2', {}, 'Pending Proxy Requests')),
    state.error && el('div', { class: 'error' }, state.error),
    state.loading ? el('div', { class: 'empty' }, 'Loading…')
      : state.proxyPending.length === 0 ? el('div', { class: 'empty' }, 'No pending requests.')
      : el('div', {}, state.proxyPending.map(renderProxyRequestCard)),
  );
}

function renderProxyRequestCard(r) {
  return el('div', { class: 'card' },
    el('div', { class: 'row' },
      el('div', { style: 'flex:1;' },
        el('div', { style: 'font-weight:600;font-size:15px;' },
          r.display_name || r.user_id,
          el('span', { style: 'color:#6b7290;font-weight:400;margin-left:8px;' }, '→ ' + r.domain),
        ),
        el('div', { class: 'meta' }, (r.proxy_username || '') + ' · ' + relTime(r.requested_at)),
        r.reason && el('div', { class: 'reason' }, r.reason),
      ),
      el('div', { class: 'actions' },
        el('button', { class: 'success', on: { click: () => decideProxy(r.id, 'approved') } }, 'Approve'),
        el('button', { class: 'danger', on: { click: () => decideProxy(r.id, 'denied') } }, 'Deny'),
      ),
    ),
  );
}

async function decideProxy(id, status) {
  try {
    await api('/api/proxy-filter/requests/' + id, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
    state.proxyPending = state.proxyPending.filter((r) => r.id !== id);
    render();
  } catch (err) {
    state.error = err.message;
    render();
  }
}

function renderProxyUsers() {
  return el('div', {},
    el('div', { class: 'page-header' },
      el('h2', {}, 'Proxy Profiles'),
      el('button', {
        class: 'primary',
        on: { click: () => { state.modal = 'newProxyUser'; render(); } },
      }, 'New Proxy Profile'),
    ),
    renderProxyStatusBanner(),
    state.error && el('div', { class: 'error' }, state.error),
    state.loading ? el('div', { class: 'empty' }, 'Loading…')
      : state.proxyUsers.length === 0
        ? el('div', { class: 'empty' }, 'No proxy profiles yet.')
        : el('div', { class: 'table-card' },
            el('table', {},
              el('thead', {}, el('tr', {},
                el('th', {}, 'Name'),
                el('th', {}, 'User ID'),
                el('th', {}, 'Proxy Username'),
                el('th', {}, 'Created'),
                el('th', {}, ''),
              )),
              el('tbody', {}, state.proxyUsers.map(renderProxyUserRow)),
            ),
          ),
    state.modal === 'newProxyUser' && renderNewProxyUserModal(),
  );
}

function renderProxyUserRow(u) {
  return el('tr', {},
    el('td', {}, u.display_name),
    el('td', { style: 'font-family:ui-monospace,monospace;font-size:13px;color:#9aa0b4;' }, u.user_id),
    el('td', { style: 'font-family:ui-monospace,monospace;font-size:13px;color:#9aa0b4;' }, u.proxy_username),
    el('td', {}, fmtDate(u.created_at)),
    el('td', { style: 'text-align:right;' },
      el('div', { class: 'actions', style: 'justify-content:flex-end;' },
        el('button', { class: 'ghost', on: { click: () => openProxySettings(u) } }, 'Settings'),
        el('button', { class: 'ghost', on: { click: () => downloadProxyProfile(u) } }, 'Download'),
        el('button', { class: 'danger', on: { click: () => deleteProxyUser(u) } }, 'Delete'),
      ),
    ),
  );
}

async function downloadProxyProfile(user) {
  try {
    const res = await fetch(API_BASE + `/api/proxy-filter/users/${user.user_id}/profile`, {
      headers: { Authorization: `Bearer ${state.token}` },
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `Download failed (${res.status})`);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${user.user_id}-filter.mobileconfig`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    state.error = err.message;
    render();
  }
}

async function deleteProxyUser(user) {
  if (!confirm(`Delete proxy profile ${user.display_name}? This will remove their Squid auth entry.`)) return;
  try {
    await api('/api/proxy-filter/users/' + user.user_id, { method: 'DELETE' });
    state.proxyUsers = state.proxyUsers.filter((u) => u.user_id !== user.user_id);
    render();
  } catch (err) {
    state.error = err.message;
    render();
  }
}

function renderNewProxyUserModal() {
  return el('div', {
    class: 'modal-overlay',
    on: { click: (e) => { if (e.target.classList.contains('modal-overlay')) { state.modal = null; render(); } } },
  },
    el('div', { class: 'modal' },
      el('h3', {}, 'New Proxy Profile'),
      el('p', { style: 'color:#9aa0b4;font-size:13px;margin:0 0 16px;' },
        'Creates a Squid auth entry and stores generated proxy + removal passwords. The user_id is used in the .mobileconfig and in per-user allowlist files.'),
      el('form', {
        on: {
          submit: async (e) => {
            e.preventDefault();
            const user_id = e.target.user_id.value.trim();
            const display_name = e.target.display_name.value.trim();
            const submitBtn = e.target.querySelector('button[type=submit]');
            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating…';
            try {
              await api('/api/proxy-filter/users', {
                method: 'POST',
                body: JSON.stringify({ user_id, display_name }),
              });
              state.modal = null;
              await loadCurrentView();
            } catch (err) {
              state.error = err.message;
              submitBtn.disabled = false;
              submitBtn.textContent = 'Create';
              render();
            }
          },
        },
      },
        el('div', { class: 'field' },
          el('label', { for: 'user_id' }, 'User ID (used in proxy auth & file names)'),
          el('input', { id: 'user_id', name: 'user_id', required: true, pattern: '[a-zA-Z0-9_-]{1,64}', placeholder: 'sarah' }),
        ),
        el('div', { class: 'field' },
          el('label', { for: 'display_name' }, 'Display name'),
          el('input', { id: 'display_name', name: 'display_name', required: true, placeholder: 'Sarah' }),
        ),
        el('div', { class: 'modal-actions' },
          el('button', { class: 'ghost', type: 'button', on: { click: () => { state.modal = null; render(); } } }, 'Cancel'),
          el('button', { class: 'primary', type: 'submit' }, 'Create'),
        ),
      ),
    ),
  );
}

/* ---------- v2: Proxy Settings (allowlist + creds + removal pw) ---------- */

async function openProxySettings(user) {
  state.view = 'proxy-settings';
  state.proxySettingsUser = user;
  state.proxyProfileBlocklist = [];
  state.proxyProfileAllowlist = [];
  state.proxyCreds = null;
  state.proxyError = null;
  render();
  await loadProxySettings();
}

async function loadProxySettings() {
  if (!state.proxySettingsUser) return;
  state.loading = true;
  render();
  try {
    const [block, allow] = await Promise.all([
      api(`/api/proxy-filter/users/${state.proxySettingsUser.user_id}/blocklist`),
      api(`/api/proxy-filter/users/${state.proxySettingsUser.user_id}/allowlist`),
    ]);
    state.proxyProfileBlocklist = block.items || [];
    state.proxyProfileAllowlist = allow.items || [];
  } catch (err) {
    state.proxyError = err.message;
  } finally {
    state.loading = false;
    render();
  }
}

function renderProxySettings() {
  if (!state.proxySettingsUser) return el('div', { class: 'empty' }, 'No profile selected.');
  const u = state.proxySettingsUser;
  return el('div', {},
    el('div', { class: 'page-header' },
      el('div', {},
        el('div', { style: 'font-size:13px;color:#9aa0b4;margin-bottom:4px;' },
          el('a', { href: '#', on: { click: (e) => { e.preventDefault(); switchView('proxy-users'); } } }, '← Back to proxy profiles'),
        ),
        el('h2', {}, u.display_name + ' — Settings'),
        el('div', { class: 'meta' }, 'User ID: ' + u.user_id + ' · Proxy username: ' + u.proxy_username),
      ),
    ),
    state.proxyError && el('div', { class: 'error' }, state.proxyError),
    el('div', {},
      renderProxyListCard('blocklist', 'Blocked Domains',
        'Sites the proxy will block for this profile. Subdomains match automatically.',
        state.proxyProfileBlocklist),
      renderProxyListCard('allowlist', 'Allowed Domains',
        'Always-allowed domains for this profile — overrides both this profile\'s blocklist and the default blocklist.',
        state.proxyProfileAllowlist),
      renderProxyCredentialsCard(),
    ),
  );
}

function renderProxyListCard(kind, title, helpText, items) {
  return el('div', { class: 'card' },
    el('div', { class: 'row' },
      el('div', { style: 'flex:1;' },
        el('h3', { style: 'margin:0 0 4px;font-size:16px;' }, title),
        el('div', { class: 'meta' }, helpText),
      ),
    ),
    el('form', {
      style: 'display:flex;gap:8px;margin-top:12px;',
      on: {
        submit: async (e) => {
          e.preventDefault();
          const inp = e.target.querySelector('input');
          const domain = inp.value.trim();
          if (!domain) return;
          state.proxyError = null;
          try {
            await api(`/api/proxy-filter/users/${state.proxySettingsUser.user_id}/${kind}`, {
              method: 'POST',
              body: JSON.stringify({ domain }),
            });
            inp.value = '';
            await loadProxySettings();
          } catch (err) {
            state.proxyError = err.message;
            render();
          }
        },
      },
    },
      el('input', { placeholder: 'example.com', style: 'flex:1;' }),
      el('button', { class: 'primary', type: 'submit' }, 'Add'),
    ),
    items.length === 0
      ? el('div', { class: 'meta', style: 'margin-top:12px;' }, 'No domains yet.')
      : el('div', { style: 'margin-top:12px;' },
          items.map((d) =>
            el('div', { class: 'list-item' },
              el('span', { style: 'font-family:ui-monospace,monospace;font-size:13px;' }, d),
              el('button', {
                class: 'danger',
                on: {
                  click: async () => {
                    state.proxyError = null;
                    try {
                      await api(`/api/proxy-filter/users/${state.proxySettingsUser.user_id}/${kind}/${encodeURIComponent(d)}`, {
                        method: 'DELETE',
                      });
                      await loadProxySettings();
                    } catch (err) {
                      state.proxyError = err.message;
                      render();
                    }
                  },
                },
              }, 'Remove'),
            )
          ),
        ),
  );
}

function renderProxyCredentialsCard() {
  const c = state.proxyCreds;
  return el('div', { class: 'card' },
    el('div', { class: 'row' },
      el('div', { style: 'flex:1;' },
        el('h3', { style: 'margin:0 0 4px;font-size:16px;' }, 'Credentials'),
        el('div', { class: 'meta' },
          'The proxy password is what Squid uses for HTTP basic auth. The removal password is what unlocks the .mobileconfig from System Settings → Profiles. Both are baked into the .mobileconfig you download — no need to share them with the user separately unless you want to.'),
      ),
    ),
    el('div', { style: 'margin-top:12px;' },
      c
        ? el('div', {},
            credentialRow('Proxy username', c.proxy_username),
            credentialRow('Proxy password', c.proxy_password),
            credentialRow('Removal password', c.removal_password),
            el('button', {
              class: 'ghost',
              style: 'margin-top:8px;',
              on: { click: () => { state.proxyCreds = null; render(); } },
            }, 'Hide'),
          )
        : el('button', {
            class: 'primary',
            on: { click: () => revealProxyCredentials() },
          }, 'Reveal Credentials'),
    ),
  );
}

function credentialRow(label, value) {
  return el('div', { style: 'display:flex;gap:8px;align-items:center;margin-bottom:8px;' },
    el('div', { style: 'width:160px;color:#9aa0b4;font-size:13px;' }, label),
    el('code', {
      style: 'flex:1;background:#14161e;border:1px solid #2a2e3f;border-radius:8px;padding:8px 12px;font-family:ui-monospace,monospace;font-size:13px;word-break:break-all;',
    }, value),
    el('button', { class: 'ghost', on: { click: () => navigator.clipboard.writeText(value) } }, 'Copy'),
  );
}

async function revealProxyCredentials() {
  state.proxyError = null;
  try {
    const data = await api(`/api/proxy-filter/users/${state.proxySettingsUser.user_id}/credentials`);
    state.proxyCreds = data;
    render();
  } catch (err) {
    state.proxyError = err.message;
    render();
  }
}

/* ---------- v2: Activity ---------- */

const proxyActivityFilter = { user: '', status: '' };

function renderProxyActivity() {
  let rows = state.proxyActivity;
  if (proxyActivityFilter.user) rows = rows.filter((r) => r.user_id === proxyActivityFilter.user);
  if (proxyActivityFilter.status) rows = rows.filter((r) => r.status === proxyActivityFilter.status);
  const userOptions = [...new Map(state.proxyActivity.map((r) => [r.user_id, r.display_name || r.user_id])).entries()];

  return el('div', {},
    el('div', { class: 'page-header' }, el('h2', {}, 'Activity')),
    el('div', { class: 'meta', style: 'margin-bottom:16px;' },
      'All access requests submitted by proxy users. Pending ones can be approved/denied here too.'),
    state.error && el('div', { class: 'error' }, state.error),
    el('div', { class: 'filters' },
      el('div', { class: 'field' },
        el('label', {}, 'Profile'),
        el('select', {
          on: { change: (e) => { proxyActivityFilter.user = e.target.value; render(); } },
        },
          el('option', { value: '' }, 'All'),
          userOptions.map(([id, name]) =>
            el('option', { value: id, selected: proxyActivityFilter.user === id }, name)
          ),
        ),
      ),
      el('div', { class: 'field' },
        el('label', {}, 'Status'),
        el('select', {
          on: { change: (e) => { proxyActivityFilter.status = e.target.value; render(); } },
        },
          el('option', { value: '' }, 'All'),
          el('option', { value: 'pending', selected: proxyActivityFilter.status === 'pending' }, 'Pending'),
          el('option', { value: 'approved', selected: proxyActivityFilter.status === 'approved' }, 'Approved'),
          el('option', { value: 'denied', selected: proxyActivityFilter.status === 'denied' }, 'Denied'),
        ),
      ),
    ),
    state.loading ? el('div', { class: 'empty' }, 'Loading…')
      : rows.length === 0 ? el('div', { class: 'empty' }, 'No requests yet.')
      : el('div', { class: 'table-card' },
          el('table', {},
            el('thead', {}, el('tr', {},
              el('th', {}, 'Profile'),
              el('th', {}, 'Domain'),
              el('th', {}, 'Status'),
              el('th', {}, 'Reason'),
              el('th', {}, 'Requested'),
              el('th', {}, ''),
            )),
            el('tbody', {}, rows.map((r) =>
              el('tr', {},
                el('td', {}, r.display_name || r.user_id),
                el('td', { style: 'font-family:ui-monospace,monospace;font-size:13px;' }, r.domain),
                el('td', {}, el('span', { class: 'badge badge-' + r.status }, r.status)),
                el('td', { style: 'max-width:300px;color:#9aa0b4;' }, r.reason),
                el('td', {}, fmtDate(r.requested_at)),
                el('td', { style: 'text-align:right;' },
                  r.status === 'pending'
                    ? el('div', { class: 'actions', style: 'justify-content:flex-end;' },
                        el('button', { class: 'success', on: { click: async () => { await decideProxy(r.id, 'approved'); await loadCurrentView(); } } }, 'Approve'),
                        el('button', { class: 'danger', on: { click: async () => { await decideProxy(r.id, 'denied'); await loadCurrentView(); } } }, 'Deny'),
                      )
                    : null,
                ),
              )
            )),
          ),
        ),
  );
}

/* ---------- v2: Blocklist ---------- */

function renderProxyBlocklist() {
  return el('div', {},
    el('div', { class: 'page-header' }, el('h2', {}, 'Default Blocklist')),
    el('div', { class: 'meta', style: 'margin-bottom:16px;' },
      'Applied to every proxy profile in addition to that profile\'s own blocklist. ',
      'Per-profile allowlists still override entries here. Edit ',
      el('code', { style: 'background:#0f1115;padding:1px 6px;border-radius:4px;' }, 'proxy-filter/server/blocklists/adult.txt'),
      ' directly to import a large list (see README for sources).'),
    renderProxyStatusBanner(),
    state.error && el('div', { class: 'error' }, state.error),
    el('div', { class: 'card' },
      el('form', {
        style: 'display:flex;gap:8px;',
        on: {
          submit: async (e) => {
            e.preventDefault();
            const inp = e.target.querySelector('input');
            const domain = inp.value.trim();
            if (!domain) return;
            try {
              await api('/api/proxy-filter/blocklist', {
                method: 'POST',
                body: JSON.stringify({ domain }),
              });
              inp.value = '';
              await loadCurrentView();
            } catch (err) {
              state.error = err.message;
              render();
            }
          },
        },
      },
        el('input', { placeholder: 'example.com', style: 'flex:1;' }),
        el('button', { class: 'primary', type: 'submit' }, 'Add to Blocklist'),
      ),
    ),
    state.loading ? el('div', { class: 'empty' }, 'Loading…')
      : state.proxyBlocklist.length === 0
        ? el('div', { class: 'empty' }, 'Blocklist is empty.')
        : el('div', { class: 'table-card' },
            el('table', {},
              el('thead', {}, el('tr', {},
                el('th', {}, 'Domain'),
                el('th', {}, ''),
              )),
              el('tbody', {}, state.proxyBlocklist.map((d) =>
                el('tr', {},
                  el('td', { style: 'font-family:ui-monospace,monospace;font-size:13px;' }, d),
                  el('td', { style: 'text-align:right;' },
                    el('button', {
                      class: 'danger',
                      on: {
                        click: async () => {
                          try {
                            await api('/api/proxy-filter/blocklist/' + encodeURIComponent(d), { method: 'DELETE' });
                            await loadCurrentView();
                          } catch (err) {
                            state.error = err.message;
                            render();
                          }
                        },
                      },
                    }, 'Remove'),
                  ),
                )
              )),
            ),
          ),
  );
}

/* ---------- Render ---------- */

function render() {
  const root = document.getElementById('app');
  root.innerHTML = '';

  if (!state.token) {
    state.view = 'login';
    root.appendChild(renderAuth());
    return;
  }

  let page;
  if (state.view === 'pending') page = renderPending();
  else if (state.view === 'users') page = renderUsers();
  else if (state.view === 'history') page = renderHistory();
  else if (state.view === 'settings') page = renderSettings();
  else if (state.view === 'proxy-pending') page = renderProxyPending();
  else if (state.view === 'proxy-users') page = renderProxyUsers();
  else if (state.view === 'proxy-settings') page = renderProxySettings();
  else if (state.view === 'proxy-activity') page = renderProxyActivity();
  else if (state.view === 'proxy-blocklist') page = renderProxyBlocklist();
  else page = el('div', { class: 'empty' }, 'Unknown view');

  const banner = state.config && state.config.nextdnsConfigured === false
    ? el('div', { class: 'config-banner' },
        '⚠️ Backend is missing NEXTDNS_API_KEY. Profile creation and settings will fail. ',
        'Set it in backend/.env and restart.')
    : null;

  root.appendChild(
    el('div', { class: 'shell' },
      sidebar(),
      el('div', { class: 'content' }, banner, page),
    )
  );
}

/* ---------- Init ---------- */

async function loadConfig() {
  try {
    state.config = await api('/api/config');
  } catch {
    state.config = null;
  }
}

async function init() {
  await loadConfig();
  if (state.token) {
    try {
      const me = await api('/api/auth/me');
      state.admin = me.admin;
      state.view = 'pending';
      await loadCurrentView();
      return;
    } catch {
      // token rejected — fall through to login
    }
  }
  render();
}

init();
