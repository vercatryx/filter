// Express router mounted at /api/proxy-filter by the parent backend.
//
// Architecture: IKEv2 VPN + transparent SSL inspection (mitmproxy).
// See PLAN.md for the full picture.

import { Router } from 'express';
import { randomUUID, randomBytes } from 'node:crypto';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, existsSync } from 'node:fs';

import { db } from './db.js';
import { requireAdmin } from '../../backend/src/auth.js';
import { generateIkev2Profile } from '../profile-generator/generate-ikev2-profile.js';
import {
  SERVER_DIR,
  PROFILES_DIR,
  allocateVpnIp,
  writeAllocations,
  mintDeviceCert,
  ensureProfileDir,
  removeProfileDir,
  readProfileBlocklist,
  readProfileAllowlist,
  addToProfileBlocklist,
  removeFromProfileBlocklist,
  addToProfileAllowlist,
  removeFromProfileAllowlist,
  readBlocklist,
  addToBlocklist,
  removeFromBlocklist,
  readExclusions,
  EXCLUSIONS_PATH,
  reloadServer,
  serverStatus,
} from './vpnOps.js';

export const proxyFilterRouter = Router();

const here = dirname(fileURLToPath(import.meta.url));
const CA_CRT_PATH = resolve(here, '..', 'server', 'ssl', 'ca.crt');

function genPassword(bytes = 18) {
  return randomBytes(bytes).toString('base64url');
}

function normalizeDomain(input) {
  if (!input) return null;
  let d = String(input).trim().toLowerCase();
  try { if (d.includes('://')) d = new URL(d).hostname; } catch {}
  d = d.replace(/^www\./, '').replace(/\/.*$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return null;
  return d;
}

function isUserId(s) {
  return typeof s === 'string' && /^[a-z0-9_-]{1,64}$/i.test(s);
}

// --------------------------------------------------------------------------
// Public: block-page submits access requests here. No auth.
// (Kept for compatibility — the new architecture serves block pages
// directly from mitmproxy. This endpoint is for admins who want to
// keep the dashboard's request-flow workflow.)
// --------------------------------------------------------------------------
proxyFilterRouter.post('/requests', (req, res) => {
  const { user_id, domain, reason } = req.body || {};
  if (!user_id || !domain) return res.status(400).json({ error: 'user_id and domain required' });
  if (!isUserId(user_id)) return res.status(400).json({ error: 'Invalid user_id' });
  const cleanDomain = normalizeDomain(domain);
  if (!cleanDomain) return res.status(400).json({ error: 'Invalid domain' });
  const exists = db.prepare('SELECT 1 FROM proxy_users WHERE user_id = ?').get(user_id);
  if (!exists) return res.status(404).json({ error: 'Unknown user' });

  const id = randomUUID();
  db.prepare(`
    INSERT INTO proxy_requests (id, user_id, domain, reason, status)
    VALUES (?, ?, ?, ?, 'pending')
  `).run(id, user_id, cleanDomain, String(reason || '').slice(0, 2000));
  res.json({ success: true, message: 'Request submitted', id });
});

// --------------------------------------------------------------------------
// Admin endpoints below.
// --------------------------------------------------------------------------
proxyFilterRouter.use(requireAdmin);

// --- Requests (kept) ---
proxyFilterRouter.get('/requests', (req, res) => {
  const status = req.query.status;
  const sql = `
    SELECT r.*, u.display_name AS display_name, u.user_id AS profile_user_id, u.owner_admin_id
    FROM proxy_requests r
    JOIN proxy_users u ON u.user_id = r.user_id
    WHERE u.owner_admin_id = ?
    ${status === 'pending' || status === 'approved' || status === 'denied' ? 'AND r.status = ?' : ''}
    ORDER BY r.requested_at DESC
  `;
  const args = [req.admin.sub];
  if (status === 'pending' || status === 'approved' || status === 'denied') args.push(status);
  res.json({ requests: db.prepare(sql).all(...args) });
});

proxyFilterRouter.patch('/requests/:id', async (req, res) => {
  const { status } = req.body || {};
  if (status !== 'approved' && status !== 'denied') {
    return res.status(400).json({ error: 'status must be "approved" or "denied"' });
  }
  const row = db.prepare(`
    SELECT r.*, u.owner_admin_id
    FROM proxy_requests r JOIN proxy_users u ON u.user_id = r.user_id
    WHERE r.id = ?
  `).get(req.params.id);
  if (!row || row.owner_admin_id !== req.admin.sub) return res.status(404).json({ error: 'Request not found' });
  if (row.status !== 'pending') return res.status(409).json({ error: `Already ${row.status}` });

  if (status === 'approved') {
    try { addToProfileAllowlist(row.user_id, row.domain); }
    catch (err) { return res.status(500).json({ error: err.message }); }
    reloadServer().then((r) => { if (!r.ok) console.error('reloadServer:', r.error); });
  }

  db.prepare(`
    UPDATE proxy_requests SET status = ?, reviewed_at = datetime('now'), reviewed_by = ?
    WHERE id = ?
  `).run(status, req.admin.sub, row.id);

  const updated = db.prepare('SELECT * FROM proxy_requests WHERE id = ?').get(row.id);
  res.json({ request: updated });
});

// --- Profiles (formerly "users") ---
proxyFilterRouter.get('/users', (req, res) => {
  const rows = db.prepare(`
    SELECT id, user_id, display_name, vpn_ip, created_at
    FROM proxy_users
    WHERE owner_admin_id = ?
    ORDER BY created_at DESC
  `).all(req.admin.sub);
  res.json({ users: rows });
});

proxyFilterRouter.post('/users', async (req, res) => {
  const { user_id, display_name } = req.body || {};
  if (!isUserId(user_id)) return res.status(400).json({ error: 'Invalid user_id (alphanumeric/-/_, 1-64 chars)' });
  if (!display_name) return res.status(400).json({ error: 'display_name required' });

  const dupe = db.prepare('SELECT 1 FROM proxy_users WHERE user_id = ?').get(user_id);
  if (dupe) return res.status(409).json({ error: 'user_id already in use' });

  let vpnIp;
  try { vpnIp = allocateVpnIp(); }
  catch (err) { return res.status(500).json({ error: err.message }); }

  const p12Password = genPassword();
  // TEMPORARY: removal password fixed to '1234' for development.
  // Switch back to genPassword() before any real deployment.
  const removalPassword = '1234';

  try {
    mintDeviceCert(user_id, p12Password);
    ensureProfileDir(user_id);
  } catch (err) {
    return res.status(500).json({ error: 'Cert minting failed: ' + err.message });
  }

  const id = randomUUID();
  db.prepare(`
    INSERT INTO proxy_users
      (id, user_id, display_name, vpn_ip, p12_password, removal_password,
       proxy_username, proxy_password, owner_admin_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, user_id, display_name, vpnIp, p12Password, removalPassword,
         user_id /* legacy */, '' /* legacy */, req.admin.sub);

  writeAllocations();
  reloadServer().then((r) => { if (!r.ok) console.error('reloadServer:', r.error); });

  res.status(201).json({
    user: {
      id, user_id, display_name, vpn_ip: vpnIp,
      created_at: new Date().toISOString(),
    },
  });
});

proxyFilterRouter.delete('/users/:user_id', async (req, res) => {
  const row = db.prepare('SELECT * FROM proxy_users WHERE user_id = ? AND owner_admin_id = ?')
    .get(req.params.user_id, req.admin.sub);
  if (!row) return res.status(404).json({ error: 'User not found' });

  removeProfileDir(row.user_id);
  db.prepare('DELETE FROM proxy_users WHERE id = ?').run(row.id);
  writeAllocations();
  reloadServer().then((r) => { if (!r.ok) console.error('reloadServer:', r.error); });

  res.json({ ok: true });
});

proxyFilterRouter.get('/users/:user_id/credentials', (req, res) => {
  const row = db.prepare('SELECT * FROM proxy_users WHERE user_id = ? AND owner_admin_id = ?')
    .get(req.params.user_id, req.admin.sub);
  if (!row) return res.status(404).json({ error: 'User not found' });
  res.json({
    user_id: row.user_id,
    vpn_ip: row.vpn_ip,
    removal_password: row.removal_password,
  });
});

// --- Profile download — IKEv2 .mobileconfig ---
proxyFilterRouter.get('/users/:user_id/profile', async (req, res) => {
  const row = db.prepare('SELECT * FROM proxy_users WHERE user_id = ? AND owner_admin_id = ?')
    .get(req.params.user_id, req.admin.sub);
  if (!row) return res.status(404).json({ error: 'User not found' });

  const vpnHost = process.env.PROXY_HOST;
  if (!vpnHost) return res.status(500).json({ error: 'PROXY_HOST (server reachable host/IP) not set in env' });

  const p12Path = join(PROFILES_DIR, row.user_id, `${row.user_id}.p12`);
  if (!existsSync(p12Path)) {
    return res.status(500).json({ error: `device cert not found at ${p12Path} — re-create the profile` });
  }
  if (!row.p12_password || !row.removal_password) {
    return res.status(500).json({ error: 'profile is missing p12_password or removal_password — re-create' });
  }

  let xml;
  try {
    xml = generateIkev2Profile({
      userId: row.user_id,
      vpnHost,
      serverCertCN: vpnHost,           // server cert was minted with CN=<vpnHost>
      caCrtPath: CA_CRT_PATH,
      p12Path,
      p12Password: row.p12_password,
      removalPassword: row.removal_password,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }

  res.setHeader('Content-Type', 'application/x-apple-aspen-config');
  res.setHeader('Content-Disposition', `attachment; filename="${row.user_id}-filter.mobileconfig"`);
  res.send(xml);
});

// --- Per-profile rule lists ---
function ownedProxyUser(req) {
  return db.prepare('SELECT * FROM proxy_users WHERE user_id = ? AND owner_admin_id = ?')
    .get(req.params.user_id, req.admin.sub);
}

function listEndpoint(reader) {
  return (req, res) => {
    const row = ownedProxyUser(req);
    if (!row) return res.status(404).json({ error: 'User not found' });
    try { res.json({ items: reader(row.user_id) }); }
    catch (err) { res.status(500).json({ error: err.message }); }
  };
}

function addEndpoint(adder) {
  return async (req, res) => {
    const row = ownedProxyUser(req);
    if (!row) return res.status(404).json({ error: 'User not found' });
    const domain = normalizeDomain(req.body?.domain);
    if (!domain) return res.status(400).json({ error: 'Invalid domain' });
    try {
      adder(row.user_id, domain);
      reloadServer().then((r) => { if (!r.ok) console.error('reloadServer:', r.error); });
      res.json({ ok: true, domain });
    } catch (err) { res.status(500).json({ error: err.message }); }
  };
}

function removeEndpoint(remover) {
  return async (req, res) => {
    const row = ownedProxyUser(req);
    if (!row) return res.status(404).json({ error: 'User not found' });
    const domain = normalizeDomain(req.params.domain);
    if (!domain) return res.status(400).json({ error: 'Invalid domain' });
    try {
      remover(row.user_id, domain);
      reloadServer().then((r) => { if (!r.ok) console.error('reloadServer:', r.error); });
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  };
}

proxyFilterRouter.get(   '/users/:user_id/blocklist',          listEndpoint(readProfileBlocklist));
proxyFilterRouter.post(  '/users/:user_id/blocklist',          addEndpoint(addToProfileBlocklist));
proxyFilterRouter.delete('/users/:user_id/blocklist/:domain',  removeEndpoint(removeFromProfileBlocklist));
proxyFilterRouter.get(   '/users/:user_id/allowlist',          listEndpoint(readProfileAllowlist));
proxyFilterRouter.post(  '/users/:user_id/allowlist',          addEndpoint(addToProfileAllowlist));
proxyFilterRouter.delete('/users/:user_id/allowlist/:domain',  removeEndpoint(removeFromProfileAllowlist));

// --- Default (shared) blocklist ---
proxyFilterRouter.get('/blocklist', (req, res) => {
  try { res.json({ items: readBlocklist() }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
proxyFilterRouter.post('/blocklist', async (req, res) => {
  const domain = normalizeDomain(req.body?.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  try {
    addToBlocklist(domain);
    reloadServer().then((r) => { if (!r.ok) console.error('reloadServer:', r.error); });
    res.json({ ok: true, domain });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
proxyFilterRouter.delete('/blocklist/:domain', async (req, res) => {
  const domain = normalizeDomain(req.params.domain);
  if (!domain) return res.status(400).json({ error: 'Invalid domain' });
  try {
    removeFromBlocklist(domain);
    reloadServer().then((r) => { if (!r.ok) console.error('reloadServer:', r.error); });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Status — surfaces server-side health to the dashboard ---
proxyFilterRouter.get('/status', async (req, res) => {
  const status = await serverStatus();
  res.json({
    architecture: 'ikev2',
    proxyHost: process.env.PROXY_HOST || null,
    ...status,
  });
});
