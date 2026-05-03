import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { db } from '../db.js';
import { requireAdmin } from '../auth.js';
import {
  createProfile,
  deleteProfile,
  enableBlockPage,
  getProfile,
  patchSecurity,
  patchParentalControl,
  addCategory,
  removeCategory,
  addBlocklist,
  removeBlocklist,
  addAllowedDomain,
  removeAllowedDomain,
  addDeniedDomain,
  removeDeniedDomain,
} from '../nextdns.js';
import {
  generateMobileConfig,
  generateRemovalPassword,
} from '../profileGenerator.js';

export const usersRouter = Router();

const AD_BLOCKLIST_ID = 'nextdns-recommended';

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    nextdns_profile_id: u.nextdns_profile_id,
    created_at: u.created_at,
  };
}

function findOwnedUser(userId, adminId) {
  return db
    .prepare('SELECT * FROM users WHERE id = ? AND admin_id = ?')
    .get(userId, adminId);
}

function normalizeDomain(input) {
  if (!input) return null;
  let d = String(input).trim().toLowerCase();
  try {
    if (d.includes('://')) d = new URL(d).hostname;
  } catch {}
  d = d.replace(/^www\./, '').replace(/\/.*$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return null;
  return d;
}

function isSlug(s) {
  return typeof s === 'string' && /^[a-z0-9_-]{1,64}$/i.test(s);
}

usersRouter.use(requireAdmin);

usersRouter.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT * FROM users WHERE admin_id = ? ORDER BY created_at DESC')
    .all(req.admin.sub);
  res.json({ users: rows.map(publicUser) });
});

usersRouter.post('/', async (req, res) => {
  const { name, email } = req.body || {};
  if (!name || !email) return res.status(400).json({ error: 'name and email required' });

  let profileId;
  try {
    profileId = await createProfile(name);
    if (!profileId) throw new Error('NextDNS did not return a profile id');
    await patchSecurity(profileId, { googleSafeBrowsing: true });
    await patchParentalControl(profileId, {
      safeSearch: true,
      youtubeRestrictedMode: true,
      blockBypass: true,
    });
    for (const cat of ['porn', 'gambling', 'dating']) {
      try { await addCategory(profileId, cat); } catch (err) {
        console.error(`addCategory ${cat} failed:`, err.message);
      }
    }
    await enableBlockPage(profileId);
  } catch (err) {
    if (profileId) {
      await deleteProfile(profileId).catch(() => {});
    }
    return res.status(502).json({ error: 'NextDNS error: ' + err.message });
  }

  const id = randomUUID();
  const removalPassword = generateRemovalPassword();
  db.prepare(`
    INSERT INTO users (id, admin_id, name, email, nextdns_profile_id, removal_password)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, req.admin.sub, name, email, profileId, removalPassword);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  res.status(201).json({ user: publicUser(user) });
});

usersRouter.get('/:id/removal-password', (req, res) => {
  const user = findOwnedUser(req.params.id, req.admin.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ removal_password: user.removal_password });
});

usersRouter.get('/:id/profile', (req, res) => {
  const user = findOwnedUser(req.params.id, req.admin.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const xml = generateMobileConfig({
    profileId: user.nextdns_profile_id,
    removalPassword: user.removal_password,
  });
  const safeName = user.name.replace(/[^a-z0-9]+/gi, '_').toLowerCase() || 'user';
  res.setHeader('Content-Type', 'application/x-apple-aspen-config');
  res.setHeader('Content-Disposition', `attachment; filename="${safeName}.mobileconfig"`);
  res.send(xml);
});

usersRouter.delete('/:id', async (req, res) => {
  const user = findOwnedUser(req.params.id, req.admin.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    await deleteProfile(user.nextdns_profile_id);
  } catch (err) {
    console.error(`Failed to delete NextDNS profile ${user.nextdns_profile_id}: ${err.message}`);
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  res.json({ ok: true });
});

usersRouter.get('/:id/settings', async (req, res) => {
  const user = findOwnedUser(req.params.id, req.admin.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    const profile = await getProfile(user.nextdns_profile_id);
    if (!profile) return res.status(404).json({ error: 'NextDNS profile missing' });
    const blocklistIds = (profile.privacy?.blocklists || []).map((b) => b.id);
    res.json({
      security: profile.security || {},
      parental: profile.parentalControl || {},
      categories: (profile.parentalControl?.categories || []).map((c) => c.id),
      blocklists: blocklistIds,
      adBlockingEnabled: blocklistIds.includes(AD_BLOCKLIST_ID),
    });
  } catch (err) {
    res.status(502).json({ error: 'NextDNS error: ' + err.message });
  }
});

usersRouter.patch('/:id/settings', async (req, res) => {
  const user = findOwnedUser(req.params.id, req.admin.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { security, parental, adBlocking } = req.body || {};
  try {
    if (security && typeof security === 'object') {
      await patchSecurity(user.nextdns_profile_id, security);
    }
    if (parental && typeof parental === 'object') {
      await patchParentalControl(user.nextdns_profile_id, parental);
    }
    if (typeof adBlocking === 'boolean') {
      if (adBlocking) {
        try { await addBlocklist(user.nextdns_profile_id, AD_BLOCKLIST_ID); } catch {}
      } else {
        try { await removeBlocklist(user.nextdns_profile_id, AD_BLOCKLIST_ID); } catch {}
      }
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: 'NextDNS error: ' + err.message });
  }
});

usersRouter.post('/:id/categories', async (req, res) => {
  const user = findOwnedUser(req.params.id, req.admin.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const cat = req.body?.id;
  if (!isSlug(cat)) return res.status(400).json({ error: 'Invalid category id' });
  try {
    await addCategory(user.nextdns_profile_id, cat);
    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: 'NextDNS error: ' + err.message });
  }
});

usersRouter.delete('/:id/categories/:cat', async (req, res) => {
  const user = findOwnedUser(req.params.id, req.admin.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!isSlug(req.params.cat)) return res.status(400).json({ error: 'Invalid category id' });
  try {
    await removeCategory(user.nextdns_profile_id, req.params.cat);
    res.json({ ok: true });
  } catch (err) {
    res.status(502).json({ error: 'NextDNS error: ' + err.message });
  }
});

function listFromProfile(getList) {
  return async (req, res) => {
    const user = findOwnedUser(req.params.id, req.admin.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    try {
      const profile = await getProfile(user.nextdns_profile_id);
      if (!profile) return res.status(404).json({ error: 'NextDNS profile missing' });
      res.json({ items: getList(profile) || [] });
    } catch (err) {
      res.status(502).json({ error: 'NextDNS error: ' + err.message });
    }
  };
}

function addEndpoint(adder) {
  return async (req, res) => {
    const user = findOwnedUser(req.params.id, req.admin.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const domain = normalizeDomain(req.body?.domain);
    if (!domain) return res.status(400).json({ error: 'Invalid domain' });
    try {
      await adder(user.nextdns_profile_id, domain);
      res.json({ ok: true, domain });
    } catch (err) {
      res.status(502).json({ error: 'NextDNS error: ' + err.message });
    }
  };
}

function removeEndpoint(remover) {
  return async (req, res) => {
    const user = findOwnedUser(req.params.id, req.admin.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const domain = normalizeDomain(req.params.domain);
    if (!domain) return res.status(400).json({ error: 'Invalid domain' });
    try {
      await remover(user.nextdns_profile_id, domain);
      res.json({ ok: true });
    } catch (err) {
      res.status(502).json({ error: 'NextDNS error: ' + err.message });
    }
  };
}

usersRouter.get('/:id/allowlist', listFromProfile((p) => p.allowlist));
usersRouter.post('/:id/allowlist', addEndpoint(addAllowedDomain));
usersRouter.delete('/:id/allowlist/:domain', removeEndpoint(removeAllowedDomain));

usersRouter.get('/:id/denylist', listFromProfile((p) => p.denylist));
usersRouter.post('/:id/denylist', addEndpoint(addDeniedDomain));
usersRouter.delete('/:id/denylist/:domain', removeEndpoint(removeDeniedDomain));
