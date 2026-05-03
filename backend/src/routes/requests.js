import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import { db } from '../db.js';
import { requireAdmin } from '../auth.js';
import { addAllowedDomain } from '../nextdns.js';
import { notifyAdminOfRequest } from '../email.js';

export const requestsRouter = Router();

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

requestsRouter.post('/', async (req, res) => {
  const { profile_id, domain, reason } = req.body || {};
  if (!profile_id || !domain || !reason) {
    return res.status(400).json({ error: 'profile_id, domain, and reason required' });
  }
  const cleanDomain = normalizeDomain(domain);
  if (!cleanDomain) return res.status(400).json({ error: 'Invalid domain' });

  const user = db.prepare('SELECT * FROM users WHERE nextdns_profile_id = ?').get(profile_id);
  if (!user) return res.status(404).json({ error: 'Unknown profile' });

  const id = randomUUID();
  db.prepare(`
    INSERT INTO access_requests (id, user_id, domain, reason, status)
    VALUES (?, ?, ?, ?, 'pending')
  `).run(id, user.id, cleanDomain, String(reason).slice(0, 2000));

  if (user.admin_id) {
    const owner = db.prepare('SELECT email, name FROM admins WHERE id = ?').get(user.admin_id);
    if (owner) {
      notifyAdminOfRequest({ admin: owner, user, domain: cleanDomain, reason }).catch((err) => {
        console.error('notifyAdminOfRequest failed:', err.message);
      });
    }
  }

  res.status(201).json({ ok: true, id });
});

const REQUEST_SELECT = `
  SELECT r.*, u.name AS user_name, u.email AS user_email, u.nextdns_profile_id, u.admin_id
  FROM access_requests r
  JOIN users u ON u.id = r.user_id
`;

requestsRouter.get('/', requireAdmin, (req, res) => {
  const status = req.query.status;
  let rows;
  if (status === 'pending' || status === 'approved' || status === 'denied') {
    rows = db
      .prepare(REQUEST_SELECT + ' WHERE u.admin_id = ? AND r.status = ? ORDER BY r.requested_at DESC')
      .all(req.admin.sub, status);
  } else {
    rows = db
      .prepare(REQUEST_SELECT + ' WHERE u.admin_id = ? ORDER BY r.requested_at DESC')
      .all(req.admin.sub);
  }
  res.json({ requests: rows });
});

requestsRouter.patch('/:id', requireAdmin, async (req, res) => {
  const { status } = req.body || {};
  if (status !== 'approved' && status !== 'denied') {
    return res.status(400).json({ error: 'status must be "approved" or "denied"' });
  }
  const request = db.prepare(REQUEST_SELECT + ' WHERE r.id = ?').get(req.params.id);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.admin_id !== req.admin.sub) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') {
    return res.status(409).json({ error: `Already ${request.status}` });
  }

  if (status === 'approved') {
    try {
      await addAllowedDomain(request.nextdns_profile_id, request.domain);
    } catch (err) {
      return res.status(502).json({ error: 'NextDNS error: ' + err.message });
    }
  }

  db.prepare(`
    UPDATE access_requests
    SET status = ?, reviewed_at = datetime('now'), reviewed_by = ?
    WHERE id = ?
  `).run(status, req.admin.sub, request.id);

  const updated = db.prepare(REQUEST_SELECT + ' WHERE r.id = ?').get(request.id);
  res.json({ request: updated });
});
