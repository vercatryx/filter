import { Router } from 'express';
import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { db } from '../db.js';
import { signAdminToken, requireAdmin } from '../auth.js';

export const authRouter = Router();

function isEmail(s) {
  return typeof s === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);
}

authRouter.post('/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!isEmail(email)) return res.status(400).json({ error: 'Valid email required' });
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  const cleanEmail = String(email).toLowerCase();
  const exists = db.prepare('SELECT id FROM admins WHERE email = ?').get(cleanEmail);
  if (exists) return res.status(409).json({ error: 'An account with that email already exists' });

  const hash = await bcrypt.hash(password, 12);
  const id = randomUUID();
  db.prepare(`
    INSERT INTO admins (id, name, email, password_hash)
    VALUES (?, ?, ?, ?)
  `).run(id, name || cleanEmail, cleanEmail, hash);

  const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(id);
  res.status(201).json({
    token: signAdminToken(admin),
    admin: { id: admin.id, email: admin.email, name: admin.name },
  });
});

authRouter.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const admin = db.prepare('SELECT * FROM admins WHERE email = ?').get(String(email).toLowerCase());
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, admin.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({
    token: signAdminToken(admin),
    admin: { id: admin.id, email: admin.email, name: admin.name },
  });
});

authRouter.get('/me', requireAdmin, (req, res) => {
  const row = db
    .prepare('SELECT id, email, name FROM admins WHERE id = ?')
    .get(req.admin.sub);
  if (!row) return res.status(401).json({ error: 'Account no longer exists' });
  res.json({ admin: { id: row.id, email: row.email, name: row.name } });
});
