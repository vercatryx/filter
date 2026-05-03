import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { db } from './db.js';
import { authRouter } from './routes/auth.js';
import { usersRouter } from './routes/users.js';
import { requestsRouter } from './routes/requests.js';
import { proxyFilterRouter } from '../../proxy-filter/admin/router.js';

const here = dirname(fileURLToPath(import.meta.url));
const ADMIN_DIR = resolve(here, '..', '..', 'admin');

const app = express();

const origins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(cors({ origin: origins.length ? origins : true }));
app.use(express.json({ limit: '256kb' }));

app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.get('/api/config', (req, res) => {
  res.json({
    nextdnsConfigured: Boolean(process.env.NEXTDNS_API_KEY),
    blockPageUrl: process.env.BLOCK_PAGE_URL || null,
  });
});

app.use('/api/auth', authRouter);
app.use('/api/users', usersRouter);
app.use('/api/requests', requestsRouter);
app.use('/api/proxy-filter', proxyFilterRouter);

// Static dashboard frontend. Order matters: this comes AFTER all
// /api/* routers so the API never gets shadowed by a stray static
// asset with a clashing name. Anything not handled above falls
// through to here.
app.use(express.static(ADMIN_DIR, { extensions: ['html'] }));

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal error' });
});

const port = Number(process.env.PORT || 4000);
app.listen(port, () => {
  console.log('═══════════════════════════════════════════════');
  console.log(`Filter API listening on http://localhost:${port}`);
  console.log('Config:');
  console.log('  JWT_SECRET:      ' + (process.env.JWT_SECRET ? '✓ set' : '✗ MISSING'));
  console.log('  NEXTDNS_API_KEY: ' + (process.env.NEXTDNS_API_KEY ? '✓ set' : '✗ MISSING'));
  console.log('  BLOCK_PAGE_URL:  ' + (process.env.BLOCK_PAGE_URL || '(unset)'));
  console.log('  PROXY_HOST:      ' + (process.env.PROXY_HOST || '(unset)'));
  console.log('  CORS_ORIGINS:    ' + (origins.join(', ') || '(any)'));
  console.log('  Static admin:    ' + ADMIN_DIR);
  console.log('═══════════════════════════════════════════════');
  if (!process.env.JWT_SECRET) {
    console.warn('WARNING: JWT_SECRET is not set — auth will fail.');
  }
  if (!process.env.NEXTDNS_API_KEY) {
    console.warn('WARNING: NEXTDNS_API_KEY is not set — profile creation and settings will fail.');
  }
});
