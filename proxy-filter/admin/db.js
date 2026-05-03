// Part of proxy-filter module — see /proxy-filter/README.md
//
// Reuses the existing project SQLite database, adding two new tables.
// Existing tables (admins, users, access_requests) are not touched.

import { db } from '../../backend/src/db.js';

db.exec(`
  CREATE TABLE IF NOT EXISTS proxy_users (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    proxy_username TEXT NOT NULL UNIQUE,
    proxy_password TEXT NOT NULL,
    removal_password TEXT NOT NULL,
    proxy_port INTEGER UNIQUE,
    owner_admin_id TEXT REFERENCES admins(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS proxy_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied')),
    requested_at TEXT NOT NULL DEFAULT (datetime('now')),
    reviewed_at TEXT,
    reviewed_by TEXT REFERENCES admins(id) ON DELETE SET NULL
  );

  CREATE INDEX IF NOT EXISTS idx_proxy_requests_status ON proxy_requests(status);
  CREATE INDEX IF NOT EXISTS idx_proxy_requests_user ON proxy_requests(user_id);
  CREATE INDEX IF NOT EXISTS idx_proxy_users_owner ON proxy_users(owner_admin_id);
`);

// Migrations.
const cols = db.prepare("PRAGMA table_info(proxy_users)").all();

// Legacy column from the per-port HTTP-proxy era. Kept (nullable) for
// backwards compatibility with any rows that still have it set.
if (!cols.some((c) => c.name === 'proxy_port')) {
  db.exec("ALTER TABLE proxy_users ADD COLUMN proxy_port INTEGER");
}

// New columns for the IKEv2 architecture.
if (!cols.some((c) => c.name === 'vpn_ip')) {
  db.exec("ALTER TABLE proxy_users ADD COLUMN vpn_ip TEXT");
}
if (!cols.some((c) => c.name === 'p12_password')) {
  db.exec("ALTER TABLE proxy_users ADD COLUMN p12_password TEXT");
}

export { db };
