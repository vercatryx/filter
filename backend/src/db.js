import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dbPath = join(here, '..', 'data', 'filter.db');
mkdirSync(dirname(dbPath), { recursive: true });

export const db = new DatabaseSync(dbPath);
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    admin_id TEXT REFERENCES admins(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    nextdns_profile_id TEXT NOT NULL,
    removal_password TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS access_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','denied')),
    requested_at TEXT NOT NULL DEFAULT (datetime('now')),
    reviewed_at TEXT,
    reviewed_by TEXT REFERENCES admins(id) ON DELETE SET NULL
  );

  CREATE INDEX IF NOT EXISTS idx_requests_status ON access_requests(status);
  CREATE INDEX IF NOT EXISTS idx_requests_user ON access_requests(user_id);
  CREATE INDEX IF NOT EXISTS idx_users_nextdns ON users(nextdns_profile_id);
  CREATE INDEX IF NOT EXISTS idx_users_admin ON users(admin_id);
`);

const userCols = db.prepare("PRAGMA table_info(users)").all();
if (!userCols.some((c) => c.name === 'admin_id')) {
  db.exec("ALTER TABLE users ADD COLUMN admin_id TEXT REFERENCES admins(id) ON DELETE CASCADE");
  db.exec("CREATE INDEX IF NOT EXISTS idx_users_admin ON users(admin_id)");
}
