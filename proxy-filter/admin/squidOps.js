// Part of proxy-filter module — see /proxy-filter/README.md
//
// Filesystem helpers backing the proxy's per-profile rules.
//
// Layout under proxy-filter/server/:
//   passwd                              bcrypt auth (proxy-username:hash)
//   blocklists/adult.txt                shared default blocklist
//   profiles/<user_id>/blocklist.txt    extra domains blocked for this profile
//   profiles/<user_id>/allowlist.txt    domains exempt from blocking for this profile
//
// Decision (proxy applies on every request):
//   if domain ∈ profile.allowlist            → ALLOW
//   else if domain ∈ profile.blocklist       → BLOCK
//   else if domain ∈ default.blocklist       → BLOCK
//   else                                     → ALLOW

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createConnection } from 'node:net';
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  rmSync,
  renameSync,
  readdirSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import bcrypt from 'bcryptjs';

const exec = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));

export const SERVER_DIR = resolve(here, '..', 'server');
export const PASSWD_PATH = join(SERVER_DIR, 'passwd');
export const PROFILES_DIR = join(SERVER_DIR, 'profiles');
export const PORTS_FILE = join(SERVER_DIR, 'ports.json');
export const BLOCKLIST_PATH = join(SERVER_DIR, 'blocklists', 'adult.txt');
export const SQUID_CONTAINER = process.env.SQUID_CONTAINER_NAME || 'proxy-filter-squid';

// Range of ports the proxy listens on. One port per profile.
export const PORT_BASE = 3128;
export const PORT_MAX = 3327;

mkdirSync(PROFILES_DIR, { recursive: true });

// One-shot migration from the old layout (allowlists/<id>.txt) to the new
// profiles/<id>/allowlist.txt layout. Safe to run repeatedly.
(function migrateLegacyAllowlists() {
  const legacyDir = join(SERVER_DIR, 'allowlists');
  if (!existsSync(legacyDir)) return;
  for (const name of readdirSync(legacyDir)) {
    if (!name.endsWith('.txt') || name === 'global.txt') continue;
    const userId = name.slice(0, -4);
    if (!/^[a-z0-9_-]{1,64}$/i.test(userId)) continue;
    const newDir = join(PROFILES_DIR, userId);
    const newPath = join(newDir, 'allowlist.txt');
    if (existsSync(newPath)) continue;
    mkdirSync(newDir, { recursive: true });
    renameSync(join(legacyDir, name), newPath);
  }
})();

// --------------------------------------------------------------------------
// Squid auth (htpasswd-style file)
// --------------------------------------------------------------------------

export function ensurePasswdEntry(username, plainPassword) {
  const hash = bcrypt.hashSync(plainPassword, 10);
  let lines = [];
  if (existsSync(PASSWD_PATH)) {
    lines = readFileSync(PASSWD_PATH, 'utf8').split('\n').filter(Boolean);
    lines = lines.filter((l) => !l.startsWith(`${username}:`));
  }
  lines.push(`${username}:${hash}`);
  writeFileSync(PASSWD_PATH, lines.join('\n') + '\n', { mode: 0o640 });
}

export function removePasswdEntry(username) {
  if (!existsSync(PASSWD_PATH)) return;
  const lines = readFileSync(PASSWD_PATH, 'utf8')
    .split('\n')
    .filter(Boolean)
    .filter((l) => !l.startsWith(`${username}:`));
  writeFileSync(PASSWD_PATH, lines.length ? lines.join('\n') + '\n' : '', { mode: 0o640 });
}

// --------------------------------------------------------------------------
// Domain-list file primitives. One domain per line, # comments allowed.
// --------------------------------------------------------------------------

function readDomainFile(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

function writeDomainFile(path, domains, header) {
  const body = domains.join('\n');
  const out = header ? `${header}\n${body}${body ? '\n' : ''}` : `${body}${body ? '\n' : ''}`;
  writeFileSync(path, out, { mode: 0o644 });
}

function safeUserId(userId) {
  if (!/^[a-z0-9_-]{1,64}$/i.test(userId)) throw new Error('Invalid user_id');
  return userId;
}

// --------------------------------------------------------------------------
// Per-profile directory + lists
// --------------------------------------------------------------------------

export function profileDir(userId) {
  return join(PROFILES_DIR, safeUserId(userId));
}

export function ensureProfileDir(userId) {
  const dir = profileDir(userId);
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function removeProfileDir(userId) {
  const dir = profileDir(userId);
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
}

const PER_PROFILE_HEADER = `# Part of proxy-filter module — see /proxy-filter/README.md
# Per-profile list — managed by the admin dashboard.`;

export function profileBlocklistPath(userId) {
  return join(profileDir(userId), 'blocklist.txt');
}

export function profileAllowlistPath(userId) {
  return join(profileDir(userId), 'allowlist.txt');
}

export function readProfileBlocklist(userId) {
  return readDomainFile(profileBlocklistPath(userId));
}

export function readProfileAllowlist(userId) {
  return readDomainFile(profileAllowlistPath(userId));
}

function addToList(path, domain) {
  const list = readDomainFile(path);
  if (list.includes(domain)) return false;
  list.push(domain);
  list.sort();
  ensureDir(dirname(path));
  writeDomainFile(path, list, PER_PROFILE_HEADER);
  return true;
}

function removeFromList(path, domain) {
  const list = readDomainFile(path);
  const next = list.filter((d) => d !== domain);
  if (next.length === list.length) return false;
  writeDomainFile(path, next, PER_PROFILE_HEADER);
  return true;
}

function ensureDir(p) {
  mkdirSync(p, { recursive: true });
}

export function addToProfileBlocklist(userId, domain) {
  ensureProfileDir(userId);
  return addToList(profileBlocklistPath(userId), domain);
}

export function removeFromProfileBlocklist(userId, domain) {
  return removeFromList(profileBlocklistPath(userId), domain);
}

export function addToProfileAllowlist(userId, domain) {
  ensureProfileDir(userId);
  return addToList(profileAllowlistPath(userId), domain);
}

export function removeFromProfileAllowlist(userId, domain) {
  return removeFromList(profileAllowlistPath(userId), domain);
}

// --------------------------------------------------------------------------
// Default (shared) blocklist — applied to every profile in addition to its
// own per-profile blocklist. Per-profile allowlist still wins over both.
// --------------------------------------------------------------------------

const DEFAULT_BLOCKLIST_HEADER = `# Part of proxy-filter module — see /proxy-filter/README.md
# Default Blocklist applied to every profile (per-profile allowlist still wins).
# Edit directly to bulk-import a list (one domain per line, # comments OK).`;

export function readBlocklist() {
  return readDomainFile(BLOCKLIST_PATH);
}

export function addToBlocklist(domain) {
  const list = readBlocklist();
  if (list.includes(domain)) return false;
  list.push(domain);
  list.sort();
  writeDomainFile(BLOCKLIST_PATH, list, DEFAULT_BLOCKLIST_HEADER);
  return true;
}

export function removeFromBlocklist(domain) {
  const list = readBlocklist();
  const next = list.filter((d) => d !== domain);
  if (next.length === list.length) return false;
  writeDomainFile(BLOCKLIST_PATH, next, DEFAULT_BLOCKLIST_HEADER);
  return true;
}

// --------------------------------------------------------------------------
// Squid status + reload (kept for compatibility — not used by Node proxy).
// --------------------------------------------------------------------------

export async function reloadSquid() {
  try {
    await exec('docker', ['exec', SQUID_CONTAINER, 'squid', '-k', 'reconfigure']);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.stderr?.toString() || err.message };
  }
}

export async function squidIsRunning() {
  try {
    const { stdout } = await exec('docker', ['inspect', '-f', '{{.State.Running}}', SQUID_CONTAINER]);
    return stdout.trim() === 'true';
  } catch {
    return false;
  }
}

export async function tailAccessLog(maxLines = 200) {
  try {
    const { stdout } = await exec('docker', [
      'exec', SQUID_CONTAINER,
      'tail', '-n', String(maxLines),
      '/var/log/squid/access.log',
    ]);
    return stdout.split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

export async function proxyPortListening(port = 3128, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const sock = createConnection({ port, host, timeout: 500 }, () => {
      sock.end();
      resolve(true);
    });
    sock.on('error', () => resolve(false));
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
  });
}

// --------------------------------------------------------------------------
// Per-profile port mapping written to ports.json — read by the proxy at
// runtime to decide which ports to listen on.
// --------------------------------------------------------------------------

import { db } from './db.js';

export function allocatePort() {
  const used = new Set(
    db
      .prepare('SELECT proxy_port FROM proxy_users WHERE proxy_port IS NOT NULL')
      .all()
      .map((r) => r.proxy_port)
  );
  for (let p = PORT_BASE; p <= PORT_MAX; p++) {
    if (!used.has(p)) return p;
  }
  throw new Error(`No free ports in ${PORT_BASE}-${PORT_MAX}`);
}

export function writePortMap() {
  const rows = db
    .prepare('SELECT user_id, proxy_port FROM proxy_users WHERE proxy_port IS NOT NULL')
    .all();
  const map = {};
  for (const r of rows) map[r.user_id] = r.proxy_port;
  writeFileSync(PORTS_FILE, JSON.stringify(map, null, 2) + '\n', { mode: 0o644 });
}

// Refresh ports.json on import so a fresh backend boot picks up existing
// rows (including ones added before this change).
try { writePortMap(); } catch {}
