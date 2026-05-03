// IKEv2-architecture lifecycle helpers used by the dashboard router.
//
// Replaces the per-port HTTP-proxy bits in squidOps.js for everything
// that was specific to the old design (passwd file writes, port
// allocation). Everything filesystem-shaped that the new architecture
// still uses (per-profile blocklist + allowlist, default blocklist,
// exclusions) is reused unchanged.

import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import {
  existsSync, readFileSync, writeFileSync, mkdirSync,
  rmSync, readdirSync, statSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { db } from './db.js';

const exec = promisify(execFile);

const here = dirname(fileURLToPath(import.meta.url));
export const SERVER_DIR = resolve(here, '..', 'server');
export const PROFILES_DIR = join(SERVER_DIR, 'profiles');
export const ALLOC_FILE = join(SERVER_DIR, 'vpn-allocations.json');
export const RULES_FILE = join(SERVER_DIR, 'rules.json');
export const SCRIPTS_DIR = join(SERVER_DIR, 'scripts');
export const MINT_DEVICE_CERT = join(SCRIPTS_DIR, 'mint-device-cert.sh');
export const RELOAD_SCRIPT = join(SCRIPTS_DIR, 'reload-config.sh');

mkdirSync(PROFILES_DIR, { recursive: true });

// VPN-internal subnet: 10.10.10.0/24, .1 reserved for the server.
const VPN_BASE_OCTETS = [10, 10, 10];
const VPN_FIRST_HOST = 2;       // .2 onwards
const VPN_LAST_HOST = 254;

export function allocateVpnIp() {
  const used = new Set(
    db.prepare("SELECT vpn_ip FROM proxy_users WHERE vpn_ip IS NOT NULL").all().map((r) => r.vpn_ip)
  );
  for (let h = VPN_FIRST_HOST; h <= VPN_LAST_HOST; h++) {
    const ip = `${VPN_BASE_OCTETS.join('.')}.${h}`;
    if (!used.has(ip)) return ip;
  }
  throw new Error(`No free IPs in 10.10.10.${VPN_FIRST_HOST}-${VPN_LAST_HOST}`);
}

export function writeAllocations() {
  const rows = db.prepare(`
    SELECT user_id, vpn_ip
    FROM proxy_users
    WHERE vpn_ip IS NOT NULL
  `).all();
  const map = {};
  for (const r of rows) map[r.user_id] = r.vpn_ip;
  writeFileSync(ALLOC_FILE, JSON.stringify(map, null, 2) + '\n');
}

export function mintDeviceCert(userId, p12Password) {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(userId)) throw new Error('Invalid user_id');
  // Synchronous: we want to fail the API call if cert minting fails.
  const out = execFileSync(
    '/bin/bash',
    [MINT_DEVICE_CERT, userId, p12Password],
    { cwd: SERVER_DIR, stdio: ['ignore', 'pipe', 'pipe'] }
  ).toString();
  // Parse "OK <p12_path>" — but we know where it should be:
  const expected = join(PROFILES_DIR, userId, `${userId}.p12`);
  if (!existsSync(expected)) {
    throw new Error(`mint-device-cert.sh did not produce ${expected}\n${out}`);
  }
  return expected;
}

export function profileDir(userId) {
  return join(PROFILES_DIR, userId);
}

export function ensureProfileDir(userId) {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(userId)) throw new Error('Invalid user_id');
  const dir = profileDir(userId);
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function removeProfileDir(userId) {
  const dir = profileDir(userId);
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
}

// --- per-profile rule files (reused unchanged from old design) ---
const PER_PROFILE_HEADER = `# Per-profile list — managed by the admin dashboard.`;

function readDomainFile(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

function writeDomainFile(path, domains) {
  const out = `${PER_PROFILE_HEADER}\n${domains.join('\n')}${domains.length ? '\n' : ''}`;
  writeFileSync(path, out);
}

export function readProfileBlocklist(userId)  { return readDomainFile(join(profileDir(userId), 'blocklist.txt')); }
export function readProfileAllowlist(userId)  { return readDomainFile(join(profileDir(userId), 'allowlist.txt')); }
export function addToProfileBlocklist(userId, domain) {
  ensureProfileDir(userId);
  const p = join(profileDir(userId), 'blocklist.txt');
  const list = readDomainFile(p);
  if (list.includes(domain)) return false;
  list.push(domain); list.sort();
  writeDomainFile(p, list); return true;
}
export function removeFromProfileBlocklist(userId, domain) {
  const p = join(profileDir(userId), 'blocklist.txt');
  const list = readDomainFile(p);
  const next = list.filter((d) => d !== domain);
  if (next.length === list.length) return false;
  writeDomainFile(p, next); return true;
}
export function addToProfileAllowlist(userId, domain) {
  ensureProfileDir(userId);
  const p = join(profileDir(userId), 'allowlist.txt');
  const list = readDomainFile(p);
  if (list.includes(domain)) return false;
  list.push(domain); list.sort();
  writeDomainFile(p, list); return true;
}
export function removeFromProfileAllowlist(userId, domain) {
  const p = join(profileDir(userId), 'allowlist.txt');
  const list = readDomainFile(p);
  const next = list.filter((d) => d !== domain);
  if (next.length === list.length) return false;
  writeDomainFile(p, next); return true;
}

// --- default (shared) blocklist ---
const DEFAULT_BLOCKLIST_PATH = join(SERVER_DIR, 'blocklists', 'adult.txt');
const DEFAULT_HEADER = `# Default Blocklist applied to every profile.`;

export function readBlocklist() { return readDomainFile(DEFAULT_BLOCKLIST_PATH); }
export function addToBlocklist(domain) {
  const list = readBlocklist();
  if (list.includes(domain)) return false;
  list.push(domain); list.sort();
  writeFileSync(DEFAULT_BLOCKLIST_PATH, `${DEFAULT_HEADER}\n${list.join('\n')}\n`);
  return true;
}
export function removeFromBlocklist(domain) {
  const list = readBlocklist();
  const next = list.filter((d) => d !== domain);
  if (next.length === list.length) return false;
  writeFileSync(DEFAULT_BLOCKLIST_PATH, `${DEFAULT_HEADER}\n${next.join('\n')}\n`);
  return true;
}

// --- exclusions list (cert-pinning passthrough) ---
export const EXCLUSIONS_PATH = join(SERVER_DIR, 'mitm', 'exclusions.txt');

export function readExclusions() {
  if (!existsSync(EXCLUSIONS_PATH)) return [];
  return readDomainFile(EXCLUSIONS_PATH);
}

// --- reload (regen ipsec.conf + rules.json + reload services) ---
export async function reloadServer() {
  if (!existsSync(RELOAD_SCRIPT)) {
    return { ok: false, error: `reload script missing: ${RELOAD_SCRIPT}` };
  }
  try {
    const { stdout, stderr } = await exec('/bin/bash', [RELOAD_SCRIPT], {
      cwd: SERVER_DIR,
      timeout: 15_000,
    });
    return { ok: true, stdout, stderr };
  } catch (err) {
    return { ok: false, error: err.stderr?.toString() || err.message };
  }
}

// --- status check (does server look configured?) ---
export async function serverStatus() {
  // Just a few file existence checks; full health needs to ssh into
  // the box / read launchctl.
  return {
    caCertExists: existsSync(join(SERVER_DIR, 'ssl', 'ca.crt')),
    serverCertExists: existsSync(join(SERVER_DIR, 'ipsec', 'vpn-server.crt')),
    allocations: existsSync(ALLOC_FILE) ? Object.keys(JSON.parse(readFileSync(ALLOC_FILE, 'utf8'))).length : 0,
  };
}
