// Part of proxy-filter module — see /proxy-filter/README.md
//
// One listener per profile, on its own dedicated port. The .mobileconfig
// for each profile points to that profile's specific port; the proxy
// derives the profile identity from which port received the request.
// No HTTP basic auth — many apps (Electron-based tools, etc.) don't
// honor system proxy credentials, so per-port identification is more
// reliable.
//
// Decision per (profile, host):
//   if domain ∈ profile.allowlist           → ALLOW (override)
//   else if domain ∈ profile.blocklist      → BLOCK (this profile only)
//   else if domain ∈ default blocklist      → BLOCK
//   else                                    → ALLOW
//
// The router writes server/ports.json mapping user_id → port. The proxy
// watches that file and adds/removes listeners as profiles are
// created/deleted in the dashboard.

import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import { readFileSync, watchFile, existsSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import forge from 'node-forge';

const here = dirname(fileURLToPath(import.meta.url));
const CA_CERT_PATH = process.env.CA_CERT_PATH || join(here, 'ssl', 'ca.crt');
const CA_KEY_PATH = process.env.CA_KEY_PATH || join(here, 'ssl', 'ca.key');
const DEFAULT_BLOCKLIST = join(here, 'blocklists', 'adult.txt');
const PROFILES_DIR = join(here, 'profiles');
const PORTS_FILE = join(here, 'ports.json');
const HOST = process.env.PROXY_BIND || '0.0.0.0';

// ---------- File loading ----------
function loadDomainFile(path) {
  if (!existsSync(path)) return new Set();
  return new Set(
    readFileSync(path, 'utf8')
      .split('\n')
      .map((l) => l.trim().toLowerCase())
      .filter((l) => l && !l.startsWith('#'))
  );
}

let defaultBlocklist = new Set();
let profiles = new Map();          // user_id → { block:Set, allow:Set }

function loadProfiles() {
  profiles = new Map();
  if (!existsSync(PROFILES_DIR)) return;
  for (const name of readdirSync(PROFILES_DIR)) {
    const dir = join(PROFILES_DIR, name);
    let s;
    try { s = statSync(dir); } catch { continue; }
    if (!s.isDirectory()) continue;
    profiles.set(name, {
      block: loadDomainFile(join(dir, 'blocklist.txt')),
      allow: loadDomainFile(join(dir, 'allowlist.txt')),
    });
  }
}

function loadDefault() {
  defaultBlocklist = loadDomainFile(DEFAULT_BLOCKLIST);
}

loadDefault();
loadProfiles();
watchFile(DEFAULT_BLOCKLIST, { interval: 2000 }, loadDefault);
setInterval(loadProfiles, 2000).unref();

// ---------- Domain matching ----------
function matchesSet(host, set) {
  if (!set || set.size === 0) return false;
  host = host.toLowerCase();
  for (const d of set) {
    if (host === d || host.endsWith('.' + d)) return true;
  }
  return false;
}

function decision(userId, host) {
  const p = profiles.get(userId);
  if (p && matchesSet(host, p.allow)) return 'allow';
  if (p && matchesSet(host, p.block)) return 'block';
  if (matchesSet(host, defaultBlocklist)) return 'block';
  return 'allow';
}

// ---------- CA + per-host cert generation ----------
if (!existsSync(CA_CERT_PATH) || !existsSync(CA_KEY_PATH)) {
  console.error(`Missing CA files. Run: cd server/ssl && ./generate-ca.sh`);
  console.error(`  expected ${CA_CERT_PATH}`);
  console.error(`  expected ${CA_KEY_PATH}`);
  process.exit(1);
}
const caCert = forge.pki.certificateFromPem(readFileSync(CA_CERT_PATH, 'utf8'));
const caKey = forge.pki.privateKeyFromPem(readFileSync(CA_KEY_PATH, 'utf8'));

const certCache = new Map();
function certForHost(host) {
  const cached = certCache.get(host);
  if (cached) return cached;
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = String(Date.now()) + Math.floor(Math.random() * 1e6);
  cert.validity.notBefore = new Date();
  const notAfter = new Date();
  notAfter.setFullYear(notAfter.getFullYear() + 1);
  cert.validity.notAfter = notAfter;
  cert.setSubject([{ name: 'commonName', value: host }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: 'subjectAltName', altNames: [{ type: 2, value: host }] },
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
  ]);
  cert.sign(caKey, forge.md.sha256.create());
  const result = {
    cert: forge.pki.certificateToPem(cert),
    key: forge.pki.privateKeyToPem(keys.privateKey),
  };
  certCache.set(host, result);
  return result;
}

// ---------- Block page ----------
function blockPageHtml(host, profile) {
  const safe = (s) => String(s).replace(/[<>&"']/g, (c) => ({
    '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;'
  }[c]));
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<title>Site Blocked</title>
<style>
  body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
       background:#0f1115;color:#e8eaed;min-height:100vh;display:flex;
       align-items:center;justify-content:center;padding:24px;}
  .card{background:#1f2230;border:1px solid #2a2e3f;border-radius:16px;
        max-width:520px;padding:40px;}
  h1{margin:0 0 8px;font-size:24px;}
  p{margin:0 0 16px;color:#9aa0b4;line-height:1.5;}
  code{background:#14161e;border:1px solid #2a2e3f;border-radius:6px;
       padding:4px 8px;font-family:ui-monospace,monospace;font-size:13px;}
  .meta{font-size:12px;color:#6b7290;margin-top:24px;}
</style></head><body><div class="card">
<h1>🛡️ This site is blocked</h1>
<p>Access to <code>${safe(host)}</code> is restricted by your network policy.</p>
<p>If you need access for a legitimate reason, contact your administrator.</p>
<div class="meta">Profile: ${safe(profile)}</div>
</div></body></html>`;
}

function blockHttpsConnection(clientSocket, host, profile) {
  const { cert, key } = certForHost(host);
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  let secureContext;
  try {
    secureContext = tls.createSecureContext({ cert, key });
  } catch (err) {
    console.error(`[blockTls] secureContext error for ${host}:`, err.message);
    clientSocket.destroy();
    return;
  }
  const tlsSocket = new tls.TLSSocket(clientSocket, { isServer: true, secureContext });
  tlsSocket.on('error', () => {});
  let buf = Buffer.alloc(0);
  tlsSocket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (buf.indexOf(Buffer.from('\r\n\r\n')) === -1) return;
    const body = blockPageHtml(host, profile);
    tlsSocket.write(
      'HTTP/1.1 403 Blocked\r\n' +
      'Content-Type: text/html; charset=utf-8\r\n' +
      `Content-Length: ${Buffer.byteLength(body)}\r\n` +
      'Connection: close\r\n\r\n' + body
    );
    tlsSocket.end();
  });
}

// ---------- Per-profile request handlers (closures over userId) ----------
function handleHttp(req, res, userId) {
  let host;
  try {
    const u = new URL(req.url.startsWith('http') ? req.url : `http://${req.headers.host}${req.url}`);
    host = u.hostname;
  } catch {
    res.writeHead(400); res.end('bad request'); return;
  }
  const verdict = decision(userId, host);
  console.log(`[${verdict.toUpperCase()} http] ${userId} ${req.method} ${host}${req.url}`);
  if (verdict === 'block') {
    res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(blockPageHtml(host, userId));
    return;
  }
  const u = new URL(req.url.startsWith('http') ? req.url : `http://${req.headers.host}${req.url}`);
  const fwdHeaders = { ...req.headers };
  delete fwdHeaders['proxy-authorization'];
  delete fwdHeaders['proxy-connection'];
  const upstream = http.request({
    method: req.method,
    hostname: u.hostname,
    port: u.port || 80,
    path: u.pathname + u.search,
    headers: fwdHeaders,
  }, (upRes) => {
    res.writeHead(upRes.statusCode || 502, upRes.headers);
    upRes.pipe(res);
  });
  upstream.on('error', (err) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Upstream error: ' + err.message);
    }
  });
  req.pipe(upstream);
}

function handleConnect(req, clientSocket, head, userId) {
  const [host, portStr] = req.url.split(':');
  const port = Number(portStr) || 443;
  const verdict = decision(userId, host);
  console.log(`[${verdict.toUpperCase()} https] ${userId} ${host}:${port}`);
  if (verdict === 'block') {
    blockHttpsConnection(clientSocket, host, userId);
    return;
  }
  const upstream = net.connect(port, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  upstream.on('error', (err) => {
    console.log(`[upstream-error] ${userId} ${host}:${port} — ${err.message}`);
    if (!clientSocket.destroyed) clientSocket.end();
  });
  clientSocket.on('error', () => upstream.destroy());
}

function makeServerForUser(userId) {
  const server = http.createServer((req, res) => handleHttp(req, res, userId));
  server.on('connect', (req, sock, head) => handleConnect(req, sock, head, userId));
  server.on('clientError', (err, sock) => {
    if (sock && !sock.destroyed) sock.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });
  return server;
}

// ---------- Listener management driven by ports.json ----------
const servers = new Map(); // userId → { server, port }

function syncListeners() {
  let portMap = {};
  if (existsSync(PORTS_FILE)) {
    try {
      portMap = JSON.parse(readFileSync(PORTS_FILE, 'utf8'));
    } catch (err) {
      console.error('[ports.json] parse error:', err.message);
      portMap = {};
    }
  }

  // Stop listeners for entries that disappeared or whose port changed.
  for (const [userId, info] of [...servers.entries()]) {
    if (!portMap[userId] || portMap[userId] !== info.port) {
      console.log(`[stop] ${userId} (port ${info.port})`);
      info.server.close();
      servers.delete(userId);
    }
  }

  // Start listeners for new entries.
  for (const [userId, port] of Object.entries(portMap)) {
    if (servers.has(userId)) continue;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.error(`[ports.json] invalid port for ${userId}: ${port}`);
      continue;
    }
    const server = makeServerForUser(userId);
    server.on('error', (err) => {
      console.error(`[error] ${userId} on ${port}:`, err.message);
      servers.delete(userId);
    });
    server.listen(port, HOST, () => {
      console.log(`[start] ${userId} listening on ${HOST}:${port}`);
    });
    servers.set(userId, { server, port });
  }

  console.log(`[sync] ${servers.size} listener(s), default-block=${defaultBlocklist.size}, profiles=${profiles.size}`);
}

syncListeners();
watchFile(PORTS_FILE, { interval: 2000 }, syncListeners);

console.log('═══════════════════════════════════════════════');
console.log(`proxy-filter — per-profile listeners`);
console.log(`  CA cert:        ${CA_CERT_PATH}`);
console.log(`  Profiles dir:   ${PROFILES_DIR}`);
console.log(`  Ports file:     ${PORTS_FILE}`);
console.log(`  Default block:  ${defaultBlocklist.size} entries`);
console.log(`  Bind interface: ${HOST}`);
console.log('═══════════════════════════════════════════════');
console.log('No auth required. Profile is identified by which port received the request.');
console.log('Logs every request as [ALLOW|BLOCK http|https] <profile> <host>.');
