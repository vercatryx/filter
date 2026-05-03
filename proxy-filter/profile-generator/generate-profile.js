// Part of proxy-filter module — see /proxy-filter/README.md
//
// Generates a per-user .mobileconfig file by filling in profile-template.xml
// with the user's proxy credentials, the CA cert (base64-encoded), fresh
// UUIDs, and the removal password.
//
// Usage (CLI):
//   USER_ID=alice PROXY_HOST=10.0.0.5 PROXY_PORT=3128 \
//   PROXY_USERNAME=alice PROXY_PASSWORD=hunter2 \
//   REMOVAL_PASSWORD=secret CA_CERT_PATH=../server/ssl/ca.crt \
//   node generate-profile.js
//
//   # OR positionally:
//   node generate-profile.js --user-id=alice --proxy-host=10.0.0.5 ...
//
// Programmatic:
//   import { generateProfile } from './generate-profile.js';
//   const xml = generateProfile({ userId, proxyHost, ... });
//
// NOTE: Output files contain plaintext proxy and removal passwords.
// /output/ is gitignored — do not commit generated profiles.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const TEMPLATE_PATH = join(here, 'profile-template.xml');

function escapeXml(s) {
  return String(s).replace(/[<>&'"]/g, (c) => ({
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    "'": '&apos;',
    '"': '&quot;',
  }[c]));
}

export function generateProfile({
  userId,
  proxyHost,
  proxyPort,
  removalPassword,
  caCertPath,
  caCertPem,
  dohUrl = 'https://family.cloudflare-dns.com/dns-query',
}) {
  if (!userId) throw new Error('userId is required');
  if (!proxyHost) throw new Error('proxyHost is required');
  if (!removalPassword) throw new Error('removalPassword is required');

  const port = Number(proxyPort) || 3128;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error('proxyPort must be a valid port number');
  }

  let pem = caCertPem;
  if (!pem) {
    if (!caCertPath) throw new Error('caCertPath or caCertPem is required');
    pem = readFileSync(caCertPath, 'utf8');
  }
  // Strip PEM headers/footers + whitespace, leaving only base64 cert body.
  const base64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');

  const template = readFileSync(TEMPLATE_PATH, 'utf8');

  const replacements = {
    USER_ID: escapeXml(userId),
    PROFILE_UUID: randomUUID().toUpperCase(),
    PAYLOAD_1_UUID: randomUUID().toUpperCase(),
    PAYLOAD_2_UUID: randomUUID().toUpperCase(),
    PAYLOAD_3_UUID: randomUUID().toUpperCase(),
    PAYLOAD_4_UUID: randomUUID().toUpperCase(),
    PAYLOAD_5_UUID: randomUUID().toUpperCase(),
    PAYLOAD_6_UUID: randomUUID().toUpperCase(),
    PAYLOAD_7_UUID: randomUUID().toUpperCase(),
    PAYLOAD_8_UUID: randomUUID().toUpperCase(),
    PAYLOAD_9_UUID: randomUUID().toUpperCase(),
    BASE64_CA_CERT: base64,
    PROXY_HOST: escapeXml(proxyHost),
    PROXY_PORT: String(port),
    REMOVAL_PASSWORD: escapeXml(removalPassword),
    DOH_URL: escapeXml(dohUrl),
  };

  return template.replace(/\{([A-Z0-9_]+)\}/g, (match, key) => {
    if (key in replacements) return replacements[key];
    throw new Error(`Unfilled placeholder in template: ${match}`);
  });
}

function parseArg(name) {
  const flag = `--${name}=`;
  const found = process.argv.find((a) => a.startsWith(flag));
  if (found) return found.slice(flag.length);
  const env = name.toUpperCase().replace(/-/g, '_');
  return process.env[env];
}

function isMain() {
  return import.meta.url === `file://${process.argv[1]}`;
}

if (isMain()) {
  try {
    const userId = parseArg('user-id');
    const xml = generateProfile({
      userId,
      proxyHost: parseArg('proxy-host'),
      proxyPort: parseArg('proxy-port'),
      removalPassword: parseArg('removal-password'),
      caCertPath: parseArg('ca-cert-path'),
      dohUrl: parseArg('doh-url'),
    });
    const outDir = resolve(here, 'output');
    if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
    const outPath = join(outDir, `${userId}.mobileconfig`);
    writeFileSync(outPath, xml);
    console.log(`✓ Wrote ${outPath}`);
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
}
