// Generate a .mobileconfig that installs the localtest setup on this Mac:
//   - Trusts our existing CA (system root)
//   - Configures WireGuard.app to tunnel everything to mitmproxy on 127.0.0.1
//   - Locks the System Settings panes that would let a regular user undo it
//   - Sets a removal password — profile can only be removed with it
//
// Prereqs:
//   - WireGuard.app installed from the Mac App Store (one time, free).
//     Search "WireGuard" — published by WireGuard Development Team.
//   - mitmproxy running (started by ./start.sh, listens on UDP/51820).
//   - Existing CA at proxy-filter/server/ssl/ca.{crt,key}.
//
// Output:
//   wg/localtest.mobileconfig — open this; macOS will guide you through
//   installation. The removal password is printed to stdout — save it.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, randomBytes } from 'node:crypto';
import forge from '../node_modules/node-forge/lib/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const SERVER_DIR = resolve(here, '..', 'server');
const CA_CRT = `${SERVER_DIR}/ssl/ca.crt`;
const KEYS_JSON = resolve(here, 'wg', 'wireguard.conf');
const OUT = resolve(here, 'wg', 'localtest.mobileconfig');

if (!existsSync(CA_CRT)) {
  console.error(`CA missing: ${CA_CRT}`);
  console.error(`Run: cd ../server/ssl && ./generate-ca.sh`);
  process.exit(1);
}
if (!existsSync(KEYS_JSON)) {
  console.error(`mitmproxy keys missing: ${KEYS_JSON}`);
  console.error(`Run ./start.sh first to seed them.`);
  process.exit(1);
}

const PROFILE_ID = 'localtest';
const REMOVAL_PASSWORD = randomBytes(18).toString('base64url');

// --- CA cert (DER, base64) for the root payload ---
const caPem = readFileSync(CA_CRT, 'utf8');
const caCert = forge.pki.certificateFromPem(caPem);
const caDerB64 = forge.util.encode64(
  forge.asn1.toDer(forge.pki.certificateToAsn1(caCert)).getBytes()
);

// --- WireGuard config string (mirrors wg/import.conf) ---
const keys = JSON.parse(readFileSync(KEYS_JSON, 'utf8'));
const serverPub = execSync(
  `printf '%s' "${keys.server_key}" | wg pubkey`,
  { shell: '/bin/bash' }
).toString().trim();

// We bake a *public* DNS in here (not mitmproxy's 10.0.0.53) so DNS
// keeps working even if mitmproxy doesn't reply on its internal DNS
// address. DNS goes through the tunnel and out via mitmproxy's egress
// to 1.1.1.1.
const wgConfig = `[Interface]
PrivateKey = ${keys.client_key}
Address = 10.0.0.1/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = ${serverPub}
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 25
`;

const u = () => randomUUID().toUpperCase();
const profileUuid = u();
const caUuid = u();
const vpnUuid = u();
const lockdownUuid = u();
const removalUuid = u();

function escapeXml(s) {
  return String(s).replace(/[<>&'"]/g, (c) => ({
    '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;'
  }[c]));
}
function wrap76(b64) { return b64.match(/.{1,76}/g).join('\n            '); }

const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>proxy-filter (local test)</string>
    <key>PayloadDescription</key>
    <string>Routes this Mac's traffic through a local mitmproxy for filter testing. Only removable with the administrator-issued password.</string>
    <key>PayloadIdentifier</key>
    <string>com.proxyfilter.localtest.${PROFILE_ID}</string>
    <key>PayloadOrganization</key>
    <string>proxy-filter</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${profileUuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadScope</key>
    <string>System</string>
    <key>ConsentText</key>
    <dict>
        <key>default</key>
        <string>This profile installs network filter settings. It can only be removed with the administrator-issued removal password.</string>
    </dict>
    <key>PayloadContent</key>
    <array>

        <!-- 1. CA root certificate (auto-trusted at System scope) -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadIdentifier</key>
            <string>com.proxyfilter.localtest.ca</string>
            <key>PayloadUUID</key>
            <string>${caUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Filter Inspection CA</string>
            <key>PayloadCertificateFileName</key>
            <string>ca.crt</string>
            <key>PayloadContent</key>
            <data>
            ${wrap76(caDerB64)}
            </data>
        </dict>

        <!-- 2. WireGuard VPN — points at mitmproxy on this same Mac -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadIdentifier</key>
            <string>com.proxyfilter.localtest.vpn</string>
            <key>PayloadUUID</key>
            <string>${vpnUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Filter (local)</string>
            <key>UserDefinedName</key>
            <string>filter-localtest</string>
            <key>VPNType</key>
            <string>VPN</string>
            <key>VPNSubType</key>
            <string>com.wireguard.macos</string>
            <key>VendorConfig</key>
            <dict>
                <key>WgQuickConfig</key>
                <string>${escapeXml(wgConfig)}</string>
            </dict>
            <key>OnDemandEnabled</key>
            <integer>1</integer>
            <key>OnDemandRules</key>
            <array>
                <dict>
                    <key>Action</key>
                    <string>Connect</string>
                </dict>
            </array>
        </dict>

        <!-- 3. System Settings lockdown -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.systempreferences</string>
            <key>PayloadIdentifier</key>
            <string>com.proxyfilter.localtest.lockdown</string>
            <key>PayloadUUID</key>
            <string>${lockdownUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>System Settings Lockdown</string>
            <key>DisabledPreferencePanes</key>
            <array>
                <string>com.apple.preference.network</string>
                <string>com.apple.preferences.configurationprofiles</string>
                <string>com.apple.preference.security</string>
            </array>
        </dict>

        <!-- 4. Removal password -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.profileRemovalPassword</string>
            <key>PayloadIdentifier</key>
            <string>com.proxyfilter.localtest.removal</string>
            <key>PayloadUUID</key>
            <string>${removalUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Removal Password</string>
            <key>RemovalPassword</key>
            <string>${escapeXml(REMOVAL_PASSWORD)}</string>
        </dict>

    </array>
</dict>
</plist>
`;

writeFileSync(OUT, xml);

console.log(`Wrote ${OUT}`);
console.log(`Size: ${xml.length} bytes`);
console.log();
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log(`REMOVAL PASSWORD:  ${REMOVAL_PASSWORD}`);
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('Save this password somewhere safe. Without it you cannot');
console.log('uninstall the profile from System Settings.');
console.log();
console.log('Next:');
console.log('  1. Install WireGuard.app from the Mac App Store (one time).');
console.log('     Search "WireGuard" — published by WireGuard Development Team.');
console.log('     (Do NOT use brew — that name resolves to a different product.)');
console.log();
console.log(`  2. Open the profile:  open '${OUT}'`);
console.log('     macOS opens System Settings → Privacy & Security → Profiles.');
console.log('     Click the profile → Install → enter your Mac admin password.');
console.log();
console.log('  3. The VPN auto-connects within ~5 seconds. Verify in the');
console.log('     menu-bar WireGuard icon → "filter-localtest" should be on.');
console.log();
console.log('  4. Test:  curl https://777.com  → should return our 🛡️ block page.');
console.log('     Tail the proxy:  tail -f /tmp/proxy-filter-localtest.log');
console.log();
console.log('  5. To uninstall: System Settings → Privacy & Security → Profiles');
console.log('     → click "proxy-filter (local test)" → Remove → enter the');
console.log('     removal password above.');
