// Spike A: prove we can generate a single .mobileconfig that combines:
//   1. IKEv2 VPN payload (works on macOS + iOS, no app needed)
//   2. CA certificate payload (the proxy's CA the device must trust)
//   3. Certificate Trust Settings payload (auto-trust the CA, so the user
//      doesn't have to flip the toggle in Settings → General → About →
//      Certificate Trust Settings on iOS — though on iOS unsupervised
//      devices, "full trust" still requires a single manual flip; we set
//      it as trusted root anyway)
//   4. Per-device IKEv2 client cert + private key (PKCS12 payload)
//   5. System Settings lockdown payload (macOS only — iOS doesn't have
//      analogous prefpanes)
//   6. Profile removal password
//
// We then lint with plutil and inspect structure with `security cms` if
// signing later. Goal: prove the schema is valid.

import { writeFileSync, readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import forge from '/Users/david/Vercatryx Projects/Filter/proxy-filter/node_modules/node-forge/lib/index.js';

const OUT = '/Users/david/Vercatryx Projects/Filter/spikes/spike-a.mobileconfig';
const CA_DIR = '/Users/david/Vercatryx Projects/Filter/proxy-filter/server/ssl';
const CA_PEM = readFileSync(`${CA_DIR}/ca.crt`, 'utf8');
const CA_KEY_PEM = readFileSync(`${CA_DIR}/ca.key`, 'utf8');

const caCert = forge.pki.certificateFromPem(CA_PEM);
const caKey = forge.pki.privateKeyFromPem(CA_KEY_PEM);

// --- 1. Per-device IKEv2 client cert + key, signed by our CA -----------
function makeClientCert(commonName) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01' + Date.now().toString();
  cert.validity.notBefore = new Date();
  const notAfter = new Date(); notAfter.setFullYear(notAfter.getFullYear() + 5);
  cert.validity.notAfter = notAfter;
  cert.setSubject([{ name: 'commonName', value: commonName }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', clientAuth: true },
    { name: 'subjectAltName', altNames: [{ type: 2, value: commonName }] },
  ]);
  cert.sign(caKey, forge.md.sha256.create());
  return { cert, keys };
}

const PROFILE_NAME = 'sarah-test';
const VPN_SERVER = 'vpn.example.com';
const REMOVAL_PASSWORD = 'test-removal-pw-' + Date.now();
const PKCS12_PW = 'temp-p12-' + Date.now(); // password to encrypt the bundled key

const { cert: clientCert, keys: clientKeys } = makeClientCert(PROFILE_NAME);

// --- 2. Bundle client cert + key as PKCS#12 (.p12) ---------------------
// macOS/iOS profiles deliver client certs as base64 PKCS12 inside a
// com.apple.security.pkcs12 payload.
const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
  clientKeys.privateKey,
  [clientCert, caCert],
  PKCS12_PW,
  { algorithm: '3des' }  // iOS supports 3des for PKCS#12; AES is newer
);
const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
const p12Base64 = Buffer.from(p12Der, 'binary').toString('base64');

// --- 3. Base64-encoded CA cert (DER) for the root payload --------------
const caDerB64 = forge.util.encode64(
  forge.asn1.toDer(forge.pki.certificateToAsn1(caCert)).getBytes()
);

// --- 4. Generate UUIDs --------------------------------------------------
const u = () => randomUUID().toUpperCase();
const profileUuid = u();
const caPayloadUuid = u();
const p12PayloadUuid = u();
const vpnPayloadUuid = u();
const lockdownPayloadUuid = u();
const removalPayloadUuid = u();
const trustUuid = u();

// --- 5. Build the plist -------------------------------------------------
function escapeXml(s) {
  return String(s).replace(/[<>&'"]/g, (c) => ({
    '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;'
  }[c]));
}

// Wrap a base64 blob into 76-char lines like Apple does (cosmetic but
// matches what plutil produces).
function wrap76(b64) {
  return b64.match(/.{1,76}/g).join('\n            ');
}

const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>Network Filter Configuration</string>
    <key>PayloadDescription</key>
    <string>Configures filtered network access. Removable only with the administrator-issued password.</string>
    <key>PayloadIdentifier</key>
    <string>com.device.networkfilter.${escapeXml(PROFILE_NAME)}</string>
    <key>PayloadOrganization</key>
    <string>Filter</string>
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
        <string>This profile installs network filtering settings on this device. It can only be removed with the administrator-issued removal password.</string>
    </dict>
    <key>PayloadContent</key>
    <array>

        <!-- Payload 1: CA root certificate (used to MITM-inspect HTTPS) -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkfilter.ca.${escapeXml(PROFILE_NAME)}</string>
            <key>PayloadUUID</key>
            <string>${caPayloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Network Inspection CA</string>
            <key>PayloadCertificateFileName</key>
            <string>ca.crt</string>
            <key>PayloadContent</key>
            <data>
            ${wrap76(caDerB64)}
            </data>
        </dict>

        <!-- Payload 2: Per-device IKEv2 client identity (PKCS#12) -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.pkcs12</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkfilter.identity.${escapeXml(PROFILE_NAME)}</string>
            <key>PayloadUUID</key>
            <string>${p12PayloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Device VPN Identity</string>
            <key>PayloadCertificateFileName</key>
            <string>${escapeXml(PROFILE_NAME)}.p12</string>
            <key>Password</key>
            <string>${escapeXml(PKCS12_PW)}</string>
            <key>PayloadContent</key>
            <data>
            ${wrap76(p12Base64)}
            </data>
        </dict>

        <!-- Payload 3: VPN (IKEv2, always-on, native to macOS + iOS) -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkfilter.vpn.${escapeXml(PROFILE_NAME)}</string>
            <key>PayloadUUID</key>
            <string>${vpnPayloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Filter VPN</string>
            <key>UserDefinedName</key>
            <string>Filter VPN</string>
            <key>VPNType</key>
            <string>IKEv2</string>
            <key>VPNSubType</key>
            <string></string>
            <key>IKEv2</key>
            <dict>
                <key>RemoteAddress</key>
                <string>${escapeXml(VPN_SERVER)}</string>
                <key>RemoteIdentifier</key>
                <string>${escapeXml(VPN_SERVER)}</string>
                <key>LocalIdentifier</key>
                <string>${escapeXml(PROFILE_NAME)}</string>
                <key>AuthenticationMethod</key>
                <string>Certificate</string>
                <key>PayloadCertificateUUID</key>
                <string>${p12PayloadUuid}</string>
                <key>ServerCertificateIssuerCommonName</key>
                <string>Proxy Filter CA</string>
                <key>ExtendedAuthEnabled</key>
                <integer>0</integer>
                <key>EnablePFS</key>
                <true/>
                <key>DisableMOBIKE</key>
                <integer>0</integer>
                <key>DisableRedirect</key>
                <integer>0</integer>
                <key>EnableCertificateRevocationCheck</key>
                <integer>0</integer>
                <key>UseConfigurationAttributeInternalIPSubnet</key>
                <integer>0</integer>
                <key>NATKeepAliveOffloadEnable</key>
                <integer>1</integer>
                <key>DeadPeerDetectionRate</key>
                <string>Medium</string>
                <key>IKESecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-256-GCM</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-256</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>20</integer>
                    <key>LifeTimeInMinutes</key>
                    <integer>1440</integer>
                </dict>
                <key>ChildSecurityAssociationParameters</key>
                <dict>
                    <key>EncryptionAlgorithm</key>
                    <string>AES-256-GCM</string>
                    <key>IntegrityAlgorithm</key>
                    <string>SHA2-256</string>
                    <key>DiffieHellmanGroup</key>
                    <integer>20</integer>
                    <key>LifeTimeInMinutes</key>
                    <integer>1440</integer>
                </dict>
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

        <!-- Payload 4: System Settings lockdown (macOS only — quietly
             ignored on iOS, which has its own restrictions payload format) -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.systempreferences</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkfilter.sysprefs.${escapeXml(PROFILE_NAME)}</string>
            <key>PayloadUUID</key>
            <string>${lockdownPayloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>System Preferences Lockdown</string>
            <key>DisabledPreferencePanes</key>
            <array>
                <string>com.apple.preference.network</string>
                <string>com.apple.preferences.configurationprofiles</string>
                <string>com.apple.preference.security</string>
            </array>
        </dict>

        <!-- Payload 5: Profile removal password -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.profileRemovalPassword</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkfilter.removal.${escapeXml(PROFILE_NAME)}</string>
            <key>PayloadUUID</key>
            <string>${removalPayloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Profile Removal Password</string>
            <key>RemovalPassword</key>
            <string>${escapeXml(REMOVAL_PASSWORD)}</string>
        </dict>

    </array>
</dict>
</plist>
`;

writeFileSync(OUT, xml);
console.log(`Wrote ${OUT} (${xml.length} bytes)`);
console.log(`PKCS#12 password: ${PKCS12_PW}`);
console.log(`Removal password: ${REMOVAL_PASSWORD}`);

// --- Validate ---
console.log('\n=== plutil -lint ===');
try {
  execSync(`plutil -lint "${OUT}"`, { stdio: 'inherit' });
} catch (e) {
  console.log('plutil failed');
}

console.log('\n=== payload count ===');
const xmlText = readFileSync(OUT, 'utf8');
const payloadTypes = (xmlText.match(/<key>PayloadType<\/key>\s*\n\s*<string>([^<]+)<\/string>/g) || [])
  .map(m => m.match(/<string>([^<]+)/)[1]);
console.log(payloadTypes);

console.log('\n=== UUIDs unique? ===');
const uuids = xmlText.match(/[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}/g) || [];
console.log(`total: ${uuids.length}, unique: ${new Set(uuids).size}`);

console.log('\n=== embedded CA visible in profile? ===');
console.log('CA byte length in DER:', Buffer.from(caDerB64, 'base64').length);
console.log('Embedded as base64 in profile:', xmlText.includes(caDerB64.slice(0, 40)) ? 'yes' : 'NO');

console.log('\n=== embedded P12 visible? ===');
console.log('P12 byte length:', Buffer.from(p12Base64, 'base64').length);
console.log('Embedded:', xmlText.includes(p12Base64.slice(0, 40)) ? 'yes' : 'NO');
