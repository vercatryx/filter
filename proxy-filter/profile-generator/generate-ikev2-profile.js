// Generate the IKEv2 .mobileconfig the dashboard hands to a target
// device. Same payload combo we validated in Spike A:
//
//   1. CA cert (com.apple.security.root) — auto-trusted at System scope
//   2. Per-device IKEv2 client identity (com.apple.security.pkcs12)
//   3. IKEv2 VPN payload referencing the PKCS#12 by UUID
//   4. System Settings lockdown (Network/Profiles/Security panes)
//   5. Removal-password protection
//
// The PKCS#12 itself is generated outside this module by
// scripts/mint-device-cert.sh, which writes it to
// server/profiles/<user_id>/<user_id>.p12. The dashboard reads that
// file and the password from the DB and passes both to this function.

import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

function escapeXml(s) {
  return String(s).replace(/[<>&'"]/g, (c) => ({
    '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;'
  }[c]));
}

function wrap76(b64) {
  return b64.match(/.{1,76}/g).join('\n            ');
}

/**
 * @param {object} args
 * @param {string} args.userId            unique identifier (also the cert CN)
 * @param {string} args.vpnHost           IP or hostname of the VPN server
 * @param {string} args.serverCertCN      CN of the server cert (Apple verifies SAN match)
 * @param {string} args.caCrtPath         path to our CA cert (PEM)
 * @param {string} args.p12Path           path to the per-device PKCS#12 file
 * @param {string} args.p12Password       password the PKCS#12 was encrypted with
 * @param {string} args.removalPassword   plaintext removal password
 * @returns {string} XML .mobileconfig
 */
export function generateIkev2Profile({
  userId,
  vpnHost,
  serverCertCN,
  caCrtPath,
  p12Path,
  p12Password,
  removalPassword,
}) {
  if (!userId || !vpnHost || !p12Path || !p12Password || !removalPassword) {
    throw new Error('generateIkev2Profile: missing required arg');
  }

  // Read CA + PKCS#12 binaries, base64-encode them for the plist <data>.
  const caPem = readFileSync(caCrtPath, 'utf8');
  const caDer = pemToDer(caPem);
  const caB64 = caDer.toString('base64');

  const p12Buf = readFileSync(p12Path);
  const p12B64 = p12Buf.toString('base64');

  // Apple verifies that the server cert's CN or SAN contains
  // ServerCertificateIssuerCommonName, OR matches RemoteIdentifier.
  // Our server cert has CN = <vpnHost> (set at mint time) and SAN
  // includes both DNS:vpn.proxyfilter.local and IP:<vpnHost>. Default
  // RemoteIdentifier to the host the device is dialing.
  const remoteIdentifier = serverCertCN || vpnHost;

  const u = () => randomUUID().toUpperCase();
  const profileUuid = u();
  const caPayloadUuid = u();
  const p12PayloadUuid = u();
  const vpnPayloadUuid = u();
  const lockdownPayloadUuid = u();
  const removalPayloadUuid = u();

  const id = escapeXml(userId);
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>Network Filter</string>
    <key>PayloadDescription</key>
    <string>Routes this device's traffic through your administrator's network filter. Removable only with the administrator-issued password.</string>
    <key>PayloadIdentifier</key>
    <string>com.proxyfilter.profile.${id}</string>
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
        <string>This profile installs network filter settings on this device. It can only be removed with the administrator-issued removal password.</string>
    </dict>
    <key>PayloadContent</key>
    <array>

        <!-- 1. CA root certificate (auto-trusted at System scope) -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadIdentifier</key>
            <string>com.proxyfilter.profile.ca.${id}</string>
            <key>PayloadUUID</key>
            <string>${caPayloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Filter Inspection CA</string>
            <key>PayloadCertificateFileName</key>
            <string>ca.crt</string>
            <key>PayloadContent</key>
            <data>
            ${wrap76(caB64)}
            </data>
        </dict>

        <!-- 2. Per-device IKEv2 client identity -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.pkcs12</string>
            <key>PayloadIdentifier</key>
            <string>com.proxyfilter.profile.identity.${id}</string>
            <key>PayloadUUID</key>
            <string>${p12PayloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Device VPN Identity</string>
            <key>PayloadCertificateFileName</key>
            <string>${id}.p12</string>
            <key>Password</key>
            <string>${escapeXml(p12Password)}</string>
            <key>PayloadContent</key>
            <data>
            ${wrap76(p12B64)}
            </data>
        </dict>

        <!-- 3. IKEv2 VPN — always-on, points at our server -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.vpn.managed</string>
            <key>PayloadIdentifier</key>
            <string>com.proxyfilter.profile.vpn.${id}</string>
            <key>PayloadUUID</key>
            <string>${vpnPayloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Filter VPN</string>
            <key>UserDefinedName</key>
            <string>filter-${id}</string>
            <key>VPNType</key>
            <string>IKEv2</string>
            <key>VPNSubType</key>
            <string></string>
            <key>IKEv2</key>
            <dict>
                <key>RemoteAddress</key>
                <string>${escapeXml(vpnHost)}</string>
                <key>RemoteIdentifier</key>
                <string>${escapeXml(remoteIdentifier)}</string>
                <key>LocalIdentifier</key>
                <string>${id}</string>
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
                    <integer>16</integer>
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
                    <integer>16</integer>
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

        <!-- 4. macOS System Settings lockdown -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.systempreferences</string>
            <key>PayloadIdentifier</key>
            <string>com.proxyfilter.profile.lockdown.${id}</string>
            <key>PayloadUUID</key>
            <string>${lockdownPayloadUuid}</string>
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

        <!-- 5. Removal password -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.profileRemovalPassword</string>
            <key>PayloadIdentifier</key>
            <string>com.proxyfilter.profile.removal.${id}</string>
            <key>PayloadUUID</key>
            <string>${removalPayloadUuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Removal Password</string>
            <key>RemovalPassword</key>
            <string>${escapeXml(removalPassword)}</string>
        </dict>

    </array>
</dict>
</plist>
`;

  return xml;
}

/** Convert a PEM cert to its DER form (Buffer). */
function pemToDer(pem) {
  const m = pem.match(/-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/);
  if (!m) throw new Error('Not a valid PEM cert');
  return Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
}
