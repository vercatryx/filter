import { randomUUID, randomBytes } from 'node:crypto';

export function generateRemovalPassword() {
  return randomBytes(24).toString('base64url');
}

function escapeXml(s) {
  return String(s).replace(/[<>&'"]/g, (c) => ({
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    "'": '&apos;',
    '"': '&quot;',
  }[c]));
}

export function generateMobileConfig({ profileId, removalPassword }) {
  const id = escapeXml(profileId);
  const pw = escapeXml(removalPassword);
  const u = Array.from({ length: 9 }, () => randomUUID().toUpperCase());
  const dohUrl = `https://dns.nextdns.io/${id}`;

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>Network Configuration</string>
    <key>PayloadDescription</key>
    <string>Configures network and security settings for this device.</string>
    <key>PayloadIdentifier</key>
    <string>com.device.networkconfig.${id}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${u[0]}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>

        <dict>
            <key>PayloadType</key>
            <string>com.apple.applicationaccess</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkconfig.restrictions.${id}</string>
            <key>PayloadUUID</key>
            <string>${u[1]}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Restrictions</string>
            <key>allowAppInstallation</key>
            <false/>
            <key>ratingRegion</key>
            <string>us</string>
            <key>safariForceFraudWarning</key>
            <true/>
        </dict>

        <dict>
            <key>PayloadType</key>
            <string>com.apple.systempreferences</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkconfig.sysprefs.${id}</string>
            <key>PayloadUUID</key>
            <string>${u[2]}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>System Preferences</string>
            <key>DisabledPreferencePanes</key>
            <array>
                <string>com.apple.preference.network</string>
                <string>com.apple.preferences.configurationprofiles</string>
                <string>com.apple.preference.security</string>
            </array>
        </dict>

        <dict>
            <key>PayloadType</key>
            <string>com.apple.ManagedClient.preferences</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkconfig.chrome.${id}</string>
            <key>PayloadUUID</key>
            <string>${u[3]}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Chrome Settings</string>
            <key>PayloadContent</key>
            <dict>
                <key>com.google.Chrome</key>
                <dict>
                    <key>Forced</key>
                    <array>
                        <dict>
                            <key>mcx_preference_settings</key>
                            <dict>
                                <key>DnsOverHttpsMode</key>
                                <string>secure</string>
                                <key>DnsOverHttpsTemplates</key>
                                <string>${dohUrl}</string>
                                <key>BuiltInDnsClientEnabled</key>
                                <false/>
                                <key>BrowserSignin</key>
                                <integer>0</integer>
                                <key>ForceGoogleSafeSearch</key>
                                <true/>
                                <key>ForceYouTubeRestrict</key>
                                <integer>2</integer>
                            </dict>
                        </dict>
                    </array>
                </dict>
            </dict>
        </dict>

        <dict>
            <key>PayloadType</key>
            <string>com.apple.ManagedClient.preferences</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkconfig.edge.${id}</string>
            <key>PayloadUUID</key>
            <string>${u[4]}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Edge Settings</string>
            <key>PayloadContent</key>
            <dict>
                <key>com.microsoft.Edge</key>
                <dict>
                    <key>Forced</key>
                    <array>
                        <dict>
                            <key>mcx_preference_settings</key>
                            <dict>
                                <key>DnsOverHttpsMode</key>
                                <string>secure</string>
                                <key>DnsOverHttpsTemplates</key>
                                <string>${dohUrl}</string>
                                <key>BuiltInDnsClientEnabled</key>
                                <false/>
                                <key>ForceGoogleSafeSearch</key>
                                <true/>
                                <key>ForceYouTubeRestrict</key>
                                <integer>2</integer>
                            </dict>
                        </dict>
                    </array>
                </dict>
            </dict>
        </dict>

        <dict>
            <key>PayloadType</key>
            <string>com.apple.ManagedClient.preferences</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkconfig.brave.${id}</string>
            <key>PayloadUUID</key>
            <string>${u[5]}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Brave Settings</string>
            <key>PayloadContent</key>
            <dict>
                <key>com.brave.Browser</key>
                <dict>
                    <key>Forced</key>
                    <array>
                        <dict>
                            <key>mcx_preference_settings</key>
                            <dict>
                                <key>DnsOverHttpsMode</key>
                                <string>secure</string>
                                <key>DnsOverHttpsTemplates</key>
                                <string>${dohUrl}</string>
                                <key>BuiltInDnsClientEnabled</key>
                                <false/>
                                <key>TorDisabled</key>
                                <true/>
                                <key>BraveVPNDisabled</key>
                                <true/>
                            </dict>
                        </dict>
                    </array>
                </dict>
            </dict>
        </dict>

        <dict>
            <key>PayloadType</key>
            <string>com.apple.ManagedClient.preferences</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkconfig.safari.${id}</string>
            <key>PayloadUUID</key>
            <string>${u[6]}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Safari Settings</string>
            <key>PayloadContent</key>
            <dict>
                <key>com.apple.Safari</key>
                <dict>
                    <key>Forced</key>
                    <array>
                        <dict>
                            <key>mcx_preference_settings</key>
                            <dict>
                                <key>WarnAboutFraudulentWebsites</key>
                                <true/>
                                <key>ExtensionsEnabled</key>
                                <false/>
                                <key>WebKitJavaScriptCanOpenWindowsAutomatically</key>
                                <false/>
                            </dict>
                        </dict>
                    </array>
                </dict>
            </dict>
        </dict>

        <dict>
            <key>PayloadType</key>
            <string>com.apple.ManagedClient.preferences</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkconfig.opera.${id}</string>
            <key>PayloadUUID</key>
            <string>${u[7]}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Opera Settings</string>
            <key>PayloadContent</key>
            <dict>
                <key>com.operasoftware.Opera</key>
                <dict>
                    <key>Forced</key>
                    <array>
                        <dict>
                            <key>mcx_preference_settings</key>
                            <dict>
                                <key>DnsOverHttpsMode</key>
                                <string>secure</string>
                                <key>DnsOverHttpsTemplates</key>
                                <string>${dohUrl}</string>
                                <key>BuiltInDnsClientEnabled</key>
                                <false/>
                            </dict>
                        </dict>
                    </array>
                </dict>
            </dict>
        </dict>

        <dict>
            <key>PayloadType</key>
            <string>com.apple.profileRemovalPassword</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkconfig.removal.${id}</string>
            <key>PayloadUUID</key>
            <string>${u[8]}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Profile Removal</string>
            <key>RemovalPassword</key>
            <string>${pw}</string>
        </dict>

    </array>
</dict>
</plist>
`;
}
