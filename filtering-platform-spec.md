# Filtering Platform — Full Architecture & Build Spec

## Overview
A managed content filtering platform where each user gets a unique configuration profile installed on their Mac/iPhone that routes all browser DNS through a per-user NextDNS profile. Blocked sites redirect to a custom block page where users can request access. Admins approve or deny requests via a dashboard, which updates NextDNS in real time via API.

No background agent. No app running on the device. Enforcement is entirely through the browser policy profile.

---

## How It Works End to End

1. Admin creates a new user in the dashboard.
2. System creates a NextDNS profile for that user via NextDNS API, storing the profile ID.
3. System generates a `.mobileconfig` file with that user's unique NextDNS DoH URL baked in, plus a unique removal password stored in the database.
4. Admin installs the profile on the user's device (Mac or iPhone) using the installer tool.
5. Every browser on the device is now forced to route DNS through `https://dns.nextdns.io/{user-profile-id}`.
6. NextDNS applies that user's filtering policy to every DNS request.
7. When a site is blocked, NextDNS redirects to the custom block page URL (e.g. `https://blocked.yourplatform.com?domain={blocked-domain}&profile={user-profile-id}`).
8. User fills out a request form on the block page explaining why they need access.
9. Request is saved to your database and admin is notified.
10. Admin logs into dashboard, reviews request, approves or denies.
11. If approved, your backend calls the NextDNS API to add the domain to that user's allow list.
12. Site immediately loads for that user on next attempt.

---

## Component 1: Database Schema

### Users table
- id (uuid, primary key)
- name (string)
- email (string)
- nextdns_profile_id (string) — the NextDNS profile ID for this user
- removal_password (string) — the password required to remove their profile, stored securely
- created_at (timestamp)

### Access Requests table
- id (uuid, primary key)
- user_id (foreign key → users)
- domain (string) — the domain they are requesting access to
- reason (string) — why they need access
- status (enum: pending / approved / denied)
- requested_at (timestamp)
- reviewed_at (timestamp, nullable)
- reviewed_by (foreign key → admins, nullable)

### Admins table
- id (uuid, primary key)
- name (string)
- email (string)
- password_hash (string)
- created_at (timestamp)

---

## Component 2: NextDNS API Integration

### Base URL
https://api.nextdns.io

### Authentication
All requests include header:
X-Api-Key: {your-nextdns-api-key}

### Create a NextDNS profile for a new user
POST https://api.nextdns.io/profiles
Body: { "name": "User Name" }
Response: { "data": { "id": "abc123" } }
Store the returned id as nextdns_profile_id in your users table.

### Set the custom block page URL for a profile
PATCH https://api.nextdns.io/profiles/{profile_id}/settings
Body:
{
  "blockPage": {
    "enabled": true,
    "url": "https://blocked.yourplatform.com"
  }
}

### Set default filtering categories on profile creation
PATCH https://api.nextdns.io/profiles/{profile_id}/security
Body:
{
  "safeBrowsing": true,
  "adBlocking": false
}

PATCH https://api.nextdns.io/profiles/{profile_id}/parentalControl
Body:
{
  "categories": ["porn", "gambling", "dating"],
  "safeSearch": true,
  "youtubeRestrictedMode": true
}

### Add a domain to a user's allow list (called on admin approval)
POST https://api.nextdns.io/profiles/{profile_id}/allowlist
Body: { "id": "example.com", "active": true }

### Remove a domain from a user's allow list
DELETE https://api.nextdns.io/profiles/{profile_id}/allowlist/example.com

### Get query logs for a user
GET https://api.nextdns.io/profiles/{profile_id}/logs

---

## Component 3: Profile Generator

When a new user is created, generate a .mobileconfig file using the template below.
Replace all placeholder values before serving the file:
- {USER_NEXTDNS_PROFILE_ID} — the user's NextDNS profile ID
- {REMOVAL_PASSWORD} — a securely generated random string stored in your database
- {UUID_1} through {UUID_9} — freshly generated UUIDs (crypto.randomUUID() in Node, uuid.uuid4() in Python)

### .mobileconfig template

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>Network Configuration</string>
    <key>PayloadDescription</key>
    <string>Configures network and security settings for this device.</string>
    <key>PayloadIdentifier</key>
    <string>com.device.networkconfig.{USER_NEXTDNS_PROFILE_ID}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{UUID_1}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>

        <dict>
            <key>PayloadType</key>
            <string>com.apple.applicationaccess</string>
            <key>PayloadIdentifier</key>
            <string>com.device.networkconfig.restrictions.{USER_NEXTDNS_PROFILE_ID}</string>
            <key>PayloadUUID</key>
            <string>{UUID_2}</string>
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
            <string>com.device.networkconfig.sysprefs.{USER_NEXTDNS_PROFILE_ID}</string>
            <key>PayloadUUID</key>
            <string>{UUID_3}</string>
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
            <string>com.device.networkconfig.chrome.{USER_NEXTDNS_PROFILE_ID}</string>
            <key>PayloadUUID</key>
            <string>{UUID_4}</string>
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
                                <string>https://dns.nextdns.io/{USER_NEXTDNS_PROFILE_ID}</string>
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
            <string>com.device.networkconfig.edge.{USER_NEXTDNS_PROFILE_ID}</string>
            <key>PayloadUUID</key>
            <string>{UUID_5}</string>
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
                                <string>https://dns.nextdns.io/{USER_NEXTDNS_PROFILE_ID}</string>
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
            <string>com.device.networkconfig.brave.{USER_NEXTDNS_PROFILE_ID}</string>
            <key>PayloadUUID</key>
            <string>{UUID_6}</string>
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
                                <string>https://dns.nextdns.io/{USER_NEXTDNS_PROFILE_ID}</string>
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
            <string>com.device.networkconfig.safari.{USER_NEXTDNS_PROFILE_ID}</string>
            <key>PayloadUUID</key>
            <string>{UUID_7}</string>
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
            <string>com.device.networkconfig.opera.{USER_NEXTDNS_PROFILE_ID}</string>
            <key>PayloadUUID</key>
            <string>{UUID_8}</string>
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
                                <string>https://dns.nextdns.io/{USER_NEXTDNS_PROFILE_ID}</string>
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
            <string>com.device.networkconfig.removal.{USER_NEXTDNS_PROFILE_ID}</string>
            <key>PayloadUUID</key>
            <string>{UUID_9}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Profile Removal</string>
            <key>RemovalPassword</key>
            <string>{REMOVAL_PASSWORD}</string>
        </dict>

    </array>
</dict>
</plist>

---

## Component 4: Backend API

### Tech stack recommendation
- Node.js with Express, or Python with FastAPI
- PostgreSQL for the database
- Hosted on any VPS (Hetzner, DigitalOcean, Railway, Render)

### Endpoints needed

POST /api/users
- Creates a user record in the database
- Calls NextDNS API to create a profile for that user
- Calls NextDNS API to set default filtering categories
- Calls NextDNS API to set the custom block page URL
- Generates a random removal password and stores it hashed
- Returns the user record including nextdns_profile_id

GET /api/users/:id/profile
- Generates and returns the .mobileconfig file for that user
- Fills in the user's nextdns_profile_id and removal_password
- Generates fresh UUIDs for all payload entries
- Returns the file as application/x-apple-aspen-config so the browser/device prompts installation

POST /api/requests
- Called by the block page when a user submits an access request
- Body: { profile_id, domain, reason }
- Looks up the user by nextdns_profile_id
- Creates an access request record with status: pending
- Sends an email notification to all admins (use Resend or Postmark)

GET /api/requests
- Admin only, requires auth
- Returns all pending access requests

PATCH /api/requests/:id
- Admin only, requires auth
- Body: { status: "approved" | "denied" }
- If approved: calls NextDNS API to add domain to user's allow list
- Updates the request record with status, reviewed_at, reviewed_by

DELETE /api/users/:id
- Admin only
- Calls NextDNS API to delete the profile
- Removes user from database

POST /api/auth/login
- Body: { email, password }
- Returns a JWT token for admin dashboard access

---

## Component 5: Custom Block Page

A simple hosted web page at https://blocked.yourplatform.com

NextDNS will append query parameters when redirecting to it:
- The blocked domain is not automatically passed by NextDNS — you read it from the browser's referrer or have the user type it
- Your profile_id IS something you can encode into the NextDNS block page URL as a static parameter per profile

So when setting the block page URL for each user, include their profile ID:
https://blocked.yourplatform.com?profile={USER_NEXTDNS_PROFILE_ID}

The block page should:
1. Display a clean branded message explaining the site is blocked
2. Show the domain that was blocked (read from window.location or referrer)
3. Show a form: "Why do you need access to this site?" with a text field
4. On submit, POST to your backend /api/requests with the profile_id, domain, and reason
5. Show a confirmation: "Your request has been sent to your administrator"

This page is just a static HTML/CSS/JS page hosted anywhere (Vercel, Netlify, Cloudflare Pages — all free).

---

## Component 6: Admin Dashboard

A web app at https://admin.yourplatform.com

### Pages needed

Login page
- Email and password form
- Calls POST /api/auth/login
- Stores JWT in localStorage

Pending Requests page (main view)
- Lists all requests with status: pending
- Shows: user name, domain requested, reason given, time requested
- Approve button — calls PATCH /api/requests/:id with status: approved
- Deny button — calls PATCH /api/requests/:id with status: denied
- On approve/deny, row updates in place

Users page
- Lists all users
- Create new user button — form with name and email
- Each user row has: Download Profile button (fetches /api/users/:id/profile and triggers download), Delete User button

Request History page
- All approved and denied requests
- Filter by user, date range, status

### Tech stack recommendation
- Next.js or plain React hosted on Vercel (free tier)
- Tailwind CSS for styling
- Auth via JWT stored in localStorage, passed as Bearer token on all API calls

---

## Component 7: Profile Installation Flow

For Mac:
1. Admin goes to Users page in dashboard
2. Clicks Download Profile for a user
3. Backend generates and returns the .mobileconfig file
4. Admin opens the file on the target Mac — macOS prompts to install
5. User enters their Mac password to confirm installation
6. Profile is installed, all browsers immediately enforce the policy

For iPhone (using the libimobiledevice/iTunes method discussed earlier):
1. Same as above — admin downloads the .mobileconfig
2. Admin connects iPhone to Windows PC with iTunes installed
3. Admin runs your installer tool (libimobiledevice) to push the profile over USB
4. Profile installs silently, no ABM required

---

## Hosting Summary

| Component | Where to host | Cost |
|---|---|---|
| Backend API | Railway, Render, or DigitalOcean | $5-20/month |
| Admin dashboard | Vercel | Free |
| Block page | Vercel or Cloudflare Pages | Free |
| Database | Railway Postgres or Supabase | Free-$5/month |
| NextDNS | nextdns.io | $19.90/year flat or free up to 300k queries/month |

Total infrastructure cost: approximately $5-25/month depending on scale.

---

## Build Order Recommendation

1. Set up NextDNS account and get API key — test API calls manually with curl first
2. Build the backend API — start with just create user, generate profile, and download profile endpoints
3. Test end to end: create a user via API, download their profile, install it, confirm chrome://policy shows their NextDNS URL
4. Build the block page — simple HTML form that posts to your backend
5. Set the block page URL in NextDNS for a test profile, confirm it redirects correctly
6. Build the requests endpoint and test the full allow request flow manually
7. Build the admin dashboard — start with just the pending requests page
8. Add the users management page
9. Add email notifications for new requests
10. Polish, add auth, deploy

---

## Key Technical Notes

- Every UUID in the profile must be unique and freshly generated per user — never reuse UUIDs across profiles
- The removal password should be generated as a cryptographically random string (32+ characters), stored hashed in your database, and the plaintext version only ever appears inside the generated .mobileconfig file
- The profile PayloadIdentifier should be unique per user — using the nextdns_profile_id as a suffix as shown in the template achieves this
- Safari does not support DoH policy via ManagedClient.preferences — it uses the system DNS. On macOS Tahoe the system DNS profile is currently broken for non-MDM devices. Safari filtering therefore relies on NextDNS being enforced by other browsers and on the user not exclusively using Safari. If Safari coverage is critical, the only current solution is ABM enrollment.
- Firefox does not support ManagedClient.preferences for DoH — it requires a policies.json file inside the app bundle. This cannot be enforced via a profile alone. Firefox filtering on Mac currently requires either accepting this gap or blocking Firefox installation entirely via the restrictions payload.
- On iPhone the profile installs cleanly and covers all browsers including Safari since iOS respects the DNS profile payload without the Tahoe bug.
```
