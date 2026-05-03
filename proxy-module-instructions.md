# New Module: Proxy-Based Filtering (v2 Architecture)

## Context
The existing project uses a browser-policy + NextDNS approach for content filtering. This is being supplemented with a new, more robust approach based on a transparent SSL-inspecting proxy. Do NOT modify or delete any existing code. Create everything below as a new isolated module/folder alongside the existing code.

---

## Why This New Approach
The browser-policy approach has gaps:
- Users can bypass DNS filtering by typing raw IP addresses
- New or uncovered browsers are not filtered
- Enforcement lives at the browser level, not the OS level

The new approach fixes all of this by:
- Forcing ALL traffic (every app, every browser, curl, wget, everything) through a proxy at the OS level via a configuration profile
- Installing a trusted root CA certificate on the device so the proxy can inspect HTTPS traffic
- Filtering at the proxy level based on destination, not DNS lookup

---

## What To Build

Create a new top-level folder called `/proxy-filter` in the project root. Everything below lives inside this folder. Do not touch anything outside it.

---

## Folder Structure To Create

```
/proxy-filter
  /server
    docker-compose.yml
    squid.conf
    /ssl
      generate-ca.sh
      (ca.crt and ca.key will be generated here, gitignored)
    /blocklists
      adult.txt
      (placeholder — instructions below for populating)
    block-page.html
  /profile-generator
    generate-profile.js
    profile-template.xml
  /admin
    (scaffold only — see spec below)
  .env.example
  README.md
```

---

## Component 1: Server (Squid Proxy with SSL Inspection)

### docker-compose.yml
Create a Docker Compose file that:
- Runs Squid proxy in a container
- Mounts squid.conf, the SSL certs folder, and the blocklists folder as volumes
- Exposes port 3128
- Restarts automatically on failure
- Uses the `ubuntu/squid` Docker image

### squid.conf
Create a Squid configuration file that does the following. Add a clear comment above each section explaining what it does.

**SSL Bump (HTTPS inspection):**
- Enable ssl-bump with the CA cert at /etc/squid/ssl/ca.crt and key at /etc/squid/ssl/ca.key
- Use bump mode: peek at step1, bump at step2 and step3
- Create an ssl_db certificate cache at /var/lib/squid/ssl_db

**Proxy authentication:**
- Use basic auth with a flat file at /etc/squid/passwd
- Require authentication on all requests
- Set auth realm to "Proxy"

**ACL rules in this order:**
1. Allow CONNECT for authenticated users (needed for HTTPS tunneling)
2. Define an ACL called `blocked_domains` that reads from /etc/squid/blocklists/adult.txt
3. Deny requests matching `blocked_domains` and redirect to the block page URL (use a placeholder URL: http://blocked.yourplatform.com)
4. Allow all other authenticated requests
5. Deny everything else

**Logging:**
- Log all requests to /var/log/squid/access.log in combined format including the authenticated username

**Performance:**
- Set cache_mem to 256 MB
- Set maximum_object_size to 50 MB

### ssl/generate-ca.sh
A shell script that generates a self-signed CA certificate and key using OpenSSL. Specifically:
- Generate a 4096-bit RSA key saved as ca.key
- Generate a self-signed certificate valid for 3650 days (10 years) saved as ca.crt
- Set the CN to "Proxy Filter CA"
- Set the certificate as a CA (basicConstraints = critical, CA:TRUE)
- Print a success message when done
- Add a warning that ca.key must be kept secret and never committed to git

### blocklists/adult.txt
Create this as an empty placeholder file with a comment at the top explaining:
- This file contains one domain per line
- Recommended free blocklist source: https://urlhaus.abuse.ch or the UT1 categorized blocklist at https://dsi.ut-capitole.fr/blacklists/
- Format: one domain per line, e.g. example.com
- The file is read by Squid on startup — restart container after updating

### block-page.html
A clean, simple HTML page that:
- Displays a message that the requested site has been blocked
- Shows a form with a single textarea asking "Why do you need access to this site?"
- Has a submit button labeled "Request Access"
- On submit, POSTs to /api/proxy-filter/requests (the admin API endpoint defined below)
- Reads the blocked domain from the URL query parameter `?domain=` and displays it
- Reads the user identifier from the query parameter `?user=` and includes it in the POST body
- Has clean, minimal styling — no external dependencies, pure HTML/CSS

---

## Component 2: Profile Generator

### profile-template.xml
A .mobileconfig XML template for macOS and iOS that includes exactly these payloads in order. Use placeholder strings in curly braces for all dynamic values:

**Payload 1 — Root Certificate**
- PayloadType: com.apple.security.root
- The certificate data goes in a <data> tag as base64
- Placeholder: {BASE64_CA_CERT}
- PayloadDisplayName: "Network Security Certificate"
- This installs the proxy CA as a trusted root so HTTPS inspection works without browser warnings

**Payload 2 — Global HTTP Proxy**
- PayloadType: com.apple.proxy.http.global  
- ProxyServer: {PROXY_HOST}
- ProxyServerPort: {PROXY_PORT} (integer)
- ProxyUsername: {PROXY_USERNAME}
- ProxyPassword: {PROXY_PASSWORD}
- ProxyCaptiveLoginAllowed: true
- PayloadDisplayName: "Network Proxy"
- This forces ALL system traffic through the proxy at the OS level

**Payload 3 — Chrome browser policy**
- PayloadType: com.apple.ManagedClient.preferences
- Bundle ID: com.google.Chrome
- Enforces: DnsOverHttpsMode = secure, DnsOverHttpsTemplates = {DOH_URL}, BuiltInDnsClientEnabled = false, ForceGoogleSafeSearch = true, ForceYouTubeRestrict = 2, BrowserSignin = 0

**Payload 4 — Edge browser policy**
- Same structure as Chrome
- Bundle ID: com.microsoft.Edge
- Same keys as Chrome

**Payload 5 — Brave browser policy**
- Same structure as Chrome
- Bundle ID: com.brave.Browser
- Same keys as Chrome plus: TorDisabled = true, BraveVPNDisabled = true

**Payload 6 — Safari browser policy**
- PayloadType: com.apple.ManagedClient.preferences
- Bundle ID: com.apple.Safari
- Enforces: WarnAboutFraudulentWebsites = true, ExtensionsEnabled = false

**Payload 7 — Opera browser policy**
- Same structure as Chrome
- Bundle ID: com.operasoftware.Opera
- Same keys as Chrome

**Payload 8 — System Preferences lockdown**
- PayloadType: com.apple.systempreferences
- DisabledPreferencePanes array containing:
  - com.apple.preference.network
  - com.apple.preferences.configurationprofiles
  - com.apple.preference.security

**Payload 9 — Removal password**
- PayloadType: com.apple.profileRemovalPassword
- RemovalPassword: {REMOVAL_PASSWORD}

**Root profile keys:**
- PayloadDisplayName: "Network Configuration"
- PayloadDescription: "Configures network and security settings for this device."
- PayloadIdentifier: com.device.networkconfig.{USER_ID}
- PayloadUUID: {PROFILE_UUID}
- PayloadVersion: 1
- PayloadType: Configuration

### generate-profile.js
A Node.js script that generates a complete .mobileconfig file for a given user. It should:

**Accept these inputs as either CLI arguments or environment variables:**
- USER_ID — unique identifier for this user (used in payload identifiers)
- PROXY_HOST — hostname or IP of the proxy server
- PROXY_PORT — port number (default 3128)
- PROXY_USERNAME — the user's proxy auth username
- PROXY_PASSWORD — the user's proxy auth password
- REMOVAL_PASSWORD — the profile removal password for this user
- CA_CERT_PATH — path to the ca.crt file generated by generate-ca.sh
- DOH_URL — the DoH URL for browser policies (can be left as Cloudflare family as fallback: https://family.cloudflare-dns.com/dns-query)

**Steps:**
1. Read the CA cert file from CA_CERT_PATH
2. Convert it to base64
3. Read profile-template.xml
4. Replace all {PLACEHOLDER} values with the provided inputs
5. Generate a fresh UUID for every payload (use crypto.randomUUID())
6. Write the output to ./output/{USER_ID}.mobileconfig
7. Create the ./output directory if it doesn't exist
8. Print a success message with the output path

Add a note in comments that the output directory should be gitignored since it contains per-user profiles with embedded passwords.

---

## Component 3: Admin API Endpoints

In whatever backend framework the existing project uses, add a new route file/module at the path `/api/proxy-filter/`. Do not modify any existing routes.

Create these endpoints:

**POST /api/proxy-filter/requests**
- Public endpoint (no auth required — called from the block page)
- Body: { user_id, domain, reason }
- Validates that user_id and domain are present
- Saves a new access request to the database with status: pending
- Returns 200 with { success: true, message: "Request submitted" }

**GET /api/proxy-filter/requests**
- Admin auth required
- Returns all access requests ordered by requested_at descending
- Supports query param ?status=pending|approved|denied for filtering

**PATCH /api/proxy-filter/requests/:id**
- Admin auth required
- Body: { status: "approved" | "denied" }
- Updates the request status
- If approved: adds the domain to the user's allowlist in the Squid passwd/allowlist config
  - Specifically: appends the domain to a per-user allowlist file at /etc/squid/allowlists/{user_id}.txt
  - The squid.conf should be updated to include these per-user allowlist files (add a note in squid.conf about this)
- Returns the updated request

**GET /api/proxy-filter/users/:user_id/profile**
- Admin auth required
- Calls generate-profile.js with that user's credentials from the database
- Returns the generated .mobileconfig file as a download
- Content-Type: application/x-apple-aspen-config
- Content-Disposition: attachment; filename="{user_id}-filter.mobileconfig"

---

## Component 4: Database Additions

Add these new tables to the existing database schema. Do not modify existing tables.

**proxy_users table:**
- id (uuid, primary key)
- user_id (string, unique) — short identifier used in proxy auth and profile generation
- display_name (string)
- proxy_username (string, unique) — used for Squid basic auth
- proxy_password_hash (string) — store hashed, generate plaintext only when generating profile
- removal_password_hash (string) — same
- created_at (timestamp)

**proxy_requests table:**
- id (uuid, primary key)
- user_id (string, foreign key → proxy_users.user_id)
- domain (string)
- reason (string)
- status (string, default: pending) — pending | approved | denied
- requested_at (timestamp, default: now)
- reviewed_at (timestamp, nullable)
- reviewed_by (string, nullable)

---

## Component 5: README.md

Create a README.md inside /proxy-filter that explains:

1. Overview of what this module does and why
2. Prerequisites: Docker, Docker Compose, Node.js, OpenSSL
3. Setup steps in order:
   a. cd into /proxy-filter/server/ssl and run generate-ca.sh to create the CA cert
   b. Copy .env.example to .env and fill in values
   c. Run docker-compose up -d to start the proxy
   d. Test the proxy works by configuring a browser to use it manually
   e. Run generate-profile.js with test values to generate a test profile
   f. Install the test profile on a Mac and verify traffic is being proxied
4. How to add users: create a proxy_users record, add their credentials to Squid's passwd file using htpasswd, generate their profile
5. How to update blocklists: replace adult.txt and restart the container
6. Known limitations and next steps

---

## .env.example

```
PROXY_HOST=your-server-ip-or-hostname
PROXY_PORT=3128
CA_CERT_PATH=./server/ssl/ca.crt
BLOCK_PAGE_URL=http://blocked.yourplatform.com
```

---

## Important Notes For The Agent

- Do not modify any existing files outside /proxy-filter
- Do not delete or replace any existing functionality
- The goal is a working testable module in isolation
- Add a comment at the top of every new file saying "Part of proxy-filter module — see /proxy-filter/README.md"
- All secrets (ca.key, .env, output/*.mobileconfig) must be added to .gitignore
- Use whatever package manager and style conventions the existing project already uses
- If the existing project has a Docker setup already, make sure the new docker-compose.yml does not conflict with existing port mappings — use port 3128 for Squid by default but make it configurable via .env
```
