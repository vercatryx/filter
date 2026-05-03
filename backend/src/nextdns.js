const BASE = 'https://api.nextdns.io';

function headers() {
  const key = process.env.NEXTDNS_API_KEY;
  if (!key) throw new Error('NEXTDNS_API_KEY is not set');
  return { 'X-Api-Key': key, 'Content-Type': 'application/json' };
}

async function call(method, path, body) {
  const res = await fetch(BASE + path, {
    method,
    headers: headers(),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`NextDNS ${method} ${path} failed: ${res.status} ${text}`);
  }
  if (res.status === 204) return null;
  const ctype = res.headers.get('content-type') || '';
  return ctype.includes('application/json') ? res.json() : res.text();
}

export async function createProfile(name) {
  const data = await call('POST', '/profiles', { name });
  return data?.data?.id;
}

export async function deleteProfile(profileId) {
  return call('DELETE', `/profiles/${profileId}`);
}

export async function listProfiles() {
  const data = await call('GET', '/profiles');
  return data?.data ?? [];
}

export async function getProfile(profileId) {
  const data = await call('GET', `/profiles/${profileId}`);
  return data?.data ?? null;
}

export async function enableBlockPage(profileId) {
  return call('PATCH', `/profiles/${profileId}/settings/blockPage`, { enabled: true });
}

export async function patchSecurity(profileId, body) {
  return call('PATCH', `/profiles/${profileId}/security`, body);
}

export async function patchParentalControl(profileId, body) {
  return call('PATCH', `/profiles/${profileId}/parentalControl`, body);
}

export async function addCategory(profileId, categoryId) {
  return call('POST', `/profiles/${profileId}/parentalControl/categories`, {
    id: categoryId,
    active: true,
  });
}

export async function removeCategory(profileId, categoryId) {
  return call('DELETE', `/profiles/${profileId}/parentalControl/categories/${encodeURIComponent(categoryId)}`);
}

export async function addService(profileId, serviceId) {
  return call('POST', `/profiles/${profileId}/parentalControl/services`, {
    id: serviceId,
    active: true,
  });
}

export async function removeService(profileId, serviceId) {
  return call('DELETE', `/profiles/${profileId}/parentalControl/services/${encodeURIComponent(serviceId)}`);
}

export async function addBlocklist(profileId, blocklistId) {
  return call('POST', `/profiles/${profileId}/privacy/blocklists`, { id: blocklistId });
}

export async function removeBlocklist(profileId, blocklistId) {
  return call('DELETE', `/profiles/${profileId}/privacy/blocklists/${encodeURIComponent(blocklistId)}`);
}

export async function getAllowlist(profileId) {
  return call('GET', `/profiles/${profileId}/allowlist`);
}

export async function addAllowedDomain(profileId, domain) {
  return call('POST', `/profiles/${profileId}/allowlist`, { id: domain, active: true });
}

export async function removeAllowedDomain(profileId, domain) {
  return call('DELETE', `/profiles/${profileId}/allowlist/${encodeURIComponent(domain)}`);
}

export async function getDenylist(profileId) {
  return call('GET', `/profiles/${profileId}/denylist`);
}

export async function addDeniedDomain(profileId, domain) {
  return call('POST', `/profiles/${profileId}/denylist`, { id: domain, active: true });
}

export async function removeDeniedDomain(profileId, domain) {
  return call('DELETE', `/profiles/${profileId}/denylist/${encodeURIComponent(domain)}`);
}
