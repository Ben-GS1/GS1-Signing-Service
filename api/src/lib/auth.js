import { createHash, timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { HttpError } from './http.js';

const unauthorized = (detail = 'Valid credentials are required.') =>
  new HttpError(401, 'Unauthorized', detail, { headers: { 'WWW-Authenticate': 'Bearer realm="gs1-signing-service"' } });

function extractToken(headers) {
  const a = headers['authorization'];
  if (a) { const m = /^Bearer\s+(\S+)$/i.exec(a); if (m) return m[1]; }
  return headers['x-api-key'] || null;
}
const sha256 = s => createHash('sha256').update(s).digest();

// deps.entraKeySet lets tests inject a local key set; production uses Microsoft's JWKS endpoint.
export async function authenticate(headers, config, deps = {}) {
  const token = extractToken(headers);
  if (!token) throw unauthorized();

  if (config.entra && token.split('.').length === 3) {
    const { tenantId, audience, requiredRole } = config.entra;
    const keySet = deps.entraKeySet || (deps._jwks ??= createRemoteJWKSet(new URL(`https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`)));
    let payload;
    try {
      ({ payload } = await jwtVerify(token, keySet, { issuer: [`https://login.microsoftonline.com/${tenantId}/v2.0`, `https://sts.windows.net/${tenantId}/`], audience, algorithms: ['RS256'] }));
    } catch { throw unauthorized('Token validation failed.'); }
    const roles = Array.isArray(payload.roles) ? payload.roles : [];
    if (!roles.includes(requiredRole)) throw new HttpError(403, 'Forbidden', `Token lacks the required app role "${requiredRole}".`);
    return { id: `entra:${payload.oid || payload.sub}`, scopes: ['sign', 'keys:read'], keyIds: ['*'] };
  }

  const presented = sha256(token);
  let match = null;
  for (const entry of config.apiKeys) {                 // compare against every entry: no early exit on first mismatch
    const same = timingSafeEqual(presented, Buffer.from(entry.sha256, 'hex'));
    if (same && !match) match = entry;
  }
  if (!match || match.disabled) throw unauthorized();
  if (match.expires && new Date(match.expires).getTime() < Date.now()) throw unauthorized('API key expired.');
  return { id: `key:${match.id}`, scopes: match.scopes || ['sign', 'keys:read'], keyIds: match.keyIds || ['*'], rateLimitPerMinute: match.rateLimitPerMinute };
}
export const requireScope = (principal, scope) => {
  if (!principal.scopes.includes(scope)) throw new HttpError(403, 'Forbidden', `Missing scope "${scope}".`);
};
export const canUseKey = (principal, keyId) => principal.keyIds.includes('*') || principal.keyIds.includes(keyId);
