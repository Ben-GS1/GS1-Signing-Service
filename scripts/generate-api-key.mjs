// Usage: node scripts/generate-api-key.mjs <client-id> [scopes comma separated] [keyIds comma separated]
import { randomBytes, createHash } from 'node:crypto';
const [id = 'issuer-spa', scopes = 'sign,keys:read', keyIds = '*'] = process.argv.slice(2);
const key = 'gsk_' + randomBytes(32).toString('base64url');
const entry = { id, sha256: createHash('sha256').update(key).digest('hex'), scopes: scopes.split(','), keyIds: keyIds.split(','), rateLimitPerMinute: 60 };
console.log('API key (give to the client, shown only once):\n  ' + key + '\n');
console.log('Add this object to the API_KEYS app setting (JSON array):\n  ' + JSON.stringify(entry));
