import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, sign as nodeSign, createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { compactVerify, importJWK, SignJWT, createLocalJWKSet, exportJWK } from 'jose';
import { loadConfig } from '../src/lib/config.js';
import { createService } from '../src/lib/service.js';
import { buildHeader, signingInput, sha256 } from '../src/lib/jws.js';

const MOCK = JSON.parse(readFileSync(new URL('./mockkey.json', import.meta.url)));
const API_KEY = 'gsk_test-key-for-unit-tests';
const hex = s => createHash('sha256').update(s).digest('hex');
const KEY = { id: 'test', backend: 'mock', issuer: MOCK.did, verificationMethod: MOCK.verificationMethod, jwk: MOCK.privateJwk };
const baseEnv = (over = {}) => ({
  SIGNING_KEYS: JSON.stringify([KEY]),
  API_KEYS: JSON.stringify([{ id: 'spa', sha256: hex(API_KEY), scopes: ['sign', 'keys:read'], keyIds: ['*'] }]),
  SIGNING_POLICY: JSON.stringify({ idPrefixes: ['https://vc.gs1.ch/', 'https://gs1-epcis-reg.org/'] }),
  ALLOWED_ORIGINS: 'null,http://localhost:4280', ...over,
});
const mk = (over, deps) => createService(loadConfig(baseEnv(over)), deps);
const credential = (o = {}) => ({
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://ref.gs1.org/gs1/vc/declaration-context'],
  id: 'https://vc.gs1.ch/credentials/gln/0810159550000.jwt', type: ['VerifiableCredential', 'KeyCredential'], issuer: { id: MOCK.did, name: 'x' },
  validFrom: new Date().toISOString(), validUntil: new Date(Date.now() + 365 * 864e5).toISOString(),
  credentialSubject: { id: 'https://id.gs1.org/417/0810159550000' }, ...o });
const call = (svc, method, path, { key = API_KEY, body, headers = {} } = {}) => svc.handle({
  method, path, headers: { ...(key ? { authorization: 'Bearer ' + key } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers },
  rawBody: body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body) });
const parse = r => (r.body ? JSON.parse(r.body) : null);

test('config fails closed', () => {
  assert.ok(loadConfig(baseEnv()).ok);
  assert.ok(!loadConfig(baseEnv({ SERVICE_ENV: 'production' })).ok, 'mock key refused in production');
  assert.ok(loadConfig(baseEnv({ SERVICE_ENV: 'production', ALLOW_MOCK_KEY: 'true' })).ok);
  assert.ok(!loadConfig(baseEnv({ API_KEYS: '' })).ok, 'no authentication');
  assert.ok(!loadConfig(baseEnv({ SIGNING_KEYS: '{oops' })).ok);
  const kv = { id: 'prod', backend: 'keyvault', issuer: 'did:webvh:abc:vc.gs1.ch', verificationMethod: 'did:webvh:abc:vc.gs1.ch#k1', keyVaultKeyId: 'https://kv-gs1.vault.azure.net/keys/gln-signing' };
  assert.ok(!loadConfig(baseEnv({ SERVICE_ENV: 'production', SIGNING_KEYS: JSON.stringify([kv]), SIGNING_POLICY: '' })).ok, 'production requires idPrefixes');
  assert.ok(loadConfig(baseEnv({ SERVICE_ENV: 'production', SIGNING_KEYS: JSON.stringify([kv]) })).ok);
});

test('health is public and reports misconfiguration', async () => {
  let r = await call(mk(), 'GET', '/v1/health', { key: null }); assert.equal(r.status, 200); assert.equal(parse(r).status, 'ok');
  r = await call(createService(loadConfig({})), 'GET', '/v1/health', { key: null }); assert.equal(r.status, 503);
  r = await call(createService(loadConfig({})), 'GET', '/v1/keys'); assert.equal(r.status, 503);
});

test('authentication', async () => {
  const s = mk();
  let r = await call(s, 'GET', '/v1/keys', { key: null }); assert.equal(r.status, 401); assert.match(r.headers['WWW-Authenticate'], /Bearer/);
  assert.equal(parse(r).status, 401); assert.match(r.headers['Content-Type'], /problem\+json/);
  assert.equal((await call(s, 'GET', '/v1/keys', { key: 'gsk_wrong' })).status, 401);
  assert.equal((await call(s, 'GET', '/v1/keys', { key: null, headers: { 'x-api-key': API_KEY } })).status, 200, 'X-Api-Key accepted');
  const expired = mk({ API_KEYS: JSON.stringify([{ id: 'old', sha256: hex(API_KEY), expires: '2020-01-01' }]) });
  assert.equal((await call(expired, 'GET', '/v1/keys')).status, 401);
  const disabled = mk({ API_KEYS: JSON.stringify([{ id: 'd', sha256: hex(API_KEY), disabled: true }]) });
  assert.equal((await call(disabled, 'GET', '/v1/keys')).status, 401);
  const ro = mk({ API_KEYS: JSON.stringify([{ id: 'ro', sha256: hex(API_KEY), scopes: ['keys:read'] }]) });
  assert.equal((await call(ro, 'POST', '/v1/sign/vc-jwt', { body: { credential: credential() } })).status, 403, 'scope sign required');
  const other = mk({ API_KEYS: JSON.stringify([{ id: 'o', sha256: hex(API_KEY), keyIds: ['another'] }]) });
  assert.equal((await call(other, 'POST', '/v1/sign/vc-jwt', { body: { credential: credential() } })).status, 403, 'key restriction');
});

test('keys endpoint exposes public key material only', async () => {
  const r = await call(mk(), 'GET', '/v1/keys'), b = parse(r);
  assert.equal(b.keys[0].keyId, 'test'); assert.equal(b.keys[0].backend, 'mock'); assert.equal(b.keys[0].didVerificationMethod.id, MOCK.verificationMethod);
  assert.ok(!r.body.includes(MOCK.privateJwk.d), 'private key must never be returned');
});

test('signs a credential; signature verifies with the published public key', async () => {
  const s = mk(), cred = credential(), r = await call(s, 'POST', '/v1/sign/vc-jwt', { body: { credential: cred } }), b = parse(r);
  assert.equal(r.status, 200, r.body); assert.equal(r.headers['X-Signing-Backend'], 'mock'); assert.equal(r.headers['Cache-Control'], 'no-store');
  const pub = parse(await call(s, 'GET', '/v1/keys')).keys[0].publicKeyJwk;
  const { payload, protectedHeader } = await compactVerify(b.jwt, await importJWK(pub, 'ES256'));
  assert.deepEqual(JSON.parse(new TextDecoder().decode(payload)), cred);
  assert.deepEqual(protectedHeader, { alg: 'ES256', kid: MOCK.verificationMethod, typ: 'vc+jwt', cty: 'vc' });
  assert.equal(b.kid, MOCK.verificationMethod);
});

test('signing policy rejects what must not be signed', async () => {
  const s = mk(), bad = {
    'wrong issuer': { issuer: 'did:web:evil.example' }, 'type not allowed': { type: ['VerifiableCredential', 'SomethingElse'] },
    'id outside prefix': { id: 'https://evil.example/x.jwt' }, 'proof present': { proof: { type: 'x' } },
    'no validUntil': { validUntil: undefined }, 'validity too long': { validUntil: new Date(Date.now() + 4000 * 864e5).toISOString() },
    'validUntil before validFrom': { validUntil: '2000-01-01T00:00:00Z' }, 'validFrom in future': { validFrom: new Date(Date.now() + 864e5).toISOString() },
    'wrong context': { '@context': ['https://www.w3.org/2018/credentials/v1'] },
  };
  for (const [name, o] of Object.entries(bad)) {
    const r = await call(s, 'POST', '/v1/sign/vc-jwt', { body: { credential: credential(o) } });
    assert.equal(r.status, 422, name + ': ' + r.body); assert.ok(parse(r).problems.length);
  }
  const status = credential({ type: ['VerifiableCredential', 'BitstringStatusListCredential'], validUntil: undefined, id: 'https://gs1-epcis-reg.org/credentials/status/revocation.jwt' });
  assert.equal((await call(s, 'POST', '/v1/sign/vc-jwt', { body: { credential: status } })).status, 200, 'status list needs no validUntil');
});

test('request validation', async () => {
  const s = mk();
  assert.equal((await call(s, 'POST', '/v1/sign/vc-jwt', { body: '{nope' })).status, 400);
  assert.equal((await call(s, 'POST', '/v1/sign/vc-jwt', { body: { credential: 5 } })).status, 400);
  assert.equal((await call(s, 'POST', '/v1/sign/vc-jwt', { body: { keyId: 'nope', credential: credential() } })).status, 404);
  assert.equal((await s.handle({ method: 'POST', path: '/v1/sign/vc-jwt', headers: { authorization: 'Bearer ' + API_KEY, 'content-type': 'text/plain' }, rawBody: '{}' })).status, 415);
  const big = await call(s, 'POST', '/v1/sign/vc-jwt', { body: { credential: credential({ blob: 'x'.repeat(200000) }) } }); assert.equal(big.status, 413);
  assert.equal((await call(s, 'GET', '/v1/unknown')).status, 405); assert.equal((await call(s, 'GET', '/nope')).status, 404);
});

test('rate limiting per principal', async () => {
  let t = 0; const s = mk({ RATE_LIMIT_PER_MINUTE: '3' }, { now: () => t });
  for (let i = 0; i < 3; i++) assert.equal((await call(s, 'GET', '/v1/keys')).status, 200);
  const r = await call(s, 'GET', '/v1/keys'); assert.equal(r.status, 429); assert.ok(Number(r.headers['Retry-After']) >= 1);
  t = 61000; assert.equal((await call(s, 'GET', '/v1/keys')).status, 200);
});

test('CORS allow-list', async () => {
  const s = mk();
  let r = await s.handle({ method: 'OPTIONS', path: '/v1/sign/vc-jwt', headers: { origin: 'null' }, rawBody: '' });
  assert.equal(r.status, 204); assert.equal(r.headers['Access-Control-Allow-Origin'], 'null');
  r = await s.handle({ method: 'OPTIONS', path: '/v1/sign/vc-jwt', headers: { origin: 'https://evil.example' }, rawBody: '' });
  assert.equal(r.status, 204); assert.equal(r.headers['Access-Control-Allow-Origin'], undefined);
});

test('Microsoft Entra ID bearer tokens', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }, keySet = createLocalJWKSet({ keys: [jwk] });
  const env = { ENTRA_TENANT_ID: 'tenant-1', ENTRA_AUDIENCE: 'api://gs1-signing', ENTRA_REQUIRED_ROLE: 'Signer' };
  const s = mk(env, { entraKeySet: keySet });
  const token = (claims, aud = 'api://gs1-signing') => new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer('https://login.microsoftonline.com/tenant-1/v2.0').setAudience(aud).setExpirationTime('5m').sign(privateKey);
  assert.equal((await call(s, 'GET', '/v1/keys', { key: await token({ oid: 'u1', roles: ['Signer'] }) })).status, 200);
  assert.equal((await call(s, 'GET', '/v1/keys', { key: await token({ oid: 'u1', roles: [] }) })).status, 403);
  assert.equal((await call(s, 'GET', '/v1/keys', { key: await token({ oid: 'u1', roles: ['Signer'] }, 'api://other') })).status, 401);
  assert.equal((await call(s, 'GET', '/v1/keys', { key: API_KEY })).status, 200, 'API keys still work next to Entra');
});

test('Key Vault backend: only the SHA-256 digest is sent, raw r||s comes back', async () => {
  const kv = { id: 'prod', backend: 'keyvault', issuer: MOCK.did, verificationMethod: MOCK.verificationMethod, keyVaultKeyId: 'https://kv-gs1.vault.azure.net/keys/gln-signing' };
  const cred = credential(), expectedInput = signingInput(buildHeader(kv), cred), priv = createPrivateKey({ key: MOCK.privateJwk, format: 'jwk' });
  let seen;
  const createClients = () => ({
    name: 'gln-signing', version: undefined,
    keys: { getKey: async () => ({ key: { kty: 'EC', crv: 'P-256', x: Buffer.from(MOCK.privateJwk.x, 'base64url'), y: Buffer.from(MOCK.privateJwk.y, 'base64url') } }) },
    crypto: { sign: async (alg, digest) => { seen = { alg, digest: Buffer.from(digest) }; return { result: nodeSign('sha256', Buffer.from(expectedInput), { key: priv, dsaEncoding: 'ieee-p1363' }) }; } },
  });
  const s = mk({ SIGNING_KEYS: JSON.stringify([kv]) }, { createClients });
  const r = await call(s, 'POST', '/v1/sign/vc-jwt', { body: { credential: cred } });
  assert.equal(r.status, 200, r.body); assert.equal(r.headers['X-Signing-Backend'], 'keyvault'); assert.equal(seen.alg, 'ES256');
  assert.ok(seen.digest.equals(sha256(expectedInput)) && seen.digest.length === 32, 'digest, not the document, is sent to Key Vault');
  await compactVerify(parse(r).jwt, await importJWK({ kty: 'EC', crv: 'P-256', x: MOCK.privateJwk.x, y: MOCK.privateJwk.y }, 'ES256'));
  const failing = mk({ SIGNING_KEYS: JSON.stringify([kv]) }, { createClients: () => ({ ...createClients(), crypto: { sign: async () => { throw new Error('boom: secret detail'); } } }) });
  const f = await call(failing, 'POST', '/v1/sign/vc-jwt', { body: { credential: cred } });
  assert.equal(f.status, 502); assert.ok(!f.body.includes('secret detail'), 'backend errors are not leaked');
});

test('wrong key behind a key id is detected (signature self-check)', async () => {
  const other = generateKeyPairSync('ec', { namedCurve: 'P-256' }), jwk = other.privateKey.export({ format: 'jwk' });
  const s = mk({}, { signerFactory: () => ({ backend: 'mock', publicJwk: async () => ({ kty: 'EC', crv: 'P-256', x: MOCK.privateJwk.x, y: MOCK.privateJwk.y }),
    sign: async input => nodeSign('sha256', Buffer.from(input), { key: other.privateKey, dsaEncoding: 'ieee-p1363' }) }) });
  assert.equal((await call(s, 'POST', '/v1/sign/vc-jwt', { body: { credential: credential() } })).status, 500);
});

test('every request is logged without credential contents', async () => {
  const lines = []; await call(mk(), 'POST', '/v1/sign/vc-jwt', { body: { credential: credential() } }).then(() => 0);
  const s = mk(); await s.handle({ method: 'POST', path: '/v1/sign/vc-jwt', headers: { authorization: 'Bearer ' + API_KEY, 'content-type': 'application/json' }, rawBody: JSON.stringify({ credential: credential() }) }, l => lines.push(JSON.parse(l)));
  const ev = lines[0]; assert.equal(ev.principal, 'key:spa'); assert.equal(ev.keyId, 'test'); assert.match(ev.payloadSha256, /^[0-9a-f]{64}$/); assert.ok(!JSON.stringify(ev).includes('credentialSubject'));
});
