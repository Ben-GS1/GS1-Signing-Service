// Signing backends. "keyvault": the private key never leaves Azure Key Vault (only a SHA-256 digest is sent). "mock": TEST ONLY, key from app settings.
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { b64u, sha256 } from './jws.js';

const publicOf = jwk => ({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y });

export function createMockSigner(keyCfg) {
  const priv = createPrivateKey({ key: keyCfg.jwk, format: 'jwk' });
  return {
    backend: 'mock',
    async publicJwk() { return publicOf(keyCfg.jwk); },
    async sign(input) { return nodeSign('sha256', Buffer.from(input), { key: priv, dsaEncoding: 'ieee-p1363' }); },   // raw r||s as JWS requires
  };
}

export function createKeyVaultSigner(keyCfg, deps = {}) {
  let clientsPromise, pub;
  const clients = () => (clientsPromise ??= (async () => {
    if (deps.createClients) return deps.createClients(keyCfg);
    const [{ DefaultAzureCredential }, { CryptographyClient, KeyClient }] = await Promise.all([import('@azure/identity'), import('@azure/keyvault-keys')]);
    const credential = new DefaultAzureCredential();      // managed identity in Azure, service principal env vars or az login locally
    const u = new URL(keyCfg.keyVaultKeyId), [, , name, version] = u.pathname.split('/');
    return { crypto: new CryptographyClient(keyCfg.keyVaultKeyId, credential), keys: new KeyClient(u.origin, credential), name, version };
  })());
  return {
    backend: 'keyvault',
    async publicJwk() {
      if (pub) return pub;
      const c = await clients(), k = await c.keys.getKey(c.name, c.version ? { version: c.version } : {});
      if (!k.key || k.key.crv !== 'P-256' || !String(k.key.kty).startsWith('EC')) throw new Error('Key Vault key must be an EC P-256 key');
      return (pub = { kty: 'EC', crv: 'P-256', x: b64u(k.key.x), y: b64u(k.key.y) });
    },
    async sign(input) {
      const c = await clients(), r = await c.crypto.sign('ES256', sha256(input));
      return Buffer.from(r.result);                          // Key Vault returns raw r||s for ES256
    },
  };
}

export function verifyEs256(publicJwk, input, signature) {
  return nodeVerify('sha256', Buffer.from(input), { key: createPublicKey({ key: publicOf(publicJwk), format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, signature);
}
