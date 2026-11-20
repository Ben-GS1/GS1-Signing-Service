import { createHash } from 'node:crypto';
export const b64u = buf => Buffer.from(buf).toString('base64url');
export const sha256 = data => createHash('sha256').update(data).digest();
export function buildHeader(keyCfg) {
  return { alg: 'ES256', kid: keyCfg.verificationMethod, typ: 'vc+jwt', cty: 'vc' };   // VC-JOSE-COSE
}
export const signingInput = (header, payload) => `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
// RFC 7638 JWK thumbprint (EC keys) - used as "kid" inside the JWK of DID documents
export const thumbprint = jwk => b64u(sha256(`{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`));
