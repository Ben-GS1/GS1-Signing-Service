// Transport-independent request router. The Azure Functions wrapper and the tests both call handle().
import { HttpError, baseHeaders, corsHeaders, json, newRequestId, problem } from './http.js';
import { authenticate, canUseKey, requireScope } from './auth.js';
import { checkCredential } from './policy.js';
import { RateLimiter } from './ratelimit.js';
import { createKeyVaultSigner, createMockSigner, verifyEs256 } from './signer.js';
import { b64u, buildHeader, sha256, signingInput, thumbprint } from './jws.js';

export function createService(config, deps = {}) {
  const limiter = new RateLimiter(config.rateLimitPerMinute, deps.now);
  const signers = new Map();
  const signerFor = k => {
    if (!signers.has(k.id)) signers.set(k.id, deps.signerFactory ? deps.signerFactory(k) : k.backend === 'mock' ? createMockSigner(k) : createKeyVaultSigner(k, deps));
    return signers.get(k.id);
  };
  const backendFail = e => new HttpError(502, 'Signing backend unavailable', 'The key store could not complete the operation.', { cause: e });

  async function listKeys(principal) {
    const out = [];
    for (const k of config.keys.filter(k => canUseKey(principal, k.id))) {
      const s = signerFor(k); let pub;
      try { pub = await s.publicJwk(); } catch (e) { throw backendFail(e); }
      const jwk = { ...pub, kid: thumbprint(pub), alg: 'ES256' };
      out.push({ keyId: k.id, default: k.id === config.defaultKeyId, backend: s.backend, issuer: k.issuer, verificationMethod: k.verificationMethod, alg: 'ES256', publicKeyJwk: jwk,
        didVerificationMethod: { id: k.verificationMethod, type: 'JsonWebKey', controller: k.issuer, publicKeyJwk: jwk } });
    }
    return out;
  }

  async function sign(principal, req, ev) {
    requireScope(principal, 'sign');
    if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Unsupported Media Type', 'Content-Type must be application/json.');
    if (Buffer.byteLength(req.rawBody || '') > config.policy.maxPayloadBytes + 4096) throw new HttpError(413, 'Payload Too Large', `Maximum credential size is ${config.policy.maxPayloadBytes} bytes.`);
    let body; try { body = JSON.parse(req.rawBody); } catch { throw new HttpError(400, 'Bad Request', 'Body is not valid JSON.'); }
    const keyId = body.keyId ?? config.defaultKeyId, keyCfg = config.keys.find(k => k.id === keyId);
    if (!keyCfg) throw new HttpError(404, 'Not Found', `Unknown keyId "${keyId}".`);
    if (!canUseKey(principal, keyId)) throw new HttpError(403, 'Forbidden', `Not allowed to use key "${keyId}".`);
    const cred = body.credential;
    if (Buffer.byteLength(JSON.stringify(cred ?? null)) > config.policy.maxPayloadBytes) throw new HttpError(413, 'Payload Too Large', `Maximum credential size is ${config.policy.maxPayloadBytes} bytes.`);
    checkCredential(cred, keyCfg, config.policy, deps.now?.());
    ev.keyId = keyId; ev.credentialId = cred.id; ev.types = cred.type; ev.payloadSha256 = sha256(JSON.stringify(cred)).toString('hex');

    const header = buildHeader(keyCfg), input = signingInput(header, cred), signer = signerFor(keyCfg);
    let sig, pub;
    try { sig = await signer.sign(input); pub = await signer.publicJwk(); } catch (e) { throw backendFail(e); }
    if (!verifyEs256(pub, input, sig)) throw new HttpError(500, 'Internal Server Error', 'Signature self-check failed; key and configuration do not match.');   // defence in depth
    ev.backend = signer.backend;
    return json(200, { jwt: `${input}.${b64u(sig)}`, keyId, kid: header.kid, alg: header.alg, requestId: ev.requestId }, { 'X-Signing-Backend': signer.backend });
  }

  async function handle(req, log = () => {}) {
    const requestId = newRequestId(req.headers['x-request-id']), t0 = Date.now();
    const hdr = { ...baseHeaders(requestId), ...corsHeaders(req.headers.origin, config.allowedOrigins) };
    const ev = { event: 'request', requestId, method: req.method, path: req.path };
    let res, principal;
    try {
      const path = req.path.replace(/\/+$/, '') || '/';
      if (req.method === 'OPTIONS') res = { status: 204, headers: hdr, body: '' };
      else if (req.method === 'GET' && path === '/v1/health') res = json(config.ok ? 200 : 503, { status: config.ok ? 'ok' : 'misconfigured', version: config.version, environment: config.serviceEnv }, hdr);
      else {
        if (!config.ok) throw new HttpError(503, 'Service Unavailable', 'The service is misconfigured.');
        principal = await authenticate(req.headers, config, deps);
        ev.principal = principal.id;
        const rl = limiter.check(principal.id, principal.rateLimitPerMinute);
        if (!rl.ok) throw new HttpError(429, 'Too Many Requests', 'Rate limit exceeded.', { headers: { 'Retry-After': String(rl.retryAfter) } });
        if (req.method === 'GET' && path === '/v1/keys') { requireScope(principal, 'keys:read'); res = json(200, { keys: await listKeys(principal) }, hdr); }
        else if (req.method === 'POST' && path === '/v1/sign/vc-jwt') { const r = await sign(principal, req, ev); res = { ...r, headers: { ...r.headers, ...hdr } }; }
        else throw new HttpError(path.startsWith('/v1/') ? 405 : 404, path.startsWith('/v1/') ? 'Method Not Allowed' : 'Not Found', 'No such operation.');
      }
    } catch (e) {
      if (e instanceof HttpError) { res = problem(e, requestId, hdr); if (e.extra?.cause) ev.error = String(e.extra.cause?.message || e.extra.cause); if (e.status === 422) ev.problems = e.extra.problems; }
      else { ev.error = String(e?.stack || e); res = problem(new HttpError(500, 'Internal Server Error', 'Unexpected error.'), requestId, hdr); }
    }
    log(JSON.stringify({ ...ev, status: res.status, durationMs: Date.now() - t0 }));
    return res;
  }
  return { handle };
}
