// Configuration from environment variables / Azure application settings. Fails closed: any problem => service reports "misconfigured".
const DEFAULT_POLICY = {
  allowedTypes: ['KeyCredential', 'OrganizationDataCredential', 'BitstringStatusListCredential'],
  idPrefixes: [],                       // credential "id" must start with one of these (empty = not enforced, NOT recommended)
  requireValidUntilFor: ['KeyCredential', 'OrganizationDataCredential'],
  maxValidityDays: 3650,
  maxPayloadBytes: 131072,
  requiredContext: 'https://www.w3.org/ns/credentials/v2',
};
const parse = (name, raw, errors, fallback) => {
  if (raw === undefined || raw === '') return fallback;
  try { return JSON.parse(raw); } catch { errors.push(`${name} is not valid JSON`); return fallback; }
};

export function loadConfig(env = process.env) {
  const errors = [];
  const serviceEnv = (env.SERVICE_ENV || 'development').toLowerCase();

  const keysRaw = parse('SIGNING_KEYS', env.SIGNING_KEYS, errors, []);
  if (!Array.isArray(keysRaw) || !keysRaw.length) errors.push('SIGNING_KEYS must be a non-empty JSON array');
  const keys = [];
  for (const k of Array.isArray(keysRaw) ? keysRaw : []) {
    const id = k?.id;
    if (!id || !/^[A-Za-z0-9._-]{1,64}$/.test(id)) { errors.push('signing key without valid id'); continue; }
    if (!/^did:[a-z0-9]+:\S+$/.test(k.issuer || '')) errors.push(`key ${id}: issuer must be a DID`);
    if (!String(k.verificationMethod || '').startsWith((k.issuer || '') + '#')) errors.push(`key ${id}: verificationMethod must be issuer DID + "#fragment"`);
    if (k.backend === 'mock') {
      if (serviceEnv === 'production' && env.ALLOW_MOCK_KEY !== 'true') errors.push(`key ${id}: mock backend is not allowed when SERVICE_ENV=production`);
      if (!k.jwk || k.jwk.kty !== 'EC' || k.jwk.crv !== 'P-256' || !k.jwk.d) errors.push(`key ${id}: mock backend needs an EC P-256 private "jwk"`);
    } else if (k.backend === 'keyvault') {
      if (!/^https:\/\/[^/]+\.(vault|managedhsm)\.[a-z.]+\/keys\/[A-Za-z0-9-]+(\/[0-9a-f]+)?$/.test(k.keyVaultKeyId || '')) errors.push(`key ${id}: keyVaultKeyId must look like https://<vault>.vault.azure.net/keys/<name>[/<version>]`);
    } else errors.push(`key ${id}: backend must be "mock" or "keyvault"`);
    keys.push(k);
  }
  if (new Set(keys.map(k => k.id)).size !== keys.length) errors.push('duplicate signing key ids');

  const apiKeys = parse('API_KEYS', env.API_KEYS, errors, []);
  for (const a of apiKeys) if (!a.id || !/^[0-9a-f]{64}$/.test(a.sha256 || '')) errors.push('API_KEYS entries need id and sha256 (hex of SHA-256 of the key)');
  const entra = env.ENTRA_TENANT_ID && env.ENTRA_AUDIENCE
    ? { tenantId: env.ENTRA_TENANT_ID, audience: env.ENTRA_AUDIENCE, requiredRole: env.ENTRA_REQUIRED_ROLE || 'Signer' } : null;
  if (!apiKeys.length && !entra) errors.push('no authentication configured: set API_KEYS and/or ENTRA_TENANT_ID + ENTRA_AUDIENCE');

  const policy = { ...DEFAULT_POLICY, ...parse('SIGNING_POLICY', env.SIGNING_POLICY, errors, {}) };
  if (serviceEnv === 'production' && !policy.idPrefixes.length) errors.push('SIGNING_POLICY.idPrefixes must be set in production');

  return {
    ok: errors.length === 0, errors, serviceEnv, version: env.SERVICE_VERSION || '1.0.0',
    keys, defaultKeyId: env.DEFAULT_KEY_ID || keys[0]?.id, apiKeys, entra, policy,
    allowedOrigins: (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
    rateLimitPerMinute: Number(env.RATE_LIMIT_PER_MINUTE || 60),
  };
}
