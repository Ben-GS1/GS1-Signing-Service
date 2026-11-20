// Signing policy: the service only signs what a GS1 member organization is supposed to issue.
// A leaked API key can therefore not be used to sign arbitrary statements.
import { HttpError } from './http.js';

export function checkCredential(cred, keyCfg, policy, now = Date.now()) {
  const problems = [];
  if (!cred || typeof cred !== 'object' || Array.isArray(cred)) throw new HttpError(400, 'Bad Request', '"credential" must be a JSON object.');
  const ctx = cred['@context'];
  if (!Array.isArray(ctx) || ctx[0] !== policy.requiredContext) problems.push(`@context must be an array starting with ${policy.requiredContext}`);
  const types = Array.isArray(cred.type) ? cred.type : [];
  if (!types.includes('VerifiableCredential')) problems.push('type must include VerifiableCredential');
  const specific = types.filter(t => t !== 'VerifiableCredential');
  if (!specific.length || !specific.every(t => policy.allowedTypes.includes(t))) problems.push(`credential type not allowed (allowed: ${policy.allowedTypes.join(', ')})`);
  const issuerId = typeof cred.issuer === 'string' ? cred.issuer : cred.issuer?.id;
  if (issuerId !== keyCfg.issuer) problems.push(`issuer must be ${keyCfg.issuer} for key ${keyCfg.id}`);
  if (typeof cred.id !== 'string' || (policy.idPrefixes.length && !policy.idPrefixes.some(p => cred.id.startsWith(p)))) problems.push('credential id is missing or outside the allowed prefixes');
  if ('proof' in cred) problems.push('credential must not contain a proof');
  const from = Date.parse(cred.validFrom);
  if (Number.isNaN(from)) problems.push('validFrom is required and must be an ISO date-time');
  else if (from > now + 5 * 60000) problems.push('validFrom must not be in the future');
  if (cred.validUntil !== undefined || specific.some(t => policy.requireValidUntilFor.includes(t))) {
    const until = Date.parse(cred.validUntil);
    if (Number.isNaN(until)) problems.push('validUntil is required and must be an ISO date-time');
    else if (!Number.isNaN(from)) {
      if (until <= from) problems.push('validUntil must be after validFrom');
      if (until > from + policy.maxValidityDays * 86400000) problems.push(`validity must not exceed ${policy.maxValidityDays} days`);
    }
  }
  if (problems.length) throw new HttpError(422, 'Credential rejected by signing policy', 'The credential does not satisfy the signing policy.', { problems });
}
