# GS1 Signing Service

Signing-as-a-Service for GS1 Digital License credentials (W3C VC 2.0 as **VC-JWT, ES256**), hosted on **Azure Static Web Apps** with a **managed Azure Functions API**. In production the private key lives in **Azure Key Vault** and never leaves it: the service sends only a SHA-256 digest to Key Vault and gets the signature back. For testing a mocked key from app settings is used.

```
GLN Credential Issuer (local SPA)  --HTTPS, API key / Entra token-->  Azure Static Web App
                                                                        |- /            landing page, /openapi.json
                                                                        '- /api/v1/*    Azure Functions (Node 20)
                                                                                         |- policy check
                                                                                         '- sign: mock key (test) | Azure Key Vault (production)
```

## API

| Operation | Auth | Purpose |
|---|---|---|
| `GET /api/v1/health` | none | status and version only |
| `GET /api/v1/keys` | scope `keys:read` | public keys, issuer DID, verification method (`didVerificationMethod` is ready to paste into the DID document) |
| `POST /api/v1/sign/vc-jwt` | scope `sign` | body `{ "keyId": "...", "credential": {...} }` returns `{ "jwt", "kid", "alg", "keyId", "requestId" }` |

Full description: `app/openapi.json` (served at `/openapi.json`). Errors are RFC 9457 `application/problem+json`; policy rejections list the reasons in `problems[]`.

```bash
curl -s -X POST https://<your-app>.azurestaticapps.net/api/v1/sign/vc-jwt \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"credential": { ... }}'
```

## Security model

* **Key protection:** Key Vault key (EC P-256, `sign`/`verify` only). The service signs a digest; after every signature it verifies it against the public key (detects a wrong key behind a key id).
* **Authentication:** API keys (only SHA-256 hashes are configured, constant-time comparison, optional expiry, per-key scopes, per-key allowed key ids and rate limit) and/or Microsoft Entra ID access tokens (signature, issuer, audience and app role `Signer` are validated). No authentication configured means the service refuses to run.
* **Signing policy:** a stolen API key cannot sign arbitrary documents. Only the configured credential types, only with `issuer` equal to the key's DID, `id` inside the allowed prefixes, `@context` starting with VC 2.0, no embedded proof, `validFrom` not in the future, `validUntil` required (max `maxValidityDays`) for key and data credentials, size limit.
* **Fail closed:** invalid configuration, mock key in production (unless `ALLOW_MOCK_KEY=true`), missing `idPrefixes` in production: the service answers 503.
* **Hygiene:** CORS allow-list, `Cache-Control: no-store`, HSTS and CSP headers on the static site, request ids, structured audit log per request (principal, key id, credential id, SHA-256 of the payload; never the payload), rate limiting, no backend error details in responses.
* **Limits to know:** the rate limiter is per function instance (use Front Door or API Management for hard global limits). Static Web Apps managed functions have cold starts and a 45 s request limit.

## Configuration (app settings)

| Setting | Meaning |
|---|---|
| `SIGNING_KEYS` | JSON array. Mock: `{"id","backend":"mock","issuer","verificationMethod","jwk"}`. Key Vault: `{"id","backend":"keyvault","issuer","verificationMethod","keyVaultKeyId"}` |
| `API_KEYS` | JSON array of `{"id","sha256","scopes":["sign","keys:read"],"keyIds":["*"],"rateLimitPerMinute","expires","disabled"}`. Create with `npm run keygen -- <client-id>` in `api/` |
| `ENTRA_TENANT_ID`, `ENTRA_AUDIENCE`, `ENTRA_REQUIRED_ROLE` | optional Entra ID validation (role default `Signer`) |
| `SIGNING_POLICY` | JSON overrides: `idPrefixes`, `allowedTypes`, `maxValidityDays`, `maxPayloadBytes`, `requireValidUntilFor` |
| `ALLOWED_ORIGINS` | comma list for CORS. The local issuer opened from a file sends origin `null`, so include `null` (safe here because auth uses a bearer key, not cookies) |
| `SERVICE_ENV` | `development` or `production` |
| `DEFAULT_KEY_ID`, `RATE_LIMIT_PER_MINUTE` | defaults: first key, 60 |

## Run locally

```bash
cd api && npm ci && npm test                      # 15 tests
cp local.settings.sample.json local.settings.json # contains the mocked TEST key and the dev API key gsk_local-dev-test-key-change-me
npm i -g @azure/static-web-apps-cli azure-functions-core-tools@4
swa start ../app --api-location .                 # http://localhost:4280  (API: http://localhost:4280/api/v1/health)
```

## Test phase: mocked key
`local.settings.sample.json` contains a throw-away P-256 key (the same TEST key that the issuer expects, with the issuer DID `did:web:vc.gs1.ch`). Responses carry `X-Signing-Backend: mock` and `GET /api/v1/keys` reports `"backend": "mock"`, which the issuer displays as a warning. Never use this key for anything real.

## Going live with Azure Key Vault
1. Run (and adapt) `infra/setup-azure.sh`: Static Web App, Key Vault (RBAC, purge protection), EC P-256 key `gln-signing`.
2. Publish the public key: `GET /api/v1/keys` returns `didVerificationMethod`. Put it into your `did:webvh` DID log / document and set `verificationMethod` to its id. The key id fragment must match what verifiers resolve.
3. App settings: `SERVICE_ENV=production`, `SIGNING_KEYS` with `"backend":"keyvault"`, `SIGNING_POLICY` with `idPrefixes`, `API_KEYS`, `ALLOWED_ORIGINS`.
4. Key Vault access, two options:
   * **Path A (simple):** API as SWA managed functions. Managed functions cannot use a managed identity (verify in the current Microsoft docs), so create a service principal with role *Key Vault Crypto User* on the vault and set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` as app settings. Rotate the secret regularly.
   * **Path B (recommended):** dedicated Function App with system-assigned managed identity (role *Key Vault Crypto User*), linked to the Static Web App; deploy with `.github/workflows/deploy-function-app.yml`. No secret anywhere.
5. Remove the mock key from the settings. Set an expiry on API keys and rotate them.

Key rotation: create a new key version or key, add a second entry to `SIGNING_KEYS`, publish the new verification method in the DID, switch `DEFAULT_KEY_ID`, keep the old method in the DID until all credentials signed with it have expired.

## GitHub and CI/CD
1. Push this repository to GitHub.
2. Create the Static Web App (`az staticwebapp create ... --sku Standard`, see `infra/setup-azure.sh`) and copy its deployment token to the repository secret **`AZURE_STATIC_WEB_APPS_API_TOKEN`**.
3. In GitHub, create the environment **production** and require a reviewer for deployments.
4. Workflows:
   * `ci.yml`: tests and `npm audit` on every branch and pull request.
   * `azure-static-web-apps.yml`: tests, then deploys `app/` and `api/`. Push to `main` deploys production, a pull request gets a preview environment that is closed together with the pull request.
   * `deploy-function-app.yml`: optional path B (OIDC login with `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` secrets and the variable `FUNCTION_APP_NAME`).
   * `dependabot.yml`: weekly dependency and action updates.
5. Application settings are managed in Azure (portal, CLI or Bicep), not in the repository. Do not commit secrets.

## Repository layout
```
app/        static landing page, openapi.json, staticwebapp.config.json (security headers)
api/        Azure Functions v4 (Node 20, ESM): src/functions/api.js, src/lib/*, test/
infra/      setup-azure.sh (Azure CLI, untested)
scripts/    generate-api-key.mjs
.github/    workflows, dependabot
```
