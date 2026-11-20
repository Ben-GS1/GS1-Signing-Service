#!/usr/bin/env bash
# One-time Azure setup with the Azure CLI. NOT TESTED against a real subscription: read it, adjust names, run step by step.
set -euo pipefail

RG=rg-gs1-signing            # resource group
LOC=westeurope
SWA=swa-gs1-signing          # Static Web App name
KV=kv-gs1-signing-$RANDOM    # Key Vault name (globally unique)
KEY=gln-signing              # Key Vault key name
SP=sp-gs1-signing            # service principal used by the API when it runs as SWA managed functions (path A)

az group create -n "$RG" -l "$LOC"

# 1) Static Web App. Standard plan is recommended for production (SLA, Key Vault references, bring-your-own backend).
az staticwebapp create -n "$SWA" -g "$RG" -l "$LOC" --sku Standard
TOKEN=$(az staticwebapp secrets list -n "$SWA" -g "$RG" --query properties.apiKey -o tsv)
echo "Store this as GitHub repository secret AZURE_STATIC_WEB_APPS_API_TOKEN:"; echo "$TOKEN"

# 2) Key Vault with RBAC authorization and purge protection, plus a NON-EXPORTABLE-by-design EC P-256 signing key.
#    Use --sku premium and --protection hsm on the key for an HSM-backed key.
az keyvault create -n "$KV" -g "$RG" -l "$LOC" --enable-rbac-authorization true --enable-purge-protection true --retention-days 90
KV_ID=$(az keyvault show -n "$KV" -g "$RG" --query id -o tsv)
az keyvault key create --vault-name "$KV" -n "$KEY" --kty EC --curve P-256 --ops sign verify --protection software
az keyvault key show --vault-name "$KV" -n "$KEY" --query key.kid -o tsv     # -> keyVaultKeyId for SIGNING_KEYS

# 3a) PATH A: API runs as managed functions inside the Static Web App. Managed functions cannot use a managed identity,
#     so the API authenticates to Key Vault as a service principal (AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET app settings).
APP_ID=$(az ad sp create-for-rbac -n "$SP" --query appId -o tsv)   # prints the password once: create it with `az ad sp credential reset` and copy it
az role assignment create --assignee "$APP_ID" --role "Key Vault Crypto User" --scope "$KV_ID"   # may need a few minutes to propagate

# 3b) PATH B (recommended, no secrets): dedicated Function App with a system-assigned managed identity, linked to the Static Web App.
#     az functionapp create ... --assign-identity '[system]'
#     az role assignment create --assignee <principalId> --role "Key Vault Crypto User" --scope "$KV_ID"
#     az staticwebapp backends link -n "$SWA" -g "$RG" --backend-resource-id <functionAppId> --backend-region "$LOC"
#     Deploy with .github/workflows/deploy-function-app.yml and leave api_location empty in the SWA workflow.
