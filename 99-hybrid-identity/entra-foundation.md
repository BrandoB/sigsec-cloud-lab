# Entra ID Hybrid-Identity Foundation

Identity substrate for the SigSec cloud purple-team lab. All tenant-specific IDs
are redacted; real values live only in the tenant and the local `az` session.

## Tenant

- Directory: `<TENANT_DOMAIN>.onmicrosoft.com`
- Tenant ID: `<TENANT_ID>`
- Subscription: Azure startup credits (Microsoft for Startups), granted 2026-09.

## Lab identities

| Object | Display name | Identifier |
|--------|--------------|------------|
| User   | Lab Alice    | `labalice@<TENANT_DOMAIN>.onmicrosoft.com` |
| Group  | sigsec-lab-users | mailNickname `sigseclabusers` |

Lab-user password is set locally and never committed.

## App registration + service principal

- App display name: `sigsec-lab-app`
- App (client) ID: `<APP_ID>`
- Service principal created for the app in this tenant.

> API permissions are intentionally **minimal** at this stage. Phase 2 over-scopes
> them to build the OAuth-consent seam — not before.

## Provenance

Created via `az` (Azure CLI) per the Phase-1 plan, Task 5. Reproduce with:

```bash
az ad user create --display-name "Lab Alice" \
  --user-principal-name "labalice@<TENANT_DOMAIN>.onmicrosoft.com" \
  --password '<set-locally>' --force-change-password-next-sign-in false
az ad group create --display-name "sigsec-lab-users" --mail-nickname "sigseclabusers"
APPID=$(az ad app create --display-name "sigsec-lab-app" --query appId -o tsv)
az ad sp create --id "$APPID"
```
