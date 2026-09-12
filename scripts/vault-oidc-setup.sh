#!/bin/sh
set -eu

ISSUER="https://sso.core.stplabs.io/application/o/vault/"
UI_CALLBACK="https://vault.core.stplabs.io/ui/vault/auth/oidc/oidc/callback"
CLI_CALLBACK="http://localhost:8250/oidc/callback"
GROUP="platform-admins"
POLICY="platform-admin"

: "${VAULT_ADDR:?set VAULT_ADDR}"
: "${VAULT_TOKEN:?set VAULT_TOKEN to an admin token}"
: "${VAULT_OIDC_CLIENT_ID:?set VAULT_OIDC_CLIENT_ID (must match the authentik blueprint)}"
: "${VAULT_OIDC_CLIENT_SECRET:?set VAULT_OIDC_CLIENT_SECRET (must match the authentik blueprint)}"

echo "==> checking vault is reachable and unsealed"
if ! vault status >/dev/null 2>&1; then
  vault status || true
  echo "ERROR: vault is sealed or unreachable" >&2
  exit 1
fi

echo "==> enabling oidc auth method"
if vault auth list | grep -q '^oidc/'; then
  echo "    already enabled, skipping"
else
  vault auth enable oidc
fi

echo "==> writing auth/oidc/config"
vault write auth/oidc/config \
  oidc_discovery_url="$ISSUER" \
  oidc_client_id="$VAULT_OIDC_CLIENT_ID" \
  oidc_client_secret="$VAULT_OIDC_CLIENT_SECRET" \
  default_role="default"

echo "==> writing $POLICY policy"
vault policy write "$POLICY" - <<'POLICYEOF'
path "auth/*"                { capabilities = ["create","read","update","delete","list","sudo"] }
path "sys/auth"              { capabilities = ["read"] }
path "sys/auth/*"            { capabilities = ["create","read","update","delete","sudo"] }
path "sys/policies/acl"      { capabilities = ["read","list"] }
path "sys/policies/acl/*"    { capabilities = ["create","read","update","delete","list"] }
path "sys/mounts"            { capabilities = ["read"] }
path "sys/mounts/*"          { capabilities = ["create","read","update","delete","list","sudo"] }
path "sys/leases/*"          { capabilities = ["create","read","update","delete","list","sudo"] }
path "sys/health"            { capabilities = ["read","sudo"] }
path "sys/capabilities-self" { capabilities = ["update"] }
path "identity/*"            { capabilities = ["create","read","update","delete","list"] }
path "secret/*"              { capabilities = ["create","read","update","delete","list"] }
POLICYEOF

echo "==> writing auth/oidc/role/default"
vault write auth/oidc/role/default \
  role_type="oidc" \
  bound_audiences="$VAULT_OIDC_CLIENT_ID" \
  allowed_redirect_uris="$UI_CALLBACK,$CLI_CALLBACK" \
  user_claim="preferred_username" \
  groups_claim="groups" \
  oidc_scopes="openid,profile,email" \
  token_policies="default" \
  ttl="1h"

echo "==> mapping authentik group '$GROUP' to policy '$POLICY'"
ACCESSOR=$(vault read -field=accessor sys/auth/oidc)
echo "    oidc mount accessor: $ACCESSOR"

if vault read "identity/group/name/$GROUP" >/dev/null 2>&1; then
  echo "    identity group exists, updating policies"
  vault write "identity/group/name/$GROUP" type="external" policies="$POLICY" >/dev/null
else
  vault write identity/group name="$GROUP" type="external" policies="$POLICY" >/dev/null
fi
CANONICAL_ID=$(vault read -field=id "identity/group/name/$GROUP")
echo "    identity group id: $CANONICAL_ID"

echo "    creating group-alias"
if vault write identity/group-alias \
     name="$GROUP" mount_accessor="$ACCESSOR" canonical_id="$CANONICAL_ID" >/dev/null 2>&1; then
  echo "    group-alias created"
else
  echo "    group-alias already exists for this mount (nothing to do)"
fi

echo
echo "==> done. verify with:"
echo "    vault read auth/oidc/config"
echo "    vault read auth/oidc/role/default"
echo "    vault read identity/group/name/$GROUP"
echo "    vault login -method=oidc"
