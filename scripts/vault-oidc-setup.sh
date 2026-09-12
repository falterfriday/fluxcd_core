#!/usr/bin/env bash
set -euo pipefail

ISSUER="https://sso.core.stplabs.io/application/o/vault/"
UI_CALLBACK="https://vault.core.stplabs.io/ui/vault/auth/oidc/oidc/callback"
CLI_CALLBACK="http://localhost:8250/oidc/callback"
GROUP="platform-admins"
POLICY="platform-admin"

: "${VAULT_ADDR:?set VAULT_ADDR, e.g. https://vault.core.stplabs.io}"
: "${VAULT_TOKEN:?set VAULT_TOKEN to an admin/root token}"
: "${VAULT_OIDC_CLIENT_ID:?set VAULT_OIDC_CLIENT_ID (must match the authentik blueprint)}"
: "${VAULT_OIDC_CLIENT_SECRET:?set VAULT_OIDC_CLIENT_SECRET (must match the authentik blueprint)}"

echo "==> vault status"
vault status -format=json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("    sealed=%s version=%s" % (d["sealed"], d["version"])); sys.exit(1 if d["sealed"] else 0)'

echo "==> enabling oidc auth method"
if vault auth list -format=json | python3 -c 'import json,sys; sys.exit(0 if "oidc/" in json.load(sys.stdin) else 1)'; then
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
ACCESSOR=$(vault auth list -format=json | python3 -c 'import json,sys; print(json.load(sys.stdin)["oidc/"]["accessor"])')
echo "    oidc mount accessor: $ACCESSOR"

if vault read -format=json "identity/group/name/$GROUP" >/dev/null 2>&1; then
  echo "    identity group exists, updating policies"
  vault write "identity/group/name/$GROUP" type="external" policies="$POLICY"
else
  vault write identity/group name="$GROUP" type="external" policies="$POLICY"
fi
CANONICAL_ID=$(vault read -field=id "identity/group/name/$GROUP")

ALIAS_ID=$(vault list -format=json identity/group-alias/id 2>/dev/null | python3 -c '
import json, subprocess, sys
try:
    ids = json.load(sys.stdin)
except Exception:
    sys.exit(0)
want_name, want_accessor = sys.argv[1], sys.argv[2]
for i in ids:
    out = subprocess.run(["vault", "read", "-format=json", "identity/group-alias/id/" + i],
                         capture_output=True, text=True)
    if out.returncode:
        continue
    d = json.loads(out.stdout)["data"]
    if d.get("name") == want_name and d.get("mount_accessor") == want_accessor:
        print(i)
        break
' "$GROUP" "$ACCESSOR" || true)

if [ -n "${ALIAS_ID:-}" ]; then
  echo "    group-alias exists ($ALIAS_ID), updating"
  vault write "identity/group-alias/id/$ALIAS_ID" \
    name="$GROUP" mount_accessor="$ACCESSOR" canonical_id="$CANONICAL_ID"
else
  echo "    creating group-alias"
  vault write identity/group-alias \
    name="$GROUP" mount_accessor="$ACCESSOR" canonical_id="$CANONICAL_ID"
fi

echo
echo "==> done. verify with:"
echo "    vault read auth/oidc/config"
echo "    vault read auth/oidc/role/default"
echo "    vault read identity/group/name/$GROUP"
echo "    vault login -method=oidc"
