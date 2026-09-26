#!/bin/sh
set -eu

KV_MOUNT="secret"
SECRET_PREFIX="claude-bridge"
POLICY="claude-bridge"
K8S_ROLE="claude-bridge"
SA_NAME="claude-bridge"
SA_NAMESPACE="claude-bridge"
KUBERNETES_HOST="https://kubernetes.default.svc"
TOKEN_TTL="15m"
TOKEN_MAX_TTL="1h"

: "${VAULT_ADDR:?set VAULT_ADDR}"
: "${VAULT_TOKEN:?set VAULT_TOKEN to an admin token}"

echo "==> checking vault is reachable and unsealed"
if ! vault status >/dev/null 2>&1; then
  vault status || true
  echo "ERROR: vault is sealed or unreachable" >&2
  exit 1
fi

echo "==> ensuring kv-v2 is mounted at $KV_MOUNT/"
if vault secrets list | grep -q "^$KV_MOUNT/"; then
  echo "    already mounted, skipping"
else
  vault secrets enable -path="$KV_MOUNT" -version=2 kv
fi

echo "==> enabling kubernetes auth method"
if vault auth list | grep -q '^kubernetes/'; then
  echo "    already enabled, skipping"
else
  vault auth enable kubernetes
fi

echo "==> writing auth/kubernetes/config"
vault write auth/kubernetes/config \
  kubernetes_host="$KUBERNETES_HOST"

echo "==> writing $POLICY policy"
vault policy write "$POLICY" - <<POLICYEOF
path "$KV_MOUNT/data/$SECRET_PREFIX/*" {
  capabilities = ["read"]
}

path "$KV_MOUNT/metadata/$SECRET_PREFIX/*" {
  capabilities = ["read", "list"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
POLICYEOF

echo "==> writing auth/kubernetes/role/$K8S_ROLE"
vault write "auth/kubernetes/role/$K8S_ROLE" \
  bound_service_account_names="$SA_NAME" \
  bound_service_account_namespaces="$SA_NAMESPACE" \
  token_policies="$POLICY" \
  token_ttl="$TOKEN_TTL" \
  token_max_ttl="$TOKEN_MAX_TTL"

echo "==> verifying"
vault policy read "$POLICY" >/dev/null
vault read "auth/kubernetes/role/$K8S_ROLE" >/dev/null
echo "    policy and role present"

cat <<'NEXTEOF'

==> configuration complete. The secrets below must be seeded by hand so the
    values never pass through a terminal transcript. The bridge has read-only
    access to them; it never writes to vault.

    A long-lived Anthropic token, from `claude setup-token`. Paste it when
    prompted rather than passing it as an argument:
  vault kv put secret/claude-bridge/anthropic-token token=-

  vault kv put secret/claude-bridge/slack webhook_url=@"$HOME/.slack-webhook"

    Verify without printing the values:
  vault kv metadata get secret/claude-bridge/anthropic-token
  vault kv metadata get secret/claude-bridge/slack

    Core needs no kubeconfig: the bridge uses its own projected ServiceAccount
    token there. The other three clusters each need one, generated after their
    read-only RBAC is merged:

  ./scripts/claude-bridge-kubeconfig.sh staging staging \
    | vault kv put secret/claude-bridge/kubeconfig-staging kubeconfig=-
  ./scripts/claude-bridge-kubeconfig.sh production production \
    | vault kv put secret/claude-bridge/kubeconfig-production kubeconfig=-
  ./scripts/claude-bridge-kubeconfig.sh internal internal \
    | vault kv put secret/claude-bridge/kubeconfig-internal kubeconfig=-
NEXTEOF
