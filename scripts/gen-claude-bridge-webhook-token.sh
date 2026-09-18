#!/bin/sh
set -eu

# Generates the shared bearer token that authenticates Alertmanager to the
# claude-bridge /alert endpoint, and writes it into two SOPS-encrypted Secrets:
#
#   apps/claude-bridge/webhook-token.sops.yaml          (ns claude-bridge)
#   infrastructure/monitoring/claude-bridge-webhook-token.sops.yaml (ns monitoring)
#
# Both copies must hold the same value, so always regenerate with this script
# rather than editing either file by hand. The token never reaches stdout.

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
BRIDGE_FILE="apps/claude-bridge/webhook-token.sops.yaml"
MONITORING_FILE="infrastructure/monitoring/claude-bridge-webhook-token.sops.yaml"

command -v sops >/dev/null || { echo "ERROR: sops not on PATH" >&2; exit 1; }
command -v openssl >/dev/null || { echo "ERROR: openssl not on PATH" >&2; exit 1; }

TOKEN=$(openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-48)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

emit() {
  cat > "$TMP/plain.yaml" <<INNER
---
apiVersion: v1
kind: Secret
metadata:
    name: $1
    namespace: $2
type: Opaque
stringData:
    token: $TOKEN
INNER
  sops --encrypt --config "$REPO_ROOT/.sops.yaml" \
       --filename-override "$3" "$TMP/plain.yaml" > "$REPO_ROOT/$3"
  rm -f "$TMP/plain.yaml"
  echo "    wrote $3"
}

echo "==> generating shared webhook bearer token"
emit claude-bridge-webhook       claude-bridge "$BRIDGE_FILE"
emit alertmanager-claude-bridge  monitoring    "$MONITORING_FILE"

echo "==> done. Commit both files together."
echo "    Rotating: re-run this script, commit, and let Flux reconcile. The"
echo "    bridge reads the token at startup, so it restarts on secret change"
echo "    only if the pod is recreated -- roll it explicitly after rotation:"
echo "      kubectl -n claude-bridge rollout restart deploy/claude-bridge"
