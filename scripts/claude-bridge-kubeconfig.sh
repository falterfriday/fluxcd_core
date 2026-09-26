#!/bin/sh
set -eu

SA_NAME="claude-bridge-readonly"
SA_NAMESPACE="monitoring"
TOKEN_DURATION="8760h"

usage() {
  echo "usage: $0 <kubectl-context> <cluster-name>" >&2
  echo "  emits a read-only kubeconfig on stdout, e.g." >&2
  echo "    $0 staging staging | vault kv put secret/claude-bridge/kubeconfig-staging kubeconfig=-" >&2
  exit 2
}

[ $# -eq 2 ] || usage
CONTEXT="$1"
CLUSTER="$2"

SERVER=$(kubectl --context="$CONTEXT" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
[ -n "$SERVER" ] || { echo "ERROR: no server for context $CONTEXT" >&2; exit 1; }

CA=$(kubectl --context="$CONTEXT" config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
if [ -z "$CA" ]; then
  CA_FILE=$(kubectl --context="$CONTEXT" config view --minify -o jsonpath='{.clusters[0].cluster.certificate-authority}')
  [ -n "$CA_FILE" ] || { echo "ERROR: no CA for context $CONTEXT" >&2; exit 1; }
  CA=$(base64 -w0 < "$CA_FILE")
fi

kubectl --context="$CONTEXT" -n "$SA_NAMESPACE" get serviceaccount "$SA_NAME" >/dev/null 2>&1 || {
  echo "ERROR: serviceaccount $SA_NAMESPACE/$SA_NAME not found in $CONTEXT — merge the RBAC first" >&2
  exit 1
}

TOKEN=$(kubectl --context="$CONTEXT" -n "$SA_NAMESPACE" create token "$SA_NAME" --duration="$TOKEN_DURATION")

cat <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: $CLUSTER
    cluster:
      server: $SERVER
      certificate-authority-data: $CA
users:
  - name: claude-bridge
    user:
      token: $TOKEN
contexts:
  - name: $CLUSTER
    context:
      cluster: $CLUSTER
      user: claude-bridge
current-context: $CLUSTER
EOF
