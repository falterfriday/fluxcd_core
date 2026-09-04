#!/usr/bin/env bash

set -uo pipefail

CATALOG='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
KUBECONFORM_ARGS=(
  -strict
  -summary
  -ignore-missing-schemas
  -schema-location default
  -schema-location "$CATALOG"
)

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cd "$repo_root" || exit 1

listing="$(python3 .github/scripts/list-kustomizations.py)" || exit 1

failed=0
checked=0
skipped=0

while IFS=$'\t' read -r name kpath file sops; do
  [ -n "$name" ] || continue
  label="$(printf '%-16s %-38s' "$name" "$file")"

  if [ "$sops" = "yes" ]; then
    if built="$(kustomize build "$kpath" 2>&1)"; then
      count="$(printf '%s\n' "$built" | grep -c '^sops:' || true)"
      echo "$label built OK (${count} encrypted resources), schema check N/A"
      skipped=$((skipped + 1))
    else
      echo "$label BUILD FAILED"
      printf '%s\n' "$built" | sed 's/^/    /'
      echo "::error file=${file},title=kustomize build failed::Kustomization '${name}' (path ${kpath}) does not build"
      failed=1
    fi
    continue
  fi

  if ! rendered="$(flux build kustomization "$name" \
      --path "$kpath" --kustomization-file "$file" --dry-run 2>&1)"; then
    echo "$label BUILD FAILED"
    printf '%s\n' "$rendered" | sed 's/^/    /'
    echo "::error file=${file},title=flux build failed::Kustomization '${name}' (path ${kpath}) does not build"
    failed=1
    continue
  fi

  if result="$(printf '%s' "$rendered" | kubeconform "${KUBECONFORM_ARGS[@]}" 2>&1)"; then
    echo "$label $(printf '%s' "$result" | tail -n 1)"
    checked=$((checked + 1))
  else
    echo "$label SCHEMA INVALID"
    printf '%s' "$result" | sed 's/^/    /'
    echo "::error file=${file},title=schema validation failed::Kustomization '${name}' renders invalid resources"
    failed=1
  fi
done <<< "$listing"

echo
echo "validate-kustomizations: ${checked} validated, ${skipped} build-only (sops)"
exit "$failed"
