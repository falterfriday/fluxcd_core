#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
FLUX_GROUP = "kustomize.toolkit.fluxcd.io"


def main() -> int:
    rows = []
    for path in sorted(REPO.glob("clusters/*/*.yaml")):
        try:
            docs = list(yaml.safe_load_all(path.read_text()))
        except yaml.YAMLError as exc:
            print(f"ERROR: {path} is not parseable YAML: {exc}", file=sys.stderr)
            return 1
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if not str(doc.get("apiVersion", "")).startswith(FLUX_GROUP):
                continue
            if doc.get("kind") != "Kustomization":
                continue
            spec = doc.get("spec") or {}
            rows.append(
                (
                    doc["metadata"]["name"],
                    spec.get("path", ""),
                    str(path.relative_to(REPO)),
                    "yes" if spec.get("decryption") else "no",
                )
            )

    if not rows:
        print("no Flux Kustomizations under clusters/ yet", file=sys.stderr)
        return 0

    for row in rows:
        print("\t".join(row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
