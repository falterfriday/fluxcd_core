#!/usr/bin/env python3
"""Every ${VAR} in a Kustomization's path must resolve from its substitute sources.

Flux performs postBuild substitution against the live cluster, so `flux build
--dry-run` leaves variables untouched and kubeconform accepts the literal
placeholder. A missing key therefore reaches the cluster silently. SOPS encrypts
values but not key names, so the keys can be checked here without decryption.
"""
from __future__ import annotations
import os
import re
import sys
from pathlib import Path
import yaml

REPO = Path(__file__).resolve().parents[2]
IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::[=-][^}]*)?\}")
failures: list[str] = []


def docs(path: Path):
    try:
        return [d for d in yaml.safe_load_all(path.read_text(errors="replace")) if isinstance(d, dict)]
    except yaml.YAMLError:
        return []


def resource_keys(name: str, kinds: set[str]) -> set[str] | None:
    """Key names of the first Secret/ConfigMap in the repo with this name."""
    for path in REPO.rglob("*.y*ml"):
        if ".git" in path.parts:
            continue
        for d in docs(path):
            if d.get("kind") in kinds and (d.get("metadata") or {}).get("name") == name:
                keys: set[str] = set()
                for section in ("data", "stringData"):
                    block = d.get(section)
                    if isinstance(block, dict):
                        keys |= set(block)
                return keys
    return None


def main() -> int:
    for path in (REPO / "clusters").rglob("*.y*ml"):
        for d in docs(path):
            if d.get("kind") != "Kustomization":
                continue
            spec = d.get("spec") or {}
            post = spec.get("postBuild") or {}
            sources = post.get("substituteFrom") or []
            inline = set((post.get("substitute") or {}))
            target = spec.get("path")
            if not target or not (sources or inline):
                continue

            available = set(inline)
            for src in sources:
                kind = src.get("kind", "Secret")
                keys = resource_keys(src.get("name", ""), {kind})
                if keys is None:
                    if not src.get("optional"):
                        failures.append(
                            f"{path.relative_to(REPO)}: Kustomization "
                            f"{d['metadata']['name']!r} references {kind} "
                            f"{src.get('name')!r}, which is not defined in this repo"
                        )
                    continue
                available |= keys

            root = REPO / target.lstrip("./")
            if not root.exists():
                continue
            for f in sorted(root.rglob("*.y*ml")):
                used = set(VAR.findall(f.read_text(errors="replace")))
                for var in sorted(used - available):
                    failures.append(
                        f"{f.relative_to(REPO)}: ${{{var}}} is not provided by the "
                        f"substitute sources of Kustomization {d['metadata']['name']!r} "
                        f"(available: {sorted(available) or 'none'})"
                    )

    if not failures:
        print("substitution-guard: OK — every ${VAR} resolves")
        return 0
    print(f"substitution-guard: {len(failures)} violation(s)\n")
    for msg in failures:
        print(f"  {msg}")
        if IN_ACTIONS:
            print(f"::error::{msg}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
