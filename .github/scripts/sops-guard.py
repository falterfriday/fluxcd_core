#!/usr/bin/env python3

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
SECRET_DIR_GLOBS = ("clusters/*/secrets",)
SECRET_DIR_EXEMPT = {"kustomization.yaml"}
VENDORED_DIRS = {".ansible", ".terraform", ".git"}

PRIVATE_KEY_MARKERS = (
    "AGE-SECRET-KEY-",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN PGP PRIVATE KEY BLOCK",
)

PRIVATE_KEY_NAMES = re.compile(r"(^|/)(age\.key|keys?\.txt|.*\.agekey|.*\.pem)$")

IN_ACTIONS = os.environ.get("GITHUB_ACTIONS") == "true"

failures: list[tuple[str, str, str]] = []


def fail(check: str, path: Path | str, message: str) -> None:
    rel = str(path.relative_to(REPO)) if isinstance(path, Path) else str(path)
    failures.append((check, rel, message))

def load_sops_rules() -> list[dict]:
    cfg = REPO / ".sops.yaml"
    if not cfg.exists():
        print("::error::.sops.yaml is missing" if IN_ACTIONS else "ERROR: .sops.yaml is missing")
        sys.exit(1)
    rules = yaml.safe_load(cfg.read_text()).get("creation_rules") or []
    for rule in rules:
        rule["_re"] = re.compile(rule["path_regex"]) if rule.get("path_regex") else None
        rule["_recipients"] = {
            r.strip() for r in str(rule.get("age", "")).split(",") if r.strip()
        }
    return rules

def matching_rule(rel_path: str, rules: list[dict]) -> dict | None:
    """First rule whose path_regex matches, mirroring sops' own resolution."""
    for rule in rules:
        if rule["_re"] is None or rule["_re"].search(rel_path):
            return rule
    return None

def yaml_files() -> list[Path]:
    out = []
    for path in REPO.rglob("*.y*ml"):
        if any(part in VENDORED_DIRS for part in path.parts):
            continue
        if ".git/" in str(path) or path.suffix not in (".yaml", ".yml"):
            continue
        out.append(path)
    return sorted(out)

def file_recipients(doc: dict) -> set[str]:
    return {entry.get("recipient", "") for entry in (doc.get("sops", {}).get("age") or [])}

def check_encrypted_values(path: Path, doc: dict) -> None:
    """C6: every leaf under data/stringData must be an ENC[...] blob."""
    for section in ("data", "stringData"):
        block = doc.get(section)
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if not (isinstance(value, str) and value.startswith("ENC[")):
                fail("C6", path, f"{section}.{key} is not encrypted")

def main() -> int:
    rules = load_sops_rules()
    secret_dirs = {d for glob in SECRET_DIR_GLOBS for d in REPO.glob(glob) if d.is_dir()}

    for path in yaml_files():
        rel = str(path.relative_to(REPO))
        raw = path.read_text(errors="replace")

        for marker in PRIVATE_KEY_MARKERS:
            if marker in raw:
                fail("C5", path, f"contains private key material ({marker})")
        if PRIVATE_KEY_NAMES.search(rel):
            fail("C5", path, "filename looks like committed key material")

        try:
            docs = [d for d in yaml.safe_load_all(raw) if isinstance(d, dict)]
        except yaml.YAMLError as exc:
            fail("C0", path, f"is not parseable YAML: {exc}")
            continue

        encrypted = any("sops" in d for d in docs)
        rule = matching_rule(rel, rules)
        in_secret_dir = path.parent in secret_dirs and path.name not in SECRET_DIR_EXEMPT

        if in_secret_dir and rule is None:
            fail(
                "C2",
                path,
                "lives in a secrets directory but matches no .sops.yaml path_regex; "
                "`sops -e` would leave it in plaintext",
            )

        if rule is not None and not encrypted:
            fail("C1", path, f"matches path_regex {rule['path_regex']!r} but is not SOPS-encrypted")

        for doc in docs:
            if encrypted and "sops" in doc:
                if rule is not None and rule["_recipients"]:
                    actual = file_recipients(doc)
                    if actual != rule["_recipients"]:
                        fail(
                            "C3",
                            path,
                            "age recipients do not match .sops.yaml: "
                            f"expected {sorted(rule['_recipients'])}, found {sorted(actual)}",
                        )
                check_encrypted_values(path, doc)
            elif doc.get("kind") == "Secret" and not encrypted:
                name = (doc.get("metadata") or {}).get("name", "<unnamed>")
                fail("C4", path, f"plaintext Secret {name!r} — encrypt it with SOPS")

    if not failures:
        print(f"sops-guard: OK — {len(yaml_files())} YAML files checked, no violations")
        return 0

    print(f"sops-guard: {len(failures)} violation(s)\n")
    for check, rel, message in failures:
        print(f"  [{check}] {rel}: {message}")
        if IN_ACTIONS:
            print(f"::error file={rel},title=sops-guard {check}::{message}")
    return 1

if __name__ == "__main__":
    sys.exit(main())
