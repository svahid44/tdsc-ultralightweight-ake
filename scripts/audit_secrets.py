#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import re
import sys
from pathlib import Path

SKIP_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "target", "node_modules"
}

BAD_NAMES = [
    "sk_tuc.key",
    "sk_smd.pem",
    "sk_nsp.pem",
    "puf_secret.key",
    "*.seed",
    "*.wallet",
    ".env",
    ".env.*",
    "*wallet*.json",
]

PRIVATE_PEM_RE = re.compile(
    r"-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----"
)

SOLANA_KEYPAIR_RE = re.compile(
    r"^\\s*\\[\\s*(?:\\d+\\s*,\\s*){31,}\\d+\\s*\\]\\s*$",
    re.M,
)

LITERAL_SECRET_RE = re.compile(
    r'''(?ix)
    \\b(?:mnemonic|seed_phrase|private_key|secret_key|wallet_key|api_key)\\b
    \\s*[:=]\\s*
    (?P<quote>["'])
    (?!<|REDACTED|PLACEHOLDER|YOUR_|EXAMPLE)
    (?P<value>[^"'\\r\\n]{16,})
    (?P=quote)
    '''
)

def should_skip(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)

    if any(part in SKIP_DIRS for part in rel.parts):
        return True

    if rel.as_posix() == "scripts/audit_secrets.py":
        return True

    return False

def bad_name(path: Path) -> bool:
    name = path.name.lower()
    return any(
        fnmatch.fnmatch(name, pattern.lower())
        for pattern in BAD_NAMES
    )

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    findings = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        if should_skip(path, root):
            continue

        if bad_name(path):
            findings.append((path, "sensitive filename"))

        if path.stat().st_size > 5_000_000:
            continue

        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue

        if PRIVATE_PEM_RE.search(text):
            findings.append((path, "private-key PEM material"))

        if SOLANA_KEYPAIR_RE.search(text):
            findings.append((path, "Solana-style raw keypair array"))

        if LITERAL_SECRET_RE.search(text):
            findings.append((path, "possible hard-coded credential literal"))

    if findings:
        print("POTENTIAL SECRETS FOUND:")
        for path, reason in findings:
            print(f"  {path.relative_to(root)} :: {reason}")
        sys.exit(2)

    print("Secret audit: PASS (no configured secret patterns detected)")

if __name__ == "__main__":
    main()
