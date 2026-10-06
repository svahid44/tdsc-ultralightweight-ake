#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, py_compile, sys
from pathlib import Path
REQ=["README.md",".gitignore","docs/ARCHITECTURE.md","docs/PROTOCOL_MAPPING.md","docs/RESULTS.md","docs/PERFORMANCE.md","docs/BLOCKCHAIN_EVIDENCE.md","docs/SECURITY_NOTES.md","evidence/public/FINAL_RESULTS.json"]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default=".",type=Path); a=ap.parse_args(); root=a.root.resolve(); fail=[]
    for rel in REQ:
        if not (root/rel).exists(): fail.append("missing: "+rel)
    try: json.loads((root/"evidence/public/FINAL_RESULTS.json").read_text())
    except Exception as e: fail.append("invalid FINAL_RESULTS.json: "+str(e))
    for p in root.rglob("*.py"):
        if ".git" in p.parts or ".venv" in p.parts: continue
        try: py_compile.compile(str(p),doraise=True)
        except Exception as e: fail.append(f"compile failed {p.relative_to(root)}: {e}")
    contract=root/"solana/programs/tdsc_smd_registry/src/lib.rs"
    if contract.exists() and "PLACEHOLDER ONLY" in contract.read_text(errors="ignore"):
        fail.append("exact deployed Solana contract source is still missing")

    for role in ("tuc","nsp","smd"):
        py=list((root/role/"src").glob("*.py"))
        if not py: fail.append(f"exact {role.upper()} source has not been imported")
    if fail:
        print("Repository verification: FAIL")
        for x in fail: print(" -",x)
        sys.exit(1)
    print("Repository verification: PASS")

if __name__=="__main__": main()
