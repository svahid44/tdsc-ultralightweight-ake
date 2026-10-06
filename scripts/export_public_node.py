#!/usr/bin/env python3
from __future__ import annotations
import argparse, fnmatch, shutil, tarfile, tempfile
from pathlib import Path

EXCLUDED_DIRS = {".venv","venv","__pycache__",".git","data","import","export","evidence","target","node_modules",".anchor","test-ledger"}
SECRET_PATTERNS = ["*private*","*secret*","*.pem","*.key","*.seed","*.wallet",".env",".env.*","*wallet*.json","*solana*.json","*.db","*.sqlite*"]

def secret_name(path: Path) -> bool:
    return any(fnmatch.fnmatch(path.name.lower(), p.lower()) for p in SECRET_PATTERNS)

def sanitize(text: str) -> str:
    out=[]
    for line in text.splitlines():
        if line.startswith("HOSTNAME="): out.append("HOSTNAME=<REDACTED_HOSTNAME>")
        elif line.startswith("IP="): out.append("IP=<REDACTED_IP>")
        else: out.append(line)
    return "\n".join(out)+("\n" if text.endswith("\n") else "")

def copy_tree(src: Path, dst: Path):
    for p in src.rglob("*"):
        rel=p.relative_to(src)
        if any(part in EXCLUDED_DIRS for part in rel.parts) or p.is_dir() or secret_name(p):
            continue
        q=dst/rel; q.parent.mkdir(parents=True,exist_ok=True)
        if p.suffix.lower() in {".conf",".ini",".txt",".json",".toml",".yaml",".yml",".py",".md",".rs"}:
            try:
                q.write_text(sanitize(p.read_text())); continue
            except UnicodeDecodeError: pass
        shutil.copy2(p,q)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--root",required=True,type=Path)
    ap.add_argument("--role",required=True,choices=["tuc","nsp","smd"])
    ap.add_argument("--out",required=True,type=Path)
    a=ap.parse_args()
    root=a.root.expanduser().resolve()
    with tempfile.TemporaryDirectory() as td:
        stage=Path(td)/"bundle"
        (stage/a.role).mkdir(parents=True)
        for top in ("src","config"):
            src=root/a.role/top
            if src.exists(): copy_tree(src,stage/a.role/top)
        if (root/"shared").exists(): copy_tree(root/"shared",stage/"shared")
        with tarfile.open(a.out.expanduser(),"w:gz") as tf:
            for child in stage.iterdir(): tf.add(child,arcname=child.name)
    print("Created:",a.out.expanduser())

if __name__=="__main__": main()
