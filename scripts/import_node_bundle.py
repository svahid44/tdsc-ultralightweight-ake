#!/usr/bin/env python3
from __future__ import annotations
import argparse, tarfile
from pathlib import Path
ALLOWED={"tuc","nsp","smd","shared"}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("bundle",type=Path); ap.add_argument("repo",type=Path)
    a=ap.parse_args(); root=a.repo.resolve()
    with tarfile.open(a.bundle,"r:gz") as tf:
        for m in tf.getmembers():
            parts=Path(m.name).parts
            if not parts or parts[0] not in ALLOWED: raise RuntimeError(f"Unexpected root: {m.name}")
            dest=(root/m.name).resolve()
            if not str(dest).startswith(str(root)): raise RuntimeError(f"Unsafe path: {m.name}")
        tf.extractall(root)
    print("Imported:",a.bundle)

if __name__=="__main__": main()
