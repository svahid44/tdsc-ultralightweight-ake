#!/usr/bin/env python3
"""Check/patch original NSP verify scripts with an opt-in observation hook.

By default, --check ONLY reads files. --apply validates both files, makes
private backups outside git, then adds a small guarded call after the existing
state-file consistency check. Does not execute NSP or the main protocol.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import stat
import sys
import tempfile
from pathlib import Path


PHASE2 = '''    if os.environ.get("TDSC_ATTACK_LAB") == "1":
        from attack_observer import record_phase2
        observation_path = record_phase2(
            eid_smd=eid_smd,
            rt_smd=rt_smd,
            t_smd=t_smd,
            h1_smd=h1_smd,
            pk_smd_raw=onchain["pk_smd"],
            a_smd_raw=onchain["a_smd"],
        )
        print("Attack-lab phase2 observation:", observation_path)

'''
PHASE3 = '''    if os.environ.get("TDSC_ATTACK_LAB") == "1":
        from attack_observer import record_phase3
        observation_path = record_phase3(
            eid_smd=eid_smd,
            id_nsp=id_nsp,
            rid_smd=rid_smd,
            r_smd=r_smd,
            st_smd=st_smd,
            v1_smd=v1_smd,
            pk_smd_raw=onchain["pk_smd"],
            a_smd_raw=onchain["a_smd"],
        )
        print("Attack-lab phase3 observation:", observation_path)

'''


def patched_text(src: str, hook: str, name: str) -> str:
    marker = 'if os.environ.get("TDSC_ATTACK_LAB") == "1":'
    if marker in src:
        raise RuntimeError(f"{name}: already instrumented; refusing a second patch")
    if 'import os\n' not in src:
        anchor_import = 'import json\n'
        if src.count(anchor_import) != 1:
            raise RuntimeError(f"{name}: cannot safely insert import")
        src = src.replace(anchor_import, anchor_import + 'import os\n', 1)
    anchor = '    print("State:", STATE_PATH)\n'
    if src.count(anchor) != 1:
        raise RuntimeError(f"{name}: expected exactly one verified-state checkpoint")
    if 'if not h1_ok:' not in src and name == "phase2":
        raise RuntimeError("phase2 verification guard not found")
    if 'if not v1_ok:' not in src and name == "phase3":
        raise RuntimeError("phase3 verification guard not found")
    source = src.replace(anchor, anchor + hook, 1)
    compile(source, name + '_instrumented.py', 'exec')
    return source


def private_dir(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"symlink directory not allowed: {path}")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    mode = path.lstat().st_mode
    if not stat.S_ISDIR(mode) or mode & 0o077:
        raise RuntimeError(f"directory must be 0700: {path}")


def exclusive_private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def replace_preserving_mode(path: Path, content: str) -> None:
    original_mode = stat.S_IMODE(path.stat().st_mode)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.lab-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(content.encode('utf-8'))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, original_mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='Only check source files, no modification')
    mode.add_argument('--apply', action='store_true', help='Patch sources with backups outside Git')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    observer = root / 'nsp' / 'src' / 'attack_observer.py'
    if observer.is_symlink() or not observer.is_file():
        raise RuntimeError('Missing nsp/src/attack_observer.py (or symlink)')
    stages = []
    for label, name, hook in (
        ('phase2', 'phase2_verify_request.py', PHASE2),
        ('phase3', 'phase3_verify_request.py', PHASE3),
    ):
        path = root / 'nsp' / 'src' / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f'Missing or symlink script: {path}')
        raw = path.read_bytes()
        text = raw.decode('utf-8')
        modified = patched_text(text, hook, label)
        stages.append((path, raw, modified))
        print(f'[READY] {name}; SHA-256 original: {hashlib.sha256(raw).hexdigest()[:20]}')
    if args.check:
        print('CHECK PASSED: no changes made; ready for optional --apply')
        return 0
    lab_root = Path.home() / 'tdsc-attack-lab'
    private_dir(lab_root)
    private_dir(lab_root / 'backups')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup_dir = lab_root / 'backups' / stamp
    private_dir(backup_dir)
    for path, raw, _ in stages:
        exclusive_private_file(backup_dir / path.name, raw)
    for path, _, modified in stages:
        replace_preserving_mode(path, modified)
        print(f'[PATCHED] {path}')
    print('Backups:', backup_dir)
    print('Opt-in only: TDSC_ATTACK_LAB=1 python nsp/src/phaseN_verify_request.py')
    print('No protocol, network or Solana operation was executed by this patcher.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, UnicodeError, SyntaxError) as error:
        print('ERROR:', error, file=sys.stderr)
        sys.exit(1)
