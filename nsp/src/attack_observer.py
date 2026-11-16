"""Opt-in, NSP-side lab capture of *verified* H1/V1 observations.

This module must only be called AFTER the corresponding verifier succeeds and
its verified state is checked. The saved files are sensitive: they may permit
private-key recovery under the protocol's fixed-offset signing construction.

No network, Solana, key loading, or change to protocol state occurs here.
Files are stored OUTSIDE git at ~/tdsc-attack-lab/nsp/ (private 0700/0600).
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import secrets
import stat
from pathlib import Path


def _b64(value: bytes, name: str, length: int | None = None) -> str:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be raw bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must be {length} bytes")
    return base64.urlsafe_b64encode(value).decode("ascii")


def _private_dir(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Refusing symlink directory: {path}")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise RuntimeError(f"Refusing insecure directory (needs 0700): {path}")


def _write(phase: str, observation: dict) -> Path:
    home = Path.home()
    root = home / "tdsc-attack-lab"
    _private_dir(root)
    dest = root / "nsp"
    _private_dir(dest)
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = dest / f"{phase}_{timestamp}_{secrets.token_hex(5)}.json"
    content = (json.dumps(observation, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return output


def record_phase2(*, eid_smd: str, rt_smd: bytes, t_smd: int, h1_smd: bytes,
                  pk_smd_raw: bytes, a_smd_raw: bytes) -> Path:
    if not isinstance(eid_smd, str) or not eid_smd:
        raise ValueError("eid_smd must be nonempty text")
    if type(t_smd) is not int or t_smd < 0:
        raise ValueError("t_smd must be a nonnegative integer")
    record = {
        "schema": "tdsc-nsp-observation-v1", "phase": "phase2",
        "verification": "PASS", "source_model": "NSP-decrypted, verified H1",
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "eid_smd": eid_smd,
        "pk_smd_sec1": _b64(pk_smd_raw, "PK_SMD"),
        "a_smd_sec1": _b64(a_smd_raw, "A_SMD"),
        "rt_smd": _b64(rt_smd, "RT_SMD", 32),
        "t_smd": t_smd,
        "h1_smd": _b64(h1_smd, "H1_SMD", 32),
    }
    return _write("phase2", record)


def record_phase3(*, eid_smd: str, id_nsp: str, rid_smd: bytes, r_smd: bytes,
                  st_smd: bytes, v1_smd: bytes, pk_smd_raw: bytes,
                  a_smd_raw: bytes) -> Path:
    if not isinstance(eid_smd, str) or not eid_smd:
        raise ValueError("eid_smd must be nonempty text")
    if not isinstance(id_nsp, str) or not id_nsp:
        raise ValueError("id_nsp must be nonempty text")
    record = {
        "schema": "tdsc-nsp-observation-v1", "phase": "phase3",
        "verification": "PASS", "source_model": "NSP-decrypted, verified V1",
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "eid_smd": eid_smd, "id_nsp": id_nsp,
        "pk_smd_sec1": _b64(pk_smd_raw, "PK_SMD"),
        "a_smd_sec1": _b64(a_smd_raw, "A_SMD"),
        "rid_smd": _b64(rid_smd, "RID_SMD", 32),
        "r_smd": _b64(r_smd, "r_SMD", 32),
        "st_smd": _b64(st_smd, "ST_SMD", 32),
        "v1_smd": _b64(v1_smd, "V1_SMD", 32),
    }
    return _write("phase3", record)
