#!/usr/bin/env python3
"""Offline key-recovery lab for two *NSP-verified* TDSC observations.

No network access, no NSP/SMD private-key reads, no modification of protocol
state. Only place records produced by an explicitly authorized test observer
under ignored runtime directories; never commit plaintext observations.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
CURVE = ec.SECP256R1()
MAX_RECORD_BYTES = 128 * 1024
PHASES = {"1": ("phase2", "phase3"), "2": ("phase2", "phase2"), "3": ("phase3", "phase3")}


class ObservationError(Exception):
    pass


def b64dec(value: str, name: str, expected_len: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ObservationError(f"{name} must be Base64 text")
    try:
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ObservationError(f"Invalid Base64 in {name}") from exc
    if expected_len is not None and len(result) != expected_len:
        raise ObservationError(f"Invalid length for {name}: expected {expected_len} bytes")
    return result


def b64enc(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def hash_to_scalar(*fields: bytes) -> int:
    h = hashlib.sha256()
    for field in fields:
        h.update(struct.pack(">I", len(field)))
        h.update(field)
    return int.from_bytes(h.digest(), "big") % N


def public_of_scalar(value: int) -> bytes:
    if not (1 <= value < N):
        raise ObservationError("Derived scalar outside valid P-256 range")
    return ec.derive_private_key(value, CURVE).public_key().public_bytes(
        Encoding.X962, PublicFormat.CompressedPoint
    )


def normalize_public(b64_text: str, name: str) -> bytes:
    raw = b64dec(b64_text, name)
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, raw)
    except (ValueError, TypeError) as exc:
        raise ObservationError(f"Invalid P-256 public point: {name}") from exc
    return pub.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def parse_observation(d: dict) -> dict:
    if not isinstance(d, dict) or d.get("schema") != "tdsc-nsp-observation-v1":
        raise ObservationError("Unrecognized observation schema")
    phase = d.get("phase")
    if phase not in ("phase2", "phase3"):
        raise ObservationError("Unknown phase")
    if d.get("verification") != "PASS":
        raise ObservationError("Only successful NSP-verification records are admissible")
    eid = d.get("eid_smd")
    if not isinstance(eid, str) or not eid:
        raise ObservationError("eid_smd missing")
    pk = normalize_public(d.get("pk_smd_sec1"), "pk_smd_sec1")
    a_pub = normalize_public(d.get("a_smd_sec1"), "a_smd_sec1")
    if phase == "phase2":
        timestamp = d.get("t_smd")
        if type(timestamp) is not int or timestamp < 0:
            raise ObservationError("t_smd must be a nonnegative Unix timestamp")
        rt = b64dec(d.get("rt_smd"), "rt_smd", 32)
        e = hash_to_scalar(eid.encode("utf-8"), rt, str(timestamp).encode("ascii"))
        y = int.from_bytes(b64dec(d.get("h1_smd"), "h1_smd", 32), "big")
    else:
        rid = b64dec(d.get("rid_smd"), "rid_smd", 32)
        r_smd = b64dec(d.get("r_smd"), "r_smd", 32)
        st = b64dec(d.get("st_smd"), "st_smd", 32)
        id_nsp = d.get("id_nsp")
        if not isinstance(id_nsp, str) or not id_nsp:
            raise ObservationError("id_nsp missing")
        e = hash_to_scalar(rid, eid.encode("utf-8"), id_nsp.encode("utf-8"), r_smd, st)
        y = int.from_bytes(b64dec(d.get("v1_smd"), "v1_smd", 32), "big")
    if not (1 <= y < N):
        raise ObservationError("Invalid token scalar")
    return {"phase": phase, "eid": eid, "pk": pk, "a_pub": a_pub, "e": e, "y": y}


def recover(first: dict, second: dict, attack: str) -> tuple[dict, dict]:
    left = parse_observation(first)
    right = parse_observation(second)
    if (left["phase"], right["phase"]) != PHASES[attack]:
        raise ObservationError(f"Wrong phase pair for attack {attack}: expected {PHASES[attack]}")
    if (left["eid"], left["pk"], left["a_pub"]) != (
        right["eid"], right["pk"], right["a_pub"]
    ):
        raise ObservationError("Observations refer to different SMD identities/public commitments")
    de = (left["e"] - right["e"]) % N
    if de == 0:
        raise ObservationError("Equal hash challenges; two independent equations required")
    sk = ((left["y"] - right["y"]) * pow(de, -1, N)) % N
    a = (left["y"] - left["e"] * sk) % N
    key_matches = (1 <= sk < N and public_of_scalar(sk) == left["pk"])
    commitment_matches = (1 <= a < N and public_of_scalar(a) == left["a_pub"])
    valid = key_matches and commitment_matches
    report = {
        "schema": "tdsc-key-recovery-report-v1",
        "attack": int(attack),
        "result": "PASS" if valid else "FAIL",
        "public_key_fingerprint_sha256": hashlib.sha256(left["pk"]).hexdigest(),
        "key_matches_public_key": key_matches,
        "nonce_matches_public_commitment": commitment_matches,
        "source_model": "NSP-accessible decrypted observations; not passive network eavesdropping",
        "note": "PASS proves algebraic recovery from supplied verified-looking observations; provenance must be documented separately.",
    }
    private = {"sk_smd_hex": f"{sk:064x}", "a_smd_hex": f"{a:064x}"} if valid else {}
    return report, private


def read_record(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ObservationError(f"Not a regular observation file: {path}")
    if path.stat().st_size > MAX_RECORD_BYTES:
        raise ObservationError("Observation file too large")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ObservationError(f"Invalid JSON: {path}") from exc


def write_exclusive(path: Path, data: dict) -> None:
    payload = (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(payload)


def demo_observation(phase: str, sk: int, a: int, eid: str, pk: bytes, a_pub: bytes) -> dict:
    shared = {
        "schema": "tdsc-nsp-observation-v1", "phase": phase, "verification": "PASS",
        "eid_smd": eid, "pk_smd_sec1": b64enc(pk), "a_smd_sec1": b64enc(a_pub)
    }
    if phase == "phase2":
        rt = secrets.token_bytes(32)
        ts = 1790000000 + secrets.randbelow(100000)
        e = hash_to_scalar(eid.encode(), rt, str(ts).encode())
        shared.update(rt_smd=b64enc(rt), t_smd=ts, h1_smd=b64enc(((e * sk + a) % N).to_bytes(32, "big")))
    else:
        rid, r, st = (secrets.token_bytes(32) for _ in range(3))
        nsp = "NSP-001"
        e = hash_to_scalar(rid, eid.encode(), nsp.encode(), r, st)
        shared.update(rid_smd=b64enc(rid), r_smd=b64enc(r), st_smd=b64enc(st), id_nsp=nsp,
                      v1_smd=b64enc(((e * sk + a) % N).to_bytes(32, "big")))
    return shared


def run_self_test() -> None:
    sk = secrets.randbelow(N - 1) + 1
    a = secrets.randbelow(N - 1) + 1
    pk, a_pub = public_of_scalar(sk), public_of_scalar(a)
    eid = "TEST-ONLY"
    records = {
        "p2a": demo_observation("phase2", sk, a, eid, pk, a_pub),
        "p2b": demo_observation("phase2", sk, a, eid, pk, a_pub),
        "p3a": demo_observation("phase3", sk, a, eid, pk, a_pub),
        "p3b": demo_observation("phase3", sk, a, eid, pk, a_pub),
    }
    for attack, names in [("1", ("p2a", "p3a")), ("2", ("p2a", "p2b")), ("3", ("p3a", "p3b"))]:
        report, private = recover(records[names[0]], records[names[1]], attack)
        assert report["result"] == "PASS" and int(private["sk_smd_hex"], 16) == sk
        print(f"[PASS] Synthetic Attack {attack}: key recovery and public-key validation")
    bad = records["p3b"].copy()
    tampered = (int.from_bytes(b64dec(bad["v1_smd"], "v1_smd"), "big") + 1) % N
    bad["v1_smd"] = b64enc(tampered.to_bytes(32, "big"))
    # A malformed/tampered observation must not pass a complete public-key check.
    report, _ = recover(records["p3a"], bad, "3")
    assert report["result"] == "FAIL"
    print("[PASS] Tampered token is not accepted as recovered key")
    print("SELF-TEST PASSED — synthetic only, NOT a live protocol attack")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true", help="Run in-memory synthetic tests; no files or NSP")
    ap.add_argument("--attack", choices=["1", "2", "3"])
    ap.add_argument("--first", type=Path)
    ap.add_argument("--second", type=Path)
    ap.add_argument("--report", type=Path, help="Save non-secret result as a new JSON file")
    ap.add_argument("--private-output", type=Path, help="Write recovered secret to new 0600 file; never commit")
    args = ap.parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if not args.attack or not args.first or not args.second:
        ap.error("Provide --attack, --first and --second (or --self-test)")
    result, private = recover(read_record(args.first), read_record(args.second), args.attack)
    if args.report:
        write_exclusive(args.report, result)
    if args.private_output:
        if result["result"] != "PASS":
            raise ObservationError("Refusing private-output: recovery did not validate")
        if "data" not in args.private_output.parts:
            raise ObservationError("Write private output only under an ignored .../data/ directory")
        write_exclusive(args.private_output, private)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["result"] == "PASS" else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ObservationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
