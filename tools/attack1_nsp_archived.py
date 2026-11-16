#!/usr/bin/env python3
"""TDSC Attack 1: read-only NSP-insider proof from archived Phase 2 and 3.

Authorized research lab only. Reads NSP's own archived ciphertexts, its NSP
private key for normal protocol decryption, and the corresponding database row.
Does not read SMD private keys, write to disk, send network requests, or print
recovered private scalars. Depends on tools/inspect_archived_phase2_phase3.py.

This is an archived, offline, *NSP-side insider* proof, NOT live acceptance on
Solana and NOT an attack available to passive external eavesdroppers.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Existing read-only archived inspector already passed on this NSP.
from inspect_archived_phase2_phase3 import N, b64, h_fields, pt, verify


def require(ok: bool, label: str) -> None:
    if not ok:
        raise RuntimeError(label)
    print(f"[PASS] {label}")


def public_matches_scalar(x: int, point: tuple[int, int]) -> bool:
    if not 1 <= x < N:
        return False
    public = ec.derive_private_key(x, ec.SECP256R1()).public_key()
    return pt(public) == point


def run(root: Path) -> int:
    required = (
        "nsp/data/sk_nsp.pem",
        "nsp/data/phase2_verified_request.json",
        "nsp/import/phase2_C1_SMD.json",
        "nsp/import/phase3_request.json",
        "nsp/data/nsp.db",
        "nsp/config/node.conf",
    )
    missing = [p for p in required if not (root / p).is_file()]
    if missing:
        raise RuntimeError("Required NSP inputs missing: " + ", ".join(missing))

    # Legitimate NSP-only decryption: this is NOT the SMD long-term key.
    sk_nsp = serialization.load_pem_private_key(
        (root / "nsp/data/sk_nsp.pem").read_bytes(), password=None
    )
    require(
        isinstance(sk_nsp, ec.EllipticCurvePrivateKey)
        and sk_nsp.curve.name == "secp256r1",
        "NSP authentication key available for authorized local decryption",
    )

    state = json.loads((root / "nsp/data/phase2_verified_request.json").read_text())
    c1 = json.loads((root / "nsp/import/phase2_C1_SMD.json").read_text())
    package = b64(c1["c1_smd"])
    if len(package) < 61:
        raise RuntimeError("Invalid C1 package length")
    ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), package[:33]
    )
    c1_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"TDSC-AENC-C1-v1",
    ).derive(sk_nsp.exchange(ec.ECDH(), ephemeral))
    p2 = json.loads(
        AESGCM(c1_key).decrypt(
            package[33:45], package[45:], b"TDSC-C1-SMD-NSP-v1"
        ).decode("utf-8")
    )
    require(
        state.get("status") == "SMD_REQUEST_VERIFIED"
        and p2["eid_smd"] == state["eid_smd"]
        and p2["rt_smd"] == state["rt_smd"]
        and int(p2["t_smd"]) == int(state["t_smd"]),
        "Registration ciphertext matches archived verified state",
    )

    pk_raw = b64(state["pk_smd_sec1"])
    a_raw = b64(state["A_smd_sec1"])
    pk = pt(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_raw))
    a_pub = pt(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), a_raw))
    rt = b64(p2["rt_smd"])
    h1 = b64(p2["h1_smd"])
    e0 = int.from_bytes(
        h_fields(p2["eid_smd"].encode("utf-8"), rt,
                 str(int(p2["t_smd"])).encode("ascii")), "big"
    ) % N
    require(len(rt) == 32 and verify(h1, e0.to_bytes(32, "big"), pk, a_pub),
            "Archived H1 is mathematically valid")

    request = json.loads((root / "nsp/import/phase3_request.json").read_text())
    rid = b64(request["rid_smd"])
    require(len(rid) == 32, "Session RID has expected size")
    db_uri = f'file:{(root / "nsp/data/nsp.db").resolve().as_posix()}?mode=ro&immutable=1'
    with sqlite3.connect(db_uri, uri=True) as conn:
        row = conn.execute(
            "SELECT s_nsp FROM smd_records WHERE rid_smd = ? LIMIT 1",
            (request["rid_smd"],),
        ).fetchone()
    require(row is not None, "NSP archive contains session RID")

    sk_nsp_scalar = sk_nsp.private_numbers().private_value.to_bytes(32, "big")
    storage_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"TDSC-NSP-SENC-v1",
    ).derive(sk_nsp_scalar)
    s_nsp = bytes(row[0])
    if len(s_nsp) < 28:
        raise RuntimeError("Invalid S_NSP package length")
    secret = json.loads(
        AESGCM(storage_key).decrypt(
            s_nsp[:12], s_nsp[12:], b"TDSC-S-NSP-v1"
        ).decode("utf-8")
    )
    require(secret["eid_smd"] == p2["eid_smd"],
            "Session and registration belong to the same SMD")

    dt_smd = h_fields(rid, b64(secret["r_nsp"]))
    pkg3 = b64(request["e_smd"])
    if len(pkg3) < 28:
        raise RuntimeError("Invalid E_SMD package length")
    p3 = json.loads(
        AESGCM(dt_smd).decrypt(
            pkg3[:12], pkg3[12:], b"TDSC-E-SMD-v1"
        ).decode("utf-8")
    )
    node_conf = (root / "nsp/config/node.conf").read_text().splitlines()
    node = dict(
        line.strip().split("=", 1) for line in node_conf
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    )
    st_smd = h_fields(secret["eid_smd"].encode("utf-8"), sk_nsp_scalar)
    r_smd, v1 = b64(p3["r_smd"]), b64(p3["v1_smd"])
    e1 = int.from_bytes(
        h_fields(rid, secret["eid_smd"].encode("utf-8"),
                 node["ID_NSP"].encode("utf-8"), r_smd, st_smd), "big"
    ) % N
    require(len(r_smd) == 32 and verify(v1, e1.to_bytes(32, "big"), pk, a_pub),
            "Archived V1 is mathematically valid")

    delta_e = (e0 - e1) % N
    require(delta_e != 0, "Distinct challenges permit modular inverse")
    token0, token1 = int.from_bytes(h1, "big"), int.from_bytes(v1, "big")

    # Core experiment: derive SMD private scalar from only two NSP-visible
    # signed scalars and their message-dependent hash challenges.
    sk_candidate = ((token0 - token1) * pow(delta_e, -1, N)) % N
    a_candidate = (token0 - e0 * sk_candidate) % N
    sk_ok = public_matches_scalar(sk_candidate, pk)
    a_ok = public_matches_scalar(a_candidate, a_pub)
    equations_ok = (
        (e0 * sk_candidate + a_candidate) % N == token0
        and (e1 * sk_candidate + a_candidate) % N == token1
    )
    require(sk_ok and a_ok and equations_ok,
            "ATTACK 1: derived SMD private scalar and fixed commitment verified")

    # Emit evidence that is safe to paste into chat or include in public README.
    print("\nRESULT: ATTACK 1 PASS — real archived NSP observations")
    print("Threat model: semi-trusted NSP insider (not an external passive observer)")
    print("Evidence: derived key agrees with archived SMD public key and A_SMD")
    print("SMD private key file accessed: NO")
    print("Recovered scalars printed or saved: NO")
    print("Network, Solana, protocol state or database modified: NO")
    print("Current revocation status / live acceptance proven: NO (offline archive)")
    print("Public-key SHA-256 fingerprint:", hashlib.sha256(pk_raw).hexdigest()[:20])
    return 0


def main() -> int:
    argp = argparse.ArgumentParser(description=__doc__)
    argp.add_argument("--root", type=Path, default=Path.cwd(),
                      help="Project root (default current working directory)")
    args = argp.parse_args()
    return run(args.root.resolve())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Suppress exception detail: avoids leaking archive paths/values.
        print(f"[FAIL] Archive-based Attack 1 stopped ({type(exc).__name__})", file=sys.stderr)
        raise SystemExit(2)
