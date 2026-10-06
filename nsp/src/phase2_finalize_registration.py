from pathlib import Path
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROOT = Path(__file__).resolve().parents[2]

INPUT_PATH = ROOT / "nsp/import/phase2_C2_SMD.json"
PENDING_PATH = ROOT / "nsp/data/phase2_response_pending.json"
SK_NSP_PATH = ROOT / "nsp/data/sk_nsp.pem"
DB_PATH = ROOT / "nsp/data/nsp.db"
RESULT_PATH = ROOT / "nsp/data/phase2_registration_complete.json"


def enc_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def h_fields(*fields: bytes) -> bytes:
    h = hashlib.sha256()
    for field in fields:
        h.update(enc_field(field))
    return h.digest()


def load_sk_nsp():
    sk = serialization.load_pem_private_key(
        SK_NSP_PATH.read_bytes(),
        password=None,
    )

    if not isinstance(sk, ec.EllipticCurvePrivateKey):
        raise RuntimeError("sk_NSP is not an ECC private key")

    if sk.curve.name != "secp256r1":
        raise RuntimeError("Unexpected sk_NSP curve")

    return sk


def decrypt_c2(c2_smd: str, sk_nsp):
    package = base64.urlsafe_b64decode(
        c2_smd.encode("ascii")
    )

    if len(package) < 61:
        raise RuntimeError("C2_SMD package is too short")

    eph_raw = package[:33]
    nonce = package[33:45]
    ciphertext = package[45:]

    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        eph_raw,
    )

    shared_secret = sk_nsp.exchange(
        ec.ECDH(),
        eph_pub,
    )

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"TDSC-AENC-C2-v1",
    ).derive(shared_secret)

    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        b"TDSC-C2-SMD-NSP-v1",
    )

    return json.loads(
        plaintext.decode("utf-8")
    )


def derive_nsp_storage_key(sk_nsp) -> bytes:
    scalar = (
        sk_nsp.private_numbers().private_value
    ).to_bytes(32, "big")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"TDSC-NSP-SENC-v1",
    ).derive(scalar)


def create_s_nsp(
    sk_nsp,
    eid_smd: str,
    r_nsp: bytes,
    pc_smd: bytes,
    hpr_smd: bytes,
) -> bytes:
    storage_key = derive_nsp_storage_key(sk_nsp)

    payload = {
        "eid_smd": eid_smd,
        "r_nsp": base64.urlsafe_b64encode(
            r_nsp
        ).decode("ascii"),
        "pc_smd": base64.urlsafe_b64encode(
            pc_smd
        ).decode("ascii"),
        "hpr_smd": base64.urlsafe_b64encode(
            hpr_smd
        ).decode("ascii"),
    }

    raw = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    nonce = os.urandom(12)

    ciphertext = AESGCM(storage_key).encrypt(
        nonce,
        raw,
        b"TDSC-S-NSP-v1",
    )

    return nonce + ciphertext


def store_record(rid_smd_text: str, s_nsp: bytes):
    conn = sqlite3.connect(DB_PATH)

    try:
        row = conn.execute(
            "SELECT s_nsp FROM smd_records WHERE rid_smd = ?",
            (rid_smd_text,),
        ).fetchone()

        if row is not None:
            if bytes(row[0]) == s_nsp:
                print("Database record already matches.")
                return "ALREADY_PRESENT"

            raise RuntimeError(
                "RID_SMD already exists with different S_NSP"
            )

        conn.execute(
            """
            INSERT INTO smd_records (rid_smd, s_nsp)
            VALUES (?, ?)
            """,
            (
                rid_smd_text,
                sqlite3.Binary(s_nsp),
            ),
        )

        conn.commit()

        verify = conn.execute(
            "SELECT s_nsp FROM smd_records WHERE rid_smd = ?",
            (rid_smd_text,),
        ).fetchone()

        if verify is None:
            raise RuntimeError(
                "Database insert verification failed"
            )

        if bytes(verify[0]) != s_nsp:
            raise RuntimeError(
                "Stored S_NSP does not match"
            )

        return "INSERTED"

    finally:
        conn.close()


def main():
    if RESULT_PATH.exists():
        existing = json.loads(
            RESULT_PATH.read_text()
        )

        if existing.get("status") == "PHASE2_COMPLETED":
            print("STATUS: PHASE 2 ALREADY COMPLETED")
            return

        raise RuntimeError(
            "Existing Phase 2 result has unexpected state"
        )

    pending = json.loads(
        PENDING_PATH.read_text()
    )

    if pending.get("status") != "WAITING_FOR_SMD_HPR":
        raise RuntimeError(
            "NSP is not waiting for SMD final response"
        )

    incoming = json.loads(
        INPUT_PATH.read_text()
    )

    c2_smd = incoming.get("c2_smd")

    if not c2_smd:
        raise RuntimeError("C2_SMD missing")

    sk_nsp = load_sk_nsp()

    plain = decrypt_c2(
        c2_smd,
        sk_nsp,
    )

    required = {
        "hpr_smd",
        "h2_smd",
    }

    missing = required - set(plain)

    if missing:
        raise RuntimeError(
            f"Missing C2 fields: {sorted(missing)}"
        )

    hpr_smd = base64.urlsafe_b64decode(
        plain["hpr_smd"].encode("ascii")
    )

    h2_smd = base64.urlsafe_b64decode(
        plain["h2_smd"].encode("ascii")
    )

    if len(hpr_smd) != 32:
        raise RuntimeError(
            "HPR_SMD must be 32 bytes"
        )

    if len(h2_smd) != 32:
        raise RuntimeError(
            "H2_SMD must be 32 bytes"
        )

    print("C2_SMD decryption: OK")
    print("HPR_SMD size:", len(hpr_smd), "bytes")
    print("H2_SMD size:", len(h2_smd), "bytes")

    st_smd = base64.urlsafe_b64decode(
        pending["st_smd"].encode("ascii")
    )

    dt_smd = base64.urlsafe_b64decode(
        pending["dt_smd"].encode("ascii")
    )

    rid_smd = base64.urlsafe_b64decode(
        pending["rid_smd"].encode("ascii")
    )

    r_nsp = base64.urlsafe_b64decode(
        pending["r_nsp"].encode("ascii")
    )

    pc_smd = base64.urlsafe_b64decode(
        pending["pc_smd"].encode("ascii")
    )

    t_smd = int(
        pending["t_smd"]
    )

    for name, value in (
        ("ST_SMD", st_smd),
        ("DT_SMD", dt_smd),
        ("RID_SMD", rid_smd),
        ("r_NSP", r_nsp),
        ("PC_SMD", pc_smd),
    ):
        if len(value) != 32:
            raise RuntimeError(
                f"{name} must be 32 bytes"
            )

    expected_h2 = h_fields(
        hpr_smd,
        st_smd,
        dt_smd,
        rid_smd,
        pc_smd,
        str(t_smd).encode("ascii"),
    )

    h2_ok = hmac.compare_digest(
        expected_h2,
        h2_smd,
    )

    print("H2_SMD verification:", h2_ok)

    if not h2_ok:
        raise RuntimeError(
            "H2_SMD verification failed"
        )

    s_nsp = create_s_nsp(
        sk_nsp,
        pending["eid_smd"],
        r_nsp,
        pc_smd,
        hpr_smd,
    )

    print("S_NSP created: YES")
    print("S_NSP size:", len(s_nsp), "bytes")

    rid_text = pending["rid_smd"]

    db_result = store_record(
        rid_text,
        s_nsp,
    )

    print("Database result:", db_result)

    result = {
        "eid_smd": pending["eid_smd"],
        "rid_smd": rid_text,
        "s_nsp_sha256": hashlib.sha256(
            s_nsp
        ).hexdigest(),
        "database": str(DB_PATH),
        "status": "PHASE2_COMPLETED",
    }

    RESULT_PATH.write_text(
        json.dumps(
            result,
            indent=2,
        ) + "\n"
    )
    RESULT_PATH.chmod(0o600)

    pending["status"] = "REGISTRATION_COMPLETED"

    PENDING_PATH.write_text(
        json.dumps(
            pending,
            indent=2,
        ) + "\n"
    )
    PENDING_PATH.chmod(0o600)

    print("Result:", RESULT_PATH)
    print()
    print(
        "STATUS: PHASE 2 REGISTRATION COMPLETED"
    )


if __name__ == "__main__":
    main()
