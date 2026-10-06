from pathlib import Path
import base64
import hashlib
import json
import os
import sqlite3
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROOT = Path(__file__).resolve().parents[2]

STATE_PATH = ROOT / "nsp/data/phase3_verified_request.json"
SK_NSP_PATH = ROOT / "nsp/data/sk_nsp.pem"
DB_PATH = ROOT / "nsp/data/nsp.db"

PENDING_PATH = ROOT / "nsp/data/phase3_response_pending.json"
OUT_PATH = ROOT / "nsp/export/phase3_response.json"


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


def senc_json(key: bytes, payload: dict, aad: bytes) -> str:
    if len(key) != 32:
        raise RuntimeError("Symmetric key must be 32 bytes")

    nonce = os.urandom(12)

    raw = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    ciphertext = AESGCM(key).encrypt(
        nonce,
        raw,
        aad,
    )

    return base64.urlsafe_b64encode(
        nonce + ciphertext
    ).decode("ascii")


def main():
    for p in (PENDING_PATH, OUT_PATH):
        if p.exists():
            raise SystemExit(
                f"ERROR: {p.name} already exists. Nothing overwritten."
            )

    state = json.loads(
        STATE_PATH.read_text()
    )

    if state.get("status") != "PHASE3_SMD_AUTHENTICATED":
        raise RuntimeError(
            "Phase 3 verified request is not ready"
        )

    eid_smd = state["eid_smd"]
    id_nsp = state["id_nsp"]

    old_rid = base64.urlsafe_b64decode(
        state["rid_smd"].encode("ascii")
    )

    r_smd = base64.urlsafe_b64decode(
        state["r_smd"].encode("ascii")
    )

    pc_smd = base64.urlsafe_b64decode(
        state["pc_smd"].encode("ascii")
    )

    hpr_smd = base64.urlsafe_b64decode(
        state["hpr_smd"].encode("ascii")
    )

    st_smd = base64.urlsafe_b64decode(
        state["st_smd"].encode("ascii")
    )

    dt_smd = base64.urlsafe_b64decode(
        state["dt_smd"].encode("ascii")
    )

    for name, value in (
        ("old RID_SMD", old_rid),
        ("r_SMD", r_smd),
        ("PC_SMD", pc_smd),
        ("HPR_SMD", hpr_smd),
        ("ST_SMD", st_smd),
        ("DT_SMD", dt_smd),
    ):
        if len(value) != 32:
            raise RuntimeError(
                f"{name} must be 32 bytes"
            )






    rid_new = os.urandom(32)
    r_nsp_new = os.urandom(32)






    sk_session = h_fields(
        eid_smd.encode("utf-8"),
        r_nsp_new,
        r_smd,
        hpr_smd,
        st_smd,
        dt_smd,
    )

    if len(sk_session) != 32:
        raise RuntimeError(
            "Session key must be 32 bytes"
        )







    sk_nsp = load_sk_nsp()

    s_nsp_new = create_s_nsp(
        sk_nsp,
        eid_smd,
        r_nsp_new,
        pc_smd,
        hpr_smd,
    )

    rid_new_text = base64.urlsafe_b64encode(
        rid_new
    ).decode("ascii")

    old_rid_text = state["rid_smd"]








    conn = sqlite3.connect(DB_PATH)

    try:
        old_row = conn.execute(
            """
            SELECT 1
            FROM smd_records
            WHERE rid_smd = ?
            """,
            (old_rid_text,),
        ).fetchone()

        if old_row is None:
            raise RuntimeError(
                "Old RID_SMD record unexpectedly missing"
            )

        new_row = conn.execute(
            """
            SELECT 1
            FROM smd_records
            WHERE rid_smd = ?
            """,
            (rid_new_text,),
        ).fetchone()

        if new_row is not None:
            raise RuntimeError(
                "Rare RID_new collision in NSP database"
            )

        conn.execute(
            """
            INSERT INTO smd_records (rid_smd, s_nsp)
            VALUES (?, ?)
            """,
            (
                rid_new_text,
                sqlite3.Binary(s_nsp_new),
            ),
        )

        conn.commit()

        count = conn.execute(
            """
            SELECT COUNT(*)
            FROM smd_records
            WHERE rid_smd IN (?, ?)
            """,
            (
                old_rid_text,
                rid_new_text,
            ),
        ).fetchone()[0]

        if count != 2:
            raise RuntimeError(
                "Old/new RID database state verification failed"
            )

    finally:
        conn.close()






    e1_nsp = senc_json(
        dt_smd,
        {
            "pc_smd": base64.urlsafe_b64encode(
                pc_smd
            ).decode("ascii"),

            "r_nsp_new": base64.urlsafe_b64encode(
                r_nsp_new
            ).decode("ascii"),
        },
        b"TDSC-E1-NSP-v1",
    )






    e2_nsp = senc_json(
        sk_session,
        {
            "rid_new": rid_new_text,
        },
        b"TDSC-E2-NSP-v1",
    )






    v_nsp = h_fields(
        eid_smd.encode("utf-8"),
        id_nsp.encode("utf-8"),
        sk_session,
        rid_new,
        pc_smd,
    )

    response = {
        "e1_nsp": e1_nsp,
        "e2_nsp": e2_nsp,
        "v_nsp": base64.urlsafe_b64encode(
            v_nsp
        ).decode("ascii"),
    }

    OUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUT_PATH.write_text(
        json.dumps(
            response,
            indent=2,
        ) + "\n"
    )

    OUT_PATH.chmod(0o600)

    pending = {
        "eid_smd": eid_smd,
        "id_nsp": id_nsp,

        "old_rid_smd": old_rid_text,
        "rid_new": rid_new_text,

        "r_smd": state["r_smd"],

        "r_nsp_new": base64.urlsafe_b64encode(
            r_nsp_new
        ).decode("ascii"),

        "pc_smd": state["pc_smd"],
        "hpr_smd": state["hpr_smd"],
        "st_smd": state["st_smd"],
        "dt_smd": state["dt_smd"],

        "session_key": base64.urlsafe_b64encode(
            sk_session
        ).decode("ascii"),

        "session_key_sha256": hashlib.sha256(
            sk_session
        ).hexdigest(),

        "v_nsp": response["v_nsp"],

        "status": "WAITING_FOR_SMD_V2",
    }

    PENDING_PATH.write_text(
        json.dumps(
            pending,
            indent=2,
        ) + "\n"
    )

    PENDING_PATH.chmod(0o600)

    print("=== Phase 3 NSP Session Response ===")
    print("RID_new generated:", len(rid_new), "bytes")
    print("r_NSP_new generated:", len(r_nsp_new), "bytes")
    print("SK_NSP generated:", len(sk_session), "bytes")
    print(
        "SK_NSP SHA256:",
        pending["session_key_sha256"]
    )
    print("S_NSP_new created: YES")
    print("Old RID kept in DB: YES")
    print("New RID added to DB: YES")
    print("E1_NSP created: YES")
    print("E2_NSP created: YES")
    print("V_NSP created:", len(v_nsp), "bytes")
    print("Pending state:", PENDING_PATH)
    print("Response file:", OUT_PATH)
    print()
    print(
        "STATUS: PHASE 3 NSP SESSION RESPONSE READY FOR SMD"
    )


if __name__ == "__main__":
    main()
