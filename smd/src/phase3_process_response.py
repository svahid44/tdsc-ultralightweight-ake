from pathlib import Path
import base64
import hashlib
import hmac
import json
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parents[2]

INPUT_PATH = ROOT / "smd/import/phase3_response.json"
PENDING_PATH = ROOT / "smd/data/phase3_pending.json"
REG_STATE_PATH = ROOT / "smd/data/registration_state.json"

SK_SMD_PATH = ROOT / "smd/data/sk_smd.pem"
PUF_SECRET_PATH = ROOT / "smd/data/puf_secret.key"
SERIAL_PATH = ROOT / "smd/data/sn_smd.txt"

RESULT_PATH = ROOT / "smd/data/phase3_session_pending_ack.json"
ACK_PATH = ROOT / "smd/export/phase3_ack.json"


def enc_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def h_fields(*fields: bytes) -> bytes:
    h = hashlib.sha256()

    for field in fields:
        h.update(enc_field(field))

    return h.digest()


def decrypt_json(
    package_b64: str,
    key: bytes,
    aad: bytes,
) -> dict:
    if len(key) != 32:
        raise RuntimeError(
            "Symmetric key must be 32 bytes"
        )

    package = base64.urlsafe_b64decode(
        package_b64.encode("ascii")
    )

    if len(package) < 28:
        raise RuntimeError(
            "Encrypted package is too short"
        )

    nonce = package[:12]
    ciphertext = package[12:]

    raw = AESGCM(key).decrypt(
        nonce,
        ciphertext,
        aad,
    )

    return json.loads(
        raw.decode("utf-8")
    )


def load_sk_smd():
    sk = serialization.load_pem_private_key(
        SK_SMD_PATH.read_bytes(),
        password=None,
    )

    if not isinstance(
        sk,
        ec.EllipticCurvePrivateKey,
    ):
        raise RuntimeError(
            "sk_SMD is not an ECC private key"
        )

    if sk.curve.name != "secp256r1":
        raise RuntimeError(
            "Unexpected sk_SMD curve"
        )

    return sk


def derive_smd_storage_key(
    sk_smd,
    serial: str,
    id_smd: str,
) -> bytes:
    scalar = (
        sk_smd.private_numbers().private_value
    ).to_bytes(32, "big")

    return h_fields(
        scalar,
        serial.encode("utf-8"),
        id_smd.encode("utf-8"),
    )


def encrypt_s_smd(
    storage_key: bytes,
    payload: dict,
) -> str:
    nonce = __import__("os").urandom(12)

    raw = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    ciphertext = AESGCM(storage_key).encrypt(
        nonce,
        raw,
        b"TDSC-S-SMD-v1",
    )

    return base64.urlsafe_b64encode(
        nonce + ciphertext
    ).decode("ascii")


def main():
    for p in (
        RESULT_PATH,
        ACK_PATH,
    ):
        if p.exists():
            raise SystemExit(
                f"ERROR: {p.name} already exists. Nothing overwritten."
            )

    incoming = json.loads(
        INPUT_PATH.read_text()
    )

    required_response = {
        "e1_nsp",
        "e2_nsp",
        "v_nsp",
    }

    missing = required_response - set(incoming)

    if missing:
        raise RuntimeError(
            f"Missing NSP response fields: {sorted(missing)}"
        )

    pending = json.loads(
        PENDING_PATH.read_text()
    )

    if pending.get(
        "status"
    ) != "WAITING_FOR_NSP_SESSION_RESPONSE":
        raise RuntimeError(
            "SMD is not waiting for NSP session response"
        )

    registration = json.loads(
        REG_STATE_PATH.read_text()
    )

    if registration.get(
        "status"
    ) != "REGISTRATION_MATERIAL_STORED":
        raise RuntimeError(
            "SMD registration state is not ready"
        )

    eid_smd = pending["eid_smd"]
    id_nsp = pending["id_nsp"]

    r_smd = base64.urlsafe_b64decode(
        pending["r_smd"].encode("ascii")
    )

    st_smd = base64.urlsafe_b64decode(
        pending["st_smd"].encode("ascii")
    )

    dt_smd = base64.urlsafe_b64decode(
        pending["dt_smd"].encode("ascii")
    )

    for name, value in (
        ("r_SMD", r_smd),
        ("ST_SMD", st_smd),
        ("DT_SMD", dt_smd),
    ):
        if len(value) != 32:
            raise RuntimeError(
                f"{name} must be 32 bytes"
            )






    e1_plain = decrypt_json(
        incoming["e1_nsp"],
        dt_smd,
        b"TDSC-E1-NSP-v1",
    )

    if not {
        "pc_smd",
        "r_nsp_new",
    }.issubset(e1_plain):
        raise RuntimeError(
            "E1_NSP fields missing"
        )

    pc_smd = base64.urlsafe_b64decode(
        e1_plain["pc_smd"].encode("ascii")
    )

    r_nsp_new = base64.urlsafe_b64decode(
        e1_plain["r_nsp_new"].encode("ascii")
    )

    if len(pc_smd) != 32:
        raise RuntimeError(
            "PC_SMD must be 32 bytes"
        )

    if len(r_nsp_new) != 32:
        raise RuntimeError(
            "r_NSP_new must be 32 bytes"
        )

    print("E1_NSP decryption: OK")
    print("PC_SMD size:", len(pc_smd), "bytes")
    print("r_NSP_new size:", len(r_nsp_new), "bytes")








    puf_secret = PUF_SECRET_PATH.read_bytes()

    if len(puf_secret) != 32:
        raise RuntimeError(
            "PUF simulation secret must be 32 bytes"
        )

    puf_response = hmac.new(
        puf_secret,
        pc_smd,
        hashlib.sha256,
    ).digest()

    hpr_smd = hashlib.sha256(
        puf_response
    ).digest()

    print("HPR_SMD recomputed: YES")







    sk_session = h_fields(
        eid_smd.encode("utf-8"),
        r_nsp_new,
        r_smd,
        hpr_smd,
        st_smd,
        dt_smd,
    )

    print("SK_SMD generated:", len(sk_session), "bytes")
    print(
        "SK_SMD SHA256:",
        hashlib.sha256(sk_session).hexdigest()
    )






    e2_plain = decrypt_json(
        incoming["e2_nsp"],
        sk_session,
        b"TDSC-E2-NSP-v1",
    )

    rid_new_text = e2_plain.get(
        "rid_new"
    )

    if not rid_new_text:
        raise RuntimeError(
            "RID_new missing from E2_NSP"
        )

    rid_new = base64.urlsafe_b64decode(
        rid_new_text.encode("ascii")
    )

    if len(rid_new) != 32:
        raise RuntimeError(
            "RID_new must be 32 bytes"
        )

    print("E2_NSP decryption: OK")
    print("RID_new size:", len(rid_new), "bytes")






    v_nsp = base64.urlsafe_b64decode(
        incoming["v_nsp"].encode("ascii")
    )

    if len(v_nsp) != 32:
        raise RuntimeError(
            "V_NSP must be 32 bytes"
        )

    expected_v = h_fields(
        eid_smd.encode("utf-8"),
        id_nsp.encode("utf-8"),
        sk_session,
        rid_new,
        pc_smd,
    )

    v_ok = hmac.compare_digest(
        expected_v,
        v_nsp,
    )

    print("V_NSP verification:", v_ok)

    if not v_ok:
        raise RuntimeError(
            "NSP session response authentication failed"
        )






    dt_new = h_fields(
        rid_new,
        r_nsp_new,
    )

    print("DT_new computed:", len(dt_new), "bytes")









    sk_smd = load_sk_smd()

    serial = SERIAL_PATH.read_text().strip()

    if not serial:
        raise RuntimeError(
            "SMD serial is empty"
        )

    if registration.get("serial") != serial:
        raise RuntimeError(
            "SMD serial mismatch"
        )

    storage_key = derive_smd_storage_key(
        sk_smd,
        serial,
        registration["id_smd"],
    )

    old_package = base64.urlsafe_b64decode(
        registration["s_smd"].encode("ascii")
    )

    old_raw = AESGCM(storage_key).decrypt(
        old_package[:12],
        old_package[12:],
        b"TDSC-S-SMD-v1",
    )

    old_secret = json.loads(
        old_raw.decode("utf-8")
    )

    a_smd_text = old_secret.get(
        "a_smd"
    )

    if not a_smd_text:
        raise RuntimeError(
            "a_SMD missing from old S_SMD"
        )

    a_smd = base64.urlsafe_b64decode(
        a_smd_text.encode("ascii")
    )

    if len(a_smd) != 32:
        raise RuntimeError(
            "a_SMD must be 32 bytes"
        )

    new_secret = {
        "eid_smd": eid_smd,
        "rid_smd": rid_new_text,
        "a_smd": a_smd_text,
        "st_smd": base64.urlsafe_b64encode(
            st_smd
        ).decode("ascii"),
        "dt_smd": base64.urlsafe_b64encode(
            dt_new
        ).decode("ascii"),
    }

    s_smd_new = encrypt_s_smd(
        storage_key,
        new_secret,
    )








    registration["s_smd"] = s_smd_new
    registration["status"] = "REGISTRATION_MATERIAL_STORED"

    REG_STATE_PATH.write_text(
        json.dumps(
            registration,
            indent=2,
        ) + "\n"
    )

    REG_STATE_PATH.chmod(0o600)

    print("S_SMD updated: YES")






    v2_smd = h_fields(
        eid_smd.encode("utf-8"),
        rid_new,
        sk_session,
    )

    ACK_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    ACK_PATH.write_text(
        json.dumps(
            {
                "v2_smd": base64.urlsafe_b64encode(
                    v2_smd
                ).decode("ascii")
            },
            indent=2,
        ) + "\n"
    )

    ACK_PATH.chmod(0o600)

    result = {
        "eid_smd": eid_smd,
        "id_nsp": id_nsp,

        "old_rid_smd": pending["rid_smd"],
        "rid_new": rid_new_text,

        "r_nsp_new": e1_plain["r_nsp_new"],

        "dt_new": base64.urlsafe_b64encode(
            dt_new
        ).decode("ascii"),

        "session_key": base64.urlsafe_b64encode(
            sk_session
        ).decode("ascii"),

        "session_key_sha256": hashlib.sha256(
            sk_session
        ).hexdigest(),

        "v2_smd": base64.urlsafe_b64encode(
            v2_smd
        ).decode("ascii"),

        "status": "WAITING_FOR_NSP_FINAL_ACK",
    }

    RESULT_PATH.write_text(
        json.dumps(
            result,
            indent=2,
        ) + "\n"
    )

    RESULT_PATH.chmod(0o600)

    print("V2_SMD created:", len(v2_smd), "bytes")
    print("Ack file:", ACK_PATH)
    print("Pending result:", RESULT_PATH)
    print()
    print(
        "STATUS: PHASE 3 SMD SESSION KEY ESTABLISHED; ACK READY"
    )


if __name__ == "__main__":
    main()
