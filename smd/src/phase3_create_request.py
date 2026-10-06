from pathlib import Path
import base64
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parents[2]

REG_STATE_PATH = ROOT / "smd/data/registration_state.json"
SERIAL_PATH = ROOT / "smd/data/sn_smd.txt"
SK_SMD_PATH = ROOT / "smd/data/sk_smd.pem"

PENDING_PATH = ROOT / "smd/data/phase3_pending.json"
OUT_PATH = ROOT / "smd/export/phase3_request.json"


P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
    "BCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


def enc_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def h_fields(*fields: bytes) -> bytes:
    h = hashlib.sha256()

    for field in fields:
        h.update(enc_field(field))

    return h.digest()


def hash_to_scalar(*fields: bytes) -> int:
    return int.from_bytes(
        h_fields(*fields),
        "big",
    ) % P256_ORDER


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
    sk_scalar = (
        sk_smd.private_numbers().private_value
    ).to_bytes(32, "big")

    return h_fields(
        sk_scalar,
        serial.encode("utf-8"),
        id_smd.encode("utf-8"),
    )


def decrypt_s_smd(
    s_smd_b64: str,
    storage_key: bytes,
) -> dict:
    package = base64.urlsafe_b64decode(
        s_smd_b64.encode("ascii")
    )

    if len(package) < 12 + 16:
        raise RuntimeError(
            "S_SMD package is too short"
        )

    nonce = package[:12]
    ciphertext = package[12:]

    raw = AESGCM(storage_key).decrypt(
        nonce,
        ciphertext,
        b"TDSC-S-SMD-v1",
    )

    return json.loads(
        raw.decode("utf-8")
    )


def encrypt_e_smd(
    dt_smd: bytes,
    r_smd: bytes,
    v1_smd: bytes,
) -> str:
    if len(dt_smd) != 32:
        raise RuntimeError(
            "DT_SMD must be 32 bytes"
        )

    payload = {
        "r_smd": base64.urlsafe_b64encode(
            r_smd
        ).decode("ascii"),

        "v1_smd": base64.urlsafe_b64encode(
            v1_smd
        ).decode("ascii"),
    }

    raw = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    nonce = os.urandom(12)

    ciphertext = AESGCM(dt_smd).encrypt(
        nonce,
        raw,
        b"TDSC-E-SMD-v1",
    )

    return base64.urlsafe_b64encode(
        nonce + ciphertext
    ).decode("ascii")


def main():
    if PENDING_PATH.exists():
        raise SystemExit(
            "ERROR: phase3_pending.json already exists. "
            "Nothing overwritten."
        )

    if OUT_PATH.exists():
        raise SystemExit(
            "ERROR: phase3_request.json already exists. "
            "Nothing overwritten."
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

    serial_file = SERIAL_PATH.read_text().strip()

    if not serial_file:
        raise RuntimeError(
            "SMD serial is empty"
        )

    if registration.get("serial") != serial_file:
        raise RuntimeError(
            "SMD serial mismatch"
        )

    id_smd = registration["id_smd"]
    id_nsp = registration["id_nsp"]

    sk_smd = load_sk_smd()

    storage_key = derive_smd_storage_key(
        sk_smd,
        serial_file,
        id_smd,
    )






    secret = decrypt_s_smd(
        registration["s_smd"],
        storage_key,
    )

    required = {
        "eid_smd",
        "rid_smd",
        "a_smd",
        "st_smd",
        "dt_smd",
    }

    missing = required - set(secret)

    if missing:
        raise RuntimeError(
            f"Missing S_SMD fields: {sorted(missing)}"
        )

    eid_smd = secret["eid_smd"]

    rid_smd = base64.urlsafe_b64decode(
        secret["rid_smd"].encode("ascii")
    )

    a_smd = base64.urlsafe_b64decode(
        secret["a_smd"].encode("ascii")
    )

    st_smd = base64.urlsafe_b64decode(
        secret["st_smd"].encode("ascii")
    )

    dt_smd = base64.urlsafe_b64decode(
        secret["dt_smd"].encode("ascii")
    )

    for name, value in (
        ("RID_SMD", rid_smd),
        ("a_SMD", a_smd),
        ("ST_SMD", st_smd),
        ("DT_SMD", dt_smd),
    ):
        if len(value) != 32:
            raise RuntimeError(
                f"{name} must be 32 bytes"
            )

    print("S_SMD decryption: OK")
    print("RID_SMD size:", len(rid_smd), "bytes")
    print("ST_SMD size:", len(st_smd), "bytes")
    print("DT_SMD size:", len(dt_smd), "bytes")






    r_smd = os.urandom(32)









    h_scalar = hash_to_scalar(
        rid_smd,
        eid_smd.encode("utf-8"),
        id_nsp.encode("utf-8"),
        r_smd,
        st_smd,
    )

    sk_scalar = (
        sk_smd.private_numbers().private_value
    )

    a_scalar = int.from_bytes(
        a_smd,
        "big",
    )

    if not (
        1 <= a_scalar < P256_ORDER
    ):
        raise RuntimeError(
            "Invalid a_SMD scalar"
        )

    v1_scalar = (
        h_scalar * sk_scalar
        + a_scalar
    ) % P256_ORDER

    if v1_scalar == 0:
        raise RuntimeError(
            "Rare zero V1_SMD scalar; regenerate session"
        )

    v1_smd = v1_scalar.to_bytes(
        32,
        "big",
    )










    e_smd = encrypt_e_smd(
        dt_smd,
        r_smd,
        v1_smd,
    )

    request = {
        "rid_smd": base64.urlsafe_b64encode(
            rid_smd
        ).decode("ascii"),

        "e_smd": e_smd,
    }

    OUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUT_PATH.write_text(
        json.dumps(
            request,
            indent=2,
        ) + "\n"
    )

    OUT_PATH.chmod(0o600)

    pending = {
        "eid_smd": eid_smd,
        "id_nsp": id_nsp,

        "rid_smd": request["rid_smd"],

        "r_smd": base64.urlsafe_b64encode(
            r_smd
        ).decode("ascii"),

        "st_smd": secret["st_smd"],
        "dt_smd": secret["dt_smd"],

        "v1_smd": base64.urlsafe_b64encode(
            v1_smd
        ).decode("ascii"),

        "e_smd_sha256": hashlib.sha256(
            e_smd.encode("ascii")
        ).hexdigest(),

        "status": "WAITING_FOR_NSP_SESSION_RESPONSE",
    }

    PENDING_PATH.write_text(
        json.dumps(
            pending,
            indent=2,
        ) + "\n"
    )

    PENDING_PATH.chmod(0o600)

    print("r_SMD generated:", len(r_smd), "bytes")
    print("V1_SMD generated:", len(v1_smd), "bytes")
    print("E_SMD created: YES")
    print(
        "E_SMD encoded size:",
        len(e_smd),
        "characters"
    )
    print("Pending state:", PENDING_PATH)
    print("Request file:", OUT_PATH)
    print()
    print(
        "STATUS: PHASE 3 SESSION REQUEST READY FOR NSP"
    )


if __name__ == "__main__":
    main()
