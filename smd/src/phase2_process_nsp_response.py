from pathlib import Path
import base64
import hashlib
import hmac
import json
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROOT = Path(__file__).resolve().parents[2]

INPUT_PATH = ROOT / "smd/import/phase2_C_NSP.json"

PHASE1_PATH = ROOT / "smd/data/phase1_state.json"
PHASE2_PENDING_PATH = ROOT / "smd/data/phase2_pending.json"

SK_SMD_PATH = ROOT / "smd/data/sk_smd.pem"
A_SMD_PATH = ROOT / "smd/data/a_smd.key"

PUF_SECRET_PATH = ROOT / "smd/data/puf_secret.key"
SERIAL_PATH = ROOT / "smd/data/sn_smd.txt"

REG_STATE_PATH = ROOT / "smd/data/registration_state.json"
C2_PENDING_PATH = ROOT / "smd/data/phase2_c2_pending.json"
OUT_PATH = ROOT / "smd/export/phase2_C2_SMD.json"


def enc_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def h_fields(*fields: bytes) -> bytes:
    h = hashlib.sha256()
    for field in fields:
        h.update(enc_field(field))
    return h.digest()


def decrypt_c_nsp(c_nsp: str, sk_smd):
    package = base64.urlsafe_b64decode(
        c_nsp.encode("ascii")
    )

    if len(package) < 61:
        raise RuntimeError(
            "C_NSP package is too short"
        )

    eph_raw = package[:33]
    nonce = package[33:45]
    ciphertext = package[45:]

    eph_pub = (
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            eph_raw,
        )
    )

    shared_secret = sk_smd.exchange(
        ec.ECDH(),
        eph_pub,
    )

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"TDSC-AENC-CNSP-v1",
    ).derive(shared_secret)

    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        b"TDSC-CNSP-NSP-SMD-v1",
    )

    return json.loads(
        plaintext.decode("utf-8")
    )


def encrypt_c2(pk_nsp_pem: str, plaintext: dict) -> str:
    pk_nsp = serialization.load_pem_public_key(
        pk_nsp_pem.encode("ascii")
    )

    if not isinstance(
        pk_nsp,
        ec.EllipticCurvePublicKey,
    ):
        raise RuntimeError(
            "PK_NSP is not an ECC public key"
        )

    if pk_nsp.curve.name != "secp256r1":
        raise RuntimeError(
            "Unexpected PK_NSP curve"
        )

    eph_sk = ec.generate_private_key(
        ec.SECP256R1()
    )

    shared_secret = eph_sk.exchange(
        ec.ECDH(),
        pk_nsp,
    )

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"TDSC-AENC-C2-v1",
    ).derive(shared_secret)

    nonce = os.urandom(12)

    raw_plaintext = json.dumps(
        plaintext,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        raw_plaintext,
        b"TDSC-C2-SMD-NSP-v1",
    )

    eph_pub = eph_sk.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )

    package = eph_pub + nonce + ciphertext

    return base64.urlsafe_b64encode(
        package
    ).decode("ascii")


def get_or_create_puf_secret():
    if PUF_SECRET_PATH.exists():
        secret = PUF_SECRET_PATH.read_bytes()

        if len(secret) != 32:
            raise RuntimeError(
                "Existing PUF simulation secret has invalid size"
            )

        return secret, False

    secret = os.urandom(32)

    PUF_SECRET_PATH.write_bytes(secret)
    PUF_SECRET_PATH.chmod(0o600)

    return secret, True


def get_or_create_serial():
    if SERIAL_PATH.exists():
        serial = SERIAL_PATH.read_text().strip()

        if not serial:
            raise RuntimeError(
                "Existing SMD serial is empty"
            )

        return serial, False

    serial = "SMD-SN-" + os.urandom(8).hex()

    SERIAL_PATH.write_text(
        serial + "\n"
    )
    SERIAL_PATH.chmod(0o600)

    return serial, True


def encrypt_s_smd(
    storage_key: bytes,
    payload: dict,
) -> str:
    nonce = os.urandom(12)

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
        REG_STATE_PATH,
        C2_PENDING_PATH,
        OUT_PATH,
    ):
        if p.exists():
            raise SystemExit(
                f"ERROR: {p.name} already exists. "
                "Nothing overwritten."
            )

    phase1 = json.loads(
        PHASE1_PATH.read_text()
    )

    if phase1.get("status") != "PHASE1_COMPLETED":
        raise RuntimeError(
            "Phase 1 state is not complete"
        )

    pending = json.loads(
        PHASE2_PENDING_PATH.read_text()
    )

    if pending.get("status") != "WAITING_FOR_NSP_RESPONSE":
        raise RuntimeError(
            "SMD is not waiting for NSP response"
        )

    incoming = json.loads(
        INPUT_PATH.read_text()
    )

    c_nsp = incoming.get("c_nsp")

    if not c_nsp:
        raise RuntimeError(
            "C_NSP missing"
        )

    sk_smd = serialization.load_pem_private_key(
        SK_SMD_PATH.read_bytes(),
        password=None,
    )

    if not isinstance(
        sk_smd,
        ec.EllipticCurvePrivateKey,
    ):
        raise RuntimeError(
            "sk_SMD is not an ECC private key"
        )

    if sk_smd.curve.name != "secp256r1":
        raise RuntimeError(
            "Unexpected sk_SMD curve"
        )






    plain = decrypt_c_nsp(
        c_nsp,
        sk_smd,
    )

    required = {
        "st_smd",
        "dt_smd",
        "rid_smd",
        "pc_smd",
        "h_nsp",
    }

    missing = required - set(plain)

    if missing:
        raise RuntimeError(
            f"Missing C_NSP fields: {sorted(missing)}"
        )

    st_smd = base64.urlsafe_b64decode(
        plain["st_smd"].encode("ascii")
    )

    dt_smd = base64.urlsafe_b64decode(
        plain["dt_smd"].encode("ascii")
    )

    rid_smd = base64.urlsafe_b64decode(
        plain["rid_smd"].encode("ascii")
    )

    pc_smd = base64.urlsafe_b64decode(
        plain["pc_smd"].encode("ascii")
    )

    h_nsp = base64.urlsafe_b64decode(
        plain["h_nsp"].encode("ascii")
    )

    for name, value in (
        ("ST_SMD", st_smd),
        ("DT_SMD", dt_smd),
        ("RID_SMD", rid_smd),
        ("PC_SMD", pc_smd),
        ("H_NSP", h_nsp),
    ):
        if len(value) != 32:
            raise RuntimeError(
                f"{name} must be 32 bytes"
            )

    rt_smd = base64.urlsafe_b64decode(
        pending["rt_smd"].encode("ascii")
    )

    t_smd = int(
        pending["t_smd"]
    )






    expected_h_nsp = h_fields(
        st_smd,
        dt_smd,
        rid_smd,
        pc_smd,
        rt_smd,
        str(t_smd).encode("ascii"),
    )

    h_ok = hmac.compare_digest(
        expected_h_nsp,
        h_nsp,
    )

    print("C_NSP decryption: OK")
    print("H_NSP verification:", h_ok)

    if not h_ok:
        raise RuntimeError(
            "H_NSP verification failed"
        )











    puf_secret, puf_created = (
        get_or_create_puf_secret()
    )

    puf_response = hmac.new(
        puf_secret,
        pc_smd,
        hashlib.sha256,
    ).digest()

    hpr_smd = hashlib.sha256(
        puf_response
    ).digest()











    serial, serial_created = (
        get_or_create_serial()
    )

    id_smd = phase1["id_smd"]

    sk_scalar = (
        sk_smd.private_numbers().private_value
    ).to_bytes(32, "big")

    storage_key = h_fields(
        sk_scalar,
        serial.encode("utf-8"),
        id_smd.encode("utf-8"),
    )

    a_smd = A_SMD_PATH.read_bytes()

    if len(a_smd) != 32:
        raise RuntimeError(
            "a_SMD must be 32 bytes"
        )

    s_payload = {
        "eid_smd": phase1["eid_smd"],

        "rid_smd": base64.urlsafe_b64encode(
            rid_smd
        ).decode("ascii"),

        "a_smd": base64.urlsafe_b64encode(
            a_smd
        ).decode("ascii"),

        "st_smd": plain["st_smd"],
        "dt_smd": plain["dt_smd"],
    }

    s_smd = encrypt_s_smd(
        storage_key,
        s_payload,
    )






    registration_state = {
        "id_smd": id_smd,
        "id_nsp": phase1["id_nsp"],
        "pk_nsp_pem": phase1["pk_nsp_pem"],
        "pk_nsp_sha256": phase1[
            "pk_nsp_sha256"
        ],
        "s_smd": s_smd,
        "puf_mode": "SIMULATED_HMAC_SHA256",
        "serial": serial,
        "status": "REGISTRATION_MATERIAL_STORED",
    }

    REG_STATE_PATH.write_text(
        json.dumps(
            registration_state,
            indent=2,
        ) + "\n"
    )
    REG_STATE_PATH.chmod(0o600)






    h2_smd = h_fields(
        hpr_smd,
        st_smd,
        dt_smd,
        rid_smd,
        pc_smd,
        str(t_smd).encode("ascii"),
    )






    c2_plain = {
        "hpr_smd": base64.urlsafe_b64encode(
            hpr_smd
        ).decode("ascii"),

        "h2_smd": base64.urlsafe_b64encode(
            h2_smd
        ).decode("ascii"),
    }

    c2_smd = encrypt_c2(
        phase1["pk_nsp_pem"],
        c2_plain,
    )

    c2_pending = {
        "rid_smd": plain["rid_smd"],
        "pc_smd": plain["pc_smd"],
        "st_smd": plain["st_smd"],
        "dt_smd": plain["dt_smd"],
        "hpr_smd": c2_plain["hpr_smd"],
        "h2_smd": c2_plain["h2_smd"],
        "t_smd": t_smd,
        "c2_sha256": hashlib.sha256(
            c2_smd.encode("ascii")
        ).hexdigest(),
        "status": "WAITING_FOR_NSP_FINALIZATION",
    }

    C2_PENDING_PATH.write_text(
        json.dumps(
            c2_pending,
            indent=2,
        ) + "\n"
    )
    C2_PENDING_PATH.chmod(0o600)

    OUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUT_PATH.write_text(
        json.dumps(
            {"c2_smd": c2_smd},
            indent=2,
        ) + "\n"
    )
    OUT_PATH.chmod(0o600)

    print("PUF simulation secret created:", puf_created)
    print("SMD serial created:", serial_created)
    print("HPR_SMD size:", len(hpr_smd), "bytes")
    print("S_SMD stored: YES")
    print("H2_SMD size:", len(h2_smd), "bytes")
    print("C2_SMD created: YES")
    print(
        "C2_SMD encoded size:",
        len(c2_smd),
        "characters"
    )
    print("Registration state:", REG_STATE_PATH)
    print("C2 pending state:", C2_PENDING_PATH)
    print("Output:", OUT_PATH)
    print()
    print(
        "STATUS: PHASE 2 C2_SMD FINAL RESPONSE READY FOR NSP"
    )


if __name__ == "__main__":
    main()
