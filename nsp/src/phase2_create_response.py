from pathlib import Path
import base64
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROOT = Path(__file__).resolve().parents[2]

VERIFIED_PATH = ROOT / "nsp/data/phase2_verified_request.json"
SK_NSP_PATH = ROOT / "nsp/data/sk_nsp.pem"

PENDING_PATH = ROOT / "nsp/data/phase2_response_pending.json"
OUT_PATH = ROOT / "nsp/export/phase2_C_NSP.json"


def enc_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def h_fields(*fields: bytes) -> bytes:
    h = hashlib.sha256()
    for field in fields:
        h.update(enc_field(field))
    return h.digest()


def encrypt_for_smd(pk_smd_sec1: bytes, plaintext: dict) -> str:
    pk_smd = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        pk_smd_sec1,
    )

    eph_sk = ec.generate_private_key(
        ec.SECP256R1()
    )

    shared_secret = eph_sk.exchange(
        ec.ECDH(),
        pk_smd,
    )

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"TDSC-AENC-CNSP-v1",
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
        b"TDSC-CNSP-NSP-SMD-v1",
    )

    eph_pub = eph_sk.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )

    package = eph_pub + nonce + ciphertext

    return base64.urlsafe_b64encode(
        package
    ).decode("ascii")


def main():
    if PENDING_PATH.exists():
        raise SystemExit(
            "ERROR: phase2_response_pending.json already exists. "
            "Nothing overwritten."
        )

    if OUT_PATH.exists():
        raise SystemExit(
            "ERROR: phase2_C_NSP.json already exists. "
            "Nothing overwritten."
        )

    verified = json.loads(
        VERIFIED_PATH.read_text()
    )

    if verified.get("status") != "SMD_REQUEST_VERIFIED":
        raise RuntimeError(
            "SMD request has not been verified"
        )

    eid_smd = verified["eid_smd"]

    rt_smd = base64.urlsafe_b64decode(
        verified["rt_smd"].encode("ascii")
    )

    t_smd = int(
        verified["t_smd"]
    )

    pk_smd_sec1 = base64.urlsafe_b64decode(
        verified["pk_smd_sec1"].encode("ascii")
    )

    if len(pk_smd_sec1) != 33:
        raise RuntimeError(
            "Invalid PK_SMD compressed point"
        )

    sk_nsp = serialization.load_pem_private_key(
        SK_NSP_PATH.read_bytes(),
        password=None,
    )

    if not isinstance(
        sk_nsp,
        ec.EllipticCurvePrivateKey,
    ):
        raise RuntimeError(
            "sk_NSP is not an ECC private key"
        )

    if sk_nsp.curve.name != "secp256r1":
        raise RuntimeError(
            "Unexpected NSP curve"
        )

    sk_nsp_scalar = (
        sk_nsp.private_numbers().private_value
    ).to_bytes(32, "big")






    rid_smd = os.urandom(32)
    r_nsp = os.urandom(32)
    pc_smd = os.urandom(32)









    st_smd = h_fields(
        eid_smd.encode("utf-8"),
        sk_nsp_scalar,
    )






    dt_smd = h_fields(
        rid_smd,
        r_nsp,
    )







    h_nsp = h_fields(
        st_smd,
        dt_smd,
        rid_smd,
        pc_smd,
        rt_smd,
        str(t_smd).encode("ascii"),
    )

    plaintext = {
        "st_smd": base64.urlsafe_b64encode(
            st_smd
        ).decode("ascii"),

        "dt_smd": base64.urlsafe_b64encode(
            dt_smd
        ).decode("ascii"),

        "rid_smd": base64.urlsafe_b64encode(
            rid_smd
        ).decode("ascii"),

        "pc_smd": base64.urlsafe_b64encode(
            pc_smd
        ).decode("ascii"),

        "h_nsp": base64.urlsafe_b64encode(
            h_nsp
        ).decode("ascii"),
    }











    c_nsp = encrypt_for_smd(
        pk_smd_sec1,
        plaintext,
    )


    pending = {
        "eid_smd": eid_smd,

        "rt_smd": base64.urlsafe_b64encode(
            rt_smd
        ).decode("ascii"),

        "t_smd": t_smd,

        "rid_smd": plaintext["rid_smd"],

        "r_nsp": base64.urlsafe_b64encode(
            r_nsp
        ).decode("ascii"),

        "pc_smd": plaintext["pc_smd"],

        "st_smd": plaintext["st_smd"],

        "dt_smd": plaintext["dt_smd"],

        "h_nsp": plaintext["h_nsp"],

        "c_nsp_sha256": hashlib.sha256(
            c_nsp.encode("ascii")
        ).hexdigest(),

        "status": "WAITING_FOR_SMD_HPR",
    }

    PENDING_PATH.write_text(
        json.dumps(
            pending,
            indent=2,
        ) + "\n"
    )
    PENDING_PATH.chmod(0o600)


    OUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUT_PATH.write_text(
        json.dumps(
            {"c_nsp": c_nsp},
            indent=2,
        ) + "\n"
    )
    OUT_PATH.chmod(0o600)

    print("=== Phase 2 NSP Registration Response ===")
    print("RID_SMD generated:", len(rid_smd), "bytes")
    print("r_NSP generated:", len(r_nsp), "bytes")
    print("PC_SMD generated:", len(pc_smd), "bytes")
    print("ST_SMD size:", len(st_smd), "bytes")
    print("DT_SMD size:", len(dt_smd), "bytes")
    print("H_NSP size:", len(h_nsp), "bytes")
    print("C_NSP created: YES")
    print(
        "C_NSP encoded size:",
        len(c_nsp),
        "characters"
    )
    print("Pending state:", PENDING_PATH)
    print("Response file:", OUT_PATH)
    print()
    print(
        "STATUS: PHASE 2 C_NSP RESPONSE READY FOR SMD"
    )


if __name__ == "__main__":
    main()
