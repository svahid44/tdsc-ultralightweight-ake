from pathlib import Path
import base64
import json
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROOT = Path(__file__).resolve().parents[2]
PRIVATE_KEY_PATH = ROOT / "nsp/data/sk_nsp.pem"


def _load_private_key():
    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=None,
    )


def _derive_symmetric_key() -> bytes:
    private_key = _load_private_key()

    private_value = private_key.private_numbers().private_value
    private_bytes = private_value.to_bytes(32, "big")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"TDSC-NSP-SENC-v1",
    ).derive(private_bytes)


def create_s_nsp(
    eid_smd: str,
    r_nsp: bytes,
    pc_smd: bytes,
    hpr_smd: bytes,
) -> bytes:

    payload = {
        "eid_smd": eid_smd,
        "r_nsp": base64.b64encode(r_nsp).decode("ascii"),
        "pc_smd": base64.b64encode(pc_smd).decode("ascii"),
        "hpr_smd": base64.b64encode(hpr_smd).decode("ascii"),
    }

    plaintext = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode("utf-8")

    key = _derive_symmetric_key()
    nonce = secrets.token_bytes(12)

    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext,
        None,
    )

    return nonce + ciphertext


def recover_s_nsp(s_nsp: bytes):
    if len(s_nsp) < 13:
        raise ValueError("Invalid S_NSP")

    nonce = s_nsp[:12]
    ciphertext = s_nsp[12:]

    key = _derive_symmetric_key()

    plaintext = AESGCM(key).decrypt(
        nonce,
        ciphertext,
        None,
    )

    payload = json.loads(plaintext.decode("utf-8"))

    return {
        "eid_smd": payload["eid_smd"],
        "r_nsp": base64.b64decode(payload["r_nsp"]),
        "pc_smd": base64.b64decode(payload["pc_smd"]),
        "hpr_smd": base64.b64decode(payload["hpr_smd"]),
    }
