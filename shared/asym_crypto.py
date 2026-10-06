import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


CURVE = ec.SECP256R1()

INFO_C1 = b"TDSC-AENC-C1-v1"
AAD_C1 = b"TDSC-C1-SMD-NSP-v1"


def _derive_key(shared_secret: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def encrypt_for_nsp(pk_nsp_pem: str, plaintext: dict) -> str:
    pk_nsp = serialization.load_pem_public_key(
        pk_nsp_pem.encode("ascii")
    )

    if not isinstance(pk_nsp, ec.EllipticCurvePublicKey):
        raise RuntimeError("PK_NSP is not an ECC key")

    if pk_nsp.curve.name != "secp256r1":
        raise RuntimeError(
            f"Unexpected curve: {pk_nsp.curve.name}"
        )


    ephemeral_sk = ec.generate_private_key(CURVE)

    shared_secret = ephemeral_sk.exchange(
        ec.ECDH(),
        pk_nsp,
    )

    aes_key = _derive_key(
        shared_secret,
        INFO_C1,
    )

    nonce = os.urandom(12)

    raw_plaintext = json.dumps(
        plaintext,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        raw_plaintext,
        AAD_C1,
    )

    ephemeral_public = (
        ephemeral_sk.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
    )

    if len(ephemeral_public) != 33:
        raise RuntimeError(
            "Unexpected ephemeral public key size"
        )





    package = (
        ephemeral_public
        + nonce
        + ciphertext
    )

    return base64.urlsafe_b64encode(
        package
    ).decode("ascii")
