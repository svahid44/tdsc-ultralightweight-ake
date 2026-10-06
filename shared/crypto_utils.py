import base64
import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def create_eid_smd(sk_tuc: bytes, id_smd: str) -> str:
    if len(sk_tuc) != 32:
        raise ValueError("sk_TUC must be 32 bytes")


    a_tuc = secrets.token_bytes(32)

    plaintext = json.dumps(
        {
            "a_tuc": base64.b64encode(a_tuc).decode("ascii"),
            "id_smd": id_smd,
        },
        separators=(",", ":"),
    ).encode("utf-8")


    nonce = secrets.token_bytes(12)

    aes = AESGCM(sk_tuc)
    ciphertext = aes.encrypt(nonce, plaintext, None)


    eid = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    return eid


def recover_id_smd(sk_tuc: bytes, eid_smd: str) -> str:
    if len(sk_tuc) != 32:
        raise ValueError("sk_TUC must be 32 bytes")

    raw = base64.urlsafe_b64decode(eid_smd.encode("ascii"))

    nonce = raw[:12]
    ciphertext = raw[12:]

    aes = AESGCM(sk_tuc)
    plaintext = aes.decrypt(nonce, ciphertext, None)

    data = json.loads(plaintext.decode("utf-8"))

    return data["id_smd"]
