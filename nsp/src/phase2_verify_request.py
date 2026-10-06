from pathlib import Path
import asyncio
import base64
import hashlib
import json
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey


ROOT = Path(__file__).resolve().parents[2]

REQUEST_PATH = ROOT / "nsp/import/phase2_C1_SMD.json"
SK_NSP_PATH = ROOT / "nsp/data/sk_nsp.pem"
STATE_PATH = ROOT / "nsp/data/phase2_verified_request.json"

RPC = "https://api.devnet.solana.com"

PROGRAM_ID = Pubkey.from_string(
    "CiQyDY4MurDQJbHGZnLvVnP6BfdxKG9Fmu1GB2gPKrGQ"
)

MAX_AGE_SECONDS = 3600
MAX_FUTURE_SKEW_SECONDS = 60

P256_P = int(
    "FFFFFFFF000000010000000000000000"
    "00000000FFFFFFFFFFFFFFFFFFFFFFFF",
    16,
)

P256_A = (P256_P - 3) % P256_P

P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
    "BCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


def encode_hash_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def protocol_hash_to_scalar(eid_smd, rt_smd, t_smd):
    payload = (
        encode_hash_field(eid_smd.encode())
        + encode_hash_field(rt_smd)
        + encode_hash_field(str(t_smd).encode())
    )
    digest = hashlib.sha256(payload).digest()
    return int.from_bytes(digest, "big") % P256_ORDER


def inv_mod(x):
    return pow(x % P256_P, P256_P - 2, P256_P)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None

    if p1 == p2:
        if y1 == 0:
            return None
        slope = (
            (3 * x1 * x1 + P256_A)
            * inv_mod(2 * y1)
        ) % P256_P
    else:
        slope = (
            (y2 - y1)
            * inv_mod(x2 - x1)
        ) % P256_P

    x3 = (slope * slope - x1 - x2) % P256_P
    y3 = (slope * (x1 - x3) - y1) % P256_P
    return x3, y3


def scalar_mult(k, point):
    k %= P256_ORDER
    if k == 0 or point is None:
        return None

    result = None
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def account_discriminator(name):
    return hashlib.sha256(
        f"account:{name}".encode()
    ).digest()[:8]


def read_u32(raw, offset):
    value = struct.unpack_from("<I", raw, offset)[0]
    return value, offset + 4


def decode_smd_record(raw):
    if raw[:8] != account_discriminator("SmdRecord"):
        raise RuntimeError("SmdRecord discriminator mismatch")

    offset = 8
    eid_hash = raw[offset:offset + 32]
    offset += 32

    eid_len, offset = read_u32(raw, offset)
    eid_smd = raw[offset:offset + eid_len].decode()
    offset += eid_len

    pk_len, offset = read_u32(raw, offset)
    pk_smd = raw[offset:offset + pk_len]
    offset += pk_len

    a_len, offset = read_u32(raw, offset)
    a_smd = raw[offset:offset + a_len]
    offset += a_len

    rs_smd = raw[offset]

    return {
        "eid_hash": eid_hash,
        "eid_smd": eid_smd,
        "pk_smd": pk_smd,
        "a_smd": a_smd,
        "rs_smd": rs_smd,
    }


def decrypt_c1(c1_smd):
    package = base64.urlsafe_b64decode(c1_smd.encode())

    if len(package) < 61:
        raise RuntimeError("C1_SMD package too short")

    ephemeral_raw = package[:33]
    nonce = package[33:45]
    ciphertext = package[45:]

    ephemeral_public = (
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            ephemeral_raw,
        )
    )

    sk_nsp = serialization.load_pem_private_key(
        SK_NSP_PATH.read_bytes(),
        password=None,
    )

    if not isinstance(sk_nsp, ec.EllipticCurvePrivateKey):
        raise RuntimeError("sk_NSP is not ECC")

    shared_secret = sk_nsp.exchange(
        ec.ECDH(),
        ephemeral_public,
    )

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"TDSC-AENC-C1-v1",
    ).derive(shared_secret)

    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        b"TDSC-C1-SMD-NSP-v1",
    )

    return json.loads(plaintext.decode())


def verify_h1(
    eid_smd,
    rt_smd,
    t_smd,
    h1_bytes,
    pk_smd_raw,
    a_smd_raw,
):
    if len(h1_bytes) != 32:
        raise RuntimeError("Invalid H1_SMD size")

    h1_scalar = int.from_bytes(h1_bytes, "big")

    if not (1 <= h1_scalar < P256_ORDER):
        raise RuntimeError("Invalid H1_SMD scalar")

    h_scalar = protocol_hash_to_scalar(
        eid_smd,
        rt_smd,
        t_smd,
    )

    pk_obj = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        pk_smd_raw,
    )

    a_obj = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        a_smd_raw,
    )

    pk_n = pk_obj.public_numbers()
    a_n = a_obj.public_numbers()

    pk_point = (pk_n.x, pk_n.y)
    a_point = (a_n.x, a_n.y)

    lhs_obj = ec.derive_private_key(
        h1_scalar,
        ec.SECP256R1(),
    ).public_key()

    lhs_n = lhs_obj.public_numbers()
    lhs = (lhs_n.x, lhs_n.y)

    rhs = point_add(
        scalar_mult(h_scalar, pk_point),
        a_point,
    )

    return lhs == rhs


async def main():
    request = json.loads(REQUEST_PATH.read_text())

    c1_smd = request.get("c1_smd")
    if not c1_smd:
        raise RuntimeError("C1_SMD missing")

    print("C1_SMD received: YES")

    plaintext = decrypt_c1(c1_smd)

    required = {"eid_smd", "rt_smd", "h1_smd", "t_smd"}
    missing = required - set(plaintext)
    if missing:
        raise RuntimeError(f"Missing fields: {sorted(missing)}")

    eid_smd = plaintext["eid_smd"]

    rt_smd = base64.urlsafe_b64decode(
        plaintext["rt_smd"].encode()
    )

    h1_smd = base64.urlsafe_b64decode(
        plaintext["h1_smd"].encode()
    )

    t_smd = int(plaintext["t_smd"])

    print("C1_SMD decryption: OK")
    print("RT_SMD size:", len(rt_smd), "bytes")
    print("H1_SMD size:", len(h1_smd), "bytes")
    print("t_SMD:", t_smd)

    if len(rt_smd) != 32:
        raise RuntimeError("Invalid RT_SMD size")

    if len(h1_smd) != 32:
        raise RuntimeError("Invalid H1_SMD size")

    now = int(time.time())
    age = now - t_smd

    print("Current Unix time:", now)
    print("Request age:", age, "seconds")

    if age < -MAX_FUTURE_SKEW_SECONDS:
        raise RuntimeError("t_SMD is too far in future")

    if age > MAX_AGE_SECONDS:
        raise RuntimeError("C1_SMD rejected: stale timestamp")

    print("Timestamp freshness: PASS")

    eid_hash = hashlib.sha256(
        eid_smd.encode()
    ).digest()

    smd_pda, _ = Pubkey.find_program_address(
        [b"smd", eid_hash],
        PROGRAM_ID,
    )

    async with AsyncClient(RPC) as client:
        response = await client.get_account_info(smd_pda)

    if response.value is None:
        raise RuntimeError("EID_SMD not found on Solana")

    if response.value.owner != PROGRAM_ID:
        raise RuntimeError("Unexpected blockchain owner")

    onchain = decode_smd_record(response.value.data)

    print("SMD PDA:", smd_pda)
    print("Blockchain record: FOUND")

    if onchain["eid_hash"] != eid_hash:
        raise RuntimeError("EID hash mismatch")

    if onchain["eid_smd"] != eid_smd:
        raise RuntimeError("EID_SMD mismatch")

    print("EID_SMD on-chain match: True")
    print("RS_SMD:", onchain["rs_smd"])

    if onchain["rs_smd"] != 0:
        raise RuntimeError("SMD is revoked")

    print("Revocation check: PASS")

    h1_ok = verify_h1(
        eid_smd,
        rt_smd,
        t_smd,
        h1_smd,
        onchain["pk_smd"],
        onchain["a_smd"],
    )

    print("H1 authentication equation:", h1_ok)

    if not h1_ok:
        raise RuntimeError("SMD authentication failed")

    state = {
        "eid_smd": eid_smd,
        "rt_smd": plaintext["rt_smd"],
        "t_smd": t_smd,
        "smd_pda": str(smd_pda),
        "pk_smd_sec1": base64.urlsafe_b64encode(
            onchain["pk_smd"]
        ).decode(),
        "A_smd_sec1": base64.urlsafe_b64encode(
            onchain["a_smd"]
        ).decode(),
        "rs_smd": onchain["rs_smd"],
        "status": "SMD_REQUEST_VERIFIED",
    }

    if STATE_PATH.exists():
        existing = json.loads(STATE_PATH.read_text())
        if existing != state:
            raise RuntimeError(
                "Existing verified state differs; nothing overwritten"
            )
    else:
        STATE_PATH.write_text(
            json.dumps(state, indent=2) + "\n"
        )
        STATE_PATH.chmod(0o600)

    print("State:", STATE_PATH)
    print()
    print(
        "STATUS: PHASE 2 SMD REQUEST AUTHENTICATED BY NSP"
    )


asyncio.run(main())
