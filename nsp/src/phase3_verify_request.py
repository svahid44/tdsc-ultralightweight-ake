from pathlib import Path
import asyncio
import base64
import hashlib
import json
import sqlite3
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey


ROOT = Path(__file__).resolve().parents[2]

REQUEST_PATH = ROOT / "nsp/import/phase3_request.json"
SK_NSP_PATH = ROOT / "nsp/data/sk_nsp.pem"
DB_PATH = ROOT / "nsp/data/nsp.db"
NODE_CONF_PATH = ROOT / "nsp/config/node.conf"
STATE_PATH = ROOT / "nsp/data/phase3_verified_request.json"

RPC = "https://api.devnet.solana.com"

PROGRAM_ID = Pubkey.from_string(
    "CiQyDY4MurDQJbHGZnLvVnP6BfdxKG9Fmu1GB2gPKrGQ"
)


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


def load_config(path: Path):
    result = {}

    for line in path.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        key, value = line.split("=", 1)
        result[key] = value

    return result


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


def inv_mod(x):
    return pow(
        x % P256_P,
        P256_P - 2,
        P256_P,
    )


def point_add(p1, p2):
    if p1 is None:
        return p2

    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if (
        x1 == x2
        and (y1 + y2) % P256_P == 0
    ):
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

    x3 = (
        slope * slope
        - x1
        - x2
    ) % P256_P

    y3 = (
        slope * (x1 - x3)
        - y1
    ) % P256_P

    return x3, y3


def scalar_mult(k, point):
    k %= P256_ORDER

    if k == 0 or point is None:
        return None

    result = None
    addend = point

    while k:
        if k & 1:
            result = point_add(
                result,
                addend,
            )

        addend = point_add(
            addend,
            addend,
        )

        k >>= 1

    return result


def account_discriminator(name: str) -> bytes:
    return hashlib.sha256(
        f"account:{name}".encode()
    ).digest()[:8]


def read_u32(raw: bytes, offset: int):
    value = struct.unpack_from(
        "<I",
        raw,
        offset,
    )[0]

    return value, offset + 4


def decode_smd_record(raw: bytes):
    expected = account_discriminator(
        "SmdRecord"
    )

    if raw[:8] != expected:
        raise RuntimeError(
            "SmdRecord discriminator mismatch"
        )

    offset = 8

    eid_hash = raw[offset:offset + 32]
    offset += 32

    eid_len, offset = read_u32(
        raw,
        offset,
    )

    eid_smd = raw[
        offset:offset + eid_len
    ].decode("utf-8")

    offset += eid_len

    pk_len, offset = read_u32(
        raw,
        offset,
    )

    pk_smd = raw[
        offset:offset + pk_len
    ]

    offset += pk_len

    a_len, offset = read_u32(
        raw,
        offset,
    )

    a_smd = raw[
        offset:offset + a_len
    ]

    offset += a_len

    rs_smd = raw[offset]

    return {
        "eid_hash": eid_hash,
        "eid_smd": eid_smd,
        "pk_smd": pk_smd,
        "a_smd": a_smd,
        "rs_smd": rs_smd,
    }


def load_sk_nsp():
    sk = serialization.load_pem_private_key(
        SK_NSP_PATH.read_bytes(),
        password=None,
    )

    if not isinstance(
        sk,
        ec.EllipticCurvePrivateKey,
    ):
        raise RuntimeError(
            "sk_NSP is not an ECC private key"
        )

    if sk.curve.name != "secp256r1":
        raise RuntimeError(
            "Unexpected sk_NSP curve"
        )

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


def decrypt_s_nsp(
    s_nsp: bytes,
    sk_nsp,
):
    if len(s_nsp) < 28:
        raise RuntimeError(
            "S_NSP package is too short"
        )

    storage_key = derive_nsp_storage_key(
        sk_nsp
    )

    nonce = s_nsp[:12]
    ciphertext = s_nsp[12:]

    raw = AESGCM(storage_key).decrypt(
        nonce,
        ciphertext,
        b"TDSC-S-NSP-v1",
    )

    return json.loads(
        raw.decode("utf-8")
    )


def decrypt_e_smd(
    e_smd_b64: str,
    dt_smd: bytes,
):
    if len(dt_smd) != 32:
        raise RuntimeError(
            "DT_SMD must be 32 bytes"
        )

    package = base64.urlsafe_b64decode(
        e_smd_b64.encode("ascii")
    )

    if len(package) < 28:
        raise RuntimeError(
            "E_SMD package is too short"
        )

    nonce = package[:12]
    ciphertext = package[12:]

    raw = AESGCM(dt_smd).decrypt(
        nonce,
        ciphertext,
        b"TDSC-E-SMD-v1",
    )

    return json.loads(
        raw.decode("utf-8")
    )


def verify_v1(
    rid_smd: bytes,
    eid_smd: str,
    id_nsp: str,
    r_smd: bytes,
    st_smd: bytes,
    v1_smd: bytes,
    pk_smd_raw: bytes,
    a_smd_raw: bytes,
):
    if len(v1_smd) != 32:
        raise RuntimeError(
            "V1_SMD must be 32 bytes"
        )

    v1_scalar = int.from_bytes(
        v1_smd,
        "big",
    )

    if not (
        1 <= v1_scalar < P256_ORDER
    ):
        raise RuntimeError(
            "Invalid V1_SMD scalar"
        )

    h_scalar = hash_to_scalar(
        rid_smd,
        eid_smd.encode("utf-8"),
        id_nsp.encode("utf-8"),
        r_smd,
        st_smd,
    )

    pk_obj = (
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            pk_smd_raw,
        )
    )

    a_obj = (
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            a_smd_raw,
        )
    )

    pk_num = pk_obj.public_numbers()
    a_num = a_obj.public_numbers()

    pk_point = (
        pk_num.x,
        pk_num.y,
    )

    a_point = (
        a_num.x,
        a_num.y,
    )

    lhs_obj = ec.derive_private_key(
        v1_scalar,
        ec.SECP256R1(),
    ).public_key()

    lhs_num = lhs_obj.public_numbers()

    lhs = (
        lhs_num.x,
        lhs_num.y,
    )

    rhs = point_add(
        scalar_mult(
            h_scalar,
            pk_point,
        ),
        a_point,
    )

    return lhs == rhs


async def main():
    request = json.loads(
        REQUEST_PATH.read_text()
    )

    required = {
        "rid_smd",
        "e_smd",
    }

    missing = required - set(request)

    if missing:
        raise RuntimeError(
            f"Missing request fields: {sorted(missing)}"
        )

    rid_smd = base64.urlsafe_b64decode(
        request["rid_smd"].encode("ascii")
    )

    if len(rid_smd) != 32:
        raise RuntimeError(
            "RID_SMD must be 32 bytes"
        )

    print("Phase 3 request received: YES")
    print("RID_SMD size:", len(rid_smd), "bytes")






    rid_text = request["rid_smd"]

    conn = sqlite3.connect(DB_PATH)

    try:
        row = conn.execute(
            """
            SELECT s_nsp
            FROM smd_records
            WHERE rid_smd = ?
            """,
            (rid_text,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise RuntimeError(
            "RID_SMD not found in NSP database"
        )

    s_nsp = bytes(row[0])

    print("NSP database record: FOUND")
    print("S_NSP size:", len(s_nsp), "bytes")

    sk_nsp = load_sk_nsp()






    secret = decrypt_s_nsp(
        s_nsp,
        sk_nsp,
    )

    needed = {
        "eid_smd",
        "r_nsp",
        "pc_smd",
        "hpr_smd",
    }

    missing = needed - set(secret)

    if missing:
        raise RuntimeError(
            f"Missing S_NSP fields: {sorted(missing)}"
        )

    eid_smd = secret["eid_smd"]

    r_nsp = base64.urlsafe_b64decode(
        secret["r_nsp"].encode("ascii")
    )

    pc_smd = base64.urlsafe_b64decode(
        secret["pc_smd"].encode("ascii")
    )

    hpr_smd = base64.urlsafe_b64decode(
        secret["hpr_smd"].encode("ascii")
    )

    for name, value in (
        ("r_NSP", r_nsp),
        ("PC_SMD", pc_smd),
        ("HPR_SMD", hpr_smd),
    ):
        if len(value) != 32:
            raise RuntimeError(
                f"{name} must be 32 bytes"
            )

    print("S_NSP decryption: OK")






    dt_smd = h_fields(
        rid_smd,
        r_nsp,
    )

    print("DT_SMD recomputed: YES")






    e_plain = decrypt_e_smd(
        request["e_smd"],
        dt_smd,
    )

    if not {
        "r_smd",
        "v1_smd",
    }.issubset(e_plain):
        raise RuntimeError(
            "E_SMD fields missing"
        )

    r_smd = base64.urlsafe_b64decode(
        e_plain["r_smd"].encode("ascii")
    )

    v1_smd = base64.urlsafe_b64decode(
        e_plain["v1_smd"].encode("ascii")
    )

    if len(r_smd) != 32:
        raise RuntimeError(
            "r_SMD must be 32 bytes"
        )

    if len(v1_smd) != 32:
        raise RuntimeError(
            "V1_SMD must be 32 bytes"
        )

    print("E_SMD decryption: OK")
    print("r_SMD size:", len(r_smd), "bytes")
    print("V1_SMD size:", len(v1_smd), "bytes")






    eid_hash = hashlib.sha256(
        eid_smd.encode("utf-8")
    ).digest()

    smd_pda, _ = Pubkey.find_program_address(
        [
            b"smd",
            eid_hash,
        ],
        PROGRAM_ID,
    )

    async with AsyncClient(RPC) as client:
        response = await client.get_account_info(
            smd_pda
        )

    if response.value is None:
        raise RuntimeError(
            "SMD record not found on Solana"
        )

    if response.value.owner != PROGRAM_ID:
        raise RuntimeError(
            "Unexpected SMD account owner"
        )

    onchain = decode_smd_record(
        response.value.data
    )

    if onchain["eid_hash"] != eid_hash:
        raise RuntimeError(
            "On-chain EID hash mismatch"
        )

    if onchain["eid_smd"] != eid_smd:
        raise RuntimeError(
            "On-chain EID_SMD mismatch"
        )

    print("Blockchain record: FOUND")
    print("SMD PDA:", smd_pda)
    print("RS_SMD:", onchain["rs_smd"])

    if onchain["rs_smd"] != 0:
        raise RuntimeError(
            "SMD is revoked"
        )

    print("Revocation check: PASS")






    sk_scalar = (
        sk_nsp.private_numbers().private_value
    ).to_bytes(32, "big")

    st_smd = h_fields(
        eid_smd.encode("utf-8"),
        sk_scalar,
    )

    print("ST_SMD recomputed: YES")









    node_conf = load_config(
        NODE_CONF_PATH
    )

    id_nsp = node_conf["ID_NSP"]

    v1_ok = verify_v1(
        rid_smd,
        eid_smd,
        id_nsp,
        r_smd,
        st_smd,
        v1_smd,
        onchain["pk_smd"],
        onchain["a_smd"],
    )

    print(
        "V1_SMD authentication equation:",
        v1_ok
    )

    if not v1_ok:
        raise RuntimeError(
            "SMD session authentication failed"
        )

    state = {
        "eid_smd": eid_smd,
        "id_nsp": id_nsp,
        "rid_smd": request["rid_smd"],

        "r_nsp": secret["r_nsp"],
        "pc_smd": secret["pc_smd"],
        "hpr_smd": secret["hpr_smd"],

        "r_smd": e_plain["r_smd"],

        "st_smd": base64.urlsafe_b64encode(
            st_smd
        ).decode("ascii"),

        "dt_smd": base64.urlsafe_b64encode(
            dt_smd
        ).decode("ascii"),

        "smd_pda": str(smd_pda),
        "rs_smd": onchain["rs_smd"],

        "status": "PHASE3_SMD_AUTHENTICATED",
    }

    if STATE_PATH.exists():
        existing = json.loads(
            STATE_PATH.read_text()
        )

        if existing != state:
            raise RuntimeError(
                "Existing Phase 3 verified state differs"
            )

    else:
        STATE_PATH.write_text(
            json.dumps(
                state,
                indent=2,
            ) + "\n"
        )

        STATE_PATH.chmod(0o600)

    print("State:", STATE_PATH)
    print()
    print(
        "STATUS: PHASE 3 SMD AUTHENTICATED BY NSP"
    )


asyncio.run(main())
