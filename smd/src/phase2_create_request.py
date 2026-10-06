from pathlib import Path
import base64
import hashlib
import json
import secrets
import struct
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[2]

import sys
sys.path.insert(0, str(ROOT))

from shared.asym_crypto import encrypt_for_nsp


STATE_PATH = ROOT / "smd/data/phase1_state.json"
SK_SMD_PATH = ROOT / "smd/data/sk_smd.pem"
A_SMD_PATH = ROOT / "smd/data/a_smd.key"

PENDING_PATH = ROOT / "smd/data/phase2_pending.json"
OUT_PATH = ROOT / "smd/export/phase2_C1_SMD.json"



P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
    "BCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


def encode_hash_field(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def protocol_hash_to_scalar(
    eid_smd: str,
    rt_smd: bytes,
    t_smd: int,
) -> int:


    payload = (
        encode_hash_field(
            eid_smd.encode("utf-8")
        )
        + encode_hash_field(rt_smd)
        + encode_hash_field(
            str(t_smd).encode("ascii")
        )
    )

    digest = hashlib.sha256(payload).digest()

    return int.from_bytes(
        digest,
        "big"
    ) % P256_ORDER







if PENDING_PATH.exists():
    raise SystemExit(
        "ERROR: phase2_pending.json already exists. "
        "Nothing was overwritten."
    )

if OUT_PATH.exists():
    raise SystemExit(
        "ERROR: phase2_C1_SMD.json already exists. "
        "Nothing was overwritten."
    )






state = json.loads(
    STATE_PATH.read_text()
)

if state["status"] != "PHASE1_COMPLETED":
    raise RuntimeError(
        "Phase 1 is not completed"
    )

eid_smd = state["eid_smd"]
id_nsp = state["id_nsp"]
pk_nsp_pem = state["pk_nsp_pem"]






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

sk_scalar = (
    sk_smd.private_numbers().private_value
)






a_raw = A_SMD_PATH.read_bytes()

if len(a_raw) != 32:
    raise RuntimeError(
        "Invalid a_SMD size"
    )

a_scalar = int.from_bytes(
    a_raw,
    "big",
)

if not (1 <= a_scalar < P256_ORDER):
    raise RuntimeError(
        "Invalid a_SMD scalar"
    )







rt_smd = secrets.token_bytes(32)









t_smd = int(time.time())










h_scalar = protocol_hash_to_scalar(
    eid_smd,
    rt_smd,
    t_smd,
)

h1_scalar = (
    h_scalar * sk_scalar
    + a_scalar
) % P256_ORDER

if h1_scalar == 0:
    raise RuntimeError(
        "Rare zero H1_SMD scalar; regenerate request"
    )

h1_bytes = h1_scalar.to_bytes(
    32,
    "big",
)








plaintext = {
    "eid_smd": eid_smd,
    "rt_smd": base64.urlsafe_b64encode(
        rt_smd
    ).decode("ascii"),
    "h1_smd": base64.urlsafe_b64encode(
        h1_bytes
    ).decode("ascii"),
    "t_smd": t_smd,
}






c1_smd = encrypt_for_nsp(
    pk_nsp_pem,
    plaintext,
)









pending = {
    "eid_smd": eid_smd,
    "id_nsp": id_nsp,
    "rt_smd": plaintext["rt_smd"],
    "t_smd": t_smd,
    "c1_sha256": hashlib.sha256(
        c1_smd.encode("ascii")
    ).hexdigest(),
    "status": "WAITING_FOR_NSP_RESPONSE",
}

PENDING_PATH.write_text(
    json.dumps(pending, indent=2) + "\n"
)

PENDING_PATH.chmod(0o600)








out = {
    "c1_smd": c1_smd
}

OUT_PATH.write_text(
    json.dumps(out, indent=2) + "\n"
)

OUT_PATH.chmod(0o600)


print("=== Phase 2 Registration Request ===")
print("ID_NSP:", id_nsp)
print("RT_SMD generated:", len(rt_smd), "bytes")
print("t_SMD:", t_smd)
print("H1_SMD generated: YES")
print("H1_SMD size:", len(h1_bytes), "bytes")
print("C1_SMD created: YES")
print(
    "C1_SMD encoded size:",
    len(c1_smd),
    "characters"
)
print("Pending state:", PENDING_PATH)
print("Request file:", OUT_PATH)

print()
print(
    "STATUS: PHASE 2 C1_SMD REGISTRATION REQUEST READY"
)
