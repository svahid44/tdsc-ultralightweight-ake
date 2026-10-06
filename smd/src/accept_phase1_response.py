from pathlib import Path
import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[2]

NODE_CONF = ROOT / "smd/config/node.conf"
RESPONSE_PATH = ROOT / "smd/import/SMD-001_phase1_response.json"
STATE_PATH = ROOT / "smd/data/phase1_state.json"


def load_config(path):
    result = {}

    for line in path.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        key, value = line.split("=", 1)
        result[key] = value

    return result


def public_key_fingerprint(pem):
    key = serialization.load_pem_public_key(
        pem.encode("ascii")
    )

    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise RuntimeError("PK_NSP is not an ECC public key")

    if key.curve.name != "secp256r1":
        raise RuntimeError(
            f"Unexpected NSP curve: {key.curve.name}"
        )

    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return hashlib.sha256(der).hexdigest()


node = load_config(NODE_CONF)
response = json.loads(RESPONSE_PATH.read_text())






required = {
    "eid_smd",
    "id_nsp",
    "pk_nsp_pem",
    "pk_nsp_sha256",
}

missing = required - set(response)

if missing:
    raise RuntimeError(
        f"Missing response fields: {sorted(missing)}"
    )






actual_fp = public_key_fingerprint(
    response["pk_nsp_pem"]
)

expected_fp = response["pk_nsp_sha256"]

print("ID_SMD:", node["ID_SMD"])
print("ID_NSP:", response["id_nsp"])
print("PK_NSP expected:", expected_fp)
print("PK_NSP actual:  ", actual_fp)
print("PK_NSP MATCH:", actual_fp == expected_fp)

if actual_fp != expected_fp:
    raise RuntimeError(
        "PK_NSP fingerprint mismatch"
    )









try:
    eid_raw = base64.urlsafe_b64decode(
        response["eid_smd"].encode("ascii")
    )
except Exception as exc:
    raise RuntimeError(
        "Invalid EID_SMD encoding"
    ) from exc

if len(eid_raw) == 0:
    raise RuntimeError(
        "Empty EID_SMD"
    )

print("EID_SMD encoding: OK")
print("EID_SMD decoded size:", len(eid_raw), "bytes")






state = {
    "id_smd": node["ID_SMD"],
    "eid_smd": response["eid_smd"],
    "id_nsp": response["id_nsp"],
    "pk_nsp_pem": response["pk_nsp_pem"],
    "pk_nsp_sha256": response["pk_nsp_sha256"],
    "status": "PHASE1_COMPLETED"
}


if STATE_PATH.exists():
    existing = json.loads(
        STATE_PATH.read_text()
    )

    if existing != state:
        raise RuntimeError(
            "Existing Phase 1 state differs. Nothing overwritten."
        )

    print("Existing Phase 1 state already matches.")

else:
    STATE_PATH.write_text(
        json.dumps(state, indent=2) + "\n"
    )

    STATE_PATH.chmod(0o600)


print("State file:", STATE_PATH)
print(
    "Permission:",
    oct(STATE_PATH.stat().st_mode & 0o777)
)

print()
print("STATUS: SMD PHASE 1 COMPLETED")
