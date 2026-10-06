from pathlib import Path
import hashlib
import json

from cryptography.hazmat.primitives import serialization


ROOT = Path(__file__).resolve().parents[2]

NODE_CONF = ROOT / "smd/config/node.conf"
PK_PATH = ROOT / "smd/data/pk_smd.pem"
A_PATH = ROOT / "smd/data/A_smd.pem"
OUT = ROOT / "smd/export/smd_public.json"


def load_config(path):
    data = {}

    for line in path.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        key, value = line.split("=", 1)
        data[key] = value

    return data


def fingerprint(public_key):
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return hashlib.sha256(der).hexdigest()


node = load_config(NODE_CONF)

pk = serialization.load_pem_public_key(
    PK_PATH.read_bytes()
)

A = serialization.load_pem_public_key(
    A_PATH.read_bytes()
)

payload = {
    "id_smd": node["ID_SMD"],
    "curve": "secp256r1",
    "pk_smd_pem": PK_PATH.read_text(),
    "A_smd_pem": A_PATH.read_text(),
    "pk_smd_sha256": fingerprint(pk),
    "A_smd_sha256": fingerprint(A),
}

OUT.write_text(
    json.dumps(payload, indent=2) + "\n"
)

OUT.chmod(0o644)

print("ID_SMD:", payload["id_smd"])
print("PK_SMD fingerprint:", payload["pk_smd_sha256"])
print("A_SMD fingerprint:", payload["A_smd_sha256"])
print("Export:", OUT)
print("STATUS: SMD PUBLIC EXPORT READY")
