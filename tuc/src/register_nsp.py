from pathlib import Path
import hashlib
import json

from cryptography.hazmat.primitives import serialization


ROOT = Path(__file__).resolve().parents[2]

IMPORT_FILE = ROOT / "tuc/import/nsp_public.json"
REGISTRY_FILE = ROOT / "tuc/data/nsp_registry.json"


data = json.loads(IMPORT_FILE.read_text())

public_key = serialization.load_pem_public_key(
    data["public_key_pem"].encode("ascii")
)

der = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

actual_fp = hashlib.sha256(der).hexdigest()

if actual_fp != data["sha256_fingerprint"]:
    raise RuntimeError("NSP public key fingerprint mismatch")


registry = json.loads(REGISTRY_FILE.read_text())

existing = next(
    (
        item
        for item in registry["nsps"]
        if item["id_nsp"] == data["id_nsp"]
    ),
    None,
)

if existing:
    if existing["sha256_fingerprint"] != data["sha256_fingerprint"]:
        raise RuntimeError(
            "NSP ID already exists with a different public key"
        )

    print("NSP already registered. Nothing changed.")

else:
    registry["nsps"].append({
        "id_nsp": data["id_nsp"],
        "curve": data["curve"],
        "public_key_pem": data["public_key_pem"],
        "sha256_fingerprint": data["sha256_fingerprint"],
    })

    REGISTRY_FILE.write_text(
        json.dumps(registry, indent=2) + "\n"
    )

    print("NSP registered successfully.")

print("ID_NSP:", data["id_nsp"])
print("Fingerprint:", data["sha256_fingerprint"])
print("Registered NSP count:", len(registry["nsps"]))
print("STATUS: TUC NSP REGISTRY READY")
