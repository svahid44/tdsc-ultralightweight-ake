from pathlib import Path
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[2]

NODE_CONFIG = ROOT / "tuc/config/node.conf"
CRYPTO_CONFIG = ROOT / "tuc/config/crypto.conf"
TUC_KEY = ROOT / "tuc/data/sk_tuc.key"
NSP_REGISTRY = ROOT / "tuc/data/nsp_registry.json"


def load_config(path):
    config = {}

    for line in path.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        key, value = line.split("=", 1)
        config[key] = value

    return config


node = load_config(NODE_CONFIG)
crypto = load_config(CRYPTO_CONFIG)

sk_tuc = TUC_KEY.read_bytes()

if len(sk_tuc) != 32:
    raise RuntimeError("sk_TUC must be exactly 32 bytes")


AESGCM(sk_tuc)


curve = ec.SECP256R1()

if crypto.get("ECC_CURVE") != curve.name:
    raise RuntimeError("ECC curve configuration mismatch")

if not NSP_REGISTRY.exists():
    NSP_REGISTRY.write_text(
        json.dumps({"nsps": []}, indent=2) + "\n"
    )

print("=== TUC Phase-0 Self Check ===")
print("Role:", node["ROLE"])
print("Host:", node["HOSTNAME"])
print("IP:", node["IP_ADDRESS"])
print("Hash:", crypto["HASH"])
print("Symmetric cipher:", crypto["SYMMETRIC_CIPHER"])
print("ECC curve:", crypto["ECC_CURVE"])
print("KDF:", crypto["KDF"])
print("sk_TUC: loaded successfully (32 bytes)")
print("NSP registry:", NSP_REGISTRY)
print("STATUS: READY")
