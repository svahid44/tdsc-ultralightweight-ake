from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives import serialization
from solders.keypair import Keypair


ROOT = Path(__file__).resolve().parents[2]

NODE_CONF = ROOT / "nsp/config/node.conf"
PRIVATE_KEY = ROOT / "nsp/data/sk_nsp.pem"
PUBLIC_KEY = ROOT / "nsp/data/pk_nsp.pem"
SOLANA_WALLET = ROOT / "nsp/data/solana_nsp.key"
DATABASE = ROOT / "nsp/data/nsp.db"


def load_config(path):
    result = {}

    for line in path.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        key, value = line.split("=", 1)
        result[key] = value

    return result


node = load_config(NODE_CONF)

private_key = serialization.load_pem_private_key(
    PRIVATE_KEY.read_bytes(),
    password=None,
)

public_key = serialization.load_pem_public_key(
    PUBLIC_KEY.read_bytes()
)

if private_key.public_key().public_numbers() != public_key.public_numbers():
    raise RuntimeError("NSP private/public key mismatch")

wallet = Keypair.from_bytes(SOLANA_WALLET.read_bytes())

with sqlite3.connect(DATABASE) as conn:
    count = conn.execute(
        "SELECT COUNT(*) FROM smd_records"
    ).fetchone()[0]


print("=== NSP Self Check ===")
print("Role:", node["ROLE"])
print("ID:", node["ID_NSP"])
print("Host:", node["HOSTNAME"])
print("Protocol ECC keypair: OK")
print("Solana wallet:", wallet.pubkey())
print("Database records:", count)
print("STATUS: NSP READY")
