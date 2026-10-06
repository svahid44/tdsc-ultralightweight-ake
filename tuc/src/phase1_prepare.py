from pathlib import Path
import hashlib
import json
import sys

from cryptography.hazmat.primitives import serialization


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from shared.crypto_utils import create_eid_smd, recover_id_smd


SMD_IMPORT = ROOT / "tuc/import/smd_public.json"
NSP_REGISTRY = ROOT / "tuc/data/nsp_registry.json"
SMD_REGISTRY = ROOT / "tuc/data/smd_registry.json"
SK_TUC = ROOT / "tuc/data/sk_tuc.key"

PENDING_DIR = ROOT / "tuc/data/pending"
PENDING_DIR.mkdir(parents=True, exist_ok=True)


def fingerprint(pem_text):
    key = serialization.load_pem_public_key(
        pem_text.encode("ascii")
    )

    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return hashlib.sha256(der).hexdigest()






smd = json.loads(SMD_IMPORT.read_text())

id_smd = smd["id_smd"]






if fingerprint(smd["pk_smd_pem"]) != smd["pk_smd_sha256"]:
    raise RuntimeError("PK_SMD fingerprint mismatch")

if fingerprint(smd["A_smd_pem"]) != smd["A_smd_sha256"]:
    raise RuntimeError("A_SMD fingerprint mismatch")






registry = json.loads(SMD_REGISTRY.read_text())

if any(x["id_smd"] == id_smd for x in registry["smds"]):
    raise RuntimeError(
        f"{id_smd} is already registered"
    )


pending_path = PENDING_DIR / f"{id_smd}.json"

if pending_path.exists():
    raise RuntimeError(
        f"Pending Phase 1 record already exists: {pending_path}"
    )






sk_tuc = SK_TUC.read_bytes()

if len(sk_tuc) != 32:
    raise RuntimeError("Invalid sk_TUC length")









eid_smd = create_eid_smd(
    sk_tuc,
    id_smd,
)



recovered_id = recover_id_smd(
    sk_tuc,
    eid_smd,
)

if recovered_id != id_smd:
    raise RuntimeError("EID_SMD recovery test failed")






nsp_registry = json.loads(NSP_REGISTRY.read_text())

if not nsp_registry["nsps"]:
    raise RuntimeError("No NSP registered in TUC")

nsp = nsp_registry["nsps"][0]








pending = {
    "id_smd": id_smd,

    "ledger_record": {
        "eid_smd": eid_smd,
        "pk_smd_pem": smd["pk_smd_pem"],
        "A_smd_pem": smd["A_smd_pem"],
        "rs_smd": 0
    },

    "initialization_response": {
        "eid_smd": eid_smd,
        "id_nsp": nsp["id_nsp"],
        "pk_nsp_pem": nsp["public_key_pem"]
    },

    "status": "PENDING_BLOCKCHAIN_INSERT"
}


pending_path.write_text(
    json.dumps(pending, indent=2) + "\n"
)

pending_path.chmod(0o600)


print("ID_SMD:", id_smd)
print("EID_SMD created: YES")
print("EID recovery:", recovered_id)
print("Selected NSP:", nsp["id_nsp"])

print()
print("Ledger fields:")
print("  EID_SMD: prepared")
print("  PK_SMD: prepared")
print("  A_SMD: prepared")
print("  RS_SMD:", pending["ledger_record"]["rs_smd"])

print()
print("Pending file:", pending_path)
print("Pending permission:",
      oct(pending_path.stat().st_mode & 0o777))

print()
print("STATUS: PHASE 1 BLOCKCHAIN RECORD PREPARED")
