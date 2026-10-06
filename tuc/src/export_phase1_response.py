from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[2]

PENDING = ROOT / "tuc/data/pending/SMD-001.json"
NSP_REGISTRY = ROOT / "tuc/data/nsp_registry.json"
OUT = ROOT / "tuc/export/SMD-001_phase1_response.json"


pending = json.loads(PENDING.read_text())

if pending["status"] != "ONCHAIN_INSERTED":
    raise RuntimeError(
        "SMD blockchain insertion has not been completed"
    )

nsp_registry = json.loads(
    NSP_REGISTRY.read_text()
)

id_nsp = pending[
    "initialization_response"
]["id_nsp"]

nsp = next(
    (
        item
        for item in nsp_registry["nsps"]
        if item["id_nsp"] == id_nsp
    ),
    None,
)

if nsp is None:
    raise RuntimeError(
        "Selected NSP was not found in TUC registry"
    )


response = {

    "eid_smd": pending[
        "initialization_response"
    ]["eid_smd"],

    "id_nsp": id_nsp,

    "pk_nsp_pem": pending[
        "initialization_response"
    ]["pk_nsp_pem"],


    "pk_nsp_sha256": nsp[
        "sha256_fingerprint"
    ],
}


OUT.write_text(
    json.dumps(response, indent=2) + "\n"
)

OUT.chmod(0o600)


print("EID_SMD included: YES")
print("ID_NSP:", response["id_nsp"])
print(
    "PK_NSP fingerprint:",
    response["pk_nsp_sha256"]
)
print("Output:", OUT)
print(
    "STATUS: PHASE 1 RESPONSE READY FOR SMD"
)
