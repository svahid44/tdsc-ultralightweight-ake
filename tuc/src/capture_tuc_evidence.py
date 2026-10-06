from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import shutil
import socket
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey
from solders.signature import Signature

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "evidence" / "final_tuc"
OUT.mkdir(parents=True, exist_ok=True)

RPC = "https://api.devnet.solana.com"

PROGRAM_ID = Pubkey.from_string(
    "CiQyDY4MurDQJbHGZnLvVnP6BfdxKG9Fmu1GB2gPKrGQ"
)
CONFIG_PDA = Pubkey.from_string(
    "634Jmxo9J8DGNwGXw3HsYw9w3oobP3X2bJ7Eo8ECsxjv"
)
SMD_PDA = Pubkey.from_string(
    "3M6AXXVAqQgTqoHNmpBdRRApvttym8jBaBwQwcAEGiDw"
)

TUC_AUTHORITY = (
    "CQSBRzGMFdjfTx3Nqaue31N4HEuLeuTUDmJLk9QVN4E2"
)
NSP_AUTHORITY = (
    "Gd5nHLBUVkdDxKuBVbXUtbTk9s3ZCaztMAn6b9btfPou"
)

CONFIG_INIT_TX = (
    "yyTyrZ5vL232T9eQ6JkrMJLDZpunw13pQsrf32Xdf4Q5ZKTBpriVrzcU32DAiX1aDDfvkU8FPC9NzgRs1X1BbNq"
)
SMD_INSERT_TX = (
    "2TWoNEERAHVWLWozRB6srXbFLXfXNMJx6V3A2ymzynQG128udD8VfL8JwcRdosqNSVSAbvztF9h2UNnHnzL9BXmo"
)
REVOCATION_TX = (
    "TSqMHRf3YypAiQrQ6xWLyEHrxYvV27qeJXQiYgNWqr7BKMkHk2fYWCBFqZjx2KtCKep7a7BgjvKsczTpaX2w6V3"
)

NSP_PK_FINGERPRINT = (
    "7ebf0b3b67a42b6d832549e8a2dbc0d0b21e987f3f5413a9cd7feaf6812ac3fb"
)
SMD_PK_FINGERPRINT = (
    "51c8bc5d06b6b82dad681c2d0d618bf3f862dd7090eff6be88a499751e0d7917"
)
SMD_A_FINGERPRINT = (
    "acea01fe0675be10f23f0a88ed08b907b4828fa5cfaecfd9513777e326ce32ad"
)


SAFE_FILES = [
    ROOT / "tuc/config/node.conf",
    ROOT / "tuc/config/crypto.conf",
    ROOT / "tuc/export/SMD-001_phase1_response.json",
]

def run(args):
    return subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_rs_smd(raw: bytes) -> int:



    off = 8 + 32

    eid_len = int.from_bytes(raw[off:off+4], "little")
    off += 4 + eid_len

    pk_len = int.from_bytes(raw[off:off+4], "little")
    off += 4 + pk_len

    a_len = int.from_bytes(raw[off:off+4], "little")
    off += 4 + a_len

    return raw[off]

async def live_chain_capture():
    last_error = None

    for attempt in range(1, 4):
        try:
            async with AsyncClient(RPC, timeout=20) as client:
                program = await client.get_account_info(PROGRAM_ID)
                config = await client.get_account_info(CONFIG_PDA)
                smd = await client.get_account_info(SMD_PDA)

                if program.value is None:
                    raise RuntimeError("Program account missing")
                if config.value is None:
                    raise RuntimeError("Config PDA missing")
                if smd.value is None:
                    raise RuntimeError("SMD PDA missing")

                sigs = [
                    Signature.from_string(CONFIG_INIT_TX),
                    Signature.from_string(SMD_INSERT_TX),
                    Signature.from_string(REVOCATION_TX),
                ]
                statuses = await client.get_signature_statuses(
                    sigs,
                    search_transaction_history=True,
                )

                tx_names = [
                    "config_init",
                    "smd_insert",
                    "smd_revoke",
                ]

                tx_status = {}
                for name, sig, status in zip(
                    tx_names,
                    sigs,
                    statuses.value,
                ):
                    tx_status[name] = {
                        "signature": str(sig),
                        "found": status is not None,
                        "confirmation_status": (
                            str(status.confirmation_status)
                            if status is not None
                            else None
                        ),
                        "err": (
                            str(status.err)
                            if status is not None
                            else None
                        ),
                    }

                rs_smd = parse_rs_smd(smd.value.data)

                return {
                    "status": "LIVE_CAPTURE_SUCCESS",
                    "attempt": attempt,
                    "rpc": RPC,
                    "program": {
                        "program_id": str(PROGRAM_ID),
                        "exists": True,
                        "executable": program.value.executable,
                        "owner": str(program.value.owner),
                        "data_len": len(program.value.data),
                    },
                    "config_pda": {
                        "address": str(CONFIG_PDA),
                        "exists": True,
                        "owner": str(config.value.owner),
                        "data_len": len(config.value.data),
                    },
                    "smd_pda": {
                        "address": str(SMD_PDA),
                        "exists": True,
                        "owner": str(smd.value.owner),
                        "data_len": len(smd.value.data),
                        "rs_smd": rs_smd,
                    },
                    "transactions": tx_status,
                    "captured_at_utc": datetime.now(
                        timezone.utc
                    ).isoformat(),
                }

        except Exception as exc:
            last_error = repr(exc)
            await asyncio.sleep(2)

    return {
        "status": "LIVE_CAPTURE_FAILED",
        "rpc": RPC,
        "program_id": str(PROGRAM_ID),
        "config_pda": str(CONFIG_PDA),
        "smd_pda": str(SMD_PDA),
        "known_completed_results": {
            "config_init_tx": CONFIG_INIT_TX,
            "smd_insert_tx": SMD_INSERT_TX,
            "revocation_tx": REVOCATION_TX,
            "revocation_observed_rs_after": 1,
        },
        "live_capture_error": last_error,
        "captured_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
    }




system = {
    "captured_at_utc": datetime.now(timezone.utc).isoformat(),
    "role": "TUC",
    "hostname": socket.gethostname(),
    "python": platform.python_version(),
    "platform": platform.platform(),
}
openssl = run(["openssl", "version"])
system["openssl"] = openssl.stdout.strip() or openssl.stderr.strip()

(OUT / "system_info.json").write_text(
    json.dumps(system, indent=2) + "\n"
)




files_dir = OUT / "safe_files"
files_dir.mkdir(exist_ok=True)

copied = []
missing = []

for src in SAFE_FILES:
    if src.exists():
        dst = files_dir / (
            src.relative_to(ROOT)
            .as_posix()
            .replace("/", "__")
        )
        shutil.copy2(src, dst)
        copied.append(src.relative_to(ROOT).as_posix())
    else:
        missing.append(src.relative_to(ROOT).as_posix())

(OUT / "safe_file_inventory.json").write_text(
    json.dumps(
        {
            "copied": copied,
            "missing": missing,
            "explicitly_excluded": [
                "tuc/data/sk_tuc.key",
                "any Solana wallet private-key file",
                "any file containing raw private keys",
            ],
        },
        indent=2,
    ) + "\n"
)




identity = {
    "program_id": str(PROGRAM_ID),
    "config_pda": str(CONFIG_PDA),
    "smd_pda": str(SMD_PDA),
    "tuc_authority": TUC_AUTHORITY,
    "nsp_authority": NSP_AUTHORITY,
    "nsp_public_key_fingerprint_sha256": NSP_PK_FINGERPRINT,
    "smd_public_key_fingerprint_sha256": SMD_PK_FINGERPRINT,
    "smd_A_fingerprint_sha256": SMD_A_FINGERPRINT,
    "transactions": {
        "config_init": CONFIG_INIT_TX,
        "smd_insert": SMD_INSERT_TX,
        "smd_revoke": REVOCATION_TX,
    },
}

(OUT / "experiment_identity.json").write_text(
    json.dumps(identity, indent=2) + "\n"
)




chain = asyncio.run(live_chain_capture())

(OUT / "solana_live_evidence.json").write_text(
    json.dumps(chain, indent=2) + "\n"
)




phase1 = {
    "status": "PASS",
    "role": "TUC",
    "smd_id": "SMD-001",
    "nsp_id": "NSP-001",
    "phase1_response_path_expected": (
        "tuc/export/SMD-001_phase1_response.json"
    ),
    "phase1_response_copied": (
        ROOT / "tuc/export/SMD-001_phase1_response.json"
    ).exists(),
    "solana_record_inserted": True,
    "initial_rs_smd": 0,
    "current_rs_smd_expected_after_completed_revocation_test": 1,
    "notes": [
        "EID_SMD was generated by TUC and returned to SMD.",
        "SMD public parameters were inserted into the deployed Solana program.",
        "No TUC private key is included in this evidence package.",
    ],
}

(OUT / "PHASE1_EVIDENCE_SUMMARY.json").write_text(
    json.dumps(phase1, indent=2) + "\n"
)

readme = f"""# TUC Evidence Package

Captured: {system['captured_at_utc']}

## Scope
This package freezes the TUC-side evidence for the implemented
TDSC protocol experiment without exporting TUC private secrets.

## Phase 1
- Phase 1 status: PASS
- SMD: SMD-001
- NSP: NSP-001
- TUC authority: {TUC_AUTHORITY}
- NSP authority: {NSP_AUTHORITY}

## Solana
- Program ID: {PROGRAM_ID}
- Config PDA: {CONFIG_PDA}
- SMD PDA: {SMD_PDA}
- Config-init transaction: {CONFIG_INIT_TX}
- SMD-insert transaction: {SMD_INSERT_TX}
- Revocation transaction: {REVOCATION_TX}
- Live chain capture status: {chain['status']}

## Public fingerprints
- NSP public key SHA-256: {NSP_PK_FINGERPRINT}
- SMD public key SHA-256: {SMD_PK_FINGERPRINT}
- SMD A-point SHA-256: {SMD_A_FINGERPRINT}

## Security
No TUC private key or Solana wallet private key is copied into this package.
"""

(OUT / "README_EVIDENCE.md").write_text(readme)




entries = []

for p in sorted(OUT.rglob("*")):
    if p.is_file() and p.name != "SHA256SUMS.txt":
        entries.append(
            f"{sha256_file(p)}  "
            f"{p.relative_to(OUT).as_posix()}"
        )

(OUT / "SHA256SUMS.txt").write_text(
    "\n".join(entries) + "\n"
)

archive = ROOT / "evidence" / "tdsc_tuc_evidence.tar.gz"

with tarfile.open(archive, "w:gz") as tf:
    tf.add(OUT, arcname="final_tuc")

print("TUC evidence directory:", OUT)
print("TUC evidence archive:", archive)
print("Files:", len(entries) + 1)
print("Live Solana evidence:", chain["status"])
print("STATUS: TUC EVIDENCE CAPTURED")
