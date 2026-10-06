from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path.home() / "tdsc-protocol"
EVIDENCE = ROOT / "evidence"
INCOMING = EVIDENCE / "incoming"

MASTER = EVIDENCE / "TDSC_IMPLEMENTATION_EVIDENCE"
RAW = MASTER / "raw_evidence"

TUC_ARCHIVE = EVIDENCE / "tdsc_tuc_evidence.tar.gz"


CANDIDATES = {
    "TUC": [
        TUC_ARCHIVE,
    ],
    "SMD": [
        INCOMING / "tdsc_smd_evidence.tar.gz",
        EVIDENCE / "tdsc_smd_evidence.tar.gz",
    ],
    "NSP": [
        INCOMING / "tdsc_nsp_evidence.tar.gz",
        EVIDENCE / "tdsc_nsp_evidence.tar.gz",
    ],
}

EXPECTED_ROOT = {
    "TUC": "final_tuc",
    "SMD": "final_smd",
    "NSP": "final_nsp",
}

TRANSACTIONS = {
    "config_init": (
        "yyTyrZ5vL232T9eQ6JkrMJLDZpunw13pQsrf32Xdf4Q5ZKTBpriVrzcU32DAiX1aDDfvkU8FPC9NzgRs1X1BbNq"
    ),
    "smd_insert": (
        "2TWoNEERAHVWLWozRB6srXbFLXfXNMJx6V3A2ymzynQG128udD8VfL8JwcRdosqNSVSAbvztF9h2UNnHnzL9BXmo"
    ),
    "smd_revoke": (
        "TSqMHRf3YypAiQrQ6xWLyEHrxYvV27qeJXQiYgNWqr7BKMkHk2fYWCBFqZjx2KtCKep7a7BgjvKsczTpaX2w6V3"
    ),
}

PROGRAM_ID = "CiQyDY4MurDQJbHGZnLvVnP6BfdxKG9Fmu1GB2gPKrGQ"
CONFIG_PDA = "634Jmxo9J8DGNwGXw3HsYw9w3oobP3X2bJ7Eo8ECsxjv"
SMD_PDA = "3M6AXXVAqQgTqoHNmpBdRRApvttym8jBaBwQwcAEGiDw"

SESSION_KEYS = {
    "session1_sha256": (
        "c1921fbf5888db250c1ac63908a72e2362a19b2bc99fca0eb570cef19528bef4"
    ),
    "session2_sha256": (
        "3d0ba378727b037c0dfbe57b5c9a62a2b96355e3123e5f2f20da25718398a1f6"
    ),
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_archive(role: str) -> Path:
    for path in CANDIDATES[role]:
        if path.exists():
            return path
    searched = "\n".join(f"  - {p}" for p in CANDIDATES[role])
    raise FileNotFoundError(
        f"{role} evidence archive not found. Searched:\n{searched}"
    )


def safe_extract(tf: tarfile.TarFile, target: Path):
    target_resolved = target.resolve()
    for member in tf.getmembers():
        destination = (target / member.name).resolve()
        if not str(destination).startswith(str(target_resolved)):
            raise RuntimeError(
                f"Unsafe path in archive: {member.name}"
            )
    tf.extractall(target)


def verify_embedded_manifest(extracted: Path, root_name: str):
    base = extracted / root_name
    manifest = base / "SHA256SUMS.txt"

    if not manifest.exists():
        raise RuntimeError(
            f"Missing SHA256SUMS.txt in {root_name}"
        )

    checked = 0
    failures = []

    for line in manifest.read_text().splitlines():
        line = line.strip()
        if not line:
            continue

        digest, rel = line.split("  ", 1)
        path = base / rel

        if not path.exists():
            failures.append(f"MISSING {rel}")
            continue

        actual = sha256_file(path)

        if actual != digest:
            failures.append(
                f"HASH MISMATCH {rel}: expected {digest}, got {actual}"
            )
        checked += 1

    return {
        "checked_files": checked,
        "ok": not failures,
        "failures": failures,
    }


def read_json(path: Path, default=None):
    if path.exists():
        return json.loads(path.read_text())
    return default





archives = {
    role: find_archive(role)
    for role in ("TUC", "SMD", "NSP")
}

MASTER.mkdir(parents=True, exist_ok=True)
RAW.mkdir(parents=True, exist_ok=True)


for item in list(MASTER.iterdir()):
    if item.name == "raw_evidence":
        continue
    if item.is_dir():
        shutil.rmtree(item)
    else:
        item.unlink()


for item in list(RAW.iterdir()):
    if item.is_file():
        item.unlink()
    elif item.is_dir():
        shutil.rmtree(item)

for role, src in archives.items():
    shutil.copy2(
        src,
        RAW / src.name,
    )




verification = {}
data = {}

with tempfile.TemporaryDirectory() as tmpdir:
    tmp = Path(tmpdir)

    for role, archive in archives.items():
        role_dir = tmp / role.lower()
        role_dir.mkdir()

        with tarfile.open(archive, "r:gz") as tf:
            safe_extract(tf, role_dir)

        root_name = EXPECTED_ROOT[role]

        result = verify_embedded_manifest(
            role_dir,
            root_name,
        )

        verification[role] = {
            "archive_filename": archive.name,
            "archive_sha256": sha256_file(archive),
            **result,
        }

        if not result["ok"]:
            raise RuntimeError(
                f"{role} evidence integrity verification FAILED"
            )

        base = role_dir / root_name

        if role == "TUC":
            data["tuc_phase1"] = read_json(
                base / "PHASE1_EVIDENCE_SUMMARY.json",
                {},
            )
            data["tuc_identity"] = read_json(
                base / "experiment_identity.json",
                {},
            )
            data["tuc_solana"] = read_json(
                base / "solana_live_evidence.json",
                {},
            )
            data["tuc_system"] = read_json(
                base / "system_info.json",
                {},
            )

        elif role == "NSP":
            data["nsp_results"] = read_json(
                base / "FINAL_RESULTS_SUMMARY.json",
                {},
            )
            data["nsp_keys"] = read_json(
                base / "session_key_fingerprints.json",
                {},
            )
            data["nsp_comm"] = read_json(
                base / "communication_metrics.json",
                {},
            )
            data["nsp_revoke"] = read_json(
                base / "solana_revocation_evidence.json",
                {},
            )
            data["nsp_db"] = read_json(
                base / "nsp_database_summary.json",
                {},
            )
            data["nsp_system"] = read_json(
                base / "system_info.json",
                {},
            )

        elif role == "SMD":
            data["smd_system"] = read_json(
                base / "system_info.json",
                {},
            )
            data["smd_notes"] = read_json(
                base / "implementation_notes.json",
                {},
            )
            bench_path = base / "benchmark_smd_primitives.txt"
            data["smd_benchmark_text"] = (
                bench_path.read_text()
                if bench_path.exists()
                else ""
            )




captured_at = datetime.now(timezone.utc).isoformat()

final_results = {
    "project": (
        "Implementation of Novel Ultra-Lightweight Leakage-Resilient "
        "Blockchain-Assisted Key Exchange Protocol"
    ),
    "paper_doi": "10.1109/TDSC.2025.3617517",
    "captured_at_utc": captured_at,
    "implementation_status": "FUNCTIONAL_IMPLEMENTATION_COMPLETE",
    "functional_validation": {
        "phase0_setup": "PASS",
        "phase1_tuc_initialization": "PASS",
        "phase2_registration": "PASS",
        "phase3_session1": "PASS",
        "phase3_session2_without_reregistration": "PASS",
        "state_rotation": "PASS",
        "fresh_session_keys": "PASS",
        "old_rid_deletion": "PASS",
        "onchain_revocation": "PASS",
        "phase3_session3_after_revocation": (
            "PASS_REJECTED_AS_EXPECTED"
        ),
    },
    "blockchain": {
        "network": "Solana Devnet",
        "program_id": PROGRAM_ID,
        "config_pda": CONFIG_PDA,
        "smd_pda": SMD_PDA,
        "transactions": TRANSACTIONS,
        "revocation": {
            "rs_before": 0,
            "rs_after": 1,
            "session3_result": "RuntimeError: SMD is revoked",
        },
    },
    "session_key_fingerprints": {
        **SESSION_KEYS,
        "session1_equals_session2": False,
        "smd_nsp_match_session1": True,
        "smd_nsp_match_session2": True,
    },
    "performance": {
        "smd_synthetic_local_us": 4.986,
        "nsp_crypto_synthetic_local_us": 461.721,
        "solana_get_account_info_median_ms": 985.521,
        "approx_nsp_crypto_plus_rpc_ms": 985.983,
        "phase3_communication": {
            "decoded_binary_bytes": 466,
            "compact_json_bytes": 702,
            "pretty_json_bytes": 732,
        },
        "paper_reference": {
            "smd_us": 531,
            "nsp_crypto_us": 150,
            "solana_query_us": 266,
            "reported_total_ms": 0.95,
            "phase3_communication_bytes": 136,
        },
    },
    "architecture": {
        "tuc": data.get("tuc_system", {}),
        "nsp": data.get("nsp_system", {}),
        "smd": data.get("smd_system", {}),
        "transport_used_in_experiment": (
            "manual transfer of JSON ciphertext messages"
        ),
    },
    "implementation_choices": {
        "hash": "SHA-256",
        "symmetric_encryption": "AES-256-GCM",
        "elliptic_curve": "NIST P-256 / secp256r1",
        "aenc": (
            "ECIES-like construction using ephemeral P-256 ECDH + "
            "HKDF-SHA256 + AES-256-GCM"
        ),
        "puf": "HMAC-SHA256 simulated PUF",
        "nsp_database": "SQLite",
    },
    "limitations": [
        "PUF is simulated; no physical-PUF unclonability or physical leakage-resilience experiment was performed.",
        "Inter-node transport was manual JSON transfer rather than an automated network API.",
        "Public Solana Devnet RPC latency is network-dependent.",
        "NSP P-256 multiplication benchmark uses ECDH as an OpenSSL-backed proxy.",
        "NSP point-add benchmark uses Python affine arithmetic and is not an optimized OpenSSL point-add measurement.",
    ],
    "node_evidence_integrity": verification,
}

(MASTER / "FINAL_RESULTS.json").write_text(
    json.dumps(final_results, indent=2) + "\n"
)

(MASTER / "EVIDENCE_VERIFICATION.json").write_text(
    json.dumps(verification, indent=2) + "\n"
)




tx_text = f"""Solana Devnet Evidence

Program ID:
{PROGRAM_ID}

Config PDA:
{CONFIG_PDA}

SMD PDA:
{SMD_PDA}

Registry config initialization transaction:
{TRANSACTIONS['config_init']}

SMD record insertion transaction:
{TRANSACTIONS['smd_insert']}

SMD revocation transaction:
{TRANSACTIONS['smd_revoke']}
"""
(MASTER / "TRANSACTION_IDS.txt").write_text(tx_text)




timeline = """# Experiment Timeline

## Phase 0 — System Setup
TUC, NSP and SMD environments were prepared without kernel upgrades. Cryptographic configuration used SHA-256, AES-256-GCM and P-256. The NSP generated its key pair and local SQLite database.

## Phase 1 — On-chain Pre-deployment Initialization
SMD generated its private/public parameters and A_SMD. TUC generated EID_SMD, initialized the Solana registry configuration and inserted the SMD record with RS_SMD=0. The SMD then accepted the Phase-1 response and verified the NSP public-key fingerprint.

## Phase 2 — Post-deployment Registration
SMD created C1. NSP decrypted it, checked freshness, read the SMD record from Solana and verified the H1 authentication equation. NSP returned C_NSP. SMD verified H_NSP, evaluated the simulated PUF, stored S_SMD and returned C2. NSP verified H2 and stored S_NSP in SQLite.

Result: registration completed successfully.

## Phase 3 — Session 1
SMD and NSP completed the session-key exchange. V1, V_NSP and V2 checks succeeded. Both sides derived the same session key. NSP deleted the old RID after successful acknowledgement and retained the new RID.

Result: PASS.

## Phase 3 — Session 2
The protocol was executed again without repeating Phase 1 or Phase 2. The new SMD RID matched the single active NSP database record. Authentication succeeded, both sides derived the same new session key, and the new session-key fingerprint differed from Session 1.

Result: repeatable state rotation and fresh session-key generation verified.

## Revocation Test
NSP invoked the deployed Solana smart-contract revocation instruction. The SMD record changed from RS_SMD=0 to RS_SMD=1 and the change was read back from Devnet.

## Phase 3 — Session 3 Negative Test
SMD generated a syntactically and cryptographically valid next-session request using its locally valid state. NSP successfully found and decrypted its local record, decrypted E_SMD and fetched the blockchain record. The on-chain record contained RS_SMD=1, so NSP stopped before continuing authentication and raised:

RuntimeError: SMD is revoked

Result: on-chain revocation enforcement verified.

## Performance Measurements
Communication size, SMD primitive timing, NSP primitive timing and public Solana Devnet account-read latency were measured and archived. These measurements are implementation-specific and are reported separately from the theoretical figures used by the source paper.
"""
(MASTER / "EXPERIMENT_TIMELINE.md").write_text(timeline)




impl_vs_paper = """# Implementation vs. Source Paper

## Faithful protocol logic implemented
The implementation follows the paper's high-level four-phase structure and the core authentication/state-transition equations for registration, session-key exchange, RID rotation, acknowledgement, old-state deletion and revocation checking.

## Concrete choices required by implementation
The source paper specifies generic cryptographic primitives such as SEnc/AEnc but does not define a wire format or a unique concrete implementation for every primitive. This implementation therefore made explicit choices:

- SHA-256 for h(.)
- AES-256-GCM for symmetric authenticated encryption
- P-256 / secp256r1 for elliptic-curve operations
- ECIES-like AEnc using ephemeral P-256 ECDH, HKDF-SHA256 and AES-256-GCM
- Length-prefixed canonical hashing of structured fields
- JSON + URL-safe Base64 for manual message transport
- SQLite for the NSP local RID -> S_NSP store
- Anchor/Solana PDA records for the blockchain registry

These are implementation choices and must not be presented as if the paper uniquely specified them.

## PUF scope
The paper assumes a physical unclonable function. This implementation uses a persistent HMAC-SHA256-based simulated PUF to exercise the protocol flow. Therefore it does not experimentally prove physical-PUF unclonability, physical tamper resistance or physical leakage resilience.

## Transport scope
The protocol messages were transferred manually as JSON files because the three physical nodes were on separate private networks without direct routing. The cryptographic/state-machine execution is real, but the transport layer is not yet automated.

## Performance interpretation
The paper reports theoretical/reference costs for protocol operations. The implementation measurements include concrete AEAD packaging, serialization and public Devnet network latency, so they should be reported as implementation measurements rather than treated as direct apples-to-apples reproductions of the paper's timing model.
"""
(MASTER / "IMPLEMENTATION_VS_PAPER.md").write_text(
    impl_vs_paper
)




performance = """# Performance Results

## SMD
Measured synthetic count corresponding to 7Th + 5Te + Tp:

- 4.986 us on the SMD NUC used in this experiment.

This is not a constrained smart-meter hardware reproduction. The PUF operation is an HMAC-based simulation.

## NSP
Synthetic local cryptographic estimate corresponding to Ta + 5Te + 6Th + 2Tm:

- 461.721 us

Important: scalar multiplication was approximated with OpenSSL-backed ECDH and point addition was measured with Python affine arithmetic.

## Solana Devnet
Public-network getAccountInfo latency:

- Median: 985.521 ms

This is an Internet/Devnet RPC round-trip and is network-dependent.

## Communication — Phase 3 Session 2
- Decoded binary fields: 466 B
- Compact JSON: 702 B
- Pretty JSON: 732 B

## Source-paper reference values
- SMD: ~531 us
- NSP local crypto: ~150 us
- Solana query: ~266 us
- Reported total: ~0.95 ms
- Phase-3 communication: 136 B

The implementation values and source-paper values are retained separately because they measure different abstraction levels and execution environments.
"""
(MASTER / "PERFORMANCE_RESULTS.md").write_text(performance)




blockchain = f"""# Blockchain Evidence

Network: Solana Devnet

Program ID: `{PROGRAM_ID}`

Config PDA: `{CONFIG_PDA}`

SMD PDA: `{SMD_PDA}`

## Important transactions
- Registry config initialization: `{TRANSACTIONS['config_init']}`
- SMD record insertion: `{TRANSACTIONS['smd_insert']}`
- SMD revocation: `{TRANSACTIONS['smd_revoke']}`

## Revocation validation
The completed experiment observed:

- RS_SMD before revocation: 0
- Revocation transaction: confirmed
- RS_SMD after revocation: 1
- Next Phase-3 request: rejected by NSP
- Rejection reason: `RuntimeError: SMD is revoked`

The TUC and NSP evidence packages additionally contain live Solana captures from the evidence-freeze stage.
"""
(MASTER / "BLOCKCHAIN_EVIDENCE.md").write_text(blockchain)




readme = f"""# TDSC Protocol Implementation — Master Evidence Package

Generated: {captured_at}

Paper: Novel Ultra-Lightweight Leakage-Resilient Blockchain-Assisted Key Exchange Protocol for Resource-Constrained Smart Meters in Smart Grid
DOI: 10.1109/TDSC.2025.3617517

## Final status

| Test | Result |
|---|---|
| Phase 0 setup | PASS |
| Phase 1 initialization | PASS |
| Phase 2 registration | PASS |
| Phase 3 Session 1 | PASS |
| Phase 3 Session 2 | PASS |
| Session 2 without re-registration | PASS |
| RID/state rotation | PASS |
| Fresh session keys | PASS |
| Old RID deletion | PASS |
| Solana on-chain revocation | PASS |
| Session 3 after revocation | REJECTED AS EXPECTED |
| Communication measurement | PASS |
| SMD benchmark | PASS |
| NSP benchmark | PASS |
| Solana RPC measurement | PASS |

## Evidence archives
The `raw_evidence/` directory contains the independently generated TUC, NSP and SMD evidence archives.

Each node archive contains its own `SHA256SUMS.txt`. During creation of this Master Package all three embedded manifests were independently verified before the package was generated.

## Important security note
No raw private keys or raw session keys are intentionally included in the node evidence archives.

## Remaining optional development
The core functional implementation is complete for the tested architecture.

Remaining extensions are:

1. Automated network transport instead of manual JSON transfer.
2. Replacement of the simulated HMAC-based PUF with a physical/hardware PUF or a hardware-backed PUF interface.

These are extensions to the completed functional experiment and should not overwrite the frozen evidence package.
"""
(MASTER / "README_FINAL.md").write_text(readme)




entries = []

for path in sorted(MASTER.rglob("*")):
    if path.is_file() and path.name != "SHA256SUMS.txt":
        entries.append(
            f"{sha256_file(path)}  "
            f"{path.relative_to(MASTER).as_posix()}"
        )

(MASTER / "SHA256SUMS.txt").write_text(
    "\n".join(entries) + "\n"
)

master_archive = EVIDENCE / "TDSC_IMPLEMENTATION_EVIDENCE.tar.gz"

if master_archive.exists():
    master_archive.unlink()

with tarfile.open(master_archive, "w:gz") as tf:
    tf.add(
        MASTER,
        arcname="TDSC_IMPLEMENTATION_EVIDENCE",
    )

archive_sha = sha256_file(master_archive)

(EVIDENCE / "TDSC_IMPLEMENTATION_EVIDENCE.tar.gz.sha256").write_text(
    f"{archive_sha}  {master_archive.name}\n"
)

print()
print("=== MASTER EVIDENCE COMPLETE ===")
print("Master directory:", MASTER)
print("Master archive:", master_archive)
print("Master archive SHA256:", archive_sha)
print()
print("Embedded node integrity:")
for role in ("TUC", "SMD", "NSP"):
    v = verification[role]
    print(
        f"  {role}: PASS "
        f"({v['checked_files']} files verified)"
    )
print()
print("STATUS: TDSC IMPLEMENTATION EVIDENCE FROZEN")
