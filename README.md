# TDSC Ultra-Lightweight Blockchain-Assisted AKE — Reproducibility Repository

Functional implementation and experimental validation of:

> **Novel Ultra-Lightweight Leakage-Resilient Blockchain-Assisted Key Exchange Protocol for Resource-Constrained Smart Meters in Smart Grid**  
> Dariush Abbasinezhad-Mood, *IEEE Transactions on Dependable and Secure Computing*, 2026.  
> DOI: `10.1109/TDSC.2025.3617517`

## Validation status

| Item | Result |
|---|---|
| Phase 0 setup | PASS |
| Phase 1 on-chain initialization | PASS |
| Phase 2 registration | PASS |
| Phase 3 Session 1 | PASS |
| Phase 3 Session 2 without re-registration | PASS |
| SMD/NSP session-key agreement | PASS |
| Fresh session keys | PASS |
| RID/state rotation | PASS |
| Old RID deletion | PASS |
| On-chain revocation `RS_SMD: 0 -> 1` | PASS |
| Session after revocation | REJECTED AS EXPECTED |
| Communication measurement | PASS |
| SMD/NSP benchmarks | PASS |
| Solana Devnet RPC measurement | PASS |

## Architecture

```text
                         Solana Devnet
                              |
                 +------------+------------+
                 |                         |
                TUC                       NSP
                 |                         |
                 +----> SMD <--------------+
                        Phase 1 / 2 / 3
```

The experiment ran on three physical Linux nodes. Because they were on separate private networks without direct routing, protocol ciphertext messages were transferred manually as JSON files. Cryptographic processing, database state transitions, Solana reads/writes, session-key derivation, RID rotation, and revocation enforcement were executed by the implementation.

## Concrete v1 implementation choices

- SHA-256
- AES-256-GCM
- NIST P-256 / secp256r1
- ECIES-like `AEnc`: ephemeral P-256 ECDH + HKDF-SHA256 + AES-256-GCM
- 4-byte big-endian length-prefix structured hashing
- SQLite NSP state database
- JSON + URL-safe Base64 transport representation
- **HMAC-SHA256 simulated PUF**, not a physical PUF

These are implementation choices, not claims that the source paper uniquely mandates them.

## Solana

- Program ID: `CiQyDY4MurDQJbHGZnLvVnP6BfdxKG9Fmu1GB2gPKrGQ`
- Config PDA: `634Jmxo9J8DGNwGXw3HsYw9w3oobP3X2bJ7Eo8ECsxjv`
- SMD PDA: `3M6AXXVAqQgTqoHNmpBdRRApvttym8jBaBwQwcAEGiDw`

See [`docs/BLOCKCHAIN_EVIDENCE.md`](docs/BLOCKCHAIN_EVIDENCE.md).

## Successful session-key fingerprints

Only SHA-256 fingerprints are published. Raw session keys are not included.

```text
Session 1:
c1921fbf5888db250c1ac63908a72e2362a19b2bc99fca0eb570cef19528bef4

Session 2:
3d0ba378727b037c0dfbe57b5c9a62a2b96355e3123e5f2f20da25718398a1f6
```

Within each session the SMD and NSP fingerprints matched; the two sessions produced different fingerprints.

## Performance snapshot

| Metric | v1 implementation |
|---|---:|
| SMD synthetic local workload | 4.986 us |
| NSP synthetic local crypto workload | 461.721 us |
| Solana Devnet `getAccountInfo` median | 985.521 ms |
| Phase-3 decoded binary fields | 466 B |
| Phase-3 compact JSON | 702 B |
| Phase-3 pretty JSON | 732 B |

See [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) for scope and caveats.

## Layout

```text
tuc/          TUC source + public config
nsp/          NSP source + public config
smd/          SMD source + public config
shared/       Shared crypto/encoding utilities
solana/       Exact deployed Anchor program source
benchmarks/   Measurement scripts
docs/         Architecture, mapping, setup, results, evidence
evidence/     Public summaries; frozen archives belong in Releases
scripts/      Source export/import, secret audit, verification
```

## Before publishing

```bash
python scripts/audit_secrets.py .
python scripts/verify_public_repo.py .
```

Never publish private EC keys, TUC secret material, Solana wallet keypairs/seed phrases, raw session keys, raw `S_SMD`/`S_NSP`, PUF secrets, or credential-bearing `.env` files.

## Versioning

- `v1.0.0`: validated functional implementation with manual JSON transport
- planned `v2`: automated network transport
- planned `v3`: physical/hardware PUF integration
