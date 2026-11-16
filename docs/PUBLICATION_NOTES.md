# Publication Notes

This repository is the sanitized publication form of the validated v1 experiment.

The protocol logic, constants, cryptographic operations, Solana program ID, state transitions, benchmark logic, and experiment results are preserved.

For publication hygiene, source-code comments and Python explanatory docstrings were removed before the first public commit. Therefore the public source files are not byte-for-byte identical to the working copies used during the experiment, although the executable logic is intended to be unchanged.

The frozen experiment evidence remains independent of the publication-source hashes and is identified by its own SHA-256 manifest.

## v1 scope

- Three-node TUC/NSP/SMD functional implementation
- Two successful Phase-3 sessions
- RID/state rotation
- Session-key agreement
- Solana Devnet registry
- On-chain revocation enforcement
- SMD, NSP, communication and Solana measurements
- Manual JSON transport between physically separated private networks
- Simulated HMAC-SHA256 PUF

Automated transport and physical/hardware PUF integration are outside v1 scope.

## November 2026 security-evaluation extension

The original protocol's runtime code is unmodified in the published source archive.
`v1.1.0` adds code used for authorized NSP-insider attack experiments, isolated
SMD retry generators, an optional NSP observer/installer, the independent
Attacker test role, and public summaries of outcomes reported by the operator.
See [`attacks/PC_ATTACKS.md`](attacks/PC_ATTACKS.md) for the exact distinction
between real offline key recovery and untested live retry acceptance.
The original snapshot manifest is preserved as `SOURCE_MANIFEST.v1.sha256`.
