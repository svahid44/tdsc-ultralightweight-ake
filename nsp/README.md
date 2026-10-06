# NSP

Neighborhood Service Provider implementation.

The NSP handles Phase-2 registration, Phase-3 request verification, Solana revocation checks, session-key derivation, RID rotation, final acknowledgement processing, and the local SQLite-backed SMD state.

Private EC keys, wallet key material, database files, raw `S_NSP`, and raw session keys are excluded from the public repository.
