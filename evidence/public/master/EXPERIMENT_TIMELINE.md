# Experiment Timeline

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
