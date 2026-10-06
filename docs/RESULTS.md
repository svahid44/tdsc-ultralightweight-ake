# Functional Results

| Test | Result |
|---|---|
| Phase 1 | PASS |
| Phase 2 | PASS |
| Phase 3 Session 1 | PASS |
| Phase 3 Session 2 | PASS |
| Session 2 without re-registration | PASS |
| SMD/NSP key equality | PASS |
| Fresh keys between sessions | PASS |
| RID/state rotation | PASS |
| Old RID deletion | PASS |
| On-chain revocation | PASS |
| Post-revocation Session 3 | REJECTED AS EXPECTED |

## Session-key fingerprints

```text
Session 1 SHA-256:
c1921fbf5888db250c1ac63908a72e2362a19b2bc99fca0eb570cef19528bef4

Session 2 SHA-256:
3d0ba378727b037c0dfbe57b5c9a62a2b96355e3123e5f2f20da25718398a1f6
```

Raw session keys are not published. Within each successful session, SMD and NSP fingerprints matched. The two sessions were distinct.

## Revocation
The completed Solana transaction changed `RS_SMD` from `0` to `1`. A subsequent Phase-3 request reached the ledger check and was rejected with `RuntimeError: SMD is revoked`.
