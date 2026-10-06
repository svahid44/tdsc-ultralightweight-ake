# Protocol-to-Code Mapping

| Paper steps | Role | Experiment entry point | Purpose |
|---|---|---|---|
| Phase 0 | all | configuration/key setup | Cryptographic and node setup |
| 1-3 | SMD | Phase-1 setup scripts | Generate `a_SMD`, `A_SMD`, `PK_SMD` |
| 4-7 | TUC | `phase1_prepare.py` + Solana scripts | Generate `EID_SMD`, insert record |
| 8-10 | SMD | `phase2_create_request.py` | Build `C1` |
| 11-14 | NSP | `phase2_verify_request.py` | Decrypt, freshness, ledger, verify `H1` |
| 15-19 | NSP | `phase2_create_response.py` | Generate RID/randomness/tokens/`C_NSP` |
| 20-26 | SMD | `phase2_process_nsp_response.py` | Verify NSP, simulated PUF, store `S_SMD`, build `C2` |
| 27-30 | NSP | `phase2_finalize_registration.py` | Verify `H2`, protect/store `S_NSP` |
| 31-34 | SMD | `phase3_create_request.py` | Recover state, generate `V1`, `E_SMD` |
| 35-42 | NSP | `phase3_verify_request.py` | Local state, Solana `RS_SMD`, verify `V1` |
| 43-49 | NSP | `phase3_create_response.py` | Fresh RID/randomness/session key/response |
| 50-58 | SMD | `phase3_process_response.py` | Derive key, verify NSP, rotate state, create `V2` |
| 59-61 | NSP | `phase3_finalize_session.py` | Verify `V2`, delete old RID, finalize |
| Revocation | NSP/TUC | `revoke_smd.py` | Set `RS_SMD=1` |

After importing the exact executed source, update this table only if the real filenames differ.

## Negative revocation test

After Session 2, the on-chain record was changed to `RS_SMD=1`. A next-session request using valid local rotated state was rejected by NSP at the ledger check:

```text
RS_SMD: 1
RuntimeError: SMD is revoked
```
