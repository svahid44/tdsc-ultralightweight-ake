# TDSC — Attack 1 (NSP-side, archived, offline)

## Goal and scope

Run the experiment on the **NSP machine**, because the attacker for this specific scenario is the **semi-trusted NSP itself**. It decrypts packets addressed to itself; this does **not** show that a passive third party can decrypt them. The script reconstructs two equations from **previously archived actual requests** and checks a derived SMD private scalar against the **public** registration key without accessing SMD's private key or printing the recovered scalar.

This is **not** a new live NSP session, not a current Solana revocation check, and not a modification of protocol state.

## Prerequisite

On NSP, `tools/inspect_archived_phase2_phase3.py` must already exist and its previous run must have returned six PASS lines. Existing archive files and their matching DB record must still be present. Python 3 and package `cryptography` are required (as for the previous diagnostic).

## Execution

Run from the repository root on the NSP host, after provisioning the archived local inputs:

```bash
cd ~/tdsc-protocol || exit 1
PYTHONDONTWRITEBYTECODE=1 python3 tools/attack1_nsp_archived.py
```

The program only prints PASS/FAIL and a public-key fingerprint. It never prints or stores secret values or sends network traffic. Do **not** use `tee` with verbose debugging that prints decrypted tokens.

## Research interpretation

* **Attack 1** = archived registration (`H1`) plus session authentication (`V1`), both decrypted by the same legitimate NSP. The fixed `a_SMD` cancels algebraically, allowing recovery of a scalar which is checked against `PK_SMD`, while `a_SMD` is checked against `A_SMD`.
* No knowledge of `sk_SMD` from a file is used. The P-256 public-key checks provide independent evidence.
* A PASS demonstrates the *archived NSP-insider* case. It does not by itself prove current live acceptance or passive wiretap feasibility.
* Attack 2 (two registration runs) and Attack 3 (two session runs) should also be exercised on the NSP side under the appropriate repeat/retry conditions. Do not delete or overwrite older protocol data to create retries.
* All private raw observations stay outside Git. Only redacted reports and reproducible source code are candidates for GitHub after review.
