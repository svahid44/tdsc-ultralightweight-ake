# Attack 2 — NSP-insider recovery using two Phase 2 registration requests

This is an **authorized, offline, local laboratory** for the original TDSC
protocol implementation. It shows that two independently generated registration
messages using the **same enrolled `sk_SMD` and fixed `a_SMD`** can reveal the
private scalar to the honest-but-curious NSP, after normal authorized C1
decryption. It is not a demonstration that registration retries are accepted by
live NSP or by the Solana ledger. Session freshness, revocation and replay
policy are **not evaluated**.

## On the SMD PC

From the repository root:

```bash
cd ~/tdsc-protocol || exit 1
source .venv/bin/activate  # only if a .venv exists
PYTHONDONTWRITEBYTECODE=1 python3 tools/attack2_smd_registration_retry_lab.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 tools/attack2_smd_registration_retry_lab.py
```

The generator **reads** original Phase 1 state, `sk_smd.pem`, `a_smd.key`,
optional public commitment `A_smd.pem`, and uses the repository's
`shared/asym_crypto.py`. It never imports `phase2_create_request.py` because
that script has top-level side effects and overwrite guards.

Each invocation creates a new private run directory outside the Git repo:

```text
~/tdsc-attack-lab/smd/phase2_retry/run_.../
  attempt_001/request.json
  attempt_002/request.json
  attack2_requests.tar.gz
```

The two `request.json` files contain only encrypted `C1_SMD` values. Transfer
**only** the `attack2_requests.tar.gz` file privately to NSP's Downloads
folder; do not upload it to GitHub or send it to a chat. The tool prints the
bundle's full local path. The SMD private key and plaintext tokens stay local.

## On the NSP PC

```bash
cd ~/tdsc-protocol || exit 1
PYTHONDONTWRITEBYTECODE=1 python3 tools/attack2_nsp_registration_retry_offline.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 tools/attack2_nsp_registration_retry_offline.py \
  --bundle "$HOME/Downloads/attack2_requests.tar.gz"
```

Dependencies: `cryptography` and the existing NSP archival helper
`tools/inspect_archived_phase2_phase3.py` (used to validate archived NSP inputs). The NSP tool accesses its own private authentication key to decrypt
`C1_SMD` locally and loads the **previously verified** SMD public key and
commitment from `nsp/data/phase2_verified_request.json`. It neither reads
`sk_SMD` nor contacts Solana, writes a database, changes protocol state, or
prints recovered private scalars.

Expected checks: two decryptions succeed, both H1 verification equations hold,
the challenge scalars differ, and the recovered scalar matches the archived
public P-256 key. Keep pass/fail logs as evidence (no secret values). Confirm
that the public-key SHA-256 fingerprint matches Attack 1 and Attack 3.

## Interpretation

- **Claim supported:** algebraic private-key recovery by an insider NSP that
  has obtained two valid plaintext H1 tokens for the same fixed commitment.
- **Claim not supported:** that two registration requests are simultaneously
  accepted by a live NSP, that a retry automatically happens, or that an
  external passive eavesdropper can recover this key.
- **Safety:** no overwrite of production pending/export paths. Keep private
  bundles and runtime state outside the repository and do not `git add -A`.
