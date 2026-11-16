# Attack 3: NSP insider from two SMD Phase 3 retry requests

Scope: a **local authorized security lab**. Uses the two genuine requests produced
by the SMD retry-lab at `20261026T112940Z`. No live protocol execution, DB
mutation, connection to Solana, or copying of SMD private keys.

## 1. On the SMD PC

```bash
cd ~/tdsc-protocol || exit 1
umask 077
BUNDLE="$HOME/Downloads/tdsc_attack3_requests_20261026.tar.gz"
if [ -e "$BUNDLE" ]; then echo "Bundle already exists — not overwriting"; exit 1; fi
tar -czf "$BUNDLE" -C smd/data/phase3_retry_lab/20261026T112940Z \
  attempt_001/request.json attempt_002/request.json
chmod 600 "$BUNDLE"
ls -lh "$BUNDLE"
```

Transfer **only that bundle** to the NSP PC via trusted USB/SCP. Do not put it
in a Git repository or paste it into chat. Keep the transfer media protected.

## 2. On the NSP PC

From the NSP repository, run the synthetic check followed by the archived-request analysis:

```bash
cd ~/tdsc-protocol || exit 1
PYTHONDONTWRITEBYTECODE=1 python3 tools/attack3_nsp_retry_archive.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 tools/attack3_nsp_retry_archive.py \
  --bundle "$HOME/Downloads/tdsc_attack3_requests_20261026.tar.gz"
```

Requires `cryptography` and existing `tools/inspect_archived_phase2_phase3.py`
(previous archived probe). Its successful run on NSP was already confirmed.

Only report pass/fail lines and the *public key* fingerprint. The output never
prints or saves recovered private scalars. A pass supports the NSP-insider
key-recovery experiment for two archived SMD messages, **not** live acceptance,
revocation state, or success for a passive network observer.

## SMD-side retry-request generation

The SMD retry-request generator is available at
`smd/src/phase3_retry_lab.py`.

On a configured SMD host, execute
`python3 smd/src/phase3_retry_lab.py --attempts 3`.

The generator creates independent Phase 3 authentication
requests using the existing SMD registration and session
materials. The generated requests are stored locally
and are not submitted to the NSP.

Two requests from the same run can be used for offline
key-recovery analysis by an NSP possessing the matching
archived registration and session information.

This experiment demonstrates offline private-key recovery;
it does not establish live acceptance of repeated requests.
