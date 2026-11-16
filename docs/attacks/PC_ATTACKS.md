# PC Security Evaluation — Original Protocol, NSP Insider

**Repository addendum:** PC proof-of-concept experiments completed on 16 November 2026.
**Baseline:** original three-node implementation, unchanged cryptographic protocol.
**Scope:** local, authorized academic evaluation of the researchers' SMD/NSP/TUC instances.

## Roles and deployment

| Logical role | Physical machine in the tested PC setup | What it does |
|---|---|---|
| SMD | SMD Linux PC | Produces authenticated/encrypted registration and session requests using its existing enrolled keys. |
| NSP | NSP Linux PC | Legitimately decrypts and validates H1/V1; is the **honest-but-curious insider attacker** in Attacks 1–3. |
| TUC | TUC Linux PC | Performs legitimate initial enrollment/utility functions. |
| Attacker (independent test role) | May be a separate process on the TUC PC | Offline algebraic self-tests and optional analysis of authorized exported observation records; **not** the attacker used in the three reported NSP-insider proofs. |

These four roles do not require four computers. Distinct OS processes do not by themselves provide security isolation. The independent Attacker role must not acquire TUC private credentials simply because it runs on the same PC.

## Threat model, actual exposure, and algebra

The original protocol reuses the same secret scalar `a_SMD` (with on-chain public commitment `A_SMD = a_SMD * G`) in both authentication-token families:

```text
H1_SMD = (e0 * sk_SMD + a_SMD) mod n
V1_SMD = (e1 * sk_SMD + a_SMD) mod n
```

Here `e0` is the structured SHA-256 challenge for Phase 2; `e1` is the structured SHA-256 challenge for Phase 3; `n` is the order of NIST P-256. Both are computed with the actual repository's **four-byte big-endian length-prefixed** field encoding. For two token/challenge pairs `(T_i, e_i)` and `(T_j, e_j)` sharing the same `a_SMD`, and with `e_i != e_j (mod n)`, the constant term can be eliminated:

```text
sk_candidate = ((T_i - T_j) * inverse(e_i - e_j, n)) mod n
a_candidate  = (T_i - e_i * sk_candidate) mod n
```

The proof checks `sk_candidate * G == PK_SMD` and `a_candidate * G == A_SMD`, **without importing the SMD private-key file into the NSP-side recovery scripts**. The candidate scalars are not printed or written in the reported runs. Computing this candidate is not equivalent to proving any additional impersonation, PFS, or KCI attack; those require separate demonstrations/analyses.

In Phase 2, the authorized NSP obtains `H1_SMD` by decrypting `C1_SMD`. In Phase 3, it obtains `V1_SMD` and the challenge inputs by decrypting `E_SMD` and using its enrolled state. **This is not a passive wiretap attack:** an external observer ordinarily sees encrypted messages, not these plaintext authentication tokens.

## Three experiments completed

| ID | Inputs | Where key recovery ran | Reported result | Interpretation |
|---|---|---|---|---|
| **Attack 1** | One archived real Phase 2 request and one archived real Phase 3 request from the same SMD | NSP PC | **PASS** | Offline recovery from two valid, NSP-decrypted tokens; archival state and matching public keys verified. |
| **Attack 2** | Two newly generated authentic **encrypted** registration requests with distinct `RT_SMD` and the same enrolled `sk_SMD`/`a_SMD` | NSP PC | **PASS** | NSP decrypted and checked two H1 equations; online registration-retry acceptance, timestamp freshness, and current revocation **not tested**. |
| **Attack 3** | Two authentic encrypted Phase 3 attempts from the SMD retry lab, sharing one `RID_SMD` but using fresh randomness | NSP PC | **PASS** | NSP decrypted and checked two V1 equations; online session/retry acceptance and current revocation **not tested**. |

All three recorded executions produced the **same public-key SHA-256 prefix**: `e19a731464ffb8ee57bb` (20 hexadecimal characters). The NSP-side recovery tools did not access the SMD private-key file. The findings below are based on laboratory terminal records; the public repository contains the code and outcome summaries, but not the original private runtime inputs or evidence files.

### Archived evidence digests

The SHA-256 digests below were recorded on the NSP host after the experiments. They identify the original private terminal logs retained on that machine, not the public result summaries.

| File on NSP (`~/tdsc-attack-lab/evidence/pc_attack_results_HDj8MUkl/`) | Reported SHA-256 |
|---|---|
| `attack1_result.txt` | `6252a9abb58496aba3d8115f9f62ffab8f7a761304bfa1b5f73decb5add98e21` |
| `attack2_result.txt` | `60168641eb5e4794226eb85905aaab4d329868bf1e8e5d9478f5d8c02fa27b3f` |
| `attack3_result.txt` | `c85ff0e2c0661b261de6fac0d5f366be47dcc792babb879be555e8bf9060f79b` |

To verify log integrity, recompute SHA-256 over the original NSP logs. Archived-request evaluation must be distinguished from acceptance in a fresh online session.

## Reproducing the software checks

**All commands below operate on local machines already provisioned with the original protocol runtime state.** The public repository does not contain SMD/NSP secret keys or previous real ciphertext/state files. The synthetically generated checks require only Python 3 and `cryptography`; the real archived attacks additionally require the authorized NSP's local private runtime input files.

```bash
# On the SMD PC, synthetic algebra and generation of real (but offline) registration retry requests:
python3 tools/attack2_smd_registration_retry_lab.py --self-test
python3 tools/attack2_smd_registration_retry_lab.py

# On the NSP PC, standalone algebraic tests (no real runtime state required):
python3 tools/attack2_nsp_registration_retry_offline.py --self-test
python3 tools/attack3_nsp_retry_archive.py --self-test

# Independent attacker node: synthetic test suite, does not contact NSP/TUC/Solana:
python3 attacker/src/attacker_node.py --self-test
python3 -m unittest discover -s attacker/tests -v

# On the NSP PC *with the archived, original NSP runtime inputs present*:
python3 tools/inspect_archived_phase2_phase3.py
python3 tools/attack1_nsp_archived.py
python3 tools/attack2_nsp_registration_retry_offline.py --bundle "$HOME/Downloads/attack2_requests.tar.gz"
python3 tools/attack3_nsp_retry_archive.py --bundle "$HOME/Downloads/tdsc_attack3_requests_20261026.tar.gz"
```

The two `--bundle` paths refer to private archives exported on the SMD PC; they are not part of this public ZIP. For Attack 3, the SMD Phase 3 retry generator was executed locally before the archive was packaged. **Its `phase3_retry_lab.py` generator and its private runtime outputs were not present in the original GitHub ZIP supplied for this merge and are not included here.** Do not claim full reproduction of that generation step from this public snapshot alone.

For optional *future live* observations: see [`README-LAB.md`](README-LAB.md) and `tools/enable_attack_observation.py`. The released NSP `phase2_verify_request.py` and `phase3_verify_request.py` are the original uninstrumented versions; run `--check` first and explicitly choose whether to patch with backups on the relevant NSP PC.

## Methodology and limitations

1. Attacks 1–3 were **local offline cryptographic recovery experiments** using genuine SMD-originated requests and authorized NSP decryption, not real-time penetration tests of a third-party service.
2. The reported pass for Attack 2 does **not** establish acceptance of a second registration by the live NSP. Attack 3 does **not** establish acceptance of a repeated Phase 3 request, either. The two requests in each experiment were valid under the tested equations.
3. The experiments do **not** establish passive eavesdropper exploitation, post-revocation acceptance, de-synchronization, automatic retries, KCI exploitation, or a PFS break in a fully specified forward-secrecy game.
4. The baseline repository models PUF with HMAC-SHA256, not an intrinsic physical PUF.
5. Existing Phase 2/3 runtime data and private NSP key remain local; GitHub must not be treated as a secret-key archive. Original evidence logs are retained on the NSP host and identified by the recorded digests above.
6. The separate `attacker/` implementation passed synthetic tests on the TUC machine; the actual three insider proofs used NSP-local `tools/attack*` scripts. These are distinct validation paths.

## Next research stages

First complete and publish the **PC experiment code + documentation**, then port **only SMD** to a resource-constrained MCU while NSP/TUC/Attacker remain on PCs, and repeat security and performance measurements with the same assumptions and new hardware readings. **Only after these baselines** should a revised protocol be proposed and evaluated against the same attacks and explicit resource limits.

### Original supporting instructions

- [`README-ATTACK1-NSP.md`](README-ATTACK1-NSP.md)
- [`README-ATTACK2-NSP.md`](README-ATTACK2-NSP.md)
- [`README-ATTACK3-NSP.md`](README-ATTACK3-NSP.md)
- [`README-LAB.md`](README-LAB.md)
- [`../../attacker/README.md`](../../attacker/README.md)
