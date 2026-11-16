# Independent Attacker Role

**Scope:** offline algebraic recovery using two authorized NSP-side observations. Does not communicate with SMD/NSP or Solana, read private keys, alter existing state, or claim success against a live target by itself.

## Where to run

The standalone **fourth logical Attacker node** may run on the TUC PC in a separate process and directory; it must not use TUC secrets. For the three **NSP-insider** proofs, run the NSP-side tools on the NSP PC itself. The independent Attacker CLI can instead process specifically exported, authorized NSP observations. Never give it `sk_SMD` as an input. Do not place its code in the operational NSP code paths. Python dependency: `cryptography` (already used by NSP).

```bash
cd ~/tdsc-protocol
python attacker/src/attacker_node.py --self-test
```

The self-test uses new random *synthetic* secrets and records, exercises all three equations, and rejects a tampered token. Passing this test is **not** proof of a live attack.

## NSP observation records

The real experiment must capture data **only after** `verify_h1` in `nsp/src/phase2_verify_request.py` and `verify_v1` in `nsp/src/phase3_verify_request.py` return true, after successful on-chain and revocation checks. Those scripts currently don't persist the H1/V1 token in their verified JSON state. Optional NSP instrumentation is available separately in `nsp/src/attack_observer.py` and `tools/enable_attack_observation.py`; it was used on the local NSP and is not automatically enabled in this published archive. Don't make up the tokens from SMD's private key.

JSON record schema: `tdsc-nsp-observation-v1`. All Base64 fields use URL-safe Base64 of **raw bytes**; `eid_smd` and `id_nsp` are UTF-8 strings; `t_smd` is the integer timestamp.

- Shared: `schema`, `phase` (`phase2` or `phase3`), `verification` (`PASS`), `eid_smd`, `pk_smd_sec1` and `a_smd_sec1` (SEC1 public points in Base64).
- Phase 2: `rt_smd` (32 raw bytes, Base64), `t_smd` (integer), `h1_smd` (32 bytes, Base64).
- Phase 3: `rid_smd` (32 bytes, Base64), `id_nsp` (UTF-8), `r_smd` (32 bytes, Base64), `st_smd` (32 bytes, Base64), `v1_smd` (32 bytes, Base64).

**Observation example using placeholders only:**

```json
{"schema":"tdsc-nsp-observation-v1","verification":"PASS","phase":"phase2","eid_smd":"<from NSP>","pk_smd_sec1":"<base64 SEC1>","a_smd_sec1":"<base64 SEC1>","rt_smd":"<base64 32 bytes>","t_smd":1790000000,"h1_smd":"<base64 32 bytes>"}
```

## Attack CLI after observations have been collected

Run on a trusted lab machine after collecting two observations. These sample paths use `nsp/data/attack_lab`, which is excluded by the repository `.gitignore`; on the separate Attacker host use an equivalent private directory outside the repository. Pass two existing observation files (the program never generates or changes them):

```bash
# Attack 1: Phase2 observation + Phase3 observation
python attacker/src/attacker_node.py --attack 1 \
  --first nsp/data/attack_lab/phase2_001.json \
  --second nsp/data/attack_lab/phase3_001.json \
  --report nsp/data/attack_lab/attack1_report.json

# Attack 2: two distinct Phase2 observations
python attacker/src/attacker_node.py --attack 2 \
  --first nsp/data/attack_lab/phase2_001.json \
  --second nsp/data/attack_lab/phase2_002.json \
  --report nsp/data/attack_lab/attack2_report.json

# Attack 3: two distinct Phase3 observations
python attacker/src/attacker_node.py --attack 3 \
  --first nsp/data/attack_lab/phase3_001.json \
  --second nsp/data/attack_lab/phase3_002.json \
  --report nsp/data/attack_lab/attack3_report.json
```

Reports contain only non-secret results and public-key hashes. `PASS` means recovered candidate matches `PK_SMD` and recovered offset matches `A_SMD`. The attacker obtains `sk` solely from the two given token/challenge pairs; no SMD private key is loaded. *Evidence provenance* (NSP decryption, verification, timestamps, code versions) must be documented independently.

Optional private evidence (never commit or paste in chat): `--private-output nsp/data/attack_lab/recovered_private.json`. The flag writes with mode `0600` and refuses overwrites.

## Threat model and limitations

This is an **NSP-accessible plaintext** attack. A passive network eavesdropper sees encrypted `C1_SMD` and `E_SMD`, not automatically H1/V1 and the phase-3 hash inputs. Phase-2 retry also must be explicitly supported and tested by the protocol's operational workflow; do not confuse synthetic success with a demonstrated retry exploit.

The implementation hashes fields using SHA-256 and four-byte big-endian per-field length prefixes, matching the repository's Phase 2/3 functions. This differs from concatenation in the preliminary `key_recovery.py` sample.

Do not upload any observation file, raw recovered key, session secret, live NSP database, or test private key. Existing `.gitignore` excludes all `**/data/` paths, but check `git status` and `scripts/audit_secrets.py` before publishing.
