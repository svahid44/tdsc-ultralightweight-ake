# NSP Observation Instrumentation

Only for authorized testing of the user's own NSP/SMD environment.

**Run on the authorized NSP host.** The observation module is included at
`nsp/src/attack_observer.py` and has no third-party dependencies. The patcher
adds opt-in hooks **after** the normal `STATE_PATH` verified-state checkpoint;
no normal protocol behavior changes when `TDSC_ATTACK_LAB` is unset.

First read-only check:

```bash
cd ~/tdsc-protocol
python3 tools/enable_attack_observation.py --check
```

After reviewing the check result, apply once:

```bash
python3 tools/enable_attack_observation.py --apply
```

The patcher backs up the original verifier scripts to `~/tdsc-attack-lab/backups/<UTC>/`
(outside Git, mode 0700/0600). It does not execute a protocol session.

Later, opt in for a fresh *authorized* protocol verification run, using the
same existing instructions and paths as before, but prefixed with the variable:

```bash
TDSC_ATTACK_LAB=1 python3 nsp/src/phase2_verify_request.py
# (after the rest of Phase2 workflow)
TDSC_ATTACK_LAB=1 python3 nsp/src/phase3_verify_request.py
```

**Do not run the verifiers yet** unless your new session state and on-chain
revocation status are ready. Existing phase2/3 verified states may refuse new
sessions; never delete them without an explicit archival plan.

Observation records: `~/tdsc-attack-lab/nsp/phase2_*.json` and
`phase3_*.json`. They contain *sensitive verified tokens and hash inputs*,
not private keys. They must not be committed or shared publicly. Transfer only
via an authorized private channel to the TUC PC. The Attacker CLI can consume
them using `--first` and `--second` (it does not require the records to live
inside the repository). Keep raw observations and recovered secrets out of Git.
