#!/usr/bin/env python3
"""Offline SMD lab: create two genuine encrypted Phase 2 requests from original material.

Reads SMD's existing Phase 1 state, sk_SMD, and fixed a_SMD.  Writes only to
~/tdsc-attack-lab/smd/phase2_retry (outside Git); never runs the original Phase 2
script, changes pending/export state, or contacts NSP/TUC/Solana.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import struct
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

N = int('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16)


def h_scalar(eid: str, rt: bytes, ts: int) -> int:
    h = hashlib.sha256()
    for field in (eid.encode('utf-8'), rt, str(ts).encode('ascii')):
        h.update(struct.pack('>I', len(field)))
        h.update(field)
    return int.from_bytes(h.digest(), 'big') % N


def require(condition: bool, label: str) -> None:
    if not condition:
        raise RuntimeError(label)
    print('[PASS]', label)


def run(root: Path, out_base: Path) -> int:
    # Import the exact asymmetric encryption implementation used by SMD.
    sys.path.insert(0, str(root))
    from shared.asym_crypto import encrypt_for_nsp

    phase1 = json.loads((root / 'smd/data/phase1_state.json').read_text())
    require(phase1.get('status') == 'PHASE1_COMPLETED', 'Original Phase 1 state available')
    eid, pk_nsp_pem = phase1['eid_smd'], phase1['pk_nsp_pem']

    sk = serialization.load_pem_private_key(
        (root / 'smd/data/sk_smd.pem').read_bytes(), password=None)
    require(isinstance(sk, ec.EllipticCurvePrivateKey)
            and sk.curve.name == 'secp256r1', 'Original SMD P-256 key loaded locally')
    s = sk.private_numbers().private_value
    a_raw = (root / 'smd/data/a_smd.key').read_bytes()
    a = int.from_bytes(a_raw, 'big')
    require(len(a_raw) == 32 and 1 <= a < N, 'Original fixed a_SMD available')

    # Additional consistency check if the public commitment is present.
    A_path = root / 'smd/data/A_smd.pem'
    if A_path.is_file():
        A = serialization.load_pem_public_key(A_path.read_bytes())
        expected = ec.derive_private_key(a, ec.SECP256R1()).public_key().public_numbers()
        require(isinstance(A, ec.EllipticCurvePublicKey)
                and A.curve.name == 'secp256r1'
                and A.public_numbers() == expected, 'Fixed a_SMD matches public commitment')

    os.umask(0o077)
    out_base.mkdir(parents=True, exist_ok=True, mode=0o700)
    if out_base.is_symlink():
        raise ValueError('Output base may not be a symlink')
    run_dir = Path(tempfile.mkdtemp(prefix='run_', dir=str(out_base)))
    attempts = []
    for i in (1, 2):
        adir = run_dir / f'attempt_{i:03d}'
        adir.mkdir(mode=0o700)
        for _ in range(16):
            rt = secrets.token_bytes(32)
            ts = int(time.time())
            e = h_scalar(eid, rt, ts)
            h1 = (e * s + a) % N
            if 1 <= h1 < N and (not attempts or (rt, e) != (attempts[0][0], attempts[0][1])):
                break
        else:
            raise RuntimeError('Failed to obtain fresh registration challenge')
        payload = {
            'eid_smd': eid,
            'rt_smd': base64.urlsafe_b64encode(rt).decode('ascii'),
            'h1_smd': base64.urlsafe_b64encode(h1.to_bytes(32, 'big')).decode('ascii'),
            't_smd': ts,
        }
        c1 = encrypt_for_nsp(pk_nsp_pem, payload)
        with (adir / 'request.json').open('x', encoding='utf-8') as stream:
            stream.write(json.dumps({'c1_smd': c1}, indent=2) + '\n')
        attempts.append((rt, e))
    require(attempts[0][0] != attempts[1][0]
            and attempts[0][1] != attempts[1][1], 'Distinct RT_SMD and H1 challenges generated')

    bundle = run_dir / 'attack2_requests.tar.gz'
    with tarfile.open(bundle, 'x:gz') as tar:
        for i in (1, 2):
            path = run_dir / f'attempt_{i:03d}/request.json'
            tar.add(path, arcname=f'attempt_{i:03d}/request.json', recursive=False)
    bundle.chmod(0o600)
    pk_bytes = sk.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    print('[PASS] Two authentic encrypted registration requests stored outside Git')
    print('Public-key SHA-256 fingerprint:', hashlib.sha256(pk_bytes).hexdigest()[:20])
    print('BUNDLE FOR NSP:', bundle)
    print('SMD private key and token scalars printed/saved: NO')
    print('Existing SMD pending/export files modified: NO')
    print('NSP / Solana contacted: NO')
    print('NOTE: Requests were generated offline, NOT accepted as live registrations')
    return 0


def self_test() -> int:
    from cryptography.hazmat.primitives.asymmetric import ec
    s, a, rt1, rt2, eid, ts = 4919, 3271, b'\x01'*32, b'\x02'*32, 'TEST-EID', 1780000000
    e1 = h_scalar(eid, rt1, ts)
    e2 = h_scalar(eid, rt2, ts)
    h1 = (e1*s+a) % N
    h2 = (e2*s+a) % N
    k = ((h1-h2)*pow((e1-e2)%N, -1, N))%N
    require(k == s and e1 != e2
            and ec.derive_private_key(k, ec.SECP256R1()).public_key().public_numbers()
            == ec.derive_private_key(s, ec.SECP256R1()).public_key().public_numbers(),
            'Synthetic registration-retry algebra')
    print('SELF-TEST PASSED — synthetic only')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--out-base', type=Path,
                        default=Path.home()/'tdsc-attack-lab/smd/phase2_retry')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return run(args.root.resolve(), args.out_base.expanduser())


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'[FAIL] Attack 2 SMD lab stopped ({type(exc).__name__}); no secrets printed',
              file=sys.stderr)
        raise SystemExit(2)
