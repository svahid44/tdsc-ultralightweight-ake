#!/usr/bin/env python3
"""Offline Attack 2 on authorized NSP: recover SMD scalar from two C1 messages.

Uses archived NSP public registration state and NSP's own authorized local key.
No access to sk_SMD/a_SMD files, no writes, network calls, or secret output.
This is an insider decryption/algebraic experiment, not live registration acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from inspect_archived_phase2_phase3 import N, b64, h_fields, pt, verify

NAMES = ('attempt_001/request.json', 'attempt_002/request.json')


def require(ok: bool, label: str) -> None:
    if not ok:
        raise RuntimeError(label)
    print('[PASS]', label)


def read_bundle(path: Path) -> list[dict]:
    if not path.is_file() or path.stat().st_size > 128*1024:
        raise ValueError('Missing or oversized input bundle')
    with tarfile.open(path, 'r:gz') as tf:
        members = tf.getmembers()
        if sorted(m.name for m in members) != sorted(NAMES):
            raise ValueError('Exactly two registration requests required')
        if any(not m.isfile() or not 1 <= m.size <= 32*1024 for m in members):
            raise ValueError('Invalid tar member')
        result = []
        for name in NAMES:
            stream = tf.extractfile(name)
            if stream is None:
                raise ValueError('Unreadable tar member')
            request = json.loads(stream.read().decode('utf-8'))
            if not isinstance(request, dict) or not isinstance(request.get('c1_smd'), str):
                raise ValueError('Missing C1_SMD')
            result.append(request)
        return result


def decrypt_c1(c1_text: str, sk: ec.EllipticCurvePrivateKey) -> dict:
    pkg = b64(c1_text)
    if len(pkg) < 61 or len(pkg) > 32768:
        raise ValueError('Invalid C1_SMD size')
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), pkg[:33])
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b'TDSC-AENC-C1-v1').derive(sk.exchange(ec.ECDH(), eph_pub))
    plain = AESGCM(aes_key).decrypt(pkg[33:45], pkg[45:], b'TDSC-C1-SMD-NSP-v1')
    return json.loads(plain.decode('utf-8'))


def public_matches_scalar(val: int, point: tuple[int, int]) -> bool:
    if not 1 <= val < N:
        return False
    return pt(ec.derive_private_key(val, ec.SECP256R1()).public_key()) == point


def run(root: Path, bundle: Path) -> int:
    state_path = root/'nsp/data/phase2_verified_request.json'
    sk_path = root/'nsp/data/sk_nsp.pem'
    if not state_path.is_file() or not sk_path.is_file():
        raise FileNotFoundError('Required NSP registration state or private key missing')

    requests = read_bundle(bundle)
    require(requests[0]['c1_smd'] != requests[1]['c1_smd'],
            'Two distinct real SMD registration ciphertexts loaded (read-only)')
    state = json.loads(state_path.read_text())
    require(state.get('status') == 'SMD_REQUEST_VERIFIED',
            'Archived NSP registration state available')
    pk_raw = b64(state['pk_smd_sec1'])
    pk = pt(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_raw))
    a_pub = pt(ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b64(state['A_smd_sec1'])))
    sk = serialization.load_pem_private_key(sk_path.read_bytes(), password=None)
    require(isinstance(sk, ec.EllipticCurvePrivateKey) and sk.curve.name == 'secp256r1',
            'NSP local authorization key loaded for decryption')

    observations = []
    for i, req in enumerate(requests, 1):
        p = decrypt_c1(req['c1_smd'], sk)
        require(p.get('eid_smd') == state['eid_smd'],
                f'Attempt {i}: same registered SMD identity')
        rt, h1 = b64(p['rt_smd']), b64(p['h1_smd'])
        ts = int(p['t_smd'])
        challenge = h_fields(p['eid_smd'].encode('utf-8'), rt,
                             str(ts).encode('ascii'))
        e = int.from_bytes(challenge, 'big') % N
        require(len(rt) == 32 and verify(h1, challenge, pk, a_pub),
                f'Attempt {i}: NSP decrypted C1 and verified H1 equation')
        observations.append((rt, e, int.from_bytes(h1, 'big')))

    (r1, e1, h1), (r2, e2, h2) = observations
    require(r1 != r2 and e1 != e2 and h1 != h2,
            'Distinct RT_SMD, H1 tokens, and scalar challenges')
    recovered_sk = ((h1 - h2) * pow((e1-e2) % N, -1, N)) % N
    recovered_a = (h1 - e1 * recovered_sk) % N
    require(public_matches_scalar(recovered_sk, pk)
            and public_matches_scalar(recovered_a, a_pub)
            and (e1 * recovered_sk + recovered_a) % N == h1
            and (e2 * recovered_sk + recovered_a) % N == h2,
            'ATTACK 2: recovered private scalar and fixed commitment match public points')
    print('\nRESULT: ATTACK 2 PASS — two genuine SMD registration retry requests')
    print('Threat model: semi-trusted NSP insider; offline decryption/verification')
    print('SMD private key file accessed: NO')
    print('Recovered scalars printed/saved: NO')
    print('Solana, database, protocol states modified: NO')
    print('Timestamp freshness, revocation, live acceptance proven: NO')
    print('Public-key SHA-256 fingerprint:', hashlib.sha256(pk_raw).hexdigest()[:20])
    return 0


def self_test() -> int:
    s, a = 337, 233
    e1, e2 = 17, 113
    h1, h2 = (e1*s+a)%N, (e2*s+a)%N
    rec = (h1-h2)*pow((e1-e2)%N, -1, N)%N
    pub = pt(ec.derive_private_key(s, ec.SECP256R1()).public_key())
    require(rec == s and public_matches_scalar(rec,pub),
            'Synthetic registration retry algebra and public-key check')
    print('SELF-TEST PASSED — synthetic only')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.bundle is None:
        parser.error('--bundle required unless --self-test')
    return run(args.root.resolve(), args.bundle.resolve())


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'[FAIL] Attack 2 NSP lab stopped ({type(exc).__name__}); no secrets printed',
              file=sys.stderr)
        raise SystemExit(2)
