#!/usr/bin/env python3
"""Read-only offline diagnostics for archived TDSC NSP Phase 2/3 requests.

Does not import protocol scripts (those have top-level asyncio.run(main())).
Does not alter files, contact Solana, or print secrets/tokens/identifiers.
Uses the exact encodings, AES-GCM AAD, and hashing as original NSP code.
This is archival verification, NOT a live acceptance or a key-recovery proof.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path.cwd()
N = int('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16)
P = int('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF', 16)


def b64(s):
    if not isinstance(s, str):
        raise ValueError('Expected Base64 string')
    return base64.urlsafe_b64decode((s + '=' * (-len(s) % 4)).encode('ascii'))


def h_fields(*fields):
    h = hashlib.sha256()
    for field in fields:
        h.update(struct.pack('>I', len(field)))
        h.update(field)
    return h.digest()


def pt(key):
    x = key.public_numbers()
    return (x.x, x.y)


def add(a, b):
    if a is None: return b
    if b is None: return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if a == b:
        if y1 == 0: return None
        lam = ((3*x1*x1 - 3) * pow(2*y1, -1, P)) % P
    else:
        lam = ((y2-y1) * pow(x2-x1, -1, P)) % P
    x3 = (lam*lam-x1-x2) % P
    return (x3, (lam*(x1-x3)-y1) % P)


def mul(k, a):
    acc = None
    while k:
        if k & 1: acc = add(acc, a)
        a = add(a, a)
        k >>= 1
    return acc


def verify(token, digest, pk, commitment):
    v = int.from_bytes(token, 'big')
    e = int.from_bytes(digest, 'big') % N
    if len(token) != 32 or not 1 <= v < N: return False
    lhs = pt(ec.derive_private_key(v, ec.SECP256R1()).public_key())
    return lhs == add(mul(e, pk), commitment)


def check(ok, label):
    print(('[PASS] ' if ok else '[FAIL] ') + label)
    if not ok: raise RuntimeError('Diagnostic check failed')


def main():
    required = (
        'nsp/data/sk_nsp.pem',
        'nsp/data/phase2_verified_request.json',
        'nsp/import/phase2_C1_SMD.json',
        'nsp/import/phase3_request.json',
        'nsp/data/nsp.db',
        'nsp/config/node.conf',
    )
    missing = [p for p in required if not (ROOT / p).is_file()]
    if missing:
        print('[CHECK] Missing inputs (paths only):', ', '.join(missing))
        return 1
    sk = serialization.load_pem_private_key((ROOT/'nsp/data/sk_nsp.pem').read_bytes(), password=None)
    if not isinstance(sk, ec.EllipticCurvePrivateKey) or sk.curve.name != 'secp256r1':
        raise RuntimeError('Unexpected NSP private-key type')

    state = json.loads((ROOT/'nsp/data/phase2_verified_request.json').read_text())
    c1 = json.loads((ROOT/'nsp/import/phase2_C1_SMD.json').read_text())
    package = b64(c1['c1_smd'])
    if len(package) < 61: raise RuntimeError('Invalid C1 package size')
    ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), package[:33])
    aes_c1 = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                  info=b'TDSC-AENC-C1-v1').derive(sk.exchange(ec.ECDH(), ephemeral))
    p2 = json.loads(AESGCM(aes_c1).decrypt(package[33:45], package[45:],
                                            b'TDSC-C1-SMD-NSP-v1'))
    check(state.get('status') == 'SMD_REQUEST_VERIFIED'
          and p2['eid_smd'] == state['eid_smd']
          and p2['rt_smd'] == state['rt_smd']
          and int(p2['t_smd']) == int(state['t_smd']),
          'Archived registration C1 matches previously verified NSP state')
    pk = pt(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64(state['pk_smd_sec1'])))
    a = pt(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b64(state['A_smd_sec1'])))
    rt, h1 = b64(p2['rt_smd']), b64(p2['h1_smd'])
    e0 = h_fields(p2['eid_smd'].encode(), rt, str(int(p2['t_smd'])).encode())
    check(len(rt) == 32 and verify(h1, e0, pk, a),
          'Archived H1 equation verifies against saved public keys (offline)')

    req = json.loads((ROOT/'nsp/import/phase3_request.json').read_text())
    rid = b64(req['rid_smd'])
    if len(rid) != 32: raise RuntimeError('Invalid RID size')
    db_uri = f'file:{(ROOT/"nsp/data/nsp.db").resolve().as_posix()}?mode=ro'
    with sqlite3.connect(db_uri, uri=True) as conn:
        row = conn.execute('SELECT s_nsp FROM smd_records WHERE rid_smd = ? LIMIT 1',
                           (req['rid_smd'],)).fetchone()
    check(row is not None, 'Archived session RID found in NSP database')
    sk_scalar = sk.private_numbers().private_value.to_bytes(32, 'big')
    aes_store = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                     info=b'TDSC-NSP-SENC-v1').derive(sk_scalar)
    s_nsp = bytes(row[0])
    if len(s_nsp) < 28: raise RuntimeError('Invalid S_NSP size')
    secret = json.loads(AESGCM(aes_store).decrypt(s_nsp[:12], s_nsp[12:],
                                                b'TDSC-S-NSP-v1'))
    r_nsp = b64(secret['r_nsp'])
    dt = h_fields(rid, r_nsp)
    e_pkg = b64(req['e_smd'])
    if len(e_pkg) < 28: raise RuntimeError('Invalid E_SMD size')
    p3 = json.loads(AESGCM(dt).decrypt(e_pkg[:12], e_pkg[12:],
                                       b'TDSC-E-SMD-v1'))
    check(secret['eid_smd'] == p2['eid_smd'],
          'Same SMD identity in archived registration and session')
    node_lines = (ROOT/'nsp/config/node.conf').read_text().splitlines()
    cfg = dict(line.strip().split('=', 1) for line in node_lines
               if line.strip() and not line.lstrip().startswith('#') and '=' in line)
    id_nsp = cfg['ID_NSP']
    st = h_fields(secret['eid_smd'].encode(), sk_scalar)
    r_smd, v1 = b64(p3['r_smd']), b64(p3['v1_smd'])
    e1 = h_fields(rid, secret['eid_smd'].encode(), id_nsp.encode(), r_smd, st)
    check(len(r_smd) == 32 and verify(v1, e1, pk, a),
          'Archived V1 equation verifies against saved public keys (offline)')
    check((int.from_bytes(e0, 'big') - int.from_bytes(e1, 'big')) % N != 0,
          'Two independent authentication challenges (e0 != e1)')
    print('\n[INFO] No key recovery executed. No secrets or observations printed or saved.')
    print('[INFO] Solana revocation/live acceptance NOT checked (offline archive only).')
    print('[INFO] No protocol state, NSP DB, or Git files were changed.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print('[CHECK] Diagnostic stopped:', type(exc).__name__)
        raise SystemExit(2)
