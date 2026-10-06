from __future__ import annotations

import asyncio
import hashlib
import os
import platform
import statistics
import time

from cryptography import __version__ as cryptography_version
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey






LOCAL_WARMUP = 2000
LOCAL_ITER = 20000

RPC_WARMUP = 2
RPC_ITER = 20

RPC_URL = "https://api.devnet.solana.com"

SMD_PDA = Pubkey.from_string(
    "3M6AXXVAqQgTqoHNmpBdRRApvttym8jBaBwQwcAEGiDw"
)

HASH_PAYLOAD = os.urandom(192)
AES_PLAINTEXT = os.urandom(160)
AES_AAD = b"TDSC-NSP-benchmark-v1"

AES_KEY = AESGCM.generate_key(bit_length=256)
AES = AESGCM(AES_KEY)

DEC_NONCE = os.urandom(12)
DEC_CT = AES.encrypt(
    DEC_NONCE,
    AES_PLAINTEXT,
    AES_AAD,
)


curve = ec.SECP256R1()
priv = ec.generate_private_key(curve)
peer_priv = ec.generate_private_key(curve)
peer_pub = peer_priv.public_key()



P256_P = int(
    "FFFFFFFF000000010000000000000000"
    "00000000FFFFFFFFFFFFFFFFFFFFFFFF",
    16,
)
P256_A = (P256_P - 3) % P256_P
P256_GX = int(
    "6B17D1F2E12C4247F8BCE6E563A440F2"
    "77037D812DEB33A0F4A13945D898C296",
    16,
)
P256_GY = int(
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E16"
    "2BCE33576B315ECECBB6406837BF51F5",
    16,
)


def affine_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None

    if p1 == p2:
        lam = (
            (3 * x1 * x1 + P256_A)
            * pow(2 * y1, -1, P256_P)
        ) % P256_P
    else:
        lam = (
            (y2 - y1)
            * pow((x2 - x1) % P256_P, -1, P256_P)
        ) % P256_P

    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P

    return x3, y3


G = (P256_GX, P256_GY)
G2 = affine_add(G, G)


def bench_ns(fn, warmup=LOCAL_WARMUP, iterations=LOCAL_ITER):
    for _ in range(warmup):
        fn()

    samples = []
    append = samples.append
    perf = time.perf_counter_ns

    for _ in range(iterations):
        t0 = perf()
        fn()
        append(perf() - t0)

    samples.sort()

    return {
        "median_ns": statistics.median(samples),
        "mean_ns": statistics.fmean(samples),
        "p95_ns": samples[int(0.95 * (len(samples) - 1))],
        "p99_ns": samples[int(0.99 * (len(samples) - 1))],
    }


def fmt(name, result):
    print(
        f"{name:<28}"
        f" median={result['median_ns']/1000:10.3f} us"
        f"  mean={result['mean_ns']/1000:10.3f} us"
        f"  p95={result['p95_ns']/1000:10.3f} us"
        f"  p99={result['p99_ns']/1000:10.3f} us"
    )


def sha256_op():
    hashlib.sha256(HASH_PAYLOAD).digest()


def aes_encrypt_op():
    nonce = os.urandom(12)
    AES.encrypt(
        nonce,
        AES_PLAINTEXT,
        AES_AAD,
    )


def aes_decrypt_op():
    AES.decrypt(
        DEC_NONCE,
        DEC_CT,
        AES_AAD,
    )


def p256_scalar_mult_proxy():


    priv.exchange(
        ec.ECDH(),
        peer_pub,
    )


def p256_point_add_python():



    affine_add(
        G,
        G2,
    )


async def rpc_benchmark():
    async with AsyncClient(RPC_URL) as client:
        for _ in range(RPC_WARMUP):
            r = await client.get_account_info(SMD_PDA)
            if r.value is None:
                raise RuntimeError(
                    "SMD PDA not found during RPC warmup"
                )

        samples = []

        for i in range(RPC_ITER):
            t0 = time.perf_counter_ns()

            r = await client.get_account_info(
                SMD_PDA
            )

            dt = time.perf_counter_ns() - t0

            if r.value is None:
                raise RuntimeError(
                    f"SMD PDA missing at RPC iteration {i}"
                )

            samples.append(dt)

        samples.sort()

        return {
            "median_ns": statistics.median(samples),
            "mean_ns": statistics.fmean(samples),
            "p95_ns": samples[int(0.95 * (len(samples) - 1))],
            "p99_ns": samples[int(0.99 * (len(samples) - 1))],
        }


print("=== TDSC NSP Primitive + Solana Benchmark ===")
print("Python:", platform.python_version())
print("Platform:", platform.platform())
print("cryptography:", cryptography_version)
print("Local iterations:", LOCAL_ITER)
print("Solana RPC iterations:", RPC_ITER)
print("SMD PDA:", SMD_PDA)
print()

hash_r = bench_ns(sha256_op)
enc_r = bench_ns(aes_encrypt_op)
dec_r = bench_ns(aes_decrypt_op)
mul_r = bench_ns(p256_scalar_mult_proxy)
add_r = bench_ns(p256_point_add_python)

fmt("SHA-256", hash_r)
fmt("AES-256-GCM encrypt", enc_r)
fmt("AES-256-GCM decrypt", dec_r)
fmt("P-256 scalar mult proxy", mul_r)
fmt("P-256 point add (Python)", add_r)

print()
print("Measuring Solana Devnet account-read round trips...")
rpc_r = asyncio.run(rpc_benchmark())
fmt("Solana getAccountInfo", rpc_r)



te_median_ns = (
    enc_r["median_ns"] + dec_r["median_ns"]
) / 2







crypto_estimate_ns = (
    add_r["median_ns"]
    + 5 * te_median_ns
    + 6 * hash_r["median_ns"]
    + 2 * mul_r["median_ns"]
)

total_with_rpc_ns = (
    crypto_estimate_ns
    + rpc_r["median_ns"]
)

print()
print("=== Paper-count synthetic NSP estimate ===")
print("Operation count: 1*Ta + 5*Te + 6*Th + 2*Tm")
print(
    "Local crypto estimate:",
    f"{crypto_estimate_ns/1000:.3f} us",
    f"({crypto_estimate_ns/1_000_000:.6f} ms)",
)
print(
    "Median Solana RPC read:",
    f"{rpc_r['median_ns']/1_000_000:.3f} ms",
)
print(
    "Crypto + median RPC:",
    f"{total_with_rpc_ns/1_000_000:.3f} ms",
)

print()
print("=== Paper reference values ===")
print("NSP local crypto: approximately 150 us")
print("Solana ledger query Tsr: approximately 266 us")
print("Reported protocol total: approximately 0.95 ms")

print()
print("IMPORTANT:")
print(
    "- Solana result here is public Devnet network round-trip latency, "
    "not a local/in-process ledger primitive."
)
print(
    "- P-256 multiplication uses OpenSSL-backed ECDH as a multiplication proxy."
)
print(
    "- P-256 point addition is Python affine arithmetic and therefore "
    "must not be treated as an optimized OpenSSL point-add figure."
)
