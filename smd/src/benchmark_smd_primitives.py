from __future__ import annotations

import hashlib
import hmac
import os
import platform
import statistics
import time

from cryptography import __version__ as cryptography_version
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


WARMUP = 2000
ITER = 20000

HASH_PAYLOAD = os.urandom(192)
AES_PLAINTEXT = os.urandom(160)
AES_AAD = b"TDSC-benchmark-v1"
PUF_CHALLENGE = os.urandom(32)

AES_KEY = AESGCM.generate_key(bit_length=256)
AES = AESGCM(AES_KEY)
PUF_SECRET = os.urandom(32)


DEC_NONCE = os.urandom(12)
DEC_CT = AES.encrypt(DEC_NONCE, AES_PLAINTEXT, AES_AAD)


def bench_ns(fn, warmup=WARMUP, iterations=ITER):
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

    median = statistics.median(samples)
    mean = statistics.fmean(samples)
    p95 = samples[int(0.95 * (len(samples) - 1))]
    p99 = samples[int(0.99 * (len(samples) - 1))]

    return {
        "median_ns": median,
        "mean_ns": mean,
        "p95_ns": p95,
        "p99_ns": p99,
    }


def fmt(name, result):
    print(
        f"{name:<24}"
        f" median={result['median_ns']/1000:9.3f} us"
        f"  mean={result['mean_ns']/1000:9.3f} us"
        f"  p95={result['p95_ns']/1000:9.3f} us"
        f"  p99={result['p99_ns']/1000:9.3f} us"
    )


def sha256_op():
    hashlib.sha256(HASH_PAYLOAD).digest()


def aes_encrypt_op():
    nonce = os.urandom(12)
    AES.encrypt(nonce, AES_PLAINTEXT, AES_AAD)


def aes_decrypt_op():
    AES.decrypt(
        DEC_NONCE,
        DEC_CT,
        AES_AAD,
    )


def puf_sim_op():
    hmac.new(
        PUF_SECRET,
        PUF_CHALLENGE,
        hashlib.sha256,
    ).digest()


print("=== TDSC SMD Primitive Benchmark ===")
print("Python:", platform.python_version())
print("Platform:", platform.platform())
print("cryptography:", cryptography_version)
print("Iterations:", ITER)
print("Hash payload:", len(HASH_PAYLOAD), "bytes")
print("AES plaintext:", len(AES_PLAINTEXT), "bytes")
print()

hash_r = bench_ns(sha256_op)
enc_r = bench_ns(aes_encrypt_op)
dec_r = bench_ns(aes_decrypt_op)
puf_r = bench_ns(puf_sim_op)

fmt("SHA-256", hash_r)
fmt("AES-256-GCM encrypt", enc_r)
fmt("AES-256-GCM decrypt", dec_r)
fmt("Simulated PUF HMAC", puf_r)



te_median_ns = (
    enc_r["median_ns"] + dec_r["median_ns"]
) / 2

synthetic_ns = (
    7 * hash_r["median_ns"]
    + 5 * te_median_ns
    + puf_r["median_ns"]
)

print()
print("=== Paper-count synthetic SMD estimate ===")
print("Operation count: 7*Th + 5*Te + 1*Tp")
print(
    "Measured local estimate:",
    f"{synthetic_ns/1000:.3f} us",
    f"({synthetic_ns/1_000_000:.6f} ms)",
)

print()
print("Paper reference SMD total: approximately 531 us")
print(
    "IMPORTANT: this host benchmark is not a reproduction "
    "of the paper's constrained-SMD hardware environment."
)
print(
    "Our PUF is HMAC-based simulation, not a physical PUF."
)
