# Performance Results

## SMD

| Operation | Median |
|---|---:|
| SHA-256 | 0.304 us |
| AES-256-GCM encrypt | 0.508 us |
| AES-256-GCM decrypt | 0.343 us |
| simulated PUF HMAC | 0.730 us |

Synthetic local count corresponding to `7Th + 5Te + Tp`: **4.986 us**.

## NSP

| Operation | Median |
|---|---:|
| SHA-256 | 2.204 us |
| AES-256-GCM encrypt | 7.137 us |
| AES-256-GCM decrypt | 4.513 us |
| P-256 scalar multiplication proxy | 180.004 us |
| P-256 affine point add in Python | 59.364 us |

Synthetic local count corresponding to `Ta + 5Te + 6Th + 2Tm`: **461.721 us**.

The scalar-multiplication value uses OpenSSL-backed ECDH as a proxy. Point addition is Python affine arithmetic.

## Solana Devnet
Public `getAccountInfo`:
- median: **985.521 ms**
- mean: **1371.072 ms**
- p95: **2080.118 ms**

This is public-network RPC latency.

## Phase-3 Session-2 communication
- decoded binary fields: **466 B**
- compact JSON: **702 B**
- pretty JSON: **732 B**

## Source-paper reference values
The source paper reports approximately SMD `531 us`, NSP local crypto `150 us`, Solana query `266 us`, total `0.95 ms`, and Phase-3 communication `136 B`. These are retained separately because the measurement scope and execution environment differ.
