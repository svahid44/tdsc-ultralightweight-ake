# Implementation vs. Source Paper

The v1 experiment follows the paper's four-phase structure and the core state transitions for initialization, registration, session-key exchange, RID rotation, final acknowledgement, old-state deletion, and on-chain revocation checking.

## Concrete implementation choices

| Abstract primitive | v1 choice |
|---|---|
| `h(.)` | SHA-256 |
| `SEnc/SDec` | AES-256-GCM |
| EC group | NIST P-256 / secp256r1 |
| `AEnc/ADec` | ephemeral P-256 ECDH + HKDF-SHA256 + AES-256-GCM |
| structured hash encoding | 4-byte big-endian length prefix |
| NSP local store | SQLite |
| wire representation | JSON + URL-safe Base64 |
| PUF | HMAC-SHA256 simulation |

These are implementation choices and must not be described as uniquely specified by the source paper.

## PUF scope
The paper assumes a physical PUF. v1 uses a persistent HMAC-based simulated PUF. Therefore v1 does not experimentally prove physical-PUF unclonability, tamper resistance, environmental reliability, or physical leakage resilience.

## Transport scope
v1 transferred encrypted JSON messages manually because the three physical nodes had no direct route. Cryptographic and state-machine execution is real; transport automation remains future work.

## Performance scope
Implementation measurements include AEAD packaging, serialization, Python/OpenSSL behavior, and public Solana Devnet network latency. Keep them separate from the source paper's theoretical/reference cost model.
