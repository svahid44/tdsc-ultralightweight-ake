# Performance Results

## SMD
Measured synthetic count corresponding to 7Th + 5Te + Tp:

- 4.986 us on the SMD NUC used in this experiment.

This is not a constrained smart-meter hardware reproduction. The PUF operation is an HMAC-based simulation.

## NSP
Synthetic local cryptographic estimate corresponding to Ta + 5Te + 6Th + 2Tm:

- 461.721 us

Important: scalar multiplication was approximated with OpenSSL-backed ECDH and point addition was measured with Python affine arithmetic.

## Solana Devnet
Public-network getAccountInfo latency:

- Median: 985.521 ms

This is an Internet/Devnet RPC round-trip and is network-dependent.

## Communication — Phase 3 Session 2
- Decoded binary fields: 466 B
- Compact JSON: 702 B
- Pretty JSON: 732 B

## Source-paper reference values
- SMD: ~531 us
- NSP local crypto: ~150 us
- Solana query: ~266 us
- Reported total: ~0.95 ms
- Phase-3 communication: 136 B

The implementation values and source-paper values are retained separately because they measure different abstraction levels and execution environments.
