# Implementation vs. Source Paper

## Faithful protocol logic implemented
The implementation follows the paper's high-level four-phase structure and the core authentication/state-transition equations for registration, session-key exchange, RID rotation, acknowledgement, old-state deletion and revocation checking.

## Concrete choices required by implementation
The source paper specifies generic cryptographic primitives such as SEnc/AEnc but does not define a wire format or a unique concrete implementation for every primitive. This implementation therefore made explicit choices:

- SHA-256 for h(.)
- AES-256-GCM for symmetric authenticated encryption
- P-256 / secp256r1 for elliptic-curve operations
- ECIES-like AEnc using ephemeral P-256 ECDH, HKDF-SHA256 and AES-256-GCM
- Length-prefixed canonical hashing of structured fields
- JSON + URL-safe Base64 for manual message transport
- SQLite for the NSP local RID -> S_NSP store
- Anchor/Solana PDA records for the blockchain registry

These are implementation choices and must not be presented as if the paper uniquely specified them.

## PUF scope
The paper assumes a physical unclonable function. This implementation uses a persistent HMAC-SHA256-based simulated PUF to exercise the protocol flow. Therefore it does not experimentally prove physical-PUF unclonability, physical tamper resistance or physical leakage resilience.

## Transport scope
The protocol messages were transferred manually as JSON files because the three physical nodes were on separate private networks without direct routing. The cryptographic/state-machine execution is real, but the transport layer is not yet automated.

## Performance interpretation
The paper reports theoretical/reference costs for protocol operations. The implementation measurements include concrete AEAD packaging, serialization and public Devnet network latency, so they should be reported as implementation measurements rather than treated as direct apples-to-apples reproductions of the paper's timing model.
