# SMD

Smart Metering Device implementation.

The SMD performs identity generation, Phase-1 response acceptance, Phase-2 registration, repeatable Phase-3 session establishment, local state rotation, and acknowledgement generation.

The v1 PUF is an HMAC-SHA256 simulation. Private SMD keys, protected runtime state, raw session keys, and the simulated-PUF secret are excluded from the public repository.
