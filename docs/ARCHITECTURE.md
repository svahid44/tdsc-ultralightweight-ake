# Architecture

## Roles

### TUC
Trusted Utility Company. Performs bootstrap functions, creates the encrypted SMD identifier, and writes the SMD public record to Solana.

### NSP
Neighborhood Service Provider. Performs registration/session authentication, keeps the local `RID -> S_NSP` database, reads the Solana revocation state, derives session keys, rotates RID state, and finalizes acknowledgements.

### SMD
Smart Metering Device. Stores protected local state, initiates registration/session requests, derives the session key, updates dynamic state, and produces the final acknowledgement.

### Solana
Stores the SMD public registry record and `RS_SMD` revocation status.

## Experiment hosts

- TUC: Ubuntu 26.04.1 LTS, Python 3.14.4
- NSP: Ubuntu 24.04.5 LTS, Python 3.12.3
- SMD: Ubuntu 26.04.1 LTS, Python 3.14.4

The three hosts were on separate private networks. v1 therefore used manual transfer of ciphertext JSON messages.

## Secret-state ownership

- TUC: TUC secret key.
- NSP: private EC key, authority wallet, encrypted local SMD state.
- SMD: private EC key, `a_SMD`, protected `S_SMD`, simulated-PUF secret.
- Solana: public SMD registry + revocation flag.

Secrets are intentionally excluded from the public repository.
