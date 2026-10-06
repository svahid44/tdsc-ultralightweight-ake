# Experiment Setup

## TUC
- Ubuntu 26.04.1 LTS
- Kernel 7.0.0-14-generic
- Python 3.14.4
- OpenSSL 3.5.5
- Solana Python 0.41.0 / solders 0.29.0

## NSP
- Ubuntu 24.04.5 LTS
- Kernel 7.0.0-31-generic
- Python 3.12.3
- OpenSSL 3.0.13
- SQLite local database

## SMD
- Ubuntu 26.04.1 LTS
- Kernel 7.0.0-14-generic
- Python 3.14.4
- simulated HMAC-SHA256 PUF

## Change-control constraint
No distribution/kernel upgrades were performed. The implementation avoided `apt update`, `apt upgrade`, and `full-upgrade`; only required packages were installed after dry-run checks.

## Network
The nodes were on different private networks/modems, so v1 used manual ciphertext JSON transfer.

## Solana
- Network: Devnet
- Program ID: `CiQyDY4MurDQJbHGZnLvVnP6BfdxKG9Fmu1GB2gPKrGQ`
- Config PDA: `634Jmxo9J8DGNwGXw3HsYw9w3oobP3X2bJ7Eo8ECsxjv`
- SMD PDA: `3M6AXXVAqQgTqoHNmpBdRRApvttym8jBaBwQwcAEGiDw`
