# Security and Publication Notes

Never publish:
- `sk_tuc.key`
- `sk_smd.pem`
- `sk_nsp.pem`
- Solana wallet keypairs or seed phrases
- `puf_secret.key`
- raw `S_SMD`
- raw `S_NSP`
- raw session keys
- runtime SQLite databases
- credential-bearing `.env` files

Safe publication material includes source code, public configuration templates, public-key fingerprints, transaction signatures, Program IDs/PDAs, ciphertext messages, session-key hash fingerprints, benchmark summaries, and evidence hash manifests.

Before every push:

```bash
python scripts/audit_secrets.py .
python scripts/verify_public_repo.py .
git status --short
git diff --cached
```

`.gitignore` is not enough after a secret has already been committed; Git history must then be rewritten and the secret rotated.
