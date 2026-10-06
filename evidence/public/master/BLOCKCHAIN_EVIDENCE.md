# Blockchain Evidence

Network: Solana Devnet

Program ID: `CiQyDY4MurDQJbHGZnLvVnP6BfdxKG9Fmu1GB2gPKrGQ`

Config PDA: `634Jmxo9J8DGNwGXw3HsYw9w3oobP3X2bJ7Eo8ECsxjv`

SMD PDA: `3M6AXXVAqQgTqoHNmpBdRRApvttym8jBaBwQwcAEGiDw`

## Important transactions
- Registry config initialization: `yyTyrZ5vL232T9eQ6JkrMJLDZpunw13pQsrf32Xdf4Q5ZKTBpriVrzcU32DAiX1aDDfvkU8FPC9NzgRs1X1BbNq`
- SMD record insertion: `2TWoNEERAHVWLWozRB6srXbFLXfXNMJx6V3A2ymzynQG128udD8VfL8JwcRdosqNSVSAbvztF9h2UNnHnzL9BXmo`
- SMD revocation: `TSqMHRf3YypAiQrQ6xWLyEHrxYvV27qeJXQiYgNWqr7BKMkHk2fYWCBFqZjx2KtCKep7a7BgjvKsczTpaX2w6V3`

## Revocation validation
The completed experiment observed:

- RS_SMD before revocation: 0
- Revocation transaction: confirmed
- RS_SMD after revocation: 1
- Next Phase-3 request: rejected by NSP
- Rejection reason: `RuntimeError: SMD is revoked`

The TUC and NSP evidence packages additionally contain live Solana captures from the evidence-freeze stage.
