# Evidence Publication Strategy

The experiment produced independently frozen TUC, NSP and SMD evidence archives, each with its own `SHA256SUMS.txt`.

## Keep in normal Git history
- readable results and performance summaries;
- protocol mapping;
- blockchain identifiers and transaction signatures;
- public machine-readable result summaries;
- verification scripts.

## Put in GitHub Release `v1.0.0`
- `TDSC_IMPLEMENTATION_EVIDENCE.tar.gz`
- `TDSC_IMPLEMENTATION_EVIDENCE.tar.gz.sha256`

This freezes the exact evidence associated with the v1 source release without bloating ordinary Git history.
