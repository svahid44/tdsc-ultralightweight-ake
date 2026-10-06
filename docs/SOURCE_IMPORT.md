# Import the Exact Executed Source

The public repository should contain the **exact source that was executed**, not reconstructed approximations.

Use `scripts/export_public_node.py` on each physical node.

Example:

```bash
python scripts/export_public_node.py \
  --root ~/tdsc-protocol \
  --role smd \
  --out ~/tdsc_smd_public_source.tar.gz
```

Run equivalently with `--role nsp` and `--role tuc`. Transfer the bundles to the repository-assembly machine and import them with:

```bash
python scripts/import_node_bundle.py tdsc_tuc_public_source.tar.gz .
python scripts/import_node_bundle.py tdsc_nsp_public_source.tar.gz .
python scripts/import_node_bundle.py tdsc_smd_public_source.tar.gz .
```

## Exact Solana source is mandatory

Export the exact Anchor/Rust source from the deployment project and place it at:

```text
solana/programs/tdsc_smd_registry/src/lib.rs
```

Do not reconstruct this file from memory and claim it is the deployed source. Until the exact source is present, keep the repository in pre-release status.
