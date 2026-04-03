# Deployment Records

The `builds/` directory contains build provenance records, auto-committed by CI
after each Nitro image build:

```
deployments/
  builds/
    nitro-<commit>.json    ← build provenance (commit, rust version, binary hash, etc.)
```

## How to verify a deployment

See [docs/verification-guide.md](../docs/verification-guide.md) for the full
step-by-step verification process.

Summary:
1. Check out the repo at the commit in the build record
2. Build with the same Rust version
3. Compare binary SHA256 — must match
4. Build the Docker image + EIF — PCR values must match
5. Verify live node attestation — PCR values must match your build
