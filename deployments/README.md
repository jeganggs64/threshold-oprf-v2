# Deployment Records

Each subdirectory is a production deployment, containing the exact artifacts used:

```
deployments/
  2026-04-15/                  ← example deployment date
    package-lock.json          ← pinned package versions (Azure image)
    hashes.txt                 ← SHA256 of binary + image
    pcr-values.json            ← Nitro PCR0/1/2 values (if applicable)
    notes.md                   ← deployment notes (nodes, regions, etc.)
```

## How to verify a deployment

1. Check out this repo at the commit tagged for the deployment
2. Build the image using the lockfile in the deployment directory
3. Compare hashes — they must match
4. Compare PCR values against live node attestation — they must match

If everything matches, the node is running exactly this code with these dependencies.
