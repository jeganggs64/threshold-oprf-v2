# Threshold OPRF v2

A distributed threshold Oblivious Pseudorandom Function (OPRF) system for privacy-preserving proof of personhood. Uses FROST DKG for distributed key generation (the master key never exists), sealed TEE nodes for hardware isolation, and client-side Lagrange combination so the mobile app verifies and combines partial evaluations directly.

## Architecture

```
Mobile App
  1. Fetch node list from /.well-known/toprf-nodes.json
  2. Verify verification shares against hardcoded group public key
  3. For each selected node (threshold of N):
       a. Challenge-response attestation (nonce -> signed report/document)
       b. POST /partial-evaluate { blindedPoint, attestation } -> partial eval + DLEQ proof
  4. Verify all DLEQ proofs locally
  5. Lagrange combine partial evaluations locally
  6. Unblind -> ruonId
```

- **FROST DKG** -- master key never exists, shares generated inside TEE nodes
- **Sealed nodes** -- no SSH, no shell, binary is the only process
- **TEE attestation** -- Nitro PCRs / SNP measurements prove exact code identity
- **On-chain DKG proof** -- immutable record on Base proves key was generated via DKG
- **Client-side combination** -- app does Lagrange interpolation + DLEQ verification locally
- **Device attestation** -- Apple App Attest / Google Play Integrity verified by each node
- **Platform-aware resharing** -- new nodes verified via well-known config before receiving shares

## Repository Structure

```
crates/
  core/         Threshold OPRF cryptography (partial eval, DLEQ, Lagrange, reshare)
  node/         Production node server (partial-evaluate, attestation, reshare, DKG)
  dkg-cli/      DKG orchestration CLI (blind relay -- never sees plaintext shares)
  dkg-node/     Standalone DKG node (deprecated)
  keygen/       Legacy key generation tool
  seal/         SEV-SNP sealing, ECIES encryption, attestation verification
contracts/      TOPRFRegistry Solidity contract (immutable DKG record on Base)
verify/         Verifier CLI (checks well-known, on-chain registry, live attestation)
image/
  nitro/        Nitro Enclave Docker image + deployment docs
  *.sh          Azure CVM sealed image scripts (pending quota)
scripts/        Integration tests
```

## Building

```bash
# Dev/test (no TEE attestation endpoint)
cargo build --release -p toprf-node

# Nitro Enclave image (AWS)
cargo build --release --target x86_64-unknown-linux-musl -p toprf-node --features nitro

# Azure CVM image (future)
cargo build --release --target x86_64-unknown-linux-musl -p toprf-node --features snp
```

Feature flags control which `/attestation` endpoint is compiled in:
- `nitro` -- returns COSE_Sign1 document from the Nitro Security Module
- `snp` -- returns AMD SEV-SNP report (for Azure CVMs)
- neither -- no `/attestation` endpoint (dev/test mode)

## Deployment

### Nitro Enclaves (current)

See [image/nitro/README.md](image/nitro/README.md) for full deployment instructions.

```bash
# 1. CI builds static binary + Docker image (manual dispatch)
#    Actions -> "Build Nitro Enclave Image" -> Run workflow

# 2. Download artifacts
gh run download <run-id> --name nitro-enclave-image

# 3. Provision EC2 instances (c5a.xlarge+, --enclave-options Enabled=true)
# 4. Upload artifacts, build EIF, launch enclave + socat proxy
# 5. Run DKG ceremony
toprf-dkg-cli init --nodes http://<n1>:3001,http://<n2>:3001,http://<n3>:3001

# 6. Deploy on-chain registry (optional)
DEPLOYER_PRIVATE_KEY=<key> RPC_URL=https://sepolia.base.org \
    toprf-dkg-cli init --nodes <...>
```

### Azure CVMs (planned)

Sealed VHD image with SEV-SNP + vTPM attestation. Pending Azure quota approval.
Build scripts in `image/build-image.sh` and `image/deploy-azure.sh`.

## Resharing

Adding a new node without reconstructing the master key:

1. Deploy new node in `--join` mode
2. Update well-known config with the new node's URL, platform, and expected measurements
3. Run `toprf-dkg-cli reshare --new-node <url> --nodes <existing-nodes>`
4. Existing nodes verify the new node's TEE attestation against well-known config
5. Each donor ECIES-encrypts its contribution to the new node's ephemeral key
6. New node combines contributions and seals the resulting share

Platform-aware: the reshare handler checks well-known config to determine whether to verify Nitro PCRs or SNP measurements.

## Testing

```bash
cargo test

# Integration tests (3 local nodes, DKG, evaluations)
bash scripts/dkg-integration-test.sh

# Partial evaluate integration test
bash scripts/integration-test.sh
```

## Trust Model

**Cryptographically provable:**
- Node runs exactly the open-source code (TEE attestation: Nitro PCRs / SNP measurements)
- No SSH or remote access (sealed image, attestation covers image contents)
- Binary holds the right key share (identity hash in attestation data)
- Master key was generated via DKG, never held by anyone (on-chain commitments)
- Shares were ECIES-encrypted -- the CLI operator never saw them
- Attestation is fresh (nonce in signed report/document)

**What users trust:**
- AWS Nitro hypervisor / AMD silicon (same assumption as all confidential computing)

**What users don't need to trust:**
- RuonLabs (can't access keys -- sealed image + TEE isolation + DKG + ECIES)
- Cloud provider host (can't read enclave/VM memory -- hypervisor/hardware isolation)

## License

See [LICENSE](LICENSE).
