# Threshold OPRF v2

A distributed threshold Oblivious Pseudorandom Function (OPRF) system for privacy-preserving proof of personhood. Uses FROST DKG for distributed key generation (the master key never exists), sealed appliance VMs on Azure Confidential VMs (AMD SEV-SNP + vTPM) for hardware isolation, and client-side Lagrange combination so the mobile app verifies and combines partial evaluations directly.

## Architecture

```
Mobile App
  ├── Fetch node list from /.well-known/toprf-nodes.json
  ├── Verify verification shares against hardcoded group public key (Lagrange at x=0)
  ├── For each selected node (threshold of n, random selection):
  │     ├── Challenge-response attestation (random nonce → AMD-signed report + vTPM PCRs)
  │     │   Proves: exact image (PCR 9), correct binary (REPORT_DATA), no SSH, signed boot
  │     └── POST /partial-evaluate { blindedPoint, attestation } → partial eval + DLEQ proof
  ├── Verify all DLEQ proofs locally
  ├── Lagrange combine partial evaluations locally
  └── Unblind → ruonId
```

- **Sealed appliance nodes** — no OS, no SSH, no shell. Binary runs as PID 1 on bare kernel
- **Secure Boot** — shim (Microsoft-signed) → GRUB (Canonical-signed) → kernel (signed)
- **vTPM PCR measurements** — prove exactly which image booted (kernel + initramfs hash)
- **Challenge-response attestation** — fresh AMD-signed report with app's nonce, not cached
- **FROST DKG** — master key never exists, shares ECIES-encrypted to production TEEs
- **On-chain DKG proof** — immutable record on Base proves key was generated via DKG
- **Client-side combination** — app does Lagrange interpolation and DLEQ verification locally
- **Device attestation** — Apple App Attest / Google Play Integrity verified by each node
- **Reproducible builds** — anyone can build the image, compute expected PCR 9, verify

## Repository Structure

```
crates/
  core/         Threshold OPRF cryptography (Shamir, partial eval, DLEQ, combine, reshare)
  node/         Production node server (partial-evaluate, attestation, rate limiting, reshare)
  dkg-node/     DKG ceremony node (separate binary, separate image, temporary)
  dkg-cli/      DKG orchestration CLI (blind relay — never sees plaintext shares)
  keygen/       Legacy ceremony tool
  seal/         AMD SEV-SNP sealing, ECIES, attestation verification
contracts/      TOPRFRegistry Solidity contract (immutable DKG record on Base)
verify/         Verifier CLI (independent system integrity verification)
image/          Sealed appliance image build (CI builds VHD, deploy to Azure)
scripts/        Integration tests
```

## Sealed Appliance Image

Each node runs as a sealed appliance — a minimal VM with no operating system:

```
Initramfs contents (the entire "OS"):
  /init                     — BusyBox script that mounts filesystems, loads modules, exec's into binary
  /usr/local/bin/toprf-node — the TOPRF binary (static musl, PID 1 after exec)
  /etc/ssl/certs/           — CA certificates
  /lib/modules/             — Hyper-V + SEV-SNP + vTPM kernel modules

NOT in the image:
  - SSH (never existed)
  - Shell (BusyBox init exec'd away after boot)
  - Package manager
  - Systemd
  - Root filesystem
```

Built entirely in CI from open source. Reproducible. Anyone clones the repo, runs the build, gets the same VHD with the same hash. vTPM PCR 9 proves the node booted exactly this initramfs.

## Quick Start (Local Testing)

```bash
# Build
cargo build --release

# Run integration test (3 nodes, partial evaluations, rate limiting)
bash scripts/integration-test.sh

# Run DKG integration test (3 DKG nodes + 3 production nodes, full ceremony)
bash scripts/dkg-integration-test.sh
```

## Deployment

### 1. Build the sealed image (CI)

Trigger the "Build Sealed Image" workflow in GitHub Actions. It produces a VHD artifact.

### 2. Deploy to Azure (local)

```bash
# Download VHD from CI
gh run download <run-id> --name sealed-image

# Deploy 3 Confidential VMs
./image/deploy-azure.sh --vhd toprf-node-sealed.vhd --region eastus --nodes 3
```

### 3. DKG Ceremony

```bash
# Boot 3 DKG nodes (separate sealed image) + 3 production nodes
# Run DKG — shares are ECIES-encrypted, CLI is a blind relay
toprf-dkg-cli init \
    --dkg-nodes <urls> \
    --production-nodes <urls>

# Terminate DKG nodes
```

### 4. On-Chain Registry

```bash
# DKG ceremony produces dkg-data.json
cd contracts
cp dkg-data.json .
bash deploy.sh   # Deploys to Base — one transaction, immutable
```

### 5. Reshare (Adding Nodes)

```bash
# Boot new node in join mode, run reshare from existing donors
# Donors verify target's attestation (PCR 9 + binary hash) before sharing
```

## Attestation

Challenge-response with random nonce — no caching, no timestamps:

```
App → GET /attestation?nonce=<32 random bytes hex>
Node → generates fresh AMD SNP report with nonce in REPORT_DATA
App verifies:
  - AMD ECDSA-P384 signature (unforgeable)
  - vTPM PCR 9 = expected initramfs hash (exact image)
  - REPORT_DATA[0..32] = sha256(binary || vShare || gpk) (correct code + key)
  - REPORT_DATA[32..64] = nonce (fresh, not replayed)
  - Secure Boot (PCR 7), VMPL=0, debug off, migration off
```

## Trust Model

**What is cryptographically provable:**
- The node runs exactly the open-source sealed image (vTPM PCR 9)
- SSH never existed in the image (reproducible build + PCR 9)
- The binary is correct and holds the right key share (REPORT_DATA)
- The master key was generated via DKG, never held by anyone (on-chain commitments)
- Shares were ECIES-encrypted during DKG — the CLI operator never saw them
- The attestation is fresh (nonce in AMD-signed report)
- The boot chain is signed (Secure Boot + PCR 7)

**What users trust:**
- AMD's silicon (same assumption as all confidential computing)

**What users don't need to trust:**
- RuonLabs (can't access keys — sealed image + SEV-SNP + DKG + ECIES)
- Azure (can't read VM memory — SEV-SNP encryption)
- The well-known endpoint (verified from nodes + on-chain)

## Security

- **FROST DKG** — master key never exists, ECIES-encrypted transport
- **Sealed appliance** — no SSH, no shell, binary as PID 1, proved via vTPM PCR 9
- **Secure Boot** — signed boot chain prevents modified kernels
- **Challenge-response attestation** — fresh AMD-signed report with random nonce
- **T-of-N threshold** — no single node can reconstruct the key
- **DLEQ proofs** — every partial evaluation proves correct key share usage
- **Client-side verification** — app verifies attestation + PCRs + DLEQ before trusting any node
- **Per-node rate limiting** — prevents glossary attacks
- **Replay protection** — blinding + nonce + clientDataHash binding
- **Immutable on-chain record** — DKG proof on Base, no owner key, no mutations
- **Reproducible builds** — anyone can verify the image matches the source

## CI

- **CI workflow** — on push: format, lint, audit, test, build static musl binaries
- **Build Sealed Image** — manual dispatch: builds VHD from source, uploads as artifact
- Docker push disabled (production images are separate)

## License

See [LICENSE](LICENSE).
