# Threshold OPRF v2

A distributed threshold Oblivious Pseudorandom Function (OPRF) system for privacy-preserving proof of personhood. Uses FROST DKG for distributed key generation (the master key never exists), AWS Nitro Enclaves for hardware isolation, and client-side Lagrange combination so the mobile app verifies and combines partial evaluations directly.

## Architecture

```
Mobile App
  1. Fetch node list from /.well-known/toprf-nodes.json
  2. Verify verification shares against hardcoded group public key
  3. For each selected node (threshold of N):
       a. Challenge-response attestation (nonce -> Nitro COSE_Sign1 document)
       b. POST /partial-evaluate { blindedPoint, attestation } -> partial eval + DLEQ proof
  4. Verify all DLEQ proofs locally
  5. Lagrange combine partial evaluations locally
  6. Unblind -> ruonId
```

- **FROST DKG** -- master key never exists, shares generated inside enclave nodes
- **Identical images** -- all nodes boot from the same image (same PCRs), configured at runtime via POST /configure
- **Nitro attestation** -- PCR values prove exact code identity, verified by peers during resharing
- **On-chain registry** -- immutable DKG record on Base (group public key, verification shares)
- **Client-side combination** -- app does Lagrange interpolation + DLEQ verification locally
- **Device attestation** -- Apple App Attest / Google Play Integrity verified by each node
- **Ephemeral keys** -- key shares exist only in enclave memory, reshare to recover if a node restarts

## Repository Structure

```
crates/
  core/           Threshold OPRF cryptography (partial eval, DLEQ, Lagrange, reshare)
  node/           Production node (partial-evaluate, attestation, reshare, DKG, configure)
  dkg-cli/        DKG ceremony orchestrator (blind relay -- never sees plaintext shares)
  reshare-cli/    Reshare orchestrator (adds new nodes to existing cluster)
  seal/           ECIES encryption, attestation verification
contracts/        TOPRFRegistry Solidity contract (immutable DKG record on Base)
image/nitro/      Nitro Enclave Docker image + deployment docs
scripts/          Deployment scripts (deploy-nodes.sh, run-dkg.sh)
docs/             Technical overview, verification guide
```

## Building

```bash
# Dev/test (no TEE attestation endpoint)
cargo build --release -p toprf-node

# Nitro Enclave image (AWS)
cargo build --release --target x86_64-unknown-linux-musl -p toprf-node --features nitro
```

## Deployment

See [image/nitro/README.md](image/nitro/README.md) for full deployment instructions.

```bash
# 1. Trigger CI: Actions -> "Build Nitro Enclave Image" -> Run workflow
# 2. Download image + CLIs
# 3. Deploy nodes (all identical images):
bash scripts/deploy-nodes.sh

# 4. Run DKG (CLI configures nodes and runs FROST ceremony):
toprf-dkg-cli init --nodes http://<n1>:3001,http://<n2>:3001,http://<n3>:3001
```

The DKG CLI sends POST /configure to each node before starting rounds. If .env has DEPLOYER_PRIVATE_KEY + RPC_URL, it deploys the on-chain registry automatically.

## Resharing

Adding a new node without reconstructing the master key:

1. Deploy a new node (same image, same PCRs)
2. Update well-known config with the new node's URL, platform, and PCR measurements
3. Run `toprf-reshare-cli --new-node http://<new-ip>:3001`

The CLI configures the new node in join mode, fetches its attestation, sends reshare requests to existing donors (who verify the attestation against well-known), and delivers the encrypted contributions.

## Testing

```bash
cargo test
```

## Trust Model

**Cryptographically provable:**
- All nodes run the same open-source code (identical PCR values, independently reproducible)
- No SSH or remote access (sealed enclave image)
- Master key was generated via DKG, never held by anyone (on-chain commitments)
- DKG CLI never sees key shares (FROST protocol + ECIES encryption)
- Attestation is fresh (nonce in signed Nitro document)

**What users trust:**
- AWS Nitro hypervisor (same assumption as all confidential computing)

**What users don't need to trust:**
- RuonLabs (can't access keys -- enclave isolation + DKG + identical attested images)
- Parent EC2 instance (can't read enclave memory, outbound TLS is end-to-end)

## License

See [LICENSE](LICENSE).
