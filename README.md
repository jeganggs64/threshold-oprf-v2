# Threshold OPRF v2

A distributed threshold Oblivious Pseudorandom Function (OPRF) system for privacy-preserving proof of personhood. Uses FROST DKG for distributed key generation (the master key never exists), AMD SEV-SNP TEEs for hardware isolation, and client-side Lagrange combination so the mobile app verifies and combines partial evaluations directly.

## Architecture

```
Mobile App
  ├── Fetch node list from /.well-known/toprf-nodes.json
  ├── Verify verification shares against hardcoded group public key (Lagrange at x=0)
  ├── For each selected node (threshold of n, random selection):
  │     ├── GET /attestation → verify AMD SNP cert chain + measurement
  │     └── POST /partial-evaluate { blindedPoint, attestation } → partial eval + DLEQ proof
  ├── Verify all DLEQ proofs locally
  ├── Lagrange combine partial evaluations locally
  └── Unblind → ruonId
```

- **Every node is identical** — no coordinator, no peer-to-peer communication during evaluation
- **Client-side combination** — the app does Lagrange interpolation, not the server
- **FROST DKG** — the master key is never generated or held by anyone
- **On-chain DKG proof** — immutable record on Base proves the key was generated via DKG
- **AMD SEV-SNP** — key shares sealed to hardware, operators cannot access them
- **Device attestation** — Apple App Attest / Google Play Integrity verified by each node
- **Per-node rate limiting** — in-memory, independent per node

## Repository Structure

```
crates/
  core/         Threshold OPRF cryptography (Shamir, partial eval, DLEQ, combine, reshare)
  node/         Production node server (partial-evaluate, attestation, rate limiting, reshare)
  dkg-node/     DKG ceremony node (separate binary, separate image, temporary)
  dkg-cli/      DKG orchestration CLI (init ceremony, reshare to new nodes)
  keygen/       Legacy ceremony tool (generate key, split into shares)
  seal/         AMD SEV-SNP sealing, ECIES, attestation verification
contracts/      TOPRFRegistry Solidity contract (immutable DKG record on Base)
verify/         Verifier CLI (independent system integrity verification)
scripts/        Integration tests
```

## Quick Start (Local Testing)

```bash
# Build
cargo build --release

# Run integration test (3 nodes, partial evaluations, rate limiting)
bash scripts/integration-test.sh

# Run DKG integration test (3 DKG nodes + 3 production nodes, full ceremony)
bash scripts/dkg-integration-test.sh
```

## DKG Ceremony

The DKG ceremony uses separate temporary TEE VMs (running `toprf-dkg-node`) to generate key shares. The shares are delivered to production nodes via reshare contributions. After the ceremony, DKG VMs are terminated.

```bash
# 1. Boot 3 DKG nodes + 3 production nodes (--join mode)
toprf-dkg-node --node-id 1 --threshold 2 --total 3 --port 4001
toprf-dkg-node --node-id 2 --threshold 2 --total 3 --port 4002
toprf-dkg-node --node-id 3 --threshold 2 --total 3 --port 4003

toprf-node --join --port 3001
toprf-node --join --port 3002
toprf-node --join --port 3003

# 2. Run DKG ceremony
toprf-dkg-cli init \
    --dkg-nodes http://localhost:4001,http://localhost:4002,http://localhost:4003 \
    --production-nodes http://localhost:3001,http://localhost:3002,http://localhost:3003

# 3. Terminate DKG nodes — production nodes now have their shares
# 4. Deploy on-chain registry (see contracts/)
```

## Adding a Node (Reshare)

```bash
# Boot new node in join mode
toprf-node --join --port 3004

# Reshare from existing nodes
toprf-dkg-cli reshare \
    --new-node http://localhost:3004 \
    --new-node-id 4 \
    --existing-nodes http://localhost:3001,http://localhost:3002

# Update /.well-known/toprf-nodes.json with the new node
```

Same threshold, more nodes. The group public key doesn't change.

## On-Chain Registry (Base)

The `TOPRFRegistry` contract is deployed once with all DKG ceremony data baked into the constructor. No owner, no functions, no mutations — pure immutable data.

```bash
cd contracts
cp .env.example .env          # Fill in DEPLOYER_PRIVATE_KEY and RPC_URL
# Place dkg-data.json (output from DKG ceremony)
bash deploy.sh                # One transaction, done forever
```

## Independent Verification

Anyone can verify the system's integrity without cooperation from the operator:

```bash
toprf-verify --endpoint https://ruonlabs.com/.well-known/toprf-nodes.json
```

This tool:
- Fetches the node manifest
- Verifies verification shares interpolate to the group public key
- Contacts each node for live AMD attestation
- Checks measurements, binary hashes, VMPL, debug/migration policy
- Cross-references against the on-chain DKG record

## Node Endpoints

```
GET  /health            — liveness check
GET  /attestation       — cached AMD SNP attestation report + cert chain
POST /partial-evaluate  — attestation-gated partial OPRF evaluation
POST /reshare           — share recovery (donor role)
POST /reshare/receive   — receive key share contributions (join mode only)
```

## Well-Known Endpoint

```json
{
  "version": 1,
  "threshold": 2,
  "groupPublicKey": "02...",
  "expectedBinaryHash": "sha256:...",
  "approvedMeasurements": ["sha384:..."],
  "registryContract": {
    "chain": "base",
    "chainId": 8453,
    "address": "0x..."
  },
  "sourceRepo": "https://github.com/jeganggs64/threshold-oprf-v2",
  "nodes": [
    { "id": 1, "url": "https://node1.ruonlabs.com", "verificationShare": "02..." }
  ]
}
```

## Trust Model

**What users verify (or anyone on their behalf):**
- Code is open source — this repo
- Build is reproducible — binary hash matches
- Nodes run correct code — AMD attestation verified by the app directly from each node
- Key was generated via DKG — on-chain commitments on Base (immutable)
- No one ever held the master key — DKG commitments prove it

**What users trust:**
- AMD's silicon (same assumption as all confidential computing)

**What users don't need to trust:**
- RuonLabs (can't access keys — TEE + DKG)
- Any cloud provider (can't read TEE memory)
- The well-known endpoint (trust-critical data verified from nodes + on-chain)

## Security

- **FROST DKG** — master key never exists, provable via on-chain commitments
- **T-of-N threshold** — no single node can reconstruct the key
- **AMD SEV-SNP** — key shares sealed to hardware via MSG_KEY_REQ
- **DLEQ proofs** — every partial evaluation proves correct key share usage
- **Client-side verification** — app verifies AMD attestation + DLEQ proofs before trusting any node
- **Device attestation** — Apple App Attest / Google Play Integrity gated per-node
- **Per-node rate limiting** — prevents glossary attacks, independent per node
- **Replay protection** — reshare requests tracked by attestation digest with TTL eviction
- **Reshare target verification** — donor nodes check LAUNCH_DIGEST against approved measurements + binary hash
- **Immutable on-chain record** — DKG ceremony proof on Base, no owner key, no mutations

## CI

GitHub Actions on push/PR to `main`: format (rustfmt), lint (clippy), security audit, unit tests, build. Docker push disabled in this repo.

## License

See [LICENSE](LICENSE).
