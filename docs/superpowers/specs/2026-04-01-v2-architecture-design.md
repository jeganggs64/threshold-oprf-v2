# RuonID OPRF v2 Architecture Design

## Overview

Redesign of the RuonID threshold OPRF system to achieve:
- **Provable key ignorance**: FROST DKG replaces the trusted dealer ceremony. The master key never exists.
- **No cloud lock-in**: Nodes are independent services with no inter-node communication during evaluation. No Lambda, API Gateway, DynamoDB, NLB, or VPC.
- **Public verifiability**: On-chain DKG commitments + live AMD attestation verification by the app. Anyone can verify the system's integrity without cooperation from RuonLabs.
- **Open source everything**: Node binary, mobile app, verifier CLI, and on-chain registry contract are all public.

## What Changes and What Doesn't

### Unchanged
- `crates/core/` — all cryptographic primitives (partial eval, DLEQ, combine, reshare, hash-to-curve, Shamir)
- `crates/seal/` — TEE sealing and attestation report generation
- `ruonid-sdk` — developer SDK (callbacks, decryption, signatures)
- `ruonid-test-console` — developer testing tool
- The OPRF protocol itself (secp256k1, blinding, unblinding, threshold evaluation)
- Developer integration flows (QR codes, callbacks, receipts)

### Changed
- Node architecture (simplified, no coordinator, attestation + rate limiting per node)
- Mobile app OPRF flow (direct node calls, client-side Lagrange combination, attestation verification)
- Key generation (FROST DKG instead of trusted dealer ceremony)
- Infrastructure (well-known endpoint for discovery, on-chain registry for DKG proof)
- Frontend (OPRF Lambdas deleted, sybil/billusage Lambdas use stateless attestation)

## Deliverables

| Deliverable | Repo (forked from) |
|---|---|
| Simplified OPRF node | `threshold-oprf` |
| DKG CLI tool | `threshold-oprf` (new `crates/dkg-cli/`) |
| Verifier CLI tool | `threshold-oprf` (new `verify/`) |
| On-chain registry contract | `threshold-oprf` (new `contracts/`) |
| Mobile app changes | `ruonid` |
| Well-known endpoint + Lambda cleanup | `ruonid-frontend` |

---

## Node Architecture

### Endpoints

```
GET  /health            — liveness check
GET  /attestation       — returns cached AMD SNP report + cert chain (rate-limited, e.g. 60/min per IP)
POST /partial-evaluate  — attestation-gated partial OPRF evaluation
POST /reshare           — share recovery for adding nodes (donor role)
```

Removed: `/evaluate` (coordinator), `/info` (moved to well-known endpoint).

### `/attestation` Response

```json
{
  "nodeId": 1,
  "attestationReport": "base64(AMD SNP report ~1184 bytes)",
  "certChain": "base64(VCEK/VLEK + ASK + ARK certificates)",
  "generatedAt": "2026-04-15T00:00:00Z"
}
```

The SNP report contains:
- `LAUNCH_DIGEST` (SHA-384 of firmware + kernel + initrd) — proves which VM image booted
- `REPORT_DATA[0..32]` = `sha256(toprf_node_binary)` — proves which binary is running
- `REPORT_DATA[32..64]` = `sha256(verificationShare || groupPublicKey)` — binds to key material
- `POLICY` flags — debug disabled, migration disabled, VMPL=0
- `SIGNATURE` — ECDSA-P384 signed by AMD's VCEK/VLEK key

Generated at boot, refreshed daily. Served from cache.

### `/partial-evaluate` Request/Response

```
Request:
{
  "blindedPoint": "02abc...",
  "attestation": {
    "platform": "ios" | "android",
    "attestationObject": "base64(...)",     // iOS: App Attest certificate chain
    "assertion": "base64(...)",             // iOS: signed assertion
    "clientDataHash": "hex(...)",           // = hash(blindedPoint)
    "integrityToken": "base64(...)"         // Android: Play Integrity token
  }
}

Response:
{
  "nodeId": 1,
  "partialPoint": "02def...",
  "dleqProof": {
    "challenge": "hex(...)",
    "response": "hex(...)"
  }
}
```

Processing order:
1. Verify device attestation statelessly (iOS: verify Apple cert chain + assertion signature, check `clientDataHash == hash(blindedPoint)`. Android: call Google API, check `nonce == hash(blindedPoint)`)
2. Check per-device rate limit (device ID = hash of attestation key, stored in-memory, daily epoch reset)
3. Compute partial evaluation + DLEQ proof (existing `toprf-core` code, unchanged)
4. Return

### Device Attestation — One Token for All Nodes

The app generates one attestation token per evaluation, sent to all selected nodes:
- iOS: `clientDataHash = sha256(blindedPoint)` — one assertion
- Android: `nonce = base64(sha256(blindedPoint))` — one Play Integrity token

Each node independently verifies the same token. No per-node registration. No increase in Apple/Google API calls compared to the current architecture.

### Rate Limiting

Each node tracks per-device rate limits independently using in-memory storage (HashMap with daily epoch reset). Since the user needs `t` nodes for a valid evaluation, the effective rate limit is the strictest single node's limit.

### Node Lifecycle — Single Production Binary

The production image contains only `toprf-node`. No DKG code. Two modes:

```
Boot → check local disk for sealed key
  → Found:                  NORMAL MODE — serve /health, /attestation, /partial-evaluate, /reshare (as donor)
  → Not found, --join flag: JOIN MODE — serve /reshare/receive endpoint, wait for incoming shares
```

Join endpoint stops responding once a key is sealed. The node transitions to normal mode.

The `/reshare/receive` endpoint is used for BOTH genesis (receiving contributions from DKG participants) and later resharing (receiving contributions from existing donor nodes). The endpoint doesn't distinguish — it accepts encrypted contributions, combines them, verifies, and seals.

```
Genesis:
  1. Boot production VMs in --join mode → waiting for contributions
  2. Separately, boot DKG VMs (different image) → run DKG ceremony
  3. DKG nodes encrypt contributions to production nodes' pubkeys
  4. CLI relays encrypted contributions to production nodes via /reshare/receive
  5. Production nodes: decrypt → combine → verify → seal → normal mode
  6. Terminate DKG VMs

Adding a node later:
  1. Boot production VM in --join mode → waiting for contributions
  2. CLI orchestrates reshare from existing production nodes
  3. Existing nodes send contributions via /reshare/receive
  4. New node: decrypt → combine → verify → seal → normal mode
```

DKG and production are completely separate images with separate measurements.

### Key Persistence

Sealed to local disk via AMD SEV-SNP `MSG_KEY_REQ` (hardware-derived key tied to CPU + measurement). Survives reboots on the same physical host. If the VM migrates to different hardware or is terminated, the sealed key is lost — recovery is via reshare from remaining nodes.

No cloud storage (S3/GCS) for sealed keys.

### Node Configuration at Boot

The node fetches the well-known endpoint once at startup:

```rust
struct NodeConfig {
    approved_measurements: Vec<[u8; 48]>,  // for reshare target verification
    expected_binary_hash: [u8; 32],         // for reshare target verification
    group_public_key: CompressedPoint,
    registry_contract: Address,
}
```

---

## DKG Ceremony

### Overview

The DKG ceremony uses a **separate DKG image** (containing `toprf-dkg-node`) that runs on temporary TEE VMs. The CLI tool `toprf-dkg` orchestrates the process. Production nodes receive the resulting shares via their standard `/reshare/receive` endpoint — they never run DKG code.

### Two Separate Images

**DKG image** — temporary, used only during genesis:
- Contains `toprf-dkg-node` binary
- Runs on TEE VMs during DKG ceremony
- Generates random polynomials, exchanges commitments, computes contributions
- ECIES-encrypts contributions to production nodes' pubkeys
- Has its own measurement (recorded on-chain as proof of correct DKG)
- VMs terminated after ceremony

**Production image** — permanent:
- Contains `toprf-node` binary only — no DKG code
- Production nodes boot in `--join` mode, receive contributions via `/reshare/receive`
- Smaller binary, smaller attack surface

### Flow

```
$ toprf-dkg init \
    --dkg-nodes https://dkg1.url,https://dkg2.url,https://dkg3.url \
    --production-nodes https://node1.url,https://node2.url,https://node3.url \
    --threshold 2 \
    --registry-contract 0xabc... \
    --rpc https://arb1.arbitrum.io/rpc \
    --deployer-key 0x...

Setup:
  CLI collects attestation + ephemeral pubkeys from all production nodes (in --join mode)

Round 1:
  CLI → POST /dkg/round1 to each DKG node
  Each DKG node (inside TEE):
    - generates random polynomial of degree (threshold - 1)
    - computes commitment (public polynomial coefficients)
    - generates AMD attestation report with REPORT_DATA containing commitment hash
    - returns: { commitment, attestationReport, certChain }
  CLI collects all round 1 packages

Round 2:
  CLI → POST /dkg/round2 to each DKG node, sending all other DKG nodes' commitments
    + production nodes' ephemeral pubkeys (for ECIES encryption)
  Each DKG node (inside TEE):
    - verifies all other commitments
    - computes its contribution f_i(j) for each production node j
    - ECIES-encrypts each contribution to the corresponding production node's pubkey
    - returns: { encrypted_contributions_for_production_nodes }
  CLI collects all encrypted contributions

Delivery:
  CLI → POST /reshare/receive to each production node, sending all encrypted
    contributions destined for that node + DKG commitments for verification
  Each production node:
    - decrypts contributions from each DKG participant
    - sums contributions → final key share
    - verifies share against DKG commitments
    - computes verification share
    - seals key share to local disk
    - returns: { nodeId, verificationShare }

On-chain:
  CLI posts to registry contract:
    - each DKG node's round 1 commitment + attestation report + cert chain
    - group public key (derived from commitments)
    - calls finalize() → locks the record permanently
  CLI then terminates DKG VMs
```

### DKG Node Endpoints (`toprf-dkg-node` binary, separate image)

```
POST /dkg/round1  — generate polynomial + commitment, return with attestation
POST /dkg/round2  — receive others' commitments + production pubkeys, return encrypted contributions
```

Two endpoints only. The DKG nodes never seal shares — they compute contributions and encrypt them for the production nodes.

### Security of the Split Design

No single DKG participant sees any production node's final share. DKG participant i only knows its own contribution f_i(j) to production node j — not the contributions from other DKG participants. The final share is the sum of all contributions, computed inside the production node's TEE.

The CLI is a message relay. It cannot:
- Influence randomness (generated inside DKG TEE before any message is sent)
- See shares (ECIES-encrypted to production nodes' pubkeys)
- Forge commitments (bound to attestation via REPORT_DATA)
- Modify messages (production nodes verify contributions against commitments)

Verifiability: each DKG node's commitment is bound to its TEE attestation report via REPORT_DATA. The attestation proves the commitment was generated by the correct DKG code on genuine AMD hardware. Published on-chain for anyone to verify.

---

## On-Chain Registry Contract

Deployed once on Arbitrum or Base. Write-once: records the DKG, finalizes, done forever. The deployer key can be discarded after finalization.

The contract's sole purpose: immutable proof that DKG happened and no one held the master key.

### Contract

```solidity
contract TOPRFRegistry {
    struct NodeRecord {
        uint8   nodeId;
        bytes   dkgCommitment;
        bytes   attestationReport;
        bytes   certChain;
        bytes32 verificationShare;
    }

    bytes32 public groupPublicKey;
    string  public sourceRepo;
    uint8   public threshold;
    uint256 public dkgTimestamp;
    bool    public finalized;

    mapping(uint8 => NodeRecord) public nodes;
    uint8 public nodeCount;

    function recordNode(uint8 nodeId, NodeRecord calldata record) external onlyOwner {
        require(!finalized);
        nodes[nodeId] = record;
        nodeCount++;
    }

    function finalize(bytes32 _groupPublicKey, string calldata _sourceRepo, uint8 _threshold) external onlyOwner {
        require(!finalized);
        groupPublicKey = _groupPublicKey;
        sourceRepo = _sourceRepo;
        threshold = _threshold;
        dkgTimestamp = block.timestamp;
        finalized = true;
        // Owner key can be discarded after this call
    }
}
```

No `addNode()`, no binary hash management, no time-locks, no ongoing owner key. The contract is immutable after `finalize()`.

### What's On-Chain vs. Well-Known Endpoint

| Data | On-chain | Well-known endpoint |
|---|---|---|
| DKG commitments | Yes | No |
| DKG node attestation reports | Yes | No |
| Group public key | Yes | Yes (convenience) |
| DKG node verification shares | Yes | No |
| Source repo URL | Yes | No |
| Threshold | Yes | Yes (convenience) |
| Binary hash | No | Yes |
| Approved measurements | No | Yes |
| Node URLs | No | Yes |
| Reshared node attestation | No | No (verified live from node by app) |

---

## Well-Known Endpoint

Static JSON file served from `ruonid-frontend`. Discovery and operational config only — no trust-critical data.

```json
{
  "version": 1,
  "threshold": 2,
  "groupPublicKey": "02abc...",
  "expectedBinaryHash": "sha256:abc...",
  "approvedMeasurements": [
    "sha384:aaa...",
    "sha384:bbb..."
  ],
  "registryContract": {
    "chain": "arbitrum",
    "chainId": 42161,
    "address": "0xdef..."
  },
  "sourceRepo": "https://github.com/ruonlabs/threshold-oprf",
  "nodes": [
    { "id": 1, "url": "https://node1.ruonlabs.com" },
    { "id": 2, "url": "https://node2.ruonlabs.com" },
    { "id": 3, "url": "https://node3.ruonlabs.com" }
  ]
}
```

### Trust Model

The well-known endpoint is trusted for operational configuration (node URLs, approved measurements). The on-chain registry is the immutable proof (DKG happened, commitments were made, attestations were recorded). Live node attestation provides real-time verification (nodes are currently running correct code).

---

## Reshare Protocol

### Adding a Node

```
$ toprf-dkg reshare \
    --new-node https://node4.url \
    --new-node-id 4 \
    --existing-nodes https://node1.url,https://node2.url

1. New node (started with --join) generates ephemeral keypair + attestation report
2. CLI sends new node's attestation to existing donor nodes
3. Each donor node verifies the new node:
   a. AMD cert chain valid
   b. LAUNCH_DIGEST in approved measurements set (from well-known endpoint)
   c. REPORT_DATA binary hash matches expected binary hash (from well-known endpoint)
   d. Debug disabled, VMPL=0, migration disabled
4. Donor computes Lagrange-weighted recovery contribution, ECIES-encrypts to new node's pubkey
5. New node combines contributions → derives share → verifies against group public key → seals
6. Update well-known endpoint with new node URL + verification share
```

### Same Threshold, More Nodes

Adding nodes keeps the polynomial degree (and threshold) the same. Going from 2-of-3 to 2-of-5 uses the existing reshare protocol — evaluate the same degree-1 polynomial at new points. No threshold change protocol needed.

### Reshare Target Verification

Donor nodes check the new node's attestation before contributing:

```rust
async fn verify_reshare_target(report: &SnpReport, cert_chain: &CertChain) -> Result<()> {
    // 1. AMD signature chain
    verify_amd_cert_chain(cert_chain, report)?;

    // 2. Security policy
    ensure!(!report.debug_enabled);
    ensure!(report.vmpl == 0);
    ensure!(!report.migration_allowed);

    // 3. LAUNCH_DIGEST in approved set
    ensure!(self.config.approved_measurements.contains(&report.launch_digest));

    // 4. Binary hash matches expected
    let binary_hash = &report.report_data[0..32];
    ensure!(binary_hash == &self.config.expected_binary_hash);

    Ok(())
}
```

---

## Mobile App Changes

### New OPRF Flow

```
1. hashToCurve(nationality, natId) → H                    (unchanged)
2. blind(H) → B, save blinding factor r                   (unchanged)
3. fetch /.well-known/toprf-nodes.json → node list         (new)
4. shuffle nodes, pick threshold (t) nodes                  (new)
5. for each selected node (parallel):
   a. GET /attestation → verify AMD cert chain + measurement  (new)
   b. if attestation invalid → skip, try next node            (new)
   c. generate attestation token with clientDataHash = hash(B)
   d. POST /partial-evaluate { blindedPoint, attestation }
   e. receive partial eval + DLEQ proof
6. verify all DLEQ proofs locally                           (new)
7. Lagrange combine partial evals locally → S               (new)
8. unblind(S) → U                                          (unchanged)
9. ruonId = keccak256(U)                                   (unchanged)
```

### Node Selection Strategy

```
Given: n nodes available, threshold t

Step 1: Shuffle node list, pick t random nodes
  → call all t in parallel (attestation check + partial eval)
  → if t valid responses with valid DLEQ proofs → combine → done

Step 2: If any node failed (attestation invalid, timeout, error, bad proof)
  → try next node from remaining shuffled list, one at a time
  → if total valid responses reach t → combine → done

Step 3: All n nodes tried, still < t valid responses
  → retry previously failed nodes once

Step 4: Still < t → return INSUFFICIENT_NODES error
```

Happy path: exactly t network calls (attestation + evaluation per node, sequential within each node, parallel across nodes).

### Attestation Verification by the App

Done hot per evaluation (not cached — onboarding is a one-time operation). No on-chain reads at any point — the on-chain registry is for auditors only.

```
ONCE AT STARTUP:
  1. Fetch well-known endpoint → node list, verification shares, binary hash, measurements
  2. Verify: Lagrange interpolation of verification shares == hardcoded groupPublicKey?
     → If no: well-known endpoint tampered with. Abort.
     → If yes: these are real shares for the real group key.

PER EVALUATION (for each selected node):
  3. AMD signature chain
     Report signed by VCEK/VLEK?                    ← P-384 ECDSA verify
     VCEK/VLEK signed by ASK?                       ← P-384 ECDSA verify
     ASK signed by ARK?                             ← P-384 ECDSA verify
     (ARK public key hardcoded in app)

  4. Code integrity
     REPORT_DATA[0..32] == expectedBinaryHash?      ← from well-known endpoint
     LAUNCH_DIGEST in approvedMeasurements?          ← from well-known endpoint

  5. Key binding
     REPORT_DATA[32..64] == sha256(verificationShare || groupPublicKey)?

  6. Security policy
     Debug bit == 0
     VMPL == 0
     Migration == disabled

  7. POST /partial-evaluate → receive partial + DLEQ proof
  8. Verify DLEQ proof against this node's verification share
```

Step 2 is the anchor: the hardcoded group public key (set during DKG, never changes) validates the verification shares from the well-known endpoint. If they're consistent, the shares are real. The DLEQ proofs (step 8) then verify each node actually used its share correctly.

### Performance Budget

```
Fetch well-known endpoint:                        ~100ms
Fetch attestation from 2 nodes (parallel):        ~200ms
Verify 6 P-384 signatures:                        ~20ms
Generate attestation token (App Attest/PI):       ~200ms
Call 2 nodes for partial eval (parallel):         ~300ms
Verify 2 DLEQ proofs:                             ~2ms
Lagrange combine + unblind:                       ~1ms
                                            ──────────
Total:                                           ~800ms
```

### New TypeScript Modules

**`app/lib/lagrange.ts`** — Lagrange coefficient computation + partial eval combination
- Port of `crates/core/src/combine.rs` verification logic
- Uses `@noble/curves/secp256k1`
- Validated against existing cross-language test vectors

**`app/lib/dleq.ts`** — DLEQ proof verification (verification only, never generates proofs)
- Reconstruct `A1 = s*G + c*V`, `A2 = s*B + c*E`
- Compute `c' = SHA-512(G, B, V, E, A1, A2) mod n`
- Check `c == c'`

**`app/lib/snp-verify.ts`** — AMD SNP attestation report verification
- Parse attestation report (fixed struct)
- Verify ECDSA-P384 certificate chain
- Check measurement, REPORT_DATA, policy flags
- Uses `@noble/curves/p384`
- AMD ARK public key hardcoded

**`app/lib/node-discovery.ts`** — Fetch and parse well-known endpoint, node selection, retry logic

### Modified TypeScript Modules

**`app/lib/oprf.ts`** — Rewritten to call nodes directly, use new modules
**`app/lib/device-attestation.ts`** — `clientDataHash = hash(blindedPoint)` instead of session-based nonce
**`app/lib/config.ts`** — Well-known endpoint URL instead of `OPRF_SERVER_URL`

### Hardcoded Values in the App

| Value | Source | Update frequency |
|---|---|---|
| Group public key | From DKG ceremony | Never (changes only if full re-DKG, which means new ruonIDs + app release) |
| AMD ARK public key | AMD's published root cert | Essentially never |
| Well-known endpoint URL | `https://ruonlabs.com/.well-known/toprf-nodes.json` | Never |

---

## Frontend Changes

### Deleted

- `handlers/challenge.ts` — nonce issuance
- `handlers/attest.ts` — device registration
- `handlers/evaluate.ts` — OPRF proxy to coordinator
- `shared/dynamo-nonces.ts` — nonce storage
- `shared/dynamo-device-keys.ts` — device key storage
- `lambda/rotation/` — node rotation Lambda
- NLB, VPC networking to OPRF nodes
- API Gateway routes for `/challenge`, `/attest`, `/evaluate`
- DynamoDB tables: `ruonid-nonces`, `ruonid-device-keys`

### Kept

- `handlers/sybil.ts` — KMS-signed receipts (modified: stateless attestation verification)
- `handlers/billusage.ts` — billing events (modified: stateless attestation verification)
- `handlers/developers.ts` — developer registration (unchanged)
- `handlers/admin.ts` — admin dashboard (unchanged)
- `handlers/webhooks.ts` — Stripe webhooks (unchanged)
- `handlers/signing-keys.ts` — JWKS endpoint (unchanged)
- DynamoDB tables: `ruonid-developers`, `ruonid-billing-events`, `ruonid-webhook-events`
- KMS signing key
- Static site, docs, admin dashboard

### Added

- `public/.well-known/toprf-nodes.json`

---

## Verifier CLI Tool

Standalone tool for independent system verification. Ships in the `threshold-oprf` repo.

```
$ toprf-verify --endpoint https://ruonlabs.com/.well-known/toprf-nodes.json

Fetching node manifest... done
Reading on-chain registry (arbitrum:0xdef...)... done

DKG verification:
  Node 1: commitment on-chain ✓, consistent with group key ✓
  Node 2: commitment on-chain ✓, consistent with group key ✓
  Node 3: commitment on-chain ✓, consistent with group key ✓
  Group public key matches ✓

Live node attestation:
  Node 1 (https://node1.ruonlabs.com):
    AMD cert chain valid ✓
    LAUNCH_DIGEST in approved measurements ✓
    Binary hash matches manifest ✓
    Debug disabled ✓  VMPL 0 ✓  Migration disabled ✓
    DKG node: LAUNCH_DIGEST matches on-chain record ✓
  Node 2 (https://node2.ruonlabs.com):
    AMD cert chain valid ✓
    LAUNCH_DIGEST in approved measurements ✓
    Binary hash matches manifest ✓
    Debug disabled ✓  VMPL 0 ✓  Migration disabled ✓
    DKG node: LAUNCH_DIGEST matches on-chain record ✓
  Node 3 (https://node3.ruonlabs.com):
    AMD cert chain valid ✓
    LAUNCH_DIGEST in approved measurements ✓
    Binary hash matches manifest ✓
    Debug disabled ✓  VMPL 0 ✓  Migration disabled ✓
    DKG node: LAUNCH_DIGEST matches on-chain record ✓
  Node 4 (https://node4.ruonlabs.com):
    AMD cert chain valid ✓
    LAUNCH_DIGEST in approved measurements ✓
    Binary hash matches manifest ✓
    Debug disabled ✓  VMPL 0 ✓  Migration disabled ✓
    Reshared node (not in DKG record)

All checks passed.
```

Fetches well-known endpoint, reads on-chain registry (for DKG proof), contacts each node directly for live attestation, cross-references everything. Requires zero cooperation from RuonLabs. DKG genesis nodes are verified against on-chain records; reshared nodes are verified against approved measurements from the well-known endpoint.

---

## Forked Repo Structure

### `threshold-oprf` fork

```
threshold-oprf/
├── crates/
│   ├── core/                    # UNCHANGED
│   ├── seal/                    # UNCHANGED
│   ├── node/                    # MODIFIED
│   │   └── src/
│   │       ├── main.rs          # Simplified: genesis/join/run modes
│   │       ├── evaluate.rs      # /partial-evaluate with attestation + rate limiting
│   │       ├── attestation.rs   # NEW: stateless App Attest + Play Integrity verification
│   │       ├── rate_limit.rs    # NEW: per-device rate limiting (in-memory)
│   │       ├── snp_endpoint.rs  # NEW: serves cached attestation report
│   │       ├── reshare.rs       # MODIFIED: checks approved measurements + binary hash
│   │       └── config.rs        # NEW: fetches well-known endpoint at boot
│   ├── keygen/                  # KEPT for backwards compatibility
│   ├── dkg-node/                # NEW — genesis-only binary (SEPARATE IMAGE, runs on temporary TEE VMs)
│   │   └── src/main.rs          # Serves /dkg/round1,2, computes + encrypts contributions
│   └── dkg-cli/                 # NEW — orchestration CLI (runs on operator machine)
│       └── src/main.rs          # Relays DKG messages, delivers shares to production nodes, posts to on-chain registry
├── contracts/                   # NEW
│   ├── src/TOPRFRegistry.sol
│   ├── test/
│   └── foundry.toml
├── verify/                      # NEW
│   └── src/main.rs              # Verifier CLI
├── scripts/
│   └── integration-test.sh      # MODIFIED for new architecture
└── Cargo.toml                   # workspace with new members
```

**Deleted:** `coordinator.rs`, `cloud_storage.rs`, `lambda/`, `deploy/`

### `ruonid` fork

```
ruonid/
└── app/lib/
    ├── oprf.ts              # REWRITTEN
    ├── lagrange.ts          # NEW
    ├── dleq.ts              # NEW
    ├── snp-verify.ts        # NEW
    ├── node-discovery.ts    # NEW
    ├── device-attestation.ts # MODIFIED
    └── config.ts            # MODIFIED
```

Everything else untouched (passport, face, crypto, backup, consent flows, stores, UI).

### `ruonid-frontend` fork

```
ruonid-frontend/
├── public/.well-known/toprf-nodes.json    # NEW
├── lambda/handlers/
│   ├── sybil.ts                            # MODIFIED (stateless attestation)
│   ├── billusage.ts                        # MODIFIED (stateless attestation)
│   ├── developers.ts                       # UNCHANGED
│   ├── admin.ts                            # UNCHANGED
│   ├── webhooks.ts                         # UNCHANGED
│   └── signing-keys.ts                     # UNCHANGED
└── lambda/shared/attestation.ts            # MODIFIED (stateless, no DynamoDB)
```

**Deleted:** `challenge.ts`, `attest.ts`, `evaluate.ts`, `dynamo-nonces.ts`, `dynamo-device-keys.ts`, `rotation/`

---

## Testing Strategy

### Unit Tests (no nodes, no attestation)
- Lagrange combination TypeScript matches Rust (cross-language test vectors)
- DLEQ verification TypeScript matches Rust
- SNP report parsing
- Well-known endpoint JSON parsing
- Contract: deploy, record, finalize, verify immutability

### Integration Tests (mock attestation)
- DKG: 3 local DKG nodes produce commitments + encrypted contributions → 3 local production nodes receive via /reshare/receive → combine → seal → serve evaluations
- Partial evaluation from each production node with mocked attestation
- Client combines partials → verifies against direct evaluation (same result)
- Reshare to 4th production node → new node produces valid partials
- Node rejects reshare to node with unapproved measurement
- Rate limiting rejects after N requests from same device hash

### End-to-End Tests (staging, real devices)
- 3 nodes on real SEV-SNP instances
- DKG with real attestation
- On-chain registry on Arbitrum Sepolia
- Real well-known endpoint (staging subdomain)
- Real mobile app (TestFlight / internal track)
- Real passport + NFC + face → OPRF → ruonId
- Validate ruonId is consistent across multiple scans of the same passport
- Validate different passports produce different ruonIds
- Kill one node → evaluation still succeeds (threshold 2 of 3)
- Point app at non-TEE server → app rejects
- Run `toprf-verify` → all checks pass

---

## Trust Model Summary

### What Users Verify (or anyone on their behalf)
- Code is open source → GitHub repos
- Build is reproducible → build instructions + binary hash
- Nodes run correct code → AMD attestation (verified by app directly from each node)
- Key was generated via DKG → on-chain commitments (immutable, publicly queryable)
- No one ever held the master key → DKG commitments prove it
- Hardware is genuine AMD SEV-SNP → AMD certificate chain

### What Users Trust
- AMD's silicon is not backdoored (same assumption as all confidential computing)

### What Users Don't Need to Trust
- RuonLabs (can't access keys — TEE + DKG)
- Any cloud provider (can't read TEE memory)
- The well-known endpoint being truthful (trust-critical data verified from nodes + on-chain)
- A key ceremony was honest (no ceremony — DKG)

---

## Migration Strategy

1. Fork all three repos
2. Build new architecture in forks
3. New nodes with DKG-generated keys (completely independent from production)
4. New app binary pointing at new nodes
5. End-to-end test: real devices, real passports, real attestation
6. Once confident: new app goes to production pipeline, new nodes become production
7. Sunset old nodes + old app + old Lambda infrastructure
8. Users re-onboard (new master key from DKG = new ruonIDs)
