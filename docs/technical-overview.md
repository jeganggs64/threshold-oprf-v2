# RuonID: Passport-Based Sybil Resistance Without a Biometric Database

## What it does

RuonID lets any app verify that a user is a unique real person, using only their existing government passport. No custom hardware, no biometric database, no trusted operator. The user gets a deterministic pseudonymous ID that is unlinkable across apps.

## How it works

```
User's phone                          OPRF Nodes (2-of-N, AWS Nitro Enclaves)
─────────────                         ─────────────────────────────────────────
1. NFC-read passport chip
2. Verify passport signature (CSCA)
3. Face match: live camera vs
   passport photo (ArcFace, on-device)
4. Fetch node list from well-known endpoint
5. Verify verification shares against
   hardcoded group public key (Lagrange)
6. Blind(nationality || documentNumber)
7. For each selected node:
   a. Challenge-response attestation:
      send random nonce, verify Nitro
      COSE_Sign1 document + PCR values
      (proves exact image, no SSH, correct binary)
   b. Send blinded point + device attestation
   ──── blinded point ──────────────→  8. Verify device attestation (App Attest / Play Integrity)
                                       9. Check rate limit (10/day per device)
                                       10. Compute partial OPRF evaluation
                                       11. Generate DLEQ proof
   ←── partial eval + DLEQ proof ──
12. Verify all DLEQ proofs locally
13. Lagrange combine locally
14. Unblind
15. ruonId = keccak256(OPRF output)
```

**The server never sees the passport data. The client never sees the key. The master key never existed. It was generated via FROST DKG. The node image is provably free of SSH or any remote access.**

Same passport → same `ruonId` every time (sybil resistance). Different apps receive `SHA256(ruonId || developerId)`, deterministic but unlinkable across apps.

## Sealed enclave nodes

Each OPRF node runs inside an AWS Nitro Enclave, an isolated VM with no network interfaces, no SSH, no shell access. The only communication channel is vsock to the parent EC2 instance, which runs socat (inbound) and vsock-proxy (outbound).

```
Enclave contents:
  /toprf-node       # the TOPRF binary (static musl, PID 1 after exec)
  /init.sh          # shell wrapper that exec's into the binary
  /etc/ssl/certs/   # CA certificates for TLS
```

All nodes boot from the same Docker image (pinned Alpine base). PCR values are deterministic. Anyone building from the same source gets the same measurements.

## Key generation (FROST DKG)

The master key never exists. FROST Distributed Key Generation creates key shares inside each enclave:

1. DKG CLI sends POST /configure to each node (sets genesis mode, node ID, threshold)
2. Round 1: Each node generates a random polynomial, sends public commitment to CLI
3. Round 2: Each node computes encrypted shares for peers, CLI routes them
4. Round 3: Each node combines received shares → derives its key share + verification share
5. CLI verifies all nodes agree on the group public key
6. Optionally deploys on-chain registry to Base

The CLI is a blind relay. It never sees plaintext key material. Key shares exist only in enclave memory (ephemeral).

## Attestation

### Nitro attestation (node identity)

Each node can produce a COSE_Sign1 attestation document from the Nitro Security Module (NSM). The document:
- Is signed by AWS (certificate chain to AWS Nitro Root CA)
- Contains PCR0/1/2 measurements (prove the exact enclave image)
- Includes user_data (binds to the node's ephemeral key)
- Is verified by peers during resharing and by clients

### Device attestation (client identity)

Each `/partial-evaluate` request requires device attestation:
- **iOS**: Apple App Attest (CBOR attestation object + ECDSA-P256 assertion signature)
- **Android**: Google Play Integrity (token verified via WIF → Google API)

Device attestation provides a stable device ID for rate limiting (10/day per device).

## On-chain registry

The TOPRFRegistry contract on Base is immutable. All data set in the constructor, no owner, no mutations:
- Group public key
- Verification shares for each node
- Source repository URL
- Threshold

Anyone can read the contract and verify the DKG was done correctly by checking that the verification shares interpolate to the group public key via Lagrange at x=0.

## Resharing

Adding a new node without reconstructing the master key:

1. Deploy new node (same image = same PCRs)
2. Update well-known config with new node's URL and PCR measurements
3. Reshare CLI configures the new node in join mode
4. CLI fetches attestation from new node, sends to existing donors
5. Each donor verifies the attestation (cert chain + PCR match against well-known)
6. Each donor ECIES-encrypts its contribution to the new node's ephemeral key
7. New node combines contributions → new key share

## Security model

**What is cryptographically provable:**
- All nodes run the same open-source code (identical PCR values, reproducible build)
- No SSH or remote access (sealed enclave image, verified by PCR measurements)
- The master key was generated via DKG, never held by anyone (on-chain commitments)
- Key shares were never visible to the CLI operator (FROST protocol)
- Attestation is fresh (nonce in Nitro-signed document)
- Each partial evaluation is correct (DLEQ proof)

**What users trust:**
- AWS Nitro hypervisor (same assumption as all confidential computing)

**What users don't need to trust:**
- RuonLabs (can't access keys: enclave isolation + DKG + identical attested images)
- Parent EC2 instance (can't read enclave memory, outbound TLS is end-to-end)
- The well-known endpoint (verified against on-chain registry + live attestation)

## Rate limiting and DoS protection

- **Device rate limit**: 10 requests per device per day (inside enclave, per attestation)
- **iptables**: 10 connections per minute per IP (on parent EC2, before socat)
- **Device attestation**: rejects unauthenticated requests before any OPRF computation
- **Security groups**: restrict network to ports 22 + 3001 only
