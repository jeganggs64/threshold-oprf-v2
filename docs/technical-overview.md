# RuonID — Passport-Based Sybil Resistance Without a Biometric Database

## What it does

RuonID lets any app verify that a user is a unique real person, using only their existing government passport. No custom hardware, no biometric database, no trusted operator. The user gets a deterministic pseudonymous ID that is unlinkable across apps.

## How it works

```
User's phone                          OPRF Nodes (2-of-N, AMD SEV-SNP)
─────────────                         ─────────────────────────────────
1. NFC-read passport chip
2. Verify passport signature (CSCA)
3. Face match: live camera vs
   passport photo (ArcFace, on-device)
4. Fetch node list from well-known endpoint
5. Verify verification shares against
   hardcoded group public key
6. Blind(nationality ∥ documentNumber)
7. For each selected node:
   a. Verify AMD SNP attestation
   b. Send blinded point + device attestation
   ──── blinded point ──────────────→  8. Verify device attestation (App Attest / Play Integrity)
                                       9. Check rate limit
                                       10. Compute partial OPRF evaluation
                                       11. Generate DLEQ proof
   ←── partial eval + DLEQ proof ──
12. Verify all DLEQ proofs locally
13. Lagrange combine locally
14. Unblind
15. ruonId = keccak256(OPRF output)
```

**The server never sees the passport data. The client never sees the key. The master key never existed — it was generated via FROST DKG across independent TEE nodes.**

Same passport → same `ruonId` every time (sybil resistance). Different apps receive `SHA256(ruonId ∥ developerId)` — deterministic but unlinkable across apps.

## Key generation: FROST DKG

The master OPRF key is **never generated or held by anyone**. Instead, FROST Distributed Key Generation (DKG) is used:

1. Temporary DKG nodes (separate TEE VMs) run the FROST DKG protocol
2. Each DKG node generates its own random polynomial inside its TEE
3. Nodes exchange commitments and encrypted secret shares
4. The resulting key shares are delivered to production nodes via reshare contributions
5. DKG VMs are terminated — the shares exist only in the production TEEs
6. DKG commitments and attestation reports are recorded immutably on-chain (Base)

**Verifiability:** Anyone can verify the DKG was correctly performed:
- On-chain commitments prove each node contributed honest randomness
- AMD attestation reports (signed by hardware) prove the DKG code ran inside genuine TEEs
- The group public key is derivable from the on-chain commitments

No ceremony, no trusted dealer, no admin shares. The master key is a mathematical construct that exists only as the sum of independently-generated shares — it was never in one place.

## Security model

| Layer | Guarantee |
|-------|-----------|
| **Key generation** | FROST DKG — master key never exists. Provable via immutable on-chain commitments on Base. |
| **Key custody** | Shares sealed to AMD SEV-SNP hardware via `MSG_KEY_REQ`. No human — including the operator — can extract a share. |
| **Node compromise** | Threshold scheme requires 2+ nodes to collude. Each node has independent attestation and hardware-sealed key shares. |
| **Client verification** | The mobile app verifies each node's AMD attestation report (P-384 cert chain, measurement, binary hash, VMPL, debug/migration policy) before sending any data. |
| **DLEQ proofs** | Every partial evaluation includes a Chaum-Pedersen proof that the node used its correct key share. The app verifies these locally. |
| **Node rotation** | Reshare protocol adds nodes without changing the master key. Donor nodes verify the target's AMD attestation (measurement in approved set, binary hash matches) before contributing. |
| **Passport verification** | Passive authentication: RSA/ECDSA signature on chip data verified against ICAO CSCA master list. Detects cloned/forged passports. |
| **Biometric** | ArcFace face embedding (ONNX, on-device). Passport photo vs live camera. 5-point landmark alignment, CLAHE preprocessing. Embedding never leaves the device. |
| **Device integrity** | iOS App Attest / Android Play Integrity. Each node verifies attestation statelessly before serving an evaluation. |
| **Rate limiting** | Per-device, per-node, daily epoch. Prevents glossary attacks. Independent per node — no shared state. |
| **Replay** | OPRF input is blinded with a fresh random scalar per request. Device attestation is bound to the blinded point via clientDataHash. |

## Public verifiability

Anyone can independently verify the system's integrity:

```bash
toprf-verify --endpoint https://ruonlabs.com/.well-known/toprf-nodes.json
```

This checks:
- Verification shares interpolate to the group public key (Lagrange at x=0)
- Each node's live AMD attestation: measurement, binary hash, VMPL, debug bit, migration policy
- DKG commitments on-chain match the live attestation reports
- All without cooperation from the operator

**Trust assumption:** AMD's silicon. Same assumption as Azure Confidential Computing, Google Confidential VMs, and AWS Nitro Enclaves.

## What integrators receive

A developer generates their own secp256k1 keypair and registers their public key. To verify a user:

1. Generate a signed QR code or deeplink containing a session ID, callback URL, and signature.
2. User scans it in RuonID → sees a consent screen → authenticates with biometrics.
3. RuonID POSTs to the callback URL:

```json
{
  "appSpecificId": "0x...",    // SHA256(ruonId ∥ developerId) — unique per user per app
  "identityTier": "passport-bound",
  "deviceVerified": true,
  "timestamp": "2026-03-30T...",
  "receipt": { ... }           // server-signed attestation, verifiable with SDK
}
```

The `appSpecificId` is deterministic — same user always produces the same ID for the same app. Different apps get different IDs. No PII is transmitted.

**For apps that need PII** (KYC): a separate identity flow sends ECIES-encrypted passport fields (name, DOB, nationality, etc.) encrypted to the developer's public key. The user explicitly consents to each field.

## Why a server-side key is necessary

Deterministic sybil resistance requires that the same person always produces the same ID. This means the output must be a function of (1) the person's identity data and (2) nothing else that varies. We show that a server-side secret is unavoidable for this to work securely.

**Claim:** A deterministic, sybil-resistant identity scheme cannot be fully client-side.

**Proof by cases:**

*Case 1: Client-only, no secret.* The function is `ID = f(passport_data)` where `f` is public. This is deterministic, but it is trivially reversible via glossary attack. Passport numbers are structured, short, and enumerable — there are roughly 10^9 possible values per country. An attacker who observes a pseudonymous `ID` on-chain or in a database can compute `f(candidate)` for every plausible passport number until they find a match, deanonymizing the user. Without a secret key gating the evaluation of `f`, there is no way to rate-limit or prevent this offline enumeration.

*Case 2: Client-only, with a client secret.* The function is `ID = f(passport_data, client_secret)`. This authenticates the computation, but the `client_secret` is device-bound. If the user loses their phone, gets a new device, or reinstalls the app, `client_secret` changes. The ID is no longer deterministic — the same person produces different IDs on different devices. Sybil resistance fails because there is no way to link the old and new IDs.

*Case 3: Server-side secret.* The function is `ID = f(passport_data, server_key)`. The `server_key` is persistent and independent of the user's device, so the same person always produces the same ID (deterministic). The secret is held server-side behind device attestation and rate limiting, so an attacker cannot freely evaluate `f` to mount a glossary attack. Additionally, the actual passport must be NFC-scanned to initiate the flow, adding a physical possession requirement. **This is the only case that satisfies determinism, glossary-attack resistance, and sybil resistance simultaneously.**

**The privacy problem with Case 3:** If the server sees `passport_data` in the clear, it learns the user's identity. This is where the OPRF comes in. The client blinds the input before sending it, the server evaluates the function on the blinded input, and the client unblinds the result. The server never sees the raw input; the client never sees the key. The output is identical to Case 3 but with no privacy loss.

**The trust problem with Case 3:** A single server holding the key is a central point of failure. This is where FROST DKG and threshold cryptography come in. The key is generated distributedly via FROST DKG — no single party ever sees the master key. The resulting shares are split across multiple independent nodes, each sealed to hardware (AMD SEV-SNP). The DKG ceremony is recorded immutably on-chain (Base), providing cryptographic proof that the key was fairly generated.

**Summary:** Determinism requires a persistent secret. Device-bound secrets break determinism. A public function with no secret is vulnerable to glossary attacks that deanonymize users by brute-forcing the small input space of passport numbers. Therefore the secret must live server-side, protected by device attestation and rate limiting. OPRF eliminates the privacy cost. FROST DKG eliminates the trust cost. Threshold splitting eliminates the single-point-of-failure cost. The result is a scheme that is deterministic, privacy-preserving, and trust-minimized — with public verifiability via on-chain DKG commitments and AMD attestation.

## Why not existing solutions?

**World ID** requires custom iris-scanning hardware (the Orb) and has been [banned or restricted in multiple countries](https://en.tempo.co/read/2004666/these-are-8-countries-banning-worldcoin-from-spain-to-indonesia) over biometric data concerns — including Spain, Kenya, Brazil, Indonesia, Thailand, Hong Kong, and the Philippines. Its coverage is limited to physical Orb locations.

**ZK passport solutions** like [Rarimo](https://rarimo.medium.com/building-zk-passport-based-voting-3f6f97ebb445) and [Self (formerly OpenPassport)](https://docs.self.xyz/) use ZK-SNARKs to prove passport validity without revealing personal data. However, they rely on a device-bound secret to generate the nullifier (the unique identifier that prevents double-registration). This means the user's identity is tied to a specific device — if they lose their phone, switch devices, or reinstall the app, the secret changes and they produce a different nullifier. The identity is not deterministic across devices, which breaks sybil resistance unless the user goes through a migration or re-registration process.

**RuonID's approach** avoids both problems. No custom hardware — any NFC phone works with any ICAO ePassport (150+ countries). No device-bound secret — the deterministic output comes from the server-side OPRF key, so the same passport produces the same ID regardless of which device the user is on. No biometric database — face matching is purely on-device. The OPRF key is generated via FROST DKG (never exists as a whole), threshold-split across hardware-sealed TEE nodes, with each node's share independently attested. The DKG ceremony is provable on-chain and the entire system is independently verifiable.

## Integration

- **SDK**: `npm install @ruonid/sdk` — verify receipts server-side
- **No server infrastructure needed** — just generate QR codes and handle the callback POST
- **Two tiers**: sybil-only (free, just `appSpecificId`) and identity (paid, encrypted PII fields)
- **API docs**: https://ruonlabs.com/developers
