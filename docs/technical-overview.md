# RuonID — Passport-Based Sybil Resistance Without a Biometric Database

## What it does

RuonID lets any app verify that a user is a unique real person, using only their existing government passport. No custom hardware, no biometric database, no trusted operator. The user gets a deterministic pseudonymous ID that is unlinkable across apps.

## How it works

```
User's phone                          OPRF Nodes (2-of-N, Azure Confidential VMs)
─────────────                         ──────────────────────────────────────────
1. NFC-read passport chip
2. Verify passport signature (CSCA)
3. Face match: live camera vs
   passport photo (ArcFace, on-device)
4. Fetch node list from well-known endpoint
5. Verify verification shares against
   hardcoded group public key (Lagrange)
6. Blind(nationality ∥ documentNumber)
7. For each selected node:
   a. Challenge-response attestation:
      send random nonce, verify AMD-signed
      SNP report + vTPM PCR measurements
      (proves exact image, no SSH, correct binary)
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

**The server never sees the passport data. The client never sees the key. The master key never existed — it was generated via FROST DKG. The node image is provably free of SSH or any remote access.**

Same passport → same `ruonId` every time (sybil resistance). Different apps receive `SHA256(ruonId ∥ developerId)` — deterministic but unlinkable across apps.

## Sealed appliance nodes

Each OPRF node runs as a **sealed appliance** — a minimal VM image containing nothing but the TOPRF binary, a tiny init script, and a Linux kernel. No operating system, no SSH, no shell, no package manager.

```
Boot chain (Secure Boot enforced):
  UEFI → shim (Microsoft-signed)
       → GRUB (Canonical-signed)
       → Linux kernel (Canonical-signed)
       → initramfs containing:
           - toprf-node binary (static, musl-linked)
           - BusyBox init (exec's into binary, then gone)
           - CA certificates
           - Hyper-V + SEV-SNP + vTPM kernel modules
```

After boot, PID 1 is the TOPRF binary. The BusyBox shell used during init is replaced by `exec` — it no longer exists in the process tree. There is literally no way to get a shell on the system.

The image is built entirely in CI from open source, producing a reproducible VHD. Anyone can:
1. Clone the repo and reproduce the build
2. Get the same VHD with the same hash
3. Verify the initramfs contains no SSH
4. Compare the expected vTPM PCR 9 value against the node's live attestation

## Key generation: FROST DKG

The master OPRF key is **never generated or held by anyone**. FROST Distributed Key Generation runs on separate temporary TEE VMs:

1. Temporary DKG nodes run the FROST DKG protocol inside their TEEs
2. Each DKG node generates its own random polynomial — the CLI never sees plaintext shares
3. Shares are ECIES-encrypted directly from DKG TEEs to production node TEEs
4. The CLI is a blind relay — it routes encrypted blobs, never touches secrets
5. Production nodes decrypt, combine, verify, and seal their shares
6. DKG VMs are terminated — shares exist only in production TEEs
7. DKG commitments and attestation reports are recorded immutably on Base

**Verifiability:** Anyone can verify:
- On-chain commitments prove each DKG node contributed honest randomness
- AMD attestation reports (hardware-signed) prove the DKG code ran inside genuine TEEs
- ECIES encryption proves shares were never exposed to the CLI operator
- The group public key is derivable from the on-chain commitments

No ceremony, no trusted dealer, no admin shares. The master key is a mathematical construct that exists only as the sum of independently-generated shares — it was never in one place, and no one ever saw it.

## Attestation: challenge-response with nonce

The app does not trust cached or stale attestation reports. Every attestation is a fresh challenge-response:

1. App generates a random 32-byte nonce
2. App sends `GET /attestation?nonce=<hex>` to the node
3. Node generates a fresh AMD SNP attestation report with the nonce in REPORT_DATA
4. App verifies:
   - AMD ECDSA-P384 signature chain (VCEK → ASK → ARK) — unforgeable
   - vTPM PCR 9 = expected initramfs hash — proves exact image
   - REPORT_DATA[0..32] = sha256(binary || vShare || gpk) — proves correct binary + key
   - REPORT_DATA[32..64] = nonce — proves the report is fresh, not replayed
   - Secure Boot policy (PCR 7) — proves signed boot chain
   - VMPL = 0, debug disabled, migration disabled

```
REPORT_DATA layout (64 bytes, AMD hardware-signed):
  [0..32]  sha256(binary || verificationShare || groupPublicKey) — identity
  [32..64] nonce from app (verbatim) — freshness
```

No timestamps, no caching, no self-reported data. The nonce proves the report was generated right now. The AMD signature proves it came from real hardware. The vTPM PCRs prove exactly what code booted.

## Security model

| Layer | Guarantee | Verifiable by |
|-------|-----------|---------------|
| **Key generation** | FROST DKG — master key never exists. ECIES-encrypted transport — CLI never sees shares. | On-chain commitments (Base) |
| **Key custody** | Shares sealed to AMD SEV-SNP hardware. No SSH, no shell, no way to extract. | vTPM PCR 9 (proves sealed image) |
| **No remote access** | Sealed appliance image — no SSH binary, no shell, no sshd ever existed in the image. | Reproducible build + PCR 9 |
| **Node integrity** | Challenge-response attestation with random nonce. Secure Boot enforces signed boot chain. | AMD SNP report + vTPM PCRs |
| **Client verification** | App verifies AMD attestation, vTPM PCRs, DLEQ proofs, verification share consistency. | Open-source app code |
| **Node compromise** | Threshold scheme requires 2+ nodes to collude. Each on independent Azure CVM. | On-chain DKG commitments |
| **Reshare security** | Donor nodes verify target's AMD attestation + PCR measurements before ECIES-encrypting contributions. | Reproducible build hashes |
| **Passport verification** | Passive authentication: RSA/ECDSA signature on chip data vs ICAO CSCA master list. | CSCA root certificates |
| **Biometric** | ArcFace face embedding (ONNX, on-device). Embedding never leaves the device. | Open-source app code |
| **Device integrity** | iOS App Attest / Google Play Integrity. Each node verifies statelessly. | Apple/Google cert chains |
| **Rate limiting** | Per-device, per-node, daily epoch. Prevents glossary attacks. | Node code (open source) |
| **Replay** | Blinded with fresh random scalar per request. Attestation bound to blinded point via clientDataHash. | OPRF protocol |

## Full verification chain

An auditor (or anyone) verifies the entire system without cooperation from the operator:

```
1. SMART CONTRACT (Base, immutable)
   └── DKG commitments prove: master key generated via FROST DKG
   └── Attestation reports prove: DKG ran inside genuine AMD TEEs
   └── Group public key derivable from commitments

2. NODE ATTESTATION (AMD hardware-signed, live challenge-response)
   └── SNP report + vTPM PCR quote
   └── PCR 9 = hash(kernel + initramfs) → proves exact image
   └── REPORT_DATA = sha256(binary || vShare || gpk) + nonce → proves binary + freshness
   └── Secure Boot (PCR 7) → proves signed boot chain
   └── Reproducible build → anyone builds the image, compares PCR 9

3. APP CODE (open source)
   └── Requires attestation before sending data
   └── Checks PCR 9 against expected value
   └── Checks REPORT_DATA against known binary hash + nonce
   └── Verifies DLEQ proofs on every partial evaluation
   └── Lagrange combines locally — no server trust

4. SEALED IMAGE (reproducible, open source)
   └── Initramfs contains ONLY: toprf-node + busybox init + CA certs
   └── No SSH, no shell, no OS, no package manager
   └── Anyone clones repo → reproduces build → compares hash
   └── If PCR 9 matches reproduced hash → node runs exactly this image
```

**Trust assumption:** AMD's silicon is not backdoored. This is the same assumption underlying Azure Confidential Computing, Google Confidential VMs, and every enterprise confidential computing deployment.

**What users don't need to trust:**
- RuonLabs (can't access keys — sealed image + SEV-SNP + DKG)
- Azure (can't read VM memory — SEV-SNP encryption)
- The well-known endpoint (trust-critical data verified from nodes + on-chain)
- A key ceremony (no ceremony — FROST DKG with ECIES transport)

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
  "timestamp": "2026-04-02T...",
  "receipt": { ... }           // server-signed attestation, verifiable with SDK
}
```

The `appSpecificId` is deterministic — same user always produces the same ID for the same app. Different apps get different IDs. No PII is transmitted.

**For apps that need PII** (KYC): a separate identity flow sends ECIES-encrypted passport fields (name, DOB, nationality, etc.) encrypted to the developer's public key. The user explicitly consents to each field.

## Why a server-side key is necessary

Deterministic sybil resistance requires that the same person always produces the same ID. This means the output must be a function of (1) the person's identity data and (2) nothing else that varies.

**Claim:** A deterministic, sybil-resistant identity scheme cannot be fully client-side.

*Case 1: Client-only, no secret.* The function `ID = f(passport_data)` is public and deterministic, but trivially reversible via glossary attack. Passport numbers are enumerable (~10^9 per country). An attacker computes `f(candidate)` for every plausible passport number until they find a match.

*Case 2: Client-only, with a client secret.* The function `ID = f(passport_data, client_secret)` is deterministic on one device, but the client secret is device-bound. New device → new secret → new ID. Sybil resistance breaks.

*Case 3: Server-side secret.* The function `ID = f(passport_data, server_key)` is deterministic across devices (same passport → same ID) and resistant to glossary attacks (the key is behind attestation + rate limiting). **This is the only case that works.**

The OPRF eliminates the privacy cost (server never sees passport data). FROST DKG eliminates the trust cost (no one ever holds the key). Sealed appliance images eliminate the access risk (no SSH, provable via attestation). The result: deterministic, privacy-preserving, trust-minimized, and publicly verifiable.

## Why not existing solutions?

**World ID** requires custom iris-scanning hardware (the Orb) and has been [banned or restricted in multiple countries](https://en.tempo.co/read/2004666/these-are-8-countries-banning-worldcoin-from-spain-to-indonesia) over biometric data concerns. Coverage is limited to physical Orb locations.

**ZK passport solutions** like [Rarimo](https://rarimo.medium.com/building-zk-passport-based-voting-3f6f97ebb445) and [Self](https://docs.self.xyz/) use ZK-SNARKs to prove passport validity without revealing personal data. However, they rely on a device-bound secret for the nullifier. Device changes → identity changes → sybil resistance breaks without migration.

**RuonID** avoids both problems. No custom hardware — any NFC phone works with any ICAO ePassport (150+ countries). No device-bound secret — the deterministic output comes from the server-side OPRF key. No biometric database — face matching is purely on-device. The OPRF key is generated via FROST DKG (never exists as a whole), runs on sealed appliance VMs with no SSH (provable via vTPM + SNP attestation), and the DKG ceremony is recorded immutably on-chain.

## Integration

- **SDK**: `npm install @ruonid/sdk` — verify receipts server-side
- **No server infrastructure needed** — just generate QR codes and handle the callback POST
- **Two tiers**: sybil-only (free, just `appSpecificId`) and identity (paid, encrypted PII fields)
- **API docs**: https://ruonlabs.com/developers
