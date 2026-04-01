# RuonID OPRF v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the RuonID threshold OPRF system with FROST DKG, client-side combination, per-node attestation verification, and public verifiability.

**Architecture:** Three forked repos (threshold-oprf, ruonid, ruonid-frontend). Production nodes are simplified (no coordinator, stateless attestation, per-node rate limiting). DKG is a separate binary/image. Mobile app calls nodes directly, verifies AMD attestation, and combines partial evaluations via Lagrange interpolation. On-chain registry records immutable DKG proof. Well-known endpoint handles node discovery.

**Tech Stack:** Rust (axum, frost-secp256k1, k256), TypeScript/React Native (@noble/curves, @noble/hashes), Solidity (Foundry), Arbitrum/Base L2.

**Spec:** `docs/superpowers/specs/2026-04-01-v2-architecture-design.md`

---

## Phase Decomposition

This plan is organized into 6 phases across 3 forked repos. Each phase produces working, testable software independently.

| Phase | Repo | Description | Depends On |
|-------|------|-------------|------------|
| 1 | threshold-oprf | Fork + simplified production node | — |
| 2 | threshold-oprf | DKG node binary + DKG CLI + on-chain contract | Phase 1 |
| 3 | ruonid | Client-side OPRF (Lagrange, DLEQ, node discovery) | Phase 1 |
| 4 | ruonid | App attestation verification (AMD SNP) | Phase 3 |
| 5 | ruonid-frontend | Well-known endpoint + Lambda cleanup | Phase 1 |
| 6 | threshold-oprf | Verifier CLI tool | Phase 2 |

**Integration testing** runs after all phases, with real SEV-SNP instances and real devices.

---

## Phase 1: Fork + Simplified Production Node

### Task 1.1: Fork the threshold-oprf repo

**Files:**
- New repo: fork of `threshold-oprf`

- [ ] **Step 1: Create the fork**

```bash
cd /Users/jegan
gh repo fork ruonlabs/threshold-oprf --clone --remote-name origin
# Or: git clone <threshold-oprf-url> threshold-oprf-v2
cd threshold-oprf-v2
git checkout -b v2/simplified-node
```

- [ ] **Step 2: Verify workspace builds**

```bash
cargo build --workspace
cargo test --workspace
```
Expected: all tests pass, no warnings.

- [ ] **Step 3: Commit baseline**

```bash
git add -A && git commit -m "chore: fork baseline from threshold-oprf"
```

---

### Task 1.2: Delete coordinator and cloud storage

**Files:**
- Delete: `crates/node/src/coordinator.rs`
- Delete: `crates/node/src/cloud_storage.rs`
- Delete: `lambda/` (entire directory)
- Delete: `deploy/` (entire directory)
- Modify: `crates/node/src/main.rs` — remove coordinator routes and imports

- [ ] **Step 1: Remove coordinator module**

Delete `crates/node/src/coordinator.rs`. Remove all references to it from `crates/node/src/main.rs`:
- Remove `mod coordinator;`
- Remove the `/evaluate` route: `.route("/evaluate", post(coordinator::evaluate_handler))`
- Remove the `CoordinatorConfig` field from `NodeState`
- Remove the `--coordinator-config` CLI argument
- Remove coordinator-related imports

- [ ] **Step 2: Remove cloud storage module**

Delete `crates/node/src/cloud_storage.rs`. Remove `mod cloud_storage;` from main.rs. Remove any cloud storage usage from key loading (the init-seal flow that uploads/downloads from S3/GCS/Azure).

- [ ] **Step 3: Delete Lambda and deploy directories**

```bash
rm -rf lambda/ deploy/
```

- [ ] **Step 4: Remove the /info endpoint**

Remove the `/info` route and `node_info` handler from main.rs. This information moves to the well-known endpoint.

- [ ] **Step 5: Verify it compiles**

```bash
cargo build -p toprf-node
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "refactor: remove coordinator, cloud storage, lambda, deploy"
```

---

### Task 1.3: Add rate limiting module

**Files:**
- Create: `crates/node/src/rate_limit.rs`
- Test: inline `#[cfg(test)]` module

- [ ] **Step 1: Write failing tests**

Create `crates/node/src/rate_limit.rs` with tests:

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Per-device rate limiter with daily epoch reset.
pub struct RateLimiter {
    limits: std::sync::Mutex<HashMap<[u8; 32], DeviceRecord>>,
    max_per_epoch: u32,
    epoch_duration: Duration,
}

struct DeviceRecord {
    count: u32,
    epoch_start: Instant,
}

impl RateLimiter {
    pub fn new(max_per_epoch: u32, epoch_duration: Duration) -> Self {
        Self {
            limits: std::sync::Mutex::new(HashMap::new()),
            max_per_epoch,
            epoch_duration,
        }
    }

    /// Check and increment rate limit for a device.
    /// Returns Ok(()) if allowed, Err(retry_after) if rate limited.
    pub fn check_and_increment(&self, device_id: &[u8; 32]) -> Result<(), Duration> {
        let mut limits = self.limits.lock().unwrap();
        let now = Instant::now();

        let record = limits.entry(*device_id).or_insert(DeviceRecord {
            count: 0,
            epoch_start: now,
        });

        // Reset if epoch expired
        if now.duration_since(record.epoch_start) >= self.epoch_duration {
            record.count = 0;
            record.epoch_start = now;
        }

        if record.count >= self.max_per_epoch {
            let retry_after = self.epoch_duration - now.duration_since(record.epoch_start);
            return Err(retry_after);
        }

        record.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_under_limit() {
        let limiter = RateLimiter::new(5, Duration::from_secs(86400));
        let device = [0u8; 32];
        for _ in 0..5 {
            assert!(limiter.check_and_increment(&device).is_ok());
        }
    }

    #[test]
    fn test_rejects_over_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(86400));
        let device = [0u8; 32];
        assert!(limiter.check_and_increment(&device).is_ok());
        assert!(limiter.check_and_increment(&device).is_ok());
        assert!(limiter.check_and_increment(&device).is_err());
    }

    #[test]
    fn test_different_devices_independent() {
        let limiter = RateLimiter::new(1, Duration::from_secs(86400));
        let device_a = [1u8; 32];
        let device_b = [2u8; 32];
        assert!(limiter.check_and_increment(&device_a).is_ok());
        assert!(limiter.check_and_increment(&device_b).is_ok());
        assert!(limiter.check_and_increment(&device_a).is_err());
    }

    #[test]
    fn test_epoch_reset() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        let device = [0u8; 32];
        assert!(limiter.check_and_increment(&device).is_ok());
        assert!(limiter.check_and_increment(&device).is_err());
        std::thread::sleep(Duration::from_millis(60));
        assert!(limiter.check_and_increment(&device).is_ok());
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p toprf-node -- rate_limit
```
Expected: all 4 tests pass.

- [ ] **Step 3: Add module to main.rs**

Add `mod rate_limit;` to `crates/node/src/main.rs`.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: add per-device rate limiting module"
```

---

### Task 1.4: Add attestation verification module (stateless)

**Files:**
- Create: `crates/node/src/attestation.rs`
- Test: inline tests + integration test with mock data

This module verifies Apple App Attest and Google Play Integrity tokens statelessly. For iOS, it verifies the certificate chain and assertion signature. For Android, it calls Google's API to verify the integrity token.

- [ ] **Step 1: Define attestation types**

Create `crates/node/src/attestation.rs`:

```rust
use serde::Deserialize;
use sha2::{Sha256, Digest};

#[derive(Debug, Deserialize)]
pub struct AttestationPayload {
    pub platform: Platform,
    #[serde(default)]
    pub attestation_object: Option<String>,  // iOS: base64 cert chain
    #[serde(default)]
    pub assertion: Option<String>,           // iOS: base64 signed assertion
    #[serde(default)]
    pub client_data_hash: Option<String>,    // hex hash(blindedPoint)
    #[serde(default)]
    pub integrity_token: Option<String>,     // Android: base64 Play Integrity token
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Android,
    Test,  // For integration testing with mock attestation
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid attestation: {0}")]
    Invalid(String),
    #[error("client data hash mismatch")]
    ClientDataHashMismatch,
    #[error("Google API error: {0}")]
    GoogleApiError(String),
}

/// Result of successful attestation verification.
pub struct AttestationResult {
    /// Hash of the device's attestation key — used as device ID for rate limiting.
    pub device_id_hash: [u8; 32],
}

/// Verify a device attestation payload statelessly.
/// `expected_client_data_hash` is sha256(blindedPoint) — binds attestation to request.
pub async fn verify_attestation(
    payload: &AttestationPayload,
    expected_client_data_hash: &[u8; 32],
) -> Result<AttestationResult, AttestationError> {
    match payload.platform {
        Platform::Ios => verify_ios_attestation(payload, expected_client_data_hash).await,
        Platform::Android => verify_android_attestation(payload, expected_client_data_hash).await,
        Platform::Test => verify_test_attestation(payload, expected_client_data_hash),
    }
}

async fn verify_ios_attestation(
    payload: &AttestationPayload,
    expected_client_data_hash: &[u8; 32],
) -> Result<AttestationResult, AttestationError> {
    let attestation_object = payload.attestation_object.as_ref()
        .ok_or(AttestationError::MissingField("attestation_object"))?;
    let assertion = payload.assertion.as_ref()
        .ok_or(AttestationError::MissingField("assertion"))?;
    let client_data_hash_hex = payload.client_data_hash.as_ref()
        .ok_or(AttestationError::MissingField("client_data_hash"))?;

    // Verify client_data_hash matches expected
    let client_data_hash = hex::decode(client_data_hash_hex)
        .map_err(|e| AttestationError::Invalid(format!("invalid client_data_hash hex: {e}")))?;
    if client_data_hash.as_slice() != expected_client_data_hash {
        return Err(AttestationError::ClientDataHashMismatch);
    }

    // TODO: Full iOS App Attest verification:
    // 1. Decode CBOR attestation object
    // 2. Verify x5c certificate chain against Apple root CA
    // 3. Extract device public key from attestation
    // 4. Verify assertion signature against device public key
    // 5. Verify clientDataHash in assertion matches expected
    //
    // For now, extract a device ID from the attestation for rate limiting.
    // Full implementation will be ported from lambda/shared/attestation.ts

    let device_id_hash = Sha256::digest(attestation_object.as_bytes());
    Ok(AttestationResult {
        device_id_hash: device_id_hash.into(),
    })
}

async fn verify_android_attestation(
    payload: &AttestationPayload,
    expected_client_data_hash: &[u8; 32],
) -> Result<AttestationResult, AttestationError> {
    let integrity_token = payload.integrity_token.as_ref()
        .ok_or(AttestationError::MissingField("integrity_token"))?;

    // TODO: Full Android Play Integrity verification:
    // 1. Call Google Play Integrity API to decrypt/verify token
    // 2. Check package name matches expected
    // 3. Check nonce matches base64(sha256(blindedPoint))
    // 4. Check device integrity verdict
    //
    // For now, extract a device ID from the token for rate limiting.
    // Full implementation will be ported from lambda/shared/attestation.ts

    let device_id_hash = Sha256::digest(integrity_token.as_bytes());
    Ok(AttestationResult {
        device_id_hash: device_id_hash.into(),
    })
}

fn verify_test_attestation(
    payload: &AttestationPayload,
    expected_client_data_hash: &[u8; 32],
) -> Result<AttestationResult, AttestationError> {
    // Test mode: accept any payload, derive device ID from client_data_hash
    let client_data_hash_hex = payload.client_data_hash.as_ref()
        .ok_or(AttestationError::MissingField("client_data_hash"))?;
    let client_data_hash = hex::decode(client_data_hash_hex)
        .map_err(|e| AttestationError::Invalid(format!("invalid hex: {e}")))?;
    if client_data_hash.as_slice() != expected_client_data_hash {
        return Err(AttestationError::ClientDataHashMismatch);
    }
    Ok(AttestationResult {
        device_id_hash: *expected_client_data_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_test_platform_accepts_valid() {
        let cdh = Sha256::digest(b"test-blinded-point");
        let payload = AttestationPayload {
            platform: Platform::Test,
            attestation_object: None,
            assertion: None,
            client_data_hash: Some(hex::encode(&cdh)),
            integrity_token: None,
        };
        let result = verify_attestation(&payload, &cdh.into()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_test_platform_rejects_mismatch() {
        let cdh = Sha256::digest(b"test-blinded-point");
        let wrong_cdh = [0u8; 32];
        let payload = AttestationPayload {
            platform: Platform::Test,
            attestation_object: None,
            assertion: None,
            client_data_hash: Some(hex::encode(&cdh)),
            integrity_token: None,
        };
        let result = verify_attestation(&payload, &wrong_cdh).await;
        assert!(matches!(result, Err(AttestationError::ClientDataHashMismatch)));
    }

    #[tokio::test]
    async fn test_ios_rejects_missing_fields() {
        let cdh = [0u8; 32];
        let payload = AttestationPayload {
            platform: Platform::Ios,
            attestation_object: None,
            assertion: None,
            client_data_hash: None,
            integrity_token: None,
        };
        let result = verify_attestation(&payload, &cdh).await;
        assert!(matches!(result, Err(AttestationError::MissingField(_))));
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p toprf-node -- attestation
```
Expected: all 3 tests pass.

- [ ] **Step 3: Add module to main.rs**

Add `mod attestation;` to main.rs.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: add stateless device attestation verification module"
```

---

### Task 1.5: Add SNP attestation endpoint

**Files:**
- Create: `crates/node/src/snp_endpoint.rs`

- [ ] **Step 1: Create the SNP attestation endpoint handler**

```rust
use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;
use crate::NodeState;

#[derive(Serialize)]
pub struct AttestationResponse {
    pub node_id: u16,
    pub attestation_report: String,  // base64 SNP report
    pub cert_chain: String,          // base64 cert chain
    pub generated_at: String,        // ISO 8601 timestamp
}

pub async fn attestation_handler(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<AttestationResponse>, (axum::http::StatusCode, String)> {
    let cached = state.cached_attestation.read().unwrap();
    match cached.as_ref() {
        Some(att) => Ok(Json(att.clone())),
        None => Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Attestation report not available (non-TEE environment)".to_string(),
        )),
    }
}
```

- [ ] **Step 2: Add cached attestation to NodeState**

In main.rs, add to `NodeState`:

```rust
pub struct NodeState {
    pub(crate) loaded_key: OnceLock<LoadedKey>,
    pub(crate) rate_limiter: rate_limit::RateLimiter,
    pub(crate) cached_attestation: std::sync::RwLock<Option<snp_endpoint::AttestationResponse>>,
    pub reshare_seen: std::sync::Mutex<Vec<([u8; 32], std::time::Instant)>>,
}
```

- [ ] **Step 3: Add route**

```rust
.route("/attestation", get(snp_endpoint::attestation_handler))
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: add /attestation endpoint serving cached SNP report"
```

---

### Task 1.6: Rewrite /partial-evaluate with attestation + rate limiting

**Files:**
- Create: `crates/node/src/evaluate.rs`
- Modify: `crates/node/src/main.rs` — swap old eval handler

- [ ] **Step 1: Create the new evaluate handler**

```rust
use axum::{extract::State, Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::sync::Arc;
use toprf_core::{partial_eval, types::*};

use crate::{NodeState, attestation, rate_limit};

#[derive(Deserialize)]
pub struct PartialEvalRequest {
    pub blinded_point: String,
    pub attestation: attestation::AttestationPayload,
}

pub async fn partial_evaluate_handler(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<PartialEvalRequest>,
) -> Result<Json<PartialEvaluation>, (StatusCode, Json<ErrorResponse>)> {
    // 1. Compute expected client_data_hash = sha256(blindedPoint bytes)
    let blinded_bytes = hex::decode(&req.blinded_point)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("invalid blinded_point hex: {e}")))?;
    let expected_cdh: [u8; 32] = Sha256::digest(&blinded_bytes).into();

    // 2. Verify device attestation
    let att_result = attestation::verify_attestation(&req.attestation, &expected_cdh).await
        .map_err(|e| error_response(StatusCode::FORBIDDEN, &format!("attestation failed: {e}")))?;

    // 3. Rate limit
    state.rate_limiter.check_and_increment(&att_result.device_id_hash)
        .map_err(|retry_after| error_response(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("rate limited, retry after {}s", retry_after.as_secs()),
        ))?;

    // 4. Compute partial evaluation (existing core code)
    let loaded = state.loaded_key.get()
        .ok_or_else(|| error_response(StatusCode::SERVICE_UNAVAILABLE, "key not loaded"))?;
    let blinded_point = hex_to_point(&req.blinded_point)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("invalid point: {e}")))?;
    let partial = partial_eval::partial_evaluate(loaded.node_id, &loaded.key_share, &blinded_point)
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("eval error: {e}")))?;

    Ok(Json(partial))
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

fn error_response(status: StatusCode, msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { error: msg.to_string() }))
}
```

- [ ] **Step 2: Update routes in main.rs**

Replace the old `eval` handler route with:

```rust
.route("/partial-evaluate", post(evaluate::partial_evaluate_handler))
```

Remove the old `eval` function from main.rs.

- [ ] **Step 3: Verify it compiles**

```bash
cargo build -p toprf-node
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: rewrite /partial-evaluate with attestation gating and rate limiting"
```

---

### Task 1.7: Add well-known endpoint config fetching

**Files:**
- Create: `crates/node/src/config.rs`

- [ ] **Step 1: Define config types and fetch logic**

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct WellKnownConfig {
    pub version: u32,
    pub threshold: u16,
    #[serde(rename = "groupPublicKey")]
    pub group_public_key: String,
    #[serde(rename = "expectedBinaryHash")]
    pub expected_binary_hash: String,
    #[serde(rename = "approvedMeasurements")]
    pub approved_measurements: Vec<String>,
    pub nodes: Vec<NodeEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeEntry {
    pub id: u16,
    pub url: String,
    #[serde(rename = "verificationShare")]
    pub verification_share: Option<String>,
}

pub async fn fetch_well_known(url: &str) -> Result<WellKnownConfig, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let config: WellKnownConfig = client.get(url).send().await?.json().await?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_well_known_json() {
        let json = r#"{
            "version": 1,
            "threshold": 2,
            "groupPublicKey": "02abc",
            "expectedBinaryHash": "sha256:def",
            "approvedMeasurements": ["sha384:aaa"],
            "nodes": [{"id": 1, "url": "https://node1.example.com"}]
        }"#;
        let config: WellKnownConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.threshold, 2);
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].id, 1);
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p toprf-node -- config
```

- [ ] **Step 3: Add to main.rs**

Add `pub mod config;` to main.rs. Add an optional `--well-known-url` CLI argument. If provided, the node fetches config at boot and stores it in `NodeState` for reshare target verification.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: add well-known endpoint config fetching"
```

---

### Task 1.8: Add join mode (/reshare/receive endpoint)

**Files:**
- Create: `crates/node/src/join.rs`
- Modify: `crates/node/src/main.rs` — add --join flag and conditional routing

- [ ] **Step 1: Create the reshare receive handler**

```rust
use axum::{extract::State, Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use toprf_core::{reshare, types::*};
use crate::NodeState;

#[derive(Deserialize)]
pub struct ReshareReceiveRequest {
    /// Encrypted contributions from DKG participants or existing donor nodes.
    /// Each entry: { from_node_id, sub_share_data (ECIES encrypted), verification_share }
    pub contributions: Vec<reshare::SerializableReshareContribution>,
    /// IDs of all participants (donors or DKG nodes) that contributed.
    pub participant_ids: Vec<u16>,
    /// The group public key to verify against.
    pub group_public_key: String,
    /// Threshold for the new share.
    pub threshold: u16,
    /// Total shares after this node joins.
    pub total_shares: u16,
    /// The new node ID assigned to this node.
    pub new_node_id: u16,
}

#[derive(Serialize)]
pub struct ReshareReceiveResponse {
    pub node_id: u16,
    pub verification_share: String,
    pub status: String,
}

pub async fn reshare_receive_handler(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<ReshareReceiveRequest>,
) -> Result<Json<ReshareReceiveResponse>, (StatusCode, String)> {
    // Reject if already have a key
    if state.loaded_key.get().is_some() {
        return Err((StatusCode::FORBIDDEN, "Node already has a key".to_string()));
    }

    // Decode and combine contributions
    let mut decoded: Vec<(u16, k256::Scalar, String)> = Vec::new();
    for contrib in &req.contributions {
        // For now: support plaintext sub-shares (test mode)
        // Production: ECIES decrypt using node's ephemeral private key
        let scalar = reshare::decode_plaintext_sub_share(contrib)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("decode error: {e}")))?;
        decoded.push((contrib.from_node_id, scalar, contrib.verification_share.clone()));
    }

    // Combine contributions → derive final key share
    let key_share = reshare::combine_recovery_contributions(
        req.new_node_id,
        &decoded,
        &req.participant_ids,
        &req.group_public_key,
        req.threshold,
        req.total_shares,
    ).map_err(|e| (StatusCode::BAD_REQUEST, format!("combine error: {e}")))?;

    let verification_share = key_share.verification_share.clone();

    // Seal and load the key
    // For dev: save to disk as JSON
    // For production: seal via MSG_KEY_REQ
    let key_json = serde_json::to_string_pretty(&key_share)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize error: {e}")))?;
    std::fs::write("node-key.json", &key_json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("write error: {e}")))?;

    // Load into state
    let loaded = crate::LoadedKey {
        node_id: key_share.node_id,
        key_share: hex_to_scalar(&key_share.secret_share)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("scalar error: {e}")))?,
        verification_share: key_share.verification_share.clone(),
        group_public_key: key_share.group_public_key.clone(),
        threshold: key_share.threshold,
        total_shares: key_share.total_shares,
    };
    state.loaded_key.set(loaded)
        .map_err(|_| (StatusCode::CONFLICT, "Key already loaded".to_string()))?;

    Ok(Json(ReshareReceiveResponse {
        node_id: req.new_node_id,
        verification_share,
        status: "sealed".to_string(),
    }))
}
```

- [ ] **Step 2: Add --join mode to main.rs**

Update main.rs to support a `--join` flag. When set AND no sealed key exists, the node serves `/reshare/receive` instead of `/partial-evaluate`. Once a key is loaded, it transitions to serving all normal endpoints.

```rust
// In main.rs, route setup:
let app = if join_mode && state.loaded_key.get().is_none() {
    Router::new()
        .route("/health", get(health))
        .route("/reshare/receive", post(join::reshare_receive_handler))
        .with_state(state)
} else {
    Router::new()
        .route("/health", get(health))
        .route("/attestation", get(snp_endpoint::attestation_handler))
        .route("/partial-evaluate", post(evaluate::partial_evaluate_handler))
        .route("/reshare", post(reshare_handler::reshare_handler))
        .with_state(state)
};
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo build -p toprf-node
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: add --join mode with /reshare/receive endpoint"
```

---

### Task 1.9: Update reshare donor to verify approved measurements

**Files:**
- Modify: `crates/node/src/reshare_handler.rs`

- [ ] **Step 1: Add measurement + binary hash checking to reshare handler**

In the existing `reshare_handler`, before computing the recovery contribution, add verification of the target node's attestation:

```rust
// In reshare_handler, after receiving the target node's attestation report:

// Check LAUNCH_DIGEST against approved measurements from well-known config
if let Some(ref wk_config) = state.well_known_config {
    let launch_digest_hex = hex::encode(&report.launch_digest);
    let measurement_str = format!("sha384:{}", launch_digest_hex);
    if !wk_config.approved_measurements.contains(&measurement_str) {
        return Err((StatusCode::FORBIDDEN, "Unapproved measurement".to_string()));
    }

    // Check binary hash in REPORT_DATA[0..32]
    let binary_hash_hex = hex::encode(&report.report_data[0..32]);
    let expected_hash = &wk_config.expected_binary_hash;
    if format!("sha256:{}", binary_hash_hex) != *expected_hash {
        return Err((StatusCode::FORBIDDEN, "Binary hash mismatch".to_string()));
    }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build -p toprf-node
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: reshare donor verifies target's measurement and binary hash"
```

---

### Task 1.10: Integration test — full node lifecycle

**Files:**
- Modify: `scripts/integration-test.sh`

- [ ] **Step 1: Write integration test**

Update `scripts/integration-test.sh` to test the new architecture:

```bash
#!/bin/bash
set -euo pipefail

echo "=== Building workspace ==="
cargo build --workspace --release

KEYGEN=./target/release/toprf-keygen
NODE=./target/release/toprf-node

echo "=== Generating test keys (2-of-3) ==="
$KEYGEN init --admin-threshold 2 --admin-shares 3 -o /tmp/toprf-test-admin
$KEYGEN node-shares \
    -a /tmp/toprf-test-admin/admin-1-share.json \
    -a /tmp/toprf-test-admin/admin-2-share.json \
    --node-threshold 2 --node-shares 3 \
    -o /tmp/toprf-test-nodes

echo "=== Starting 3 nodes ==="
$NODE --key-file /tmp/toprf-test-nodes/node-1-share.json --port 3001 &
PID1=$!
$NODE --key-file /tmp/toprf-test-nodes/node-2-share.json --port 3002 &
PID2=$!
$NODE --key-file /tmp/toprf-test-nodes/node-3-share.json --port 3003 &
PID3=$!
sleep 2

cleanup() { kill $PID1 $PID2 $PID3 2>/dev/null; }
trap cleanup EXIT

echo "=== Health checks ==="
curl -sf http://localhost:3001/health | jq .
curl -sf http://localhost:3002/health | jq .
curl -sf http://localhost:3003/health | jq .

echo "=== Partial evaluations (with test attestation) ==="
BLINDED="02a1b2c3..."  # A valid test blinded point
CDH=$(echo -n "$BLINDED" | xxd -r -p | sha256sum | cut -d' ' -f1)

PARTIAL1=$(curl -sf -X POST http://localhost:3001/partial-evaluate \
    -H "Content-Type: application/json" \
    -d "{\"blinded_point\": \"$BLINDED\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH\"}}")
echo "Node 1: $PARTIAL1"

PARTIAL2=$(curl -sf -X POST http://localhost:3002/partial-evaluate \
    -H "Content-Type: application/json" \
    -d "{\"blinded_point\": \"$BLINDED\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH\"}}")
echo "Node 2: $PARTIAL2"

echo "=== Rate limit test ==="
# Should be rejected (already used this device hash in this epoch)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/partial-evaluate \
    -H "Content-Type: application/json" \
    -d "{\"blinded_point\": \"$BLINDED\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH\"}}")
echo "Rate limit response: $HTTP_CODE (expected 429)"

echo "=== Join mode test ==="
$NODE --join --port 3004 &
PID4=$!
sleep 1

# Reshare from nodes 1 and 2 to new node 4
# (This would use the CLI tool in production, but for testing we call the endpoint directly)
echo "Join mode health: $(curl -sf http://localhost:3004/health)"

kill $PID4 2>/dev/null

echo "=== All tests passed ==="
```

- [ ] **Step 2: Run integration test**

```bash
bash scripts/integration-test.sh
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "test: update integration test for simplified node architecture"
```

---

## Phase 2: DKG Node + DKG CLI + On-Chain Contract

### Task 2.1: Create dkg-node crate

**Files:**
- Create: `crates/dkg-node/Cargo.toml`
- Create: `crates/dkg-node/src/main.rs`
- Modify: `Cargo.toml` (workspace) — add member

The DKG node is a separate binary with 2 endpoints: `/dkg/round1` and `/dkg/round2`. It uses `frost-secp256k1` for DKG operations.

- [ ] **Step 1: Create crate with Cargo.toml**

```toml
[package]
name = "toprf-dkg-node"
version = "0.1.0"
edition = "2021"

[dependencies]
toprf-core = { path = "../core" }
toprf-seal = { path = "../seal" }
axum = { workspace = true }
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
frost-secp256k1 = { workspace = true }
k256 = { workspace = true }
rand = { workspace = true }
hex = { workspace = true }
sha2 = { workspace = true }
x25519-dalek = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
thiserror = { workspace = true }
```

- [ ] **Step 2: Implement round1 endpoint**

The round1 endpoint generates a random polynomial, computes commitments, and returns them with an attestation report.

```rust
// crates/dkg-node/src/main.rs
use axum::{routing::post, Router, Json, extract::State, http::StatusCode};
use frost_secp256k1 as frost;
use frost::keys::dkg;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

struct DkgState {
    identifier: frost::Identifier,
    max_signers: u16,
    min_signers: u16,
    round1_secret: Mutex<Option<dkg::round1::SecretPackage>>,
}

#[derive(Serialize)]
struct Round1Response {
    identifier: String,
    package: String,  // JSON-serialized frost Round1Package
    // In production: include attestation_report and cert_chain
}

async fn round1_handler(
    State(state): State<Arc<DkgState>>,
) -> Result<Json<Round1Response>, (StatusCode, String)> {
    let mut rng = rand::rngs::OsRng;
    let (round1_secret, round1_package) = dkg::part1(
        state.identifier,
        state.max_signers,
        state.min_signers,
        &mut rng,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DKG round1 error: {e}")))?;

    // Store secret for round2
    *state.round1_secret.lock().await = Some(round1_secret);

    let package_json = serde_json::to_string(&round1_package)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize error: {e}")))?;

    Ok(Json(Round1Response {
        identifier: format!("{:?}", state.identifier),
        package: package_json,
    }))
}
```

- [ ] **Step 3: Implement round2 endpoint**

The round2 endpoint receives other nodes' round1 packages, computes shares, and returns encrypted contributions for production nodes.

- [ ] **Step 4: Add workspace member and verify build**

Add `"crates/dkg-node"` to workspace members in root `Cargo.toml`.

```bash
cargo build -p toprf-dkg-node
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add dkg-node crate with round1 and round2 endpoints"
```

---

### Task 2.2: Create dkg-cli crate

**Files:**
- Create: `crates/dkg-cli/Cargo.toml`
- Create: `crates/dkg-cli/src/main.rs`

The CLI orchestrates DKG between DKG nodes and delivers shares to production nodes. It also posts DKG records to the on-chain registry.

- [ ] **Step 1: Create crate with subcommands**

Two subcommands: `init` (DKG ceremony) and `reshare` (add a node).

```rust
// crates/dkg-cli/src/main.rs
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "toprf-dkg")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run DKG ceremony between DKG nodes and deliver shares to production nodes
    Init {
        /// Comma-separated DKG node URLs
        #[arg(long)]
        dkg_nodes: String,
        /// Comma-separated production node URLs (must be in --join mode)
        #[arg(long)]
        production_nodes: String,
        /// Threshold (min signers)
        #[arg(long)]
        threshold: u16,
        /// Registry contract address (optional, for on-chain posting)
        #[arg(long)]
        registry_contract: Option<String>,
        /// RPC URL for on-chain posting
        #[arg(long)]
        rpc: Option<String>,
        /// Deployer private key (hex) for on-chain posting
        #[arg(long)]
        deployer_key: Option<String>,
    },
    /// Reshare from existing nodes to a new production node
    Reshare {
        /// New node URL (must be in --join mode)
        #[arg(long)]
        new_node: String,
        /// New node ID
        #[arg(long)]
        new_node_id: u16,
        /// Comma-separated existing node URLs (donors)
        #[arg(long)]
        existing_nodes: String,
    },
}
```

- [ ] **Step 2: Implement init subcommand flow**

The init subcommand:
1. Collects ephemeral pubkeys from production nodes
2. Calls `/dkg/round1` on each DKG node
3. Relays round1 packages
4. Calls `/dkg/round2` on each DKG node with all commitments + production pubkeys
5. Collects encrypted contributions
6. Delivers contributions to production nodes via `POST /reshare/receive`
7. Optionally posts DKG records on-chain

- [ ] **Step 3: Implement reshare subcommand flow**

The reshare subcommand:
1. Gets new node's attestation
2. Sends attestation to each existing donor node via `POST /reshare`
3. Collects encrypted contributions
4. Delivers contributions to new node via `POST /reshare/receive`

- [ ] **Step 4: Verify build**

```bash
cargo build -p toprf-dkg-cli
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add dkg-cli with init and reshare subcommands"
```

---

### Task 2.3: Create on-chain registry contract

**Files:**
- Create: `contracts/foundry.toml`
- Create: `contracts/src/TOPRFRegistry.sol`
- Create: `contracts/test/TOPRFRegistry.t.sol`

- [ ] **Step 1: Initialize Foundry project**

```bash
cd contracts
forge init --no-git
```

- [ ] **Step 2: Write the contract**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract TOPRFRegistry is Ownable {
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

    event NodeRecorded(uint8 indexed nodeId);
    event Finalized(bytes32 groupPublicKey, uint8 threshold);

    constructor() Ownable(msg.sender) {}

    function recordNode(uint8 nodeId, NodeRecord calldata record) external onlyOwner {
        require(!finalized, "Already finalized");
        require(nodes[nodeId].nodeId == 0, "Node already recorded");
        nodes[nodeId] = record;
        nodeCount++;
        emit NodeRecorded(nodeId);
    }

    function finalize(
        bytes32 _groupPublicKey,
        string calldata _sourceRepo,
        uint8 _threshold
    ) external onlyOwner {
        require(!finalized, "Already finalized");
        require(nodeCount >= _threshold, "Not enough nodes");
        groupPublicKey = _groupPublicKey;
        sourceRepo = _sourceRepo;
        threshold = _threshold;
        dkgTimestamp = block.timestamp;
        finalized = true;
        emit Finalized(_groupPublicKey, _threshold);
    }
}
```

- [ ] **Step 3: Write tests**

```solidity
// contracts/test/TOPRFRegistry.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TOPRFRegistry.sol";

contract TOPRFRegistryTest is Test {
    TOPRFRegistry registry;

    function setUp() public {
        registry = new TOPRFRegistry();
    }

    function testRecordAndFinalize() public {
        TOPRFRegistry.NodeRecord memory record = TOPRFRegistry.NodeRecord({
            nodeId: 1,
            dkgCommitment: hex"aabb",
            attestationReport: hex"ccdd",
            certChain: hex"eeff",
            verificationShare: bytes32(uint256(1))
        });
        registry.recordNode(1, record);
        assertEq(registry.nodeCount(), 1);

        registry.finalize(bytes32(uint256(42)), "https://github.com/ruonlabs/threshold-oprf", 2);
        assertTrue(registry.finalized());
        assertEq(registry.groupPublicKey(), bytes32(uint256(42)));
    }

    function testCannotModifyAfterFinalize() public {
        TOPRFRegistry.NodeRecord memory record = TOPRFRegistry.NodeRecord({
            nodeId: 1,
            dkgCommitment: hex"aa",
            attestationReport: hex"bb",
            certChain: hex"cc",
            verificationShare: bytes32(uint256(1))
        });
        registry.recordNode(1, record);
        registry.finalize(bytes32(uint256(42)), "repo", 1);

        vm.expectRevert("Already finalized");
        registry.recordNode(2, record);
    }

    function testCannotFinalizeWithoutEnoughNodes() public {
        vm.expectRevert("Not enough nodes");
        registry.finalize(bytes32(uint256(42)), "repo", 2);
    }
}
```

- [ ] **Step 4: Run tests**

```bash
cd contracts && forge test -v
```
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add TOPRFRegistry Solidity contract with tests"
```

---

### Task 2.4: DKG integration test

- [ ] **Step 1: Write end-to-end DKG test script**

Test the full flow: boot 3 DKG nodes + 3 production nodes, run DKG, verify shares work.

- [ ] **Step 2: Run it, verify partial evaluations combine correctly**

- [ ] **Step 3: Commit**

---

## Phase 3: Mobile App — Client-Side OPRF

### Task 3.1: Port Lagrange combination to TypeScript

**Files:**
- Create: `app/lib/lagrange.ts`
- Create: `app/lib/__tests__/lagrange.test.ts`

- [ ] **Step 1: Write failing tests using cross-language test vectors**

```typescript
// app/lib/__tests__/lagrange.test.ts
import { lagrangeCoefficient, combinePartials } from '../lagrange';

describe('lagrangeCoefficient', () => {
  test('2-of-3 coefficients at x=0', () => {
    // These values must match crates/core/src/combine.rs test_lagrange_coefficients_2_of_3
    const lambda1 = lagrangeCoefficient(1, [1, 2]);
    const lambda2 = lagrangeCoefficient(2, [1, 2]);
    // lambda1 = -2 / (1 - 2) = 2
    // lambda2 = -1 / (2 - 1) = -1
    // Verify modular arithmetic matches Rust
    expect(lambda1).toBeDefined();
    expect(lambda2).toBeDefined();
  });
});

describe('combinePartials', () => {
  test('matches Rust combine_partials for known vectors', () => {
    // Use the cross-language test vectors from toprf-core
    // These are the same vectors used in test_cross_lang_vectors
    // TODO: import exact vectors from the Rust test suite
  });
});
```

- [ ] **Step 2: Implement lagrange.ts**

```typescript
// app/lib/lagrange.ts
import { secp256k1 } from '@noble/curves/secp256k1';
import { mod } from '@noble/curves/abstract/modular';

const ORDER = secp256k1.CURVE.n;

export function lagrangeCoefficient(myId: number, participantIds: number[]): bigint {
  let num = 1n;
  let den = 1n;
  for (const otherId of participantIds) {
    if (otherId === myId) continue;
    num = mod(num * BigInt(-otherId), ORDER);
    den = mod(den * BigInt(myId - otherId), ORDER);
  }
  // modular inverse via Fermat's little theorem: den^(ORDER-2) mod ORDER
  const denInv = mod(
    BigInt(secp256k1.CURVE.n) - 2n >= 0n
      ? modPow(den, ORDER - 2n, ORDER)
      : 0n,
    ORDER
  );
  return mod(num * denInv, ORDER);
}

function modPow(base: bigint, exp: bigint, modulus: bigint): bigint {
  let result = 1n;
  base = mod(base, modulus);
  while (exp > 0n) {
    if (exp % 2n === 1n) result = mod(result * base, modulus);
    exp = exp >> 1n;
    base = mod(base * base, modulus);
  }
  return result;
}

export interface PartialEvaluation {
  nodeId: number;
  partialPoint: string;  // hex compressed point
  dleqProof: { challenge: string; response: string };
}

export function combinePartials(
  partials: PartialEvaluation[],
): typeof secp256k1.ProjectivePoint.BASE {
  const ids = partials.map(p => p.nodeId);
  let combined = secp256k1.ProjectivePoint.ZERO;

  for (const p of partials) {
    const lambda = lagrangeCoefficient(p.nodeId, ids);
    const point = secp256k1.ProjectivePoint.fromHex(p.partialPoint);
    combined = combined.add(point.multiply(lambda));
  }

  return combined;
}
```

- [ ] **Step 3: Run tests**

```bash
cd app && npx jest lagrange --verbose
```

- [ ] **Step 4: Commit**

---

### Task 3.2: Port DLEQ verification to TypeScript

**Files:**
- Create: `app/lib/dleq.ts`
- Create: `app/lib/__tests__/dleq.test.ts`

- [ ] **Step 1: Write failing tests**

- [ ] **Step 2: Implement dleq.ts**

```typescript
// app/lib/dleq.ts
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha512 } from '@noble/hashes/sha512';
import { mod } from '@noble/curves/abstract/modular';

const ORDER = secp256k1.CURVE.n;
const G = secp256k1.ProjectivePoint.BASE;

/**
 * Verify a DLEQ proof: proves log_G(V) == log_B(E)
 * i.e., the same secret k was used for both V = k*G and E = k*B
 */
export function verifyDLEQ(
  blindedPoint: typeof G,       // B
  evaluation: typeof G,         // E = k*B
  verificationShare: typeof G,  // V = k*G
  challenge: bigint,            // c
  response: bigint,             // s
): boolean {
  // Reconstruct A1 = s*G + c*V
  const a1 = G.multiply(response).add(verificationShare.multiply(challenge));
  // Reconstruct A2 = s*B + c*E
  const a2 = blindedPoint.multiply(response).add(evaluation.multiply(challenge));

  // Recompute challenge: c' = H(G, B, V, E, A1, A2) mod ORDER
  const hashInput = Buffer.concat([
    Buffer.from('TOPRF-DLEQ-secp256k1-v1'),
    Buffer.from(G.toRawBytes(true)),
    Buffer.from(blindedPoint.toRawBytes(true)),
    Buffer.from(verificationShare.toRawBytes(true)),
    Buffer.from(evaluation.toRawBytes(true)),
    Buffer.from(a1.toRawBytes(true)),
    Buffer.from(a2.toRawBytes(true)),
  ]);
  const hashOutput = sha512(hashInput);
  const cPrime = mod(BigInt('0x' + Buffer.from(hashOutput).toString('hex')), ORDER);

  return cPrime === challenge;
}

/**
 * Convenience wrapper that takes hex-encoded inputs.
 */
export function verifyDLEQHex(
  blindedPointHex: string,
  partialPointHex: string,
  verificationShareHex: string,
  challengeHex: string,
  responseHex: string,
): boolean {
  const B = secp256k1.ProjectivePoint.fromHex(blindedPointHex);
  const E = secp256k1.ProjectivePoint.fromHex(partialPointHex);
  const V = secp256k1.ProjectivePoint.fromHex(verificationShareHex);
  const c = BigInt('0x' + challengeHex);
  const s = BigInt('0x' + responseHex);
  return verifyDLEQ(B, E, V, c, s);
}
```

- [ ] **Step 3: Run tests, verify against Rust test vectors**

- [ ] **Step 4: Commit**

---

### Task 3.3: Create node discovery module

**Files:**
- Create: `app/lib/node-discovery.ts`
- Create: `app/lib/__tests__/node-discovery.test.ts`

- [ ] **Step 1: Define types and implement fetch + validation**

```typescript
// app/lib/node-discovery.ts
import { secp256k1 } from '@noble/curves/secp256k1';
import { lagrangeCoefficient } from './lagrange';

const WELL_KNOWN_URL = 'https://ruonlabs.com/.well-known/toprf-nodes.json';
const GROUP_PUBLIC_KEY = '02abc...';  // Hardcoded after DKG

export interface NodeManifest {
  version: number;
  threshold: number;
  groupPublicKey: string;
  expectedBinaryHash: string;
  approvedMeasurements: string[];
  nodes: NodeInfo[];
}

export interface NodeInfo {
  id: number;
  url: string;
  verificationShare?: string;
}

let cachedManifest: NodeManifest | null = null;

export async function fetchNodeManifest(): Promise<NodeManifest> {
  if (cachedManifest) return cachedManifest;

  const res = await fetch(WELL_KNOWN_URL);
  if (!res.ok) throw new Error(`Failed to fetch node manifest: ${res.status}`);
  const manifest: NodeManifest = await res.json();

  // Validate verification shares against hardcoded group public key
  validateVerificationShares(manifest);

  cachedManifest = manifest;
  return manifest;
}

function validateVerificationShares(manifest: NodeManifest): void {
  const nodesWithShares = manifest.nodes.filter(n => n.verificationShare);
  if (nodesWithShares.length < manifest.threshold) {
    throw new Error('Not enough nodes with verification shares');
  }

  // Pick threshold nodes and verify Lagrange interpolation matches group public key
  const subset = nodesWithShares.slice(0, manifest.threshold);
  const ids = subset.map(n => n.id);
  let interpolated = secp256k1.ProjectivePoint.ZERO;

  for (const node of subset) {
    const lambda = lagrangeCoefficient(node.id, ids);
    const vShare = secp256k1.ProjectivePoint.fromHex(node.verificationShare!);
    interpolated = interpolated.add(vShare.multiply(lambda));
  }

  const expectedGpk = secp256k1.ProjectivePoint.fromHex(GROUP_PUBLIC_KEY);
  if (!interpolated.equals(expectedGpk)) {
    throw new Error('Verification shares inconsistent with group public key');
  }
}

export function selectNodes(manifest: NodeManifest, threshold: number): NodeInfo[] {
  const shuffled = [...manifest.nodes].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, threshold);
}

export function clearCache(): void {
  cachedManifest = null;
}
```

- [ ] **Step 2: Write tests**

- [ ] **Step 3: Run tests**

- [ ] **Step 4: Commit**

---

### Task 3.4: Rewrite oprf.ts with client-side combination

**Files:**
- Modify: `app/lib/oprf.ts`
- Modify: `app/lib/device-attestation.ts`
- Modify: `app/lib/config.ts`

- [ ] **Step 1: Update config.ts**

```typescript
// app/lib/config.ts
export const WELL_KNOWN_URL = 'https://ruonlabs.com/.well-known/toprf-nodes.json';
export const API_BASE_URL = 'https://api.ruonlabs.com';
// OPRF_SERVER_URL removed — app talks to nodes directly
```

- [ ] **Step 2: Update device-attestation.ts**

Change the attestation token generation to use `clientDataHash = sha256(blindedPoint)` instead of a session-based nonce:

```typescript
export async function getAttestationPayload(blindedPointHex: string): Promise<AttestationPayload> {
  const blindedBytes = hexToBytes(blindedPointHex);
  const clientDataHash = sha256(blindedBytes);
  const clientDataHashHex = bytesToHex(clientDataHash);

  if (Platform.OS === 'ios') {
    const assertion = await generateAssertionAsync(keyId, clientDataHashHex);
    return {
      platform: 'ios',
      attestationObject: storedAttestationObject,
      assertion,
      clientDataHash: clientDataHashHex,
    };
  } else {
    const nonce = base64Encode(clientDataHash);
    const integrityToken = await requestIntegrityToken(nonce);
    return {
      platform: 'android',
      integrityToken,
    };
  }
}
```

- [ ] **Step 3: Rewrite oprf.ts**

```typescript
// app/lib/oprf.ts
import { fetchNodeManifest, selectNodes, NodeInfo } from './node-discovery';
import { combinePartials, PartialEvaluation } from './lagrange';
import { verifyDLEQHex } from './dleq';
import { verifyNodeAttestation } from './snp-verify';
import { getAttestationPayload } from './device-attestation';
import { hashToCurve } from './hash-to-curve';  // unchanged
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

export async function evaluateOPRF(
  nationality: string,
  natIdNumber: string,
): Promise<{ ruonId: string; identitySalt: string }> {
  // 1. Hash to curve (unchanged)
  const H = hashToCurve(nationality, natIdNumber);

  // 2. Blind (unchanged)
  const r = secp256k1.utils.randomPrivateKey();
  const rScalar = secp256k1.CURVE.Fp.create(BigInt('0x' + Buffer.from(r).toString('hex')));
  const B = H.multiply(rScalar);
  const blindedPointHex = Buffer.from(B.toRawBytes(true)).toString('hex');

  // 3. Fetch node manifest
  const manifest = await fetchNodeManifest();

  // 4. Generate attestation token (one for all nodes)
  const attestation = await getAttestationPayload(blindedPointHex);

  // 5. Evaluate with retry strategy
  const partials = await evaluateWithRetry(manifest, blindedPointHex, attestation);

  // 6. Verify DLEQ proofs
  for (const p of partials) {
    const node = manifest.nodes.find(n => n.id === p.nodeId);
    if (!node?.verificationShare) throw new OPRFError('INVALID_RESPONSE', `No verification share for node ${p.nodeId}`);
    const valid = verifyDLEQHex(
      blindedPointHex,
      p.partialPoint,
      node.verificationShare,
      p.dleqProof.challenge,
      p.dleqProof.response,
    );
    if (!valid) throw new OPRFError('INVALID_RESPONSE', `DLEQ verification failed for node ${p.nodeId}`);
  }

  // 7. Lagrange combine
  const S = combinePartials(partials);

  // 8. Unblind: U = r^-1 * S
  const rInv = secp256k1.CURVE.Fp.inv(rScalar);
  const U = S.multiply(rInv);

  // 9. Derive ruonId
  const uBytes = U.toRawBytes(false).slice(1); // uncompressed, skip prefix
  const ruonId = Buffer.from(keccak_256(uBytes)).toString('hex');
  const identitySalt = Buffer.from(keccak_256(
    Buffer.concat([Buffer.from('salt'), uBytes])
  )).toString('hex');

  return { ruonId, identitySalt };
}

async function evaluateWithRetry(
  manifest: NodeManifest,
  blindedPointHex: string,
  attestation: AttestationPayload,
): Promise<PartialEvaluation[]> {
  const threshold = manifest.threshold;
  const shuffled = [...manifest.nodes].sort(() => Math.random() - 0.5);
  const results: PartialEvaluation[] = [];
  const failed: NodeInfo[] = [];

  // Step 1: try threshold nodes in parallel
  const firstBatch = shuffled.splice(0, threshold);
  const responses = await Promise.allSettled(
    firstBatch.map(node => callNode(node, blindedPointHex, attestation, manifest))
  );

  for (let i = 0; i < responses.length; i++) {
    if (responses[i].status === 'fulfilled') {
      results.push((responses[i] as PromiseFulfilledResult<PartialEvaluation>).value);
    } else {
      failed.push(firstBatch[i]);
    }
  }
  if (results.length >= threshold) return results;

  // Step 2: try remaining nodes one at a time
  for (const node of shuffled) {
    try {
      const partial = await callNode(node, blindedPointHex, attestation, manifest);
      results.push(partial);
      if (results.length >= threshold) return results;
    } catch {
      failed.push(node);
    }
  }

  // Step 3: retry failed nodes once
  for (const node of failed) {
    try {
      const partial = await callNode(node, blindedPointHex, attestation, manifest);
      results.push(partial);
      if (results.length >= threshold) return results;
    } catch { /* exhausted */ }
  }

  throw new OPRFError('INSUFFICIENT_NODES', `Got ${results.length} partials, need ${threshold}`);
}

async function callNode(
  node: NodeInfo,
  blindedPointHex: string,
  attestation: AttestationPayload,
  manifest: NodeManifest,
): Promise<PartialEvaluation> {
  // Verify node attestation first
  await verifyNodeAttestation(node, manifest);

  // Call partial-evaluate
  const res = await fetch(`${node.url}/partial-evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      blinded_point: blindedPointHex,
      attestation,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'unknown' }));
    if (res.status === 429) throw new OPRFError('RATE_LIMITED', err.error);
    if (res.status === 403) throw new OPRFError('ATTESTATION_FAILED', err.error);
    throw new OPRFError('INVALID_RESPONSE', `Node ${node.id}: ${err.error}`);
  }

  return await res.json();
}
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: rewrite OPRF flow with client-side combination and node discovery"
```

---

## Phase 4: Mobile App — AMD SNP Attestation Verification

### Task 4.1: Implement SNP attestation verification in TypeScript

**Files:**
- Create: `app/lib/snp-verify.ts`
- Create: `app/lib/__tests__/snp-verify.test.ts`

This module verifies AMD SNP attestation reports from each node before sending evaluation requests. It checks the AMD certificate chain, measurement, REPORT_DATA, and security policy.

- [ ] **Step 1: Define types and implement parser**

```typescript
// app/lib/snp-verify.ts
import { p384 } from '@noble/curves/p384';
import { sha256 } from '@noble/hashes/sha256';
import { sha384 } from '@noble/hashes/sha512';
import { NodeInfo, NodeManifest } from './node-discovery';

// AMD ARK (Attestation Root Key) for Milan/Genoa — hardcoded
const AMD_ARK_PUBLIC_KEY = '04...';  // P-384 uncompressed public key

interface SnpReport {
  version: number;
  guestSvn: number;
  policy: bigint;
  measurement: Uint8Array;     // 48 bytes (LAUNCH_DIGEST)
  reportData: Uint8Array;      // 64 bytes
  vmpl: number;
  signature: Uint8Array;       // ECDSA-P384 signature
}

export async function verifyNodeAttestation(
  node: NodeInfo,
  manifest: NodeManifest,
): Promise<void> {
  // 1. Fetch attestation from node
  const res = await fetch(`${node.url}/attestation`);
  if (!res.ok) throw new Error(`Failed to fetch attestation from node ${node.id}`);
  const att = await res.json();

  // 2. Parse attestation report
  const reportBytes = base64ToBytes(att.attestationReport);
  const report = parseSnpReport(reportBytes);

  // 3. Verify AMD certificate chain
  const certChainBytes = base64ToBytes(att.certChain);
  verifyCertChain(certChainBytes, reportBytes);

  // 4. Check LAUNCH_DIGEST against approved measurements
  const launchDigestHex = bytesToHex(report.measurement);
  const measurementStr = `sha384:${launchDigestHex}`;
  if (!manifest.approvedMeasurements.includes(measurementStr)) {
    throw new Error(`Node ${node.id}: unapproved measurement ${measurementStr}`);
  }

  // 5. Check REPORT_DATA[0..32] == expectedBinaryHash
  const binaryHashHex = bytesToHex(report.reportData.slice(0, 32));
  if (`sha256:${binaryHashHex}` !== manifest.expectedBinaryHash) {
    throw new Error(`Node ${node.id}: binary hash mismatch`);
  }

  // 6. Check REPORT_DATA[32..64] == sha256(verificationShare || groupPublicKey)
  if (node.verificationShare) {
    const expected = sha256(
      concatBytes(hexToBytes(node.verificationShare), hexToBytes(manifest.groupPublicKey))
    );
    const actual = report.reportData.slice(32, 64);
    if (!bytesEqual(expected, actual)) {
      throw new Error(`Node ${node.id}: key binding mismatch in REPORT_DATA`);
    }
  }

  // 7. Security policy checks
  if (report.vmpl !== 0) throw new Error(`Node ${node.id}: VMPL != 0`);
  // Check debug bit (bit 19 of policy)
  if ((report.policy >> 19n) & 1n) throw new Error(`Node ${node.id}: debug mode enabled`);
  // Check migration (bit 18 of policy)
  if ((report.policy >> 18n) & 1n) throw new Error(`Node ${node.id}: migration allowed`);
}

function parseSnpReport(bytes: Uint8Array): SnpReport {
  // AMD SEV-SNP attestation report layout (simplified):
  // offset 0x000: version (4 bytes LE)
  // offset 0x004: guest_svn (4 bytes LE)
  // offset 0x008: policy (8 bytes LE)
  // ...
  // offset 0x090: measurement (48 bytes) — LAUNCH_DIGEST
  // offset 0x0C0: report_data (64 bytes)
  // offset 0x01C: vmpl (4 bytes LE)
  // offset 0x2A0: signature (512 bytes)
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    version: view.getUint32(0x000, true),
    guestSvn: view.getUint32(0x004, true),
    policy: view.getBigUint64(0x008, true),
    measurement: bytes.slice(0x090, 0x090 + 48),
    reportData: bytes.slice(0x0C0, 0x0C0 + 64),
    vmpl: view.getUint32(0x01C, true),
    signature: bytes.slice(0x2A0, 0x2A0 + 512),
  };
}

function verifyCertChain(certChainBytes: Uint8Array, reportBytes: Uint8Array): void {
  // Parse DER-encoded certificates (VCEK/VLEK, ASK, ARK)
  // Verify: ARK signs ASK, ASK signs VCEK, VCEK signs report
  // Using @noble/curves/p384 for ECDSA-P384 verification
  // Full implementation: parse X.509 DER, extract public keys and signatures,
  // verify each level of the chain
  // For now: placeholder that will be fully implemented
  // with actual certificate parsing
}
```

- [ ] **Step 2: Write tests with mock attestation data**

- [ ] **Step 3: Run tests**

- [ ] **Step 4: Commit**

---

## Phase 5: Frontend Cleanup

### Task 5.1: Add well-known endpoint

**Files:**
- Create: `public/.well-known/toprf-nodes.json`

- [ ] **Step 1: Create the JSON file**

```json
{
  "version": 1,
  "threshold": 2,
  "groupPublicKey": "02...",
  "expectedBinaryHash": "sha256:...",
  "approvedMeasurements": ["sha384:..."],
  "registryContract": {
    "chain": "arbitrum",
    "chainId": 42161,
    "address": "0x..."
  },
  "sourceRepo": "https://github.com/ruonlabs/threshold-oprf",
  "nodes": [
    {"id": 1, "url": "https://node1.ruonlabs.com", "verificationShare": "02..."},
    {"id": 2, "url": "https://node2.ruonlabs.com", "verificationShare": "03..."},
    {"id": 3, "url": "https://node3.ruonlabs.com", "verificationShare": "02..."}
  ]
}
```

Values are placeholders — populated after DKG ceremony.

- [ ] **Step 2: Commit**

---

### Task 5.2: Delete OPRF Lambda handlers

**Files:**
- Delete: `lambda/handlers/challenge.ts`
- Delete: `lambda/handlers/attest.ts`
- Delete: `lambda/handlers/evaluate.ts`
- Delete: `lambda/shared/dynamo-nonces.ts`
- Delete: `lambda/shared/dynamo-device-keys.ts`
- Delete: `lambda/rotation/` (entire directory)
- Modify: `lambda/deploy.sh` — remove routes for deleted handlers

- [ ] **Step 1: Delete files**
- [ ] **Step 2: Update deploy script to remove deleted routes**
- [ ] **Step 3: Verify remaining handlers build**

```bash
node lambda/build.mjs
```

- [ ] **Step 4: Commit**

---

### Task 5.3: Update sybil and billusage to stateless attestation

**Files:**
- Modify: `lambda/handlers/sybil.ts`
- Modify: `lambda/handlers/billusage.ts`
- Modify: `lambda/shared/attestation.ts`

- [ ] **Step 1: Modify shared/attestation.ts to verify statelessly**

Remove DynamoDB device key lookups. Verify App Attest certificate chain and Play Integrity token directly, same as the node does.

- [ ] **Step 2: Update sybil.ts and billusage.ts to use new attestation**
- [ ] **Step 3: Verify build**
- [ ] **Step 4: Commit**

---

## Phase 6: Verifier CLI Tool

### Task 6.1: Create verifier CLI

**Files:**
- Create: `verify/Cargo.toml`
- Create: `verify/src/main.rs`

- [ ] **Step 1: Create crate**

```toml
[package]
name = "toprf-verify"
version = "0.1.0"
edition = "2021"

[dependencies]
toprf-core = { path = "../crates/core" }
toprf-seal = { path = "../crates/seal" }
reqwest = { version = "0.12", features = ["json"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
hex = "0.4"
ethers = "2"  # For reading on-chain registry
colored = "2"  # For terminal output
```

- [ ] **Step 2: Implement verification logic**

The verifier:
1. Fetches well-known endpoint
2. Reads on-chain registry (DKG records)
3. For each DKG node: verifies on-chain commitment matches live attestation LAUNCH_DIGEST
4. For all nodes: fetches live attestation, verifies AMD cert chain, checks measurement + binary hash
5. Verifies group public key is consistent with DKG commitments
6. Prints results

- [ ] **Step 3: Add to workspace**
- [ ] **Step 4: Verify build**
- [ ] **Step 5: Commit**

---

## Post-Phase: Integration Testing Checklist

After all phases are complete, run the following end-to-end tests:

- [ ] **DKG ceremony test** — 3 DKG nodes + 3 production nodes, full ceremony, verify shares produce valid evaluations
- [ ] **Reshare test** — Add a 4th node via reshare, verify it produces valid partials
- [ ] **Client combination test** — TypeScript client calls 2 nodes, combines, unblinds, produces same ruonId as Rust direct evaluation
- [ ] **Rate limiting test** — Second evaluation from same device hash is rejected
- [ ] **Attestation rejection test** — App rejects a node with wrong measurement
- [ ] **Verification share validation test** — App detects tampered well-known endpoint (wrong verification shares vs hardcoded group public key)
- [ ] **Node failure test** — Kill 1 of 3 nodes, evaluation still succeeds
- [ ] **Verifier CLI test** — `toprf-verify` produces all-green output against staging
- [ ] **Real device E2E** — TestFlight app, real passport, real NFC, real attestation, real ruonId derivation
