//! Share recovery endpoint for donor nodes.
//!
//! `POST /reshare` — accepts a new node's attestation data and X25519 public key.
//! Independently verifies attestation based on the target node's platform
//! (looked up from well-known config), generates a recovery contribution
//! (Lagrange-weighted share), ECIES-encrypts it to the verified pubkey, and
//! returns the encrypted sub-share.
//!
//! Platform-aware: the handler looks up the target node's URL in the well-known
//! config to determine which attestation verification to apply (Nitro, SNP, etc.).
//!
//! Security: the donor node is the trust anchor. It verifies the target's
//! attestation independently — the CLI/orchestrator is just a courier.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

use toprf_core::reshare::{generate_recovery_contribution, SerializableReshareContribution};

use crate::config::NodeEntry;
use crate::NodeState;

/// Request body for POST /reshare.
#[derive(Deserialize)]
pub struct ReshareRequest {
    /// The new node's X25519 public key (hex-encoded, 64 chars / 32 bytes).
    pub target_pubkey: String,
    /// The new node's URL — used to look up platform and expected measurements
    /// from the well-known config.
    pub target_url: String,
    /// Base64-encoded attestation data from the target node.
    /// Format depends on platform: Nitro COSE_Sign1 document, SNP report, etc.
    pub attestation_data: String,
    /// Base64-encoded certificate chain (SNP only — Nitro embeds certs in the
    /// COSE_Sign1 document). Optional, reserved for future SNP support.
    #[allow(dead_code)]
    pub cert_chain: Option<String>,
    /// The target new node's ID (1-indexed).
    pub new_node_id: u16,
    /// IDs of all participating donor nodes (must include this node).
    pub participant_ids: Vec<u16>,
    /// Group public key — donor verifies this matches its own.
    pub group_public_key: String,
}

/// Response body from POST /reshare.
#[derive(Serialize)]
pub struct ReshareResponse {
    /// The serializable contribution (ECIES-encrypted sub-share).
    #[serde(flatten)]
    pub contribution: SerializableReshareContribution,
}

/// POST /reshare — donor node endpoint.
pub async fn reshare_handler(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<ReshareRequest>,
) -> Result<Json<ReshareResponse>, axum::response::Response> {
    // 1. Check key is loaded
    let key = state.loaded_key.get().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "no key loaded".to_string()).into_response()
    })?;

    // 2. Verify group_public_key matches this node's
    if req.group_public_key != key.group_public_key {
        warn!(
            expected = %key.group_public_key,
            got = %req.group_public_key,
            "reshare: group_public_key mismatch"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            "group_public_key does not match this node's key".to_string(),
        )
            .into_response());
    }

    // 3. Verify this node is in the participant list
    if !req.participant_ids.contains(&key.node_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("this node ({}) is not in participant_ids", key.node_id),
        )
            .into_response());
    }

    // 4. Verify new_node_id is not in participant_ids
    if req.participant_ids.contains(&req.new_node_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            "new_node_id must not be in participant_ids".to_string(),
        )
            .into_response());
    }

    // 5. Decode the target X25519 public key
    let pubkey_bytes = hex::decode(&req.target_pubkey).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid target_pubkey hex: {e}"),
        )
            .into_response()
    })?;
    if pubkey_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("target_pubkey must be 32 bytes, got {}", pubkey_bytes.len()),
        )
            .into_response());
    }
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);

    // 6. Look up the target node in the well-known config to determine platform
    let wk_config = state.well_known_config.as_ref().ok_or_else(|| {
        warn!("reshare: no well-known config — cannot verify target attestation");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "no well-known config available — cannot verify target node".to_string(),
        )
            .into_response()
    })?;

    let target_entry = wk_config
        .nodes
        .iter()
        .find(|n| n.url == req.target_url)
        .ok_or_else(|| {
            warn!(
                target_url = %req.target_url,
                "reshare: target URL not found in well-known config"
            );
            (
                StatusCode::FORBIDDEN,
                format!(
                    "target URL {} not found in well-known config — not an approved node",
                    req.target_url
                ),
            )
                .into_response()
        })?;

    // 7. Decode attestation data
    use base64::Engine;
    let attestation_bytes = base64::engine::general_purpose::STANDARD
        .decode(&req.attestation_data)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid attestation_data base64: {e}"),
            )
                .into_response()
        })?;

    // 8. Platform-specific attestation verification
    let platform = target_entry.platform.as_deref().unwrap_or("unknown");
    match platform {
        "nitro" => {
            verify_nitro_attestation(&attestation_bytes, &pubkey_bytes, target_entry)?;
        }
        "snp" | "azure-cvm" => {
            // SNP/Azure verification — not yet implemented.
            // When needed, move the old SNP logic here.
            return Err((
                StatusCode::NOT_IMPLEMENTED,
                format!("SNP/Azure CVM attestation verification not yet implemented for resharing"),
            )
                .into_response());
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unsupported platform: {other}"),
            )
                .into_response());
        }
    }

    // 9. Replay protection: reject duplicate attestation data
    let report_digest = {
        let mut hasher = Sha256::new();
        hasher.update(&attestation_bytes);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    };
    {
        let mut seen = state.reshare_seen.lock().unwrap();

        // Evict entries older than TTL
        let now = std::time::Instant::now();
        seen.retain(|(_, ts)| now.duration_since(*ts) < crate::RESHARE_SEEN_TTL);

        if seen.iter().any(|(digest, _)| digest == &report_digest) {
            warn!("reshare: duplicate attestation data — possible replay");
            return Err((
                StatusCode::CONFLICT,
                "reshare request already processed for this attestation data".to_string(),
            )
                .into_response());
        }
        seen.push((report_digest, now));
    }

    info!(
        platform = platform,
        target_url = %req.target_url,
        "reshare: attestation verified successfully"
    );

    // 10. Generate recovery contribution: L_i(new_node_id) * k_i
    let sub_scalar = generate_recovery_contribution(
        key.node_id,
        &key.key_share,
        &req.participant_ids,
        req.new_node_id,
    )
    .map_err(|e| {
        warn!("reshare: contribution generation failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("reshare contribution failed: {e}"),
        )
            .into_response()
    })?;

    // 11. ECIES-encrypt to the verified target pubkey
    let recipient = PublicKey::from(pubkey_arr);
    let raw_bytes = sub_scalar.to_bytes();
    let sub_share_bytes = Zeroizing::new(raw_bytes.to_vec());
    let ciphertext = toprf_seal::ecies::encrypt(&recipient, &sub_share_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("ECIES encryption failed: {e}"),
        )
            .into_response()
    })?;
    let sub_share_data = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

    let donor_vs = key.verification_share.clone();

    info!(
        from_node_id = key.node_id,
        target_node_id = req.new_node_id,
        platform = platform,
        "reshare: recovery contribution generated"
    );

    Ok(Json(ReshareResponse {
        contribution: SerializableReshareContribution {
            from_node_id: key.node_id,
            new_node_id: req.new_node_id,
            sub_share_data,
            encrypted: true,
            verification_share: donor_vs,
        },
    }))
}

// ---------------------------------------------------------------------------
// Platform-specific verification
// ---------------------------------------------------------------------------

/// Verify a Nitro Enclave attestation document for resharing.
///
/// Checks:
/// 1. COSE_Sign1 signature is valid (signed by cert chaining to AWS Nitro Root CA)
/// 2. PCR0, PCR1, PCR2 match expected values from well-known config
/// 3. Enclave is not in debug mode (all-zero PCRs)
/// 4. user_data binds to the target's X25519 public key (SHA-256)
fn verify_nitro_attestation(
    attestation_bytes: &[u8],
    target_pubkey: &[u8],
    node_entry: &NodeEntry,
) -> Result<(), axum::response::Response> {
    // Verify the COSE_Sign1 document (cert chain + signature)
    let attestation = crate::nitro_verify::verify(attestation_bytes).map_err(|e| {
        warn!("reshare: Nitro attestation verification failed: {e}");
        (
            StatusCode::FORBIDDEN,
            format!("Nitro attestation verification failed: {e}"),
        )
            .into_response()
    })?;

    // Reject debug-mode enclaves (all-zero PCRs)
    crate::nitro_verify::reject_debug_mode(&attestation).map_err(|e| {
        warn!("reshare: {e}");
        (StatusCode::FORBIDDEN, e).into_response()
    })?;

    // Check PCR values against expected measurements from well-known config
    let measurements = node_entry.measurements.as_ref().ok_or_else(|| {
        warn!("reshare: no measurements in well-known config for target node");
        (
            StatusCode::FORBIDDEN,
            "no measurements configured for target node in well-known config".to_string(),
        )
            .into_response()
    })?;

    let pcr0 = measurements.pcr0.as_deref().ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            "missing pcr0 in well-known measurements".to_string(),
        )
            .into_response()
    })?;
    let pcr1 = measurements.pcr1.as_deref().ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            "missing pcr1 in well-known measurements".to_string(),
        )
            .into_response()
    })?;
    let pcr2 = measurements.pcr2.as_deref().ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            "missing pcr2 in well-known measurements".to_string(),
        )
            .into_response()
    })?;

    crate::nitro_verify::check_pcrs(&attestation, pcr0, pcr1, pcr2).map_err(|e| {
        warn!("reshare: PCR mismatch: {e}");
        (StatusCode::FORBIDDEN, format!("PCR mismatch: {e}")).into_response()
    })?;

    // Verify user_data binds to the target's X25519 public key
    // user_data = SHA-256(target_pubkey)
    let expected_binding = Sha256::digest(target_pubkey);
    match &attestation.user_data {
        Some(ud) if ud.len() >= 32 => {
            if ud[..32] != expected_binding[..] {
                warn!("reshare: Nitro user_data does not bind to target_pubkey");
                return Err((
                    StatusCode::FORBIDDEN,
                    "Nitro attestation user_data does not bind to target_pubkey".to_string(),
                )
                    .into_response());
            }
        }
        Some(ud) => {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "Nitro attestation user_data too short: {} bytes, need at least 32",
                    ud.len()
                ),
            )
                .into_response());
        }
        None => {
            return Err((
                StatusCode::FORBIDDEN,
                "Nitro attestation has no user_data — cannot verify pubkey binding".to_string(),
            )
                .into_response());
        }
    }

    Ok(())
}
