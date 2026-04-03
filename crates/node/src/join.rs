//! Join mode endpoints for receiving key shares from donor nodes.
//!
//! `GET  /join-info` — returns the node's ephemeral X25519 public key so DKG
//! nodes can ECIES-encrypt contributions directly to this production node.
//!
//! `POST /reshare/receive` — accepts encrypted or plaintext contributions from
//! donor nodes, combines them using Lagrange interpolation, verifies against
//! the group public key, and seals the resulting key share into node state.
//!
//! This endpoint is used both during initial DKG (receiving contributions from
//! DKG participants) and later resharing (receiving contributions from existing
//! donor nodes).
//!
//! The handler rejects requests if the node already has a key loaded (403),
//! ensuring it can only be called once to initialize the node.

use axum::{extract::State, http::StatusCode, Json};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use toprf_core::reshare::{self, SerializableReshareContribution};
use toprf_core::{hex_to_scalar, NodeKeyShare};

use crate::{LoadedKey, NodeState};

/// Response body for GET /join-info.
#[derive(Serialize)]
pub struct JoinInfoResponse {
    /// Hex-encoded 32-byte X25519 public key for ECIES encryption.
    pub ephemeral_pubkey: String,
}

/// GET /join-info — returns the node's ephemeral X25519 public key.
///
/// Only available after /configure and for 1 hour. Returns 403 after expiry.
pub async fn join_info_handler(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<JoinInfoResponse>, (StatusCode, String)> {
    // Must be configured
    if state.configured.get().is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "not configured — send POST /configure first".to_string(),
        ));
    }

    // Expires 1 hour after /configure
    if let Some(configured_at) = state.configured_at.get() {
        if configured_at.elapsed() > std::time::Duration::from_secs(3600) {
            return Err((
                StatusCode::FORBIDDEN,
                "join-info expired (1 hour after configure)".to_string(),
            ));
        }
    }

    let (_, pubkey) = &state.join_keypair;
    Ok(Json(JoinInfoResponse {
        ephemeral_pubkey: hex::encode(pubkey.as_bytes()),
    }))
}

/// Request body for POST /reshare/receive.
#[derive(Deserialize)]
pub struct ReshareReceiveRequest {
    /// Contributions from donor nodes (one per donor).
    pub contributions: Vec<SerializableReshareContribution>,
    /// IDs of all participating donor nodes.
    pub participant_ids: Vec<u16>,
    /// The group public key (compressed point hex).
    pub group_public_key: String,
    /// Threshold (min_signers).
    pub threshold: u16,
    /// Total number of shares (max_signers).
    pub total_shares: u16,
    /// The new node's ID (this node's ID).
    pub new_node_id: u16,
}

/// Response body from POST /reshare/receive.
#[derive(Serialize)]
pub struct ReshareReceiveResponse {
    /// This node's assigned ID.
    pub node_id: u16,
    /// The verification share for the newly created key (compressed point hex).
    pub verification_share: String,
    /// Status of the operation.
    pub status: String,
}

/// POST /reshare/receive — new node endpoint.
///
/// Combines contributions from donor nodes into a key share, verifies it
/// against the group public key, writes it to disk, and loads it into state.
pub async fn reshare_receive_handler(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<ReshareReceiveRequest>,
) -> Result<Json<ReshareReceiveResponse>, (StatusCode, String)> {
    // Hold the join lock for the entire operation to prevent TOCTOU races
    let _join_lock = state.join_in_progress.lock().unwrap();

    // 1. Reject if already has a key
    if state.loaded_key.get().is_some() {
        warn!("reshare/receive: node already has a key loaded — rejecting");
        return Err((
            StatusCode::FORBIDDEN,
            "node already has a key loaded".to_string(),
        ));
    }

    // 2. Validate inputs
    if req.new_node_id == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "new_node_id must be nonzero".to_string(),
        ));
    }
    if req.contributions.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "no contributions provided".to_string(),
        ));
    }
    if req.participant_ids.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "participant_ids must not be empty".to_string(),
        ));
    }
    if req.threshold == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "threshold must be nonzero".to_string(),
        ));
    }
    if req.total_shares == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "total_shares must be nonzero".to_string(),
        ));
    }

    // 3. Decode each contribution (plaintext or ECIES-encrypted)
    let mut decoded: Vec<(u16, k256::Scalar, String)> = Vec::with_capacity(req.contributions.len());
    for contribution in &req.contributions {
        let scalar = if contribution.encrypted {
            // ECIES-encrypted: decrypt using join keypair
            let secret = &state.join_keypair.0;
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(&contribution.sub_share_data)
                .map_err(|e| {
                    warn!(
                        from_node_id = contribution.from_node_id,
                        "reshare/receive: invalid base64: {e}"
                    );
                    (
                        StatusCode::BAD_REQUEST,
                        format!(
                            "invalid base64 in encrypted contribution from node {}: {e}",
                            contribution.from_node_id
                        ),
                    )
                })?;
            let plaintext = toprf_seal::ecies::decrypt(secret, &ciphertext).map_err(|e| {
                warn!(
                    from_node_id = contribution.from_node_id,
                    "reshare/receive: ECIES decrypt failed: {e}"
                );
                (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "ECIES decrypt failed for contribution from node {}: {e}",
                        contribution.from_node_id
                    ),
                )
            })?;
            // plaintext is the scalar bytes (32 bytes)
            hex_to_scalar(&hex::encode(&*plaintext)).map_err(|e| {
                warn!(
                    from_node_id = contribution.from_node_id,
                    "reshare/receive: invalid scalar after decrypt: {e}"
                );
                (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "invalid scalar in decrypted contribution from node {}: {e}",
                        contribution.from_node_id
                    ),
                )
            })?
        } else {
            // Plaintext: decode directly
            reshare::decode_plaintext_sub_share(contribution).map_err(|e| {
                warn!(
                    from_node_id = contribution.from_node_id,
                    "reshare/receive: failed to decode contribution: {e}"
                );
                (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "failed to decode contribution from node {}: {e}",
                        contribution.from_node_id
                    ),
                )
            })?
        };
        decoded.push((
            contribution.from_node_id,
            scalar,
            contribution.verification_share.clone(),
        ));
    }

    // 4. Combine contributions into new key share (includes verification)
    let key_share: NodeKeyShare = reshare::combine_recovery_contributions(
        req.new_node_id,
        &decoded,
        &req.participant_ids,
        &req.group_public_key,
        req.threshold,
        req.total_shares,
    )
    .map_err(|e| {
        warn!("reshare/receive: combine_recovery_contributions failed: {e}");
        (
            StatusCode::BAD_REQUEST,
            format!("failed to combine contributions: {e}"),
        )
    })?;

    // 5. Save to disk (dev mode — production would seal)
    let share_json = serde_json::to_vec_pretty(&key_share).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize key share: {e}"),
        )
    })?;
    let key_path = state.data_dir.as_deref().unwrap_or(".");
    let key_file = format!("{}/node-key.json", key_path);
    std::fs::write(&key_file, &share_json).map_err(|e| {
        warn!("reshare/receive: failed to write {}: {e}", key_file);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to write key to disk: {e}"),
        )
    })?;

    // 6. Convert NodeKeyShare to LoadedKey and store in OnceLock
    let node_id = key_share.node_id;
    let verification_share = key_share.verification_share.clone();

    let key_scalar = hex_to_scalar(&key_share.secret_share).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("internal error: invalid secret_share after combine: {e}"),
        )
    })?;

    let loaded = LoadedKey {
        node_id: key_share.node_id,
        key_share: key_scalar,
        verification_share: key_share.verification_share.clone(),
        group_public_key: key_share.group_public_key.clone(),
        threshold: key_share.threshold,
        total_shares: key_share.total_shares,
    };

    state.loaded_key.set(loaded).map_err(|_| {
        // This can only happen if another request raced us — still shouldn't happen
        // given the check at the top, but handle it gracefully.
        warn!("reshare/receive: OnceLock already set (race condition)");
        (
            StatusCode::CONFLICT,
            "key was set concurrently — node already initialized".to_string(),
        )
    })?;

    info!(
        node_id = node_id,
        threshold = req.threshold,
        total_shares = req.total_shares,
        "reshare/receive: key share received, verified, and loaded"
    );

    // 7. Return response
    Ok(Json(ReshareReceiveResponse {
        node_id,
        verification_share,
        status: "sealed".to_string(),
    }))
}
