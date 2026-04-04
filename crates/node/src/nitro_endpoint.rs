//! Nitro Enclave attestation endpoint (challenge-response).
//!
//! The client sends a random 32-byte nonce; the node generates a fresh Nitro
//! attestation document (COSE_Sign1) with:
//!   - user_data[0..32] = SHA-256(ephemeral X25519 pubkey) — key binding
//!   - nonce = the client's nonce — freshness
//!
//! The COSE_Sign1 document is signed by the NSM (Nitro Security Module) and
//! chains to the AWS Nitro Root CA. It contains PCR0/1/2 measurements that
//! prove the enclave's identity.
//!
//! Only works inside a Nitro Enclave (/dev/nsm must exist). Returns 503 outside.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::NodeState;

#[derive(Deserialize)]
pub struct NitroAttestationQuery {
    /// 32-byte hex-encoded nonce from the client.
    pub nonce: String,
}

#[derive(Serialize)]
pub struct NitroAttestationResponse {
    pub node_id: u16,
    /// Base64-encoded COSE_Sign1 attestation document from the NSM.
    pub attestation_document: String,
    pub platform: String,
}

pub async fn nitro_attestation_handler(
    State(state): State<Arc<NodeState>>,
    Query(query): Query<NitroAttestationQuery>,
) -> Result<Json<NitroAttestationResponse>, (StatusCode, String)> {
    // Validate nonce
    let nonce_bytes = hex::decode(&query.nonce)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid nonce hex: {e}")))?;
    if nonce_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("nonce must be 32 bytes, got {}", nonce_bytes.len()),
        ));
    }

    // Build user_data: SHA-256(ephemeral X25519 pubkey) for key binding.
    let (_, pubkey) = &state.join_keypair;
    let user_data = Sha256::digest(pubkey.as_bytes()).to_vec();

    // Request attestation from NSM device
    let document = crate::nsm::request_attestation(Some(&user_data), Some(&nonce_bytes), None)
        .map_err(|e| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Nitro attestation not available: {e}"),
            )
        })?;

    let node_id = state.loaded_key.get().map(|k| k.node_id).unwrap_or(0);

    use base64::Engine;
    Ok(Json(NitroAttestationResponse {
        node_id,
        attestation_document: base64::engine::general_purpose::STANDARD.encode(&document),
        platform: "nitro".to_string(),
    }))
}

// NSM interface is now in crate::nsm (shared with DKG)
