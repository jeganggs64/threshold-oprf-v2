//! AMD SEV-SNP attestation endpoint (challenge-response).
//!
//! The client sends a random 32-byte nonce; the node generates a fresh AMD
//! SEV-SNP attestation report with the nonce embedded in REPORT_DATA[32..64].
//! REPORT_DATA[0..32] contains a static identity hash:
//!   sha256(binary_hash || verificationShare || groupPublicKey)
//!
//! In dev/test environments without SNP hardware the endpoint returns 503.

use axum::{extract::{Query, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::NodeState;

#[derive(Deserialize)]
pub struct AttestationQuery {
    /// 32-byte hex-encoded nonce from the client.
    pub nonce: String,
}

#[derive(Clone, Serialize)]
pub struct AttestationResponse {
    pub node_id: u16,
    pub attestation_report: String, // base64 encoded AMD SNP report
    pub cert_chain: String,         // base64 encoded cert chain (VCEK/VLEK -> ASK -> ARK)
}

pub async fn attestation_handler(
    State(state): State<Arc<NodeState>>,
    Query(query): Query<AttestationQuery>,
) -> Result<Json<AttestationResponse>, (StatusCode, String)> {
    // Validate nonce is 32 bytes hex (64 hex chars)
    let nonce_bytes = hex::decode(&query.nonce)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid nonce hex: {e}")))?;
    if nonce_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("nonce must be 32 bytes, got {}", nonce_bytes.len()),
        ));
    }

    // Build REPORT_DATA:
    // [0..32] = sha256(binary_hash || verificationShare || groupPublicKey)
    // [32..64] = nonce (verbatim)
    let loaded = state
        .loaded_key
        .get()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "key not loaded".to_string()))?;

    let mut report_data = [0u8; 64];

    // Static identity hash
    let identity_input = format!(
        "{}{}{}",
        state.binary_hash.as_deref().unwrap_or("unknown"),
        loaded.verification_share,
        loaded.group_public_key
    );
    let identity_hash = Sha256::digest(identity_input.as_bytes());
    report_data[0..32].copy_from_slice(&identity_hash);

    // Nonce
    report_data[32..64].copy_from_slice(&nonce_bytes);

    // In production: call /dev/sev-guest ioctl with this report_data
    // The actual SEV-SNP report generation would be:
    //   let report = toprf_seal::provider::get_attestation_report(Some(&report_data))?;
    //
    // For now: return 503 in non-TEE environment (app handles this gracefully in dev mode)
    let _ = report_data; // suppress unused warning
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "TEE attestation not available (non-SNP environment)".to_string(),
    ))
}
