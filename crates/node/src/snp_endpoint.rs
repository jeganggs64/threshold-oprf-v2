//! AMD SEV-SNP attestation endpoint.
//!
//! Returns the node's cached attestation report so that clients can verify
//! this node is running legitimate code inside a genuine AMD SEV-SNP TEE.
//!
//! The report is generated once at boot (on real SNP hardware) and stored in
//! `NodeState::cached_attestation`. In dev/test environments without SNP
//! hardware the field is `None` and the endpoint returns 503.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use std::sync::Arc;

use crate::NodeState;

#[derive(Clone, Serialize)]
pub struct AttestationResponse {
    pub node_id: u16,
    pub attestation_report: String, // base64 encoded AMD SNP report
    pub cert_chain: String,         // base64 encoded cert chain (VCEK/VLEK → ASK → ARK)
    pub generated_at: String,       // ISO 8601 timestamp
}

pub async fn attestation_handler(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<AttestationResponse>, (StatusCode, String)> {
    let cached = state.cached_attestation.read().unwrap();
    match cached.as_ref() {
        Some(att) => Ok(Json(att.clone())),
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Attestation report not available (non-TEE environment)".to_string(),
        )),
    }
}
