//! Handler for POST /partial-evaluate with attestation gating and rate limiting.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use toprf_core::partial_eval::partial_evaluate;
use toprf_core::{hex_to_point, PartialEvaluation};

use crate::{attestation, NodeState};

#[derive(Deserialize)]
pub struct PartialEvalRequest {
    pub blinded_point: String,
    pub attestation: attestation::AttestationPayload,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn partial_evaluate_handler(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<PartialEvalRequest>,
) -> Result<Json<PartialEvaluation>, (StatusCode, Json<ErrorResponse>)> {
    // 1. Compute expected client_data_hash = sha256(blinded_point_bytes)
    let blinded_bytes = hex::decode(&req.blinded_point)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("invalid hex: {e}")))?;
    let expected_cdh: [u8; 32] = Sha256::digest(&blinded_bytes).into();

    // 2. Verify device attestation (stateless)
    let att_result = attestation::verify_attestation(&req.attestation, &expected_cdh)
        .await
        .map_err(|e| error_response(StatusCode::FORBIDDEN, &format!("attestation failed: {e}")))?;

    // 3. Rate limit
    state
        .rate_limiter
        .check_and_increment(&att_result.device_id_hash)
        .map_err(|retry_after| {
            error_response(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("rate limited, retry after {}s", retry_after.as_secs()),
            )
        })?;

    // 4. Compute partial evaluation
    let loaded = state
        .loaded_key
        .get()
        .ok_or_else(|| error_response(StatusCode::SERVICE_UNAVAILABLE, "key not loaded"))?;
    let blinded_point = hex_to_point(&req.blinded_point)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("invalid point: {e}")))?;
    let partial = partial_evaluate(loaded.node_id, &loaded.key_share, &blinded_point)
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("eval error: {e}"),
            )
        })?;

    Ok(Json(partial))
}

fn error_response(status: StatusCode, msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}
