//! Runtime configuration endpoint.
//!
//! `POST /configure`: sets the node's mode (genesis or join) and parameters.
//! Can only be called once. After configuration, returns 403.
//!
//! This allows all nodes to boot from the same image (identical PCRs)
//! and receive their mode/config at runtime from the DKG CLI.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::dkg;
use crate::NodeState;

#[derive(Deserialize)]
pub struct ConfigureRequest {
    /// "genesis" or "join"
    pub mode: String,
    /// Node ID (required for genesis)
    #[serde(default)]
    pub node_id: Option<u16>,
    /// Threshold (required for genesis)
    #[serde(default)]
    pub threshold: Option<u16>,
    /// Total number of nodes (required for genesis)
    #[serde(default)]
    pub total: Option<u16>,
}

#[derive(Serialize)]
pub struct ConfigureResponse {
    pub status: String,
    pub mode: String,
}

pub async fn configure_handler(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<ConfigureRequest>,
) -> Result<Json<ConfigureResponse>, (StatusCode, String)> {
    // Can only configure once
    if state.configured.get().is_some() {
        return Err((
            StatusCode::FORBIDDEN,
            "node is already configured".to_string(),
        ));
    }

    // Also reject if key is already loaded (shouldn't happen, but guard)
    if state.loaded_key.get().is_some() {
        return Err((
            StatusCode::FORBIDDEN,
            "node already has a key loaded".to_string(),
        ));
    }

    match req.mode.as_str() {
        "genesis" => {
            let node_id = req.node_id.ok_or((
                StatusCode::BAD_REQUEST,
                "node_id is required for genesis mode".to_string(),
            ))?;
            let threshold = req.threshold.ok_or((
                StatusCode::BAD_REQUEST,
                "threshold is required for genesis mode".to_string(),
            ))?;
            let total = req.total.ok_or((
                StatusCode::BAD_REQUEST,
                "total is required for genesis mode".to_string(),
            ))?;

            if node_id == 0 {
                return Err((StatusCode::BAD_REQUEST, "node_id must be >= 1".to_string()));
            }
            if threshold < 2 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "threshold must be >= 2".to_string(),
                ));
            }
            if total < threshold {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "total must be >= threshold".to_string(),
                ));
            }

            let dkg_state = Arc::new(dkg::DkgState::new(node_id, threshold, total));
            state
                .dkg_state
                .set(dkg_state)
                .map_err(|_| (StatusCode::CONFLICT, "DKG state already set".to_string()))?;

            state
                .configured
                .set("genesis".to_string())
                .map_err(|_| (StatusCode::CONFLICT, "already configured".to_string()))?;
            let _ = state.configured_at.set(std::time::Instant::now());

            info!(
                node_id = node_id,
                threshold = threshold,
                total = total,
                "configured for genesis mode, DKG endpoints active"
            );

            Ok(Json(ConfigureResponse {
                status: "configured".to_string(),
                mode: "genesis".to_string(),
            }))
        }
        "join" => {
            state
                .configured
                .set("join".to_string())
                .map_err(|_| (StatusCode::CONFLICT, "already configured".to_string()))?;
            let _ = state.configured_at.set(std::time::Instant::now());

            info!("configured for join mode, waiting for /reshare/receive");

            Ok(Json(ConfigureResponse {
                status: "configured".to_string(),
                mode: "join".to_string(),
            }))
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            format!("unknown mode: {other} (expected 'genesis' or 'join')"),
        )),
    }
}
