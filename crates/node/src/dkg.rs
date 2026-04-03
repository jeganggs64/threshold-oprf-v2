//! DKG (Distributed Key Generation) module for genesis mode.
//!
//! When a node boots with `--genesis`, it participates in a FROST DKG ceremony
//! with peer nodes. After the ceremony completes, the node holds a key share
//! that it seals to disk and loads into `NodeState`, transitioning to normal
//! operational mode.
//!
//! Endpoints:
//!   POST /dkg/round1 — generate polynomial + commitment (FROST part1)
//!   POST /dkg/round2 — receive round1 packages, produce round2 packages (FROST part2)
//!   POST /dkg/round3 — receive round1+round2 packages, finalize key (FROST part3),
//!                       seal key share, transition to normal mode

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use frost_secp256k1 as frost;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use toprf_core::{hex_to_scalar, NodeKeyShare};

use crate::{LoadedKey, NodeState};

// -- DKG state --

/// Holds the FROST DKG state for genesis mode. Stored as
/// `Option<Arc<DkgState>>` inside `NodeState` — `Some` only when the node
/// was started with `--genesis`.
pub struct DkgState {
    pub identifier: frost::Identifier,
    pub node_id: u16,
    pub max_signers: u16,
    pub min_signers: u16,
    pub round1_secret: Mutex<Option<frost::keys::dkg::round1::SecretPackage>>,
    pub round2_secret: Mutex<Option<frost::keys::dkg::round2::SecretPackage>>,
    pub round1_package: Mutex<Option<String>>,
}

impl DkgState {
    pub fn new(node_id: u16, threshold: u16, total: u16) -> Self {
        let identifier = frost::Identifier::try_from(node_id).expect("valid FROST identifier");
        Self {
            identifier,
            node_id,
            max_signers: total,
            min_signers: threshold,
            round1_secret: Mutex::new(None),
            round2_secret: Mutex::new(None),
            round1_package: Mutex::new(None),
        }
    }
}

// -- Request/response types --

#[derive(Serialize)]
pub struct Round1Response {
    pub identifier: String,
    pub package: String,
}

#[derive(Deserialize)]
pub struct Round2Request {
    pub round1_packages: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct Round2Response {
    pub round2_packages: BTreeMap<String, String>,
}

#[derive(Deserialize)]
pub struct Round3Request {
    pub round1_packages: BTreeMap<String, String>,
    pub round2_packages: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct Round3Response {
    pub node_id: u16,
    pub verification_share: String,
    pub group_public_key: String,
    pub threshold: u16,
    pub total_shares: u16,
}

// -- Error response helper --

#[derive(Serialize)]
pub struct DkgErrorResponse {
    pub error: String,
}

fn error_response(
    status: StatusCode,
    msg: impl Into<String>,
) -> (StatusCode, Json<DkgErrorResponse>) {
    let msg = msg.into();
    error!("{}", msg);
    (status, Json(DkgErrorResponse { error: msg }))
}

/// Guard: returns 403 if the node already has a key loaded (DKG already
/// completed) or if the node was not started in genesis mode.
fn require_dkg_state(
    state: &NodeState,
) -> Result<&Arc<DkgState>, (StatusCode, Json<DkgErrorResponse>)> {
    if state.loaded_key.get().is_some() {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "DKG already completed — key is sealed",
        ));
    }
    state.dkg_state.get().ok_or_else(|| {
        error_response(
            StatusCode::NOT_FOUND,
            "node is not in genesis mode — send POST /configure first",
        )
    })
}

// -- Handlers --

pub async fn round1_handler(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<Round1Response>, (StatusCode, Json<DkgErrorResponse>)> {
    let dkg = require_dkg_state(&state)?;

    // Check if round1 was already run
    {
        let guard = dkg.round1_package.lock().unwrap();
        if guard.is_some() {
            return Err(error_response(
                StatusCode::CONFLICT,
                "round1 already executed",
            ));
        }
    }

    let (secret_package, round1_package) =
        frost::keys::dkg::part1(dkg.identifier, dkg.max_signers, dkg.min_signers, OsRng).map_err(
            |e| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("FROST part1 failed: {e}"),
                )
            },
        )?;

    // Serialize the round1 package
    let package_json = serde_json::to_string(&round1_package).map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize round1 package: {e}"),
        )
    })?;

    // Serialize our identifier
    let id_hex = hex::encode(dkg.identifier.serialize());

    // Store the secret and package
    {
        let mut guard = dkg.round1_secret.lock().unwrap();
        *guard = Some(secret_package);
    }
    {
        let mut guard = dkg.round1_package.lock().unwrap();
        *guard = Some(package_json.clone());
    }

    info!(node_id = dkg.node_id, "DKG round1 complete");

    Ok(Json(Round1Response {
        identifier: id_hex,
        package: package_json,
    }))
}

pub async fn round2_handler(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<Round2Request>,
) -> Result<Json<Round2Response>, (StatusCode, Json<DkgErrorResponse>)> {
    let dkg = require_dkg_state(&state)?;

    // Take the round1 secret (consumed by part2)
    let secret_package = {
        let mut guard = dkg.round1_secret.lock().unwrap();
        guard.take().ok_or_else(|| {
            error_response(
                StatusCode::BAD_REQUEST,
                "round1 not yet executed or round2 already executed",
            )
        })?
    };

    // Deserialize round1 packages from other participants
    let mut round1_packages: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> =
        BTreeMap::new();

    for (id_hex, pkg_json) in &req.round1_packages {
        let id_bytes = hex::decode(id_hex).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid identifier hex '{id_hex}': {e}"),
            )
        })?;
        let identifier = frost::Identifier::deserialize(&id_bytes).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid FROST identifier '{id_hex}': {e}"),
            )
        })?;
        let package: frost::keys::dkg::round1::Package =
            serde_json::from_str(pkg_json).map_err(|e| {
                error_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid round1 package for '{id_hex}': {e}"),
                )
            })?;
        round1_packages.insert(identifier, package);
    }

    // Run FROST part2
    let (round2_secret, round2_packages) =
        frost::keys::dkg::part2(secret_package, &round1_packages).map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("FROST part2 failed: {e}"),
            )
        })?;

    // Store the round2 secret for part3
    {
        let mut guard = dkg.round2_secret.lock().unwrap();
        *guard = Some(round2_secret);
    }

    // Serialize the round2 packages for each participant
    let mut response_packages = BTreeMap::new();
    for (identifier, package) in &round2_packages {
        let id_hex = hex::encode(identifier.serialize());
        let pkg_json = serde_json::to_string(package).map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to serialize round2 package: {e}"),
            )
        })?;
        response_packages.insert(id_hex, pkg_json);
    }

    info!(
        node_id = dkg.node_id,
        recipients = response_packages.len(),
        "DKG round2 complete"
    );

    Ok(Json(Round2Response {
        round2_packages: response_packages,
    }))
}

pub async fn round3_handler(
    State(state): State<Arc<NodeState>>,
    Json(req): Json<Round3Request>,
) -> Result<Json<Round3Response>, (StatusCode, Json<DkgErrorResponse>)> {
    let dkg = require_dkg_state(&state)?;

    // Take the round2 secret (consumed — round3 can only be called once)
    let round2_secret = {
        let mut guard = dkg.round2_secret.lock().unwrap();
        guard.take().ok_or_else(|| {
            error_response(
                StatusCode::BAD_REQUEST,
                "round2 not yet executed or round3 already executed",
            )
        })?
    };

    // Deserialize round1 packages
    let mut round1_packages: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> =
        BTreeMap::new();

    for (id_hex, pkg_json) in &req.round1_packages {
        let id_bytes = hex::decode(id_hex).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid identifier hex '{id_hex}': {e}"),
            )
        })?;
        let identifier = frost::Identifier::deserialize(&id_bytes).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid FROST identifier '{id_hex}': {e}"),
            )
        })?;
        let package: frost::keys::dkg::round1::Package =
            serde_json::from_str(pkg_json).map_err(|e| {
                error_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid round1 package for '{id_hex}': {e}"),
                )
            })?;
        round1_packages.insert(identifier, package);
    }

    // Deserialize round2 packages
    let mut round2_packages: BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package> =
        BTreeMap::new();

    for (id_hex, pkg_json) in &req.round2_packages {
        let id_bytes = hex::decode(id_hex).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid identifier hex '{id_hex}': {e}"),
            )
        })?;
        let identifier = frost::Identifier::deserialize(&id_bytes).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid FROST identifier '{id_hex}': {e}"),
            )
        })?;
        let package: frost::keys::dkg::round2::Package =
            serde_json::from_str(pkg_json).map_err(|e| {
                error_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid round2 package for '{id_hex}': {e}"),
                )
            })?;
        round2_packages.insert(identifier, package);
    }

    // Run FROST part3
    let (key_package, _public_key_package) =
        frost::keys::dkg::part3(&round2_secret, &round1_packages, &round2_packages).map_err(
            |e| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("FROST part3 failed: {e}"),
                )
            },
        )?;

    // Extract the raw scalar share and verification info
    let signing_share = key_package.signing_share();
    let share_bytes = signing_share.serialize();
    let share_hex = hex::encode(&share_bytes);

    let verifying_share = key_package.verifying_share();
    let vs_bytes = verifying_share.serialize().map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize verifying share: {e}"),
        )
    })?;
    let vs_hex = hex::encode(&vs_bytes);

    let group_key = key_package.verifying_key();
    let gk_bytes = group_key.serialize().map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize group key: {e}"),
        )
    })?;
    let gk_hex = hex::encode(&gk_bytes);

    // Build the NodeKeyShare
    let node_key_share = NodeKeyShare {
        node_id: dkg.node_id,
        secret_share: share_hex.clone(),
        verification_share: vs_hex.clone(),
        group_public_key: gk_hex.clone(),
        threshold: dkg.min_signers,
        total_shares: dkg.max_signers,
    };

    // Seal to disk (same as join.rs)
    let share_json = serde_json::to_vec_pretty(&node_key_share).map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize key share: {e}"),
        )
    })?;
    let key_path = state.data_dir.as_deref().unwrap_or(".");
    let key_file = format!("{}/node-key.json", key_path);
    std::fs::write(&key_file, &share_json).map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to write key to disk: {e}"),
        )
    })?;

    // Load into NodeState (same as join.rs)
    let key_scalar = hex_to_scalar(&share_hex).map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("internal error: invalid secret_share after DKG: {e}"),
        )
    })?;

    let loaded = LoadedKey {
        node_id: dkg.node_id,
        key_share: key_scalar,
        verification_share: vs_hex.clone(),
        group_public_key: gk_hex.clone(),
        threshold: dkg.min_signers,
        total_shares: dkg.max_signers,
    };

    state.loaded_key.set(loaded).map_err(|_| {
        error_response(
            StatusCode::CONFLICT,
            "key was set concurrently — node already initialized",
        )
    })?;

    info!(
        node_id = dkg.node_id,
        group_public_key = %gk_hex,
        "DKG round3 complete — key share sealed and loaded, transitioning to normal mode"
    );

    Ok(Json(Round3Response {
        node_id: dkg.node_id,
        verification_share: vs_hex,
        group_public_key: gk_hex,
        threshold: dkg.min_signers,
        total_shares: dkg.max_signers,
    }))
}
