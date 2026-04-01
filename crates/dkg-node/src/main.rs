//! DKG ceremony node — runs on temporary TEE VMs during the distributed key
//! generation ceremony.
//!
//! Each DKG node participates in the FROST DKG protocol (part1, part2, part3)
//! to generate threshold key shares. After the ceremony completes, the raw
//! scalar shares are extracted and delivered to the production TOPRF nodes.
//! The DKG VMs are then terminated.
//!
//! Endpoints:
//!   GET  /health      — liveness check
//!   POST /dkg/round1  — generate polynomial + commitment (FROST part1)
//!   POST /dkg/round2  — receive round1 packages, produce round2 packages (FROST part2)
//!   POST /dkg/round3  — receive round1+round2 packages, finalize key (FROST part3)
//!
//! Usage:
//!   toprf-dkg-node --node-id 1 --threshold 2 --total 3 --port 4001

use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use frost_secp256k1 as frost;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use toprf_core::NodeKeyShare;

// -- Application state --

struct DkgState {
    identifier: frost::Identifier,
    node_id: u16,
    max_signers: u16,
    min_signers: u16,
    round1_secret: Mutex<Option<frost::keys::dkg::round1::SecretPackage>>,
    round2_secret: Mutex<Option<frost::keys::dkg::round2::SecretPackage>>,
    round1_package: Mutex<Option<String>>,
    key_package: Mutex<Option<frost::keys::KeyPackage>>,
}

// -- Request/response types --

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    node_id: u16,
    threshold: u16,
    total: u16,
}

#[derive(Serialize)]
struct Round1Response {
    identifier: String,
    package: String,
}

#[derive(Deserialize)]
struct Round2Request {
    round1_packages: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct Round2Response {
    round2_packages: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Round3Request {
    round1_packages: BTreeMap<String, String>,
    round2_packages: BTreeMap<String, String>,
}

// -- Error response helper --

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn error_response(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    let msg = msg.into();
    error!("{}", msg);
    (status, Json(ErrorResponse { error: msg }))
}

// -- Handlers --

async fn health(State(state): State<Arc<DkgState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        node_id: state.node_id,
        threshold: state.min_signers,
        total: state.max_signers,
    })
}

async fn round1(
    State(state): State<Arc<DkgState>>,
) -> Result<Json<Round1Response>, (StatusCode, Json<ErrorResponse>)> {
    // Check if round1 was already run
    {
        let guard = state.round1_package.lock().unwrap();
        if guard.is_some() {
            return Err(error_response(
                StatusCode::CONFLICT,
                "round1 already executed",
            ));
        }
    }

    let (secret_package, round1_package) = frost::keys::dkg::part1(
        state.identifier,
        state.max_signers,
        state.min_signers,
        OsRng,
    )
    .map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("FROST part1 failed: {e}"),
        )
    })?;

    // Serialize the round1 package
    let package_json = serde_json::to_string(&round1_package).map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize round1 package: {e}"),
        )
    })?;

    // Serialize our identifier
    let id_hex = hex::encode(state.identifier.serialize());

    // Store the secret and package
    {
        let mut guard = state.round1_secret.lock().unwrap();
        *guard = Some(secret_package);
    }
    {
        let mut guard = state.round1_package.lock().unwrap();
        *guard = Some(package_json.clone());
    }

    info!(node_id = state.node_id, "round1 complete");

    Ok(Json(Round1Response {
        identifier: id_hex,
        package: package_json,
    }))
}

async fn round2(
    State(state): State<Arc<DkgState>>,
    Json(req): Json<Round2Request>,
) -> Result<Json<Round2Response>, (StatusCode, Json<ErrorResponse>)> {
    // Take the round1 secret (consumed by part2)
    let secret_package = {
        let mut guard = state.round1_secret.lock().unwrap();
        guard.take().ok_or_else(|| {
            error_response(
                StatusCode::BAD_REQUEST,
                "round1 not yet executed or round2 already executed",
            )
        })?
    };

    // Deserialize round1 packages from other participants
    let mut round1_packages: BTreeMap<
        frost::Identifier,
        frost::keys::dkg::round1::Package,
    > = BTreeMap::new();

    for (id_hex, pkg_json) in &req.round1_packages {
        let id_bytes = hex::decode(id_hex).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid identifier hex '{id_hex}': {e}"),
            )
        })?;
        let identifier =
            frost::Identifier::deserialize(&id_bytes).map_err(|e| {
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
        let mut guard = state.round2_secret.lock().unwrap();
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
        node_id = state.node_id,
        recipients = response_packages.len(),
        "round2 complete"
    );

    Ok(Json(Round2Response {
        round2_packages: response_packages,
    }))
}

async fn round3(
    State(state): State<Arc<DkgState>>,
    Json(req): Json<Round3Request>,
) -> Result<Json<NodeKeyShare>, (StatusCode, Json<ErrorResponse>)> {
    // Get the round2 secret
    let round2_secret = {
        let guard = state.round2_secret.lock().unwrap();
        guard.as_ref().cloned().ok_or_else(|| {
            error_response(
                StatusCode::BAD_REQUEST,
                "round2 not yet executed",
            )
        })?
    };

    // Deserialize round1 packages
    let mut round1_packages: BTreeMap<
        frost::Identifier,
        frost::keys::dkg::round1::Package,
    > = BTreeMap::new();

    for (id_hex, pkg_json) in &req.round1_packages {
        let id_bytes = hex::decode(id_hex).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid identifier hex '{id_hex}': {e}"),
            )
        })?;
        let identifier =
            frost::Identifier::deserialize(&id_bytes).map_err(|e| {
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
    let mut round2_packages: BTreeMap<
        frost::Identifier,
        frost::keys::dkg::round2::Package,
    > = BTreeMap::new();

    for (id_hex, pkg_json) in &req.round2_packages {
        let id_bytes = hex::decode(id_hex).map_err(|e| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid identifier hex '{id_hex}': {e}"),
            )
        })?;
        let identifier =
            frost::Identifier::deserialize(&id_bytes).map_err(|e| {
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

    // Store the key package
    {
        let mut guard = state.key_package.lock().unwrap();
        *guard = Some(key_package);
    }

    let result = NodeKeyShare {
        node_id: state.node_id,
        secret_share: share_hex,
        verification_share: vs_hex,
        group_public_key: gk_hex,
        threshold: state.min_signers,
        total_shares: state.max_signers,
    };

    info!(
        node_id = state.node_id,
        group_public_key = %result.group_public_key,
        "round3 complete — key share derived"
    );

    Ok(Json(result))
}

// -- Main --

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    let mut port = "4001".to_string();
    let mut node_id: Option<u16> = None;
    let mut threshold: Option<u16> = None;
    let mut total: Option<u16> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --port");
                    std::process::exit(1);
                }
                port = args[i].clone();
            }
            "--node-id" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --node-id");
                    std::process::exit(1);
                }
                node_id = Some(
                    args[i]
                        .parse()
                        .unwrap_or_else(|_| {
                            eprintln!("--node-id must be a positive integer");
                            std::process::exit(1);
                        }),
                );
            }
            "--threshold" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --threshold");
                    std::process::exit(1);
                }
                threshold = Some(
                    args[i]
                        .parse()
                        .unwrap_or_else(|_| {
                            eprintln!("--threshold must be a positive integer");
                            std::process::exit(1);
                        }),
                );
            }
            "--total" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --total");
                    std::process::exit(1);
                }
                total = Some(
                    args[i]
                        .parse()
                        .unwrap_or_else(|_| {
                            eprintln!("--total must be a positive integer");
                            std::process::exit(1);
                        }),
                );
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-dkg-node [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -p, --port <PORT>           Listen port (default: 4001)");
                eprintln!("      --node-id <ID>          Node identifier (1-indexed, required)");
                eprintln!("      --threshold <T>          Minimum signers threshold (required)");
                eprintln!("      --total <N>              Total number of signers (required)");
                eprintln!("  -h, --help                  Show this help");
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let node_id = node_id.unwrap_or_else(|| {
        eprintln!("--node-id is required");
        std::process::exit(1);
    });
    let threshold = threshold.unwrap_or_else(|| {
        eprintln!("--threshold is required");
        std::process::exit(1);
    });
    let total = total.unwrap_or_else(|| {
        eprintln!("--total is required");
        std::process::exit(1);
    });

    if node_id == 0 {
        eprintln!("--node-id must be >= 1");
        std::process::exit(1);
    }
    if threshold < 2 {
        eprintln!("--threshold must be >= 2");
        std::process::exit(1);
    }
    if total < threshold {
        eprintln!("--total must be >= --threshold");
        std::process::exit(1);
    }

    let identifier = frost::Identifier::try_from(node_id).expect("valid FROST identifier");

    let state = Arc::new(DkgState {
        identifier,
        node_id,
        max_signers: total,
        min_signers: threshold,
        round1_secret: Mutex::new(None),
        round2_secret: Mutex::new(None),
        round1_package: Mutex::new(None),
        key_package: Mutex::new(None),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/dkg/round1", post(round1))
        .route("/dkg/round2", post(round2))
        .route("/dkg/round3", post(round3))
        .with_state(state);

    let bind_addr: SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .unwrap_or_else(|e| panic!("invalid bind address: {e}"));

    info!(
        node_id = node_id,
        threshold = threshold,
        total = total,
        addr = %bind_addr,
        "starting toprf-dkg-node"
    );

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind to {bind_addr}: {e}"));

    axum::serve(listener, app)
        .await
        .unwrap_or_else(|e| error!("server error: {e}"));
}
