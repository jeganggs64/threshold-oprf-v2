//! TOPRF node server — sealed TEE that evaluates partial OPRF requests.
//!
//! Every node is identical: it holds one key share and serves partial
//! evaluations. The client collects threshold-many partial evaluations and
//! performs Lagrange combination locally.
//!
//! Nodes boot from a single identical image. Configuration (genesis vs join)
//! is sent at runtime via POST /configure from the DKG CLI.
//!
//! Endpoints:
//!   POST /configure       — set mode (genesis or join), called once
//!   GET  /health          — liveness + key status
//!   POST /partial-evaluate — partial OPRF evaluation
//!   POST /reshare         — reshare donor
//!   GET  /attestation     — TEE attestation (feature-gated: nitro or snp)
//!
//! Usage:
//!   toprf-node --port 3001

mod attestation;
pub mod config;
mod configure;
mod dkg;
mod evaluate;
mod google_auth;
pub mod ip_rate_limit;
mod join;
#[cfg(feature = "nitro")]
mod nitro_endpoint;
mod nitro_verify;
pub mod outbound_proxy;
mod rate_limit;
mod reshare_handler;
#[cfg(feature = "snp")]
mod snp_endpoint;

use std::env;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::{DefaultBodyLimit, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use k256::Scalar;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{info, warn};
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
mod vsock_server;

// -- Application state --

/// TTL for reshare attestation digest replay protection (1 hour).
const RESHARE_SEEN_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

pub struct NodeState {
    /// The loaded key material. Set exactly once after DKG or reshare.
    pub(crate) loaded_key: OnceLock<LoadedKey>,
    /// Tracks attestation report digests already processed by /reshare.
    pub reshare_seen: std::sync::Mutex<Vec<([u8; 32], std::time::Instant)>>,
    /// SHA-256 hash of the node binary, computed at boot.
    pub binary_hash: Option<String>,
    /// Per-device rate limiter for /partial-evaluate.
    pub rate_limiter: rate_limit::RateLimiter,
    /// Directory for persisting key files.
    pub data_dir: Option<String>,
    /// Guards against concurrent join operations.
    pub join_in_progress: std::sync::Mutex<()>,
    /// Ephemeral X25519 keypair for ECIES decryption (always generated at boot).
    pub join_keypair: (x25519_dalek::StaticSecret, x25519_dalek::PublicKey),
    /// DKG state — set via /configure when mode is "genesis".
    pub dkg_state: OnceLock<Arc<dkg::DkgState>>,
    /// Configuration mode — set once via /configure ("genesis" or "join").
    pub configured: OnceLock<String>,
    /// When /configure was called — used to expire /join-info after 1 hour.
    pub configured_at: OnceLock<std::time::Instant>,
    /// Per-route IP-based rate limiters.
    pub ip_limiters: ip_rate_limit::RateLimiters,
}

#[allow(dead_code)]
pub(crate) struct LoadedKey {
    pub(crate) node_id: u16,
    pub(crate) key_share: Scalar,
    pub(crate) verification_share: String,
    pub(crate) group_public_key: String,
    pub(crate) threshold: u16,
    pub(crate) total_shares: u16,
}

impl std::fmt::Debug for LoadedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedKey")
            .field("node_id", &self.node_id)
            .field("key_share", &"<redacted>")
            .finish()
    }
}

impl Drop for LoadedKey {
    fn drop(&mut self) {
        self.key_share.zeroize();
    }
}

// -- Request/response types --

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
}

// -- Handlers --

async fn health(State(state): State<Arc<NodeState>>) -> Json<HealthResponse> {
    let mode = state.configured.get().cloned();

    match state.loaded_key.get() {
        Some(key) => Json(HealthResponse {
            status: "ready".into(),
            node_id: Some(key.node_id),
            mode,
        }),
        None => Json(HealthResponse {
            status: if mode.is_some() {
                "waiting_for_key".into()
            } else {
                "waiting_for_config".into()
            },
            node_id: None,
            mode,
        }),
    }
}

// -- Main --

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    let mut port = env::var("PORT").unwrap_or_else(|_| "3001".into());
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut client_ca: Option<String> = None;
    let mut data_dir: Option<String> = None;
    let mut tcp_mode = false;

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
            "--tls-cert" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --tls-cert");
                    std::process::exit(1);
                }
                tls_cert = Some(args[i].clone());
            }
            "--tls-key" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --tls-key");
                    std::process::exit(1);
                }
                tls_key = Some(args[i].clone());
            }
            "--client-ca" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --client-ca");
                    std::process::exit(1);
                }
                client_ca = Some(args[i].clone());
            }
            "--data-dir" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --data-dir");
                    std::process::exit(1);
                }
                data_dir = Some(args[i].clone());
            }
            "--tcp" => {
                tcp_mode = true;
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-node [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -p, --port <PORT>           Listen port (default: 3001)");
                eprintln!("      --data-dir <PATH>       Directory for persisting key files");
                eprintln!("      --tcp                   Use TCP instead of vsock (dev/test)");
                eprintln!("      --tls-cert <PATH>       TLS server certificate (PEM)");
                eprintln!("      --tls-key <PATH>        TLS server private key (PEM)");
                eprintln!("      --client-ca <PATH>      CA cert for client auth (mTLS)");
                eprintln!("  -h, --help                  Show this help");
                eprintln!();
                eprintln!("The node boots in 'waiting_for_config' state.");
                eprintln!("Send POST /configure to set genesis or join mode.");
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // -- Start outbound vsock bridges (Nitro only) --
    outbound_proxy::start_bridges();

    // Compute sha256 of own binary at boot
    let binary_hash = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::read(&path).ok())
        .map(|bytes| {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&bytes))
        });
    if let Some(ref h) = binary_hash {
        info!(hash = %h, "computed binary hash");
    } else {
        warn!("could not compute binary hash (non-fatal)");
    }

    // Always generate ephemeral keypair (needed for both genesis and join)
    let (secret, pubkey_bytes) = toprf_seal::ecies::generate_keypair();
    let pubkey = x25519_dalek::PublicKey::from(pubkey_bytes);
    info!(
        ephemeral_pubkey = %hex::encode(pubkey.as_bytes()),
        "generated X25519 keypair for ECIES"
    );

    let state = Arc::new(NodeState {
        loaded_key: OnceLock::new(),
        reshare_seen: std::sync::Mutex::new(Vec::with_capacity(64)),
        binary_hash,
        rate_limiter: rate_limit::RateLimiter::new(10, std::time::Duration::from_secs(86400)),
        data_dir,
        join_in_progress: std::sync::Mutex::new(()),
        join_keypair: (secret, pubkey),
        dkg_state: OnceLock::new(),
        configured: OnceLock::new(),
        configured_at: OnceLock::new(),
        ip_limiters: ip_rate_limit::RateLimiters::new(),
    });

    #[allow(unused_mut)]
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/configure", post(configure::configure_handler))
        .route("/join-info", get(join::join_info_handler))
        .route(
            "/partial-evaluate",
            post(evaluate::partial_evaluate_handler),
        )
        .route("/reshare", post(reshare_handler::reshare_handler))
        .route("/reshare/receive", post(join::reshare_receive_handler))
        // DKG routes are always registered — they check dkg_state internally
        .route("/dkg/round1", post(dkg::round1_handler))
        .route("/dkg/round2", post(dkg::round2_handler))
        .route("/dkg/round3", post(dkg::round3_handler));

    // Platform-specific attestation endpoint
    #[cfg(feature = "nitro")]
    {
        app = app.route(
            "/attestation",
            get(nitro_endpoint::nitro_attestation_handler),
        );
    }
    #[cfg(feature = "snp")]
    {
        app = app.route("/attestation", get(snp_endpoint::attestation_handler));
    }

    let app = app
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);

    let port_num: u16 = port.parse().unwrap_or_else(|_| {
        eprintln!("invalid port number: {port}");
        std::process::exit(1);
    });
    let _ = port_num;
    let bind_addr = format!("0.0.0.0:{port}");

    let use_tcp = tcp_mode || !cfg!(target_os = "linux");

    info!("node booted — waiting for POST /configure");

    match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            use axum_server::tls_rustls::RustlsConfig;
            use rustls::server::WebPkiClientVerifier;
            use rustls::RootCertStore;

            let mut rustls_config = if let Some(ca_path) = &client_ca {
                let ca_pem = std::fs::read(ca_path)
                    .unwrap_or_else(|e| panic!("failed to read client CA {ca_path}: {e}"));
                let mut ca_reader = BufReader::new(ca_pem.as_slice());
                let ca_certs = rustls_pemfile::certs(&mut ca_reader)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("failed to parse client CA PEM");

                let mut root_store = RootCertStore::empty();
                for cert in ca_certs {
                    root_store.add(cert).expect("failed to add CA cert");
                }

                let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
                    .build()
                    .expect("failed to build client verifier");

                let cert_pem = std::fs::read(&cert_path)
                    .unwrap_or_else(|e| panic!("failed to read TLS cert {cert_path}: {e}"));
                let key_pem = std::fs::read(&key_path)
                    .unwrap_or_else(|e| panic!("failed to read TLS key {key_path}: {e}"));

                let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_slice()))
                    .collect::<Result<Vec<_>, _>>()
                    .expect("failed to parse server certificate PEM");
                let private_key =
                    rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_slice()))
                        .expect("failed to parse server private key PEM")
                        .expect("no private key found");

                rustls::ServerConfig::builder()
                    .with_client_cert_verifier(client_verifier)
                    .with_single_cert(certs, private_key)
                    .expect("failed to build rustls ServerConfig")
            } else {
                let cert_pem = std::fs::read(&cert_path)
                    .unwrap_or_else(|e| panic!("failed to read TLS cert {cert_path}: {e}"));
                let key_pem = std::fs::read(&key_path)
                    .unwrap_or_else(|e| panic!("failed to read TLS key {key_path}: {e}"));

                let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_slice()))
                    .collect::<Result<Vec<_>, _>>()
                    .expect("failed to parse server certificate PEM");
                let private_key =
                    rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_slice()))
                        .expect("failed to parse server private key PEM")
                        .expect("no private key found");

                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, private_key)
                    .expect("failed to build rustls ServerConfig")
            };

            rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let tls_config = RustlsConfig::from_config(Arc::new(rustls_config));
            let addr: SocketAddr = bind_addr.parse().unwrap();

            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await
                .unwrap_or_else(|e| tracing::error!("server error: {e}"));
        }
        (None, None) if use_tcp => {
            warn!(addr = %bind_addr, "starting on TCP (dev/test)");
            let listener = TcpListener::bind(&bind_addr).await.unwrap();
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| tracing::error!("server error: {e}"));
        }
        #[cfg(target_os = "linux")]
        (None, None) => {
            vsock_server::serve(app, port_num).await;
        }
        #[cfg(not(target_os = "linux"))]
        (None, None) => {
            unreachable!("use_tcp is always true on non-Linux");
        }
        _ => {
            eprintln!("Error: --tls-cert and --tls-key must both be provided (or neither)");
            std::process::exit(1);
        }
    }
}
