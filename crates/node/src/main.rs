//! TOPRF node server — stateless TEE that evaluates partial OPRF requests.
//!
//! Every node is identical: it holds one key share and serves partial
//! evaluations. The client collects threshold-many partial evaluations and
//! performs Lagrange combination locally.
//!
//! Key loading (at boot, never at runtime):
//!
//! **Key file** (testing/dev) — `--key-file <PATH>` loads a NodeKeyShare
//! JSON file from disk at boot.
//!
//! In all modes, the key exists only in memory after loading.
//!
//! Endpoints:
//!   GET  /health           — liveness + key status
//!   POST /partial-evaluate — partial OPRF evaluation
//!   POST /reshare          — reshare donor (generates and returns sub-share)
//!
//! Usage:
//!   toprf-node --port 3001 --key-file /path/to/share.json
//!
//! Environment variables:
//!   PORT                        — HTTP listen port (default: 3001)
//!   EXPECTED_VERIFICATION_SHARE — hex-encoded k_i * G for key verification

mod attestation;
pub mod config;
mod dkg;
mod evaluate;
mod join;
mod rate_limit;
mod reshare_handler;
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
use tracing::{error, info, warn};
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
mod vsock_server;

use toprf_core::{hex_to_point, hex_to_scalar, NodeKeyShare};

// -- Application state --

/// TTL for reshare attestation digest replay protection (1 hour).
/// Entries older than this are evicted on each insertion. A rotation cycle
/// completes well within this window.
const RESHARE_SEEN_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

pub struct NodeState {
    /// The loaded key material. Set exactly once at boot.
    pub(crate) loaded_key: OnceLock<LoadedKey>,
    /// Tracks attestation report digests already processed by /reshare
    /// to prevent replay attacks. Entries are evicted after RESHARE_SEEN_TTL.
    pub reshare_seen: std::sync::Mutex<Vec<([u8; 32], std::time::Instant)>>,
    /// SHA-256 hash of the node binary, computed at boot. Used in attestation
    /// REPORT_DATA[0..32] as part of the identity hash.
    pub binary_hash: Option<String>,
    /// Per-device rate limiter for /partial-evaluate (max 5 evaluations per day).
    pub rate_limiter: rate_limit::RateLimiter,
    /// Well-known config fetched at boot. None in dev/test mode (no --well-known-url).
    pub well_known_config: Option<config::WellKnownConfig>,
    /// Directory for persisting key files. Defaults to current directory.
    pub data_dir: Option<String>,
    /// Guards against concurrent join operations (TOCTOU protection).
    pub join_in_progress: std::sync::Mutex<()>,
    /// Ephemeral X25519 keypair for ECIES decryption in join mode.
    /// Generated at boot when --join is specified.
    pub join_keypair: Option<(x25519_dalek::StaticSecret, x25519_dalek::PublicKey)>,
    /// DKG state for genesis mode. `Some` only when the node was started
    /// with `--genesis`. After round3 completes and the key is sealed,
    /// the DKG endpoints return 403.
    pub dkg_state: Option<Arc<dkg::DkgState>>,
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

// Manual Debug to avoid leaking key_share
impl std::fmt::Debug for LoadedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedKey")
            .field("node_id", &self.node_id)
            .field("key_share", &"<redacted>")
            .finish()
    }
}

// Zeroize key material on drop (defense-in-depth; LoadedKey lives in OnceLock
// for the process lifetime, but this ensures cleanup if that ever changes).
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
}

// -- Handlers --

async fn health(State(state): State<Arc<NodeState>>) -> Json<HealthResponse> {
    match state.loaded_key.get() {
        Some(key) => Json(HealthResponse {
            status: "ready".into(),
            node_id: Some(key.node_id),
        }),
        None => Json(HealthResponse {
            status: "waiting_for_key".into(),
            node_id: None,
        }),
    }
}

// -- Main --

#[tokio::main]
async fn main() {
    // Install the default rustls crypto provider (ring via reqwest's rustls-tls)
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    let mut port = env::var("PORT").unwrap_or_else(|_| "3001".into());
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut client_ca: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut well_known_url: Option<String> = None;
    let mut data_dir: Option<String> = None;
    let mut join_mode = false;
    let mut tcp_mode = false;
    let mut genesis_peers: Option<String> = None;
    let mut genesis_node_id: Option<u16> = None;
    let mut genesis_threshold: Option<u16> = None;
    let mut genesis_total: Option<u16> = None;

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
            "--key-file" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --key-file");
                    std::process::exit(1);
                }
                key_file = Some(args[i].clone());
            }
            "--well-known-url" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --well-known-url");
                    std::process::exit(1);
                }
                well_known_url = Some(args[i].clone());
            }
            "--data-dir" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --data-dir");
                    std::process::exit(1);
                }
                data_dir = Some(args[i].clone());
            }
            "--genesis" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --genesis (comma-separated peer URLs)");
                    std::process::exit(1);
                }
                genesis_peers = Some(args[i].clone());
            }
            "--node-id" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --node-id");
                    std::process::exit(1);
                }
                genesis_node_id = Some(args[i].parse().unwrap_or_else(|_| {
                    eprintln!("--node-id must be a positive integer");
                    std::process::exit(1);
                }));
            }
            "--threshold" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --threshold");
                    std::process::exit(1);
                }
                genesis_threshold = Some(args[i].parse().unwrap_or_else(|_| {
                    eprintln!("--threshold must be a positive integer");
                    std::process::exit(1);
                }));
            }
            "--total" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --total");
                    std::process::exit(1);
                }
                genesis_total = Some(args[i].parse().unwrap_or_else(|_| {
                    eprintln!("--total must be a positive integer");
                    std::process::exit(1);
                }));
            }
            "--join" => {
                join_mode = true;
            }
            "--tcp" => {
                tcp_mode = true;
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-node [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -p, --port <PORT>           Listen port (default: 3001)");
                eprintln!("      --key-file <PATH>       Load key share from JSON file at boot");
                eprintln!("      --well-known-url <URL>  Fetch operational config from well-known endpoint at boot");
                eprintln!("      --data-dir <PATH>       Directory for persisting key files (default: current directory)");
                eprintln!("      --tcp                   Use TCP listener instead of vsock (default on non-Linux; for dev/test)");
                eprintln!("      --join                  Start in join mode: accept /reshare/receive to receive a key share");
                eprintln!("      --genesis <PEERS>       Start in genesis mode: run FROST DKG with comma-separated peer URLs");
                eprintln!("      --node-id <ID>          This node's ID (required for --genesis)");
                eprintln!("      --threshold <T>         Minimum signers threshold (required for --genesis)");
                eprintln!("      --total <N>             Total number of signers (required for --genesis)");
                eprintln!("      --tls-cert <PATH>       TLS server certificate (PEM)");
                eprintln!("      --tls-key <PATH>        TLS server private key (PEM)");
                eprintln!("      --client-ca <PATH>      CA cert for client auth (enables mTLS)");
                eprintln!("  -h, --help                  Show this help");
                eprintln!();
                eprintln!("Environment:");
                eprintln!("  PORT                        Listen port (default: 3001)");
                eprintln!("  EXPECTED_VERIFICATION_SHARE Hex-encoded k_i * G for key verification");
                eprintln!("  (attestation uses /dev/sev-guest ioctl automatically)");
                eprintln!();
                eprintln!("When --tls-cert and --tls-key are provided, the node serves HTTPS.");
                eprintln!("When --client-ca is also provided, clients must present a certificate");
                eprintln!("signed by that CA (mutual TLS).");
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // -- Fetch well-known config (non-fatal if unavailable) --
    let well_known_config = if let Some(ref url) = well_known_url {
        info!(url = %url, "fetching well-known config");
        match config::fetch_well_known(url).await {
            Ok(cfg) => {
                info!(
                    version = cfg.version,
                    threshold = cfg.threshold,
                    nodes = cfg.nodes.len(),
                    "well-known config loaded"
                );
                Some(cfg)
            }
            Err(e) => {
                warn!(url = %url, error = %e, "failed to fetch well-known config — continuing without it");
                None
            }
        }
    } else {
        info!("no --well-known-url provided, skipping well-known config fetch");
        None
    };

    // Compute sha256 of own binary at boot (for attestation identity hash)
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

    // -- Genesis mode setup --
    let genesis_mode = genesis_peers.is_some();
    let dkg_state = if genesis_mode {
        let node_id = genesis_node_id.unwrap_or_else(|| {
            eprintln!("--node-id is required when --genesis is specified");
            std::process::exit(1);
        });
        let threshold = genesis_threshold.unwrap_or_else(|| {
            eprintln!("--threshold is required when --genesis is specified");
            std::process::exit(1);
        });
        let total = genesis_total.unwrap_or_else(|| {
            eprintln!("--total is required when --genesis is specified");
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

        info!(
            node_id = node_id,
            threshold = threshold,
            total = total,
            "starting in genesis mode — FROST DKG endpoints active"
        );

        Some(Arc::new(dkg::DkgState::new(node_id, threshold, total)))
    } else {
        None
    };

    // Genesis mode implies join behavior (no key loaded), so generate
    // an ephemeral keypair for /join-info compatibility.
    let effective_join_mode = join_mode || genesis_mode;

    // Generate ephemeral X25519 keypair in join mode for ECIES decryption
    let join_keypair = if effective_join_mode {
        let (secret, pubkey_bytes) = toprf_seal::ecies::generate_keypair();
        let pubkey = x25519_dalek::PublicKey::from(pubkey_bytes);
        info!(
            ephemeral_pubkey = %hex::encode(pubkey.as_bytes()),
            "generated X25519 keypair for join mode ECIES"
        );
        Some((secret, pubkey))
    } else {
        None
    };

    let state = Arc::new(NodeState {
        loaded_key: OnceLock::new(),
        reshare_seen: std::sync::Mutex::new(Vec::with_capacity(64)),
        binary_hash,
        rate_limiter: rate_limit::RateLimiter::new(5, std::time::Duration::from_secs(86400)),
        well_known_config,
        data_dir,
        join_in_progress: std::sync::Mutex::new(()),
        join_keypair,
        dkg_state,
    });

    // -- Load key from file (testing/dev) --
    if let Some(ref path) = key_file {
        info!("loading key share from file: {path}");
        let share_bytes =
            std::fs::read(path).unwrap_or_else(|e| panic!("failed to read key file {path}: {e}"));
        let share: NodeKeyShare = serde_json::from_slice(&share_bytes)
            .unwrap_or_else(|e| panic!("invalid NodeKeyShare JSON in {path}: {e}"));

        if share.node_id == 0 {
            panic!("key file: node_id must be nonzero");
        }

        let key_share = hex_to_scalar(&share.secret_share)
            .unwrap_or_else(|e| panic!("key file: invalid secret_share: {e}"));

        // Verify k_i * G == verification_share
        let expected_point = hex_to_point(&share.verification_share)
            .unwrap_or_else(|e| panic!("key file: invalid verification_share: {e}"));
        let computed_point = {
            use k256::elliptic_curve::ops::MulByGenerator;
            use k256::ProjectivePoint;
            ProjectivePoint::mul_by_generator(&key_share)
        };
        if expected_point != computed_point {
            panic!("key file: key share does not match verification share");
        }

        // Optionally check against EXPECTED_VERIFICATION_SHARE env var
        if let Ok(expected_vs) = env::var("EXPECTED_VERIFICATION_SHARE") {
            if share.verification_share != expected_vs {
                panic!(
                    "key file: verification share mismatch\n  loaded:   {}\n  expected: {}",
                    share.verification_share, expected_vs
                );
            }
        }

        let loaded = LoadedKey {
            node_id: share.node_id,
            key_share,
            verification_share: share.verification_share.clone(),
            group_public_key: share.group_public_key.clone(),
            threshold: share.threshold,
            total_shares: share.total_shares,
        };

        state
            .loaded_key
            .set(loaded)
            .expect("key file: OnceLock already set");
        info!(
            node_id = share.node_id,
            threshold = share.threshold,
            total_shares = share.total_shares,
            "key share loaded from file"
        );
    }

    if genesis_mode {
        info!("starting in genesis mode — DKG endpoints active, waiting for ceremony");
    } else if join_mode {
        info!("starting in join mode — waiting for /reshare/receive to initialize key");
    }

    let mut app = Router::new()
        .route("/health", get(health))
        .route("/join-info", get(join::join_info_handler))
        .route("/attestation", get(snp_endpoint::attestation_handler))
        .route(
            "/partial-evaluate",
            post(evaluate::partial_evaluate_handler),
        )
        .route("/reshare", post(reshare_handler::reshare_handler))
        .route("/reshare/receive", post(join::reshare_receive_handler));

    // Register DKG routes when in genesis mode
    if genesis_mode {
        app = app
            .route("/dkg/round1", post(dkg::round1_handler))
            .route("/dkg/round2", post(dkg::round2_handler))
            .route("/dkg/round3", post(dkg::round3_handler));
    }

    let app = app
        .layer(DefaultBodyLimit::max(64 * 1024)) // 64KB for reshare requests with attestation
        .with_state(state);

    let port_num: u16 = port.parse().unwrap_or_else(|_| {
        eprintln!("invalid port number: {port}");
        std::process::exit(1);
    });
    // port_num is used by vsock_server on Linux; suppress warning on other platforms
    let _ = port_num;
    let bind_addr = format!("0.0.0.0:{port}");

    // If --tcp flag is set, OR if not on Linux, use TCP.
    // Otherwise, use vsock (Nitro Enclave default).
    let use_tcp = tcp_mode || !cfg!(target_os = "linux");

    // Determine whether to serve plain HTTP or HTTPS (with optional mTLS)
    match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            // -- TLS mode --
            use axum_server::tls_rustls::RustlsConfig;
            use rustls::server::WebPkiClientVerifier;
            use rustls::RootCertStore;

            let mut rustls_config = if let Some(ca_path) = &client_ca {
                // mTLS: require client certificates signed by this CA
                let ca_pem = std::fs::read(ca_path)
                    .unwrap_or_else(|e| panic!("failed to read client CA {ca_path}: {e}"));
                let mut ca_reader = BufReader::new(ca_pem.as_slice());
                let ca_certs = rustls_pemfile::certs(&mut ca_reader)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("failed to parse client CA PEM");

                let mut root_store = RootCertStore::empty();
                for cert in ca_certs {
                    root_store
                        .add(cert)
                        .expect("failed to add CA cert to root store");
                }

                let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
                    .build()
                    .expect("failed to build client certificate verifier");

                // Load server cert chain and key
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
                        .expect("no private key found in PEM file");

                rustls::ServerConfig::builder()
                    .with_client_cert_verifier(client_verifier)
                    .with_single_cert(certs, private_key)
                    .expect("failed to build rustls ServerConfig")
            } else {
                // TLS without client auth
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
                        .expect("no private key found in PEM file");

                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, private_key)
                    .expect("failed to build rustls ServerConfig")
            };

            rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let tls_config = RustlsConfig::from_config(Arc::new(rustls_config));
            let addr: SocketAddr = bind_addr
                .parse()
                .unwrap_or_else(|e| panic!("invalid bind address {bind_addr}: {e}"));

            if client_ca.is_some() {
                info!(addr = %bind_addr, "starting toprf-node with mTLS (waiting for key)");
            } else {
                info!(addr = %bind_addr, "starting toprf-node with TLS (waiting for key)");
            }

            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await
                .unwrap_or_else(|e| error!("server error: {e}"));
        }
        (None, None) if use_tcp => {
            // -- Plain HTTP/TCP mode (local dev / --tcp flag) --
            warn!(addr = %bind_addr, "starting WITHOUT TLS on 0.0.0.0:{port} — not recommended for production");

            let listener = TcpListener::bind(&bind_addr)
                .await
                .unwrap_or_else(|e| panic!("failed to bind to {bind_addr}: {e}"));

            axum::serve(listener, app)
                .await
                .unwrap_or_else(|e| error!("server error: {e}"));
        }
        #[cfg(target_os = "linux")]
        (None, None) => {
            // -- vsock mode (Nitro Enclave default on Linux) --
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
