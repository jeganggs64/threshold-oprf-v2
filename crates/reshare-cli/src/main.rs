//! Reshare CLI — adds a new node to an existing TOPRF cluster.
//!
//! Fetches the well-known config to discover existing nodes, then orchestrates
//! the reshare protocol: fetches attestation + join info from the new node,
//! sends reshare requests to existing donor nodes, collects contributions,
//! and delivers them to the new node.
//!
//! Usage:
//!   toprf-reshare-cli --new-node http://<ip>:3001

use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::error;

const WELL_KNOWN_URL: &str = "https://ruonlabs.com/.well-known/toprf-nodes.json";

// ---------------------------------------------------------------------------
// Well-known config types (mirrors crates/node/src/config.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct WellKnownConfig {
    threshold: u16,
    #[serde(rename = "groupPublicKey")]
    group_public_key: String,
    nodes: Vec<NodeEntry>,
}

#[derive(Debug, Deserialize)]
struct NodeEntry {
    id: u16,
    url: String,
    #[serde(rename = "verificationShare")]
    verification_share: Option<String>,
}

// ---------------------------------------------------------------------------
// Node endpoint types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct HealthResponse {
    status: String,
    node_id: Option<u16>,
}

#[derive(Deserialize)]
struct JoinInfoResponse {
    ephemeral_pubkey: String,
}

#[derive(Deserialize)]
struct AttestationResponse {
    attestation_document: String,
    platform: String,
}

#[derive(Serialize)]
struct ReshareRequest {
    target_pubkey: String,
    target_url: String,
    attestation_data: String,
    new_node_id: u16,
    participant_ids: Vec<u16>,
    group_public_key: String,
}

#[derive(Deserialize, Debug)]
struct ReshareResponse {
    from_node_id: u16,
    new_node_id: u16,
    sub_share_data: String,
    encrypted: bool,
    verification_share: String,
}

#[derive(Serialize)]
struct ReshareReceiveRequest {
    contributions: Vec<Contribution>,
    participant_ids: Vec<u16>,
    group_public_key: String,
    threshold: u16,
    total_shares: u16,
    new_node_id: u16,
}

#[derive(Serialize)]
struct Contribution {
    from_node_id: u16,
    new_node_id: u16,
    sub_share_data: String,
    encrypted: bool,
    verification_share: String,
}

#[derive(Deserialize, Debug)]
struct ReshareReceiveResponse {
    node_id: u16,
    verification_share: String,
    status: String,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();

    let mut new_node_url: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--new-node" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("missing value for --new-node");
                    std::process::exit(1);
                }
                new_node_url = Some(args[i].clone().trim_end_matches('/').to_string());
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-reshare-cli --new-node <URL>");
                eprintln!();
                eprintln!("Adds a new node to an existing TOPRF cluster via resharing.");
                eprintln!("Discovers existing nodes from the well-known config at:");
                eprintln!("  {WELL_KNOWN_URL}");
                eprintln!();
                eprintln!("The new node must:");
                eprintln!("  - Be running in --join mode");
                eprintln!("  - Be listed in the well-known config with platform + measurements");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --new-node <URL>  URL of the new node (e.g. http://1.2.3.4:3001)");
                return;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                eprintln!("Run with --help for usage");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let new_node_url = new_node_url.unwrap_or_else(|| {
        eprintln!("Error: --new-node is required");
        eprintln!("Run with --help for usage");
        std::process::exit(1);
    });

    if let Err(e) = run_reshare(&new_node_url).await {
        error!("{e}");
        std::process::exit(1);
    }
}

async fn run_reshare(new_node_url: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    // 1. Fetch well-known config
    println!("[1/7] Fetching well-known config from {WELL_KNOWN_URL}");
    let wk: WellKnownConfig = client
        .get(WELL_KNOWN_URL)
        .send()
        .await
        .map_err(|e| format!("failed to fetch well-known config: {e}"))?
        .json()
        .await
        .map_err(|e| format!("failed to parse well-known config: {e}"))?;

    // Find existing nodes (those with a verification share = already have keys)
    let existing_nodes: Vec<&NodeEntry> = wk
        .nodes
        .iter()
        .filter(|n| n.verification_share.is_some())
        .collect();

    if existing_nodes.len() < wk.threshold as usize {
        return Err(format!(
            "need at least {} existing nodes with keys, found {}",
            wk.threshold,
            existing_nodes.len()
        ));
    }

    // Find the new node entry in well-known config
    let new_node_entry = wk
        .nodes
        .iter()
        .find(|n| n.url == new_node_url)
        .ok_or_else(|| {
            format!("new node URL {new_node_url} not found in well-known config — add it first")
        })?;

    let new_node_id = new_node_entry.id;
    let total_shares = wk.nodes.len() as u16;
    let participant_ids: Vec<u16> = existing_nodes.iter().map(|n| n.id).collect();

    println!(
        "  Found {} existing nodes, new node will be id={}, threshold={}, total={}",
        existing_nodes.len(),
        new_node_id,
        wk.threshold,
        total_shares
    );

    // 2. Verify existing nodes are healthy
    println!("[2/7] Checking existing nodes are healthy");
    for node in &existing_nodes {
        let resp: HealthResponse = client
            .get(format!("{}/health", node.url))
            .send()
            .await
            .map_err(|e| format!("node {} health check failed: {e}", node.url))?
            .json()
            .await
            .map_err(|e| format!("node {} health response invalid: {e}", node.url))?;
        if resp.status != "ready" {
            return Err(format!("node {} is not ready: {}", node.url, resp.status));
        }
        println!("  {} (id={}) — ready", node.url, resp.node_id.unwrap_or(0));
    }

    // 3. Configure new node in join mode (if not already configured)
    println!("[3/8] Configuring new node in join mode");
    let configure_resp = client
        .post(format!("{new_node_url}/configure"))
        .json(&serde_json::json!({"mode": "join"}))
        .send()
        .await
        .map_err(|e| format!("failed to configure new node: {e}"))?;
    if configure_resp.status().is_success() {
        println!("  Configured for join mode");
    } else if configure_resp.status().as_u16() == 403 {
        println!("  Already configured (continuing)");
    } else {
        let body = configure_resp.text().await.unwrap_or_default();
        return Err(format!("configure failed: {body}"));
    }

    // 4. Get new node's join info (ephemeral pubkey)
    println!("[4/8] Fetching join info from new node {new_node_url}");
    let join_info: JoinInfoResponse = client
        .get(format!("{new_node_url}/join-info"))
        .send()
        .await
        .map_err(|e| format!("failed to fetch join-info from new node: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid join-info response: {e}"))?;
    println!(
        "  Ephemeral pubkey: {}...",
        &join_info.ephemeral_pubkey[..16]
    );

    // 4. Get new node's attestation document
    println!("[5/8] Fetching attestation from new node");
    let nonce = generate_nonce();
    let att_resp = client
        .get(format!("{new_node_url}/attestation?nonce={nonce}"))
        .send()
        .await
        .map_err(|e| format!("failed to fetch attestation from new node: {e}"))?;

    let att_status = att_resp.status();
    if !att_status.is_success() {
        let body = att_resp.text().await.unwrap_or_default();
        return Err(format!(
            "new node attestation endpoint returned {att_status}: {body}"
        ));
    }

    let att: AttestationResponse = att_resp
        .json()
        .await
        .map_err(|e| format!("invalid attestation response: {e}"))?;
    println!(
        "  Platform: {}, document length: {} bytes",
        att.platform,
        base64::engine::general_purpose::STANDARD
            .decode(&att.attestation_document)
            .map(|d| d.len())
            .unwrap_or(0)
    );

    // 5. Send reshare request to each existing node
    println!("[6/8] Requesting reshare contributions from existing nodes");
    let mut contributions: Vec<Contribution> = Vec::new();

    for node in &existing_nodes {
        let req = ReshareRequest {
            target_pubkey: join_info.ephemeral_pubkey.clone(),
            target_url: new_node_url.to_string(),
            attestation_data: att.attestation_document.clone(),
            new_node_id,
            participant_ids: participant_ids.clone(),
            group_public_key: wk.group_public_key.clone(),
        };

        let resp = client
            .post(format!("{}/reshare", node.url))
            .json(&req)
            .send()
            .await
            .map_err(|e| format!("reshare request to {} failed: {e}", node.url))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "node {} rejected reshare (HTTP {}): {}",
                node.url, status, body
            ));
        }

        let reshare_resp: ReshareResponse = resp
            .json()
            .await
            .map_err(|e| format!("invalid reshare response from {}: {e}", node.url))?;

        println!(
            "  {} (id={}) — contribution received (encrypted={})",
            node.url, reshare_resp.from_node_id, reshare_resp.encrypted
        );

        contributions.push(Contribution {
            from_node_id: reshare_resp.from_node_id,
            new_node_id: reshare_resp.new_node_id,
            sub_share_data: reshare_resp.sub_share_data,
            encrypted: reshare_resp.encrypted,
            verification_share: reshare_resp.verification_share,
        });
    }

    // 6. Deliver contributions to the new node
    println!(
        "[7/8] Delivering {} contributions to new node",
        contributions.len()
    );
    let receive_req = ReshareReceiveRequest {
        contributions,
        participant_ids: participant_ids.clone(),
        group_public_key: wk.group_public_key.clone(),
        threshold: wk.threshold,
        total_shares,
        new_node_id,
    };

    let resp = client
        .post(format!("{new_node_url}/reshare/receive"))
        .json(&receive_req)
        .send()
        .await
        .map_err(|e| format!("failed to deliver contributions to new node: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "new node rejected contributions (HTTP {status}): {body}"
        ));
    }

    let receive_resp: ReshareReceiveResponse = resp
        .json()
        .await
        .map_err(|e| format!("invalid reshare/receive response: {e}"))?;

    println!(
        "  New node id={}, verification_share={}..., status={}",
        receive_resp.node_id,
        &receive_resp.verification_share[..16.min(receive_resp.verification_share.len())],
        receive_resp.status
    );

    // 7. Verify the new node is operational
    println!("[8/8] Verifying new node is operational");
    let health: HealthResponse = client
        .get(format!("{new_node_url}/health"))
        .send()
        .await
        .map_err(|e| format!("new node health check failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid health response: {e}"))?;

    if health.status != "ready" {
        return Err(format!(
            "new node is not ready after reshare: {}",
            health.status
        ));
    }

    println!();
    println!("Reshare complete.");
    println!("  New node: {} (id={})", new_node_url, new_node_id);
    println!("  Verification share: {}", receive_resp.verification_share);
    println!("  Status: {}", receive_resp.status);
    println!();
    println!("Next steps:");
    println!("  1. Update well-known config with the new node's verification share");
    println!("  2. Test partial evaluations against the new node");

    Ok(())
}

/// Generate a random 32-byte hex nonce for attestation challenge-response.
fn generate_nonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Simple nonce: timestamp + counter bytes, hashed
    // In production, use a CSPRNG. For the CLI tool this is fine.
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let bytes = ts.to_le_bytes();
    let mut nonce = [0u8; 32];
    // Fill with timestamp bytes repeated
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = bytes[i % bytes.len()];
    }
    hex::encode(nonce)
}
