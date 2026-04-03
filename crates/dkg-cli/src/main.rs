//! DKG CLI — orchestrates the FROST DKG ceremony.
//!
//! Each production node started with `--genesis` serves DKG endpoints
//! (`/dkg/round1`, `/dkg/round2`, `/dkg/round3`). After round3, each node
//! seals its own key share. The CLI never sees plaintext key material.
//!
//! Reads DEPLOYER_PRIVATE_KEY and RPC_URL from .env for on-chain deployment.
//!
//! Usage:
//!   toprf-dkg-cli init \
//!       --nodes http://node1:3001,http://node2:3001,http://node3:3001

use std::collections::BTreeMap;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::error;

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "toprf-dkg-cli", about = "Orchestrate FROST DKG ceremony")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the full DKG ceremony (nodes seal their own keys).
    Init {
        /// Comma-separated node URLs (production nodes running with --genesis).
        #[arg(long, value_delimiter = ',')]
        nodes: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// DKG node API types (mirrors node's dkg module request/response types)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Round1Response {
    identifier: String,
    package: String,
}

#[derive(Serialize)]
struct Round2Request {
    round1_packages: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Round2Response {
    round2_packages: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct Round3Request {
    round1_packages: BTreeMap<String, String>,
    round2_packages: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    production_pubkeys: Option<BTreeMap<u16, String>>,
}

// ---------------------------------------------------------------------------
// Round3 response types
// ---------------------------------------------------------------------------

/// Response from genesis-mode nodes (merged design) — no encrypted
/// contributions, the node sealed its own key.
#[derive(Deserialize)]
struct Round3Response {
    node_id: u16,
    verification_share: String,
    group_public_key: String,
    threshold: u16,
    total_shares: u16,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Load .env file if present (non-fatal if missing)
    dotenvy::dotenv().ok();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { nodes } => {
            if nodes.is_empty() {
                eprintln!("Error: --nodes requires at least one URL");
                std::process::exit(1);
            }
            if let Err(e) = run_init_genesis(nodes).await {
                error!("DKG init failed: {e}");
                std::process::exit(1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Init subcommand: genesis mode (merged design)
// ---------------------------------------------------------------------------

async fn run_init_genesis(nodes: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let n = nodes.len();
    if n < 2 {
        return Err("need at least 2 nodes".into());
    }

    println!("=== DKG Ceremony (Genesis Mode): {n} nodes ===\n");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    // ------------------------------------------------------------------
    // Configure each node for genesis mode
    // ------------------------------------------------------------------
    println!("[Configure] Setting genesis mode on each node...");

    let threshold = 2u16; // TODO: make configurable if needed
    let total = n as u16;

    for (i, url) in nodes.iter().enumerate() {
        let node_id = (i + 1) as u16;
        let body = serde_json::json!({
            "mode": "genesis",
            "node_id": node_id,
            "threshold": threshold,
            "total": total,
        });

        let resp = client
            .post(format!("{url}/configure"))
            .json(&body)
            .send()
            .await?;

        if resp.status().is_success() {
            println!(
                "  Node {} ({}): configured (genesis, id={})",
                node_id, url, node_id
            );
        } else if resp.status() == 403 {
            println!(
                "  Node {} ({}): already configured (continuing)",
                node_id, url
            );
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Node {} configure failed ({}): {}", node_id, status, body).into());
        }
    }
    println!("[Configure] Complete.\n");

    // ------------------------------------------------------------------
    // Round 1: collect identifiers and round1 packages from each node
    // ------------------------------------------------------------------
    println!("[Round 1] Calling /dkg/round1 on each node...");

    let mut round1_identifiers: Vec<String> = Vec::with_capacity(n);
    let mut round1_packages: Vec<String> = Vec::with_capacity(n);

    for (i, url) in nodes.iter().enumerate() {
        let resp = client
            .post(format!("{url}/dkg/round1"))
            .send()
            .await?
            .error_for_status()?
            .json::<Round1Response>()
            .await?;

        println!(
            "  Node {} ({}): identifier={}...",
            i + 1,
            url,
            &resp.identifier[..8.min(resp.identifier.len())]
        );

        round1_identifiers.push(resp.identifier);
        round1_packages.push(resp.package);
    }

    println!("[Round 1] Complete.\n");

    // ------------------------------------------------------------------
    // Round 2: send each node all OTHER nodes' round1 packages
    // ------------------------------------------------------------------
    println!("[Round 2] Calling /dkg/round2 on each node...");

    let mut round2_results: Vec<BTreeMap<String, String>> = Vec::with_capacity(n);

    for (i, url) in nodes.iter().enumerate() {
        let mut r1_map = BTreeMap::new();
        for (j, (id, pkg)) in round1_identifiers
            .iter()
            .zip(round1_packages.iter())
            .enumerate()
        {
            if j != i {
                r1_map.insert(id.clone(), pkg.clone());
            }
        }

        let req = Round2Request {
            round1_packages: r1_map,
        };

        let resp = client
            .post(format!("{url}/dkg/round2"))
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json::<Round2Response>()
            .await?;

        println!(
            "  Node {} ({}): produced {} round2 packages",
            i + 1,
            url,
            resp.round2_packages.len()
        );

        round2_results.push(resp.round2_packages);
    }

    println!("[Round 2] Complete.\n");

    // ------------------------------------------------------------------
    // Round 3: finalize — each node seals its own key share
    // ------------------------------------------------------------------
    println!("[Round 3] Calling /dkg/round3 on each node (self-sealing mode)...");

    let mut round3_results: Vec<Round3Response> = Vec::with_capacity(n);

    for (i, url) in nodes.iter().enumerate() {
        // round1_packages: all OTHER nodes' round1 packages
        let mut r1_map = BTreeMap::new();
        for (j, (id, pkg)) in round1_identifiers
            .iter()
            .zip(round1_packages.iter())
            .enumerate()
        {
            if j != i {
                r1_map.insert(id.clone(), pkg.clone());
            }
        }

        // round2_packages: for node i, collect round2 packages FROM each other node j
        // that are addressed TO node i.
        let my_identifier = &round1_identifiers[i];
        let mut r2_map = BTreeMap::new();
        for (j, r2_pkgs) in round2_results.iter().enumerate() {
            if j != i {
                if let Some(pkg) = r2_pkgs.get(my_identifier) {
                    r2_map.insert(round1_identifiers[j].clone(), pkg.clone());
                } else {
                    return Err(format!(
                        "Node {} did not produce a round2 package for node {}",
                        j + 1,
                        i + 1
                    )
                    .into());
                }
            }
        }

        let req = Round3Request {
            round1_packages: r1_map,
            round2_packages: r2_map,
            production_pubkeys: None, // Not needed — node seals its own key
        };

        let resp = client
            .post(format!("{url}/dkg/round3"))
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json::<Round3Response>()
            .await?;

        println!(
            "  Node {} ({}): node_id={}, threshold={}, total={}, sealed",
            i + 1,
            url,
            resp.node_id,
            resp.threshold,
            resp.total_shares,
        );

        round3_results.push(resp);
    }

    println!("[Round 3] Complete.\n");

    // ------------------------------------------------------------------
    // Verify: all nodes must agree on group public key
    // ------------------------------------------------------------------
    let group_public_key = &round3_results[0].group_public_key;
    let threshold = round3_results[0].threshold;
    let total_shares = round3_results[0].total_shares;

    for r3 in &round3_results[1..] {
        if &r3.group_public_key != group_public_key {
            return Err(format!(
                "Group public key mismatch: node {} has {} but node {} has {}",
                round3_results[0].node_id, group_public_key, r3.node_id, r3.group_public_key
            )
            .into());
        }
    }

    println!("[Verify] All nodes agree on group public key: {group_public_key}");
    println!("[Verify] Threshold: {threshold}, Total shares: {total_shares}\n");

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    println!("=== DKG Ceremony Summary ===");
    println!("  Group public key: {group_public_key}");
    println!("  Threshold:        {threshold}");
    println!("  Total shares:     {total_shares}");
    println!("  Mode:             Genesis (each node sealed its own key)");
    println!();
    for r3 in &round3_results {
        println!(
            "  Node {}: verification_share={}...",
            r3.node_id,
            &r3.verification_share[..16.min(r3.verification_share.len())]
        );
    }
    // ------------------------------------------------------------------
    // Write dkg-data.json (for contract deployment + deployment records)
    // ------------------------------------------------------------------
    let dkg_data = serde_json::json!({
        "groupPublicKey": format!("0x{group_public_key}"),
        "sourceRepo": "https://github.com/jeganggs64/threshold-oprf-v2",
        "threshold": threshold,
        "nodeCount": round3_results.len(),
        "nodes": round3_results.iter().map(|r3| {
            serde_json::json!({
                "nodeId": r3.node_id,
                "dkgCommitment": "0x",
                "attestationReport": "0x",
                "certChain": "0x",
                "verificationShare": format!("0x{}", r3.verification_share)
            })
        }).collect::<Vec<_>>()
    });

    let dkg_data_path = "dkg-data.json";
    std::fs::write(dkg_data_path, serde_json::to_string_pretty(&dkg_data)?)?;
    println!("  Written: {dkg_data_path}");

    // ------------------------------------------------------------------
    // Optional: deploy contract to Base (if env vars are set)
    // ------------------------------------------------------------------
    let deployer_key = std::env::var("DEPLOYER_PRIVATE_KEY").ok();
    let rpc_url = std::env::var("RPC_URL").ok();

    if let (Some(key), Some(rpc)) = (deployer_key, rpc_url) {
        if key.is_empty() || rpc.is_empty() {
            println!("\n  DEPLOYER_PRIVATE_KEY or RPC_URL is empty — skipping contract deployment");
        } else {
            println!("\n[Deploy] Posting DKG record on-chain...");
            println!("  RPC: {rpc}");

            // Copy dkg-data.json to contracts/ and run forge script
            let contracts_dir = std::path::Path::new("contracts");
            if contracts_dir.exists() {
                std::fs::copy(dkg_data_path, contracts_dir.join("dkg-data.json"))?;

                // Write .env for forge (add 0x prefix if missing — forge expects it)
                let key_with_prefix = if key.starts_with("0x") {
                    key.clone()
                } else {
                    format!("0x{key}")
                };
                std::fs::write(
                    contracts_dir.join(".env"),
                    format!("DEPLOYER_PRIVATE_KEY={key_with_prefix}\nRPC_URL={rpc}\n"),
                )?;

                // Try to run forge script
                let forge_path = std::env::var("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".foundry/bin/forge"))
                    .unwrap_or_else(|_| std::path::PathBuf::from("forge"));

                let status = std::process::Command::new(&forge_path)
                    .current_dir(contracts_dir)
                    .env("DEPLOYER_PRIVATE_KEY", &key_with_prefix)
                    .env("RPC_URL", &rpc)
                    .args([
                        "script",
                        "script/Deploy.s.sol:DeployScript",
                        "--rpc-url",
                        &rpc,
                        "--broadcast",
                    ])
                    .status();

                match status {
                    Ok(s) if s.success() => {
                        println!("[Deploy] Contract deployed successfully!");
                    }
                    Ok(s) => {
                        println!(
                            "[Deploy] WARNING: forge script exited with code {}",
                            s.code().unwrap_or(-1)
                        );
                        println!("  You can deploy manually: cd contracts && bash deploy.sh");
                    }
                    Err(e) => {
                        println!("[Deploy] WARNING: could not run forge: {e}");
                        println!(
                            "  Install foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
                        );
                        println!("  Then deploy manually: cd contracts && bash deploy.sh");
                    }
                }

                // Clean up .env (don't leave private key on disk)
                let _ = std::fs::remove_file(contracts_dir.join(".env"));
            } else {
                println!("  WARNING: contracts/ directory not found — skipping deployment");
                println!("  Deploy manually with: cd contracts && bash deploy.sh");
            }
        }
    } else {
        println!("\n  Set DEPLOYER_PRIVATE_KEY and RPC_URL to auto-deploy the on-chain record");
        println!("  Or deploy manually: cd contracts && bash deploy.sh");
    }

    println!();
    println!("DKG ceremony completed successfully.");

    Ok(())
}
