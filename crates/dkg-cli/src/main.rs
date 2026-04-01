//! DKG CLI — orchestrates the FROST DKG ceremony between temporary DKG nodes
//! and delivers the resulting key shares to production TOPRF nodes using the
//! reshare/receive endpoint.
//!
//! Usage:
//!   toprf-dkg-cli init \
//!       --dkg-nodes http://localhost:4001,http://localhost:4002,http://localhost:4003 \
//!       --production-nodes http://localhost:3001,http://localhost:3002,http://localhost:3003
//!
//!   toprf-dkg-cli reshare \
//!       --new-node http://localhost:3004 \
//!       --new-node-id 4 \
//!       --existing-nodes http://localhost:3001,http://localhost:3002

use std::collections::BTreeMap;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use toprf_core::reshare::{generate_recovery_contribution, SerializableReshareContribution};
use toprf_core::{hex_to_scalar, scalar_to_hex, NodeKeyShare};

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
    /// Run the full DKG ceremony and deliver shares to production nodes.
    Init {
        /// Comma-separated DKG node URLs (e.g. http://localhost:4001,http://localhost:4002,http://localhost:4003)
        #[arg(long, value_delimiter = ',')]
        dkg_nodes: Vec<String>,

        /// Comma-separated production node URLs (same count as dkg-nodes)
        #[arg(long, value_delimiter = ',')]
        production_nodes: Vec<String>,
    },

    /// Reshare an existing key to a new node (stub).
    Reshare {
        /// URL of the new production node
        #[arg(long)]
        new_node: String,

        /// Node ID to assign to the new node
        #[arg(long)]
        new_node_id: u16,

        /// Comma-separated URLs of existing production nodes to act as donors
        #[arg(long, value_delimiter = ',')]
        existing_nodes: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// DKG node API types (mirrors dkg-node's request/response types)
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
}

// ---------------------------------------------------------------------------
// Production node reshare/receive types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ReshareReceiveRequest {
    contributions: Vec<SerializableReshareContribution>,
    participant_ids: Vec<u16>,
    group_public_key: String,
    threshold: u16,
    total_shares: u16,
    new_node_id: u16,
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

    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            dkg_nodes,
            production_nodes,
        } => {
            if let Err(e) = run_init(dkg_nodes, production_nodes).await {
                error!("DKG init failed: {e}");
                std::process::exit(1);
            }
        }
        Commands::Reshare {
            new_node: _,
            new_node_id: _,
            existing_nodes: _,
        } => {
            println!("TODO: implement reshare orchestration");
        }
    }
}

// ---------------------------------------------------------------------------
// Init subcommand implementation
// ---------------------------------------------------------------------------

async fn run_init(
    dkg_nodes: Vec<String>,
    production_nodes: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate inputs
    if dkg_nodes.len() != production_nodes.len() {
        return Err(format!(
            "DKG node count ({}) must equal production node count ({})",
            dkg_nodes.len(),
            production_nodes.len()
        )
        .into());
    }
    let n = dkg_nodes.len();
    if n < 2 {
        return Err("need at least 2 nodes".into());
    }

    println!("=== DKG Ceremony: {n} nodes ===\n");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    // ------------------------------------------------------------------
    // Round 1: collect identifiers and round1 packages from each DKG node
    // ------------------------------------------------------------------
    println!("[Round 1] Calling /dkg/round1 on each DKG node...");

    let mut round1_identifiers: Vec<String> = Vec::with_capacity(n);
    let mut round1_packages: Vec<String> = Vec::with_capacity(n);

    for (i, url) in dkg_nodes.iter().enumerate() {
        let resp = client
            .post(format!("{url}/dkg/round1"))
            .send()
            .await?
            .error_for_status()?
            .json::<Round1Response>()
            .await?;

        println!(
            "  DKG node {} ({}): identifier={}...",
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
    println!("[Round 2] Calling /dkg/round2 on each DKG node...");

    // round2_results[i] = the round2 response from DKG node i
    // Each response contains: { round2_packages: { recipient_id_hex: pkg_json, ... } }
    let mut round2_results: Vec<BTreeMap<String, String>> = Vec::with_capacity(n);

    for (i, url) in dkg_nodes.iter().enumerate() {
        // Build round1_packages map excluding self
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
            "  DKG node {} ({}): produced {} round2 packages",
            i + 1,
            url,
            resp.round2_packages.len()
        );

        round2_results.push(resp.round2_packages);
    }

    println!("[Round 2] Complete.\n");

    // ------------------------------------------------------------------
    // Round 3: for each node, build round1 + round2 maps and finalize
    // ------------------------------------------------------------------
    println!("[Round 3] Calling /dkg/round3 on each DKG node...");

    let mut key_shares: Vec<NodeKeyShare> = Vec::with_capacity(n);

    for (i, url) in dkg_nodes.iter().enumerate() {
        // round1_packages: all OTHER nodes' round1 packages (same as round2 input)
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
        //
        // round2_results[j] is a map { recipient_id_hex: pkg_json, ... }
        // We want the entry keyed by node i's identifier from each other node j.
        let my_identifier = &round1_identifiers[i];
        let mut r2_map = BTreeMap::new();
        for (j, r2_pkgs) in round2_results.iter().enumerate() {
            if j != i {
                // From node j's round2 output, get the package addressed to node i
                if let Some(pkg) = r2_pkgs.get(my_identifier) {
                    // Key it by sender j's identifier
                    r2_map.insert(round1_identifiers[j].clone(), pkg.clone());
                } else {
                    return Err(format!(
                        "DKG node {} did not produce a round2 package for node {}",
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
        };

        let resp = client
            .post(format!("{url}/dkg/round3"))
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json::<NodeKeyShare>()
            .await?;

        println!(
            "  DKG node {} ({}): node_id={}, threshold={}, total={}",
            i + 1,
            url,
            resp.node_id,
            resp.threshold,
            resp.total_shares
        );

        key_shares.push(resp);
    }

    println!("[Round 3] Complete.\n");

    // ------------------------------------------------------------------
    // Verify: all shares must agree on group public key
    // ------------------------------------------------------------------
    let group_public_key = &key_shares[0].group_public_key;
    let threshold = key_shares[0].threshold;
    let total_shares = key_shares[0].total_shares;

    for share in &key_shares[1..] {
        if &share.group_public_key != group_public_key {
            return Err(format!(
                "Group public key mismatch: node {} has {} but node {} has {}",
                key_shares[0].node_id,
                group_public_key,
                share.node_id,
                share.group_public_key
            )
            .into());
        }
    }

    println!("[Verify] All shares agree on group public key: {group_public_key}");
    println!(
        "[Verify] Threshold: {threshold}, Total shares: {total_shares}\n"
    );

    // ------------------------------------------------------------------
    // Deliver shares to production nodes via /reshare/receive
    // ------------------------------------------------------------------
    println!("[Deliver] Sending shares to production nodes...\n");

    for (i, prod_url) in production_nodes.iter().enumerate() {
        let target_share = &key_shares[i];
        let target_node_id = target_share.node_id;

        // Pick `threshold` OTHER DKG shares as donors (exclude the target share)
        let donors: Vec<&NodeKeyShare> = key_shares
            .iter()
            .filter(|s| s.node_id != target_node_id)
            .take(threshold as usize)
            .collect();

        if donors.len() < threshold as usize {
            return Err(format!(
                "Not enough donors for node {target_node_id}: need {threshold}, have {}",
                donors.len()
            )
            .into());
        }

        // The participant_ids are the donor node IDs
        let donor_node_ids: Vec<u16> = donors.iter().map(|d| d.node_id).collect();

        println!(
            "  Production node {} ({prod_url}): target_node_id={target_node_id}, donors={:?}",
            i + 1,
            donor_node_ids
        );

        // Generate recovery contributions from each donor
        let mut contributions: Vec<SerializableReshareContribution> =
            Vec::with_capacity(donors.len());

        for donor in &donors {
            let donor_scalar = hex_to_scalar(&donor.secret_share).map_err(|e| {
                format!(
                    "failed to parse secret share for donor node {}: {e}",
                    donor.node_id
                )
            })?;

            let contribution = generate_recovery_contribution(
                donor.node_id,
                &donor_scalar,
                &donor_node_ids,
                target_node_id,
            )
            .map_err(|e| {
                format!(
                    "generate_recovery_contribution failed for donor {}: {e}",
                    donor.node_id
                )
            })?;

            let contribution_hex = scalar_to_hex(&contribution);

            contributions.push(SerializableReshareContribution {
                from_node_id: donor.node_id,
                new_node_id: target_node_id,
                sub_share_data: contribution_hex,
                encrypted: false,
                verification_share: donor.verification_share.clone(),
            });

            info!(
                donor_node_id = donor.node_id,
                target_node_id = target_node_id,
                "generated recovery contribution"
            );
        }

        // Send to production node
        let req = ReshareReceiveRequest {
            contributions,
            participant_ids: donor_node_ids.clone(),
            group_public_key: group_public_key.clone(),
            threshold,
            total_shares,
            new_node_id: target_node_id,
        };

        let resp = client
            .post(format!("{prod_url}/reshare/receive"))
            .json(&req)
            .send()
            .await?
            .error_for_status()
            .map_err(|e| {
                format!("production node {prod_url} rejected reshare/receive: {e}")
            })?
            .json::<ReshareReceiveResponse>()
            .await?;

        println!(
            "    -> node_id={}, verification_share={}..., status={}",
            resp.node_id,
            &resp.verification_share[..16.min(resp.verification_share.len())],
            resp.status
        );
    }

    println!("\n[Deliver] Complete.\n");

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    println!("=== DKG Ceremony Summary ===");
    println!("  Group public key: {group_public_key}");
    println!("  Threshold:        {threshold}");
    println!("  Total shares:     {total_shares}");
    println!();
    for share in &key_shares {
        println!(
            "  Node {}: verification_share={}...",
            share.node_id,
            &share.verification_share[..16.min(share.verification_share.len())]
        );
    }
    println!();
    println!("DKG ceremony completed successfully.");

    Ok(())
}
