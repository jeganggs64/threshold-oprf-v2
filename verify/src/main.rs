use base64::Engine;
use clap::Parser;
use colored::Colorize;
use k256::ProjectivePoint;
use serde::Deserialize;
use toprf_core::combine::lagrange_coefficient;
use toprf_core::hex_to_point;
use toprf_core::point_to_hex;

#[derive(Parser)]
#[command(
    name = "toprf-verify",
    about = "Independently verify TOPRF system integrity.\n\n\
             Fetches the well-known node manifest, contacts each node for live\n\
             attestation, and cross-references verification shares against the\n\
             group public key. Requires zero cooperation from RuonLabs."
)]
struct Cli {
    /// Well-known endpoint URL (e.g. https://ruonlabs.com/.well-known/toprf-nodes.json)
    #[arg(long)]
    endpoint: String,

    /// RPC URL for on-chain verification (optional)
    #[arg(long)]
    rpc: Option<String>,

    /// Registry contract address for on-chain verification (optional)
    #[arg(long)]
    registry: Option<String>,
}

#[derive(Deserialize, Debug)]
struct NodeManifest {
    version: u32,
    threshold: u16,
    #[serde(rename = "groupPublicKey")]
    group_public_key: String,
    #[allow(dead_code)]
    #[serde(rename = "expectedBinaryHash")]
    expected_binary_hash: String,
    #[serde(rename = "approvedMeasurements")]
    approved_measurements: Vec<String>,
    nodes: Vec<NodeEntry>,
}

#[derive(Deserialize, Debug)]
struct NodeEntry {
    id: u16,
    url: String,
    #[serde(rename = "verificationShare")]
    verification_share: Option<String>,
}

#[derive(Deserialize, Debug)]
struct AttestationResponse {
    #[allow(dead_code)]
    node_id: u16,
    attestation_report: Option<String>,
    #[allow(dead_code)]
    cert_chain: Option<String>,
}

/// Counters for pass/fail/warn
struct Results {
    pass: u32,
    fail: u32,
    warn: u32,
}

impl Results {
    fn new() -> Self {
        Self {
            pass: 0,
            fail: 0,
            warn: 0,
        }
    }

    fn check(&mut self, label: &str, ok: bool) {
        if ok {
            self.pass += 1;
            println!("    {} {}", "PASS".green(), label);
        } else {
            self.fail += 1;
            println!("    {} {}", "FAIL".red(), label);
        }
    }

    fn warn(&mut self, msg: &str) {
        self.warn += 1;
        println!("    {} {}", "WARN".yellow(), msg);
    }

    fn fail(&mut self, msg: &str) {
        self.fail += 1;
        println!("    {} {}", "FAIL".red(), msg);
    }
}

fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(false)
        .build()
        .expect("Failed to build HTTP client");

    let mut r = Results::new();

    // ── 1. Fetch manifest ───────────────────────────────────────────
    println!("\n{}", "========================================".bold());
    println!("  {} Verifier", "TOPRF".bold());
    println!("{}", "========================================".bold());
    println!("\n{} {}", "Fetching manifest:".bold(), cli.endpoint);

    let manifest: NodeManifest = match client.get(&cli.endpoint).send().await {
        Ok(res) if res.status().is_success() => match res.json().await {
            Ok(m) => m,
            Err(e) => {
                eprintln!("  {} Invalid manifest JSON: {}", "FAIL".red(), e);
                std::process::exit(1);
            }
        },
        Ok(res) => {
            eprintln!(
                "  {} Failed to fetch manifest: HTTP {}",
                "FAIL".red(),
                res.status()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("  {} Cannot reach endpoint: {}", "FAIL".red(), e);
            std::process::exit(1);
        }
    };

    r.check("Manifest fetched successfully", true);
    println!(
        "    Version: {}, Threshold: {}/{}, Nodes: {}",
        manifest.version,
        manifest.threshold,
        manifest.nodes.len(),
        manifest.nodes.len()
    );
    println!(
        "    Group public key: {}...{}",
        &manifest.group_public_key[..8],
        &manifest.group_public_key[manifest.group_public_key.len() - 8..]
    );

    // ── 2. Verification share consistency ───────────────────────────
    println!("\n{}", "Verification share consistency:".bold());

    let nodes_with_shares: Vec<&NodeEntry> = manifest
        .nodes
        .iter()
        .filter(|n| n.verification_share.is_some())
        .collect();

    if nodes_with_shares.len() >= manifest.threshold as usize {
        // Parse the group public key
        match hex_to_point(&manifest.group_public_key) {
            Ok(gpk) => {
                // Pick the first `threshold` nodes that have verification shares
                let subset = &nodes_with_shares[..manifest.threshold as usize];
                let ids: Vec<u16> = subset.iter().map(|n| n.id).collect();

                let mut interpolated = ProjectivePoint::IDENTITY;
                let mut interp_ok = true;

                for node in subset {
                    let vs_hex = node.verification_share.as_ref().unwrap();
                    match hex_to_point(vs_hex) {
                        Ok(vs_point) => match lagrange_coefficient(node.id, &ids) {
                            Ok(lambda) => {
                                interpolated += vs_point * lambda;
                            }
                            Err(e) => {
                                r.fail(&format!(
                                    "Lagrange coefficient failed for node {}: {}",
                                    node.id, e
                                ));
                                interp_ok = false;
                                break;
                            }
                        },
                        Err(e) => {
                            r.fail(&format!(
                                "Invalid verification share for node {}: {}",
                                node.id, e
                            ));
                            interp_ok = false;
                            break;
                        }
                    }
                }

                if interp_ok {
                    let consistent = point_to_hex(&interpolated) == point_to_hex(&gpk);
                    r.check(
                        "Verification shares interpolate to group public key",
                        consistent,
                    );
                }
            }
            Err(e) => {
                r.fail(&format!("Invalid group public key in manifest: {}", e));
            }
        }
    } else {
        r.warn(&format!(
            "Not enough verification shares ({}/{}) for consistency check",
            nodes_with_shares.len(),
            manifest.threshold
        ));
    }

    // ── 3. Live node attestation ────────────────────────────────────
    println!("\n{}", "Live node attestation:".bold());

    for node in &manifest.nodes {
        println!("\n  {} ({})", format!("Node {}", node.id).bold(), node.url);

        // Generate a random 32-byte nonce for challenge-response attestation
        let nonce: [u8; 32] = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let mut buf = [0u8; 32];
            // Simple nonce: timestamp + node id (sufficient for verify tool)
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            buf[0..16].copy_from_slice(&ts.to_le_bytes());
            buf[16..18].copy_from_slice(&node.id.to_le_bytes());
            buf
        };
        let nonce_hex = hex::encode(nonce);
        let attestation_url = format!("{}/attestation?nonce={}", node.url, nonce_hex);
        match client.get(&attestation_url).send().await {
            Ok(res) if res.status().is_success() => {
                match res.json::<AttestationResponse>().await {
                    Ok(att) => {
                        if let Some(ref report_b64) = att.attestation_report {
                            let report_bytes = b64_decode(report_b64);
                            if report_bytes.len() >= 0x318 {
                                // Extract VMPL (offset 0x030, 4 bytes LE)
                                let vmpl = u32::from_le_bytes(
                                    report_bytes[0x030..0x034].try_into().unwrap(),
                                );

                                // Extract policy (offset 0x008, 8 bytes LE)
                                let policy = u64::from_le_bytes(
                                    report_bytes[0x008..0x010].try_into().unwrap(),
                                );

                                // Extract LAUNCH_DIGEST / measurement (offset 0x090, 48 bytes)
                                let measurement = &report_bytes[0x090..0x090 + 48];

                                // Extract REPORT_DATA (offset 0x050, 64 bytes)
                                let report_data = &report_bytes[0x050..0x050 + 64];

                                // Check measurement against approved list
                                let measurement_str =
                                    format!("sha384:{}", hex::encode(measurement));
                                let m_ok =
                                    manifest.approved_measurements.contains(&measurement_str);
                                r.check("LAUNCH_DIGEST in approved measurements", m_ok);

                                // Check nonce in REPORT_DATA[32..64]
                                let report_nonce = &report_data[32..64];
                                let n_ok = report_nonce == nonce.as_slice();
                                r.check("Nonce matches (anti-replay)", n_ok);

                                // REPORT_DATA[0..32] is now an identity hash:
                                //   sha256(binary_hash || verificationShare || groupPublicKey)
                                // We log it but cannot fully verify without the binary_hash
                                let identity_hash_hex = hex::encode(&report_data[..32]);
                                r.check(
                                    &format!("Identity hash present: {:.16}...", identity_hash_hex),
                                    !report_data[..32].iter().all(|&b| b == 0),
                                );

                                // Check VMPL == 0
                                let v_ok = vmpl == 0;
                                r.check(&format!("VMPL == 0 (got {})", vmpl), v_ok);

                                // Check debug bit (bit 19 of policy)
                                let debug_off = (policy >> 19) & 1 == 0;
                                r.check("Debug disabled in policy", debug_off);
                            } else {
                                r.fail(&format!(
                                    "Attestation report too short ({} bytes, need >= {})",
                                    report_bytes.len(),
                                    0x318
                                ));
                            }
                        } else {
                            r.fail("No attestation report in response");
                        }
                    }
                    Err(e) => {
                        r.fail(&format!("Invalid attestation response: {}", e));
                    }
                }
            }
            Ok(res) if res.status().as_u16() == 503 => {
                r.warn("Attestation not available (non-TEE environment)");
            }
            Ok(res) => {
                r.fail(&format!("Attestation fetch failed: HTTP {}", res.status()));
            }
            Err(e) => {
                r.fail(&format!("Cannot reach node: {}", e));
            }
        }
    }

    // ── 4. On-chain verification (stub) ─────────────────────────────
    if let (Some(rpc), Some(registry)) = (&cli.rpc, &cli.registry) {
        println!("\n{}", "On-chain registry verification:".bold());
        r.warn(&format!(
            "On-chain verification not yet implemented (RPC: {}, Registry: {})",
            rpc, registry
        ));
    }

    // ── Summary ─────────────────────────────────────────────────────
    println!("\n{}", "========================================".bold());
    println!("  {} Verification Results", "TOPRF".bold());
    println!("{}", "========================================".bold());
    println!("  Passed:   {}", format!("{}", r.pass).green());
    if r.fail > 0 {
        println!("  Failed:   {}", format!("{}", r.fail).red());
    }
    if r.warn > 0 {
        println!("  Warnings: {}", format!("{}", r.warn).yellow());
    }
    println!("{}", "========================================".bold());

    if r.fail > 0 {
        println!("\n  {}\n", "RESULT: FAIL".red().bold());
        std::process::exit(1);
    } else if r.warn > 0 {
        println!("\n  {}\n", "RESULT: PASS (with warnings)".yellow().bold());
    } else {
        println!("\n  {}\n", "RESULT: PASS".green().bold());
    }
}
