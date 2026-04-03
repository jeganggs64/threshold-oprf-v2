use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct WellKnownConfig {
    pub version: u32,
    pub threshold: u16,
    #[serde(rename = "groupPublicKey")]
    pub group_public_key: String,
    #[serde(rename = "expectedBinaryHash")]
    pub expected_binary_hash: String,
    #[serde(rename = "approvedMeasurements")]
    pub approved_measurements: Vec<String>,
    pub nodes: Vec<NodeEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeEntry {
    pub id: u16,
    pub url: String,
    #[serde(rename = "verificationShare")]
    pub verification_share: Option<String>,
    /// TEE platform: "nitro", "snp", "azure-cvm", or None (dev/test).
    pub platform: Option<String>,
    /// Platform-specific measurements for attestation verification.
    pub measurements: Option<PlatformMeasurements>,
}

/// Platform-specific attestation measurements.
/// Which fields are present depends on the platform.
#[derive(Debug, Clone, Deserialize)]
pub struct PlatformMeasurements {
    // -- Nitro Enclave PCRs --
    pub pcr0: Option<String>,
    pub pcr1: Option<String>,
    pub pcr2: Option<String>,
    // -- SNP / Azure CVM --
    pub measurement: Option<String>,
    #[serde(rename = "expectedBinaryHash")]
    pub expected_binary_hash: Option<String>,
}

/// Fetch and parse the well-known config from a URL.
/// Routes through vsock in Nitro enclaves, direct TCP otherwise.
pub async fn fetch_well_known(url: &str) -> Result<WellKnownConfig, Box<dyn std::error::Error>> {
    let body = crate::outbound_proxy::https_get(url).await?;
    let config: WellKnownConfig = serde_json::from_str(&body)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_well_known_json() {
        let json = r#"{
            "version": 1,
            "threshold": 2,
            "groupPublicKey": "02abc",
            "expectedBinaryHash": "sha256:def",
            "approvedMeasurements": ["sha384:aaa"],
            "nodes": [
                {"id": 1, "url": "https://node1.example.com"},
                {"id": 2, "url": "https://node2.example.com", "verificationShare": "03xyz"}
            ]
        }"#;
        let config: WellKnownConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.threshold, 2);
        assert_eq!(config.group_public_key, "02abc");
        assert_eq!(config.expected_binary_hash, "sha256:def");
        assert_eq!(config.approved_measurements.len(), 1);
        assert_eq!(config.nodes.len(), 2);
        assert_eq!(config.nodes[0].id, 1);
        assert!(config.nodes[0].verification_share.is_none());
        assert_eq!(config.nodes[1].verification_share.as_deref(), Some("03xyz"));
    }

    #[test]
    fn test_parse_well_known_with_platform() {
        let json = r#"{
            "version": 1,
            "threshold": 2,
            "groupPublicKey": "02abc",
            "expectedBinaryHash": "sha256:def",
            "approvedMeasurements": [],
            "nodes": [
                {
                    "id": 1,
                    "url": "http://node1:3001",
                    "platform": "nitro",
                    "measurements": {
                        "pcr0": "7eb77f79d944",
                        "pcr1": "4b4d5b3661b3",
                        "pcr2": "6248b22b95a0"
                    }
                },
                {
                    "id": 2,
                    "url": "http://node2:3001",
                    "platform": "snp",
                    "measurements": {
                        "measurement": "sha384:aaa",
                        "expectedBinaryHash": "sha256:bbb"
                    }
                }
            ]
        }"#;
        let config: WellKnownConfig = serde_json::from_str(json).unwrap();
        let n1 = &config.nodes[0];
        assert_eq!(n1.platform.as_deref(), Some("nitro"));
        let m1 = n1.measurements.as_ref().unwrap();
        assert_eq!(m1.pcr0.as_deref(), Some("7eb77f79d944"));
        assert_eq!(m1.pcr1.as_deref(), Some("4b4d5b3661b3"));
        assert_eq!(m1.pcr2.as_deref(), Some("6248b22b95a0"));

        let n2 = &config.nodes[1];
        assert_eq!(n2.platform.as_deref(), Some("snp"));
        let m2 = n2.measurements.as_ref().unwrap();
        assert_eq!(m2.measurement.as_deref(), Some("sha384:aaa"));
        assert_eq!(m2.expected_binary_hash.as_deref(), Some("sha256:bbb"));
    }
}
