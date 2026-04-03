//! Nitro Enclave attestation document verification.
//!
//! Verifies COSE_Sign1 attestation documents from AWS Nitro Enclaves.
//!
//! Verification steps:
//! 1. Parse COSE_Sign1 structure (CBOR tag 18)
//! 2. Extract attestation claims: PCRs, signing certificate, CA bundle, user_data
//! 3. Verify certificate chain against the AWS Nitro Root CA
//! 4. Verify COSE_Sign1 ECDSA-P384 signature using the signing certificate
//! 5. Return verified claims for the caller to check PCR values and bindings

use std::collections::BTreeMap;

use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use tracing::warn;
use x509_parser::prelude::*;

/// AWS Nitro Enclaves Root CA certificate (PEM).
/// This is the trust anchor for all Nitro attestation documents.
/// Valid from 2019-10-28 to 2049-10-28.
const AWS_NITRO_ROOT_CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"#;

/// Parsed and verified attestation claims from a Nitro attestation document.
#[allow(dead_code)]
pub struct VerifiedAttestation {
    /// PCR values (index -> SHA-384 hash, 48 bytes each).
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    /// Optional user data embedded in the attestation request.
    pub user_data: Option<Vec<u8>>,
    /// Optional nonce embedded in the attestation request.
    pub nonce: Option<Vec<u8>>,
    /// Timestamp (milliseconds since epoch).
    pub timestamp: u64,
}

/// Intermediate struct for parsed attestation claims before signature verification.
struct AttestationClaims {
    pcrs: BTreeMap<u32, Vec<u8>>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    timestamp: u64,
}

/// Verify a Nitro Enclave attestation document (COSE_Sign1).
///
/// Returns the verified attestation claims (PCRs, user_data, etc.) on success.
/// The caller is responsible for checking PCR values against expected measurements
/// and verifying any bindings in user_data.
pub fn verify(document: &[u8]) -> Result<VerifiedAttestation, String> {
    // 1. Parse COSE_Sign1 structure
    let (protected, payload_bytes, signature_bytes) = parse_cose_sign1(document)?;

    // 2. Parse attestation claims from payload
    let claims = parse_claims(&payload_bytes)?;

    // 3. Verify certificate chain: signing cert -> cabundle -> AWS Root CA
    verify_cert_chain(&claims.certificate, &claims.cabundle)?;

    // 4. Build COSE Sig_structure and verify ECDSA-P384 signature
    let sig_structure = build_sig_structure(&protected, &payload_bytes);
    verify_cose_signature(&claims.certificate, &sig_structure, &signature_bytes)?;

    Ok(VerifiedAttestation {
        pcrs: claims.pcrs,
        user_data: claims.user_data,
        nonce: claims.nonce,
        timestamp: claims.timestamp,
    })
}

/// Check that the attestation document is recent (within 5 minutes).
pub fn check_freshness(attestation: &VerifiedAttestation) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let age_ms = now_ms.saturating_sub(attestation.timestamp);
    let max_age_ms = 5 * 60 * 1000; // 5 minutes

    if age_ms > max_age_ms {
        return Err(format!(
            "attestation document is too old: {}s (max {}s)",
            age_ms / 1000,
            max_age_ms / 1000
        ));
    }

    // Also reject future timestamps (clock skew tolerance: 30s)
    if attestation.timestamp > now_ms + 30_000 {
        return Err("attestation document has a future timestamp".into());
    }

    Ok(())
}

/// Check that the verified PCR values match the expected measurements.
pub fn check_pcrs(
    attestation: &VerifiedAttestation,
    expected_pcr0: &str,
    expected_pcr1: &str,
    expected_pcr2: &str,
) -> Result<(), String> {
    let check = |idx: u32, expected: &str| -> Result<(), String> {
        let actual = attestation
            .pcrs
            .get(&idx)
            .ok_or_else(|| format!("PCR{idx} missing from attestation"))?;
        let actual_hex = hex::encode(actual);
        if actual_hex != expected {
            return Err(format!(
                "PCR{idx} mismatch: expected {expected}, got {actual_hex}"
            ));
        }
        Ok(())
    };
    check(0, expected_pcr0)?;
    check(1, expected_pcr1)?;
    check(2, expected_pcr2)?;
    Ok(())
}

/// Check that all PCR values in debug mode are NOT all zeros.
/// Debug-mode enclaves zero all PCRs — reject these for resharing.
pub fn reject_debug_mode(attestation: &VerifiedAttestation) -> Result<(), String> {
    for idx in [0u32, 1, 2] {
        if let Some(pcr) = attestation.pcrs.get(&idx) {
            if pcr.iter().all(|&b| b == 0) {
                return Err(format!(
                    "PCR{idx} is all zeros — enclave is in debug mode, refusing reshare"
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// COSE_Sign1 parsing
// ---------------------------------------------------------------------------

/// Parsed COSE_Sign1 components: (protected_headers, payload, signature).
type CoseSign1Parts = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Parse a COSE_Sign1 structure from raw CBOR bytes.
/// Returns (protected_header_bytes, payload_bytes, signature_bytes).
fn parse_cose_sign1(data: &[u8]) -> Result<CoseSign1Parts, String> {
    let value: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| format!("CBOR parse error: {e}"))?;

    // COSE_Sign1 is CBOR Tag(18, Array([protected, unprotected, payload, signature]))
    let array = match value {
        ciborium::Value::Tag(18, inner) => match *inner {
            ciborium::Value::Array(arr) => arr,
            _ => return Err("COSE_Sign1 tag 18 does not contain an array".into()),
        },
        // Some implementations omit the tag
        ciborium::Value::Array(arr) if arr.len() == 4 => arr,
        _ => return Err("not a COSE_Sign1 structure (expected tag 18 or 4-element array)".into()),
    };

    if array.len() != 4 {
        return Err(format!(
            "COSE_Sign1 array has {} elements, expected 4",
            array.len()
        ));
    }

    let protected = extract_bytes(&array[0], "protected header")?;
    let payload = extract_bytes(&array[2], "payload")?;
    let signature = extract_bytes(&array[3], "signature")?;

    Ok((protected, payload, signature))
}

/// Extract a byte string from a CBOR Value, or return an error.
fn extract_bytes(value: &ciborium::Value, field: &str) -> Result<Vec<u8>, String> {
    match value {
        ciborium::Value::Bytes(b) => Ok(b.clone()),
        _ => Err(format!("{field} is not a byte string")),
    }
}

// ---------------------------------------------------------------------------
// Attestation claims parsing
// ---------------------------------------------------------------------------

/// Parse attestation claims from the COSE_Sign1 payload (CBOR map).
fn parse_claims(payload: &[u8]) -> Result<AttestationClaims, String> {
    let value: ciborium::Value =
        ciborium::from_reader(payload).map_err(|e| format!("payload CBOR parse error: {e}"))?;

    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return Err("attestation payload is not a CBOR map".into()),
    };

    let mut pcrs: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut certificate: Option<Vec<u8>> = None;
    let mut cabundle: Vec<Vec<u8>> = Vec::new();
    let mut user_data: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut timestamp: u64 = 0;

    for (key, val) in &map {
        let key_str = match key {
            ciborium::Value::Text(s) => s.as_str(),
            _ => continue,
        };
        match key_str {
            "pcrs" => {
                if let ciborium::Value::Map(pcr_map) = val {
                    for (idx, hash) in pcr_map {
                        if let (Some(i), ciborium::Value::Bytes(h)) = (cbor_to_u32(idx), hash) {
                            pcrs.insert(i, h.clone());
                        }
                    }
                }
            }
            "certificate" => {
                certificate = Some(extract_bytes(val, "certificate")?);
            }
            "cabundle" => {
                if let ciborium::Value::Array(certs) = val {
                    for cert in certs {
                        cabundle.push(extract_bytes(cert, "cabundle entry")?);
                    }
                }
            }
            "user_data" => {
                if let ciborium::Value::Bytes(b) = val {
                    user_data = Some(b.clone());
                }
                // Null means no user_data — leave as None
            }
            "nonce" => {
                if let ciborium::Value::Bytes(b) = val {
                    nonce = Some(b.clone());
                }
            }
            "timestamp" => {
                if let Some(t) = cbor_to_u64(val) {
                    timestamp = t;
                }
            }
            _ => {} // ignore unknown fields
        }
    }

    let certificate =
        certificate.ok_or_else(|| "attestation claims missing 'certificate' field".to_string())?;

    if pcrs.is_empty() {
        return Err("attestation claims have no PCR values".into());
    }

    Ok(AttestationClaims {
        pcrs,
        certificate,
        cabundle,
        user_data,
        nonce,
        timestamp,
    })
}

/// Convert a CBOR integer value to u32.
fn cbor_to_u32(value: &ciborium::Value) -> Option<u32> {
    match value {
        ciborium::Value::Integer(i) => {
            let n: i128 = (*i).into();
            u32::try_from(n).ok()
        }
        _ => None,
    }
}

/// Convert a CBOR integer value to u64.
fn cbor_to_u64(value: &ciborium::Value) -> Option<u64> {
    match value {
        ciborium::Value::Integer(i) => {
            let n: i128 = (*i).into();
            u64::try_from(n).ok()
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Certificate chain verification
// ---------------------------------------------------------------------------

/// Verify the certificate chain: signing_cert -> cabundle -> AWS Nitro Root CA.
///
/// The cabundle is ordered leaf-to-root (intermediate certs). The last cert
/// in the cabundle must be signed by the AWS Nitro Root CA.
fn verify_cert_chain(signing_cert_der: &[u8], cabundle: &[Vec<u8>]) -> Result<(), String> {
    // Parse the AWS Nitro Root CA
    let root_pem = ::pem::parse(AWS_NITRO_ROOT_CA_PEM)
        .map_err(|e| format!("failed to parse root CA PEM: {e}"))?;
    let (_, root_cert) = X509Certificate::from_der(root_pem.contents())
        .map_err(|e| format!("failed to parse root CA DER: {e}"))?;

    // Build the full chain: signing_cert, cabundle[0], cabundle[1], ..., root
    // Each cert must be signed by the next cert in the chain.
    let (_, signing_cert) = X509Certificate::from_der(signing_cert_der)
        .map_err(|e| format!("failed to parse signing certificate: {e}"))?;

    // Parse all cabundle certs
    let mut intermediates: Vec<X509Certificate> = Vec::with_capacity(cabundle.len());
    for (i, cert_der) in cabundle.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| format!("failed to parse cabundle cert {i}: {e}"))?;
        intermediates.push(cert);
    }

    // Walk the chain: signing_cert -> intermediates -> root
    // Verify signatures and certificate validity
    let chain: Vec<&X509Certificate> = std::iter::once(&signing_cert)
        .chain(intermediates.iter())
        .collect();

    for i in 0..chain.len() {
        // Check certificate is within its validity period
        if !chain[i].validity().is_valid() {
            return Err(format!(
                "certificate at depth {i} has expired or is not yet valid"
            ));
        }

        let issuer = if i + 1 < chain.len() {
            chain[i + 1]
        } else {
            &root_cert
        };

        chain[i]
            .verify_signature(Some(issuer.public_key()))
            .map_err(|e| format!("certificate chain verification failed at depth {i}: {e}"))?;
    }

    // Verify the last intermediate (or signing cert if no intermediates) is signed by root
    // This is already handled by the loop above — the last iteration verifies against root_cert.

    // Verify root cert is self-signed
    root_cert
        .verify_signature(Some(root_cert.public_key()))
        .map_err(|e| format!("root CA self-signature verification failed: {e}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// COSE signature verification
// ---------------------------------------------------------------------------

/// Build the COSE Sig_structure1 for signature verification.
///
/// ```text
/// Sig_structure1 = [
///     "Signature1",     // context
///     protected,        // serialized protected headers (bstr)
///     b"",              // external_aad (empty)
///     payload            // serialized payload (bstr)
/// ]
/// ```
fn build_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let structure = ciborium::Value::Array(vec![
        ciborium::Value::Text("Signature1".to_string()),
        ciborium::Value::Bytes(protected.to_vec()),
        ciborium::Value::Bytes(vec![]),
        ciborium::Value::Bytes(payload.to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&structure, &mut buf).expect("CBOR serialization cannot fail");
    buf
}

/// Verify the COSE_Sign1 ECDSA-P384 signature using the signing certificate's public key.
fn verify_cose_signature(
    signing_cert_der: &[u8],
    sig_structure_cbor: &[u8],
    signature_bytes: &[u8],
) -> Result<(), String> {
    // Parse the signing certificate to extract its P-384 public key
    let (_, cert) = X509Certificate::from_der(signing_cert_der)
        .map_err(|e| format!("failed to parse signing cert for signature verification: {e}"))?;

    let spki = cert.public_key();
    let pk_bytes = &spki.subject_public_key.data;

    // Build P-384 verifying key from the raw public key bytes
    let verifying_key = VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| format!("invalid P-384 public key in signing cert: {e}"))?;

    // The COSE ES384 signature is raw r||s (48 + 48 = 96 bytes)
    if signature_bytes.len() != 96 {
        return Err(format!(
            "ECDSA-P384 signature must be 96 bytes, got {}",
            signature_bytes.len()
        ));
    }
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| format!("invalid ECDSA-P384 signature: {e}"))?;

    // Verify: ECDSA-P384 over SHA-384(sig_structure_cbor)
    // The `verify` method internally computes SHA-384
    verifying_key
        .verify(sig_structure_cbor, &signature)
        .map_err(|e| {
            warn!("COSE_Sign1 signature verification failed: {e}");
            format!("COSE_Sign1 signature verification failed: {e}")
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_ca_parses() {
        let pem = ::pem::parse(AWS_NITRO_ROOT_CA_PEM).unwrap();
        let (_, cert) = X509Certificate::from_der(pem.contents()).unwrap();
        assert_eq!(
            cert.subject().to_string(),
            "C=US, O=Amazon, OU=AWS, CN=aws.nitro-enclaves"
        );
        // Self-signed
        assert_eq!(cert.issuer(), cert.subject());
    }

    #[test]
    fn test_parse_cose_sign1_rejects_garbage() {
        let result = parse_cose_sign1(b"not cbor");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_sig_structure() {
        let protected = b"\xa1\x01\x38\x22"; // {1: -35} = ES384
        let payload = b"test payload";
        let sig = build_sig_structure(protected, payload);
        // Should be a valid CBOR array
        let value: ciborium::Value = ciborium::from_reader(&sig[..]).unwrap();
        if let ciborium::Value::Array(items) = value {
            assert_eq!(items.len(), 4);
            assert_eq!(items[0], ciborium::Value::Text("Signature1".into()));
        } else {
            panic!("expected array");
        }
    }

    #[test]
    fn test_reject_debug_mode_zeros() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, vec![0u8; 48]);
        pcrs.insert(1, vec![0u8; 48]);
        pcrs.insert(2, vec![0u8; 48]);
        let att = VerifiedAttestation {
            pcrs,
            user_data: None,
            nonce: None,
            timestamp: 0,
        };
        let result = reject_debug_mode(&att);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("debug mode"));
    }

    #[test]
    fn test_reject_debug_mode_passes_nonzero() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, vec![1u8; 48]);
        pcrs.insert(1, vec![2u8; 48]);
        pcrs.insert(2, vec![3u8; 48]);
        let att = VerifiedAttestation {
            pcrs,
            user_data: None,
            nonce: None,
            timestamp: 0,
        };
        assert!(reject_debug_mode(&att).is_ok());
    }
}
