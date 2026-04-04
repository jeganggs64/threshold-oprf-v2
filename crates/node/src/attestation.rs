//! Device attestation verification for /partial-evaluate requests.
//!
//! Supports iOS (Apple App Attest) and Android (Google Play Integrity).
//! Verification is stateless — the client sends full attestation data
//! with every request. A `device_id_hash` is derived from the attestation
//! material and used for per-device rate limiting.

use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::outbound_proxy;

// -- Configuration --

const IOS_APP_ID: &str = "WBX7VLTXXK.com.ruonid.app";
const ANDROID_PACKAGE_NAME: &str = "com.ruonid.app";

// -- Types --

#[derive(Debug, Deserialize)]
pub struct AttestationPayload {
    pub platform: Platform,
    #[serde(default)]
    pub attestation_object: Option<String>, // iOS: base64 CBOR attestation
    #[serde(default)]
    pub assertion: Option<String>, // iOS: base64 signed assertion
    #[serde(default)]
    pub client_data_hash: Option<String>, // hex sha256(blindedPoint)
    #[serde(default)]
    pub integrity_token: Option<String>, // Android: Play Integrity token
    #[serde(default)]
    pub device_id: Option<String>, // Android: stable device UUID for rate limiting
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Android,
}

#[derive(Debug)]
pub struct AttestationResult {
    pub device_id_hash: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid attestation: {0}")]
    Invalid(String),
    #[error("client data hash mismatch")]
    ClientDataHashMismatch,
    #[error("Google API error: {0}")]
    GoogleApiError(String),
}

/// Verify device attestation and return a stable device identifier.
pub async fn verify_attestation(
    payload: &AttestationPayload,
    expected_client_data_hash: &[u8; 32],
) -> Result<AttestationResult, AttestationError> {
    match payload.platform {
        Platform::Ios => verify_ios(payload, expected_client_data_hash),
        Platform::Android => verify_android(payload, expected_client_data_hash).await,
    }
}

// -- iOS App Attest --------------------------------------------------------

/// Apple App Attest Root CA (PEM).
/// Source: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
const APPLE_APP_ATTEST_ROOT_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----"#;

fn verify_ios(
    payload: &AttestationPayload,
    expected_client_data_hash: &[u8; 32],
) -> Result<AttestationResult, AttestationError> {
    let attestation_b64 = payload
        .attestation_object
        .as_deref()
        .ok_or(AttestationError::MissingField("attestation_object"))?;

    let assertion_b64 = payload
        .assertion
        .as_deref()
        .ok_or(AttestationError::MissingField("assertion"))?;

    let client_data_hash_hex = payload
        .client_data_hash
        .as_deref()
        .ok_or(AttestationError::MissingField("client_data_hash"))?;

    // Verify client_data_hash matches expected
    let provided_hash = hex::decode(client_data_hash_hex).map_err(|e| {
        AttestationError::Invalid(format!("client_data_hash is not valid hex: {e}"))
    })?;
    if provided_hash.as_slice() != expected_client_data_hash.as_slice() {
        return Err(AttestationError::ClientDataHashMismatch);
    }

    // Decode attestation object (base64 -> CBOR)
    let att_bytes = base64::engine::general_purpose::STANDARD
        .decode(attestation_b64)
        .map_err(|e| AttestationError::Invalid(format!("attestation_object base64: {e}")))?;

    // Parse CBOR attestation object
    let att_value: ciborium::Value = ciborium::from_reader(&att_bytes[..])
        .map_err(|e| AttestationError::Invalid(format!("attestation CBOR parse: {e}")))?;

    let att_map = match att_value {
        ciborium::Value::Map(m) => m,
        _ => {
            return Err(AttestationError::Invalid(
                "attestation is not a CBOR map".into(),
            ))
        }
    };

    // Extract authData and attStmt
    let auth_data = cbor_map_get_bytes(&att_map, "authData")
        .ok_or_else(|| AttestationError::Invalid("missing authData".into()))?;
    let att_stmt = cbor_map_get_map(&att_map, "attStmt")
        .ok_or_else(|| AttestationError::Invalid("missing attStmt".into()))?;

    // Verify rpIdHash (first 32 bytes of authData) matches SHA256(appId)
    if auth_data.len() < 37 {
        return Err(AttestationError::Invalid("authData too short".into()));
    }
    let rp_id_hash = &auth_data[..32];
    let expected_rp_id_hash = Sha256::digest(IOS_APP_ID.as_bytes());
    if rp_id_hash != &expected_rp_id_hash[..] {
        return Err(AttestationError::Invalid(
            "rpIdHash does not match app ID".into(),
        ));
    }

    // Extract x5c certificate chain from attStmt
    let x5c = cbor_map_get_array(att_stmt, "x5c")
        .ok_or_else(|| AttestationError::Invalid("missing x5c in attStmt".into()))?;

    if x5c.is_empty() {
        return Err(AttestationError::Invalid("x5c is empty".into()));
    }

    // Parse leaf certificate (the credential certificate)
    let leaf_der = match &x5c[0] {
        ciborium::Value::Bytes(b) => b,
        _ => return Err(AttestationError::Invalid("x5c[0] is not bytes".into())),
    };

    // Verify certificate chain against Apple root CA
    let root_pem = ::pem::parse(APPLE_APP_ATTEST_ROOT_CA)
        .map_err(|e| AttestationError::Invalid(format!("Apple root CA parse: {e}")))?;
    let (_, root_cert) = x509_parser::parse_x509_certificate(root_pem.contents())
        .map_err(|e| AttestationError::Invalid(format!("Apple root CA DER: {e}")))?;

    let (_, leaf_cert) = x509_parser::parse_x509_certificate(leaf_der)
        .map_err(|e| AttestationError::Invalid(format!("leaf cert parse: {e}")))?;

    // Verify certificate validity periods
    if !leaf_cert.validity().is_valid() {
        return Err(AttestationError::Invalid(
            "leaf certificate has expired or is not yet valid".into(),
        ));
    }

    // Verify certificate chain signatures: leaf -> intermediate -> root
    if x5c.len() >= 2 {
        let intermediate_der = match &x5c[1] {
            ciborium::Value::Bytes(b) => b,
            _ => return Err(AttestationError::Invalid("x5c[1] is not bytes".into())),
        };
        let (_, intermediate_cert) = x509_parser::parse_x509_certificate(intermediate_der)
            .map_err(|e| AttestationError::Invalid(format!("intermediate cert: {e}")))?;

        if !intermediate_cert.validity().is_valid() {
            return Err(AttestationError::Invalid(
                "intermediate certificate has expired or is not yet valid".into(),
            ));
        }

        leaf_cert
            .verify_signature(Some(intermediate_cert.public_key()))
            .map_err(|e| AttestationError::Invalid(format!("leaf cert signature: {e}")))?;

        intermediate_cert
            .verify_signature(Some(root_cert.public_key()))
            .map_err(|e| AttestationError::Invalid(format!("intermediate cert signature: {e}")))?;
    } else {
        leaf_cert
            .verify_signature(Some(root_cert.public_key()))
            .map_err(|e| AttestationError::Invalid(format!("leaf cert signature: {e}")))?;
    }

    // Extract the credential public key from authData
    // authData layout: rpIdHash(32) + flags(1) + signCount(4) + attestedCredData(...)
    // attestedCredData: aaguid(16) + credIdLen(2) + credId(credIdLen) + credPubKey(CBOR)
    let flags = auth_data[32];
    let _sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

    // Check attested credential data flag (bit 6)
    if flags & 0x40 == 0 {
        return Err(AttestationError::Invalid(
            "authData does not contain attested credential data".into(),
        ));
    }

    let att_cred_offset = 37;
    if auth_data.len() < att_cred_offset + 18 {
        return Err(AttestationError::Invalid(
            "authData too short for attested cred data".into(),
        ));
    }
    // aaguid is 16 bytes starting at att_cred_offset
    let cred_id_len = u16::from_be_bytes([
        auth_data[att_cred_offset + 16],
        auth_data[att_cred_offset + 17],
    ]) as usize;
    let cred_pub_key_offset = att_cred_offset + 18 + cred_id_len;

    if auth_data.len() <= cred_pub_key_offset {
        return Err(AttestationError::Invalid(
            "authData too short for credential public key".into(),
        ));
    }

    // Parse the COSE public key from authData (EC P-256)
    // COSE key map uses integer keys: 1=kty, -1=crv, -2=x, -3=y
    let cred_pub_key: ciborium::Value = ciborium::from_reader(&auth_data[cred_pub_key_offset..])
        .map_err(|e| AttestationError::Invalid(format!("credential public key CBOR: {e}")))?;

    let cose_map = match &cred_pub_key {
        ciborium::Value::Map(m) => m,
        _ => return Err(AttestationError::Invalid("COSE key is not a map".into())),
    };

    // Extract x (-2) and y (-3) coordinates
    let x_bytes = cose_map_get_bytes(cose_map, -2)
        .ok_or_else(|| AttestationError::Invalid("missing x coordinate in COSE key".into()))?;
    let y_bytes = cose_map_get_bytes(cose_map, -3)
        .ok_or_else(|| AttestationError::Invalid("missing y coordinate in COSE key".into()))?;

    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(AttestationError::Invalid(
            "COSE key coordinates must be 32 bytes each".into(),
        ));
    }

    // Build uncompressed P-256 public key: 0x04 || x || y
    let mut pub_key_uncompressed = vec![0x04u8];
    pub_key_uncompressed.extend_from_slice(&x_bytes);
    pub_key_uncompressed.extend_from_slice(&y_bytes);

    let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pub_key_uncompressed)
        .map_err(|e| AttestationError::Invalid(format!("invalid P-256 public key: {e}")))?;

    // Decode and verify the assertion
    let assertion_bytes = base64::engine::general_purpose::STANDARD
        .decode(assertion_b64)
        .map_err(|e| AttestationError::Invalid(format!("assertion base64: {e}")))?;

    let assertion_value: ciborium::Value = ciborium::from_reader(&assertion_bytes[..])
        .map_err(|e| AttestationError::Invalid(format!("assertion CBOR: {e}")))?;

    let assertion_map = match assertion_value {
        ciborium::Value::Map(m) => m,
        _ => {
            return Err(AttestationError::Invalid(
                "assertion is not a CBOR map".into(),
            ))
        }
    };

    let assertion_signature = cbor_map_get_bytes(&assertion_map, "signature")
        .ok_or_else(|| AttestationError::Invalid("missing signature in assertion".into()))?;

    let assertion_auth_data =
        cbor_map_get_bytes(&assertion_map, "authenticatorData").ok_or_else(|| {
            AttestationError::Invalid("missing authenticatorData in assertion".into())
        })?;

    // Verify rpIdHash in assertion authenticatorData
    if assertion_auth_data.len() < 32 {
        return Err(AttestationError::Invalid(
            "assertion authData too short".into(),
        ));
    }
    if assertion_auth_data[..32] != expected_rp_id_hash[..] {
        return Err(AttestationError::Invalid(
            "assertion rpIdHash does not match app ID".into(),
        ));
    }

    // Verify assertion signature: ECDSA-P256 over SHA256(authenticatorData || clientDataHash)
    // Pass the raw concatenation to verify() — it computes SHA256 internally.
    // Do NOT pre-hash: verify() would double-hash and reject valid signatures.
    let mut signed_data = Vec::with_capacity(assertion_auth_data.len() + 32);
    signed_data.extend_from_slice(&assertion_auth_data);
    signed_data.extend_from_slice(expected_client_data_hash);

    let signature = p256::ecdsa::DerSignature::from_bytes(&assertion_signature)
        .map_err(|e| AttestationError::Invalid(format!("invalid assertion signature DER: {e}")))?;

    use p256::ecdsa::signature::Verifier;
    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|e| {
            AttestationError::Invalid(format!("assertion signature verification failed: {e}"))
        })?;

    // Device ID: SHA256 of the credential public key (stable per device)
    let device_id_hash: [u8; 32] = Sha256::digest(&pub_key_uncompressed).into();

    Ok(AttestationResult { device_id_hash })
}

// -- Android Play Integrity ------------------------------------------------

/// Verify a Google Play Integrity token by calling Google's decodeIntegrityToken API.
async fn verify_android(
    payload: &AttestationPayload,
    expected_client_data_hash: &[u8; 32],
) -> Result<AttestationResult, AttestationError> {
    let integrity_token = payload
        .integrity_token
        .as_deref()
        .ok_or(AttestationError::MissingField("integrity_token"))?;

    // Get Google access token via WIF
    let access_token = crate::google_auth::get_google_access_token()
        .await
        .map_err(|e| AttestationError::GoogleApiError(format!("WIF auth failed: {e}")))?;

    // Call decodeIntegrityToken API
    let url = format!(
        "https://playintegrity.googleapis.com/v1/{}:decodeIntegrityToken",
        ANDROID_PACKAGE_NAME
    );

    let body = serde_json::json!({
        "integrity_token": integrity_token,
    });

    let resp_body = outbound_proxy::https_post_json(&url, &body.to_string(), Some(&access_token))
        .await
        .map_err(|e| AttestationError::GoogleApiError(format!("API request failed: {e}")))?;

    let result: serde_json::Value = serde_json::from_str(&resp_body)
        .map_err(|e| AttestationError::GoogleApiError(format!("response parse: {e}")))?;

    // Validate the integrity verdict
    let token_payload = result
        .get("tokenPayloadExternal")
        .ok_or_else(|| AttestationError::Invalid("missing tokenPayloadExternal".into()))?;

    // Check package name
    let package_name = token_payload
        .pointer("/appIntegrity/packageName")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if package_name != ANDROID_PACKAGE_NAME {
        return Err(AttestationError::Invalid(format!(
            "package name mismatch: expected {ANDROID_PACKAGE_NAME}, got {package_name}"
        )));
    }

    // Check app recognition verdict
    let app_verdict = token_payload
        .pointer("/appIntegrity/appRecognitionVerdict")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if app_verdict != "PLAY_RECOGNIZED" {
        return Err(AttestationError::Invalid(format!(
            "app not recognized: {app_verdict}"
        )));
    }

    // Check device integrity
    let device_verdicts = token_payload
        .pointer("/deviceIntegrity/deviceRecognitionVerdict")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    if !device_verdicts.contains(&"MEETS_DEVICE_INTEGRITY") {
        return Err(AttestationError::Invalid(format!(
            "device integrity check failed: {:?}",
            device_verdicts
        )));
    }

    // Check request timestamp freshness (within 5 minutes)
    if let Some(ts) = token_payload
        .pointer("/requestDetails/timestampMillis")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
    {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let age_ms = now_ms.saturating_sub(ts);
        if age_ms > 5 * 60 * 1000 {
            return Err(AttestationError::Invalid(format!(
                "integrity token too old: {}s",
                age_ms / 1000
            )));
        }
    }

    // Extract device_id from the attestation payload (required for Android)
    let device_id = payload
        .device_id
        .as_deref()
        .ok_or(AttestationError::MissingField("device_id"))?;

    // Verify nonce binding: the app computes SHA256(client_data_hash_hex + device_id)
    // and uses that as the integrity token nonce. This binds device_id to the token
    // so it can't be swapped after the fact.
    let nonce = token_payload
        .pointer("/requestDetails/nonce")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let client_data_hash_hex = hex::encode(expected_client_data_hash);
    let expected_bound_nonce = hex::encode(Sha256::digest(
        format!("{client_data_hash_hex}{device_id}").as_bytes(),
    ));
    if nonce != expected_bound_nonce {
        warn!(
            expected = %expected_bound_nonce,
            got = %nonce,
            "Play Integrity nonce mismatch (device_id binding)"
        );
        return Err(AttestationError::ClientDataHashMismatch);
    }

    // Device ID: SHA256 of the device_id (stable per device install).
    // The device_id is bound to the integrity token via the nonce, so it can't
    // be forged. Play Integrity proves the device is genuine and the app is
    // unmodified, so the device_id from secure storage is trustworthy.
    let device_id_hash: [u8; 32] = Sha256::digest(device_id.as_bytes()).into();

    Ok(AttestationResult { device_id_hash })
}

// -- CBOR helpers ----------------------------------------------------------

/// Get bytes from a CBOR map with an integer key (for COSE key maps).
fn cose_map_get_bytes(map: &[(ciborium::Value, ciborium::Value)], key: i64) -> Option<Vec<u8>> {
    let target = ciborium::Value::Integer(key.into());
    for (k, v) in map {
        if k == &target {
            if let ciborium::Value::Bytes(b) = v {
                return Some(b.clone());
            }
        }
    }
    None
}

fn cbor_map_get_bytes(map: &[(ciborium::Value, ciborium::Value)], key: &str) -> Option<Vec<u8>> {
    for (k, v) in map {
        if let ciborium::Value::Text(s) = k {
            if s == key {
                if let ciborium::Value::Bytes(b) = v {
                    return Some(b.clone());
                }
            }
        }
    }
    None
}

fn cbor_map_get_map<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a [(ciborium::Value, ciborium::Value)]> {
    for (k, v) in map {
        if let ciborium::Value::Text(s) = k {
            if s == key {
                if let ciborium::Value::Map(m) = v {
                    return Some(m);
                }
            }
        }
    }
    None
}

fn cbor_map_get_array<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a [ciborium::Value]> {
    for (k, v) in map {
        if let ciborium::Value::Text(s) = k {
            if s == key {
                if let ciborium::Value::Array(a) = v {
                    return Some(a);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Catches typos/hallucinations in the hardcoded Apple App Attest Root CA.
    /// If this fails, update from https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
    #[test]
    fn apple_app_attest_root_ca_parses() {
        let pem = ::pem::parse(APPLE_APP_ATTEST_ROOT_CA).expect("PEM parse");
        let (_, cert) = x509_parser::parse_x509_certificate(pem.contents()).expect("DER parse");
        let subject = cert.subject().to_string();
        assert!(
            subject.contains("Apple App Attestation Root CA"),
            "unexpected subject: {subject}"
        );
    }
}
