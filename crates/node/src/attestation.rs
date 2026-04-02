//! Stateless device attestation verification.
//!
//! Supports iOS (Apple App Attest) and Android (Google Play Integrity).
//! Verification is stateless — no device keys or registration state is stored
//! on the node. A `device_id_hash` is derived from the attestation material
//! and returned to the caller for use in rate limiting.

use sha2::{Digest, Sha256};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AttestationPayload {
    pub platform: Platform,
    #[serde(default)]
    pub attestation_object: Option<String>, // iOS: base64 App Attest cert chain
    #[serde(default)]
    pub assertion: Option<String>, // iOS: base64 signed assertion
    #[serde(default)]
    pub client_data_hash: Option<String>, // hex sha256(blindedPoint)
    #[serde(default)]
    pub integrity_token: Option<String>, // Android: base64 Play Integrity token
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Android,
    Test, // For integration testing with mock attestation
}

#[derive(Debug)]
pub struct AttestationResult {
    /// Hash of the device's attestation key — used as device ID for rate limiting.
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
    #[allow(dead_code)] // Used when Google Play Integrity verification is implemented
    #[error("Google API error: {0}")]
    GoogleApiError(String),
}

/// Verify device attestation and return a stable device identifier.
///
/// `expected_client_data_hash` is sha256 of the blinded OPRF point bytes.
/// The caller must supply this so the attestation can be bound to the
/// specific request, preventing replay of a valid attestation against a
/// different request.
pub async fn verify_attestation(
    payload: &AttestationPayload,
    expected_client_data_hash: &[u8; 32],
) -> Result<AttestationResult, AttestationError> {
    match payload.platform {
        Platform::Ios => verify_ios(payload, expected_client_data_hash),
        Platform::Android => verify_android(payload).await,
        Platform::Test => {
            if std::env::var("TOPRF_ALLOW_TEST_ATTESTATION").unwrap_or_default() != "1" {
                return Err(AttestationError::Invalid(
                    "test platform not available — set TOPRF_ALLOW_TEST_ATTESTATION=1 for dev mode"
                        .into(),
                ));
            }
            verify_test(payload, expected_client_data_hash)
        }
    }
}

// -- iOS -------------------------------------------------------------------

fn verify_ios(
    payload: &AttestationPayload,
    expected_client_data_hash: &[u8; 32],
) -> Result<AttestationResult, AttestationError> {
    let attestation_object = payload
        .attestation_object
        .as_deref()
        .ok_or(AttestationError::MissingField("attestation_object"))?;

    let _assertion = payload
        .assertion
        .as_deref()
        .ok_or(AttestationError::MissingField("assertion"))?;

    let client_data_hash_hex = payload
        .client_data_hash
        .as_deref()
        .ok_or(AttestationError::MissingField("client_data_hash"))?;

    // Decode and verify that the supplied client_data_hash matches the expected
    // hash of the blinded point. This binds the attestation to this request.
    let provided_hash = hex::decode(client_data_hash_hex).map_err(|e| {
        AttestationError::Invalid(format!("client_data_hash is not valid hex: {e}"))
    })?;

    if provided_hash.as_slice() != expected_client_data_hash.as_slice() {
        return Err(AttestationError::ClientDataHashMismatch);
    }

    // TODO: Decode the CBOR-encoded attestation_object (base64 → CBOR → authData + attStmt).
    // TODO: Parse the x5c certificate chain from attStmt.
    // TODO: Verify the leaf certificate's public key hash matches the credCert's key ID in authData.
    // TODO: Verify the certificate chain up to Apple App Attest Root CA
    //       (embed the root CA DER and validate the full chain).
    // TODO: Check that the App ID (team_id.bundle_id) in the certificate matches the expected value.
    // TODO: Verify the assertion: decode base64 assertion → CBOR → {signature, authenticatorData}.
    // TODO: Reconstruct the signed payload: sha256(authenticatorData || client_data_hash) and
    //       verify the ECDSA-P256 signature using the credential public key from authData.
    // TODO: Check the counter value in authenticatorData is monotonically increasing.

    // Interim device_id_hash: sha256 of the raw attestation_object bytes.
    // Replace this with sha256 of the credential public key once full CBOR
    // parsing is implemented.
    let device_id_hash: [u8; 32] = Sha256::digest(attestation_object.as_bytes()).into();

    Ok(AttestationResult { device_id_hash })
}

// -- Android ---------------------------------------------------------------

async fn verify_android(
    payload: &AttestationPayload,
) -> Result<AttestationResult, AttestationError> {
    let integrity_token = payload
        .integrity_token
        .as_deref()
        .ok_or(AttestationError::MissingField("integrity_token"))?;

    // TODO: Call the Google Play Integrity API to verify the token.
    //       POST https://playintegrity.googleapis.com/v1/{package_name}:decodeIntegrityToken
    //       with the integrity_token in the request body. Use a service account or
    //       application default credentials for authentication.
    // TODO: Parse the DecodeIntegrityTokenResponse and validate:
    //       - requestDetails.requestPackageName matches expected package name
    //       - requestDetails.nonce matches base64(expected_client_data_hash)
    //       - appIntegrity.appRecognitionVerdict == "PLAY_RECOGNIZED"
    //       - deviceIntegrity.deviceRecognitionVerdict contains "MEETS_DEVICE_INTEGRITY"
    //       - accountDetails.appLicensingVerdict == "LICENSED" (optional, for paid apps)
    // TODO: Derive device_id_hash from a stable device identifier returned by the API.

    // Interim device_id_hash: sha256 of the raw integrity_token bytes.
    let device_id_hash: [u8; 32] = Sha256::digest(integrity_token.as_bytes()).into();

    Ok(AttestationResult { device_id_hash })
}

// -- Test ------------------------------------------------------------------

fn verify_test(
    payload: &AttestationPayload,
    expected_client_data_hash: &[u8; 32],
) -> Result<AttestationResult, AttestationError> {
    let client_data_hash_hex = payload
        .client_data_hash
        .as_deref()
        .ok_or(AttestationError::MissingField("client_data_hash"))?;

    let provided_hash = hex::decode(client_data_hash_hex).map_err(|e| {
        AttestationError::Invalid(format!("client_data_hash is not valid hex: {e}"))
    })?;

    if provided_hash.as_slice() != expected_client_data_hash.as_slice() {
        return Err(AttestationError::ClientDataHashMismatch);
    }

    // In test mode the device_id_hash is just the expected client_data_hash
    // so that integration tests get a deterministic, predictable device ID.
    Ok(AttestationResult {
        device_id_hash: *expected_client_data_hash,
    })
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_hash(bytes: &[u8; 32]) -> String {
        hex::encode(bytes)
    }

    #[tokio::test]
    async fn test_test_platform_accepts_valid() {
        std::env::set_var("TOPRF_ALLOW_TEST_ATTESTATION", "1");
        let expected: [u8; 32] = [0xab; 32];
        let payload = AttestationPayload {
            platform: Platform::Test,
            attestation_object: None,
            assertion: None,
            client_data_hash: Some(hex_hash(&expected)),
            integrity_token: None,
        };

        let result = verify_attestation(&payload, &expected).await.unwrap();
        assert_eq!(result.device_id_hash, expected);
    }

    #[tokio::test]
    async fn test_test_platform_rejects_mismatch() {
        std::env::set_var("TOPRF_ALLOW_TEST_ATTESTATION", "1");
        let expected: [u8; 32] = [0xab; 32];
        let wrong: [u8; 32] = [0xcd; 32];
        let payload = AttestationPayload {
            platform: Platform::Test,
            attestation_object: None,
            assertion: None,
            client_data_hash: Some(hex_hash(&wrong)),
            integrity_token: None,
        };

        let err = verify_attestation(&payload, &expected).await.unwrap_err();
        assert!(
            matches!(err, AttestationError::ClientDataHashMismatch),
            "expected ClientDataHashMismatch, got: {err}"
        );
    }

    // Note: the env-var gate for Platform::Test cannot be reliably tested
    // in-process because env vars are process-global and tests run in parallel.
    // The gate is exercised by the integration tests instead.

    #[tokio::test]
    async fn test_ios_rejects_missing_fields() {
        let expected: [u8; 32] = [0x01; 32];
        let payload = AttestationPayload {
            platform: Platform::Ios,
            attestation_object: None,
            assertion: None,
            client_data_hash: None,
            integrity_token: None,
        };

        let err = verify_attestation(&payload, &expected).await.unwrap_err();
        assert!(
            matches!(err, AttestationError::MissingField(_)),
            "expected MissingField, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_android_rejects_missing_token() {
        let expected: [u8; 32] = [0x02; 32];
        let payload = AttestationPayload {
            platform: Platform::Android,
            attestation_object: None,
            assertion: None,
            client_data_hash: None,
            integrity_token: None,
        };

        let err = verify_attestation(&payload, &expected).await.unwrap_err();
        assert!(
            matches!(err, AttestationError::MissingField("integrity_token")),
            "expected MissingField(integrity_token), got: {err}"
        );
    }

    #[tokio::test]
    async fn test_ios_rejects_wrong_client_data_hash() {
        let expected: [u8; 32] = [0x03; 32];
        let wrong: [u8; 32] = [0xff; 32];
        let payload = AttestationPayload {
            platform: Platform::Ios,
            attestation_object: Some("dGVzdC1hdHRlc3RhdGlvbg==".to_string()), // base64 placeholder
            assertion: Some("dGVzdC1hc3NlcnRpb24=".to_string()),              // base64 placeholder
            client_data_hash: Some(hex_hash(&wrong)),
            integrity_token: None,
        };

        let err = verify_attestation(&payload, &expected).await.unwrap_err();
        assert!(
            matches!(err, AttestationError::ClientDataHashMismatch),
            "expected ClientDataHashMismatch, got: {err}"
        );
    }
}
