//! Nitro Enclave attestation endpoint (challenge-response).
//!
//! The client sends a random 32-byte nonce; the node generates a fresh Nitro
//! attestation document (COSE_Sign1) with:
//!   - user_data[0..32] = SHA-256(ephemeral X25519 pubkey) — key binding
//!   - nonce = the client's nonce — freshness
//!
//! The COSE_Sign1 document is signed by the NSM (Nitro Security Module) and
//! chains to the AWS Nitro Root CA. It contains PCR0/1/2 measurements that
//! prove the enclave's identity.
//!
//! Only works inside a Nitro Enclave (/dev/nsm must exist). Returns 503 outside.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::NodeState;

#[derive(Deserialize)]
pub struct NitroAttestationQuery {
    /// 32-byte hex-encoded nonce from the client.
    pub nonce: String,
}

#[derive(Serialize)]
pub struct NitroAttestationResponse {
    pub node_id: u16,
    /// Base64-encoded COSE_Sign1 attestation document from the NSM.
    pub attestation_document: String,
    pub platform: String,
}

pub async fn nitro_attestation_handler(
    State(state): State<Arc<NodeState>>,
    Query(query): Query<NitroAttestationQuery>,
) -> Result<Json<NitroAttestationResponse>, (StatusCode, String)> {
    // Validate nonce
    let nonce_bytes = hex::decode(&query.nonce)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid nonce hex: {e}")))?;
    if nonce_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("nonce must be 32 bytes, got {}", nonce_bytes.len()),
        ));
    }

    // Build user_data: SHA-256(ephemeral X25519 pubkey) for key binding.
    let (_, pubkey) = &state.join_keypair;
    let user_data = Sha256::digest(pubkey.as_bytes()).to_vec();

    // Request attestation from NSM device
    let document = request_nsm_attestation(&user_data, &nonce_bytes).map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Nitro attestation not available: {e}"),
        )
    })?;

    let node_id = state.loaded_key.get().map(|k| k.node_id).unwrap_or(0);

    use base64::Engine;
    Ok(Json(NitroAttestationResponse {
        node_id,
        attestation_document: base64::engine::general_purpose::STANDARD.encode(&document),
        platform: "nitro".to_string(),
    }))
}

// ---------------------------------------------------------------------------
// NSM device interface
// ---------------------------------------------------------------------------

/// Request an attestation document from the Nitro Security Module.
///
/// This communicates with `/dev/nsm` via ioctl. Only works inside a Nitro
/// Enclave. Returns the raw COSE_Sign1 bytes.
#[cfg(target_os = "linux")]
fn request_nsm_attestation(user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    // Check if NSM device exists
    let nsm_path = "/dev/nsm";
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(nsm_path)
        .map_err(|e| format!("/dev/nsm not available: {e}"))?;

    // Build CBOR request: { "Attestation": { "user_data": <bytes>, "nonce": <bytes>, "public_key": null } }
    let request_payload = ciborium::Value::Map(vec![(
        ciborium::Value::Text("Attestation".to_string()),
        ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("user_data".to_string()),
                ciborium::Value::Bytes(user_data.to_vec()),
            ),
            (
                ciborium::Value::Text("nonce".to_string()),
                ciborium::Value::Bytes(nonce.to_vec()),
            ),
            (
                ciborium::Value::Text("public_key".to_string()),
                ciborium::Value::Null,
            ),
        ]),
    )]);

    let mut request_buf = Vec::new();
    ciborium::into_writer(&request_payload, &mut request_buf)
        .map_err(|e| format!("CBOR encode error: {e}"))?;

    // Allocate response buffer. Nitro attestation documents are typically ~4-5KB
    // but cert chains vary by region. 32KB covers all observed cases.
    let mut response_buf = vec![0u8; 32768];

    // NSM ioctl — the kernel driver uses struct iovec (pointer + size_t),
    // so lengths must be usize, not u32.
    #[repr(C)]
    struct NsmMessage {
        request: *const u8,
        request_len: usize,
        response: *mut u8,
        response_len: usize,
    }

    let mut msg = NsmMessage {
        request: request_buf.as_ptr(),
        request_len: request_buf.len(),
        response: response_buf.as_mut_ptr(),
        response_len: response_buf.len(),
    };

    // ioctl number: _IOWR(0x0A, 0, NsmMessage)
    // Direction: read+write (3), magic: 0x0A, number: 0, size: size_of::<NsmMessage>()
    let nsm_msg_size = std::mem::size_of::<NsmMessage>() as u32;
    let ioctl_num = (3u32 << 30) | (nsm_msg_size << 16) | (0x0Au32 << 8);

    // `as _` lets the compiler cast to whatever type libc::ioctl expects
    // (Ioctl is i32 on some Linux targets, c_ulong on others)
    #[allow(clippy::unnecessary_cast)]
    let ret = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            ioctl_num as _,
            &mut msg as *mut NsmMessage,
        )
    };
    if ret < 0 {
        return Err(format!(
            "NSM ioctl failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Parse CBOR response
    let response_data = &response_buf[..msg.response_len];

    let response_value: ciborium::Value = ciborium::from_reader(response_data)
        .map_err(|e| format!("NSM response CBOR parse error: {e}"))?;

    // Expected: { "Attestation": { "document": <bytes> } }
    // Or: { "Error": "<error string>" }
    match &response_value {
        ciborium::Value::Map(entries) => {
            for (key, val) in entries {
                if let ciborium::Value::Text(k) = key {
                    if k == "Attestation" {
                        if let ciborium::Value::Map(att_entries) = val {
                            for (ak, av) in att_entries {
                                if let ciborium::Value::Text(ak_str) = ak {
                                    if ak_str == "document" {
                                        if let ciborium::Value::Bytes(doc) = av {
                                            return Ok(doc.clone());
                                        }
                                    }
                                }
                            }
                        }
                        return Err("NSM response missing 'document' field".to_string());
                    } else if k == "Error" {
                        return Err(format!("NSM error: {:?}", val));
                    }
                }
            }
            Err("unexpected NSM response format".to_string())
        }
        _ => Err("NSM response is not a CBOR map".to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
fn request_nsm_attestation(_user_data: &[u8], _nonce: &[u8]) -> Result<Vec<u8>, String> {
    Err("Nitro NSM device is only available on Linux".to_string())
}
