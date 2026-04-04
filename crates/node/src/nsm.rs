//! Shared Nitro Security Module (NSM) interface.
//!
//! Provides attestation document generation from the NSM device (/dev/nsm).
//! Used by both the attestation endpoint and DKG round 1.

/// Request an attestation document from the NSM device.
///
/// - `user_data`: optional bytes bound into the attestation (e.g., hash of commitment)
/// - `nonce`: optional bytes for freshness (e.g., client challenge)
/// - `public_key`: optional DER-encoded public key (for KMS integration)
///
/// Returns the raw COSE_Sign1 attestation document bytes.
#[cfg(target_os = "linux")]
pub fn request_attestation(
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let nsm_path = "/dev/nsm";
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(nsm_path)
        .map_err(|e| format!("/dev/nsm not available: {e}"))?;

    // Build CBOR request
    let ud = match user_data {
        Some(d) => ciborium::Value::Bytes(d.to_vec()),
        None => ciborium::Value::Null,
    };
    let nc = match nonce {
        Some(d) => ciborium::Value::Bytes(d.to_vec()),
        None => ciborium::Value::Null,
    };
    let pk = match public_key {
        Some(d) => ciborium::Value::Bytes(d.to_vec()),
        None => ciborium::Value::Null,
    };

    let request_payload = ciborium::Value::Map(vec![(
        ciborium::Value::Text("Attestation".to_string()),
        ciborium::Value::Map(vec![
            (ciborium::Value::Text("user_data".to_string()), ud),
            (ciborium::Value::Text("nonce".to_string()), nc),
            (ciborium::Value::Text("public_key".to_string()), pk),
        ]),
    )]);

    let mut request_buf = Vec::new();
    ciborium::into_writer(&request_payload, &mut request_buf)
        .map_err(|e| format!("CBOR encode error: {e}"))?;

    let mut response_buf = vec![0u8; 32768];

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

    let nsm_msg_size = std::mem::size_of::<NsmMessage>() as u32;
    let ioctl_num = (3u32 << 30) | (nsm_msg_size << 16) | (0x0Au32 << 8);

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

    let response_data = &response_buf[..msg.response_len];
    let response_value: ciborium::Value = ciborium::from_reader(response_data)
        .map_err(|e| format!("NSM response CBOR parse error: {e}"))?;

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
pub fn request_attestation(
    _user_data: Option<&[u8]>,
    _nonce: Option<&[u8]>,
    _public_key: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    Err("NSM device is only available on Linux (Nitro Enclave)".to_string())
}
