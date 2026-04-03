//! Outbound HTTPS via vsock for Nitro Enclave network access.
//!
//! Nitro Enclaves have no network interfaces (not even localhost). All outbound
//! connections go through vsock to the parent EC2 instance:
//!
//! ```text
//! enclave: VsockStream(CID 3, port) → TLS(rustls) → HTTP request
//! parent:  vsock-proxy(port) → TCP → remote server
//! ```
//!
//! TLS is end-to-end (enclave ↔ remote server). The parent is a dumb relay.
//!
//! On non-Linux (dev/test), uses standard reqwest with direct TCP.

use reqwest::Client;
use tracing::info;

/// Well-known vsock port assignments for outbound proxies on the parent.
/// Each maps to a `vsock-proxy` or `socat VSOCK-LISTEN` instance on the parent.
pub const PROXY_PORT_METADATA: u32 = 8080; // → 169.254.169.254:80
pub const PROXY_PORT_GOOGLE_STS: u32 = 8443; // → sts.googleapis.com:443
pub const PROXY_PORT_PLAY_INTEGRITY: u32 = 8444; // → playintegrity.googleapis.com:443
pub const PROXY_PORT_WELL_KNOWN: u32 = 8445; // → ruonlabs.com:443
pub const PROXY_PORT_GOOGLE_IAM: u32 = 8446; // → iamcredentials.googleapis.com:443

/// Parent CID in Nitro Enclaves (always 3).
#[cfg(target_os = "linux")]
const PARENT_CID: u32 = 3;

/// Hostname-to-vsock-port mapping for outbound routing.
#[cfg(target_os = "linux")]
const HOST_PORT_MAP: &[(&str, u32)] = &[
    ("sts.googleapis.com", PROXY_PORT_GOOGLE_STS),
    ("playintegrity.googleapis.com", PROXY_PORT_PLAY_INTEGRITY),
    ("ruonlabs.com", PROXY_PORT_WELL_KNOWN),
    ("iamcredentials.googleapis.com", PROXY_PORT_GOOGLE_IAM),
];

/// No-op on non-Linux (bridges not needed, reqwest connects directly).
pub fn start_bridges() {
    #[cfg(not(target_os = "linux"))]
    info!("not in Nitro enclave — using direct TCP for outbound");
    #[cfg(target_os = "linux")]
    info!("Nitro enclave — outbound HTTPS will use vsock to parent CID 3");
}

/// Make an HTTPS GET request, routing through vsock in Nitro or direct TCP otherwise.
///
/// On Linux (Nitro): connects via AF_VSOCK to the parent's vsock-proxy,
/// wraps with TLS (rustls), sends the HTTP request, returns the body.
///
/// On non-Linux: uses reqwest directly.
pub async fn https_get(url: &str) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        vsock_https_get(url).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        direct_https_get(url).await
    }
}

/// Make an HTTPS POST request with JSON body.
pub async fn https_post_json(
    url: &str,
    body: &str,
    bearer_token: Option<&str>,
) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        vsock_https_post(url, body, bearer_token).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        direct_https_post(url, body, bearer_token).await
    }
}

/// Make a plain HTTP request (for IMDS).
pub async fn http_get(url: &str, headers: &[(&str, &str)]) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        vsock_http_request("GET", url, None, headers).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("client build: {e}"))?;
        let mut req = client.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.send()
            .await
            .map_err(|e| format!("request: {e}"))?
            .text()
            .await
            .map_err(|e| format!("body: {e}"))
    }
}

/// Make a plain HTTP PUT request (for IMDS token).
pub async fn http_put(url: &str, headers: &[(&str, &str)]) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        vsock_http_request("PUT", url, None, headers).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("client build: {e}"))?;
        let mut req = client.put(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.send()
            .await
            .map_err(|e| format!("request: {e}"))?
            .text()
            .await
            .map_err(|e| format!("body: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Non-Linux: direct reqwest
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
async fn direct_https_get(url: &str) -> Result<String, String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("client build: {e}"))?;
    client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("request: {e}"))?
        .text()
        .await
        .map_err(|e| format!("body: {e}"))
}

#[cfg(not(target_os = "linux"))]
async fn direct_https_post(
    url: &str,
    body: &str,
    bearer_token: Option<&str>,
) -> Result<String, String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("client build: {e}"))?;
    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body.to_string());
    if let Some(token) = bearer_token {
        req = req.bearer_auth(token);
    }
    req.send()
        .await
        .map_err(|e| format!("request: {e}"))?
        .text()
        .await
        .map_err(|e| format!("body: {e}"))
}

// ---------------------------------------------------------------------------
// Linux (Nitro): vsock + TLS
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn resolve_host_port(url: &str) -> Result<(&str, u32, &str, bool), String> {
    // Parse hostname and path from URL
    let is_https = url.starts_with("https://");
    let is_http = url.starts_with("http://");
    if !is_https && !is_http {
        return Err(format!("unsupported URL scheme: {url}"));
    }

    let without_scheme = if is_https { &url[8..] } else { &url[7..] };
    let (host, path) = match without_scheme.find('/') {
        Some(i) => (&without_scheme[..i], &without_scheme[i..]),
        None => (without_scheme, "/"),
    };

    // Look up vsock port for this host
    if is_https {
        for (h, port) in HOST_PORT_MAP {
            if *h == host {
                return Ok((host, *port, path, true));
            }
        }
    } else if host == "imds.local" || host == "169.254.169.254" {
        return Ok((host, PROXY_PORT_METADATA, path, false));
    }

    Err(format!("no vsock proxy configured for host: {host}"))
}

#[cfg(target_os = "linux")]
async fn vsock_https_get(url: &str) -> Result<String, String> {
    let (host, port, path, _tls) = resolve_host_port(url)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: toprf-node\r\n\r\n"
    );
    vsock_tls_request(host, port, &request).await
}

#[cfg(target_os = "linux")]
async fn vsock_https_post(
    url: &str,
    body: &str,
    bearer_token: Option<&str>,
) -> Result<String, String> {
    let (host, port, path, _tls) = resolve_host_port(url)?;
    let auth_header = match bearer_token {
        Some(token) => format!("Authorization: Bearer {token}\r\n"),
        None => String::new(),
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{auth_header}User-Agent: toprf-node\r\n\r\n{body}",
        body.len()
    );
    vsock_tls_request(host, port, &request).await
}

#[cfg(target_os = "linux")]
async fn vsock_http_request(
    method: &str,
    url: &str,
    body: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> Result<String, String> {
    let (host, port, path, _) = resolve_host_port(url)?;

    let mut headers = String::new();
    for (k, v) in extra_headers {
        headers.push_str(&format!("{k}: {v}\r\n"));
    }

    let body_str = body.unwrap_or("");
    let content_length = if !body_str.is_empty() {
        format!("Content-Length: {}\r\n", body_str.len())
    } else {
        String::new()
    };

    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{headers}{content_length}\r\n{body_str}"
    );

    // Plain HTTP (no TLS) over vsock
    vsock_plain_request(port, &request).await
}

/// Send a raw HTTP request over vsock with TLS.
#[cfg(target_os = "linux")]
async fn vsock_tls_request(host: &str, port: u32, raw_request: &str) -> Result<String, String> {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_vsock::VsockStream;

    // Connect via vsock to parent
    let vsock_addr = tokio_vsock::VsockAddr::new(PARENT_CID, port);
    let vsock_stream = VsockStream::connect(vsock_addr)
        .await
        .map_err(|e| format!("vsock connect to port {port}: {e}"))?;

    // Set up TLS with rustls
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid server name: {e}"))?;

    let mut tls_stream = connector
        .connect(server_name, vsock_stream)
        .await
        .map_err(|e| format!("TLS handshake with {host}: {e}"))?;

    // Send HTTP request
    tls_stream
        .write_all(raw_request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    // Read response
    let mut response = Vec::new();
    tls_stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("read: {e}"))?;

    let response_str =
        String::from_utf8(response).map_err(|e| format!("response not utf8: {e}"))?;

    // Extract body (after \r\n\r\n)
    match response_str.find("\r\n\r\n") {
        Some(i) => Ok(response_str[i + 4..].to_string()),
        None => Ok(response_str),
    }
}

/// Send a raw HTTP request over vsock without TLS (for IMDS).
#[cfg(target_os = "linux")]
async fn vsock_plain_request(port: u32, raw_request: &str) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_vsock::VsockStream;

    let vsock_addr = tokio_vsock::VsockAddr::new(PARENT_CID, port);
    let mut stream = VsockStream::connect(vsock_addr)
        .await
        .map_err(|e| format!("vsock connect to port {port}: {e}"))?;

    stream
        .write_all(raw_request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("read: {e}"))?;

    let response_str =
        String::from_utf8(response).map_err(|e| format!("response not utf8: {e}"))?;

    match response_str.find("\r\n\r\n") {
        Some(i) => Ok(response_str[i + 4..].to_string()),
        None => Ok(response_str),
    }
}
