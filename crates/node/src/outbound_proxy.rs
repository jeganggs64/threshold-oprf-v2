//! Outbound TCP-to-vsock bridge for Nitro Enclave network access.
//!
//! Nitro Enclaves have no network. Outbound HTTPS connections are routed
//! through the parent EC2 instance via vsock:
//!
//! ```text
//! enclave reqwest → TCP 127.0.0.1:<port> → this bridge → vsock CID 3:<port> → vsock-proxy (parent) → internet
//! ```
//!
//! The parent runs `vsock-proxy` for each allowed endpoint. TLS is end-to-end
//! (enclave to remote server), so the parent cannot read or modify traffic.
//!
//! On non-Linux or when vsock is unavailable (dev/test), the bridge is not
//! started and reqwest connects directly via TCP.

use reqwest::Client;
#[cfg(target_os = "linux")]
use tracing::error;
use tracing::info;

/// Well-known vsock port assignments for outbound proxies on the parent.
/// Each port maps to a specific `vsock-proxy` instance on the parent.
pub const PROXY_PORT_METADATA: u32 = 8080; // → 169.254.169.254:80 (AWS instance metadata)
pub const PROXY_PORT_GOOGLE_STS: u32 = 8443; // → sts.googleapis.com:443
pub const PROXY_PORT_PLAY_INTEGRITY: u32 = 8444; // → playintegrity.googleapis.com:443
pub const PROXY_PORT_WELL_KNOWN: u32 = 8445; // → ruonlabs.com:443
pub const PROXY_PORT_GOOGLE_IAM: u32 = 8446; // → iamcredentials.googleapis.com:443

/// Parent CID in Nitro Enclaves.
#[cfg(target_os = "linux")]
const PARENT_CID: u32 = 3;

/// Start TCP-to-vsock bridges for all outbound endpoints.
///
/// Each bridge listens on 127.0.0.1:<port> and forwards connections to
/// vsock CID 3 (parent) on the same port. reqwest connects to these local
/// TCP ports, and the parent's vsock-proxy forwards to the real endpoint.
#[cfg(target_os = "linux")]
pub fn start_bridges() {
    let ports = [
        (PROXY_PORT_METADATA, "instance-metadata"),
        (PROXY_PORT_GOOGLE_STS, "sts.googleapis.com"),
        (PROXY_PORT_PLAY_INTEGRITY, "playintegrity.googleapis.com"),
        (PROXY_PORT_WELL_KNOWN, "ruonlabs.com"),
        (PROXY_PORT_GOOGLE_IAM, "iamcredentials.googleapis.com"),
    ];

    for (port, label) in ports {
        tokio::spawn(async move {
            if let Err(e) = run_bridge(port, label).await {
                error!(port, label, "outbound bridge failed: {e}");
            }
        });
    }

    info!("outbound vsock bridges started");
}

#[cfg(target_os = "linux")]
async fn run_bridge(port: u32, label: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::copy_bidirectional;
    use tokio::net::TcpListener;
    use tokio_vsock::VsockStream;

    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).await?;
    info!(port, label, "outbound bridge listening on {addr}");

    loop {
        let (mut tcp_stream, _) = listener.accept().await?;
        let vsock_addr = tokio_vsock::VsockAddr::new(PARENT_CID, port);

        tokio::spawn(async move {
            match VsockStream::connect(vsock_addr).await {
                Ok(mut vsock_stream) => {
                    if let Err(e) = copy_bidirectional(&mut tcp_stream, &mut vsock_stream).await {
                        // Connection closed is normal
                        if e.kind() != std::io::ErrorKind::UnexpectedEof {
                            error!(port, "bridge copy error: {e}");
                        }
                    }
                }
                Err(e) => {
                    error!(port, label, "vsock connect to parent failed: {e}");
                }
            }
        });
    }
}

/// On non-Linux, bridges are not needed — reqwest connects directly.
#[cfg(not(target_os = "linux"))]
pub fn start_bridges() {
    info!("not in Nitro enclave — outbound bridges not started, using direct TCP");
}

/// Build a reqwest client that routes specific hosts through the vsock bridges.
///
/// On Linux (Nitro), hostnames are resolved to 127.0.0.1 with the bridge port,
/// so reqwest connects to the local TCP bridge which forwards via vsock.
/// TLS still uses the real hostname for SNI and cert verification.
///
/// On non-Linux (dev/test), reqwest connects directly.
pub fn build_proxied_client() -> Result<Client, reqwest::Error> {
    let builder = Client::builder().timeout(std::time::Duration::from_secs(30));

    #[cfg(target_os = "linux")]
    let builder = builder
        .resolve(
            "sts.googleapis.com",
            format!("127.0.0.1:{PROXY_PORT_GOOGLE_STS}")
                .parse()
                .unwrap(),
        )
        .resolve(
            "playintegrity.googleapis.com",
            format!("127.0.0.1:{PROXY_PORT_PLAY_INTEGRITY}")
                .parse()
                .unwrap(),
        )
        .resolve(
            "ruonlabs.com",
            format!("127.0.0.1:{PROXY_PORT_WELL_KNOWN}")
                .parse()
                .unwrap(),
        )
        .resolve(
            "iamcredentials.googleapis.com",
            format!("127.0.0.1:{PROXY_PORT_GOOGLE_IAM}")
                .parse()
                .unwrap(),
        );

    builder.build()
}

/// Build a reqwest client for AWS instance metadata (HTTP, not HTTPS).
#[cfg(target_os = "linux")]
pub fn build_metadata_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .resolve(
            "169.254.169.254",
            format!("127.0.0.1:{PROXY_PORT_METADATA}").parse().unwrap(),
        )
        .build()
}
