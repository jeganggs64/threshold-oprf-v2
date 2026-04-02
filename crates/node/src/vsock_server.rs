//! vsock listener for AWS Nitro Enclaves.
//!
//! Nitro Enclaves have no network interface. Communication with the parent
//! EC2 instance happens over virtio-vsock. This module accepts vsock
//! connections and serves the axum Router over HTTP/1.1 using hyper directly.

use axum::Router;
use hyper_util::rt::TokioIo;
use tokio_vsock::VsockListener;
use tower::Service;
use tracing::{info, warn};

/// CID_ANY (0xFFFFFFFF) — binds to any CID, which is standard for an
/// enclave that accepts connections from the parent instance.
const VSOCK_CID_ANY: u32 = 0xFFFFFFFF;

/// Serve the given axum Router on a vsock listener at the specified port.
///
/// This function loops forever, accepting connections and spawning a
/// task for each one. It never returns under normal operation.
pub async fn serve(app: Router, port: u16) -> ! {
    let listener =
        VsockListener::bind(VSOCK_CID_ANY, port as u32).expect("failed to bind vsock listener");
    info!(
        port = port,
        cid = VSOCK_CID_ANY,
        "listening on vsock (Nitro Enclave mode)"
    );

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let app = app.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    // Convert the incoming hyper::body::Incoming into axum::body::Body
                    // so the Router can process it.
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let mut app = app.clone();
                            async move {
                                let (parts, body) = req.into_parts();
                                let body = axum::body::Body::new(body);
                                let req = hyper::Request::from_parts(parts, body);
                                Ok::<_, std::convert::Infallible>(
                                    app.call(req).await.unwrap_or_else(|e| match e {}),
                                )
                            }
                        },
                    );
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        warn!(peer = ?addr, "vsock connection error: {e}");
                    }
                });
            }
            Err(e) => {
                warn!("vsock accept error: {e}");
            }
        }
    }
}
