//! A minimal gRPC (HTTP/2) backend for the `grpc_pass` tests.
//!
//! It answers every call with a `200` response whose body echoes the received `:path` and
//! whose trailers carry `grpc-status: 0`, which is exactly the shape a gRPC client reads.

use bytes::Bytes;
use h2::server;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// Start a gRPC backend on an ephemeral port with its own request log.
///
/// Each call gets a fresh log: tests run in parallel, so a process-wide log would mix their
/// requests.
pub fn spawn_grpc_backend() -> (u16, Arc<Mutex<Vec<String>>>) {
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind gRPC backend");
    let port = listener.local_addr().unwrap().port();
    let accept_log = Arc::clone(&log);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let log = Arc::clone(&accept_log);
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                runtime.block_on(async move {
                    stream
                        .set_nonblocking(true)
                        .expect("non-blocking backend socket");
                    let stream = tokio::net::TcpStream::from_std(stream).expect("tokio stream");
                    let mut connection = match server::handshake(stream).await {
                        Ok(connection) => connection,
                        Err(_) => return,
                    };
                    while let Some(request) = connection.accept().await {
                        let Ok((request, mut respond)) = request else {
                            return;
                        };
                        let path = request.uri().path().to_string();
                        let method = request.method().to_string();
                        let content_type = request
                            .headers()
                            .get("content-type")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        let te = request
                            .headers()
                            .get("te")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_string();
                        if let Ok(mut entries) = log.lock() {
                            entries.push(format!(
                                "{method} {path} content-type={content_type} te={te}"
                            ));
                        }
                        let mut body = request.into_body();
                        let mut received = Vec::new();
                        while let Some(chunk) = body.data().await {
                            let Ok(chunk) = chunk else { break };
                            received.extend_from_slice(&chunk);
                        }
                        let reply = format!("{path}|{}", received.len());
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(())
                            .expect("grpc response head");
                        let Ok(mut send) = respond.send_response(response, false) else {
                            return;
                        };
                        let _ = send.send_data(Bytes::from(reply), false);
                        // `grpc-status` lives in the trailers.
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        trailers.insert("grpc-message", "ok".parse().unwrap());
                        let _ = send.send_trailers(trailers);
                    }
                });
            });
        }
    });
    (port, log)
}
