//! `ssl_reject_handshake`: servers without certificates and names that must fail.

#[path = "../support/mod.rs"]
mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use support::client::https_get_any;
use support::http::{body, status};
use support::server::run;
use support::{Certificates, Env, config_path};

/// `ssl_reject_handshake on` lets a server exist without certificates (`-t` accepts it) and
/// rejects the handshake for its names (`ngx_http_ssl_servername` -> `handshake_rejected`).
#[test]
fn ssl_reject_handshake_rejects_unmatched_names() {
    let env = Env::new();
    let certs = Certificates::new(env.path());
    let Some((cert, key)) = certs.self_signed("default", "default.test") else {
        eprintln!("skipping ssl_reject_handshake_rejects_unmatched_names: openssl is unavailable");
        return;
    };
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl default_server;
                server_name default.test;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                location / {{ return 200 "default"; }}
            }}
            server {{
                listen 127.0.0.1:{port} ssl;
                server_name rejected.test;
                ssl_reject_handshake on;
                location / {{ return 200 "never"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = env.start(&config);

    // The configured name is answered normally.
    let response = https_get_any("default.test", port, "/");
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "default");

    // The rejected name never completes a handshake.
    let mut roots = rustls::RootCertStore::empty();
    let data = std::fs::read(&cert).unwrap();
    for item in rustls_pemfile::certs(&mut data.as_slice()) {
        roots.add(item.unwrap()).unwrap();
    }
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector =
        rustls::ClientConnection::new(Arc::new(client), "rejected.test".try_into().unwrap())
            .unwrap();
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut stream = rustls::StreamOwned::new(connector, socket);
    let request = "GET / HTTP/1.1\r\nHost: rejected.test\r\nConnection: close\r\n\r\n";
    let handshake = stream.write_all(request.as_bytes());
    assert!(
        handshake.is_err(),
        "the handshake must fail for a rejected server name"
    );
    let mut sink = Vec::new();
    let _ = stream.read(&mut sink);
}

/// A `server` may rely on `ssl_reject_handshake` alone: `-t` must accept it.
#[test]
fn ssl_reject_handshake_server_needs_no_certificate() {
    let env = Env::new();
    let path = env.path().join("nginx.conf");
    std::fs::write(
        &path,
        r#"
        http {
            server {
                listen 127.0.0.1:18097 ssl default_server;
                ssl_reject_handshake on;
                location / { return 200 "never"; }
            }
        }
        "#,
    )
    .unwrap();
    let output = run(["-c", path.to_str().unwrap(), "-t"]);
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{message}");
    assert!(message.contains("successful"), "{message}");
}

/// `ssl_verify_client on` with `ssl_verify_depth` rejects a client certificate signed by an
/// unknown CA, and accepts one from the configured CA.
#[test]
fn ssl_verify_client_validates_the_client_certificate() {
    let env = Env::new();
    let certs = Certificates::new(env.path());
    let Some((server_cert, server_key)) = certs.self_signed("server", "mtls.test") else {
        eprintln!("skipping ssl_verify_client_validates_the_client_certificate: openssl is unavailable");
        return;
    };
    let Some((ca, client_cert, client_key)) = certs.signed("client", "client.test") else {
        return;
    };
    // A second CA whose certificate is NOT configured on the server.
    let Some((_other_ca, other_cert, other_key)) = certs.signed("other", "other.test") else {
        return;
    };
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate {server_cert};
                ssl_certificate_key {server_key};
                ssl_verify_client on;
                ssl_verify_depth 2;
                ssl_client_certificate {ca};
                location / {{ return 200 "$ssl_client_verify|$ssl_client_s_dn"; }}
            }}
        }}
        "#,
        server_cert = config_path(&server_cert),
        server_key = config_path(&server_key),
        ca = config_path(&ca),
    );
    let _server = env.start(&config);

    let roots: [&Path; 1] = [server_cert.as_path()];
    let trusted = support::client::https_get_with(
        support::client::client_with_certificate(&roots, &client_cert, &client_key),
        "mtls.test",
        port,
        "/",
    );
    assert_eq!(status(&trusted), 200, "{trusted}");
    let reported = body(&trusted);
    assert!(
        reported.starts_with("SUCCESS|"),
        "the trusted certificate must verify: {reported}"
    );

    // An untrusted client certificate must not produce a 200.
    let untrusted = support::client::https_get_with(
        support::client::client_with_certificate(&roots, &other_cert, &other_key),
        "mtls.test",
        port,
        "/",
    );
    assert!(
        untrusted.is_empty() || status(&untrusted) != 200,
        "an untrusted client certificate must be rejected: {untrusted}"
    );
}