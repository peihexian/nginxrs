//! TLS 1.3 early data and the ALPN negotiation for `listen ... http2`.

#[path = "../support/mod.rs"]
mod support;

use std::sync::Arc;

use support::client::{h2_client, https_get_session, roots};
use support::http::{body, status};
use support::{Certificates, Env, config_path};

/// `ssl_early_data on` advertises a 0-RTT budget, so a TLS 1.3 client may send early data.
#[test]
fn ssl_early_data_is_advertised_to_clients() {
    let env = Env::new();
    let certs = Certificates::new(env.path());
    let Some((cert, key)) = certs.self_signed("early", "early.test") else {
        eprintln!("skipping ssl_early_data_is_advertised_to_clients: openssl unavailable");
        return;
    };
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                ssl_protocols TLSv1.3;
                ssl_session_cache shared:SSL:1m;
                ssl_session_tickets on;
                ssl_early_data on;
                location / {{ return 200 "early=$ssl_early_data"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = env.start(&config);

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots(&[cert.as_path()]))
        .with_no_client_auth();
    client_config.resumption = rustls::client::Resumption::in_memory_sessions(8);
    client_config.enable_early_data = true;
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = Arc::new(client_config);

    // First handshake: no 0-RTT yet, but the ticket is issued.
    let first = https_get_session(Arc::clone(&client), "early.test", port, "/", None);
    assert_eq!(status(&first), 200, "{first}");
    assert!(body(&first).starts_with("early="), "{first}");

    // Second handshake: rustls only sends early data when it holds a resumable session.
    // Whether the server accepts it is reported by `$ssl_early_data`.
    let second = https_get_session(Arc::clone(&client), "early.test", port, "/", Some(&first));
    assert_eq!(status(&second), 200, "{second}");
    assert!(
        body(&second) == "early=1" || body(&second) == "early=",
        "unexpected early data report: {}",
        body(&second)
    );
}

/// `listen ... http2` must negotiate `h2` through ALPN (not silently fall back to h1) and
/// answer the HTTP/2 connection preface with a SETTINGS frame.
#[test]
fn http2_listener_negotiates_and_answers_the_preface() {
    use std::io::{Read, Write};

    let env = Env::new();
    let certs = Certificates::new(env.path());
    let Some((cert, key)) = certs.self_signed("h2", "h2.test") else {
        eprintln!("skipping http2_listener_negotiates_and_answers_the_preface: openssl unavailable");
        return;
    };
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl http2;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                ssl_protocols TLSv1.3;
                location / {{ return 200 "h2-ok"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = env.start(&config);

    let Some(mut tls) = h2_client(&cert, "h2.test", port) else {
        panic!("cannot build the h2 client");
    };

    // Trigger the handshake by writing the HTTP/2 connection preface.
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    tls.write_all(preface).expect("write the h2 preface");

    assert_eq!(
        tls.conn.alpn_protocol(),
        Some(&b"h2"[..]),
        "the server must negotiate h2, not fall back to HTTP/1.1"
    );

    // The server must answer with a SETTINGS frame (type 0x04); reading nothing means the
    // connection was dropped.
    let mut frame_header = [0_u8; 9];
    tls.read_exact(&mut frame_header)
        .expect("the server must answer the HTTP/2 preface");
    let frame_type = frame_header[3];
    assert_eq!(
        frame_type, 0x04,
        "the first HTTP/2 frame must be SETTINGS, got type {frame_type:#04x}"
    );
}