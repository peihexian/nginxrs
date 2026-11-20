//! Session resumption and OCSP stapling.

#[path = "../support/mod.rs"]
mod support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use support::client::https_get_any;
use support::http::{body, status};
use support::server::run;
use support::{Certificates, Env, config_path};

/// `ssl_session_cache` resumes a session: a later handshake reports `r`.
#[test]
fn ssl_session_cache_resumes_connections() {
    let env = Env::new();
    let certs = Certificates::new(env.path());
    let Some((cert, key)) = certs.self_signed("session", "session.test") else {
        eprintln!("skipping ssl_session_cache_resumes_connections: openssl is unavailable");
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
                ssl_protocols TLSv1.2;
                ssl_session_cache shared:SSL:10m;
                ssl_session_tickets off;
                location / {{ return 200 "$ssl_session_reused"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = env.start(&config);

    // rustls needs a resumption store on the client side to reuse a session.
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(support::client::roots(&[cert.as_path()]))
        .with_no_client_auth();
    client_config.resumption = rustls::client::Resumption::in_memory_sessions(8);
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = Arc::new(client_config);

    let mut results = Vec::new();
    for _ in 0..3 {
        let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let connection =
            rustls::ClientConnection::new(Arc::clone(&client), "session.test".try_into().unwrap())
                .unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let request = "GET / HTTP/1.1\r\nHost: session.test\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        results.push(String::from_utf8_lossy(&response).to_string());
    }
    // The first handshake establishes the session; at least one later one must resume it.
    assert!(
        results.iter().skip(1).any(|response| body(response) == "r"),
        "no session was reused: {results:?}"
    );
}

/// A fake OCSP responder: counts the POSTs it receives and answers with `response`.
fn spawn_ocsp_responder(response: &'static [u8]) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0_u8; 8192];
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => request.extend_from_slice(&buffer[..count]),
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&request);
            assert!(
                text.contains("application/ocsp-request"),
                "the responder must receive an OCSP request"
            );
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(response);
            let _ = stream.flush();
        }
    });
    (port, hits)
}

/// `ssl_stapling on` + `ssl_stapling_responder` fetches the OCSP response at startup.
#[test]
fn ssl_stapling_responder_is_queried_for_a_response() {
    let env = Env::new();
    let certs = Certificates::new(env.path());
    let Some((cert, key)) = certs.self_signed("staple", "staple.test") else {
        eprintln!("skipping ssl_stapling_responder_is_queried_for_a_response: openssl unavailable");
        return;
    };
    let (responder_port, hits) =
        spawn_ocsp_responder(b"HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\nstaple-bytes");

    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                ssl_stapling on;
                ssl_stapling_responder http://127.0.0.1:{responder_port}/ocsp;
                location / {{ return 200 "ok"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = env.start(&config);
    let response = https_get_any("staple.test", port, "/");
    assert_eq!(status(&response), 200, "{response}");
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "the responder must have been queried"
    );
}

/// `ssl_stapling_verify on` rejects a responder answer that is not a valid OCSP response.
#[test]
fn ssl_stapling_verify_rejects_a_bogus_response() {
    let env = Env::new();
    let certs = Certificates::new(env.path());
    let Some((cert, key)) = certs.self_signed("verify", "verify.test") else {
        eprintln!("skipping ssl_stapling_verify_rejects_a_bogus_response: openssl unavailable");
        return;
    };
    let (responder_port, _hits) = spawn_ocsp_responder(
        b"HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\nnot-an-ocsp-response",
    );

    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                ssl_stapling on;
                ssl_stapling_verify on;
                ssl_stapling_responder http://127.0.0.1:{responder_port}/ocsp;
                location / {{ return 200 "ok"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let path = env.path().join("nginx.conf");
    std::fs::write(&path, &config).unwrap();
    let output = run(["-c", path.to_str().unwrap(), "-t"]);
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "a bogus OCSP response must fail the configuration check: {message}"
    );
    assert!(
        message.to_lowercase().contains("ocsp") || message.contains("stapling"),
        "{message}"
    );
    let _ = https_get_any("verify.test", port, "/");
}
