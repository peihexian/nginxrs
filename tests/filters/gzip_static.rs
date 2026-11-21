//! `ngx_http_gzip_static_module`: the `.gz` sibling.

#[path = "../support/mod.rs"]
mod support;

use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use support::http::{body, gzip_decode_bytes, is_gzip_encoded, raw_head, raw_request, request, status, try_header};
use support::Env;

const PAYLOAD: &str = "precompressed body serving: the plain file is never touched";

/// Write `app.js` and `app.js.gz` under `root`.
fn fixture(env: &Env) -> String {
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.js"), PAYLOAD).unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(PAYLOAD.as_bytes()).unwrap();
    std::fs::write(root.join("app.js.gz"), encoder.finish().unwrap()).unwrap();
    root.to_string_lossy().replace('\\', "/")
}

fn config(root: &str, port: u16, mode: &str) -> String {
    format!(
        r#"
        http {{
            access_log off;
            gzip_static {mode};
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{ }}
            }}
        }}
        "#,
    )
}

#[test]
fn gzip_static_on_serves_the_compressed_file() {
    let env = Env::new();
    let root = fixture(&env);
    let _server = env.start(&config(&root, env.port, "on"));
    let raw = raw_request(
        env.port,
        "GET /app.js HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    assert!(is_gzip_encoded(&raw), "{}", raw_head(&raw));
    assert_eq!(gzip_decode_bytes(&raw), PAYLOAD);
    // `gzip_static on` sets `Vary: Accept-Encoding`.
    assert!(
        raw_head(&raw).to_ascii_lowercase().contains("vary: accept-encoding"),
        "{}",
        raw_head(&raw)
    );
}

#[test]
fn gzip_static_on_falls_back_for_a_plain_client() {
    let env = Env::new();
    let root = fixture(&env);
    let _server = env.start(&config(&root, env.port, "on"));
    let response = request(env.port, "GET /app.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(status(&response), 200);
    assert!(try_header(&response, "Content-Encoding").is_none(), "{response}");
    assert_eq!(body(&response), PAYLOAD);
    // The location still varies on `Accept-Encoding`.
    assert_eq!(
        support::http::header(&response, "Vary"),
        "Accept-Encoding",
        "{response}"
    );
}

#[test]
fn gzip_static_always_serves_without_accept_encoding() {
    let env = Env::new();
    let root = fixture(&env);
    let _server = env.start(&config(&root, env.port, "always"));
    let raw = raw_request(
        env.port,
        "GET /app.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(is_gzip_encoded(&raw), "{}", raw_head(&raw));
    assert_eq!(gzip_decode_bytes(&raw), PAYLOAD);
}

#[test]
fn gzip_static_misses_without_the_sibling() {
    let env = Env::new();
    let root = fixture(&env);
    std::fs::write(env.path().join("html").join("plain.js"), "no sibling").unwrap();
    let _server = env.start(&config(&root, env.port, "on"));
    let response = request(
        env.port,
        "GET /plain.js HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200);
    assert_eq!(body(&response), "no sibling");
}

#[test]
fn gzip_static_off_uses_the_plain_file() {
    let env = Env::new();
    let root = fixture(&env);
    let _server = env.start(&config(&root, env.port, "off"));
    let response = request(
        env.port,
        "GET /app.js HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200);
    assert!(try_header(&response, "Content-Encoding").is_none(), "{response}");
    assert_eq!(body(&response), PAYLOAD);
}

#[test]
fn gzip_static_head_stops_after_the_headers() {
    let env = Env::new();
    let root = fixture(&env);
    let _server = env.start(&config(&root, env.port, "always"));
    let response = request(
        env.port,
        "HEAD /app.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200);
    assert_eq!(
        support::http::header(&response, "Content-Encoding"),
        "gzip",
        "{response}"
    );
    assert!(body(&response).is_empty(), "{response}");
}

#[test]
fn gzip_static_keeps_the_original_content_type() {
    let env = Env::new();
    let root = fixture(&env);
    let _server = env.start(&config(&root, env.port, "always"));
    let raw = raw_request(
        env.port,
        "GET /app.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let head = raw_head(&raw).to_ascii_lowercase();
    // The requested URI carries the type (`application/javascript`), not `.gz`.
    assert!(head.contains("content-type: text/javascript") || head.contains("content-type: application/javascript"), "{head}");
}

#[test]
fn gzip_static_rejects_invalid_values() {
    let env = Env::new();
    let config = format!(
        r#"
        http {{
            gzip_static maybe;
            server {{ listen 127.0.0.1:{}; location / {{ }} }}
        }}
        "#,
        env.port
    );
    let path = env.path().join("nginx.conf");
    std::fs::write(&path, config).unwrap();
    let output = support::run(["-c", &path.to_string_lossy(), "-t"]);
    assert!(!output.status.success());
}
