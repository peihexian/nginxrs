//! `ngx_http_gzip_filter_module` and `ngx_http_gunzip_filter_module` against real requests.

#[path = "../support/mod.rs"]
mod support;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Read, Write};
use support::http::{
    body, gzip_decode_bytes, header, is_gzip_encoded, raw_head, raw_request, request, status,
    try_header,
};
use support::Env;

/// A gzip response needs raw bytes: the decoded body is text, the wire form is not.
fn gzip_request(port: u16, path: &str, accept: &str) -> (String, String) {
    let raw = raw_request(
        port,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: {accept}\r\nConnection: close\r\n\r\n"
        ),
    );
    (raw_head(&raw), gzip_decode_bytes(&raw))
}

/// A body long enough to satisfy `gzip_min_length` (20 bytes by default).
const PAYLOAD: &str = "the quick brown fox jumps over the lazy dog, repeatedly and at length";

fn html_fixture(env: &Env) -> String {
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("page.html"), PAYLOAD).unwrap();
    std::fs::write(root.join("style.css"), PAYLOAD).unwrap();
    std::fs::write(root.join("tiny.html"), "small").unwrap();
    root.to_string_lossy().replace('\\', "/")
}

#[test]
fn gzip_compresses_text_html() {
    let env = Env::new();
    let root = html_fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            gzip on;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let (head, decoded) = gzip_request(port, "/page.html", "gzip");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(is_gzip_encoded(head.as_bytes()), "{head}");
    // `ngx_http_clear_accept_ranges`.
    assert!(!head.to_ascii_lowercase().contains("accept-ranges"), "{head}");
    assert_eq!(decoded, PAYLOAD);
}

#[test]
fn gzip_is_skipped_without_accept_encoding() {
    let env = Env::new();
    let root = html_fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            gzip on;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(port, "GET /page.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(status(&response), 200);
    assert!(try_header(&response, "Content-Encoding").is_none(), "{response}");
    assert_eq!(body(&response), PAYLOAD);
}

#[test]
fn gzip_respects_types_and_min_length() {
    let env = Env::new();
    let root = html_fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            gzip on;
            gzip_types text/css;
            gzip_min_length 50;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    // `text/css` is listed, so it compresses.
    let (head, decoded) = gzip_request(port, "/style.css", "gzip");
    assert!(is_gzip_encoded(head.as_bytes()), "{head}");
    assert_eq!(decoded, PAYLOAD);
    // A body below `gzip_min_length` is sent as-is.
    let response = request(
        port,
        "GET /tiny.html HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    assert!(try_header(&response, "Content-Encoding").is_none(), "{response}");
    assert_eq!(body(&response), "small");
}

#[test]
fn gzip_q_zero_disables_compression() {
    let env = Env::new();
    let root = html_fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            gzip on;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /page.html HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip;q=0\r\nConnection: close\r\n\r\n",
    );
    assert!(try_header(&response, "Content-Encoding").is_none(), "{response}");
    assert_eq!(body(&response), PAYLOAD);
}

#[test]
fn gzip_vary_is_configurable() {
    let env = Env::new();
    let root = html_fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            gzip on;
            gzip_vary on;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let (head, _) = gzip_request(port, "/page.html", "gzip");
    assert!(head.to_ascii_lowercase().contains("vary: accept-encoding"), "{head}");
}

#[test]
fn gzip_leaves_head_responses_uncompressed() {
    let env = Env::new();
    let root = html_fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            gzip on;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "HEAD /page.html HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200);
    // `r->header_only`: nginx announces the encoding but sends no body.
    // `r->header_only`: nginx announces the encoding but sends no body.
    assert!(is_gzip_encoded(response.as_bytes()), "{response}");
}

/// A backend that always answers with a gzipped body, whatever the client asked for.
fn spawn_gzip_backend() -> u16 {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(PAYLOAD.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    // The gzip stream is binary: it must not pass through `&str`, which would replace the
    // bytes that are not valid UTF-8.
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        compressed.len()
    )
    .into_bytes();
    response.extend_from_slice(&compressed);
    support::backend::spawn_raw_backend_bytes(Box::leak(response.into_boxed_slice()))
}

#[test]
fn gunzip_removes_an_encoding_the_client_cannot_read() {
    let env = Env::new();
    let backend = spawn_gzip_backend();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            gunzip on;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_set_header Host $host;
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    // The client sends no `Accept-Encoding`, so `ngx_http_gzip_ok` fails and gunzip runs.
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(status(&response), 200, "{response}");
    assert!(try_header(&response, "Content-Encoding").is_none(), "{response}");
    assert_eq!(header(&response, "Vary"), "Accept-Encoding", "{response}");
    assert_eq!(body(&response), PAYLOAD);
}

#[test]
fn gunzip_keeps_the_body_for_a_gzip_client() {
    let env = Env::new();
    let backend = spawn_gzip_backend();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            gunzip on;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_set_header Host $host;
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let (head, decoded) = gzip_request(port, "/", "gzip");
    assert!(is_gzip_encoded(head.as_bytes()), "{head}");
    assert_eq!(decoded, PAYLOAD);
}

#[test]
fn gzip_types_keep_the_implicit_text_html() {
    let env = Env::new();
    let root = html_fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            gzip on;
            gzip_types application/json;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    // `text/html` compresses even though the list names another type
    // (`ngx_http_merge_types` keeps the built-in default).
    let (head, decoded) = gzip_request(port, "/page.html", "gzip");
    assert!(is_gzip_encoded(head.as_bytes()), "{head}");
    assert_eq!(decoded, PAYLOAD);
}

#[test]
fn gzip_applies_behind_a_proxy() {
    use support::backend::spawn_raw_backend;
    let env = Env::new();
    let plain: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            PAYLOAD.len(),
            PAYLOAD
        )
        .into_boxed_str(),
    );
    let backend = spawn_raw_backend(plain);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            gzip on;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_set_header Host $host;
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let (head, decoded) = gzip_request(port, "/", "gzip");
    assert!(is_gzip_encoded(head.as_bytes()), "{head}");
    assert_eq!(decoded, PAYLOAD);
}

/// The decoder helper is exercised directly so a failure is reported here.
#[test]
fn decoder_round_trip() {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(b"hello").unwrap();
    let compressed = encoder.finish().unwrap();
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decoded = String::new();
    decoder.read_to_string(&mut decoded).unwrap();
    assert_eq!(decoded, "hello");
}
