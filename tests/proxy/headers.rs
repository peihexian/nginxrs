//! Which response and request headers the proxy hides, passes through or rewrites.

#[path = "../support/mod.rs"]
mod support;

use support::backend::{spawn_echo_backend, spawn_raw_backend, spawn_recording_backend};
use support::http::{body, request, status};
use support::Env;

/// `proxy_pass_header` restores a header which is hidden by default.
#[test]
fn proxy_pass_header_restores_a_default_hidden_header() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_raw_backend(
        "HTTP/1.1 200 OK\r\nServer: upstream/1.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_pass_header Server;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert!(
        response.to_lowercase().contains("server: upstream/1.0"),
        "the upstream Server must be passed through: {response}"
    );
}

/// An upstream `Server` header is dropped unless `proxy_pass_header` names it.
#[test]
fn upstream_date_is_hidden_by_default() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_raw_backend(
        "HTTP/1.1 200 OK\r\nServer: upstream/1.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ proxy_pass http://backend; }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert!(
        !response.to_lowercase().contains("upstream/1.0"),
        "the upstream Server must be hidden: {response}"
    );
}

/// `X-Accel-*` control headers are consumed and never forwarded.
#[test]
fn x_accel_headers_are_not_forwarded() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_raw_backend(
        "HTTP/1.1 200 OK\r\nX-Accel-Expires: 60\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    );
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ proxy_pass http://backend; }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert!(
        !response.to_lowercase().contains("x-accel-expires"),
        "X-Accel-* must not reach the client: {response}"
    );
}

/// `ngx_http_proxy_headers`: hop-by-hop fields are cleared and `Connection: close` is sent.
#[test]
fn connection_header_is_not_forwarded_upstream() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_echo_backend();
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ proxy_pass http://backend/; }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /x HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    let echoed = body(&response);
    assert!(
        !echoed.contains("keep-alive: timeout"),
        "Keep-Alive must not reach the upstream: {echoed}"
    );
    // The default is `proxy_set_header Connection close`, so the client's `keep-alive` is
    // replaced rather than forwarded.
    assert!(
        echoed.contains("connection: close"),
        "the default Connection: close must be sent: {echoed}"
    );
    assert!(
        !echoed.contains("connection: keep-alive"),
        "the client Connection must not be forwarded: {echoed}"
    );
}

/// `proxy_http_version 1.1` (the default) sends an HTTP/1.1 request line upstream.
#[test]
fn proxy_http_version_defaults_to_1_1() {
    let env = Env::new();
    let port = env.port;
    let (backend, seen) = spawn_recording_backend();
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ proxy_pass http://backend/; }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    let request_line = seen.lock().unwrap().clone();
    assert!(
        request_line.ends_with("HTTP/1.1"),
        "the upstream request line must be HTTP/1.1 by default: {request_line}"
    );
}

/// `proxy_http_version 1.0` is still available and switches the request line.
#[test]
fn proxy_http_version_1_0_is_honoured() {
    let env = Env::new();
    let port = env.port;
    let (backend, seen) = spawn_recording_backend();
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend/;
                    proxy_http_version 1.0;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    let request_line = seen.lock().unwrap().clone();
    assert!(
        request_line.ends_with("HTTP/1.0"),
        "proxy_http_version 1.0 must be honoured: {request_line}"
    );
}