//! `proxy_redirect`, `proxy_cookie_*`, `proxy_method`, `proxy_set_body` and the
//! `proxy_pass_request_body`/`proxy_pass_request_headers` switches.

#[path = "../support/mod.rs"]
mod support;

use support::backend::{spawn_echo_backend, spawn_raw_backend, spawn_raw_backend_on};
use support::http::{body, header, request, status};
use support::{Env, free_port};

/// `proxy_redirect default` rewrites an absolute upstream `Location` to the client origin.
#[test]
fn proxy_redirect_default_rewrites_location() {
    let env = Env::new();
    let port = env.port;
    // The upstream answers with its own address, which is what `proxy_redirect default`
    // matches (`proxy_pass http://127.0.0.1:<backend>/`).
    let backend_port = free_port();
    let response_bytes: &'static str = Box::leak(
        format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{backend_port}/login?next=/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_boxed_str(),
    );
    let backend = spawn_raw_backend_on(backend_port, response_bytes);
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://127.0.0.1:{backend}/;
                    proxy_set_header Host $host;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 302, "{response}");
    let rewritten = header(&response, "Location");
    assert!(!rewritten.contains(&format!("127.0.0.1:{backend}")), "{rewritten}");
    assert!(rewritten.contains("localhost"), "{rewritten}");
    assert!(rewritten.ends_with("/login?next=/x"), "{rewritten}");
}

/// An explicit `proxy_redirect off` keeps the upstream `Location` verbatim.
#[test]
fn proxy_redirect_off_keeps_upstream_location() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_raw_backend(concat!(
        "HTTP/1.1 302 Found\r\n",
        "Location: http://127.0.0.1:9000/keep\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n\r\n",
    ));
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend/;
                    proxy_redirect off;
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
    assert_eq!(status(&response), 302, "{response}");
    assert_eq!(header(&response, "Location"), "http://127.0.0.1:9000/keep");
}

/// `proxy_redirect pattern replacement` applies an explicit rewrite.
#[test]
fn proxy_redirect_rule_replaces_the_pattern() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_raw_backend(concat!(
        "HTTP/1.1 301 Moved Permanently\r\n",
        "Location: http://upstream.internal/a/b\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n\r\n",
    ));
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend/;
                    proxy_redirect http://upstream.internal/ /front/;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /a/b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(header(&response, "Location"), "/front/a/b", "{response}");
}

/// `proxy_cookie_domain`/`proxy_cookie_path`/`proxy_cookie_flags` rewrite `Set-Cookie`.
#[test]
fn proxy_cookie_rewrites_domain_path_and_flags() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_raw_backend(concat!(
        "HTTP/1.1 200 OK\r\n",
        "Set-Cookie: sid=abc; Domain=backend.local; Path=/; HttpOnly\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n\r\n",
    ));
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend/;
                    proxy_cookie_domain backend.local example.com;
                    proxy_cookie_path / /app/;
                    proxy_cookie_flags sid secure samesite=strict;
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
    let cookie = header(&response, "Set-Cookie");
    assert!(cookie.contains("Domain=example.com"), "{cookie}");
    assert!(cookie.contains("Path=/app/"), "{cookie}");
    assert!(cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
}

/// `proxy_method` and `proxy_pass_request_body off` shape the upstream request.
#[test]
fn proxy_method_and_request_body_flags_shape_the_upstream_request() {
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
                location / {{
                    proxy_pass http://backend/;
                    proxy_method DELETE;
                    proxy_pass_request_body off;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "POST /items HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    assert_eq!(status(&response), 200, "{response}");
    let echoed = body(&response);
    assert!(!echoed.contains("content-length"), "{echoed}");
}

/// `proxy_set_body` replaces the request body.
#[test]
fn proxy_set_body_replaces_the_request_body() {
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
                location / {{
                    proxy_pass http://backend/;
                    proxy_set_body "fixed-body";
                    proxy_set_header Content-Length 10;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "POST /x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    let echoed = body(&response);
    assert!(echoed.contains("content-length: 10"), "{echoed}");
}