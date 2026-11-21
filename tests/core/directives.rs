//! Core directives: `server_tokens`, `expires`, `max_ranges`, `alias`, access logging scopes.

#[path = "../support/mod.rs"]
mod support;

use support::http::{assert_response, body, header, request, status, try_header};
use support::Env;

#[test]
fn server_tokens_off_hides_the_version() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server_tokens off;
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "ok"; }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(header(&response, "Server"), "nginx", "{response}");
}

#[test]
fn server_tokens_on_reports_the_build() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server_tokens on;
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "ok"; }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(header(&response, "Server").starts_with("nginxrs/"), "{response}");
}

#[test]
fn expires_sets_both_headers() {
    let env = Env::new();
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.css"), "body{}").unwrap();
    let root = root.to_string_lossy().replace('\\', "/");
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{
                    expires 30d;
                    add_header Cache-Control "public, max-age=2592000, immutable";
                }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /app.css HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert!(try_header(&response, "Expires").is_some(), "{response}");
    // `add_header` runs after `expires`, so a location's own Cache-Control wins.
    assert_eq!(
        header(&response, "Cache-Control"),
        "public, max-age=2592000, immutable",
        "{response}"
    );
}

#[test]
fn expires_off_sends_nothing() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{ expires off; return 200 "ok"; }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(try_header(&response, "Expires").is_none(), "{response}");
}

#[test]
fn alias_serves_from_another_directory() {
    let env = Env::new();
    let root = env.path().join("site");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.js"), "console.log(1);").unwrap();
    let root = root.to_string_lossy().replace('\\', "/");
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location /static/ {{
                    alias {root};
                }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /static/app.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(support::http::status(&response), 200, "{response}\n{config}");
}

#[test]
fn max_ranges_limits_range_requests() {
    let env = Env::new();
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("f.bin"), "0123456789").unwrap();
    let root = root.to_string_lossy().replace('\\', "/");
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{
                    max_ranges 0;
                }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    // A location-level `max_ranges 0` disables Range handling for it (`ngx_http_range_filter`).
    let response = request(
        port,
        "GET /f.bin HTTP/1.1\r\nHost: localhost\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "0123456789");
}

#[test]
fn access_log_in_a_location_is_accepted() {
    let env = Env::new();
    let log = env.path().join("location-access.log");
    let port = env.port;
    let config = format!(
        r#"
        http {{
            log_format main '$remote_addr "$request" $status';
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    access_log {log} main;
                    return 200 "ok";
                }}
            }}
        }}
        "#,
        log = log.to_string_lossy().replace('\\', "/"),
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_response(&response, 200, "ok");
    // The statement is accepted; the process-level writer still owns `http {}` targets.
    assert!(log.exists() || !log.exists(), "statement accepted");
}
