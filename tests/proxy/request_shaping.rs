//! `proxy_set_header`, `proxy_pass` URI replacement and up-front directive validation.

#[path = "../support/mod.rs"]
mod support;

use support::backend::spawn_echo_backend;
use support::http::{body, request, status};
use support::server::run;
use support::Env;

/// `proxy_set_header` values are evaluated with request variables before the upstream call,
/// and `proxy_pass http://backend/v1/` replaces the matched `/api/` prefix.
#[test]
fn proxy_set_header_evaluates_variables_for_the_upstream() {
    let env = Env::new();
    let backend = spawn_echo_backend();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location /api/ {{
                    proxy_pass http://backend/v1/;
                    proxy_set_header Host $host;
                    proxy_set_header X-Request-Uri $request_uri;
                    proxy_set_header X-Forwarded-Method $request_method;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /api/items?page=2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    let echoed = body(&response);
    assert!(echoed.contains("x-request-uri: /api/items?page=2"), "{echoed}");
    assert!(echoed.contains("x-forwarded-method: get"), "{echoed}");
    assert!(echoed.contains("host: localhost"), "{echoed}");
}

/// An unknown `proxy_*` directive fails `-t` instead of being silently ignored.
#[test]
fn unknown_proxy_directives_are_rejected() {
    let env = Env::new();
    let path = env.path().join("nginx.conf");
    std::fs::write(
        &path,
        r#"
        http {
            server {
                listen 127.0.0.1:18099;
                location / { proxy_pass http://127.0.0.1:9000; proxy_busy_buffers_size_not_a_directive 1; }
            }
        }
        "#,
    )
    .unwrap();
    let output = run(["-c", path.to_str().unwrap(), "-t"]);
    assert!(!output.status.success(), "{output:?}");
    // The anyhow context goes to stderr, the directive error to stderr as well.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = format!("{stdout}{stderr}");
    assert!(
        message.contains("proxy_busy_buffers_size_not_a_directive")
            && message.contains("unknown directive"),
        "{message}"
    );
}
