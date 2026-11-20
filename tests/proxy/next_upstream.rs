//! `proxy_next_upstream` retry semantics: which failures retry, how many attempts, and when
//! a non-idempotent request may be retried.

#[path = "../support/mod.rs"]
mod support;

use support::backend::spawn_raw_backend;
use support::http::{body, request, status};
use support::{Env, free_port};

const UNAVAILABLE: &str = concat!(
    "HTTP/1.1 503 Service Unavailable\r\n",
    "Content-Length: 0\r\n",
    "Connection: close\r\n\r\n",
);
const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

fn get(port: u16) -> String {
    request(
        port,
        "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
}

/// A two-peer upstream where the first peer always answers 503 and the second answers 200.
fn failing_then_healthy() -> (u16, u16) {
    let failing = spawn_raw_backend(UNAVAILABLE);
    let healthy = spawn_raw_backend(
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
    );
    (failing, healthy)
}

/// `proxy_next_upstream http_503` retries the request on the next backend.
#[test]
fn proxy_next_upstream_retries_on_configured_status() {
    let (failing, healthy) = failing_then_healthy();
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{failing};
                server 127.0.0.1:{healthy};
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_next_upstream error timeout http_503;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    // The balancer round-robins; whichever backend comes first, a 503 must be retried, so
    // every request ends up served by the healthy peer.
    for _ in 0..4 {
        let response = get(port);
        assert_eq!(status(&response), 200, "{response}");
        assert_eq!(body(&response), "second", "{response}");
    }
}

/// Without `http_503` in `proxy_next_upstream` the 503 reaches the client unchanged.
#[test]
fn proxy_next_upstream_default_does_not_retry_on_status() {
    let (failing, healthy) = failing_then_healthy();
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{failing};
                server 127.0.0.1:{healthy};
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ proxy_pass http://backend; }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    // Round robin alternates, so among four requests at least one hits the failing peer and
    // must surface its 503 (the default is `error timeout`, which excludes http_503).
    let mut saw_503 = false;
    for _ in 0..4 {
        if status(&get(port)) == 503 {
            saw_503 = true;
        }
    }
    assert!(saw_503, "the default configuration must not retry a 503");
}

/// A connection-level failure is retried by default (`error` is in the default set).
#[test]
fn proxy_next_upstream_retries_connection_errors_by_default() {
    let dead = free_port();
    let healthy = spawn_raw_backend(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nalive",
    );
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{dead};
                server 127.0.0.1:{healthy};
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ proxy_pass http://backend; }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    for _ in 0..4 {
        let response = get(port);
        assert_eq!(status(&response), 200, "{response}");
        assert_eq!(body(&response), "alive", "{response}");
    }
}

/// `proxy_next_upstream off` disables retrying even for connection failures.
#[test]
fn proxy_next_upstream_off_disables_retries() {
    let dead = free_port();
    let healthy = spawn_raw_backend(OK);
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{dead};
                server 127.0.0.1:{healthy};
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_next_upstream off;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let mut saw_failure = false;
    for _ in 0..4 {
        if status(&get(port)) >= 500 {
            saw_failure = true;
        }
    }
    assert!(saw_failure, "`proxy_next_upstream off` must not retry");
}

/// `proxy_next_upstream_tries 1` bounds the attempts: one peer only.
#[test]
fn proxy_next_upstream_tries_limits_attempts() {
    let dead = free_port();
    let healthy = spawn_raw_backend(OK);
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{dead};
                server 127.0.0.1:{healthy};
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_next_upstream_tries 1;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let mut failures = 0;
    for _ in 0..4 {
        if status(&get(port)) >= 500 {
            failures += 1;
        }
    }
    assert!(failures > 0, "a single try must fail when it hits the dead peer");
}

/// A status retry is not attempted for a non-idempotent method unless `non_idempotent` is
/// listed, so the upstream status reaches the client.
#[test]
fn proxy_next_upstream_requires_non_idempotent_for_post() {
    let failing = spawn_raw_backend(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{failing}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_next_upstream error http_500;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "POST /item HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        status(&response),
        500,
        "the single peer's status must reach the client: {response}"
    );
}
