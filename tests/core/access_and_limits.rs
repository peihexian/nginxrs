//! Access control and rate limiting: `ngx_http_access_module`, `limit_req` and `limit_conn`.

#[path = "../support/mod.rs"]
mod support;

use std::time::Duration;

use support::backend::spawn_slow_backend;
use support::http::{assert_response, body, header, request, status};
use support::Env;

/// `deny all` rejects and an allow list admits, evaluated in declaration order.
#[test]
fn access_module_denies_and_allows_by_cidr() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location = /denied {{
                    deny all;
                    return 200 "never";
                }}
                location = /allowed {{
                    deny 203.0.113.0/24;
                    allow all;
                    return 200 "ok";
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);

    let response = request(
        port,
        "GET /denied HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 403);
    let response = request(
        port,
        "GET /allowed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "ok");
}

/// `rate=1r/s burst=1 nodelay`: the first request passes, the burst is drained by the
/// following ones and `$limit_req_status` reports `PASSED` for the accepted request.
#[test]
fn limit_req_rejects_over_rate_and_reports_status() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            limit_req_zone $binary_remote_addr zone=one:1m rate=1r/s;
            server {{
                listen 127.0.0.1:{port};
                location = /limited {{
                    limit_req zone=one burst=1 nodelay;
                    limit_req_status 429;
                    return 200 "$limit_req_status";
                }}
                location = /lua {{
                    content_by_lua_block "ngx.say(ngx.var.limit_req_status or 'unset')";
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);

    let first = request(
        port,
        "GET /limited HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&first, 200, "PASSED");

    let mut rejected = 0;
    for _ in 0..3 {
        let response = request(
            port,
            "GET /limited HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if status(&response) == 429 {
            rejected += 1;
        }
    }
    assert!(
        rejected >= 1,
        "expected at least one 429 after the burst was exhausted"
    );
}

/// `limit_conn addr 1` rejects a second concurrent request while the first is in flight.
#[test]
fn limit_conn_rejects_second_request_while_first_is_in_flight() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            limit_conn_zone $binary_remote_addr zone=addr:1m;
            server {{
                listen 127.0.0.1:{port};
                location = /slow {{
                    limit_conn addr 1;
                    limit_conn_status 429;
                    proxy_pass http://127.0.0.1:{backend};
                }}
            }}
        }}
        "#,
        backend = spawn_slow_backend()
    );
    let _server = env.start(&config);

    let handle = std::thread::spawn(move || {
        request(
            port,
            "GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
    });
    std::thread::sleep(Duration::from_millis(200));
    let second = request(
        port,
        "GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let first = handle.join().unwrap();
    assert_eq!(status(&second), 429, "second request: {second}");
    assert_eq!(status(&first), 200, "first request: {first}");
}

/// `stub_status` keeps the Nginx page layout and `prometheus_metrics` keeps its text format.
#[test]
fn stub_status_and_prometheus_report_counters() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location = /status {{ stub_status; }}
                location = /metrics {{ prometheus_metrics; }}
                location = / {{ return 200 "ok"; }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);

    request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    let status_page = request(
        port,
        "GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&status_page), 200);
    let status_body = body(&status_page);
    assert!(
        status_body.starts_with("Active connections: "),
        "{status_body}"
    );
    assert!(
        status_body.contains("server accepts handled requests"),
        "{status_body}"
    );
    assert!(
        status_body.contains("Reading: 0 Writing: 0 Waiting: 0"),
        "{status_body}"
    );

    let metrics = request(
        port,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&metrics), 200);
    assert!(
        header(&metrics, "Content-Type").starts_with("text/plain"),
        "{metrics}"
    );
    let metrics_body = body(&metrics);
    assert!(metrics_body.contains("# TYPE nginxrs_requests_total counter"));
    assert!(metrics_body.contains("nginxrs_requests_total "));
}
