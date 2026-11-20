//! `error_page` and `proxy_intercept_errors`.

#[path = "../support/mod.rs"]
mod support;

use support::backend::spawn_raw_backend;
use support::http::{body, request, status};
use support::Env;

const UPSTREAM_404: &str = concat!(
    "HTTP/1.1 404 Not Found\r\n",
    "Content-Type: text/plain\r\n",
    "Content-Length: 8\r\n",
    "Connection: close\r\n\r\nupstream",
);

/// `proxy_intercept_errors on` hands upstream error responses to `error_page`.
#[test]
fn proxy_intercept_errors_uses_the_error_page() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_raw_backend(UPSTREAM_404);
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                error_page 404 /custom-404;
                location / {{
                    proxy_pass http://backend;
                    proxy_intercept_errors on;
                    proxy_set_header Host $host;
                }}
                location = /custom-404 {{
                    return 404 "intercepted";
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 404, "{response}");
    assert_eq!(
        body(&response),
        "intercepted",
        "the error_page body must replace the upstream one: {response}"
    );
}

/// Without `proxy_intercept_errors` the upstream error body reaches the client unchanged.
#[test]
fn proxy_without_intercept_errors_passes_the_upstream_body() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_raw_backend(UPSTREAM_404);
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                error_page 404 /custom-404;
                location / {{
                    proxy_pass http://backend;
                    proxy_set_header Host $host;
                }}
                location = /custom-404 {{ return 404 "intercepted"; }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 404, "{response}");
    assert_eq!(body(&response), "upstream", "{response}");
}

/// `error_page` also applies to a locally generated 404.
#[test]
fn error_page_serves_a_local_404() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                error_page 404 /not-here;
                location / {{ }}
                location = /not-here {{ return 404 "custom page"; }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 404, "{response}");
    assert_eq!(body(&response), "custom page", "{response}");
}
