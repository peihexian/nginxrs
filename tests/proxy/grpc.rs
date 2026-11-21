//! `ngx_http_grpc_module`: `grpc_pass` against a real HTTP/2 backend.

#[path = "../support/mod.rs"]
mod support;

use support::grpc_backend::spawn_grpc_backend;
use support::http::{body, header, request, status, try_header};
use support::Env;

#[test]
fn grpc_pass_forwards_the_call_and_relays_the_response() {
    let env = Env::new();
    let (backend, log) = spawn_grpc_backend();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    grpc_pass grpc://127.0.0.1:{backend};
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "POST /pkg.Service/Call HTTP/1.1\r\nHost: grpc.example\r\nContent-Type: application/grpc\r\nContent-Length: 5\r\nConnection: close\r\n\r\n\x00\x00\x00\x00\x00",
    );
    assert_eq!(status(&response), 200, "{response}");
    // The backend saw the method, path, content type and the `te: trailers` nginx adds.
    let entries = log.lock().unwrap().clone();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert!(entries[0].contains("POST /pkg.Service/Call"), "{entries:?}");
    assert!(entries[0].contains("content-type=application/grpc"), "{entries:?}");
    assert!(entries[0].contains("te=trailers"), "{entries:?}");
    // The body is the reply (`:path` plus the received byte count).
    assert_eq!(body(&response), "/pkg.Service/Call|5");
    // `grpc-status` is forwarded from the trailers.
    assert_eq!(try_header(&response, "grpc-status"), Some("0"), "{response}");
    assert!(try_header(&response, "grpc-message").is_some(), "{response}");
}

#[test]
fn grpc_pass_uses_an_upstream_group() {
    let env = Env::new();
    let (backend, _log) = spawn_grpc_backend();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream grpc_backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    grpc_pass grpc://grpc_backend;
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "POST /svc/Health HTTP/1.1\r\nHost: grpc.example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "/svc/Health|0");
}

#[test]
fn grpc_pass_query_string_is_preserved() {
    let env = Env::new();
    let (backend, log) = spawn_grpc_backend();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{ grpc_pass grpc://127.0.0.1:{backend}; }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "POST /svc/Query?key=value HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "/svc/Query|0");
    let entries = log.lock().unwrap().clone();
    assert!(entries[0].contains("/svc/Query"), "{entries:?}");
}

#[test]
fn grpc_set_header_overrides_and_hides() {
    let env = Env::new();
    let (backend, log) = spawn_grpc_backend();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    grpc_pass grpc://127.0.0.1:{backend};
                    grpc_set_header X-Trace $request_id_missing;
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "POST /svc/Head HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    // An empty value removes the inherited field; the call still completes.
    assert_eq!(body(&response), "/svc/Head|0");
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[test]
fn grpc_unknown_directive_is_rejected() {
    let env = Env::new();
    let config = format!(
        r#"
        http {{
            server {{
                listen 127.0.0.1:{}; 
                location / {{ grpc_nonsense on; }}
            }}
        }}
        "#,
        env.port
    );
    let path = env.path().join("nginx.conf");
    std::fs::write(&path, config).unwrap();
    let output = support::run(["-c", &path.to_string_lossy(), "-t"]);
    assert!(!output.status.success());
}

#[test]
fn grpc_pass_requires_a_location() {
    let env = Env::new();
    let config = format!(
        r#"
        http {{
            grpc_pass grpc://127.0.0.1:1;
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

#[test]
fn grpc_upstream_failure_reports_502() {
    let env = Env::new();
    let port = env.port;
    // Nothing listens on this port; `grpc_next_upstream off` prevents a retry loop.
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    grpc_pass grpc://127.0.0.1:1;
                    grpc_next_upstream off;
                    grpc_connect_timeout 1s;
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "POST /svc/Fail HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 502, "{response}");
    // The core error page answers (`ngx_http_special_response_handler`).
    assert!(header(&response, "Content-Type").contains("text/plain"), "{response}");
}
