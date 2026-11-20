//! `proxy_buffering`, the buffer directives and temp-file spooling.

#[path = "../support/mod.rs"]
mod support;

use support::backend::spawn_sized_backend;
use support::http::{body, request, status};
use support::{Env, config_path};

/// A response larger than `proxy_buffers * proxy_buffer_size` still reaches the client
/// intact, with the overflow spooled through `proxy_temp_path`.
#[test]
fn proxy_buffering_spools_large_responses_to_the_temp_path() {
    let env = Env::new();
    let temp_path = env.path().join("proxy_temp");
    let port = env.port;
    let backend = spawn_sized_backend(200_000);
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_buffering on;
                    proxy_buffers 2 1024;
                    proxy_buffer_size 1024;
                    proxy_busy_buffers_size 4096;
                    proxy_max_temp_file_size 10m;
                    proxy_temp_path {temp_path};
                }}
            }}
        }}
        "#,
        temp_path = config_path(&temp_path),
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /big HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response).len(), 200_000, "the body must not be truncated");
    assert!(
        body(&response).bytes().all(|byte| byte == b'x'),
        "the buffered body must be forwarded verbatim"
    );
}

/// `proxy_buffering off` forwards the body as well, without a temp file.
#[test]
fn proxy_buffering_off_streams_the_response() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_sized_backend(50_000);
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_buffering off;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /big HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response).len(), 50_000);
}

/// `proxy_max_temp_file_size 0` disables spooling: the body still arrives complete.
#[test]
fn proxy_max_temp_file_size_zero_still_serves_the_body() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_sized_backend(120_000);
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_buffers 2 1024;
                    proxy_max_temp_file_size 0;
                    proxy_temp_path {temp_dir};
                }}
            }}
        }}
        "#,
        temp_dir = config_path(&env.path().join("proxy_temp")),
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /big HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response).len(), 120_000);
}

/// `proxy_buffers` needs two entries; a single one fails `-t`.
#[test]
fn proxy_buffers_requires_two_buffers() {
    use support::server::run;
    let env = Env::new();
    let path = env.path().join("nginx.conf");
    std::fs::write(
        &path,
        r#"
        http {
            server {
                listen 127.0.0.1:18098;
                location / {
                    proxy_pass http://127.0.0.1:9000;
                    proxy_buffers 1 4096;
                }
            }
        }
        "#,
    )
    .unwrap();
    let output = run(["-c", path.to_str().unwrap(), "-t"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("at least 2") && stderr.contains("proxy_buffers"),
        "{stderr}"
    );
}
