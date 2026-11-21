//! A configuration with the *shape* of a production deployment loads cleanly.
//!
//! Every value here is a placeholder (`example.test`, `192.0.2.0/24`, `127.0.0.1`): the
//! repository never carries real hostnames, addresses or certificates. The point is the
//! directive mix — the combinations that made `-t` stop on a real configuration — so a
//! regression shows up as this test failing.

#[path = "../support/mod.rs"]
mod support;

use support::backend::spawn_named_backend;
use support::http::{assert_response, request, status};
use support::{Env, config_path};

/// The directive mix of a reverse-proxy vhost: TLS listener, SSI, error pages, aliases,
/// `if`/`set`, proxy tuning, upstream keepalive and a default catch-all server.
fn reverse_proxy_vhost(port: u16, backend: u16) -> String {
    format!(
        r#"
worker_processes 2;
worker_rlimit_nofile 65530;
events {{
    use epoll;
    worker_connections 65530;
}}
http {{
    include mime.types;
    default_type application/octet-stream;
    limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
    server_tokens on;
    sendfile on;
    keepalive_timeout 120;
    keepalive_requests 500;
    client_max_body_size 500M;
    client_header_buffer_size 128k;
    large_client_header_buffers 4 512k;
    proxy_buffer_size 512k;
    proxy_buffers 32 1M;
    proxy_busy_buffers_size 4M;
    proxy_temp_file_write_size 4M;
    server_names_hash_bucket_size 96;
    underscores_in_headers on;
    add_header X-Frame-Options sameorigin;
    log_format main '$remote_addr "$request" $status $body_bytes_sent "$http_referer"';
    access_log off;

    upstream backend_a {{
        server 127.0.0.1:{backend} max_fails=15 fail_timeout=10s;
        keepalive 32;
        keepalive_timeout 30s;
        keepalive_requests 50;
    }}

    server {{
        listen 127.0.0.1:{port} default_server;
        server_name _;
        server_tokens off;
        return 403;
    }}

    server {{
        listen 127.0.0.1:{port};
        server_name app.example.test;
        ssi on;
        ssi_silent_errors on;
        error_page 500 502 504 503 /50.html;
        location /50.html {{ return 200 "maintenance"; }}
        location @router {{
            rewrite /index.php/(.*)/VueMain/ /index.php/$1/VueMain/ last;
        }}
        location /static/ {{
            root html;
            expires 30d;
            add_header Cache-Control "public, max-age=2592000, immutable";
            access_log off;
        }}
        set $backend "";
        if ($remote_addr = "127.0.0.1") {{
            set $backend http://backend_a/lm;
        }}
        location / {{
            proxy_connect_timeout 360s;
            proxy_read_timeout 600s;
            proxy_send_timeout 600s;
            proxy_buffer_size 64k;
            proxy_buffers 4 64k;
            proxy_busy_buffers_size 128k;
            proxy_temp_file_write_size 128k;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_buffering off;
            proxy_pass http://backend_a;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_ssl_session_reuse on;
        }}
    }}
}}
"#
    )
}

#[test]
fn production_shaped_config_loads_and_serves() {
    let env = Env::new();
    let backend = spawn_named_backend("vhost");
    let config = reverse_proxy_vhost(env.port, backend);
    std::fs::write(env.path().join("mime.types"), MIME_TYPES).unwrap();
    let path = env.path().join("nginx.conf");
    std::fs::write(&path, &config).unwrap();

    // `-t` must accept the whole mix (this is what stopped on real configurations).
    let check = support::run(["-c", &path.to_string_lossy(), "-t"]);
    assert!(
        check.status.success(),
        "-t rejected the configuration:\n{}",
        String::from_utf8_lossy(&check.stderr)
    );

    let _server = env.start(&config);
    let response = request(
        env.port,
        "GET /hello HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    // A `$backend` chosen by `if` and used as `proxy_pass $backend` answers from the group.
    assert!(support::http::body(&response).contains("vhost"), "{response}");
}

/// Unknown directives are still rejected, so the acceptance above is not blanket.
#[test]
fn unknown_directives_are_still_errors() {
    let env = Env::new();
    let config = format!(
        r#"
        http {{
            server {{
                listen 127.0.0.1:{port};
                made_up_directive on;
            }}
        }}
        "#,
        port = env.port
    );
    let path = env.path().join("nginx.conf");
    std::fs::write(&path, config).unwrap();
    let check = support::run(["-c", &path.to_string_lossy(), "-t"]);
    assert!(!check.status.success());
    let stderr = String::from_utf8_lossy(&check.stderr);
    assert!(stderr.contains("made_up_directive"), "{stderr}");
}

#[test]
fn config_path_helper_is_portable() {
    let env = Env::new();
    assert!(config_path(&env.path().join("nginx.conf")).contains('/'));
}

/// A minimal `mime.types` so the fixture does not depend on the machine.
const MIME_TYPES: &str = r#"
types {
    text/html                             html htm shtml;
    text/css                              css;
    text/plain                            txt;
    application/javascript                js;
    image/png                             png;
    image/svg+xml                         svg svgz;
    application/octet-stream              bin;
}
"#;
