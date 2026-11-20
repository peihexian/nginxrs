//! `ngx_http_realip_module`: rewriting the client address from a trusted proxy header.

#[path = "../support/mod.rs"]
mod support;

use support::backend::spawn_echo_backend;
use support::http::{assert_response, body, request, status};
use support::Env;

/// With a trusted proxy and `real_ip_recursive on`, the right-most trusted hop is skipped and
/// the first untrusted address becomes `$remote_addr`; the peer stays in
/// `$realip_remote_addr` and both reach the upstream through `proxy_set_header`.
#[test]
fn realip_rewrites_client_address_for_variables_and_upstream() {
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
                set_real_ip_from 127.0.0.0/8;
                real_ip_header X-Forwarded-For;
                real_ip_recursive on;
                location = /client {{
                    content_by_lua_block "ngx.say(ngx.var.remote_addr .. ' ' .. ngx.var.realip_remote_addr)";
                }}
                location /api/ {{
                    proxy_pass http://backend;
                    proxy_set_header Host $host;
                    proxy_set_header X-Real-IP $remote_addr;
                    proxy_set_header X-Origin $realip_remote_addr;
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);

    let response = request(
        port,
        "GET /client HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.9, 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "203.0.113.9 127.0.0.1\n");

    let response = request(
        port,
        "GET /api/echo HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.9, 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200);
    let echoed = body(&response);
    assert!(echoed.contains("x-real-ip: 203.0.113.9"), "{echoed}");
    assert!(echoed.contains("x-origin: 127.0.0.1"), "{echoed}");
}

/// Without `set_real_ip_from` the header is ignored and the peer address is kept.
#[test]
fn realip_is_ignored_without_trusted_sources() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location = /client {{
                    content_by_lua_block "ngx.say(ngx.var.remote_addr)";
                }}
            }}
        }}
        "#
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /client HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 203.0.113.9\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "127.0.0.1\n");
}
