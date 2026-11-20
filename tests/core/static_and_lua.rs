//! `ngx_http_core_module` and `ngx_http_static_module`: static files, Range, MIME types,
//! `index`, `try_files`, rewrites, Lua content handlers and `upstream` load balancing.

#[path = "../support/mod.rs"]
mod support;

use support::backend::spawn_named_backend;
use support::http::{assert_response, body, header, request, status};
use support::{Env, config_path};

/// Static files, Range/HEAD, HLS MIME types, rewrites, Lua and load balancing over two
/// backends, all in one realistic server block.
#[test]
fn serves_static_proxy_rewrite_lua_and_load_balancing() {
    let env = Env::new();
    let www = env.path().join("www");
    std::fs::create_dir_all(www.join("media")).unwrap();
    std::fs::write(www.join("index.html"), "hello nginxrs").unwrap();
    std::fs::write(www.join("media/movie.bin"), b"0123456789").unwrap();
    std::fs::write(
        www.join("media/live.m3u8"),
        "#EXTM3U\n#EXTINF:4,\nsegment0.ts\n",
    )
    .unwrap();

    let backend1 = spawn_named_backend("one");
    let backend2 = spawn_named_backend("two");
    let port = env.port;
    let config = format!(
        r#"
        worker_processes 2;
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{backend1};
                server 127.0.0.1:{backend2};
            }}
            server {{
                listen 127.0.0.1:{port};
                server_name localhost;
                root {root};
                index index.html;
                location = /lua {{
                    add_header X-Content-Config yes;
                    header_filter_by_lua_block "ngx.header['X-Lua-Filter']='yes'";
                    content_by_lua_block "ngx.header['X-Lua']='yes'; ngx.say('lua:' .. ngx.var.uri)";
                }}
                location /api/ {{
                    proxy_pass http://backend;
                    proxy_set_header Host $host;
                    proxy_next_upstream_tries 2;
                }}
                location /old/ {{ rewrite ^/old/(.*)$ /media/$1 permanent; }}
                location /media/ {{
                    add_header X-Media yes;
                    header_filter_by_lua_block "ngx.header['X-Lua-Filter']='yes'";
                }}
                location / {{ try_files $uri $uri/ =404; }}
            }}
        }}
        "#,
        root = config_path(&www),
    );
    let _server = env.start(&config);

    let response = request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "hello nginxrs");
    assert!(header(&response, "Content-Type").starts_with("text/html"));

    let response = request(
        port,
        "GET /media/movie.bin HTTP/1.1\r\nHost: localhost\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 206, "2345");
    assert_eq!(header(&response, "Content-Range"), "bytes 2-5/10");
    assert_eq!(header(&response, "X-Media"), "yes");
    assert_eq!(header(&response, "X-Lua-Filter"), "yes");

    let response = request(
        port,
        "HEAD /media/movie.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200);
    assert_eq!(header(&response, "Content-Length"), "10");
    assert!(body(&response).is_empty());

    let response = request(
        port,
        "GET /media/live.m3u8 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200);
    assert_eq!(
        header(&response, "Content-Type"),
        "application/vnd.apple.mpegurl"
    );

    let response = request(
        port,
        "GET /old/movie.bin?download=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 301);
    assert_eq!(header(&response, "Location"), "/media/movie.bin?download=1");

    let response = request(
        port,
        "GET /lua HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "lua:/lua\n");
    assert_eq!(header(&response, "X-Lua"), "yes");
    assert_eq!(header(&response, "X-Content-Config"), "yes");
    assert_eq!(header(&response, "X-Lua-Filter"), "yes");

    let mut backends = std::collections::HashSet::new();
    for _ in 0..6 {
        let response = request(
            port,
            "GET /api/test?x=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status(&response), 200);
        let response_body = body(&response);
        assert!(
            response_body.contains("path=/api/test?x=1"),
            "{response_body}"
        );
        assert!(response_body.contains("host=localhost"), "{response_body}");
        backends.insert(response_body.split(' ').next().unwrap().to_string());
    }
    assert_eq!(backends.len(), 2, "both backends should receive traffic");

    let response = request(
        port,
        "GET /%2e%2e/secret HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(matches!(status(&response), 400 | 403 | 404));
}
