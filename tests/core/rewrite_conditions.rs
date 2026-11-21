//! `if` conditions and `set` (`ngx_http_rewrite_module`).

#[path = "../support/mod.rs"]
mod support;

use support::backend::spawn_named_backend;
use support::http::{assert_response, body, request, status};
use support::Env;

/// A `set` variable chosen by an `if` on the client address picks the upstream, which is the
/// shape real configurations use to divert a single operator to a maintenance copy.
#[test]
fn if_selects_a_proxy_target() {
    let env = Env::new();
    let port = env.port;
    let backend = spawn_named_backend("chosen");
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream chosen {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                set $backend "";
                if ($remote_addr = "127.0.0.1") {{
                    set $backend http://chosen;
                }}
                location / {{
                    if ($backend) {{
                        proxy_pass $backend;
                    }}
                    proxy_pass http://chosen;
                    proxy_set_header Host $host;
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    // `$backend` is set for this peer, and the location-level `proxy_pass $backend` is the
    // one that answers (the plain `if` block has no content handler here).
    let response = request(
        port,
        "GET /here HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert!(body(&response).contains("chosen path=/here"), "{response}");
}

#[test]
fn if_regex_rewrites_a_uri() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    if ($request_uri ~* "^/index\\.php/site/page") {{
                        rewrite ^(.*)$ /rewritten last;
                    }}
                    return 200 "original";
                }}
                location = /rewritten {{
                    return 200 "rewritten";
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /index.php/site/page/1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "rewritten");
    let response = request(
        port,
        "GET /other HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "original");
}

#[test]
fn if_not_equal_and_else_branch() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    set $flag no;
                    if ($flag != yes) {{
                        set $flag changed;
                    }}
                    return 200 "$flag";
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_response(&response, 200, "changed");
}

#[test]
fn if_file_test_and_break() {
    let env = Env::new();
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("present.html"), "present file").unwrap();
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
                    if (-f $document_root$uri) {{
                        set $exists yes;
                    }}
                    if (!-f $document_root$uri) {{
                        set $exists no;
                    }}
                    return 200 "$exists";
                }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /present.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "no");
}

#[test]
fn if_rejects_invalid_conditions_at_load_time() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    if ($host ?? something) {{ return 403; }}
                    return 200;
                }}
            }}
        }}
        "#,
    );
    let path = env.path().join("invalid.conf");
    std::fs::write(&path, config).unwrap();
    let output = support::run(["-c", &path.to_string_lossy(), "-t"]);
    assert!(!output.status.success(), "{output:?}");
}
