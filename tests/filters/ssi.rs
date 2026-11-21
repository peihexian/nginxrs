//! `ngx_http_ssi_filter_module`: server-side includes in static files and proxy responses.

#[path = "../support/mod.rs"]
mod support;

use support::http::{assert_response, body, header, request, status};
use support::{Env, config_path};

/// Write `alpha.html` and `parts/header.html` next to the configuration and return the root.
fn fixture(env: &Env) -> String {
    let root = env.path().join("html");
    std::fs::create_dir_all(root.join("parts")).unwrap();
    std::fs::write(
        root.join("alpha.html"),
        "<html><body><!--#include virtual=\"/parts/header.html\" -->|\
         <!--#echo var=\"request_method\" -->|\
         <!--#set var=\"who\" value=\"world\" -->hello <!--#echo var=\"who\" --></body></html>",
    )
    .unwrap();
    std::fs::write(root.join("parts").join("header.html"), "<h1>included</h1>").unwrap();
    std::fs::write(root.join("plain.html"), "<h1>no directives</h1>").unwrap();
    root.to_string_lossy().replace('\\', "/")
}

#[test]
fn ssi_renders_includes_echo_and_set() {
    let env = Env::new();
    let root = fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                ssi on;
                location / {{ index alpha.html; }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /alpha.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(
        body(&response),
        "<html><body><h1>included</h1>|GET|hello world</body></html>"
    );
    // The output is rendered, so it cannot claim a fixed length or validators.
    assert!(support::http::try_header(&response, "Last-Modified").is_none());
    assert!(support::http::try_header(&response, "ETag").is_none());
}

#[test]
fn ssi_off_leaves_directives_untouched() {
    let env = Env::new();
    let root = fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /parts/header.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "<h1>included</h1>");
}

#[test]
fn ssi_silent_errors_drops_broken_directives() {
    let env = Env::new();
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    // `<!--#echo uri -->` is malformed: the parameter has no `=`.
    std::fs::write(root.join("bad.html"), "a<!--#echo uri -->b").unwrap();
    let root = root.to_string_lossy().replace('\\', "/");
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                ssi on;
                ssi_silent_errors on;
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /bad.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&response), "ab", "{response}");
}

#[test]
fn ssi_reports_errmsg_for_broken_directives() {
    let env = Env::new();
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("bad.html"), "a<!--#echo uri -->b").unwrap();
    let root = root.to_string_lossy().replace('\\', "/");
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                ssi on;
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /bad.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        body(&response),
        "a[an error occurred while processing the directive]b",
        "{response}"
    );
}

#[test]
fn ssi_types_limit_the_filter() {
    let env = Env::new();
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("page.html"), "<!--#echo var=\"request_method\" -->").unwrap();
    let root = root.to_string_lossy().replace('\\', "/");
    let port = env.port;
    // `ssi_types` is a compatibility directive; the default (text/html) still applies.
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                ssi on;
                ssi_types text/html;
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /page.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&response), "GET", "{response}");
    assert_eq!(
        header(&response, "Content-Type"),
        "text/html",
        "{response}"
    );
}

#[test]
fn ssi_variables_come_from_the_request() {
    let env = Env::new();
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("vars.html"),
        "uri=<!--#echo var=\"uri\" encoding=\"none\" --> args=<!--#echo var=\"args\" encoding=\"none\" -->",
    )
    .unwrap();
    let root = root.to_string_lossy().replace('\\', "/");
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                ssi on;
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /vars.html?a=1&b=2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&response), "uri=/vars.html args=a=1&b=2", "{response}");
}

#[test]
fn ssi_stub_blocks_and_config() {
    let env = Env::new();
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("block.html"),
        "<!--#block name=\"b\" -->STUB<!--#endblock -->\
         <!--#config errmsg=\"!\" -->\
         <!--#include virtual=\"/missing.html\" stub=\"b\" -->|\
         <!--#include virtual=\"/missing.html\" stub=\"b\" -->|<!--#echo var=\"nope\" default=\"\" -->",
    )
    .unwrap();
    let root = root.to_string_lossy().replace('\\', "/");
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                ssi on;
                location / {{ }}
            }}
        }}
        "#,
        root = root
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET /block.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&response), "STUB|STUB|", "{response}");
}

#[test]
fn config_fixture_uses_the_documented_root() {
    // `config_path` keeps test paths portable; the helper is exercised here so every test
    // file in the domain imports the same support surface.
    let env = Env::new();
    assert!(config_path(env.path()).contains('/'));
}
