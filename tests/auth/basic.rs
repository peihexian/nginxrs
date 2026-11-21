//! `ngx_http_auth_basic_module`: Basic authentication against an htpasswd file.

#[path = "../support/mod.rs"]
mod support;

use base64::Engine as _;
use support::http::{assert_status, body, header, request, status, try_header};
use support::Env;

/// `openssl passwd -apr1 -salt testsalt <password>` for `s3cret`.
const HASH_S3CRET: &str = "$apr1$testsalt$";
const SALT: &str = "testsalt";

/// Compute the `$apr1$` hash with the library so the fixture cannot drift from the code.
fn apr1(password: &str) -> String {
    nginxrs::core::crypt::encrypt_for_test(password.as_bytes(), SALT.as_bytes())
}

fn basic(user: &str, password: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {encoded}")
}

fn fixture(env: &Env) -> String {
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("index.html"), "<h1>protected</h1>").unwrap();
    let htpasswd = env.path().join(".htpasswd");
    std::fs::write(
        &htpasswd,
        format!("# operator accounts\noperator:{}\n", apr1("s3cret")),
    )
    .unwrap();
    htpasswd.to_string_lossy().replace('\\', "/")
}

#[test]
fn missing_credentials_get_a_challenge() {
    let env = Env::new();
    let htpasswd = fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                auth_basic "Admin Area";
                auth_basic_user_file {htpasswd};
                location / {{ }}
            }}
        }}
        "#,
        root = env.path().join("html").to_string_lossy().replace('\\', "/"),
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_status(&response, 401);
    assert_eq!(header(&response, "WWW-Authenticate"), "Basic realm=\"Admin Area\"");
    assert!(!body(&response).contains("protected"), "{response}");
    assert!(body(&response).contains("Unauthorized"), "{response}");
    let _ = HASH_S3CRET;
}

#[test]
fn valid_credentials_serve_the_file() {
    let env = Env::new();
    let htpasswd = fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                auth_basic "Admin Area";
                auth_basic_user_file {htpasswd};
                location / {{ }}
            }}
        }}
        "#,
        root = env.path().join("html").to_string_lossy().replace('\\', "/"),
    );
    let _server = env.start(&config);
    let response = request(
        port,
        &format!(
            "GET /index.html HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nConnection: close\r\n\r\n",
            basic("operator", "s3cret")
        ),
    );
    assert_status(&response, 200);
    assert!(body(&response).contains("protected"), "{response}");
}

#[test]
fn wrong_password_and_unknown_user_are_rejected() {
    let env = Env::new();
    let htpasswd = fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                auth_basic "Admin Area";
                auth_basic_user_file {htpasswd};
                location / {{ }}
            }}
        }}
        "#,
        root = env.path().join("html").to_string_lossy().replace('\\', "/"),
    );
    let _server = env.start(&config);
    for credentials in [basic("operator", "wrong"), basic("stranger", "s3cret")] {
        let response = request(
            port,
            &format!(
                "GET /index.html HTTP/1.1\r\nHost: localhost\r\nAuthorization: {credentials}\r\nConnection: close\r\n\r\n"
            ),
        );
        assert_status(&response, 401);
        assert!(try_header(&response, "WWW-Authenticate").is_some());
    }
}

#[test]
fn auth_basic_off_skips_authentication() {
    let env = Env::new();
    let htpasswd = fixture(&env);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                auth_basic "Admin Area";
                auth_basic_user_file {htpasswd};
                location /secret/ {{ auth_basic off; }}
                location / {{ }}
            }}
        }}
        "#,
        root = env.path().join("html").to_string_lossy().replace('\\', "/"),
    );
    let _server = env.start(&config);
    // `auth_basic off` disables the check for this location only; a location that keeps the
    // server-level setting still challenges.
    let open = request(
        port,
        "GET /secret/index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_ne!(status(&open), 401, "{open}");
    let protected = request(
        port,
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_status(&protected, 401);
}

#[test]
fn a_missing_user_file_answers_403() {
    let env = Env::new();
    let root = env.path().join("html");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("index.html"), "x").unwrap();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                root {root};
                auth_basic "Admin Area";
                auth_basic_user_file {missing};
                location / {{ }}
            }}
        }}
        "#,
        root = root.to_string_lossy().replace('\\', "/"),
        missing = env
            .path()
            .join("does-not-exist")
            .to_string_lossy()
            .replace('\\', "/"),
    );
    let _server = env.start(&config);
    let response = request(
        port,
        &format!(
            "GET /index.html HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nConnection: close\r\n\r\n",
            basic("operator", "s3cret")
        ),
    );
    // `ngx_open_file` fails with ENOENT → 403 (`ngx_http_auth_basic_handler`).
    assert_status(&response, 403);
    assert_eq!(status(&response), 403);
}
