//! TLS listeners: handshake, `$ssl_*` variables and SNI certificate selection.

#[path = "../support/mod.rs"]
mod support;

use support::client::{https_get, https_get_any};
use support::http::{body, status};
use support::{Certificates, Env, config_path};

/// A real HTTPS handshake serves the protected location.
#[test]
fn ssl_listener_serves_https() {
    let env = Env::new();
    let certs = Certificates::new(env.path());
    let Some(certificate) = certs.self_signed_or_skip("ssl_listener_serves_https", "cert", "localhost")
    else {
        return;
    };
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                {certificate}
                ssl_protocols TLSv1.2 TLSv1.3;
                location = /secure {{ return 200 "tls-ok"; }}
            }}
        }}
        "#,
        certificate = certificate.directive(),
    );
    let _server = env.start(&config);

    let response = https_get_any("localhost", port, "/secure");
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "tls-ok");
}

/// `$ssl_*` variables report the negotiated connection, as `ngx_http_ssl_variable` does.
#[test]
fn ssl_variables_report_the_negotiated_connection() {
    let env = Env::new();
    let certs = Certificates::new(env.path());
    let Some((cert, key)) = certs.self_signed("server", "localhost") else {
        eprintln!(
            "skipping ssl_variables_report_the_negotiated_connection: openssl is unavailable"
        );
        return;
    };
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                ssl_protocols TLSv1.2 TLSv1.3;
                ssl_verify_client off;
                location = /vars {{
                    return 200 "$ssl_protocol|$ssl_cipher|$ssl_server_name|$ssl_client_verify|$https";
                }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = env.start(&config);

    let response = https_get("localhost", port, "/vars", vec![cert.clone()]);
    assert_eq!(status(&response), 200, "{response}");
    let reported = body(&response);
    let fields: Vec<&str> = reported.split('|').collect();
    assert!(
        matches!(fields[0], "TLSv1.2" | "TLSv1.3"),
        "unexpected protocol in {reported}"
    );
    assert!(!fields[1].is_empty(), "no cipher in {reported}");
    assert_eq!(fields[2], "localhost", "SNI is not reported: {reported}");
    assert_eq!(fields[3], "NONE", "no client certificate was requested");
    assert_eq!(fields[4], "on");
}

/// `ssl_certificate` in a second server is selected by SNI (`ngx_http_ssl_servername`).
#[test]
fn sni_selects_the_certificate_of_the_matching_server() {
    let env = Env::new();
    let certs = Certificates::new(env.path());
    let Some((first_cert, first_key)) = certs.self_signed("first", "first.test") else {
        eprintln!("skipping sni_selects_the_certificate_of_the_matching_server: openssl is unavailable");
        return;
    };
    let Some((second_cert, second_key)) = certs.self_signed("second", "second.test") else {
        return;
    };
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl default_server;
                server_name first.test;
                ssl_certificate {first_cert};
                ssl_certificate_key {first_key};
                location / {{ return 200 "first"; }}
            }}
            server {{
                listen 127.0.0.1:{port} ssl;
                server_name second.test;
                ssl_certificate {second_cert};
                ssl_certificate_key {second_key};
                location / {{ return 200 "second"; }}
            }}
        }}
        "#,
        first_cert = config_path(&first_cert),
        first_key = config_path(&first_key),
        second_cert = config_path(&second_cert),
        second_key = config_path(&second_key),
    );
    let _server = env.start(&config);

    // `second.test` only verifies with the second certificate installed for that name.
    let response = https_get("second.test", port, "/", vec![second_cert.clone()]);
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "second");

    let response = https_get("first.test", port, "/", vec![first_cert.clone()]);
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "first");
}
