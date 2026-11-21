//! `ngx_http_geo_module`: address → value variables.

#[path = "../support/mod.rs"]
mod support;

use support::http::{assert_response, body, request, status};
use support::Env;

#[test]
fn geo_cidr_variable_classifies_the_client() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            geo $country {{
                default       ZZ;
                127.0.0.1/32  localhost;
                10.0.0.0/8    EU;
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "$country"; }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_response(&response, 200, "localhost");
}

#[test]
fn geo_ranges_and_trusted_proxy() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            geo $zone {{
                ranges;
                proxy 127.0.0.0/8;
                default                    outside;
                203.0.113.0-203.0.113.255  office;
                198.51.100.0-198.51.100.255 lab;
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "$zone"; }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.7\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "office");
    let response = request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 198.51.100.9\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "lab");
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_response(&response, 200, "outside");
}

#[test]
fn geo_source_variable_and_recursive_proxy() {
    let env = Env::new();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            geo $city $http_x_city {{
                default        unknown;
                10.1.0.0/16    Beijing;
                10.2.0.0/16    Shanghai;
            }}
            geo $hop {{
                proxy 127.0.0.0/8;
                proxy_recursive;
                default         far;
                192.0.2.0/24    near;
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "$city/$hop"; }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-City: 10.1.2.3\r\nX-Forwarded-For: 192.0.2.5, 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "Beijing/near");
    let response = request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-City: 203.0.113.1\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "unknown/far");
}

#[test]
fn geo_include_and_volatile() {
    let env = Env::new();
    let networks = env.path().join("networks.conf");
    std::fs::write(&networks, "10.0.0.0/8 EU;\n192.0.2.0/24 TEST;\n").unwrap();
    let networks = networks.to_string_lossy().replace('\\', "/");
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            geo $geo_code {{
                volatile;
                include {networks};
                default ZZ;
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "$geo_code"; }}
            }}
        }}
        "#,
    );
    let path = env.path().join("nginx.conf");
    std::fs::write(&path, &config).unwrap();
    let check = support::run(["-c", &path.to_string_lossy(), "-t"]);
    assert!(
        check.status.success(),
        "{:?}",
        String::from_utf8_lossy(&check.stderr)
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_response(&response, 200, "EU");
}

#[test]
fn geo_rejects_invalid_entries() {
    let env = Env::new();
    for source in [
        "geo $g { 10.0.0.0/33 EU; }",
        "geo $g { ranges; 10.0.1.0-10.0.0.0 EU; }",
        "geo $g { 10.0.0.0/8 EU; ranges; }",
        "geo g { default ZZ; }",
    ] {
        let config = format!(
            "http {{ {source} server {{ listen 127.0.0.1:{}; location / {{ return 200; }} }} }}",
            env.port
        );
        let path = env.path().join("invalid.conf");
        std::fs::write(&path, config).unwrap();
        let output = support::run(["-c", &path.to_string_lossy(), "-t"]);
        assert!(
            !output.status.success(),
            "{source} must be rejected: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
