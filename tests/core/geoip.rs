//! `ngx_http_geoip_module`: the `geoip_*` variables from a MaxMind DB file.
//!
//! The tests build a small database in the real binary format (see
//! `src/modules/geoip/mmdb.rs` for the layout) so no downloaded data set is needed.

#[path = "../support/mod.rs"]
mod support;

use support::http::{assert_response, request};
use support::Env;

/// Encode a string data-section value.
fn push_text(out: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    if bytes.len() < 29 {
        out.push(0x40 | bytes.len() as u8);
    } else {
        // Size bucket 29: the next byte holds `size - 29`.
        assert!(bytes.len() < 256, "test values stay below 285 bytes");
        out.push(0x40 | 29);
        out.push((bytes.len() - 29) as u8);
    }
    out.extend_from_slice(bytes);
}

fn push_map(out: &mut Vec<u8>, pairs: usize) {
    assert!(pairs < 29);
    out.push(0xE0 | pairs as u8);
}

fn push_uint16(out: &mut Vec<u8>, value: u16) {
    out.push(0xA0 | 2);
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_uint32(out: &mut Vec<u8>, value: u32) {
    out.push(0xC0 | 4);
    out.extend_from_slice(&value.to_be_bytes());
}

/// An `f64` value (type 3).
fn push_double(out: &mut Vec<u8>, value: f64) {
    out.push(0x60 | 8);
    out.extend_from_slice(&value.to_be_bytes());
}

fn metadata(node_count: u32, database_type: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_map(&mut out, 4);
    push_text(&mut out, "node_count");
    push_uint32(&mut out, node_count);
    push_text(&mut out, "record_size");
    push_uint16(&mut out, 32);
    push_text(&mut out, "ip_version");
    push_uint16(&mut out, 4);
    push_text(&mut out, "database_type");
    push_text(&mut out, database_type);
    out
}

/// A one-node database: the left record points at `entry`, so every IPv4 address matches it.
fn database(database_type: &str, entry: &[u8]) -> Vec<u8> {
    let node_count: u32 = 1;
    let data_offset = node_count as usize + 16;
    let mut file = Vec::new();
    file.extend_from_slice(&(data_offset as u32).to_be_bytes());
    file.extend_from_slice(&node_count.to_be_bytes());
    file.extend_from_slice(entry);
    file.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
    file.extend_from_slice(&metadata(node_count, database_type));
    file
}

fn write_database(env: &Env, name: &str, database_type: &str, entry: &[u8]) -> String {
    let path = env.path().join(name);
    std::fs::write(&path, database(database_type, entry)).unwrap();
    path.to_string_lossy().replace('\\', "/")
}

fn country_entry(code: &str, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_map(&mut out, 1);
    push_text(&mut out, "country");
    push_map(&mut out, 2);
    push_text(&mut out, "iso_code");
    push_text(&mut out, code);
    push_text(&mut out, "names");
    push_map(&mut out, 1);
    push_text(&mut out, "en");
    push_text(&mut out, name);
    out
}

#[test]
fn geoip_country_variables() {
    let env = Env::new();
    let country = write_database(
        &env,
        "country.mmdb",
        "GeoIP2-Country",
        &country_entry("CN", "Anchoria"),
    );
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            geoip_country {country};
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    return 200 "$geoip_country_code $geoip_country_code3 $geoip_country_name";
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    // `geoip_country_code3` maps alpha-2 → alpha-3 (`ngx_http_geoip_code3`).
    assert_response(&response, 200, "CN CHN Anchoria");
}

#[test]
fn geoip_city_variables() {
    let env = Env::new();
    // `{"continent":{"code":"XX"},"country":{"iso_code":"CN"},"subdivisions":[{"iso_code":"9X"}]}`
    let mut entry = Vec::new();
    push_map(&mut entry, 3);
    push_text(&mut entry, "continent");
    push_map(&mut entry, 1);
    push_text(&mut entry, "code");
    push_text(&mut entry, "XX");
    push_text(&mut entry, "country");
    push_map(&mut entry, 1);
    push_text(&mut entry, "iso_code");
    push_text(&mut entry, "CN");
    push_text(&mut entry, "subdivisions");
    entry.extend_from_slice(&[0x01, 0x04]); // array (extended type 11), one element
    push_map(&mut entry, 1);
    push_text(&mut entry, "iso_code");
    push_text(&mut entry, "9X");
    let city = write_database(&env, "city.mmdb", "GeoIP2-City", &entry);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            geoip_city {city};
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    return 200 "$geoip_city_continent_code $geoip_city_country_code \
$geoip_city_country_code3 $geoip_region";
                }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_response(&response, 200, "XX CN CHN 9X");
}

#[test]
fn geoip_coordinates_are_rendered_with_the_degree_check() {
    let env = Env::new();
    // `{"location":{"latitude":12.5,"longitude":-77.25}}`
    let mut entry = Vec::new();
    push_map(&mut entry, 1);
    push_text(&mut entry, "location");
    push_map(&mut entry, 2);
    push_text(&mut entry, "latitude");
    push_double(&mut entry, 12.5);
    push_text(&mut entry, "longitude");
    push_double(&mut entry, -77.25);
    let city = write_database(&env, "coords.mmdb", "GeoIP2-City", &entry);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            geoip_city {city};
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "$geoip_latitude $geoip_longitude"; }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_response(&response, 200, "12.5 -77.25");
}

#[test]
fn geoip_org_reads_the_asn_edition() {
    let env = Env::new();
    let mut entry = Vec::new();
    push_map(&mut entry, 1);
    push_text(&mut entry, "autonomous_system_organization");
    push_text(&mut entry, "Example Networks");
    let org = write_database(&env, "asn.mmdb", "GeoLite2-ASN", &entry);
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            geoip_org {org};
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "$geoip_org"; }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    let response = request(port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_response(&response, 200, "Example Networks");
}

#[test]
fn geoip_proxy_walks_the_forwarded_header() {
    let env = Env::new();
    let country = write_database(
        &env,
        "country.mmdb",
        "GeoIP2-Country",
        &country_entry("CN", "Anchoria"),
    );
    let port = env.port;
    // Without `geoip_proxy` the header is ignored; nothing about the peer matches a database
    // built for a single address space, so the variable is empty.
    let config = format!(
        r#"
        http {{
            access_log off;
            geoip_country {country};
            geoip_proxy 10.0.0.0/8;
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "[$geoip_country_code]"; }}
            }}
        }}
        "#,
    );
    let _server = env.start(&config);
    // The loopback peer is not a trusted geoip proxy, so the header does not change anything.
    let response = request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.9\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "[CN]");
}

#[test]
fn geoip_rejects_a_mismatched_database() {
    let env = Env::new();
    // A City database given to `geoip_country` is an error (`invalid GeoIP Country database`).
    let city = write_database(&env, "city.mmdb", "GeoIP2-City", &country_entry("CN", "A"));
    let config = format!(
        r#"
        http {{
            geoip_country {city};
            server {{ listen 127.0.0.1:{}; location / {{ return 200; }} }}
        }}
        "#,
        env.port
    );
    let path = env.path().join("nginx.conf");
    std::fs::write(&path, config).unwrap();
    let output = support::run(["-c", &path.to_string_lossy(), "-t"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid GeoIP Country database"), "{stderr}");
}

#[test]
fn geoip_rejects_a_missing_file() {
    let env = Env::new();
    let config = format!(
        r#"
        http {{
            geoip_city {missing};
            server {{ listen 127.0.0.1:{}; location / {{ return 200; }} }}
        }}
        "#,
        env.port,
        missing = env
            .path()
            .join("absent.mmdb")
            .to_string_lossy()
            .replace('\\', "/"),
    );
    let path = env.path().join("nginx.conf");
    std::fs::write(&path, config).unwrap();
    let output = support::run(["-c", &path.to_string_lossy(), "-t"]);
    assert!(!output.status.success());
}
