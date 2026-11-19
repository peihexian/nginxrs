use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start nginxrs with the given configuration and wait for its listener.
fn start(config: &str, port: u16, temp: &Path) -> ChildGuard {
    let config_path = temp.join("nginx.conf");
    std::fs::write(&config_path, config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let guard = ChildGuard(child);
    wait_until_ready(port, &config_path, Duration::from_secs(10));
    guard
}

#[test]
fn serves_static_proxy_rewrite_lua_and_load_balancing() {
    let temp = tempfile::tempdir().unwrap();
    let www = temp.path().join("www");
    std::fs::create_dir_all(www.join("media")).unwrap();
    std::fs::write(www.join("index.html"), "hello nginxrs").unwrap();
    std::fs::write(www.join("media/movie.bin"), b"0123456789").unwrap();
    std::fs::write(
        www.join("media/live.m3u8"),
        "#EXTM3U\n#EXTINF:4,\nsegment0.ts\n",
    )
    .unwrap();

    let backend1 = spawn_backend("one");
    let backend2 = spawn_backend("two");
    let port = free_port();
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
    let _server = start(&config, port, temp.path());

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

#[test]
fn realip_rewrites_client_address_for_variables_and_upstream() {
    let temp = tempfile::tempdir().unwrap();
    let backend = spawn_echo_backend();
    let port = free_port();
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
    let _server = start(&config, port, temp.path());

    // `real_ip_recursive on`: the right-most trusted hop (127.0.0.1) is skipped and the
    // first untrusted address becomes `$remote_addr`; the original peer stays visible as
    // `$realip_remote_addr`.
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

#[test]
fn realip_is_ignored_without_trusted_sources() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
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
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "GET /client HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 203.0.113.9\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "127.0.0.1\n");
}

fn spawn_backend(name: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0_u8; 8192];
            let Ok(count) = stream.read(&mut buffer) else {
                continue;
            };
            let request = String::from_utf8_lossy(&buffer[..count]);
            let path = request.split_whitespace().nth(1).unwrap_or("/");
            let host = request
                .lines()
                .find_map(|line| line.strip_prefix("Host: "))
                .unwrap_or("")
                .trim();
            let response_body = format!("{name} path={path} host={host}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

/// Echo every request header as `name: value` lines.
fn spawn_echo_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0_u8; 8192];
            let Ok(count) = stream.read(&mut buffer) else {
                continue;
            };
            let request = String::from_utf8_lossy(&buffer[..count]);
            let headers = request
                .lines()
                .skip(1)
                .take_while(|line| !line.is_empty())
                .map(|line| line.to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join("\n");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{headers}",
                headers.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    port
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_until_ready(port: u16, config_path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    // Surface the server's own error instead of only the connection refusal.
    let output = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(config_path)
        .arg("-t")
        .output()
        .expect("configuration check runs");
    panic!(
        "nginxrs did not listen on port {port} within {timeout:?}\nconfig at {}\ncheck stderr:\n{}{}",
        config_path.display(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
}

fn request(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8(response).unwrap()
}

fn status(response: &str) -> u16 {
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn header<'a>(response: &'a str, name: &str) -> &'a str {
    response
        .split("\r\n")
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .unwrap_or_else(|| panic!("missing {name} header in {response}"))
}

fn body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

fn assert_response(response: &str, expected_status: u16, expected_body: &str) {
    assert_eq!(status(response), expected_status, "{response}");
    assert_eq!(body(response), expected_body, "{response}");
}

fn config_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[test]
fn access_module_denies_and_allows_by_cidr() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location = /denied {{
                    deny all;
                    return 200 "never";
                }}
                location = /allowed {{
                    deny 203.0.113.0/24;
                    allow all;
                    return 200 "ok";
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());

    let response = request(
        port,
        "GET /denied HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 403);
    let response = request(
        port,
        "GET /allowed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&response, 200, "ok");
}

#[test]
fn limit_req_rejects_over_rate_and_reports_status() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            limit_req_zone $binary_remote_addr zone=one:1m rate=1r/s;
            server {{
                listen 127.0.0.1:{port};
                location = /limited {{
                    limit_req zone=one burst=1 nodelay;
                    limit_req_status 429;
                    return 200 "$limit_req_status";
                }}
                location = /lua {{
                    content_by_lua_block "ngx.say(ngx.var.limit_req_status or 'unset')";
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());

    // rate=1r/s, burst=1, nodelay: the first request passes, the second exceeds the burst
    // almost immediately (only a few milliseconds of drainage) and is rejected.
    let first = request(
        port,
        "GET /limited HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&first, 200, "PASSED");

    let mut rejected = 0;
    for _ in 0..3 {
        let response = request(
            port,
            "GET /limited HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if status(&response) == 429 {
            rejected += 1;
        }
    }
    assert!(
        rejected >= 1,
        "expected at least one 429 after the burst was exhausted"
    );
}

#[test]
fn limit_conn_rejects_second_request_while_first_is_in_flight() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            limit_conn_zone $binary_remote_addr zone=addr:1m;
            server {{
                listen 127.0.0.1:{port};
                location = /slow {{
                    limit_conn addr 1;
                    limit_conn_status 429;
                    proxy_pass http://127.0.0.1:{backend};
                }}
            }}
        }}
        "#,
        backend = spawn_slow_backend()
    );
    let _server = start(&config, port, temp.path());

    let handle = std::thread::spawn(move || {
        request(
            port,
            "GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
    });
    std::thread::sleep(Duration::from_millis(200));
    let second = request(
        port,
        "GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let first = handle.join().unwrap();
    assert_eq!(status(&second), 429, "second request: {second}");
    assert_eq!(status(&first), 200, "first request: {first}");
}

/// Backend that answers after a short delay, keeping the proxied request in flight so
/// `limit_conn` sees a genuinely concurrent request.
fn spawn_slow_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0_u8; 8192];
            if stream.read(&mut buffer).is_err() {
                continue;
            }
            thread::sleep(Duration::from_millis(800));
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone",
            );
        }
    });
    port
}

#[test]
fn stub_status_and_prometheus_report_counters() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location = /status {{ stub_status; }}
                location = /metrics {{ prometheus_metrics; }}
                location = / {{ return 200 "ok"; }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());

    request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    let status_page = request(
        port,
        "GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&status_page), 200);
    let status_body = body(&status_page);
    assert!(
        status_body.starts_with("Active connections: "),
        "{status_body}"
    );
    assert!(
        status_body.contains("server accepts handled requests"),
        "{status_body}"
    );
    assert!(
        status_body.contains("Reading: 0 Writing: 0 Waiting: 0"),
        "{status_body}"
    );

    let metrics = request(
        port,
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&metrics), 200);
    assert!(
        header(&metrics, "Content-Type").starts_with("text/plain"),
        "{metrics}"
    );
    let metrics_body = body(&metrics);
    assert!(metrics_body.contains("# TYPE nginxrs_requests_total counter"));
    assert!(metrics_body.contains("nginxrs_requests_total "));
}

#[test]
fn reload_swaps_configuration_and_rejects_broken_files() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let pid_file = temp.path().join("nginxrs.pid");
    let config_file = temp.path().join("nginx.conf");
    let write = |body: &str| {
        std::fs::write(
            &config_file,
            format!(
                r#"
                worker_processes 2;
                pid nginxrs.pid;
                http {{
                    access_log off;
                    server {{
                        listen 127.0.0.1:{port};
                        location = /version {{ return 200 "{body}"; }}
                    }}
                }}
                "#
            ),
        )
        .unwrap();
    };

    write("one");
    let child = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(&config_file)
        .arg("-p")
        .arg(&pid_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = ChildGuard(child);
    wait_until_ready(port, &config_file, Duration::from_secs(10));

    let first = request(
        port,
        "GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&first, 200, "one");

    // Valid reload: new routes take effect without dropping the listener.
    write("two");
    let output = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(&config_file)
        .arg("-p")
        .arg(&pid_file)
        .arg("-s")
        .arg("reload")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let second = request(
        port,
        "GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&second, 200, "two");

    // Invalid reload is rejected and the running configuration stays active.
    std::fs::write(
        &config_file,
        "worker_processes 2; http { server { listen 1; made_up on; } }",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(&config_file)
        .arg("-p")
        .arg(&pid_file)
        .arg("-s")
        .arg("reload")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "invalid reload should fail: {output:?}"
    );
    let third = request(
        port,
        "GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_response(&third, 200, "two");
}

#[test]
fn ssl_listener_serves_https() {
    use std::io::Write;

    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("cert.pem");
    let key = temp.path().join("key.pem");
    // Generate a throwaway certificate; skip when openssl is unavailable.
    let openssl = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(openssl, Ok(result) if result.success()) {
        eprintln!("skipping ssl_listener_serves_https: openssl is unavailable");
        return;
    }

    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate cert.pem;
                ssl_certificate_key key.pem;
                ssl_protocols TLSv1.2 TLSv1.3;
                location = /secure {{ return 200 "tls-ok"; }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());

    let context = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate::new()))
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut connection = rustls::ClientConnection::new(Arc::new(context), server_name).unwrap();
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut tls = rustls::Stream::new(&mut connection, &mut socket);
    tls.write_all(b"GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).unwrap();
    let response = String::from_utf8_lossy(&response).to_string();
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "tls-ok");
}

/// Test-only verifier: accepts the throwaway self-signed certificate.
#[derive(Debug)]
struct AcceptAnyCertificate {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl AcceptAnyCertificate {
    fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
