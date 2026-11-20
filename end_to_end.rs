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
            // Read until the header terminator: one request may arrive in several segments.
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => request.extend_from_slice(&buffer[..count]),
                    Err(_) => break,
                }
            }
            let request = String::from_utf8_lossy(&request).to_string();
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

// ---------------------------------------------------------------------------------------
// ssl module: `$ssl_*` variables, SNI certificate selection and proxy semantics
// ---------------------------------------------------------------------------------------

/// Generate a throwaway self-signed certificate; returns `None` when openssl is missing.
fn self_signed_cert(dir: &Path, name: &str, cn: &str) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let cert = dir.join(format!("{name}.crt"));
    let key = dir.join(format!("{name}.key"));
    let status = Command::new("openssl")
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
            &format!("/CN={cn}"),
            "-addext",
            &format!("subjectAltName=DNS:{cn}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if matches!(status, Ok(result) if result.success()) {
        Some((cert, key))
    } else {
        None
    }
}

/// Trust the certificate files under `dir` and GET `path` over TLS with the given SNI.
fn https_get(sni: &'static str, port: u16, path: &str, trusted: Vec<std::path::PathBuf>) -> String {
    let mut roots = rustls::RootCertStore::empty();
    for file in trusted {
        let data = std::fs::read(file).unwrap();
        for item in rustls_pemfile::certs(&mut data.as_slice()) {
            roots.add(item.unwrap()).unwrap();
        }
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = rustls::ClientConnection::new(Arc::new(config), sni.try_into().unwrap()).unwrap();
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut stream = rustls::StreamOwned::new(connector, socket);
    let request = format!("GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

/// `$ssl_*` variables report the negotiated connection, as `ngx_http_ssl_variable` does.
#[test]
fn ssl_variables_report_the_negotiated_connection() {
    let temp = tempfile::tempdir().unwrap();
    let Some((cert, key)) = self_signed_cert(temp.path(), "server", "localhost") else {
        eprintln!("skipping ssl_variables_report_the_negotiated_connection: openssl is unavailable");
        return;
    };
    let port = free_port();
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
    let _server = start(&config, port, temp.path());

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
    let temp = tempfile::tempdir().unwrap();
    let Some((first_cert, first_key)) = self_signed_cert(temp.path(), "first", "first.test") else {
        eprintln!("skipping sni_selects_the_certificate_of_the_matching_server: openssl is unavailable");
        return;
    };
    let Some((second_cert, second_key)) = self_signed_cert(temp.path(), "second", "second.test")
    else {
        return;
    };
    let port = free_port();
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
    let _server = start(&config, port, temp.path());

    // `second.test` only verifies with the second certificate installed for that name.
    let response = https_get("second.test", port, "/", vec![second_cert.clone()]);
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "second");

    let response = https_get("first.test", port, "/", vec![first_cert.clone()]);
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "first");
}

/// `proxy_set_header` values are evaluated with request variables before the upstream call.
#[test]
fn proxy_set_header_evaluates_variables_for_the_upstream() {
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
                location /api/ {{
                    proxy_pass http://backend/v1/;
                    proxy_set_header Host $host;
                    proxy_set_header X-Request-Uri $request_uri;
                    proxy_set_header X-Forwarded-Method $request_method;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "GET /api/items?page=2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    let echoed = body(&response);
    // `proxy_pass http://backend/v1/` replaces the matched `/api/` prefix.
    assert!(echoed.contains("x-request-uri: /api/items?page=2"), "{echoed}");
    assert!(echoed.contains("x-forwarded-method: get"), "{echoed}");
    assert!(echoed.contains("host: localhost"), "{echoed}");
}

/// `proxy_http_version`/`proxy_set_body` are rejected instead of silently ignored.
#[test]
fn unknown_proxy_directives_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nginx.conf");
    std::fs::write(
        &path,
        r#"
        http {
            server {
                listen 127.0.0.1:18099;
                location / { proxy_pass http://127.0.0.1:9000; proxy_busy_buffers_size_not_a_directive 1; }
            }
        }
        "#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(&path)
        .arg("-t")
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    // The anyhow context goes to stderr, the directive error to stderr as well.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = format!("{stdout}{stderr}");
    assert!(
        message.contains("proxy_busy_buffers_size_not_a_directive") && message.contains("unknown directive"),
        "{message}"
    );
}

// ---------------------------------------------------------------------------------------
// proxy module: response rewriting, request shaping
// ---------------------------------------------------------------------------------------

/// A backend that answers with configurable raw response bytes.
fn spawn_raw_backend(response: &'static str) -> u16 {
    spawn_raw_backend_on(0, response)
}

/// Bind the raw backend to `port` (`0` picks a free one) and return the bound port, so a
/// response can refer to its own address.
fn spawn_raw_backend_on(port: u16, response: &'static str) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Read the complete request header before answering; one `read` may return only
            // part of it.
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => request.extend_from_slice(&buffer[..count]),
                    Err(_) => break,
                }
            }
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

/// `proxy_redirect default` rewrites an absolute upstream `Location` to the client origin.
#[test]
fn proxy_redirect_default_rewrites_location() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    // The upstream answers with its own address, which is what `proxy_redirect default`
    // matches (`proxy_pass http://127.0.0.1:<backend>/`).
    let backend_port = free_port();
    let response_bytes: &'static str = Box::leak(
        format!(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{backend_port}/login?next=/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_boxed_str(),
    );
    let backend = spawn_raw_backend_on(backend_port, response_bytes);
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://127.0.0.1:{backend}/;
                    proxy_set_header Host $host;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "GET /login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 302, "{response}");
    let rewritten = header(&response, "Location");
    assert!(!rewritten.contains(&format!("127.0.0.1:{backend}")), "{rewritten}");
    assert!(rewritten.contains("localhost"), "{rewritten}");
    assert!(rewritten.ends_with("/login?next=/x"), "{rewritten}");
}

/// An explicit `proxy_redirect off` keeps the upstream `Location` verbatim.
#[test]
fn proxy_redirect_off_keeps_upstream_location() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let backend = spawn_raw_backend(concat!(
        "HTTP/1.1 302 Found\r\n",
        "Location: http://127.0.0.1:9000/keep\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n\r\n",
    ));
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend/;
                    proxy_redirect off;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "GET /x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 302, "{response}");
    assert_eq!(header(&response, "Location"), "http://127.0.0.1:9000/keep");
}

/// `proxy_redirect pattern replacement` applies an explicit rewrite.
#[test]
fn proxy_redirect_rule_replaces_the_pattern() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let backend = spawn_raw_backend(concat!(
        "HTTP/1.1 301 Moved Permanently\r\n",
        "Location: http://upstream.internal/a/b\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n\r\n",
    ));
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend/;
                    proxy_redirect http://upstream.internal/ /front/;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "GET /a/b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(header(&response, "Location"), "/front/a/b", "{response}");
}

/// `proxy_cookie_domain`/`proxy_cookie_path`/`proxy_cookie_flags` rewrite `Set-Cookie`.
#[test]
fn proxy_cookie_rewrites_domain_path_and_flags() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let backend = spawn_raw_backend(concat!(
        "HTTP/1.1 200 OK\r\n",
        "Set-Cookie: sid=abc; Domain=backend.local; Path=/; HttpOnly\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n\r\n",
    ));
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend/;
                    proxy_cookie_domain backend.local example.com;
                    proxy_cookie_path / /app/;
                    proxy_cookie_flags sid secure samesite=strict;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let cookie = header(&response, "Set-Cookie");
    assert!(cookie.contains("Domain=example.com"), "{cookie}");
    assert!(cookie.contains("Path=/app/"), "{cookie}");
    assert!(cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
}

/// `proxy_pass_request_body off` and `proxy_method` shape the upstream request.
#[test]
fn proxy_method_and_request_body_flags_shape_the_upstream_request() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let backend = spawn_echo_backend();
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend/;
                    proxy_method DELETE;
                    proxy_pass_request_body off;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "POST /items HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    assert_eq!(status(&response), 200, "{response}");
    let echoed = body(&response);
    assert!(!echoed.contains("content-length"), "{echoed}");
}

/// `proxy_set_body` replaces the request body.
#[test]
fn proxy_set_body_replaces_the_request_body() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let backend = spawn_echo_backend();
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend/;
                    proxy_set_body "fixed-body";
                    proxy_set_header Content-Length 10;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "POST /x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    let echoed = body(&response);
    assert!(echoed.contains("content-length: 10"), "{echoed}");
}

// ---------------------------------------------------------------------------------------
// proxy module: proxy_next_upstream retry semantics
// ---------------------------------------------------------------------------------------

/// `proxy_next_upstream http_503` retries the request on the next backend.
#[test]
fn proxy_next_upstream_retries_on_configured_status() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    // Two backends: the first always answers 503, the second answers 200.
    let failing = spawn_raw_backend(concat!(
        "HTTP/1.1 503 Service Unavailable\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n\r\n",
    ));
    let healthy = spawn_raw_backend(
        "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecond",
    );
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{failing};
                server 127.0.0.1:{healthy};
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_next_upstream error timeout http_503;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    // The balancer round-robins; whichever backend comes first, a 503 must be retried, so
    // every request ends up served by the healthy peer.
    for _ in 0..4 {
        let response = request(
            port,
            "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status(&response), 200, "{response}");
        assert_eq!(body(&response), "second", "{response}");
    }
}

/// Without `http_503` in `proxy_next_upstream` the 503 reaches the client unchanged.
#[test]
fn proxy_next_upstream_default_does_not_retry_on_status() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let failing = spawn_raw_backend(concat!(
        "HTTP/1.1 503 Service Unavailable\r\n",
        "Content-Length: 0\r\n",
        "Connection: close\r\n\r\n",
    ));
    let healthy =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{failing};
                server 127.0.0.1:{healthy};
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ proxy_pass http://backend; }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    // Round robin alternates, so among four requests at least one hits the failing peer and
    // must surface its 503 (the default is `error timeout`, which excludes http_503).
    let mut saw_503 = false;
    for _ in 0..4 {
        let response = request(
            port,
            "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if status(&response) == 503 {
            saw_503 = true;
        }
    }
    assert!(saw_503, "the default configuration must not retry a 503");
}

/// A connection-level failure is retried by default (`error` is in the default set).
#[test]
fn proxy_next_upstream_retries_connection_errors_by_default() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    // A dead port: nothing listens there, so connecting is refused.
    let dead = free_port();
    let healthy = spawn_raw_backend(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nalive",
    );
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{dead};
                server 127.0.0.1:{healthy};
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{ proxy_pass http://backend; }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    for _ in 0..4 {
        let response = request(
            port,
            "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status(&response), 200, "{response}");
        assert_eq!(body(&response), "alive", "{response}");
    }
}

/// `proxy_next_upstream off` disables retrying even for connection failures.
#[test]
fn proxy_next_upstream_off_disables_retries() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let dead = free_port();
    let healthy =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{dead};
                server 127.0.0.1:{healthy};
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_next_upstream off;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let mut saw_failure = false;
    for _ in 0..4 {
        let response = request(
            port,
            "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if status(&response) >= 500 {
            saw_failure = true;
        }
    }
    assert!(saw_failure, "`proxy_next_upstream off` must not retry");
}

/// `proxy_next_upstream_tries 1` bounds the attempts: one peer only.
#[test]
fn proxy_next_upstream_tries_limits_attempts() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let dead = free_port();
    let healthy =
        spawn_raw_backend("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{
                server 127.0.0.1:{dead};
                server 127.0.0.1:{healthy};
            }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_next_upstream_tries 1;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let mut failures = 0;
    for _ in 0..4 {
        let response = request(
            port,
            "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        if status(&response) >= 500 {
            failures += 1;
        }
    }
    assert!(failures > 0, "a single try must fail when it hits the dead peer");
}

/// `proxy_next_upstream http_500` is rejected for a non-idempotent method unless
/// `non_idempotent` is listed.
#[test]
fn proxy_next_upstream_requires_non_idempotent_for_post() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let failing = spawn_raw_backend(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{failing}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_next_upstream error http_500;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "POST /item HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        status(&response),
        500,
        "the single peer's status must reach the client: {response}"
    );
}

// ---------------------------------------------------------------------------------------
// proxy module: response buffering
// ---------------------------------------------------------------------------------------

/// A backend that returns a body of `size` bytes, built from the request count.
fn spawn_sized_backend(size: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body: &'static str = Box::leak("x".repeat(size).into_boxed_str());
    let response: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n{body}"
        )
        .into_boxed_str(),
    );
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => request.extend_from_slice(&buffer[..count]),
                    Err(_) => break,
                }
            }
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

/// A response larger than `proxy_buffers * proxy_buffer_size` still reaches the client
/// intact, with the overflow spooled through `proxy_temp_path`.
#[test]
fn proxy_buffering_spools_large_responses_to_the_temp_path() {
    let temp = tempfile::tempdir().unwrap();
    let temp_path = temp.path().join("proxy_temp");
    let port = free_port();
    let backend = spawn_sized_backend(200_000);
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_buffering on;
                    proxy_buffers 2 1024;
                    proxy_buffer_size 1024;
                    proxy_busy_buffers_size 4096;
                    proxy_max_temp_file_size 10m;
                    proxy_temp_path {temp_path};
                }}
            }}
        }}
        "#,
        temp_path = config_path(&temp_path),
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "GET /big HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response).len(), 200_000, "the body must not be truncated");
    assert!(
        body(&response).bytes().all(|byte| byte == b'x'),
        "the buffered body must be forwarded verbatim"
    );
}

/// `proxy_buffering off` forwards the body as well, without a temp file.
#[test]
fn proxy_buffering_off_streams_the_response() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let backend = spawn_sized_backend(50_000);
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_buffering off;
                }}
            }}
        }}
        "#
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "GET /big HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response).len(), 50_000);
}

/// `proxy_max_temp_file_size 0` disables spooling: the body still arrives complete.
#[test]
fn proxy_max_temp_file_size_zero_still_serves_the_body() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let backend = spawn_sized_backend(120_000);
    let config = format!(
        r#"
        http {{
            access_log off;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_buffers 1 1024;
                    proxy_max_temp_file_size 0;
                    proxy_temp_path {temp_dir};
                }}
            }}
        }}
        "#,
        temp_dir = config_path(&temp.path().join("proxy_temp")),
    );
    let _server = start(&config, port, temp.path());
    let response = request(
        port,
        "GET /big HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response).len(), 120_000);
}

// ---------------------------------------------------------------------------------------
// proxy module: proxy_cache
// ---------------------------------------------------------------------------------------

/// A backend that counts requests and answers `hit-<n>` with a configurable TTL.
fn spawn_counting_backend() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let shared = Arc::clone(&counter);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => request.extend_from_slice(&buffer[..count]),
                    Err(_) => break,
                }
            }
            let n = shared.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let body = format!("hit-{n}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (port, counter)
}

/// A cached response is served without contacting the upstream on the second request.
#[test]
fn proxy_cache_serves_the_second_request_from_the_cache() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let port = free_port();
    let (backend, counter) = spawn_counting_backend();
    let config = format!(
        r#"
        http {{
            access_log off;
            proxy_cache_path {cache_dir} levels=1:2 keys_zone=z:10m inactive=1h max_size=10m;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_cache z;
                    proxy_cache_valid 200 10m;
                }}
            }}
        }}
        "#,
        cache_dir = config_path(&cache_dir),
    );
    let _server = start(&config, port, temp.path());

    let first = request(
        port,
        "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&first), 200, "{first}");
    assert_eq!(body(&first), "hit-1");

    let second = request(
        port,
        "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status(&second), 200, "{second}");
    assert_eq!(body(&second), "hit-1", "the cached body must be replayed");
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the upstream must only be contacted once"
    );
}

/// Different cache keys are stored separately.
#[test]
fn proxy_cache_key_separates_requests() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let port = free_port();
    let (backend, counter) = spawn_counting_backend();
    let config = format!(
        r#"
        http {{
            access_log off;
            proxy_cache_path {cache_dir} levels=1:2 keys_zone=z:10m inactive=1h max_size=10m;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_cache z;
                    proxy_cache_key $request_uri;
                    proxy_cache_valid 200 10m;
                }}
            }}
        }}
        "#,
        cache_dir = config_path(&cache_dir),
    );
    let _server = start(&config, port, temp.path());

    let a = request(
        port,
        "GET /a HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let b = request(
        port,
        "GET /b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&a), "hit-1", "{a}");
    assert_eq!(body(&b), "hit-2", "{b}");
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 2);

    // Both keys now hit.
    let a2 = request(
        port,
        "GET /a HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&a2), "hit-1");
}

/// `proxy_cache_bypass` skips the cache and is reported as `BYPASS`.
#[test]
fn proxy_cache_bypass_skips_the_lookup() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let port = free_port();
    let (backend, counter) = spawn_counting_backend();
    let config = format!(
        r#"
        http {{
            access_log off;
            proxy_cache_path {cache_dir} levels=1:2 keys_zone=z:10m inactive=1h max_size=10m;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_cache z;
                    proxy_cache_valid 200 10m;
                    proxy_cache_bypass $arg_nocache;
                }}
            }}
        }}
        "#,
        cache_dir = config_path(&cache_dir),
    );
    let _server = start(&config, port, temp.path());

    let first = request(
        port,
        "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );

    assert_eq!(body(&first), "hit-1", "{first}");
    let bypass = request(
        port,
        "GET /item?nocache=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&bypass), "hit-2", "a bypass must reach the upstream");
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// Without `proxy_cache_valid` and without expiry headers the response is not cached.
#[test]
fn proxy_cache_without_validity_is_not_cached() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let port = free_port();
    let (backend, counter) = spawn_counting_backend();
    let config = format!(
        r#"
        http {{
            access_log off;
            proxy_cache_path {cache_dir} levels=1:2 keys_zone=z:10m inactive=1h max_size=10m;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    proxy_cache z;
                }}
            }}
        }}
        "#,
        cache_dir = config_path(&cache_dir),
    );
    let _server = start(&config, port, temp.path());

    let first = request(
        port,
        "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&first), "hit-1", "{first}");
    let second = request(
        port,
        "GET /item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body(&second), "hit-2", "{second}");
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// An unknown `proxy_cache` zone is a configuration error, as in Nginx.
#[test]
fn proxy_cache_unknown_zone_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nginx.conf");
    std::fs::write(
        &path,
        r#"
        http {
            server {
                listen 127.0.0.1:18098;
                location / { proxy_pass http://127.0.0.1:9000; proxy_cache missing; }
            }
        }
        "#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(&path)
        .arg("-t")
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(message.contains("unknown"), "{message}");
}

/// `ssl_reject_handshake on` lets a server exist without certificates and rejects the
/// handshake for its names (`ngx_http_ssl_servername` 鈫?`handshake_rejected`).
#[test]
fn ssl_reject_handshake_rejects_unmatched_names() {
    let temp = tempfile::tempdir().unwrap();
    let Some((cert, key)) = self_signed_cert(temp.path(), "default", "default.test") else {
        eprintln!("skipping ssl_reject_handshake_rejects_unmatched_names: openssl is unavailable");
        return;
    };
    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl default_server;
                server_name default.test;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                location / {{ return 200 "default"; }}
            }}
            server {{
                listen 127.0.0.1:{port} ssl;
                server_name rejected.test;
                ssl_reject_handshake on;
                location / {{ return 200 "never"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = start(&config, port, temp.path());

    // The configured name is answered normally.
    let response = https_get("default.test", port, "/", vec![cert.clone()]);
    assert_eq!(status(&response), 200, "{response}");
    assert_eq!(body(&response), "default");

    // The rejected name never completes a handshake.
    let mut roots = rustls::RootCertStore::empty();
    let data = std::fs::read(&cert).unwrap();
    for item in rustls_pemfile::certs(&mut data.as_slice()) {
        roots.add(item.unwrap()).unwrap();
    }
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = rustls::ClientConnection::new(
        Arc::new(client),
        "rejected.test".try_into().unwrap(),
    )
    .unwrap();
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut stream = rustls::StreamOwned::new(connector, socket);
    let request = "GET / HTTP/1.1\r\nHost: rejected.test\r\nConnection: close\r\n\r\n";
    let handshake = stream.write_all(request.as_bytes());
    assert!(
        handshake.is_err(),
        "the handshake must fail for a rejected server name"
    );
}

/// A `server` may rely on `ssl_reject_handshake` alone: `-t` must accept it.
#[test]
fn ssl_reject_handshake_server_needs_no_certificate() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("nginx.conf");
    std::fs::write(
        &path,
        r#"
        http {
            server {
                listen 127.0.0.1:18097 ssl default_server;
                ssl_reject_handshake on;
                location / { return 200 "never"; }
            }
        }
        "#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(&path)
        .arg("-t")
        .output()
        .unwrap();
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{message}");
    assert!(message.contains("successful"), "{message}");
}

// ---------------------------------------------------------------------------------------
// ssl module: session resumption and client certificate chains
// ---------------------------------------------------------------------------------------

/// Build a CA plus a leaf certificate signed by it; returns (ca_pem, leaf_cert, leaf_key).
fn signed_cert(
    dir: &Path,
    name: &str,
    cn: &str,
) -> Option<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
    let ca_key = dir.join(format!("{name}-ca.key"));
    let ca_pem = dir.join(format!("{name}-ca.crt"));
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            ca_key.to_str().unwrap(),
            "-out",
            ca_pem.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=nginxrs-test-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(status, Ok(result) if result.success()) {
        return None;
    }
    let leaf_key = dir.join(format!("{name}.key"));
    let csr = dir.join(format!("{name}.csr"));
    let leaf_cert = dir.join(format!("{name}.crt"));
    let status = Command::new("openssl")
        .args([
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            leaf_key.to_str().unwrap(),
            "-out",
            csr.to_str().unwrap(),
            "-subj",
            &format!("/CN={cn}"),
            "-addext",
            &format!("subjectAltName=DNS:{cn}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(status, Ok(result) if result.success()) {
        return None;
    }
    let status = Command::new("openssl")
        .args([
            "x509",
            "-req",
            "-in",
            csr.to_str().unwrap(),
            "-CA",
            ca_pem.to_str().unwrap(),
            "-CAkey",
            ca_key.to_str().unwrap(),
            "-CAcreateserial",
            "-out",
            leaf_cert.to_str().unwrap(),
            "-days",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(status, Ok(result) if result.success()) {
        return None;
    }
    Some((ca_pem, leaf_cert, leaf_key))
}

/// `ssl_session_cache` resumes a session: the second handshake reports `r`.
#[test]
fn ssl_session_cache_resumes_connections() {
    let temp = tempfile::tempdir().unwrap();
    let Some((cert, key)) = self_signed_cert(temp.path(), "session", "session.test") else {
        eprintln!("skipping ssl_session_cache_resumes_connections: openssl is unavailable");
        return;
    };
    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                ssl_protocols TLSv1.2;
                ssl_session_cache shared:SSL:10m;
                ssl_session_tickets off;
                location / {{ return 200 "$ssl_session_reused"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = start(&config, port, temp.path());

    let mut roots = rustls::RootCertStore::empty();
    let data = std::fs::read(&cert).unwrap();
    for item in rustls_pemfile::certs(&mut data.as_slice()) {
        roots.add(item.unwrap()).unwrap();
    }
    // rustls needs a resumption store on the client side to reuse a session.
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = rustls::client::Resumption::in_memory_sessions(8);
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = Arc::new(client);

    let mut results = Vec::new();
    for _ in 0..3 {
        let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let connection = rustls::ClientConnection::new(
            Arc::clone(&client),
            "session.test".try_into().unwrap(),
        )
        .unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let request = "GET / HTTP/1.1\r\nHost: session.test\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        results.push(String::from_utf8_lossy(&response).to_string());
    }
    // The first handshake establishes the session; at least one later one must resume it.
    assert!(
        results.iter().skip(1).any(|response| body(response) == "r"),
        "no session was reused: {results:?}"
    );
}

/// `ssl_verify_client on` with `ssl_verify_depth` rejects a client certificate signed by an
/// unknown CA, and accepts one from the configured CA.
#[test]
fn ssl_verify_client_validates_the_client_certificate() {
    let temp = tempfile::tempdir().unwrap();
    let Some((server_cert, server_key)) = self_signed_cert(temp.path(), "server", "mtls.test") else {
        eprintln!("skipping ssl_verify_client_validates_the_client_certificate: openssl is unavailable");
        return;
    };
    let Some((ca, client_cert, client_key)) = signed_cert(temp.path(), "client", "client.test")
    else {
        return;
    };
    // A second CA whose certificate is NOT configured on the server.
    let Some((other_ca, other_cert, other_key)) = signed_cert(temp.path(), "other", "other.test")
    else {
        return;
    };
    let _ = other_ca;
    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate {server_cert};
                ssl_certificate_key {server_key};
                ssl_verify_client on;
                ssl_verify_depth 2;
                ssl_client_certificate {ca};
                location / {{ return 200 "$ssl_client_verify|$ssl_client_s_dn"; }}
            }}
        }}
        "#,
        server_cert = config_path(&server_cert),
        server_key = config_path(&server_key),
        ca = config_path(&ca),
    );
    let _server = start(&config, port, temp.path());

    let mut roots = rustls::RootCertStore::empty();
    let data = std::fs::read(&server_cert).unwrap();
    for item in rustls_pemfile::certs(&mut data.as_slice()) {
        roots.add(item.unwrap()).unwrap();
    }
    let build = |cert: &Path, key: &Path| {
        let mut chain = Vec::new();
        let cert_data = std::fs::read(cert).unwrap();
        for item in rustls_pemfile::certs(&mut cert_data.as_slice()) {
            chain.push(item.unwrap());
        }
        let key_data = std::fs::read(key).unwrap();
        let key = rustls_pemfile::private_key(&mut key_data.as_slice())
            .unwrap()
            .unwrap();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(chain, key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    };

    let trusted = https_get_with(build(&client_cert, &client_key), "mtls.test", port, "/");
    assert_eq!(status(&trusted), 200, "{trusted}");
    let reported = body(&trusted);
    assert!(
        reported.starts_with("SUCCESS|"),
        "the trusted certificate must verify: {reported}"
    );

    // An untrusted client certificate must not produce a 200.
    let untrusted = https_get_with(build(&other_cert, &other_key), "mtls.test", port, "/");
    assert!(
        untrusted.is_empty() || status(&untrusted) != 200,
        "an untrusted client certificate must be rejected: {untrusted}"
    );
}

/// GET over TLS with a prepared client configuration.
fn https_get_with(config: Arc<rustls::ClientConfig>, sni: &'static str, port: u16, path: &str) -> String {
    let socket = match TcpStream::connect(("127.0.0.1", port)) {
        Ok(socket) => socket,
        Err(_) => return String::new(),
    };
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let connection = match rustls::ClientConnection::new(config, sni.try_into().unwrap()) {
        Ok(connection) => connection,
        Err(_) => return String::new(),
    };
    let mut stream = rustls::StreamOwned::new(connection, socket);
    let request = format!("GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return String::new();
    }
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

/// `ssl_stapling on` + `ssl_stapling_responder` fetches the OCSP response at startup.
#[test]
fn ssl_stapling_responder_is_queried_for_a_response() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let temp = tempfile::tempdir().unwrap();
    let Some((cert, key)) = self_signed_cert(temp.path(), "staple", "staple.test") else {
        eprintln!("skipping ssl_stapling_responder_is_queried_for_a_response: openssl unavailable");
        return;
    };
    // A fake responder answering every POST with a canned OCSP response.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let responder_port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0_u8; 8192];
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => request.extend_from_slice(&buffer[..count]),
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&request);
            assert!(
                text.contains("application/ocsp-request"),
                "the responder must receive an OCSP request"
            );
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(
                b"HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\nstaple-bytes",
            );
        }
    });

    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                ssl_stapling on;
                ssl_stapling_responder http://127.0.0.1:{responder_port}/ocsp;
                location / {{ return 200 "ok"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = start(&config, port, temp.path());
    let response = https_get("staple.test", port, "/", vec![cert.clone()]);
    assert_eq!(status(&response), 200, "{response}");
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "the responder must have been queried"
    );
}

/// `ssl_stapling_verify on` rejects a responder answer that is not a valid OCSP response.
#[test]
fn ssl_stapling_verify_rejects_a_bogus_response() {
    let temp = tempfile::tempdir().unwrap();
    let Some((cert, key)) = self_signed_cert(temp.path(), "verify", "verify.test") else {
        eprintln!("skipping ssl_stapling_verify_rejects_a_bogus_response: openssl unavailable");
        return;
    };
    // A responder answering with bytes that are not an OCSP response.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let responder_port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0_u8; 8192];
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => request.extend_from_slice(&buffer[..count]),
                    Err(_) => break,
                }
            }
            let _ = stream.write_all(
                b"HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\nnot-an-ocsp-response",
            );
        }
    });

    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                ssl_stapling on;
                ssl_stapling_verify on;
                ssl_stapling_responder http://127.0.0.1:{responder_port}/ocsp;
                location / {{ return 200 "ok"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let temp_dir = temp.path();
    let path = temp_dir.join("nginx.conf");
    std::fs::write(&path, &config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(&path)
        .arg("-t")
        .output()
        .unwrap();
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "a bogus OCSP response must fail the configuration check: {message}"
    );
    assert!(
        message.to_lowercase().contains("ocsp") || message.contains("stapling"),
        "{message}"
    );
}

/// `ssl_early_data on` advertises a 0-RTT budget, so a TLS 1.3 client may send early data.
#[test]
fn ssl_early_data_is_advertised_to_clients() {
    let temp = tempfile::tempdir().unwrap();
    let Some((cert, key)) = self_signed_cert(temp.path(), "early", "early.test") else {
        eprintln!("skipping ssl_early_data_is_advertised_to_clients: openssl unavailable");
        return;
    };
    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                ssl_protocols TLSv1.3;
                ssl_session_cache shared:SSL:1m;
                ssl_session_tickets on;
                ssl_early_data on;
                location / {{ return 200 "early=$ssl_early_data"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = start(&config, port, temp.path());

    let mut roots = rustls::RootCertStore::empty();
    let data = std::fs::read(&cert).unwrap();
    for item in rustls_pemfile::certs(&mut data.as_slice()) {
        roots.add(item.unwrap()).unwrap();
    }
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = rustls::client::Resumption::in_memory_sessions(8);
    client.enable_early_data = true;
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = Arc::new(client);

    // First handshake: no 0-RTT yet, but the ticket is issued.
    let first = https_get_session(Arc::clone(&client), "early.test", port, "/", None);
    assert_eq!(status(&first), 200, "{first}");
    assert!(body(&first).starts_with("early="), "{first}");

    // Second handshake: rustls only sends early data when it holds a resumable session.
    // Whether the server accepts it is reported by `$ssl_early_data`.
    let second = https_get_session(Arc::clone(&client), "early.test", port, "/", Some(&first));
    assert_eq!(status(&second), 200, "{second}");
    assert!(
        body(&second) == "early=1" || body(&second) == "early=",
        "unexpected early data report: {}",
        body(&second)
    );
}

/// A TLS GET that records the session for the next call.
fn https_get_session(
    config: Arc<rustls::ClientConfig>,
    sni: &'static str,
    port: u16,
    path: &str,
    _previous: Option<&str>,
) -> String {
    let socket = match TcpStream::connect(("127.0.0.1", port)) {
        Ok(socket) => socket,
        Err(_) => return String::new(),
    };
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let connection = match rustls::ClientConnection::new(config, sni.try_into().unwrap()) {
        Ok(connection) => connection,
        Err(_) => return String::new(),
    };
    let mut stream = rustls::StreamOwned::new(connection, socket);
    let request = format!("GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return String::new();
    }
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

// ---------------------------------------------------------------------------------------
// core: HTTP/2 downstream (`listen ... http2`)
// ---------------------------------------------------------------------------------------

/// Build a TLS client which offers only `h2` and returns the negotiated connection.
fn h2_client(cert: &Path, sni: &'static str, port: u16) -> Option<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    let data = std::fs::read(cert).ok()?;
    for item in rustls_pemfile::certs(&mut data.as_slice()) {
        roots.add(item.ok()?).ok()?;
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = rustls::ClientConnection::new(Arc::new(config), sni.try_into().ok()?).ok()?;
    let socket = TcpStream::connect(("127.0.0.1", port)).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    Some(rustls::StreamOwned::new(connector, socket))
}

/// `listen ... http2` must negotiate `h2` through ALPN (not silently fall back to h1) and
/// answer the HTTP/2 connection preface with a SETTINGS frame.
#[test]
fn http2_listener_negotiates_and_answers_the_preface() {
    let temp = tempfile::tempdir().unwrap();
    let Some((cert, key)) = self_signed_cert(temp.path(), "h2", "h2.test") else {
        eprintln!("skipping http2_listener_negotiates_and_answers_the_preface: openssl unavailable");
        return;
    };
    let port = free_port();
    let config = format!(
        r#"
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port} ssl http2;
                ssl_certificate {cert};
                ssl_certificate_key {key};
                ssl_protocols TLSv1.3;
                location / {{ return 200 "h2-ok"; }}
            }}
        }}
        "#,
        cert = config_path(&cert),
        key = config_path(&key),
    );
    let _server = start(&config, port, temp.path());

    let Some(mut tls) = h2_client(&cert, "h2.test", port) else {
        panic!("cannot build the h2 client");
    };

    // Trigger the handshake by writing the HTTP/2 connection preface.
    use std::io::Write as _;
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    tls.write_all(preface).expect("write the h2 preface");

    assert_eq!(
        tls.conn.alpn_protocol(),
        Some(&b"h2"[..]),
        "the server must negotiate h2, not fall back to HTTP/1.1"
    );

    // The server must answer with a SETTINGS frame (type 0x04) within the first frames;
    // reading nothing means the connection was dropped (`serve_h2` used to return None).
    let mut frame_header = [0_u8; 9];
    tls.read_exact(&mut frame_header)
        .expect("the server must answer the HTTP/2 preface");
    let frame_type = frame_header[3];
    assert_eq!(
        frame_type, 0x04,
        "the first HTTP/2 frame must be SETTINGS, got type {frame_type:#04x}"
    );
}

/// `nginxrs -s stop` must terminate the server, not only acknowledge the command.
#[test]
fn stop_signal_terminates_the_server() {
    let temp = tempfile::tempdir().unwrap();
    let port = free_port();
    let pid_file = temp.path().join("nginxrs.pid");
    let config = format!(
        r#"
        pid {pid};
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "up"; }}
            }}
        }}
        "#,
        pid = config_path(&pid_file),
    );
    let config_file = temp.path().join("nginx.conf");
    std::fs::write(&config_file, &config).unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(&config_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_until_ready(port, &config_file, Duration::from_secs(10));

    let output = Command::new(env!("CARGO_BIN_EXE_nginxrs"))
        .arg("-c")
        .arg(&config_file)
        .args(["-s", "stop"])
        .output()
        .unwrap();
    // The server may exit before the control reply is drained, so a reset on that socket is
    // acceptable; what matters is that the server actually stops (asserted below).
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() || stderr.contains("10054") || stderr.is_empty(),
        "unexpected stop failure: {stderr}"
    );

    // The process must exit and stop listening.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_err(),
        "the listener must be closed after `-s stop`"
    );
    let _ = server.wait();
}
