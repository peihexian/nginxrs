//! OCSP responder fetching (`ssl_stapling on` + `ssl_stapling_responder`).
//!
//! Nginx (`c/nginx/src/event/ngx_event_openssl_stapling.c`) sends the DER OCSP request with
//! `application/ocsp-request` over a plain HTTP/1.0 POST and stores the returned
//! `application/ocsp-response` bytes for stapling. The fetch happens at configuration time
//! here (`nginxrs -t` / startup), which is where Nginx's `ssl_stapling` resolver also warms
//! the staple before the first handshake completes.

use anyhow::{Context, Result, bail};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// `ngx_ssl_stapling_timeout` default (`NGX_OCSP_RESPONSE_TIMEOUT`).
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// Fetch a stapled OCSP response from a responder URL (`http://host[:port]/path`).
///
/// `request` is the DER-encoded OCSP request built from the server certificate and its
/// issuer. Returns the DER response bytes.
pub fn fetch(responder: &str, request: &[u8]) -> Result<Vec<u8>> {
    let url = responder
        .strip_prefix("http://")
        .with_context(|| format!("unsupported OCSP responder URL \"{responder}\""))?;
    let (authority, path) = match url.find('/') {
        Some(index) => (&url[..index], &url[index..]),
        None => (url, "/"),
    };
    let address = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let mut resolved = address
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve the OCSP responder \"{authority}\""))?;
    let endpoint = resolved
        .next()
        .ok_or_else(|| anyhow::anyhow!("the OCSP responder \"{authority}\" has no address"))?;

    let mut stream = TcpStream::connect_timeout(&endpoint, RESPONSE_TIMEOUT)
        .with_context(|| format!("cannot connect to the OCSP responder {endpoint}"))?;
    stream.set_read_timeout(Some(RESPONSE_TIMEOUT)).ok();
    stream.set_write_timeout(Some(RESPONSE_TIMEOUT)).ok();

    // `ngx_event_openssl_stapling.c` uses `HTTP/1.0` with an explicit `Content-Length`.
    let head = format!(
        "POST {path} HTTP/1.0\r\nHost: {authority}\r\nContent-Type: application/ocsp-request\r\nContent-Length: {}\r\n\r\n",
        request.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(request))
        .context("cannot send the OCSP request")?;
    stream.flush().ok();

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .context("cannot read the OCSP response")?;
    split_response(&response)
}

/// Split an HTTP response into status and body (`ngx_http_parse_status_line` equivalent).
fn split_response(response: &[u8]) -> Result<Vec<u8>> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .with_context(|| "the OCSP responder sent an invalid response")?;
    let head = String::from_utf8_lossy(&response[..split]);
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    if status != 200 {
        bail!("the OCSP responder returned HTTP {status}");
    }
    let body = &response[split + 4..];
    if body.is_empty() {
        bail!("the OCSP responder returned an empty response");
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn splits_a_valid_response() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\n\x30\x03\x0a\x01\x00";
        assert_eq!(split_response(raw).unwrap(), b"\x30\x03\x0a\x01\x00");
    }

    #[test]
    fn rejects_a_non_200_status() {
        let raw = b"HTTP/1.0 404 Not Found\r\n\r\nmissing";
        assert!(split_response(raw).is_err());
    }

    #[test]
    fn rejects_an_empty_body() {
        let raw = b"HTTP/1.0 200 OK\r\n\r\n";
        assert!(split_response(raw).is_err());
    }

    #[test]
    fn fetches_a_response_over_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buffer = [0_u8; 4096];
                let mut request = Vec::new();
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(count) => request.extend_from_slice(&buffer[..count]),
                        Err(_) => break,
                    }
                }
                // The body follows the header; one more read gets it.
                let length: usize = String::from_utf8_lossy(&request)
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                let header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4)
                    .unwrap_or(request.len());
                let mut body = request[header_end..].to_vec();
                while body.len() < length {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(count) => body.extend_from_slice(&buffer[..count]),
                        Err(_) => break,
                    }
                }
                assert_eq!(body, b"req");
                let _ = stream.write_all(
                    b"HTTP/1.0 200 OK\r\nContent-Type: application/ocsp-response\r\n\r\nstaple",
                );
            }
        });
        let response = fetch(&format!("http://127.0.0.1:{port}/ocsp"), b"req").unwrap();
        assert_eq!(response, b"staple");
    }

    #[test]
    fn rejects_a_non_http_url() {
        assert!(fetch("https://responder/ocsp", b"req").is_err());
    }
}
