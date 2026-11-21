//! Assertions over raw HTTP/1.1 responses.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Send a raw HTTP/1.1 request to loopback `port` and return the raw response text.
pub fn request(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8(response).unwrap()
}

/// The HTTP status code of a raw response.
pub fn status(response: &str) -> u16 {
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// The value of a header, matched case-insensitively.
pub fn header<'a>(response: &'a str, name: &str) -> &'a str {
    response
        .split("\r\n")
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .unwrap_or_else(|| panic!("missing {name} header in {response}"))
}

/// The first header named `name`, or `None`.
pub fn try_header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response.split("\r\n").find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// Every header of the response as `(name, value)` pairs.
pub fn headers(response: &str) -> Vec<(&str, &str)> {
    response
        .split_once("\r\n\r\n")
        .map(|(head, _)| head)
        .unwrap_or(response)
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name, value.trim()))
        .collect()
}

/// The response body.
pub fn body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

/// Send a raw request and return the raw response bytes (headers and body).
///
/// A gzip body is not valid UTF-8, so a test that decodes it must not lose bytes to `&str`.
pub fn raw_request(port: u16, request: &str) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    response
}

/// `Content-Encoding: gzip` from raw response bytes (headers only).
pub fn is_gzip_encoded(response: &[u8]) -> bool {
    let headers_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(response.len());
    String::from_utf8_lossy(&response[..headers_end])
        .lines()
        .any(|line| {
            line.split_once(':')
                .is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("content-encoding")
                        && value.trim().eq_ignore_ascii_case("gzip")
                })
        })
}

/// The raw headers of a response (up to the blank line).
pub fn raw_head(response: &[u8]) -> String {
    let headers_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(response.len());
    String::from_utf8_lossy(&response[..headers_end]).into_owned()
}

/// Decompress a `Content-Encoding: gzip` response body.
///
/// The body is taken as raw bytes: a gzip stream is not valid UTF-8, so it must not be
/// round-tripped through `&str` (the test helper loses invalid sequences).
pub fn gzip_decode_bytes(response: &[u8]) -> String {
    let start = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap_or(0);
    let mut decoder = flate2::read::GzDecoder::new(&response[start..]);
    let mut decoded = String::new();
    std::io::Read::read_to_string(&mut decoder, &mut decoded).ok();
    decoded
}

/// Assert that the response has this status and exactly this body.
pub fn assert_response(response: &str, expected_status: u16, expected_body: &str) {
    assert_eq!(status(response), expected_status, "{response}");
    assert_eq!(body(response), expected_body, "{response}");
}

/// Assert only the status code.
pub fn assert_status(response: &str, expected_status: u16) {
    assert_eq!(status(response), expected_status, "{response}");
}
