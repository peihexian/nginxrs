//! Test backends: small TCP servers the tests proxy to.
//!
//! Each helper binds an ephemeral loopback port and serves every connection on a background
//! thread, so a test only has to format the returned port into its `upstream` block.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Read one complete request header off `stream` and return it as text.
///
/// One `read` may return only part of the request, so the terminator is awaited; the announced
/// body is then drained so the proxy is not left writing into a closed socket.
pub fn read_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => request.extend_from_slice(&buffer[..count]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&request).to_string();
    if let Some(length) = text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
    {
        let mut body = Vec::new();
        while body.len() < length {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => body.extend_from_slice(&buffer[..count]),
                Err(_) => break,
            }
        }
    }
    text
}

/// Write a complete HTTP/1.1 response with `Connection: close` and a text body.
pub fn write_close(stream: &mut std::net::TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn spawn_with<F>(listener: TcpListener, handler: F) -> u16
where
    F: Fn(&mut std::net::TcpStream) + Send + 'static,
{
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            handler(&mut stream);
        }
    });
    port
}

fn bind(port: u16) -> TcpListener {
    TcpListener::bind(("127.0.0.1", port)).unwrap()
}

/// A backend that answers `<name> path=<path> host=<Host>` for every request.
pub fn spawn_named_backend(name: &'static str) -> u16 {
    spawn_with(bind(0), move |stream| {
        let mut buffer = [0_u8; 8192];
        let Ok(count) = stream.read(&mut buffer) else {
            return;
        };
        let request = String::from_utf8_lossy(&buffer[..count]);
        let path = request.split_whitespace().nth(1).unwrap_or("/");
        let host = request
            .lines()
            .find_map(|line| line.strip_prefix("Host: "))
            .unwrap_or("")
            .trim();
        write_close(stream, &format!("{name} path={path} host={host}"));
    })
}

/// Echo every request header as `name: value` lines.
pub fn spawn_echo_backend() -> u16 {
    spawn_with(bind(0), |stream| {
        let request = read_request(stream);
        let headers = request
            .lines()
            .skip(1)
            .take_while(|line| !line.is_empty())
            .map(|line| line.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("\n");
        write_close(stream, &headers);
    })
}

/// Answer after a short delay, keeping the proxied request in flight long enough for
/// `limit_conn` to see a genuinely concurrent request.
pub fn spawn_slow_backend() -> u16 {
    spawn_with(bind(0), |stream| {
        let mut buffer = [0_u8; 8192];
        if stream.read(&mut buffer).is_err() {
            return;
        }
        thread::sleep(Duration::from_millis(800));
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone");
    })
}

/// Answer every request with the same raw bytes.
pub fn spawn_raw_backend(response: &'static str) -> u16 {
    spawn_raw_backend_on(0, response)
}

/// Bind the raw backend to `port` (`0` picks a free one) and return the bound port, so a
/// response can refer to its own address.
pub fn spawn_raw_backend_on(port: u16, response: &'static str) -> u16 {
    spawn_with(bind(port), move |stream| {
        let _ = read_request(stream);
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    })
}

/// A backend whose body is exactly `size` bytes.
pub fn spawn_sized_backend(size: usize) -> u16 {
    let body: &'static str = Box::leak("x".repeat(size).into_boxed_str());
    let response: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n{body}"
        )
        .into_boxed_str(),
    );
    spawn_raw_backend(response)
}

/// An echo backend that also counts how many requests reached it.
#[derive(Clone)]
pub struct EchoBackend {
    pub port: u16,
    pub hits: Arc<AtomicUsize>,
}

impl EchoBackend {
    /// Number of requests received so far.
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// Expose `upstream` blocks for backends by name, so a test reads as configuration.
#[derive(Default)]
pub struct Backends {
    entries: Vec<(&'static str, u16)>,
}

impl Backends {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a named backend and return the port it listens on.
    pub fn serve(mut self, name: &'static str, port: u16) -> Self {
        self.entries.push((name, port));
        self
    }

    /// Add a named backend that answers `<name> path=.. host=..`.
    pub fn named(mut self, name: &'static str) -> Self {
        let port = spawn_named_backend(name);
        self.entries.push((name, port));
        self
    }

    /// The `upstream ... { ... }` blocks for every backend, ready to concatenate into `http`.
    pub fn upstreams(&self) -> String {
        self.entries
            .iter()
            .map(|(name, port)| format!("upstream {name} {{ server 127.0.0.1:{port}; }}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn port(&self, name: &str) -> u16 {
        self.entries
            .iter()
            .find(|(entry, _)| *entry == name)
            .map(|(_, port)| *port)
            .unwrap_or_else(|| panic!("no backend named {name}"))
    }
}

/// A backend that records the request line of the last request it served.
pub fn spawn_counting_backend() -> (u16, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let shared = Arc::clone(&counter);
    let port = spawn_with(bind(0), move |stream| {
        let _ = read_request(stream);
        let n = shared.fetch_add(1, Ordering::SeqCst) + 1;
        write_close(stream, &format!("hit-{n}"));
    });
    (port, counter)
}

/// A backend that records the request line of the last request it served.
pub fn spawn_recording_backend() -> (u16, &'static std::sync::Mutex<String>) {
    let seen: &'static std::sync::Mutex<String> =
        Box::leak(Box::new(std::sync::Mutex::new(String::new())));
    let port = spawn_with(bind(0), move |stream| {
        let request = read_request(stream);
        *seen.lock().unwrap() = request.lines().next().unwrap_or("").to_string();
        write_close(stream, "ok");
    });
    (port, seen)
}