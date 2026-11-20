//! Starting and stopping a real nginxrs process.

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A spawned server that is killed when the guard is dropped, so a failing assertion never
/// leaves a listener behind.
pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl ChildGuard {
    /// Wait for the process to exit and return its status.
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.0.wait()
    }

    pub fn id(&self) -> u32 {
        self.0.id()
    }
}

/// The path to the nginxrs binary Cargo built for this test run.
pub const BINARY: &str = env!("CARGO_BIN_EXE_nginxrs");

/// One `nginxrs` invocation with its output captured.
pub fn run<I, S>(args: I) -> std::process::Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(BINARY).args(args).output().expect("run nginxrs")
}

/// Start nginxrs with the given configuration and wait for its listener.
pub fn start(config: &str, port: u16, temp: &Path) -> ChildGuard {
    let config_path = temp.join("nginx.conf");
    std::fs::write(&config_path, config).unwrap();
    let child = Command::new(BINARY)
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

/// A started server bound to one port, with a helper for talking to it.
pub struct Server<'a> {
    guard: ChildGuard,
    port: u16,
    _env: std::marker::PhantomData<&'a ()>,
}

impl<'a> Server<'a> {
    pub fn new(guard: ChildGuard, port: u16) -> Self {
        Self {
            guard,
            port,
            _env: std::marker::PhantomData,
        }
    }

    /// Send a raw HTTP/1.1 request and return the raw response.
    pub fn request(&self, request: &str) -> String {
        crate::support::http::request(self.port, request)
    }

    /// GET `path` with `Host: localhost`.
    pub fn get(&self, path: &str) -> String {
        self.request(&format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        ))
    }

    /// GET `path` with a custom `Host` header.
    pub fn get_host(&self, host: &str, path: &str) -> String {
        self.request(&format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The running process, for tests that stop or reload it.
    pub fn child(&mut self) -> &mut Child {
        &mut self.guard.0
    }
}

/// An unused loopback port. The port is released before it is returned, so tests using it
/// must start their listener promptly.
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Wait for the server to accept connections, or report why it never did.
pub fn wait_until_ready(port: u16, config_path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Surface the server's own error instead of only the connection refusal.
    let output = Command::new(BINARY)
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

/// Wait until nothing accepts connections on `port`, or fail.
pub fn wait_until_closed(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the listener on port {port} is still open");
}

/// A path written with `/` separators, for use inside a configuration file.
pub fn config_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// The temporary directory of a test, canonicalised so configuration paths are absolute.
pub fn temp_path(temp: &tempfile::TempDir) -> PathBuf {
    temp.path()
        .canonicalize()
        .unwrap_or_else(|_| temp.path().to_path_buf())
}
