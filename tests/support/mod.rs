//! Shared end-to-end test support.
//!
//! Every integration test binary owns its own copy of this crate (Cargo compiles each file
//! under `tests/` as a separate crate), so the modules here are shared by path, not by a
//! library:
//!
//! ```ignore
//! #[path = "support/mod.rs"]
//! mod support;
//! ```
//!
//! `dead_code` is allowed because each binary pulls in the whole support surface while
//! using only the part its own tests need.
#![allow(dead_code, unused_imports)]

pub mod backend;
pub mod cert;
pub mod client;
pub mod http;
pub mod server;
pub mod tlsc;

pub use backend::{EchoBackend, Backends};
pub use cert::{Certificates, OpenSsl};
pub use client::{h2_client, https_get, https_get_session, https_get_with};
pub use http::{assert_response, assert_status, body, header, headers, request, status};
pub use http::try_header;
pub use server::{
    ChildGuard, Server, config_path, free_port, run, start, temp_path, wait_until_closed,
    wait_until_ready,
};
pub use tlsc::AcceptAnyCertificate;

/// A scratch directory plus the free port the configuration should listen on.
///
/// Tests that need a working directory and the server port start from this:
///
/// ```ignore
/// let env = Env::new();
/// let config = format!("http {{ server {{ listen 127.0.0.1:{}; }} }}", env.port);
/// let server = env.start(&config);
/// ```
pub struct Env {
    pub temp: tempfile::TempDir,
    pub port: u16,
}

impl Env {
    pub fn new() -> Self {
        Self {
            temp: tempfile::tempdir().expect("temporary directory"),
            port: free_port(),
        }
    }

    /// Directory for files the test creates next to the configuration.
    pub fn path(&self) -> &std::path::Path {
        self.temp.path()
    }

    /// Write `config` into the temporary directory and start nginxrs on `self.port`.
    pub fn start(&self, config: &str) -> ChildGuard {
        start(config, self.port, self.path())
    }

    /// Write `config` and start nginxrs on `self.port`, returning the running server.
    pub fn serve(&self, config: &str) -> Server<'_> {
        let guard = self.start(config);
        Server::new(guard, self.port)
    }

    /// A path inside the temporary directory, written with `/` separators for nginx configs.
    pub fn config_path(&self, name: &str) -> String {
        self.path().join(name).to_string_lossy().replace('\\', "/")
    }
}

impl Default for Env {
    fn default() -> Self {
        Self::new()
    }
}
