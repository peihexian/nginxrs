//! Configuration reloading.
//!
//! Nginx reloads with `SIGHUP` (or `nginx -s reload`): the master re-reads the
//! configuration, validates it, then starts new workers while old ones finish in-flight
//! requests.
//!
//! nginxrs keeps a single process and swaps the routing table atomically:
//!
//! 1. Parse and compile the configuration into a fresh [`Engine`](crate::core::http_core::Engine).
//! 2. On failure, log the error and keep serving with the current engine — a broken
//!    configuration never takes the server down (Nginx behaves the same way).
//! 3. On success, `ArcSwap::store` the new engine. In-flight requests keep the snapshot
//!    they started with; new requests see the new routes immediately.
//!
//! Triggers: `SIGHUP` on Unix and `nginxrs -c <conf> -s reload`, which talks to a small
//! loopback control endpoint whose port is written next to the pid file
//! (`<pidfile>.ctl`). The latter also works on Windows, where `SIGHUP` does not exist.

use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const RELOAD: &str = "reload";
pub const STOP: &str = "stop";

/// Path of the control endpoint descriptor, stored next to the pid file.
pub fn control_path(pid_file: &Path) -> PathBuf {
    let mut name = pid_file.as_os_str().to_os_string();
    name.push(".ctl");
    PathBuf::from(name)
}

/// Handle used by the reload listener to swap the live configuration.
pub struct Reloader {
    pub config_path: PathBuf,
    pub swap: Arc<dyn Fn() -> Result<()> + Send + Sync>,
}

impl Reloader {
    pub fn reload(&self) -> Result<()> {
        (self.swap)()
    }
}

/// Runs the control endpoint in the background until the process exits.
///
/// Each accepted connection reads one command line and answers `ok` or `error: ...`.
pub fn serve_control(
    listener: TcpListener,
    reloader: Arc<Reloader>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    std::thread::spawn(move || {
        while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = handle_control(stream, &reloader);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
    });
    Ok(())
}

fn handle_control(stream: TcpStream, reloader: &Reloader) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = match line.trim() {
        RELOAD => match reloader.reload() {
            Ok(()) => format!("ok {}\n", reloader.config_path.display()),
            Err(error) => format!("error: {error:#}\n"),
        },
        STOP => "ok stopping\n".to_string(),
        other => format!("error: unknown command \"{other}\"\n"),
    };
    let mut stream = stream;
    stream.write_all(response.as_bytes())?;
    Ok(())
}

/// Sends `reload` to a running server and returns its answer.
pub fn request_reload(pid_file: &Path) -> Result<String> {
    let control = control_path(pid_file);
    let address = std::fs::read_to_string(&control).with_context(|| {
        format!(
            "cannot read control descriptor {}; is nginxrs running with this pid file?",
            control.display()
        )
    })?;
    send(&address, RELOAD)
}

/// Sends `stop` to a running server and returns its answer.
pub fn request_stop(pid_file: &Path) -> Result<String> {
    let control = control_path(pid_file);
    let address = std::fs::read_to_string(&control)
        .with_context(|| format!("cannot read control descriptor {}", control.display()))?;
    send(&address, STOP)
}

fn send(address: &str, command: &str) -> Result<String> {
    let mut stream = TcpStream::connect(address.trim())
        .with_context(|| format!("cannot connect to control endpoint {address}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    writeln!(stream, "{command}")?;
    let mut answer = String::new();
    BufReader::new(stream).read_line(&mut answer)?;
    if answer.starts_with("error:") {
        bail!("{}", answer.trim_start_matches("error:").trim());
    }
    Ok(answer.trim().to_string())
}

/// Writes the control endpoint address next to the pid file.
pub fn publish_control(pid_file: &Path, address: &str) -> Result<()> {
    let path = control_path(pid_file);
    std::fs::write(&path, address)
        .with_context(|| format!("cannot write control descriptor {}", path.display()))?;
    Ok(())
}

/// Removes pid and control descriptors on shutdown.
pub fn remove_descriptors(pid_file: &Path) {
    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_file(control_path(pid_file));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_path_appends_suffix() {
        assert_eq!(
            control_path(Path::new("run/nginxrs.pid")),
            PathBuf::from("run/nginxrs.pid.ctl")
        );
    }

    #[test]
    fn reload_command_round_trips_through_the_control_endpoint() {
        let temp = tempfile::tempdir().unwrap();
        let pid_file = temp.path().join("nginxrs.pid");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let called = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = called.clone();
        let reloader = Arc::new(Reloader {
            config_path: PathBuf::from("nginxrs.conf"),
            swap: Arc::new(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }),
        });
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        serve_control(listener, reloader, shutdown.clone()).unwrap();
        publish_control(&pid_file, &address).unwrap();

        let answer = request_reload(&pid_file).unwrap();
        assert!(answer.starts_with("ok"), "{answer}");
        assert_eq!(called.load(std::sync::atomic::Ordering::SeqCst), 1);
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn failed_reload_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        let pid_file = temp.path().join("nginxrs.pid");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let reloader = Arc::new(Reloader {
            config_path: PathBuf::from("broken.conf"),
            swap: Arc::new(|| bail!("unknown directive \"broken\"")),
        });
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        serve_control(listener, reloader, shutdown.clone()).unwrap();
        publish_control(&pid_file, &address).unwrap();

        let error = request_reload(&pid_file).unwrap_err().to_string();
        assert!(error.contains("unknown directive"), "{error}");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}
