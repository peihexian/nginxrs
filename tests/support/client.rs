//! TLS clients: plain HTTPS, session reuse, client certificates and HTTP/2.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::tlsc::AcceptAnyCertificate;

fn server_name(sni: &str) -> rustls::pki_types::ServerName<'static> {
    sni.to_string().try_into().unwrap()
}

fn read_all(stream: &mut (impl Read + ?Sized)) -> String {
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

fn get_request(sni: &str, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n")
}

/// Trust the certificate files in `trusted` and GET `path` over TLS with the given SNI.
pub fn https_get(sni: &str, port: u16, path: &str, trusted: Vec<PathBuf>) -> String {
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
    https_get_with(Arc::new(config), sni, port, path)
}

/// GET over TLS with a prepared client configuration.
pub fn https_get_with(
    config: Arc<rustls::ClientConfig>,
    sni: &str,
    port: u16,
    path: &str,
) -> String {
    let socket = match TcpStream::connect(("127.0.0.1", port)) {
        Ok(socket) => socket,
        Err(_) => return String::new(),
    };
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let connection = match rustls::ClientConnection::new(config, server_name(sni)) {
        Ok(connection) => connection,
        Err(_) => return String::new(),
    };
    let mut stream = rustls::StreamOwned::new(connection, socket);
    if stream.write_all(get_request(sni, path).as_bytes()).is_err() {
        return String::new();
    }
    read_all(&mut stream)
}

/// A TLS GET that records the session for a later `https_get_session` call.
pub fn https_get_session(
    config: Arc<rustls::ClientConfig>,
    sni: &str,
    port: u16,
    path: &str,
    _previous: Option<&str>,
) -> String {
    https_get_with(config, sni, port, path)
}

/// GET over TLS accepting any server certificate: use when the test starts its own CA.
pub fn https_get_any(sni: &str, port: u16, path: &str) -> String {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate::new()))
        .with_no_client_auth();
    https_get_with(Arc::new(config), sni, port, path)
}

/// Build a TLS client which offers only `h2` and returns the negotiated connection.
pub fn h2_client(
    cert: &Path,
    sni: &str,
    port: u16,
) -> Option<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    let data = std::fs::read(cert).ok()?;
    for item in rustls_pemfile::certs(&mut data.as_slice()) {
        roots.add(item.ok()?).ok()?;
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector =
        rustls::ClientConnection::new(Arc::new(config), sni.to_string().try_into().ok()?).ok()?;
    let socket = TcpStream::connect(("127.0.0.1", port)).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    Some(rustls::StreamOwned::new(connector, socket))
}

/// A client configuration that requires `roots` as trust anchors and offers only HTTP/1.1.
pub fn client_trusting(roots: &[&Path]) -> Arc<rustls::ClientConfig> {
    let mut store = rustls::RootCertStore::empty();
    for file in roots {
        let data = std::fs::read(file).unwrap();
        for item in rustls_pemfile::certs(&mut data.as_slice()) {
            store.add(item.unwrap()).unwrap();
        }
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// A root store containing the certificates in `files`.
pub fn roots(files: &[&Path]) -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    for file in files {
        let data = std::fs::read(file).unwrap();
        for item in rustls_pemfile::certs(&mut data.as_slice()) {
            store.add(item.unwrap()).unwrap();
        }
    }
    store
}
/// A client configuration that trusts `roots` and presents a client certificate.
pub fn client_with_certificate(
    roots: &[&Path],
    cert: &Path,
    key: &Path,
) -> Arc<rustls::ClientConfig> {
    let mut store = rustls::RootCertStore::empty();
    for file in roots {
        let data = std::fs::read(file).unwrap();
        for item in rustls_pemfile::certs(&mut data.as_slice()) {
            store.add(item.unwrap()).unwrap();
        }
    }
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
        .with_root_certificates(store)
        .with_client_auth_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}