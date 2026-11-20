//! TLS termination for one downstream connection.
//!
//! Nginx's `ngx_http_ssl_servername` runs during the handshake: the SNI name selects the
//! virtual server, whose `SSL_CTX` carries the certificate list, protocol versions, ciphers
//! and client-certificate policy. nginxrs does the same with
//! [`tokio_rustls::LazyConfigAcceptor`]: the ClientHello is read once, the server is chosen
//! from its SNI name, and the rest of the handshake runs with that server's configuration.
//!
//! The resulting facts are attached to the stream; the HTTP engine reads them to resolve the
//! `$ssl_*` variables without touching the TLS session again.

use crate::core::http_core::ListenerTls;
use crate::modules::ssl::variables::SslSession;
use anyhow::{Result, bail};
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, Ssl, TimingDigest,
    UniqueID, UniqueIDType, raw_connect::ProxyDigest, tls::SslDigest, SocketDigest, ALPN,
};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::server::TlsStream;

/// A TLS-terminated downstream connection plus its handshake facts.
pub struct DownstreamTls {
    inner: TlsStream<pingora_core::protocols::Stream>,
    /// `$ssl_*` facts (`ngx_http_ssl_variable`).
    pub facts: Arc<SslSession>,
    /// `server {}` selected by SNI (`ngx_http_ssl_servername`).
    pub server_index: usize,
    /// Bytes returned by `peek` that the next read must replay.
    peeked: Vec<u8>,
}

impl DownstreamTls {
    /// The underlying TCP/UDS stream, for socket digests.
    pub fn inner(&self) -> &pingora_core::protocols::Stream {
        self.inner.get_ref().0
    }

    fn session(&self) -> &rustls::ServerConnection {
        self.inner.get_ref().1
    }
}

impl std::fmt::Debug for DownstreamTls {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DownstreamTls")
            .field("server_index", &self.server_index)
            .field("protocol", &self.facts.protocol)
            .field("cipher", &self.facts.cipher)
            .finish()
    }
}

impl AsyncRead for DownstreamTls {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Replay bytes handed out by `try_peek` before reading more TLS records.
        if !self.peeked.is_empty() {
            let count = self.peeked.len().min(buf.remaining());
            buf.put_slice(&self.peeked[..count]);
            self.peeked.drain(..count);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DownstreamTls {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[async_trait::async_trait]
impl Shutdown for DownstreamTls {
    async fn shutdown(&mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = AsyncWriteExt::shutdown(&mut self.inner).await;
    }
}

impl UniqueID for DownstreamTls {
    fn id(&self) -> UniqueIDType {
        self.inner.get_ref().0.id()
    }
}

impl Ssl for DownstreamTls {
    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        let session = self.session();
        let cipher = session
            .negotiated_cipher_suite()
            .and_then(|suite| suite.suite().as_str())
            .unwrap_or_default();
        let version = session
            .protocol_version()
            .and_then(|version| version.as_str())
            .unwrap_or_default();
        let cert = session
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| {
                ring::digest::digest(&ring::digest::SHA256, cert.as_ref())
                    .as_ref()
                    .to_vec()
            })
            .unwrap_or_default();
        let (organization, serial) = session
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|cert| {
                let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
                Some((
                    Some(parsed.subject().to_string()),
                    Some(parsed.tbs_certificate.raw_serial_as_string()),
                ))
            })
            .unwrap_or_default();
        Some(Arc::new(SslDigest::new(
            cipher.to_string(),
            version.to_string(),
            organization,
            serial,
            cert,
        )))
    }

    fn selected_alpn_proto(&self) -> Option<ALPN> {
        self.session()
            .alpn_protocol()
            .and_then(|protocol| match protocol {
                b"h2" => Some(ALPN::H2),
                b"http/1.1" => Some(ALPN::H1),
                _ => None,
            })
    }
}

impl GetTimingDigest for DownstreamTls {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.inner.get_ref().0.get_timing_digest()
    }
}

impl GetProxyDigest for DownstreamTls {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.inner.get_ref().0.get_proxy_digest()
    }
}

impl GetSocketDigest for DownstreamTls {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.inner.get_ref().0.get_socket_digest()
    }
}

#[async_trait::async_trait]
impl Peek for DownstreamTls {
    /// Peek the first bytes of the next HTTP request without consuming them, matching
    /// `ngx_http_wait_request_handler`'s look at the request line for h2c detection.
    async fn try_peek(&mut self, buf: &mut [u8]) -> std::io::Result<bool> {
        use tokio::io::AsyncReadExt;
        let count = self.inner.read(buf).await?;
        if count == 0 {
            return Ok(false);
        }
        self.peeked = buf[..count].to_vec();
        Ok(true)
    }
}

/// Perform the TLS handshake for one accepted downstream connection.
///
/// `deadline` bounds the whole handshake, like Nginx's `ssl_handshake_timeout`.
pub async fn accept(
    stream: pingora_core::protocols::Stream,
    tls: &ListenerTls,
    deadline: std::time::Duration,
) -> Result<DownstreamTls> {
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    let start = match tokio::time::timeout(deadline, acceptor).await {
        Ok(Ok(start)) => start,
        Ok(Err(error)) => bail!("{error}"),
        Err(_) => bail!("ssl_handshake_timeout"),
    };
    let sni = start.client_hello().server_name().map(str::to_string);
    // `ngx_http_ssl_servername` tail: a server with `ssl_reject_handshake on` answers the
    // handshake with `unrecognized_name` instead of presenting a certificate.
    if tls
        .hosts
        .select(sni.as_deref())
        .reject_handshake
    {
        bail!("ssl_reject_handshake: unrecognized_name");
    }
    let (index, config) = tls.hosts.resolve(sni.as_deref());
    let negotiated = config.clone();
    let stream = match tokio::time::timeout(deadline, start.into_stream(config)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => bail!("{error}"),
        Err(_) => bail!("ssl_handshake_timeout"),
    };
    let facts = Arc::new(ssl_session(&stream, &negotiated, sni));
    tls.note_handshake(&facts);
    Ok(DownstreamTls {
        inner: stream,
        facts,
        server_index: index,
        peeked: Vec::new(),
    })
}

/// Capture `ngx_http_ssl_variable` facts from the completed connection.
fn ssl_session(
    stream: &TlsStream<pingora_core::protocols::Stream>,
    _config: &rustls::ServerConfig,
    sni: Option<String>,
) -> SslSession {
    let (_io, session) = stream.get_ref();
    let protocol = session
        .protocol_version()
        .and_then(|version| version.as_str())
        .map(str::to_string);
    let cipher = session
        .negotiated_cipher_suite()
        .and_then(|suite| suite.suite().as_str())
        .map(str::to_string);
    let alpn = session
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).to_string());
    let client_chain: Vec<Vec<u8>> = session
        .peer_certificates()
        .map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
        .unwrap_or_default();
    let presented = !client_chain.is_empty();
    let early_data = session
        .negotiated_key_exchange_group()
        .is_some()
        && session
            .handshake_kind()
            .is_some_and(|kind| matches!(kind, rustls::HandshakeKind::Full));
    SslSession {
        protocol,
        cipher,
        session_id: None,
        session_reused: matches!(
            session.handshake_kind(),
            Some(rustls::HandshakeKind::Resumed)
        ),
        server_name: sni,
        alpn_protocol: alpn,
        early_data,
        client_presented: presented,
        // A completed handshake means the verifier accepted the chain; the verifier decides
        // whether an untrusted certificate is accepted (`optional_no_ca`).
        client_verify_ok: presented,
        client_unverified: false,
        client_chain,
    }
}
