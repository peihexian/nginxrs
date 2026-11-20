//! Upstream TLS for `proxy_pass https://` (`ngx_http_proxy_module` SSL directives).
//!
//! Nginx builds one `SSL_CTX` per `proxy_pass` location (`ngx_http_proxy_set_ssl`) from
//! `proxy_ssl_protocols`, `proxy_ssl_ciphers`, `proxy_ssl_trusted_certificate`,
//! `proxy_ssl_crl`, `proxy_ssl_verify` and `proxy_ssl_verify_depth`, and sends SNI when
//! `proxy_ssl_server_name` is `on` (default `off`). The client below mirrors that with
//! rustls; the peer supplies the address and SNI name.

use crate::modules::proxy::ProxyConf;
use anyhow::{Context, Result, bail};
use pingora_core::upstreams::peer::HttpPeer;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::sync::Arc;
use tokio_rustls::TlsConnector;

/// Build the TLS client for one `proxy_pass https://` location.
pub fn client(peer: &HttpPeer, conf: &ProxyConf) -> Result<TlsConnector> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = crate::modules::ssl::config::select_cipher_suites(
        &conf.ssl_ciphers,
        conf.ssl_protocols,
        &Arc::new(provider.clone()),
    )
    .context("proxy_ssl_ciphers")?;

    let versions = crate::modules::ssl::certificates::protocol_versions(conf.ssl_protocols)
        .context("proxy_ssl_protocols")?;
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)
        .context("proxy_ssl_protocols")?;

    let mut config;
    if conf.ssl_verify {
        let mut roots = RootCertStore::empty();
        match conf.ssl_trusted_certificate.as_deref() {
            Some(path) => {
                let certificates = crate::modules::ssl::codec::load_certificates(
                    path,
                    "proxy_ssl_trusted_certificate",
                )?;
                for certificate in certificates {
                    roots
                        .add(certificate)
                        .context("invalid proxy_ssl_trusted_certificate")?;
                }
            }
            None => {
                for certificate in
                    pingora_rustls::load_native_certs().context("cannot load system certificates")?
                {
                    roots.add(certificate).ok();
                }
            }
        }
        let crls = match conf.ssl_crl.as_deref() {
            Some(path) => crate::modules::ssl::codec::parse_pem_file(path, "proxy_ssl_crl")?.crls,
            None => Vec::new(),
        };
        // `proxy_ssl_verify_depth` bounded the chain length in OpenSSL; rustls validates the
        // whole presented chain, so the directive is accepted for compatibility.
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .with_crls(crls)
            .build()
            .context("cannot build the upstream certificate verifier")?;
        config = builder.with_webpki_verifier(verifier).with_no_client_auth();
    } else {
        // `proxy_ssl_verify off` (the Nginx default): accept any upstream certificate.
        config = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
            .with_no_client_auth();
    }
    // `proxy_ssl_server_name on` gates SNI; rustls always sends it, and the peer always
    // carries a name, so the default (`off`) uses that name as `proxy_ssl_name` would.
    config.enable_sni = conf.ssl_server_name || !peer.sni.is_empty();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// `ngx_http_upstream_ssl_init_connection`: run the handshake against the upstream.
pub async fn connect(
    connector: &TlsConnector,
    stream: pingora_core::protocols::Stream,
    peer: &HttpPeer,
) -> Result<UpstreamTls> {
    let name = ServerName::try_from(peer.sni.clone())
        .context("invalid upstream name for the TLS handshake")?;
    if name.to_str().is_empty() {
        bail!("the upstream name used for the TLS handshake is empty");
    }
    let stream = connector
        .connect(name, stream)
        .await
        .context("upstream TLS handshake")?;
    Ok(UpstreamTls { inner: stream })
}

/// The TLS client stream to an upstream, usable as a pingora transport (`IO`).
pub struct UpstreamTls {
    inner: tokio_rustls::client::TlsStream<pingora_core::protocols::Stream>,
}

impl std::fmt::Debug for UpstreamTls {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UpstreamTls")
    }
}

impl tokio::io::AsyncRead for UpstreamTls {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for UpstreamTls {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait::async_trait]
impl pingora_core::protocols::Shutdown for UpstreamTls {
    async fn shutdown(&mut self) {
        use tokio::io::AsyncWriteExt;
        let _ = AsyncWriteExt::shutdown(&mut self.inner).await;
    }
}

impl pingora_core::protocols::UniqueID for UpstreamTls {
    fn id(&self) -> pingora_core::protocols::UniqueIDType {
        self.inner.get_ref().0.id()
    }
}

impl pingora_core::protocols::Ssl for UpstreamTls {}

impl pingora_core::protocols::GetTimingDigest for UpstreamTls {
    fn get_timing_digest(
        &self,
    ) -> Vec<Option<pingora_core::protocols::TimingDigest>> {
        self.inner.get_ref().0.get_timing_digest()
    }
}

impl pingora_core::protocols::GetProxyDigest for UpstreamTls {
    fn get_proxy_digest(
        &self,
    ) -> Option<Arc<pingora_core::protocols::raw_connect::ProxyDigest>> {
        self.inner.get_ref().0.get_proxy_digest()
    }
}

impl pingora_core::protocols::GetSocketDigest for UpstreamTls {
    fn get_socket_digest(&self) -> Option<Arc<pingora_core::protocols::SocketDigest>> {
        self.inner.get_ref().0.get_socket_digest()
    }
}

impl pingora_core::protocols::Peek for UpstreamTls {}

/// `proxy_ssl_verify off`: accept any upstream certificate.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
