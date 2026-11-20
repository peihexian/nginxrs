//! Certificate selection (`ngx_http_ssl_servername` / `ngx_ssl_certificate_cb`),
//! client-certificate verification and the per-server rustls configuration.
//!
//! Nginx resolves the certificate in two steps: SNI picks the virtual server, then the
//! certificate is matched on hash, wildcard, regular expression and finally the `default`
//! marker. [`CertificateResolver`] reproduces that precedence.

use super::conf::{Protocols, TlsServerConf, VerifyClient};
use super::codec;
use super::crypto;
use crate::modules::http_core::{normalize_host, server_matches_names};
use anyhow::{Context, Result, bail};
use parking_lot::Mutex;
use pingora_rustls::{ClientCertVerified, ClientCertVerifier, ResolvesServerCert};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{DistinguishedName, server::ClientHello};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// `ngx_ssl_certificate` name type after `ngx_ssl_names_next`.
#[derive(Clone, Debug)]
pub enum CertSelector {
    /// `default` keyword.
    Default,
    /// Literal (lowercased) host name.
    Hash(String),
    /// `*.example.com` 闁?a leading wildcard label.
    Wildcard(String),
    /// `.example.com` 闁?matches the domain and every sub-domain.
    Suffix(String),
    /// `~^www\d+\.example\.com$` 闁?PCRE selector.
    Regex(regex::Regex),
}

impl CertSelector {
    pub fn parse(name: &str) -> Result<Self> {
        if name == "default" {
            return Ok(Self::Default);
        }
        let lower = name.to_ascii_lowercase();
        if let Some(pattern) = lower.strip_prefix('~') {
            let regex = regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .context("invalid ssl_certificate regular expression")?;
            return Ok(Self::Regex(regex));
        }
        if let Some(suffix) = lower.strip_prefix("*.") {
            return Ok(Self::Wildcard(format!(".{suffix}")));
        }
        if let Some(suffix) = lower.strip_prefix('.') {
            return Ok(Self::Suffix(format!(".{suffix}")));
        }
        Ok(Self::Hash(lower))
    }

    /// Match one SNI name. Wildcards only cover one additional label, as in
    /// `ngx_ssl_hostnames`/`ngx_ssl_certificate_hash`.
    pub fn matches(&self, sni: &str) -> bool {
        match self {
            Self::Default => false,
            Self::Hash(name) => name == sni,
            Self::Wildcard(suffix) => {
                // `*.example.com` covers `a.example.com` but not `example.com`.
                sni.len() > suffix.len()
                    && sni.ends_with(suffix.as_str())
                    && !sni[..sni.len() - suffix.len()].contains('.')
            }
            Self::Suffix(suffix) => {
                sni == suffix.trim_start_matches('.') || sni.ends_with(suffix.as_str())
            }
            Self::Regex(regex) => regex.is_match(sni),
        }
    }
}

/// One certificate plus the names it is selected by (`ssl_certificate` repeated).
#[derive(Clone)]
pub struct NamedCertificate {
    pub selectors: Vec<CertSelector>,
    pub certificate: Arc<CertifiedKey>,
    /// Certificate chain and key as loaded, kept for `-t` diagnostics.
    pub chain_len: usize,
}

/// Certificate resolver for one TLS `server {}` block.
pub struct CertificateResolver {
    /// Order of declaration; Nginx keeps the "default" certificate first.
    certificates: Vec<NamedCertificate>,
    /// If no name matches, Nginx's `cmp` order falls back to the default certificate.
    default_index: Option<usize>,
}

impl std::fmt::Debug for CertificateResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertificateResolver")
            .field("certificates", &self.certificates.len())
            .finish()
    }
}

impl CertificateResolver {
    pub fn new(certificates: Vec<NamedCertificate>) -> Self {
        let default_index = certificates
            .iter()
            .position(|entry| entry.selectors.is_empty())
            .or(if certificates.is_empty() { None } else { Some(0) });
        Self {
            certificates,
            default_index,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// `ngx_ssl_certificate_cb`: default first, then hash, then wildcard, then regex,
    /// then any certificate that declared a set of names.
    pub fn select(&self, sni: Option<&str>) -> Option<&Arc<CertifiedKey>> {
        let sni = sni.map(|value| value.trim_end_matches('.').to_ascii_lowercase());
        if let Some(sni) = sni.as_deref() {
            for kind in 0..4usize {
                for certificate in &self.certificates {
                    let matched = certificate.selectors.iter().any(|selector| {
                        let wanted = matches!(
                            (kind, selector),
                            (0, CertSelector::Hash(_))
                                | (1, CertSelector::Wildcard(_))
                                | (2, CertSelector::Regex(_))
                                | (3, _)
                        );
                        wanted && selector.matches(sni)
                    });
                    if matched {
                        return Some(&certificate.certificate);
                    }
                }
            }
        }
        self.default_index
            .and_then(|index| self.certificates.get(index))
            .map(|entry| &entry.certificate)
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.select(client_hello.server_name()).cloned()
    }
}

/// One trusted CA plus its pre-parsed validity window.
#[derive(Clone, Debug)]
pub struct TrustAnchor {
    pub certificate: CertificateDer<'static>,
    pub subject: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub is_ca: bool,
}

/// A loaded CA store (`ssl_client_certificate` / `ssl_trusted_certificate`).
#[derive(Clone, Debug, Default)]
pub struct CaStore {
    pub anchors: Vec<TrustAnchor>,
}

impl CaStore {
    pub fn from_file(path: &Path) -> Result<Self> {
        let certificates = codec::load_certificates(path, "ssl_client_certificate")?;
        let mut anchors = Vec::new();
        for certificate in certificates {
            let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
                .map_err(|error| {
                    anyhow::anyhow!(
                        "invalid X.509 certificate in {}: {error}",
                        path.display()
                    )
                })?;
            anchors.push(TrustAnchor {
                subject: parsed.subject().as_raw().to_vec(),
                not_before: parsed.validity().not_before.timestamp(),
                not_after: parsed.validity().not_after.timestamp(),
                is_ca: parsed
                    .basic_constraints()
                    .ok()
                    .flatten()
                    .map(|constraints| constraints.value.ca)
                    .unwrap_or(true),
                certificate,
            });
        }
        Ok(Self { anchors })
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// `ngx_http_ssl_verify_client`: verify the client chain against
/// `ssl_client_certificate`, with `ssl_verify_depth`.
///
/// `ngx_ssl_verify_callback` adds one to the configured depth before calling
/// `X509_verify_cert`: `ssl_verify_depth 1` therefore accepts the leaf plus one
/// intermediate. `optional_no_ca` only checks that the presented certificate is
/// well-formed and signed by its own key.
#[derive(Debug)]
pub struct ClientVerifier {
    store: CaStore,
    /// `NGX_HTTP_SSL_VERIFY_DEPTH` limit after Nginx's `+ 1` adjustment.
    max_chain: usize,
    mandatory: bool,
    /// `optional_no_ca`: present the request but accept unverifiable certificates.
    accept_untrusted: bool,
    schemes: Vec<SignatureScheme>,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for ClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // The leaf must always be a parsable X.509 certificate, exactly like
        // `SSL_get_peer_certificate` in Nginx.
        if x509_parser::parse_x509_certificate(end_entity.as_ref()).is_err() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        if self.accept_untrusted {
            return Ok(ClientCertVerified::assertion());
        }
        if self.store.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        self.verify_chain(end_entity, intermediates, now.as_secs() as i64)
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
            &self.provider.signature_verification_algorithms,
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
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// The subset of an X.509 certificate needed for issuer chain building.
struct ChainLink {
    subject: Vec<u8>,
    issuer: Vec<u8>,
    not_before: i64,
    not_after: i64,
    der: Vec<u8>,
}

impl ClientVerifier {
    /// Walk issuer links from the leaf to a trusted anchor, verifying each certificate's
    /// signature with the trust store's supported algorithms, like `X509_verify_cert`.
    fn verify_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: i64,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let mut links = Vec::new();
        for der in std::iter::once(end_entity.as_ref())
            .chain(intermediates.iter().map(|certificate| certificate.as_ref()))
        {
            match x509_parser::parse_x509_certificate(der) {
                Ok((_, parsed)) => links.push(ChainLink {
                    subject: parsed.subject().as_raw().to_vec(),
                    issuer: parsed.issuer().as_raw().to_vec(),
                    not_before: parsed.validity().not_before.timestamp(),
                    not_after: parsed.validity().not_after.timestamp(),
                    der: der.to_vec(),
                }),
                Err(_) => continue,
            }
        }
        if links.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let mut index = 0usize;
        let mut visited = vec![0usize];
        loop {
            let link = &links[index];
            if now < link.not_before || now > link.not_after {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired,
                ));
            }
            if visited.len() >= self.max_chain {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ));
            }
            let issuer = link.issuer.clone();
            // Try to terminate at a trusted anchor.
            for anchor in self.store.anchors.iter().filter(|anchor| anchor.is_ca) {
                if anchor.subject != issuer {
                    continue;
                }
                if now < anchor.not_before || now > anchor.not_after {
                    continue;
                }
                if self.verify_signature(&links[index], &anchor.certificate) {
                    return Ok(ClientCertVerified::assertion());
                }
            }
            // Otherwise continue with a presented intermediate signed by this certificate.
            let mut next = None;
            for (candidate_index, candidate) in links.iter().enumerate() {
                if candidate_index == 0 || visited.contains(&candidate_index) {
                    continue;
                }
                if candidate.subject != issuer {
                    continue;
                }
                if crypto::issuer_signed_child(&links[index].der, &candidate.der) {
                    next = Some(candidate_index);
                    break;
                }
            }
            match next {
                Some(candidate_index) => {
                    visited.push(candidate_index);
                    index = candidate_index;
                }
                None => {
                    return Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::UnknownIssuer,
                    ));
                }
            }
        }
    }

    fn verify_signature(&self, child: &ChainLink, issuer: &CertificateDer<'_>) -> bool {
        let _ = &self.provider;
        crypto::issuer_signed_child(&child.der, issuer.as_ref())
    }
}

/// Build the client verifier for a server, or `None` when client certificates are off.
pub fn build_client_verifier(
    conf: &TlsServerConf,
    provider: &Arc<CryptoProvider>,
) -> Result<Option<Arc<ClientVerifier>>> {
    let mode = conf.verify_client.unwrap_or(VerifyClient::Off);
    if mode == VerifyClient::Off {
        return Ok(None);
    }
    let store = match conf.client_certificate.as_deref() {
        Some(path) => CaStore::from_file(path)?,
        None => CaStore::default(),
    };
    Ok(Some(Arc::new(ClientVerifier {
        store,
        // `ngx_ssl_verify_callback`: depth = conf->verify_depth + 1, then the callback
        // compares `chain->error` at `depth >= verify_depth`.
        max_chain: conf.verify_depth.unwrap_or(1) as usize + 1,
        mandatory: mode == VerifyClient::On,
        accept_untrusted: mode == VerifyClient::OptionalNoCa,
        schemes: provider.signature_verification_algorithms.supported_schemes(),
        provider: provider.clone(),
    })))
}

/// Load every `ssl_certificate` pair of one server into a resolver.
pub fn load_resolver(conf: &TlsServerConf, provider: &Arc<CryptoProvider>) -> Result<CertificateResolver> {
    // `ssl_stapling_file`: the pre-fetched OCSP response stapled to the leaf certificate
    // (`ngx_ssl_stapling_file` reads it with `d2i_OCSP_RESPONSE`).
    // `ssl_stapling on` sources the response from `ssl_stapling_file` when set, otherwise
    // from `ssl_stapling_responder` (`ngx_ssl_stapling` → `ngx_ssl_stapling_responder`).
    let stapled = if conf.ocsp.stapling {
        match (&conf.ocsp.stapling_file, &conf.ocsp.stapling_responder) {
            (Some(path), _) => Some(load_stapled_response(path)?),
            (None, Some(responder)) => Some(fetch_stapled_response(conf, responder)?),
            (None, None) => None,
        }
    } else {
        None
    };
    let mut named = Vec::new();
    for pair in &conf.certificates {
        let chain = codec::load_certificates(&pair.certificate, "ssl_certificate")?;
        let key_path = pair.key.as_ref().context(
            "ssl_certificate without ssl_certificate_key (BIO_new_file() failed)",
        )?;
        let key = load_key(key_path)?;
        if !crypto::pair_matches(&chain, &key, provider.clone()) {
            bail!(
                "key values mismatch in {} / {}",
                pair.certificate.display(),
                key_path.display()
            );
        }
        let mut certified = rustls::sign::CertifiedKey::from_der(chain.clone(), key, provider)
            .map_err(|error| {
                anyhow::anyhow!(
                    "key values mismatch in {} / {}: {error}",
                    pair.certificate.display(),
                    key_path.display()
                )
            })?;
        if let Some(staple) = &stapled {
            certified.ocsp = Some(staple.clone());
        }
        let mut selectors = Vec::new();
        for name in &pair.selectors {
            selectors.push(CertSelector::parse(name)?);
        }
        named.push(NamedCertificate {
            selectors,
            chain_len: chain.len(),
            certificate: Arc::new(certified),
        });
    }
    Ok(CertificateResolver::new(named))
}

/// `ngx_ssl_stapling_responder`: build the OCSP request and fetch the response.
fn fetch_stapled_response(conf: &TlsServerConf, responder: &str) -> Result<Vec<u8>> {
    let pair = conf
        .certificates
        .first()
        .context("ssl_stapling_responder needs an ssl_certificate")?;
    let chain = codec::load_certificates(&pair.certificate, "ssl_certificate")?;
    let leaf = chain.first().context("empty ssl_certificate")?.clone();
    // The chain is leaf-first, so the issuer is the next certificate when present.
    let issuer = chain.get(1).cloned().unwrap_or(leaf.clone());
    let request = build_ocsp_request(leaf.as_ref(), issuer.as_ref());
    let response = super::stapling::fetch(responder, &request)?;
    // `ssl_stapling_verify on`: `ngx_ssl_stapling_verify` validates the response before
    // installing it, so a broken or unrelated staple never reaches a handshake.
    if conf.ocsp.stapling_verify {
        let verified = super::ocsp_verify::verify(response.as_slice(), leaf.as_ref(), issuer.as_ref())
            .with_context(|| format!("invalid OCSP response from {responder}"))?;
        if verified.status == super::ocsp_verify::CertStatus::Revoked {
            bail!("the certificate is revoked according to {responder}");
        }
    }
    Ok(response)
}

/// Minimal DER `OCSPRequest` with a single SHA-1 `CertID`, matching what
/// `ngx_event_openssl_stapling.c` sends (`OCSP_REQUEST` + one `OCSP_CERTID`).
fn build_ocsp_request(certificate: &[u8], issuer: &[u8]) -> Vec<u8> {
    let _ = certificate;
    fn der(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let length = payload.len();
        if length < 0x80 {
            out.push(length as u8);
        } else if length < 0x100 {
            out.push(0x81);
            out.push(length as u8);
        } else {
            out.push(0x82);
            out.push((length >> 8) as u8);
            out.push(length as u8);
        }
        out.extend_from_slice(payload);
        out
    }
    fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.iter().flat_map(|item| item.iter().copied()).collect();
        der(0x30, &payload)
    }
    let sha1_alg = sequence(&[der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]), der(0x05, &[])]);
    let digest = |bytes: &[u8]| -> Vec<u8> {
        use sha1::Digest;
        let mut hasher = sha1::Sha1::new();
        hasher.update(bytes);
        der(0x04, &hasher.finalize())
    };
    let name_hash = digest(issuer);
    let key_hash = digest(&subject_public_key_info(issuer));
    let cert_id = sequence(&[sha1_alg, name_hash, key_hash, der(0x02, &[0x00])]);
    let request = sequence(&[cert_id]);
    sequence(&[request])
}

/// The DER `SubjectPublicKeyInfo` of a certificate, used as the OCSP `KeyHash` input.
fn subject_public_key_info(certificate: &[u8]) -> Vec<u8> {
    // A full X.509 parse is unnecessary for a hash input: take the outermost SEQUENCE that
    // contains the RSA/EC algorithm identifier followed by a BIT STRING.
    let mut best = Vec::new();
    let mut index = 0;
    while index + 2 < certificate.len() {
        if certificate[index] == 0x30 {
            let length_byte = certificate[index + 1];
            let (header, length) = if length_byte < 0x80 {
                (2, length_byte as usize)
            } else {
                let count = (length_byte & 0x7f) as usize;
                if count == 0 || count > 2 || index + 2 + count > certificate.len() {
                    break;
                }
                let mut length = 0usize;
                for offset in 0..count {
                    length = (length << 8) | certificate[index + 2 + offset] as usize;
                }
                (2 + count, length)
            };
            if index + header + length <= certificate.len() && length > 40 {
                let inner = &certificate[index + header..index + header + length];
                if inner.len() > 8 && inner[0] == 0x30 && inner.contains(&0x03) {
                    best = certificate[index..index + header + length].to_vec();
                    break;
                }
            }
        }
        index += 1;
    }
    best
}

/// `ngx_ssl_stapling_file`: read a DER (or PEM) OCSP response for stapling.
fn load_stapled_response(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)
        .map_err(|error| anyhow::anyhow!("cannot load {}: {error}", path.display()))?;
    // A PEM-wrapped response (BEGIN OCSP RESPONSE) is accepted as well.
    if bytes.starts_with(b"-----BEGIN") {
        let text = String::from_utf8_lossy(&bytes);
        // The body starts after the first header line and ends at the END marker.
        let body_start = text.find("\n").map(|offset| offset + 1).unwrap_or(0);
        let body_end = text[body_start..]
            .find("-----END")
            .map(|offset| body_start + offset)
            .unwrap_or(text.len());
        let body: String = text[body_start..body_end]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        return base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body)
            .map_err(|error| anyhow::anyhow!("invalid ssl_stapling_file: {error}"));
    }
    if bytes.is_empty() {
        bail!("the stapling file {} is empty", path.display());
    }
    Ok(bytes)
}

fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {    let bundle = codec::parse_pem_file(path, "ssl_certificate_key")?;
    bundle
        .keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path.display()))
}

/// rustls protocol versions enabled by `ssl_protocols`.
pub fn protocol_versions(
    protocols: Protocols,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    let mut versions = Vec::new();
    if protocols.contains(Protocols(Protocols::TLSV1_3)) {
        versions.push(&rustls::version::TLS13);
    }
    if protocols.contains(Protocols(Protocols::TLSV1_2)) {
        versions.push(&rustls::version::TLS12);
    }
    if versions.is_empty() {
        bail!(
            "SSL_CTX_set_options() failed: ssl_protocols enables no protocol supported by nginxrs \
             (only TLSv1.2 and TLSv1.3 are available)"
        );
    }
    Ok(versions)
}

/// `ssl_session_timeout` on the rustls side.
pub fn session_timeout(_timeout: Duration) -> Duration {
    _timeout
}

/// `ssl_prefer_server_ciphers`: rustls never honours the client order.
pub struct ProviderSelection(pub Mutex<()>);

pub fn sni_matches_any(server_names: &[String], sni: &str) -> bool {
    let host = normalize_host(sni);
    server_matches_names(server_names, &host)
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn stapling_file_accepts_der_and_pem() {
        let dir = std::env::temp_dir().join(format!("nginxrs-ocsp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let der = dir.join("response.der");
        let payload = b"\x30\x03\x0a\x01\x00";
        std::fs::write(&der, payload).unwrap();
        assert_eq!(load_stapled_response(&der).unwrap(), payload);

        let pem = dir.join("response.pem");
        std::fs::write(
            &pem,
            "-----BEGIN OCSP RESPONSE-----\nMAMKAQA=\n-----END OCSP RESPONSE-----\n",
        )
        .unwrap();
        assert_eq!(load_stapled_response(&pem).unwrap(), payload);

        let empty = dir.join("empty.der");
        std::fs::write(&empty, b"").unwrap();
        assert!(load_stapled_response(&empty).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn selectors_parse_nginx_forms() {
        assert!(matches!(
            CertSelector::parse("default").unwrap(),
            CertSelector::Default
        ));
        assert!(matches!(
            CertSelector::parse("Example.COM").unwrap(),
            CertSelector::Hash(name) if name == "example.com"
        ));
        assert!(matches!(
            CertSelector::parse("*.example.com").unwrap(),
            CertSelector::Wildcard(suffix) if suffix == ".example.com"
        ));
        assert!(matches!(
            CertSelector::parse(".example.com").unwrap(),
            CertSelector::Suffix(suffix) if suffix == ".example.com"
        ));
        assert!(matches!(
            CertSelector::parse("~^www\\d+\\.example\\.com$").unwrap(),
            CertSelector::Regex(_)
        ));
    }

    #[test]
    fn wildcard_covers_one_label_only() {
        let selector = CertSelector::parse("*.example.com").unwrap();
        assert!(selector.matches("www.example.com"));
        assert!(!selector.matches("a.b.example.com"));
        assert!(!selector.matches("example.com"));
    }

    #[test]
    fn suffix_covers_the_domain_itself() {
        let selector = CertSelector::parse(".example.com").unwrap();
        assert!(selector.matches("example.com"));
        assert!(selector.matches("a.b.example.com"));
        assert!(!selector.matches("badexample.com"));
    }

    #[test]
    fn regex_selector_is_anchored_by_the_pattern() {
        let selector = CertSelector::parse("~^www[0-9]+\\.example\\.com$").unwrap();
        assert!(selector.matches("www1.example.com"));
        assert!(!selector.matches("wwwx.example.com"));
    }
}
