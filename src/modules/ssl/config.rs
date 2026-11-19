//! Per-server TLS configuration.
//!
//! Builds the rustls `ServerConfig` for every TLS `server {}` block: protocol versions,
//! cipher suites (`ssl_ciphers`), key exchange groups (`ssl_ecdh_curve`), SNI certificate
//! selection, client certificate verification (`ssl_verify_client`), session resumption
//! (`ssl_session_cache` / `ssl_session_tickets`) and the handshake buffer size
//! (`ssl_buffer_size`).

use super::certificates::{self, CertificateResolver};
use super::conf::{Protocols, TlsServerConf};
use super::sessions::{SessionCache, SharedCaches};
use anyhow::{Context, Result, bail};
use parking_lot::Mutex;
use rustls::crypto::CryptoProvider;
use rustls::server::{NoServerSessionStorage, StoresServerSessions};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::Arc;

/// The crypto provider shared by every listener: rustls' `ring` backend, which supports
/// the TLS 1.2 AEAD suites and the three key exchange groups Nginx maps from
/// `ssl_ecdh_curve`.
pub fn provider() -> Arc<CryptoProvider> {
    pingora_rustls::install_default_crypto_provider();
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

/// Cipher suites enabled by `ssl_ciphers`, in the order of the `OPENSSL` cipher list.
///
/// rustls only implements AEAD suites plus ChaCha20-Poly1305, so the supported set is:
///
/// | OpenSSL name | rustls suite |
/// |---|---|
/// | `ECDHE-ECDSA-AES128-GCM-SHA256` | `TLS13_AES_128_GCM_SHA256` / `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` |
/// | `ECDHE-RSA-AES128-GCM-SHA256` | `ECDHE_RSA_WITH_AES_128_GCM_SHA256` |
/// | `ECDHE-ECDSA-AES256-GCM-SHA384` | `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` |
/// | `ECDHE-RSA-AES256-GCM-SHA384` | `ECDHE_RSA_WITH_AES_256_GCM_SHA384` |
/// | `ECDHE-ECDSA-CHACHA20-POLY1305` | `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` |
/// | `ECDHE-RSA-CHACHA20-POLY1305` | `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` |
/// | `AES128-GCM-SHA256` | `AES_128_GCM_SHA256` (non-ECDHE, not implemented by rustls) |
///
/// Unknown or unsupported cipher names are rejected the way `SSL_CTX_set_cipher_list`
/// reports `SSL_CTX_set_cipher_list("...") failed`.
pub fn select_cipher_suites(
    expression: &str,
    versions: Protocols,
    provider: &Arc<CryptoProvider>,
) -> Result<Vec<rustls::SupportedCipherSuite>> {
    let available: Vec<rustls::SupportedCipherSuite> = provider.cipher_suites.clone();
    let all_names: Vec<&str> = available
        .iter()
        .filter_map(|suite| suite.suite().as_str())
        .collect();
    let selected = apply_cipher_expression(expression, &all_names)
        .map_err(|error| anyhow::anyhow!("SSL_CTX_set_cipher_list(\"{expression}\") failed: {error}"))?;
    let mut suites: Vec<rustls::SupportedCipherSuite> = Vec::new();
    for name in &selected {
        if let Some(suite) = available
            .iter()
            .find(|suite| suite.suite().as_str() == Some(name.as_str()))
        {
            suites.push(*suite);
        }
    }
    // `SSL_CTX_set_cipher_list` only covers TLS 1.2 and below: OpenSSL keeps the TLS 1.3
    // defaults (`SSL_CTX_set_ciphersuites`) unless asked otherwise, so TLS 1.3 suites are
    // prepended in the provider order.
    if versions.contains(Protocols(Protocols::TLSV1_3)) {
        let mut ordered: Vec<rustls::SupportedCipherSuite> = available
            .iter()
            .copied()
            .filter(|suite| suite.version() == &rustls::version::TLS13)
            .collect();
        ordered.extend(
            suites
                .iter()
                .copied()
                .filter(|suite| suite.version() != &rustls::version::TLS13),
        );
        suites = ordered;
    }
    suites.retain(|suite| {
        if suite.version() == &rustls::version::TLS13 {
            versions.contains(Protocols(Protocols::TLSV1_3))
        } else {
            versions.contains(Protocols(Protocols::TLSV1_2))
        }
    });
    if suites.is_empty() {
        bail!("no cipher suite from ssl_ciphers is supported for the enabled protocols");
    }
    Ok(suites)
}

/// Evaluate an OpenSSL cipher string (`HIGH:!aNULL:!MD5:ECDHE+AESGCM`) against the rustls
/// suite names.
///
/// The grammar follows `ssl_cipher_get/ssl_cipher_list/ssl_cipher_strength_sort` in
/// OpenSSL's `ssl/ssl_ciph.c`: `+`, `-`, `@`, `!`, `*`, `:` separated items, `ALL`, `COMPLEMENTOFALL`,
/// `COMPLEMENTOFDEFAULT`, and the selector keywords used by Nginx.
pub fn apply_cipher_expression(expression: &str, suites: &[&str]) -> Result<Vec<String>> {
    let mut result: Vec<String> = Vec::new();
    for item in expression.split(':') {
        if item.is_empty() {
            continue;
        }
        let (operation, rest) = match item.as_bytes()[0] {
            b'!' => ('!', &item[1..]),
            b'-' => ('-', &item[1..]),
            b'+' => ('+', &item[1..]),
            b'@' => ('@', &item[1..]),
            _ => ('=', item),
        };
        let matched: Vec<String> = if let Some(keyword) = Keyword::parse(rest) {
            keyword.matches(suites)
        } else {
            let mut names: Vec<String> = Vec::new();
            for alias in rest.split('+') {
                names.extend(alias_matches(alias, suites));
            }
            names
        };
        if matched.is_empty() && operation == '=' {
            bail!("no ciphers available for {rest}");
        }
        match operation {
            '=' => {
                if result.is_empty() {
                    result.extend(matched);
                } else {
                    result.retain(|name| !matched.contains(name));
                    result.extend(matched);
                }
            }
            // `!` removes from the configured list, or from `ALL` when it is still empty
            // (OpenSSL starts the list from the default set).
            '!' => {
                if result.is_empty() {
                    result.extend(suites.iter().map(|name| name.to_string()));
                }
                result.retain(|name| !matched.contains(name));
            }
            '-' => {
                if !result.is_empty() {
                    result.retain(|name| !matched.contains(name));
                }
            }
            '+' => {
                if result.is_empty() {
                    result.extend(matched);
                }
            }
            '@' => {}
            _ => {}
        }
    }
    if result.is_empty() {
        // `ERROR` when nothing matched is reported by the caller.
        return Ok(Vec::new());
    }
    Ok(result)
}

/// OpenSSL cipher keywords supported for `ssl_ciphers`.
enum Keyword {
    All,
    ComplementOfAll,
    ComplementOfDefault,
    High,
    Default,
    Aead,
}

impl Keyword {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "ALL" => Some(Self::All),
            "COMPLEMENTOFALL" => Some(Self::ComplementOfAll),
            "COMPLEMENTOFDEFAULT" => Some(Self::ComplementOfDefault),
            // rustls only implements high-strength AEAD suites, so every strength and
            // algorithm selector Nginx configs use (`HIGH`, `AES`, `AESGCM`, `CHACHA20`,
            // `ECDHE`, `kECDHE`, `aRSA`, `aECDSA`) resolves to that one set.
            "HIGH" | "AES" | "AESGCM" | "CHACHA20" | "ECDHE" | "EECDH" | "kECDHE" | "aRSA" | "aECDSA" => {
                Some(Self::High)
            }
            "DEFAULT" => Some(Self::Default),
            "AEAD" => Some(Self::Aead),
            _ => None,
        }
    }

    fn matches(&self, suites: &[&str]) -> Vec<String> {
        suites
            .iter()
            .filter(|_name| match self {
                Self::All => true,
                // Everything rustls implements is high strength and AEAD.
                Self::High => true,
                Self::Default => true,
                Self::ComplementOfAll | Self::ComplementOfDefault => false,
                // Every suite rustls implements is AEAD, and `AESGCM`/`CHACHA20`/`ECDHE`
                // select that same set through the `High` alias.
                Self::Aead => true,
            })
            .map(|name| name.to_string())
            .collect()
    }
}

/// Match one cipher alias (`ECDHE-RSA-AES128-GCM-SHA256`, `AES128-GCM-SHA256`,
/// `TLS_AES_128_GCM_SHA256`, `kRSA`, `aNULL`, ...).
fn alias_matches(alias: &str, suites: &[&str]) -> Vec<String> {
    let alias = alias.trim();
    if alias.is_empty() {
        return Vec::new();
    }
    // Direct rustls names (`TLS_AES_128_GCM_SHA256`) and OpenSSL IANA names.
    let normalized = normalize_alias(alias);
    let mut matched: Vec<String> = suites
        .iter()
        .filter(|name| normalize_alias(name) == normalized || **name == alias)
        .map(|name| name.to_string())
        .collect();
    if matched.is_empty() {
        // Component selectors: `kRSA`, `aNULL`, `aECDSA`, `AES128`, `AES256`, `SHA384`.
        matched = suites
            .iter()
            .filter(|name| {
                let name = name.to_ascii_lowercase();
                match alias {
                    "kRSA" => name.contains("_rsa_"),
                    "kECDHE" => name.contains("ecdhe"),
                    "aRSA" => name.contains("_rsa_"),
                    "aECDSA" => name.contains("_ecdsa_"),
                    "aNULL" => false,
                    "AES128" => name.contains("aes_128"),
                    "AES256" => name.contains("aes_256"),
                    "AES" => name.contains("aes"),
                    "GCM" => name.contains("gcm"),
                    "SHA256" => name.ends_with("sha256"),
                    "SHA384" => name.ends_with("sha384"),
                    _ => false,
                }
            })
            .map(|name| name.to_string())
            .collect();
    }
    matched
}

/// Normalise an OpenSSL cipher name to rustls' `TLS_*` name: `ECDHE-RSA-AES128-GCM-SHA256`
/// and `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` both map to the same suite.
pub fn normalize_alias(name: &str) -> String {
    let upper = name.to_ascii_uppercase();
    let dashed = upper.replace('-', "_");
    // OpenSSL IANA names: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    if dashed.starts_with("TLS_") && dashed.contains("_WITH_") {
        return dashed;
    }
    if let Some(rest) = dashed.strip_prefix("TLS_") {
        // TLS 1.3: `TLS_AES_128_GCM_SHA256` is already the rustls name.
        if !rest.contains("_WITH_") {
            return dashed;
        }
    }
    // OpenSSL 1.0 style: `ECDHE-RSA-AES128-GCM-SHA256` 鈫?`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    let mut parts: Vec<&str> = dashed.split('_').collect();
    if parts.first().is_some_and(|part| matches!(*part, "ECDHE" | "DHE" | "ECDH" | "AES")) {
        let mut auth = None;
        if parts.len() > 1 && matches!(parts[1], "RSA" | "ECDSA") {
            auth = Some(parts.remove(1));
        }
        let kex = parts.remove(0);
        let mut rest = parts.join("_");
        rest = rest.replace("AES128", "AES_128").replace("AES256", "AES_256");
        rest = rest.replace("CHACHA20POLY1305", "CHACHA20_POLY1305");
        // OpenSSL omits the SHA-256 suffix of ChaCha20-Poly1305 suites.
        if rest == "CHACHA20_POLY1305" {
            rest = "CHACHA20_POLY1305_SHA256".to_string();
        }
        match auth {
            Some(auth) => format!("TLS_{kex}_{auth}_WITH_{rest}"),
            None => format!("TLS_{kex}_WITH_{rest}"),
        }
    } else {
        // Non-ECDHE suites such as `AES128-GCM-SHA256` have no rustls implementation.
        dashed
    }
}

/// `ssl_ecdh_curve` 鈫?key exchange groups (`auto`, `prime256v1`, `secp384r1`, `X25519`).
pub fn select_kx_groups(
    curve: &str,
    provider: &Arc<CryptoProvider>,
) -> Result<Vec<&'static dyn rustls::crypto::SupportedKxGroup>> {
    let all = &provider.kx_groups;
    match curve {
        "auto" => Ok(all.clone()),
        "prime256v1" | "secp256r1" => Ok(all
            .iter()
            .copied()
            .filter(|group| group.name() == rustls::NamedGroup::secp256r1)
            .chain(
                all.iter()
                    .copied()
                    .filter(|group| group.name() != rustls::NamedGroup::secp256r1),
            )
            .collect()),
        "secp384r1" => Ok(all
            .iter()
            .copied()
            .filter(|group| group.name() == rustls::NamedGroup::secp384r1)
            .collect::<Vec<_>>()
            .into_iter()
            .chain(
                all.iter()
                    .copied()
                    .filter(|group| group.name() != rustls::NamedGroup::secp384r1),
            )
            .collect()),
        "X25519" => Ok(all
            .iter()
            .copied()
            .filter(|group| group.name() == rustls::NamedGroup::X25519)
            .chain(
                all.iter()
                    .copied()
                    .filter(|group| group.name() != rustls::NamedGroup::X25519),
            )
            .collect()),
        other => {
            if let Some(group) = all
                .iter()
                .find(|group| format!("{:?}", group.name()).eq_ignore_ascii_case(other))
            {
                Ok(all
                    .iter()
                    .copied()
                    .filter(|candidate| candidate.name() != group.name())
                    .fold(vec![*group], |mut groups, candidate| {
                        groups.push(candidate);
                        groups
                    }))
            } else {
                bail!("ssl_ecdh_curve {other}: curve is not supported by rustls")
            }
        }
    }
}

/// Session store backed by the shared session caches.
#[derive(Debug)]
pub struct CacheSessionStore {
    cache: Arc<Mutex<SessionCache>>,
}

impl CacheSessionStore {
    pub fn new(cache: Arc<Mutex<SessionCache>>) -> Self {
        Self { cache }
    }
}

impl StoresServerSessions for CacheSessionStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache.lock().put(key, value);
        true
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.lock().get(key).map(|data| (*data).clone())
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.lock().get(key).map(|data| (*data).clone())
    }

    fn can_cache(&self) -> bool {
        true
    }
}

/// Build the rustls `ServerConfig` for one TLS server.
///
/// `ALPN` follows `listen ... ssl http2`: when enabled, `h2` is offered ahead of
/// `http/1.1`, exactly like `ssl_alpn` in `ngx_http_ssl_module.c`.
pub fn build_server_config(
    conf: &TlsServerConf,
    resolver: Arc<CertificateResolver>,
    shared: &SharedCaches,
    provider: &Arc<CryptoProvider>,
    http2: bool,
) -> Result<Arc<ServerConfig>> {    let settings = conf.settings();
    let versions = certificates::protocol_versions(settings.protocols)?;
    let mut custom = (*provider.as_ref()).clone();
    custom.cipher_suites = select_cipher_suites(&settings.ciphers, settings.protocols, provider)?;
    custom.kx_groups = select_kx_groups(&settings.ecdh_curve, provider)?;
    let custom = Arc::new(custom);

    let builder = ServerConfig::builder_with_provider(custom.clone())
        .with_protocol_versions(&versions)
        .context("cannot configure the TLS protocol versions")?;
    let builder = match certificates::build_client_verifier(conf, &custom)? {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_cert_resolver(resolver);

    // `ssl_early_data`: rustls' equivalent also needs `send_half_rtt_data`.
    config.max_early_data_size = if settings.early_data { 0xffff_ffff } else { 0 };
    config.send_half_rtt_data = settings.early_data;
    // `ssl_prefer_server_ciphers`: rustls always prefers the server order, which is what
    // Nginx's `on` selects. The default (`off`) cannot be expressed: rustls does not
    // implement the client-order variant.
    config.ignore_client_order = true;
    config.alpn_protocols = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    config.session_storage = match settings.session_cache.kind {
        super::conf::SessionCacheKind::Off => Arc::new(NoServerSessionStorage {}),
        super::conf::SessionCacheKind::Builtin => Arc::new(CacheSessionStore::new(Arc::new(
            Mutex::new(SessionCache::new(BUILTIN_SESSION_CACHE_SIZE)),
        ))),
        super::conf::SessionCacheKind::Shared => Arc::new(CacheSessionStore::new(shared.zone(
            &settings.session_cache.zone_name,
            Some(settings.session_cache.zone_size),
        ))),
    };
    if !settings.session_tickets {
        config.send_tls13_tickets = 0;
    }
    Ok(Arc::new(config))
}

/// `ssl_session_cache builtin`: 2048 sessions per worker, as in the Nginx docs.
pub const BUILTIN_SESSION_CACHE_SIZE: usize = 2048;

/// Map from TLS server index to its built configuration.
pub type ServerConfigs = HashMap<usize, Arc<ServerConfig>>;

/// One TLS virtual server as seen by the handshake: its names and its rustls config.
#[derive(Clone, Debug)]
pub struct TlsVirtualServer {
    /// Server index in the compiled configuration.
    pub index: usize,
    pub server_names: Vec<String>,
    pub config: Arc<ServerConfig>,
}

/// All TLS virtual servers bound to one listener address.
#[derive(Clone, Debug)]
pub struct TlsVirtualHosts {
    pub servers: Vec<TlsVirtualServer>,
    /// `default_server` position inside `servers`.
    pub default: usize,
    /// Crypto provider shared by the listener's configurations.
    pub provider: Arc<CryptoProvider>,
}

impl TlsVirtualHosts {
    /// `ngx_http_ssl_servername`: pick the virtual server by SNI, falling back to the
    /// `default_server` of the address.
    pub fn select(&self, sni: Option<&str>) -> &TlsVirtualServer {
        if let Some(sni) = sni.filter(|sni| !sni.is_empty()) {
            let host = crate::modules::http_core::normalize_host(sni);
            let mut best: Option<(usize, usize)> = None;
            for (order, server) in self.servers.iter().enumerate() {
                if !crate::modules::http_core::server_matches_names(&server.server_names, &host) {
                    continue;
                }
                let specificity = server
                    .server_names
                    .iter()
                    .map(|name| crate::modules::http_core::server_name_specificity(name, &host))
                    .max()
                    .unwrap_or(0);
                let better = best.is_none_or(|(score, previous_order)| {
                    specificity > score || (specificity == score && order < previous_order)
                });
                if better {
                    best = Some((specificity, order));
                }
            }
            if let Some((_, order)) = best {
                return &self.servers[order];
            }
        }
        self.servers
            .get(self.default)
            .unwrap_or_else(|| &self.servers[0])
    }

    /// The handshake configuration for `sni`, plus the server index it belongs to.
    pub fn resolve(&self, sni: Option<&str>) -> (usize, Arc<ServerConfig>) {
        let server = self.select(sni);
        (server.index, server.config.clone())
    }

    /// The server index whose certificate answered a hostname, without a handshake.
    pub fn index_for(&self, sni: Option<&str>) -> usize {
        self.select(sni).index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_expression_honours_high_and_exclusions() {
        let suites = &[
            "TLS13_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ];
        let selected = apply_cipher_expression("HIGH:!aNULL:!MD5", suites).unwrap();
        assert_eq!(selected.len(), 4);
        let selected = apply_cipher_expression("ECDHE-RSA-AES256-GCM-SHA384", suites).unwrap();
        assert_eq!(selected, vec!["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]);
        let selected = apply_cipher_expression("HIGH:!CHACHA20", suites).unwrap();
        assert!(!selected.iter().any(|name| name.contains("CHACHA20")));
    }

    #[test]
    fn openssl_aliases_normalise_to_rustls_names() {
        assert_eq!(
            normalize_alias("ECDHE-RSA-AES128-GCM-SHA256"),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(
            normalize_alias("ECDHE-ECDSA-CHACHA20-POLY1305"),
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        );
        assert_eq!(
            normalize_alias("TLS_AES_256_GCM_SHA384"),
            "TLS_AES_256_GCM_SHA384"
        );
    }

    #[test]
    fn unknown_cipher_expression_is_rejected() {
        let suites = &["TLS13_AES_128_GCM_SHA256"];
        assert!(apply_cipher_expression("NOT-A-CIPHER", suites).is_err());
        // Exclusions alone leave the default set untouched (OpenSSL `!` semantics).
        assert_eq!(
            apply_cipher_expression("!aNULL", suites).unwrap().len(),
            1
        );
    }

    #[test]
    fn ecdh_curve_prefers_the_named_group() {
        let provider = provider();
        let groups = select_kx_groups("prime256v1", &provider).unwrap();
        assert_eq!(groups[0].name(), rustls::NamedGroup::secp256r1);
        assert!(select_kx_groups("brainpoolP256r1", &provider).is_err());
    }
}
