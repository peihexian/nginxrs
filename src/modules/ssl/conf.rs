//! `ngx_http_ssl_module` configuration model.
//!
//! Mirrors `ngx_http_ssl_srv_conf_t` / `ngx_http_ssl_loc_conf_t`: directives are stored in
//! the module's `srv_conf` (one entry per `server {}` block) and `loc_conf` (one entry per
//! `location`), exactly like `ngx_http_ssl_create_srv_conf` / `ngx_http_ssl_merge_srv_conf`
//! in `c/nginx/src/http/modules/ngx_http_ssl_module.c`.

use std::path::PathBuf;
use std::time::Duration;

/// `ssl_verify_client` (`ngx_http_ssl_verify_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VerifyClient {
    #[default]
    Off,
    On,
    Optional,
    OptionalNoCa,
}

impl VerifyClient {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "on" => Some(Self::On),
            "optional" => Some(Self::Optional),
            "optional_no_ca" => Some(Self::OptionalNoCa),
            _ => None,
        }
    }

    pub fn needs_ca(&self) -> bool {
        matches!(self, Self::On | Self::Optional)
    }
}

/// `ssl_protocols` bits, matching `NGX_SSL_SSLv2` ... `NGX_SSL_TLSv1_3`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protocols(pub u32);

impl Protocols {
    pub const SSLV2: u32 = 0x0001;
    pub const SSLV3: u32 = 0x0002;
    pub const TLSV1: u32 = 0x0004;
    pub const TLSV1_1: u32 = 0x0008;
    pub const TLSV1_2: u32 = 0x0010;
    pub const TLSV1_3: u32 = 0x0020;

    /// Nginx default: `TLSv1 TLSv1.1 TLSv1.2 TLSv1.3`.
    pub const DEFAULT: Protocols = Protocols(
        Self::TLSV1 | Self::TLSV1_1 | Self::TLSV1_2 | Self::TLSV1_3,
    );

    pub fn empty() -> Self {
        Protocols(0)
    }

    pub fn contains(&self, other: Protocols) -> bool {
        self.0 & other.0 != 0
    }

    pub fn union(self, other: Protocols) -> Self {
        Protocols(self.0 | other.0)
    }

    pub fn names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        for (bit, name) in [
            (Self::TLSV1, "TLSv1"),
            (Self::TLSV1_1, "TLSv1.1"),
            (Self::TLSV1_2, "TLSv1.2"),
            (Self::TLSV1_3, "TLSv1.3"),
        ] {
            if self.contains(Protocols(bit)) {
                names.push(name);
            }
        }
        names
    }
}

/// One `ssl_certificate`/`ssl_certificate_key` pair.
///
/// `ssl_certificate` accepts several `name:path` arguments, and the directive may be
/// repeated; Nginx keeps all of them in one list and the SNI callback picks the entry whose
/// names match (`ngx_ssl_certificate_cb`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificatePair {
    pub certificate: PathBuf,
    pub key: Option<PathBuf>,
    /// Selector strings exactly as written on the directive (`default`, `example.com`,
    /// `*.example.com`, `~^regex$`, ...). Empty for a plain `ssl_certificate` argument.
    pub selectors: Vec<String>,
}

/// `ssl_session_cache` (`ngx_http_ssl_sess_cache_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SessionCacheKind {
    #[default]
    Off,
    Builtin,
    Shared,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionCache {
    pub kind: SessionCacheKind,
    /// `ssl_session_cache shared:NAME:SIZE`.
    pub zone_name: String,
    pub zone_size: usize,
}

/// OCSP knobs derived from `ssl_stapling`, `ssl_ocsp`, `ssl_stapling_file`,
/// `ssl_stapling_responder`, `ssl_stapling_verify`, `ssl_ocsp_responder`, `ssl_ocsp_cache`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OcspConf {
    pub stapling: bool,
    pub stapling_file: Option<PathBuf>,
    pub stapling_responder: Option<String>,
    pub stapling_verify: bool,
}

/// A TLS server (`srv_conf`) before and after merge.
///
/// The pre-merge value keeps `Option`s so the merge can tell "not set here" from an
/// explicit value; [`TlsServerConf::merge`] produces the fully resolved configuration the
/// runtime uses.
#[derive(Clone, Debug, Default)]
pub struct TlsServerConf {
    /// `ssl` in effect for any `listen` of this server (set by the listener, not a
    /// directive).
    pub enabled: bool,
    pub certificates: Vec<CertificatePair>,
    pub certificate_keys: Vec<PathBuf>,
    pub passwords: Vec<PathBuf>,
    pub dhparam: Option<PathBuf>,
    pub protocols: Option<Protocols>,
    pub ciphers: Option<String>,
    pub buffer_size: Option<usize>,
    pub verify_client: Option<VerifyClient>,
    pub verify_depth: Option<u32>,
    pub client_certificate: Option<PathBuf>,
    pub trusted_certificate: Option<PathBuf>,
    pub crl: Option<PathBuf>,
    pub prefer_server_ciphers: Option<bool>,
    pub session_cache: Option<SessionCache>,
    pub session_tickets: Option<bool>,
    pub session_ticket_keys: Vec<PathBuf>,
    pub session_timeout: Option<Duration>,
    pub ecdh_curve: Option<String>,
    pub early_data: Option<bool>,
    pub reject_handshake: Option<bool>,
    pub ocsp: OcspConf,
}

/// Effective TLS values for one server.
#[derive(Clone, Debug, PartialEq)]
pub struct TlsSettings {
    pub protocols: Protocols,
    pub ciphers: String,
    pub buffer_size: usize,
    pub verify_client: VerifyClient,
    pub verify_depth: u32,
    pub prefer_server_ciphers: bool,
    pub session_cache: SessionCache,
    pub session_tickets: bool,
    pub session_timeout: Duration,
    pub ecdh_curve: String,
    pub early_data: bool,
    pub reject_handshake: bool,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            protocols: Protocols::DEFAULT,
            ciphers: DEFAULT_CIPHERS.to_string(),
            buffer_size: 16 * 1024,
            verify_client: VerifyClient::Off,
            verify_depth: 1,
            prefer_server_ciphers: false,
            session_cache: SessionCache::default(),
            session_tickets: true,
            session_timeout: Duration::from_secs(5 * 60),
            ecdh_curve: "auto".to_string(),
            early_data: false,
            reject_handshake: false,
        }
    }
}

/// `ssl_ciphers` default: `HIGH:!aNULL:!MD5`.
pub const DEFAULT_CIPHERS: &str = "HIGH:!aNULL:!MD5";

impl TlsServerConf {
    /// `ssl_reject_handshake on` for this server (`handshake_rejected`).
    pub fn reject_handshake_enabled(&self) -> bool {
        self.reject_handshake.unwrap_or(false)
    }

    /// `ngx_http_ssl_merge_srv_conf`: apply `http {}`-level defaults and the built-in
    /// defaults.
    pub fn merge(parent: Option<&TlsServerConf>, child: &TlsServerConf) -> Self {
        let mut merged = child.clone();
        if let Some(parent) = parent {
            if merged.protocols.is_none() {
                merged.protocols = parent.protocols;
            }
            if merged.ciphers.is_none() {
                merged.ciphers = parent.ciphers.clone();
            }
            if merged.buffer_size.is_none() {
                merged.buffer_size = parent.buffer_size;
            }
            if merged.verify_client.is_none() {
                merged.verify_client = parent.verify_client;
            }
            if merged.verify_depth.is_none() {
                merged.verify_depth = parent.verify_depth;
            }
            if merged.client_certificate.is_none() {
                merged.client_certificate = parent.client_certificate.clone();
            }
            if merged.trusted_certificate.is_none() {
                merged.trusted_certificate = parent.trusted_certificate.clone();
            }
            if merged.crl.is_none() {
                merged.crl = parent.crl.clone();
            }
            if merged.prefer_server_ciphers.is_none() {
                merged.prefer_server_ciphers = parent.prefer_server_ciphers;
            }
            if merged.session_cache.is_none() {
                merged.session_cache = parent.session_cache.clone();
            }
            if merged.session_tickets.is_none() {
                merged.session_tickets = parent.session_tickets;
            }
            if merged.session_timeout.is_none() {
                merged.session_timeout = parent.session_timeout;
            }
            if merged.ecdh_curve.is_none() {
                merged.ecdh_curve = parent.ecdh_curve.clone();
            }
            if merged.early_data.is_none() {
                merged.early_data = parent.early_data;
            }
        }
        merged
    }

    /// Resolve the merged configuration into the runtime values.
    pub fn settings(&self) -> TlsSettings {
        TlsSettings {
            protocols: self.protocols.unwrap_or(Protocols::DEFAULT),
            ciphers: self.ciphers.clone().unwrap_or_else(|| DEFAULT_CIPHERS.to_string()),
            buffer_size: self.buffer_size.unwrap_or(16 * 1024),
            verify_client: self.verify_client.unwrap_or(VerifyClient::Off),
            verify_depth: self.verify_depth.unwrap_or(1),
            prefer_server_ciphers: self.prefer_server_ciphers.unwrap_or(false),
            session_cache: self.session_cache.clone().unwrap_or_default(),
            session_tickets: self.session_tickets.unwrap_or(true),
            session_timeout: self.session_timeout.unwrap_or(Duration::from_secs(300)),
            ecdh_curve: self.ecdh_curve.clone().unwrap_or_else(|| "auto".to_string()),
            early_data: self.early_data.unwrap_or(false),
            reject_handshake: self.reject_handshake.unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_prefers_child_and_falls_back_to_parent() {
        let parent = TlsServerConf {
            protocols: Some(Protocols(Protocols::TLSV1_2 | Protocols::TLSV1_3)),
            verify_client: Some(VerifyClient::Optional),
            session_tickets: Some(false),
            ..Default::default()
        };

        let child = TlsServerConf {
            verify_depth: Some(4),
            ..Default::default()
        };
        let merged = TlsServerConf::merge(Some(&parent), &child);
        let settings = merged.settings();
        // `ssl_protocols` only exists in the server context; the parent value is inherited.
        assert_eq!(
            settings.protocols,
            Protocols(Protocols::TLSV1_2 | Protocols::TLSV1_3)
        );
        assert_eq!(settings.verify_client, VerifyClient::Optional);
        assert_eq!(settings.verify_depth, 4);
        assert!(!settings.session_tickets);
    }

    #[test]
    fn defaults_match_nginx() {
        let settings = TlsServerConf::default().settings();
        assert_eq!(settings.protocols, Protocols::DEFAULT);
        assert_eq!(settings.ciphers, "HIGH:!aNULL:!MD5");
        assert_eq!(settings.buffer_size, 16384);
        assert_eq!(settings.verify_depth, 1);
        assert_eq!(settings.session_timeout, Duration::from_secs(300));
        assert!(settings.session_tickets);
        assert_eq!(settings.session_cache.kind, SessionCacheKind::Off);
    }
}
