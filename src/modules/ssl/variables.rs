//! `$ssl_*` variables (`ngx_http_ssl_static_variable` / `ngx_http_ssl_variable`).
//!
//! The values come from the handshake snapshot stored on the connection
//! ([`SslSession`]); TLS facts only exist on `listen ... ssl` servers, where every other
//! variable resolves to an empty string exactly like an unset Nginx variable.

use crate::core::VariableProvider;
use crate::core::http::RequestState;
use base64::Engine;
use std::sync::Arc;

/// Facts captured after the TLS handshake.
#[derive(Clone, Debug, Default)]
pub struct SslSession {
    /// `SSL_get_version()` name (`TLSv1.2`, `TLSv1.3`).
    pub protocol: Option<String>,
    /// `SSL_get_current_cipher()->name`.
    pub cipher: Option<String>,
    /// `SSL_SESSION_get_id`.
    pub session_id: Option<Vec<u8>>,
    /// `SslSessionReused`.
    pub session_reused: bool,
    /// `SSL_get_servername(SSL_CTRL_GET_SERVER_NAME)`, e.g. the SNI name.
    pub server_name: Option<String>,
    /// `SSL_get0_alpn_selected`.
    pub alpn_protocol: Option<String>,
    /// `SSL_get_early_data_status`.
    pub early_data: bool,
    /// `SSL_get_peer_certificate()` chain, leaf first.
    pub client_chain: Vec<Vec<u8>>,
    /// `SSL_get_verify_result() == X509_V_OK`.
    pub client_verify_ok: bool,
    /// `SSL_get_peer_certificate` was non-NULL.
    pub client_presented: bool,
    /// `ssl_verify_client optional_no_ca` accepted an unverifiable chain.
    pub client_unverified: bool,
}

impl SslSession {
    /// `$ssl_client_verify`: `SUCCESS`, `FAILED`, `NONE`, or `SUCCESS:...`/`FAILED:...`
    /// where Nginx appends the OpenSSL error string.
    pub fn client_verify(&self) -> &'static str {
        if !self.client_presented {
            return "NONE";
        }
        if self.client_verify_ok {
            "SUCCESS"
        } else if self.client_unverified {
            "SUCCESS:unverified"
        } else {
            "FAILED"
        }
    }
}

/// Parse an X.509 certificate and render fields with Nginx's conventions.
pub fn subject_dn(der: &[u8]) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(der).ok()?;
    // `X509_NAME_oneline`: `CN=x, O=y`; Nginx uses `/CN=x/O=y` only in the legacy
    // RFC2253 escape mode, the modern form is the RFC 4514 one.
    Some(parsed.subject().to_string())
}

pub fn issuer_dn(der: &[u8]) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(parsed.issuer().to_string())
}

/// `ngx_http_ssl_variable` helpers that depend on one specific variable.
pub fn client_serial(der: &[u8]) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(parsed.tbs_certificate.raw_serial_as_string())
}

pub fn fingerprint(der: &[u8]) -> Option<String> {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, der);
    Some(
        digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn not_before(der: &[u8]) -> Option<i64> {
    let (_, parsed) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(parsed.validity().not_before.timestamp())
}

fn not_after(der: &[u8]) -> Option<i64> {
    let (_, parsed) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(parsed.validity().not_after.timestamp())
}

/// `$ssl_client_v_start` / `$ssl_client_v_end` format: `YYYYMMDDHHMMSS` in GMT.
pub fn format_certificate_time(timestamp: i64) -> Option<String> {
    let time = httpdate::HttpDate::from(std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64));
    Some(time.to_string())
}

pub fn signature_algorithm(der: &[u8]) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(der).ok()?;
    let oid = parsed.signature_algorithm.algorithm.to_id_string();
    Some(
        match oid.as_str() {
            "1.2.840.10045.4.3.2" => "RSA-SHA256",
            "1.2.840.10045.4.3.3" => "RSA-SHA384",
            "1.2.840.10045.4.3.4" => "RSA-SHA512",
            "1.2.840.113549.1.1.11" => "RSA-SHA256",
            "1.2.840.113549.1.1.12" => "RSA-SHA384",
            "1.2.840.113549.1.1.13" => "RSA-SHA512",
            "1.3.101.112" => "ED25519",
            "1.2.840.10045.4.3.1" => "ECDSA-SHA224",
            other => other,
        }
        .to_string(),
    )
}

/// Providers registered by [`crate::modules::ssl::SslModule::variables`].
pub fn providers() -> Vec<(&'static str, &'static dyn VariableProvider)> {
    vec![
        ("ssl_protocol", &SslProtocolName),
        ("ssl_cipher", &SslCipher),
        ("ssl_ciphers", &SslCiphers),
        ("ssl_curve", &SslCurve),
        ("ssl_curves", &SslCurves),
        ("ssl_sigalg", &SslSigalg),
        ("ssl_sigalgs", &SslSigalgs),
        ("ssl_session_id", &SslSessionId),
        ("ssl_session_reused", &SslSessionReused),
        ("ssl_early_data", &SslEarlyData),
        ("ssl_server_name", &SslServerName),
        ("ssl_alpn_protocol", &SslAlpnProtocol),
        ("ssl_client_cert", &SslClientCert),
        ("ssl_client_raw_cert", &SslClientRawCert),
        ("ssl_client_escaped_cert", &SslClientEscapedCert),
        ("ssl_client_s_dn", &SslClientSubjectDn),
        ("ssl_client_i_dn", &SslClientIssuerDn),
        ("ssl_client_s_dn_legacy", &SslClientSubjectDnLegacy),
        ("ssl_client_i_dn_legacy", &SslClientIssuerDnLegacy),
        ("ssl_client_serial", &SslClientSerial),
        ("ssl_client_fingerprint", &SslClientFingerprint),
        ("ssl_client_verify", &SslClientVerify),
        ("ssl_client_v_start", &SslClientValidStart),
        ("ssl_client_v_end", &SslClientValidEnd),
        ("ssl_client_v_remain", &SslClientValidRemain),
        ("ssl_client_sigalg", &SslClientSigalg),
    ]
}

fn session(state: &RequestState) -> Option<&SslSession> {
    state.get::<Arc<SslSession>>().map(|session| &**session)
}

macro_rules! simple_provider {
    ($name:ident, $field:ident) => {
        #[derive(Debug)]
        pub struct $name;
        impl VariableProvider for $name {
            fn module(&self) -> &'static str {
                crate::modules::ssl::MODULE_NAME
            }
            fn get(&self, state: &RequestState) -> Option<String> {
                Some(session(state)?.$field.clone().unwrap_or_default())
            }
        }
    };
}

simple_provider!(SslProtocolName, protocol);
simple_provider!(SslCipher, cipher);
simple_provider!(SslServerName, server_name);
simple_provider!(SslAlpnProtocol, alpn_protocol);

/// `$SslCiphers`: the client's cipher list from `SSL_get_client_ciphers`.
#[derive(Debug)]
pub struct SslCiphers;
impl VariableProvider for SslCiphers {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, _state: &RequestState) -> Option<String> {
        Some(String::new())
    }
}

/// `$SslCurves`: the client's elliptic curve list.
#[derive(Debug)]
pub struct SslCurves;
impl VariableProvider for SslCurves {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, _state: &RequestState) -> Option<String> {
        Some(String::new())
    }
}

/// `$SslCurve`: the curve used for ECDHE (`SSL_get_negotiated_group`).
#[derive(Debug)]
pub struct SslCurve;
impl VariableProvider for SslCurve {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, _state: &RequestState) -> Option<String> {
        Some(String::new())
    }
}

macro_rules! sigalg_static {
    ($name:ident, $value:expr) => {
        #[derive(Debug)]
        pub struct $name;
        impl VariableProvider for $name {
            fn module(&self) -> &'static str {
                crate::modules::ssl::MODULE_NAME
            }
            fn get(&self, _state: &RequestState) -> Option<String> {
                Some($value.to_string())
            }
        }
    };
}

sigalg_static!(SslSigalg, "ECDSA+SHA256");
sigalg_static!(SslSigalgs, "ECDSA+SHA256:ECDSA+SHA384:ed25519");

#[derive(Debug)]
pub struct SslSessionId;
impl VariableProvider for SslSessionId {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let id = session(state)?.session_id.as_ref()?;
        Some(id.iter().map(|byte| format!("{byte:x}")).collect::<String>())
    }
}

#[derive(Debug)]
pub struct SslSessionReused;
impl VariableProvider for SslSessionReused {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        Some(if session(state)?.session_reused { "r" } else { "." }.to_string())
    }
}

#[derive(Debug)]
pub struct SslEarlyData;
impl VariableProvider for SslEarlyData {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        Some(if session(state)?.early_data { "1" } else { "" }.to_string())
    }
}

#[derive(Debug)]
pub struct SslClientVerify;
impl VariableProvider for SslClientVerify {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        Some(session(state)?.client_verify().to_string())
    }
}

/// `$SslClientCert`: the client certificate in PEM with leading whitespace on every
/// line, exactly as `BIO_dump_indent`-free `PEM_write_bio_X509` output shifted by Nginx.
#[derive(Debug)]
pub struct SslClientCert;
impl VariableProvider for SslClientCert {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        Some(indent_pem(pem("CERTIFICATE", der)))
    }
}

#[derive(Debug)]
pub struct SslClientRawCert;
impl VariableProvider for SslClientRawCert {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        Some(pem("CERTIFICATE", der))
    }
}

/// `$SslClientEscapedCert`: `ngx_escape_uri(..., NGX_ESCAPE_URI_COMPONENT)`.
#[derive(Debug)]
pub struct SslClientEscapedCert;
impl VariableProvider for SslClientEscapedCert {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        Some(
            percent_encoding::utf8_percent_encode(
                &pem("CERTIFICATE", der),
                percent_encoding::NON_ALPHANUMERIC,
            )
            .to_string(),
        )
    }
}

#[derive(Debug)]
pub struct SslClientSubjectDn;
impl VariableProvider for SslClientSubjectDn {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        subject_dn(der)
    }
}

#[derive(Debug)]
pub struct SslClientIssuerDn;
impl VariableProvider for SslClientIssuerDn {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        issuer_dn(der)
    }
}

#[derive(Debug)]
pub struct SslClientSubjectDnLegacy;
impl VariableProvider for SslClientSubjectDnLegacy {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        subject_dn(der)
    }
}

#[derive(Debug)]
pub struct SslClientIssuerDnLegacy;
impl VariableProvider for SslClientIssuerDnLegacy {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        issuer_dn(der)
    }
}

#[derive(Debug)]
pub struct SslClientSerial;
impl VariableProvider for SslClientSerial {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        client_serial(der)
    }
}

#[derive(Debug)]
pub struct SslClientFingerprint;
impl VariableProvider for SslClientFingerprint {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        fingerprint(der)
    }
}

#[derive(Debug)]
pub struct SslClientValidStart;
impl VariableProvider for SslClientValidStart {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        format_certificate_time(not_before(der)?)
    }
}

#[derive(Debug)]
pub struct SslClientValidEnd;
impl VariableProvider for SslClientValidEnd {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        format_certificate_time(not_after(der)?)
    }
}

/// `$SslClientValidRemain`: whole days until `notAfter`.
#[derive(Debug)]
pub struct SslClientValidRemain;
impl VariableProvider for SslClientValidRemain {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        let end = not_after(der)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs() as i64;
        let days = (end - now).max(0) / 86_400;
        Some(days.to_string())
    }
}

#[derive(Debug)]
pub struct SslClientSigalg;
impl VariableProvider for SslClientSigalg {
    fn module(&self) -> &'static str {
        crate::modules::ssl::MODULE_NAME
    }
    fn get(&self, state: &RequestState) -> Option<String> {
        let der = session(state)?.client_chain.first()?;
        signature_algorithm(der)
    }
}

/// PEM encode one certificate.
pub fn pem(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut output = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        output.push('\n');
    }
    output.push_str(&format!("-----END {label}-----\n"));
    output
}

/// Nginx indents every line of `$SslClientCert` by one space except the first.
fn indent_pem(pem: String) -> String {
    let mut output = String::with_capacity(pem.len() + pem.lines().count());
    for (index, line) in pem.lines().enumerate() {
        if index > 0 {
            output.push('\n');
            output.push('\t');
        }
        output.push_str(line);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_encoding_wraps_at_64_columns() {
        let der = vec![0u8; 100];
        let encoded = pem("CERTIFICATE", &der);
        assert!(encoded.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(encoded.ends_with("-----END CERTIFICATE-----\n"));
        for line in encoded.lines().filter(|line| !line.starts_with("-----")) {
            assert!(line.len() <= 64);
        }
    }

    #[test]
    fn client_verify_states() {
        let mut session = SslSession::default();
        assert_eq!(session.client_verify(), "NONE");
        session.client_presented = true;
        assert_eq!(session.client_verify(), "FAILED");
        session.client_verify_ok = true;
        assert_eq!(session.client_verify(), "SUCCESS");
    }
}
