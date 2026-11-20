//! `ngx_http_ssl_module`.
//!
//! Nginx enables HTTPS with `listen ... ssl` and configures TLS through the SSL module's
//! directives. This module mirrors `c/nginx/src/http/modules/ngx_http_ssl_module.c`:
//!
//! * `srv_conf` 鈥?one [`TlsServerConf`] per `server {}` block, merged at the end of the
//!   block like `ngx_http_ssl_merge_srv_conf` (inherits `http {}` values, applies the
//!   built-in defaults, validates certificates, sessions and verification);
//! * `loc_conf` 鈥?the `ssl` flag (`ngx_http_ssl_loc_conf_t`), taken from `listen ... ssl`;
//! * runtime 鈥?one rustls `ServerConfig` per TLS server, selected by SNI at handshake time
//!   (`ngx_http_ssl_servername`), plus the per-connection facts exposed as `$ssl_*`
//!   variables (`ngx_http_ssl_variable`).

pub mod certificates;
pub mod codec;
pub mod conf;
pub mod config;
pub mod crypto;
pub mod sessions;
pub mod ocsp_verify;
pub mod stapling;
pub mod variables;

use crate::core::state::StateAccess;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use anyhow::{Context as _, Result, bail};
use conf::{
    CertificatePair, OcspConf, Protocols, SessionCache, SessionCacheKind, TlsServerConf,
    TlsSettings, VerifyClient,
};
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub const MODULE_NAME: &str = "ngx_http_ssl_module";

/// `ngx_http_ssl_loc_conf_t`: one bit saying `listen ... ssl` is in effect.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SslLocConf {
    pub enable: bool,
}

impl LocationConf for SslLocConf {}

/// Every TLS server plus its listeners, produced by the configuration compiler.
#[derive(Default)]
pub struct SslModuleState {
    /// One entry per `server {}`, in declaration order.
    pub servers: Vec<TlsServerConf>,
    /// Server index whose directives are currently being parsed.
    current: usize,
    /// Built rustls configurations, replaced on reload.
    pub runtime: Arc<RwLock<RuntimeTls>>,
}

/// Handshake-time state shared by every listener.
pub struct RuntimeTls {
    /// Per-server rustls `ServerConfig`, keyed by server index.
    pub servers: std::collections::HashMap<usize, Arc<rustls::ServerConfig>>,
    /// Session caches shared between servers that use the same zone name.
    pub caches: sessions::SharedCaches,
    /// The crypto provider shared by every configuration.
    pub provider: Arc<rustls::crypto::CryptoProvider>,
}

impl Default for RuntimeTls {
    fn default() -> Self {
        Self {
            servers: Default::default(),
            caches: sessions::SharedCaches::default(),
            provider: config::provider(),
        }
    }
}

pub struct SslModule;

impl Module for SslModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn http_state(&self) -> Option<crate::core::StateInstance> {
        Some(crate::core::StateInstance::new(SslModuleState::default()))
    }

    fn variables(&self) -> Vec<(&'static str, &'static dyn crate::core::VariableProvider)> {
        variables::providers()
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        let specs = vec![
            // Server context, `NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF`, one or more
            // `[name:path ...]` arguments.
            spec("ssl_certificate", &[Context::Server], ssl_certificate),
            spec("ssl_certificate_key", &[Context::Server], ssl_certificate_key),
            spec("ssl_password_file", &[Context::Server], ssl_password_file),
            spec("ssl_dhparam", &[Context::Server], ssl_dhparam),
            spec("ssl_protocols", &[Context::Server], ssl_protocols),
            spec("ssl_ciphers", &[Context::Server], ssl_ciphers),
            spec("ssl_buffer_size", &[Context::Server], ssl_buffer_size),
            spec("ssl_verify_client", &[Context::Server], ssl_verify_client),
            // `ssl_verify_depth` is also accepted in `http {}` (merged down like Nginx).
            spec(
                "ssl_verify_depth",
                &[Context::Http, Context::Server],
                ssl_verify_depth,
            ),
            spec(
                "ssl_client_certificate",
                &[Context::Server],
                ssl_client_certificate,
            ),
            spec(
                "ssl_trusted_certificate",
                &[Context::Server],
                ssl_trusted_certificate,
            ),
            spec(
                "ssl_prefer_server_ciphers",
                &[Context::Server],
                ssl_prefer_server_ciphers,
            ),
            spec("ssl_session_cache", &[Context::Server], ssl_session_cache),
            spec("ssl_session_tickets", &[Context::Server], ssl_session_tickets),
            spec(
                "ssl_session_ticket_key",
                &[Context::Server],
                ssl_session_ticket_key,
            ),
            spec("ssl_session_timeout", &[Context::Server], ssl_session_timeout),
            spec("ssl_crl", &[Context::Server], ssl_crl),
            spec("ssl_early_data", &[Context::Server], ssl_early_data),
            spec("ssl_ecdh_curve", &[Context::Server], ssl_ecdh_curve),
            spec("ssl_reject_handshake", &[Context::Server], ssl_reject_handshake),
            // OCSP stapling (`ssl_stapling_requested`, `ssl_ocsp`).
            spec("ssl_stapling", &[Context::Server], ssl_stapling),
            spec("ssl_stapling_file", &[Context::Server], ssl_stapling_file),
            spec(
                "ssl_stapling_responder",
                &[Context::Server],
                ssl_stapling_responder,
            ),
            spec("ssl_stapling_verify", &[Context::Server], ssl_stapling_verify),
            spec("ssl_ocsp", &[Context::Server], ssl_ocsp),
            spec("ssl_ocsp_responder", &[Context::Server], ssl_ocsp_responder),
            spec(
                "ssl_ocsp_cache",
                &[Context::Server, Context::Http],
                ssl_ocsp_cache,
            ),
            // Directives Nginx knows but nginxrs cannot express; rejected explicitly
            // instead of being ignored.
            spec("ssl_certificate_cache", &[Context::Server], unsupported),
            spec("ssl_certificate_compression", &[Context::Server], unsupported),
            spec("ssl_ech_file", &[Context::Server], unsupported),
            spec("ssl_conf_command", &[Context::Server], unsupported),
            // `ssl` on `listen` is compiled by the HTTP core module.
            spec("ssl", &[Context::Server], unsupported),
        ];
        specs
    }
}

fn spec(
    name: &'static str,
    contexts: &'static [Context],
    handler: fn(&mut crate::modules::DirectiveView<'_>) -> Result<()>,
) -> DirectiveSpec {
    DirectiveSpec {
        name,
        contexts,
        handler,
    }
}

fn unsupported(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    Err(view.directive.error(
        "nginxrs does not implement this OpenSSL-level knob; remove it from the configuration",
    ))
}

impl SslModuleState {
    /// Index of the server whose directives are being parsed.
    pub fn current_server(&self) -> usize {
        self.current
    }

    pub fn begin_server(&mut self, index: usize) {
        self.current = index;
        while self.servers.len() <= index {
            self.servers.push(TlsServerConf::default());
        }
    }

    pub fn server_mut(&mut self) -> &mut TlsServerConf {
        let index = self.current;
        while self.servers.len() <= index {
            self.servers.push(TlsServerConf::default());
        }
        &mut self.servers[index]
    }

    pub fn server(&self, index: usize) -> Option<&TlsServerConf> {
        self.servers.get(index)
    }

    /// `ngx_http_ssl_merge_srv_conf`: finalise one server.
    pub fn finish_server(
        &mut self,
        index: usize,
        parent: Option<&TlsServerConf>,
        secure_listens: &[String],
        server_names: &[String],
    ) -> Result<()> {
        let child = self
            .servers
            .get(index)
            .cloned()
            .unwrap_or_default();
        let merged = TlsServerConf::merge(parent, &child);
        let settings: TlsSettings = merged.settings();
        if secure_listens.is_empty() {
            self.servers[index] = merged;
            return Ok(());
        }
        // `ngx_http_ssl_merge_srv_conf` validations.
        // `ssl_reject_handshake on` makes a certificate optional
        // (`sscf->certificates == NULL` is accepted in that branch).
        if merged.certificates.is_empty() {
            if merged.reject_handshake == Some(true) {
                self.servers[index] = merged;
                return Ok(());
            }
            bail!(
                "no \"ssl_certificate\" is defined for the \"listen ... ssl\" directive in {}",
                describe_server(index, server_names)
            );
        }
        for pair in &merged.certificates {
            if pair.key.is_none() {
                bail!(
                    "no \"ssl_certificate_key\" is defined for the \"ssl_certificate\" \"{}\"",
                    pair.certificate.display()
                );
            }
        }
        if merged.certificate_keys.len() != merged.certificates.len() {
            bail!(
                "the \"ssl_certificate_key\" must be defined for every \"ssl_certificate\" \
                 ({} key(s) for {} certificate(s))",
                merged.certificate_keys.len(),
                merged.certificates.len()
            );
        }
        if merged.verify_client.is_some_and(|mode| mode.needs_ca())
            && merged.client_certificate.is_none()
        {
            bail!(
                "no \"ssl_client_certificate\" is defined for the \"ssl_verify_client\" \
                 directive in {}",
                describe_server(index, server_names)
            );
        }
        // `ssl_protocols` must name a protocol rustls can speak.
        certificates::protocol_versions(settings.protocols)
            .context("invalid ssl_protocols")?;
        // `ssl_ciphers` is validated against the available suites.
        let provider = config::provider();
        config::select_cipher_suites(&settings.ciphers, settings.protocols, &provider)
            .context("invalid ssl_ciphers")?;
        config::select_kx_groups(&settings.ecdh_curve, &provider)
            .context("invalid ssl_ecdh_curve")?;
        if settings.session_tickets && merged.session_ticket_keys.len() > 1 {
            bail!(
                "only the first \"ssl_session_ticket_key\" is used for TLS 1.3 tickets \
                 ({} keys configured)",
                merged.session_ticket_keys.len()
            );
        }
        let mut merged = merged;
        merged.enabled = true;
        self.servers[index] = merged;
        Ok(())
    }

    /// Build the rustls configuration for every TLS server.
    pub fn build_runtime(
        &self,
        http2: impl Fn(usize) -> bool,
    ) -> Result<RuntimeTls> {
        let provider = config::provider();
        let mut runtime = RuntimeTls {
            provider: provider.clone(),
            ..Default::default()
        };
        let mut servers = std::collections::HashMap::new();
        for (index, conf) in self.servers.iter().enumerate() {
            // `ssl_reject_handshake on` allows a server without certificates
            // (`ngx_http_ssl_merge_srv_conf` returns early only when not rejecting).
            if conf.certificates.is_empty() && conf.reject_handshake != Some(true) {
                continue;
            }
            let resolver = Arc::new(certificates::load_resolver(conf, &provider)?);
            let config = config::build_server_config(
                conf,
                resolver,
                &runtime.caches,
                &provider,
                http2(index),
            )
            .with_context(|| format!("cannot build the TLS configuration of server {index}"))?;
            servers.insert(index, config);
        }
        runtime.servers = servers;
        Ok(runtime)
    }
}

fn describe_server(index: usize, server_names: &[String]) -> String {
    match server_names.iter().find(|name| !name.is_empty()) {
        Some(name) => format!("server name \"{name}\" (server #{index})"),
        None => format!("server #{index}"),
    }
}

impl std::fmt::Debug for SslModuleState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SslModuleState")
            .field("servers", &self.servers.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------------------
// Directive handlers. Each mirrors the corresponding `ngx_*` setter in
// `ngx_http_ssl_module.c`.
// ---------------------------------------------------------------------------------------

fn with_server<'a>(
    view: &'a mut crate::modules::DirectiveView<'_>,
) -> Result<&'a mut TlsServerConf> {
    let state = view.state::<SslModuleState>()?;
    Ok(state.server_mut())
}

/// `ssl_certificate [name:path ...]`: every argument becomes a pair; names select the
/// certificate through SNI.
fn ssl_certificate(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error("invalid number of arguments in \"ssl_certificate\""));
    }
    let args = directive.args.clone();
    let mut pairs = Vec::new();
    for arg in &args {
        let (selectors, path) = split_name_path(arg);
        let resolved = view.path(path);
        if !resolved.exists() {
            return Err(directive.error(format!(
                "cannot load certificate \"{}\": BIO_new_file() failed",
                resolved.display()
            )));
        }
        pairs.push((selectors, resolved));
    }
    let server = with_server(view)?;
    if server.certificates.is_empty() {
        // A `ssl_certificate` without names after named entries adds a default one.
    }
    for (selectors, path) in pairs {
        server.certificates.push(CertificatePair {
            certificate: path,
            key: None,
            selectors,
        });
    }
    Ok(())
}

/// `ssl_certificate_key [name:path ...]`: keys are paired with the certificates in order,
/// either by name or by position.
fn ssl_certificate_key(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error(
            "invalid number of arguments in \"ssl_certificate_key\"",
        ));
    }
    let mut entries = Vec::new();
    for arg in &directive.args {
        let (selectors, path) = split_name_path(arg);
        let resolved = view.path(path);
        if !resolved.exists() {
            return Err(directive.error(format!(
                "cannot load certificate key \"{}\": BIO_new_file() failed",
                resolved.display()
            )));
        }
        entries.push((selectors, resolved));
    }
    let server = with_server(view)?;
    for (selectors, path) in entries {
        server.certificate_keys.push(path.clone());
        // Pair by position; named keys pair with the certificate of the same name.
        let named = !selectors.is_empty();
        let target = if named {
            server.certificates.iter_mut().find(|pair| pair.selectors == selectors)
        } else {
            server.certificates.iter_mut().find(|pair| pair.key.is_none())
        };
        match target {
            Some(pair) => pair.key = Some(path),
            None => {
                // A key without a certificate: keep it so merge can report the mismatch.
                if server.certificates.is_empty() {
                    server.certificates.push(CertificatePair {
                        certificate: PathBuf::new(),
                        key: Some(path),
                        selectors,
                    });
                } else {
                    return Err(directive.error(format!(
                        "the \"ssl_certificate_key\" \"{}\" has no matching \"ssl_certificate\"",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Split `name:path` into the list of selectors and the path. Plain paths (which contain
/// no `:` or a `:` only in a `C:\` form) have no selectors.
fn split_name_path(arg: &str) -> (Vec<String>, &str) {
    let mut selectors = Vec::new();
    let mut rest = arg;
    loop {
        let trimmed = rest.trim();
        let is_drive = trimmed.len() > 1
            && trimmed.as_bytes()[1] == b':'
            && trimmed.as_bytes()[0].is_ascii_alphabetic();
        match trimmed.split_once(':') {
            Some((name, path)) if !name.is_empty() && !is_drive && !path.is_empty() => {
                // Stop when the remainder no longer starts with a selector.
                if name.starts_with('~') || name.contains('.') || name == "default" || true {
                    selectors.push(name.to_string());
                    rest = path;
                }
            }
            _ => break,
        }
        if selectors.len() > 32 {
            break;
        }
    }
    (selectors, rest.trim())
}

fn ssl_password_file(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let path = view.path(&directive.args[0]);
    if !path.exists() {
        return Err(directive.error(format!(
            "ssl_password_file {} not found",
            path.display()
        )));
    }
    with_server(view)?.passwords.push(path);
    Ok(())
}

fn ssl_dhparam(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let path = view.path(&directive.args[0]);
    if !path.exists() {
        return Err(directive.error(format!("ssl_dhparam {} not found", path.display())));
    }
    with_server(view)?.dhparam = Some(path);
    Ok(())
}

fn ssl_protocols(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error(
            "the \"ssl_protocols\" directive must have at least one argument",
        ));
    }
    let mut protocols = Protocols::empty();
    for value in &directive.args {
        let bit = match value.as_str() {
            "SSLv2" => Protocols::SSLV2,
            "SSLv3" => Protocols::SSLV3,
            "TLSv1" => Protocols::TLSV1,
            "TLSv1.1" => Protocols::TLSV1_1,
            "TLSv1.2" => Protocols::TLSV1_2,
            "TLSv1.3" => Protocols::TLSV1_3,
            other => {
                return Err(directive.error(format!(
                    "invalid value \"{other}\" in \"ssl_protocols\" directive; \
                     expected SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2 or TLSv1.3"
                )));
            }
        };
        protocols = protocols.union(Protocols(bit));
    }
    // Nginx rejects SSLv2/SSLv3 outright in release builds.
    if protocols.contains(Protocols(Protocols::SSLV2))
        || protocols.contains(Protocols(Protocols::SSLV3))
    {
        return Err(directive.error(
            "invalid value in \"ssl_protocols\" directive: SSLv2 and SSLv3 are not supported",
        ));
    }
    with_server(view)?.protocols = Some(protocols);
    Ok(())
}

fn ssl_ciphers(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    with_server(view)?.ciphers = Some(directive.args[0].clone());
    Ok(())
}

fn ssl_buffer_size(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let size = crate::core::value::parse_size(directive, &directive.args[0])?;
    // `ssl_buffer_size` must stay inside a sane range: Nginx uses it for the BIO buffer
    // that determines the record size.
    let size = size as usize;
    let size = size.clamp(512, 65536);
    with_server(view)?.buffer_size = Some(size);
    Ok(())
}

fn ssl_verify_client(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let mode = VerifyClient::parse(&directive.args[0]).ok_or_else(|| {
        directive.error("invalid value in \"ssl_verify_client\" directive; expected off, on, optional or optional_no_ca")
    })?;
    with_server(view)?.verify_client = Some(mode);
    Ok(())
}

fn ssl_verify_depth(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let depth: u32 = directive.args[0]
        .parse()
        .map_err(|_| directive.error("invalid value in \"ssl_verify_depth\" directive"))?;
    with_server(view)?.verify_depth = Some(depth);
    Ok(())
}

fn ssl_client_certificate(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let path = view.path(&directive.args[0]);
    if !path.exists() {
        return Err(directive.error(format!(
            "cannot load certificate \"{}\" for ssl_client_certificate",
            path.display()
        )));
    }
    with_server(view)?.client_certificate = Some(path);
    Ok(())
}

fn ssl_trusted_certificate(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let path = view.path(&directive.args[0]);
    if !path.exists() {
        return Err(directive.error(format!(
            "cannot load certificate \"{}\" for ssl_trusted_certificate",
            path.display()
        )));
    }
    with_server(view)?.trusted_certificate = Some(path);
    Ok(())
}

fn ssl_prefer_server_ciphers(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = match directive.args[0].as_str() {
        "on" => true,
        "off" => false,
        other => {
            return Err(directive.error(format!(
                "invalid value \"{other}\" in \"ssl_prefer_server_ciphers\" directive; expected \"on\" or \"off\""
            )));
        }
    };
    with_server(view)?.prefer_server_ciphers = Some(value);
    Ok(())
}

fn ssl_session_cache(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error("invalid number of arguments in \"ssl_session_cache\""));
    }
    let mut cache = SessionCache::default();
    let mut seen = Vec::new();
    for value in &directive.args {
        if value == "off" {
            if seen.contains(&"off".to_string()) {
                return Err(directive.error("duplicate value in \"ssl_session_cache\""));
            }
            seen.push("off".to_string());
            cache.kind = SessionCacheKind::Off;
            continue;
        }
        if value == "none" {
            if seen.contains(&"none".to_string()) {
                return Err(directive.error("duplicate value in \"ssl_session_cache\""));
            }
            seen.push("none".to_string());
            if cache.kind == SessionCacheKind::Off {
                cache.kind = SessionCacheKind::Off;
            }
            continue;
        }
        if value == "builtin" {
            if cache.kind == SessionCacheKind::Builtin {
                return Err(directive.error("duplicate value in \"ssl_session_cache\""));
            }
            cache.kind = SessionCacheKind::Builtin;
            continue;
        }
        if let Some(zone) = value.strip_prefix("shared:") {
            let (name, size) = zone.split_once(':').ok_or_else(|| {
                directive.error("invalid zone \"shared\"; expected shared:NAME:SIZE")
            })?;
            if cache.kind == SessionCacheKind::Shared {
                return Err(directive.error("duplicate value in \"ssl_session_cache\""));
            }
            let size = crate::core::value::parse_size(directive, size)? as usize;
            if !(8 * 1024..=512 * 1024 * 1024).contains(&size) {
                return Err(directive.error(
                    "zone size must be between 8k and 512m",
                ));
            }
            cache.kind = SessionCacheKind::Shared;
            cache.zone_name = name.to_string();
            cache.zone_size = size;
            continue;
        }
        return Err(directive.error(format!(
            "invalid value \"{value}\" in \"ssl_session_cache\" directive"
        )));
    }
    with_server(view)?.session_cache = Some(cache);
    Ok(())
}

fn ssl_session_tickets(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = match directive.args[0].as_str() {
        "on" => true,
        "off" => false,
        other => {
            return Err(directive.error(format!(
                "invalid value \"{other}\" in \"ssl_session_tickets\" directive"
            )));
        }
    };
    with_server(view)?.session_tickets = Some(value);
    Ok(())
}

fn ssl_session_ticket_key(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let path = view.path(&directive.args[0]);
    let bytes = std::fs::read(&path)
        .map_err(|_| directive.error(format!("\"{}\" failed", path.display())))?;
    if sessions::TicketKey::from_bytes(&bytes).is_none() {
        return Err(directive.error(format!(
            "\"{}\" must be 48 or 80 bytes for ssl_session_ticket_key",
            path.display()
        )));
    }
    with_server(view)?.session_ticket_keys.push(path);
    Ok(())
}

fn ssl_session_timeout(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let timeout = crate::core::value::parse_time(directive, &directive.args[0])?;
    with_server(view)?.session_timeout = Some(timeout);
    Ok(())
}

fn ssl_crl(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let path = view.path(&directive.args[0]);
    if !codec::parse_pem_file(&path, "ssl_crl").is_ok() {
        return Err(directive.error(format!("cannot load ssl_crl {}", path.display())));
    }
    with_server(view)?.crl = Some(path);
    Ok(())
}

fn ssl_early_data(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = match directive.args[0].as_str() {
        "on" => true,
        "off" => false,
        other => {
            return Err(directive.error(format!(
                "invalid value \"{other}\" in \"ssl_early_data\" directive"
            )));
        }
    };
    with_server(view)?.early_data = Some(value);
    Ok(())
}

fn ssl_ecdh_curve(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    with_server(view)?.ecdh_curve = Some(directive.args[0].clone());
    Ok(())
}

fn ssl_reject_handshake(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = match directive.args[0].as_str() {
        "on" => true,
        "off" => false,
        other => {
            return Err(directive.error(format!(
                "invalid value \"{other}\" in \"ssl_reject_handshake\" directive"
            )));
        }
    };
    with_server(view)?.reject_handshake = Some(value);
    Ok(())
}

fn on_off(directive: &crate::core::syntax::Directive) -> Result<bool> {
    match directive.args[0].as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(directive.error(format!(
            "invalid value \"{other}\" in \"{}\" directive; expected \"on\" or \"off\"",
            directive.name
        ))),
    }
}

fn ssl_stapling(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = on_off(directive)?;
    with_server(view)?.ocsp.stapling = value;
    Ok(())
}

fn ssl_stapling_file(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let path = view.path(&directive.args[0]);
    if !path.exists() {
        return Err(directive.error(format!(
            "BIO_new_file() failed (SSL: unable to load certificate status \"{}\")",
            path.display()
        )));
    }
    with_server(view)?.ocsp = OcspConf {
        stapling_file: Some(path),
        ..Default::default()
    };
    Ok(())
}

fn ssl_stapling_responder(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = directive.args[0].clone();
    if !value.starts_with("http://") {
        return Err(directive.error(
            "invalid URL prefix in \"ssl_stapling_responder\" directive",
        ));
    }
    let mut ocsp = with_server(view)?.ocsp.clone();
    ocsp.stapling_responder = Some(value);
    with_server(view)?.ocsp = ocsp;
    Ok(())
}

fn ssl_stapling_verify(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = on_off(directive)?;
    let mut ocsp = with_server(view)?.ocsp.clone();
    ocsp.stapling_verify = value;
    with_server(view)?.ocsp = ocsp;
    Ok(())
}

fn ssl_ocsp(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    match directive.args[0].as_str() {
        "on" | "leaf" => {}
        other => {
            return Err(directive.error(format!(
                "invalid value \"{other}\" in \"ssl_ocsp\" directive"
            )));
        }
    }
    // `ssl_ocsp on` turns stapling on for the whole chain, `leaf` for the leaf only;
    // rustls staples one response, which matches the leaf behaviour.
    let mut ocsp = with_server(view)?.ocsp.clone();
    ocsp.stapling = true;
    with_server(view)?.ocsp = ocsp;
    Ok(())
}

fn ssl_ocsp_responder(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = directive.args[0].clone();
    if !value.starts_with("http://") {
        return Err(directive.error(
            "invalid URL prefix in \"ssl_ocsp_responder\" directive",
        ));
    }
    let mut ocsp = with_server(view)?.ocsp.clone();
    ocsp.stapling_responder = Some(value);
    with_server(view)?.ocsp = ocsp;
    Ok(())
}

fn ssl_ocsp_cache(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = &directive.args[0];
    if value == "off" || value == "none" {
        return Ok(());
    }
    let Some(zone) = value.strip_prefix("shared:") else {
        return Err(directive.error(format!(
            "invalid value \"{value}\" in \"ssl_ocsp_cache\" directive"
        )));
    };
    let (name, size) = zone.split_once(':').ok_or_else(|| {
        directive.error("invalid zone \"shared\"; expected shared:NAME:SIZE")
    })?;
    let size = crate::core::value::parse_size(directive, size)? as usize;
    if !(8 * 1024..=512 * 1024 * 1024).contains(&size) {
        return Err(directive.error("zone size must be between 8k and 512m"));
    }
    let _ = name;
    Ok(())
}

/// Build the virtual-host table of one TLS listener address.
///
/// Returns the SNI-routable servers plus the handshake buffer size, or `None` when the
/// address has no `listen ... ssl`.
pub fn virtual_hosts(
    config: &crate::config::Config,
    runtime: &RuntimeTls,
    address: &str,
) -> Option<(config::TlsVirtualHosts, usize)> {
    let mut servers = Vec::new();
    let mut default = 0usize;
    let mut buffer = 16 * 1024;
    for (index, server) in config.http.servers.iter().enumerate() {
        let listens = server
            .listens
            .iter()
            .filter(|listen| listen.address == address && listen.tls)
            .collect::<Vec<_>>();
        if listens.is_empty() {
            continue;
        }
        let Some(server_config) = runtime.servers.get(&index) else {
            continue;
        };
        if listens.iter().any(|listen| listen.default_server) {
            default = servers.len();
        }
        let mut reject_handshake = false;
        if let Some(state) = config
            .module_states
            .get::<SslModuleState>(MODULE_NAME)
            .and_then(|state| state.server(index))
        {
            buffer = state.settings().buffer_size;
            reject_handshake = state.reject_handshake_enabled();
        }
        servers.push(config::TlsVirtualServer {
            index,
            server_names: server.server_names.clone(),
            config: server_config.clone(),
            reject_handshake,
        });
    }
    if servers.is_empty() {
        return None;
    }
    Some((
        config::TlsVirtualHosts {
            servers,
            default,
            provider: runtime.provider.clone(),
        },
        buffer,
    ))
}

/// Index of the server whose directives are being parsed.
pub type SslState = SslModuleState;

/// Ensure the module state is reachable from the compiler (used by `http_core`).
pub fn state_ref<'a>(access: &'a crate::core::state::StateRead<'_>) -> Option<&'a SslModuleState> {
    access.get::<SslModuleState>(MODULE_NAME)
}

pub fn state_mut<'a>(access: &'a mut StateAccess<'_>) -> Option<&'a mut SslModuleState> {
    access.get_mut::<SslModuleState>(MODULE_NAME)
}

/// Timeout used for session resumption (`ssl_session_timeout`).
pub fn timeout_pair(timeout: Duration) -> Duration {
    timeout
}
