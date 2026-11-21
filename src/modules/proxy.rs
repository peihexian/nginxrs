//! `ngx_http_proxy_module`: upstream proxying.
//!
//! The adapter keeps Pingora's streaming pipeline; this module owns the directives,
//! builds the request sent upstream, and applies the proxy response filters.

use crate::core::http::RequestState;
use crate::core::value::parse_time;
use crate::core::variables::Template;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use anyhow::{Context as _, Result, bail};
use pingora_http::{RequestHeader, ResponseHeader};
use std::time::Duration;
use url::Url;

pub const MODULE_NAME: &str = "ngx_http_proxy_module";

#[derive(Clone, Debug)]
pub struct ProxyPass {
    /// Upstream group name, or `host:port` for a direct host.
    pub upstream: String,
    /// `host:port` exactly as written in `proxy_pass` (a name for upstream groups) plus the
    /// URI, which is what `proxy_redirect default` matches against (`ngx_http_proxy_pass`).
    pub url: String,
    pub tls: bool,
    pub host_header: String,
    /// URI part of `proxy_pass`; `None` keeps the rewritten request URI.
    pub uri: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ProxyConf {
    pub pass: Option<ProxyPass>,
    pub set_headers: Vec<(String, Template)>,
    pub hide_headers: Vec<String>,
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub send_timeout: Option<Duration>,
    pub next_upstream_tries: Option<usize>,
    /// `proxy_next_upstream` conditions (`error timeout` by default).
    pub next_upstream: UpstreamFailures,
    /// `proxy_ssl_protocols` (`TLSv1.2 TLSv1.3` by default, as in Nginx).
    pub ssl_protocols: crate::modules::ssl::conf::Protocols,
    /// `proxy_ssl_ciphers`: the OpenSSL cipher string (`DEFAULT` maps to `HIGH`).
    pub ssl_ciphers: String,
    /// `proxy_ssl_server_name`: send SNI (off by default in Nginx).
    pub ssl_server_name: bool,
    /// `proxy_ssl_name`: the SNI name / verified host (`$proxy_host` by default).
    pub ssl_name: Option<Template>,
    /// `proxy_ssl_verify`: verify the upstream certificate (off by default in Nginx).
    pub ssl_verify: bool,
    /// `proxy_ssl_verify_depth` (`1` by default; informational for rustls).
    pub ssl_verify_depth: usize,
    /// `proxy_ssl_trusted_certificate`.
    pub ssl_trusted_certificate: Option<std::path::PathBuf>,
    /// `proxy_ssl_crl`.
    pub ssl_crl: Option<std::path::PathBuf>,
    /// `proxy_ssl_certificate` / `proxy_ssl_certificate_key` (mTLS to the upstream).
    pub ssl_certificate: Option<std::path::PathBuf>,
    pub ssl_certificate_key: Option<std::path::PathBuf>,
    /// `proxy_redirect [off|default|off] [pattern replacement];` rules (`ngx_http_proxy_rewrite_t`).
    pub redirects: Vec<crate::modules::proxy_rewrite::Rewrite>,
    /// `proxy_redirect off` disables the built-in `Location`/`Refresh` rewriting.
    pub redirects_off: bool,
    /// `proxy_cookie_domain` rules.
    pub cookie_domains: Vec<crate::modules::proxy_rewrite::Rewrite>,
    /// `proxy_cookie_path` rules.
    pub cookie_paths: Vec<crate::modules::proxy_rewrite::Rewrite>,
    /// `proxy_cookie_flags`: `name [flag ...]`.
    pub cookie_flags: Vec<(Template, Vec<crate::modules::proxy_rewrite::CookieFlag>)>,
    /// `proxy_pass_header`: server headers that are passed through.
    pub pass_headers: Vec<String>,
    /// `proxy_ignore_headers`: upstream headers ignored for cache/expires semantics.
    pub ignore_headers: Vec<String>,
    /// `proxy_intercept_errors on|off`.
    pub intercept_errors: bool,
    /// `proxy_buffering on|off`.
    pub buffering: bool,
    /// `proxy_buffers number size`.
    pub buffers: (usize, usize),
    /// `proxy_buffer_size` for the response header.
    pub buffer_size: usize,
    /// `proxy_busy_buffers_size`.
    pub busy_buffers_size: Option<usize>,
    /// `proxy_max_temp_file_size`, `0` disables temp files.
    pub max_temp_file_size: usize,
    /// `proxy_temp_path`.
    pub temp_path: Option<std::path::PathBuf>,
    /// `proxy_temp_file_write_size`: bytes written to a temp file per write.
    pub temp_file_write_size: Option<usize>,
    /// `proxy_next_upstream_timeout`, `0` disables the bound.
    pub next_upstream_timeout: Option<Duration>,
    /// `proxy_method`: an explicit method for the upstream request.
    pub method: Option<Template>,
    /// `proxy_set_body`.
    pub set_body: Option<Template>,
    /// `proxy_pass_request_body on|off`.
    pub pass_request_body: bool,
    /// `proxy_pass_request_headers on|off`.
    pub pass_request_headers: bool,
    /// `proxy_http_version 1.0|1.1`.
    pub http_version: u8,
    /// `proxy_limit_rate`: bandwidth limit in bytes per second (`0` disables).
    pub limit_rate: Option<usize>,
    /// `proxy_store` / `proxy_store_access` (accepted, validated at configure time).
    pub store: Option<Template>,
    /// `proxy_cache*`; an empty [`crate::modules::proxy_cache::CacheConf::zone`] means off.
    pub cache: crate::modules::proxy_cache::CacheConf
}

impl Default for ProxyConf {
    fn default() -> Self {
        Self {
            pass: None,
            set_headers: Vec::new(),
            hide_headers: Vec::new(),
            connect_timeout: None,
            read_timeout: None,
            send_timeout: None,
            next_upstream_tries: None,
            ssl_protocols: crate::modules::ssl::conf::Protocols::DEFAULT,
            ssl_ciphers: crate::modules::ssl::conf::DEFAULT_CIPHERS.to_string(),
            ssl_server_name: false,
            ssl_name: None,
            ssl_verify: false,
            ssl_verify_depth: 1,
            ssl_trusted_certificate: None,
            ssl_crl: None,
            ssl_certificate: None,
            ssl_certificate_key: None,
            redirects: Vec::new(),
            redirects_off: false,
            cookie_domains: Vec::new(),
            cookie_paths: Vec::new(),
            cookie_flags: Vec::new(),
            pass_headers: Vec::new(),
            ignore_headers: Vec::new(),
            intercept_errors: false,
            buffering: true,
            buffers: (8, page_size()),
            buffer_size: page_size(),
            busy_buffers_size: None,
            max_temp_file_size: 1024 * 1024 * 1024,
            temp_path: None,
            temp_file_write_size: None,
            next_upstream_timeout: None,
            next_upstream: UpstreamFailures(UpstreamFailures::DEFAULT),
            method: None,
            set_body: None,
            pass_request_body: true,
            pass_request_headers: true,
            http_version: 11,
            limit_rate: None,
            store: None,
            cache: crate::modules::proxy_cache::CacheConf::default()
        }
    }
}

/// One failed upstream attempt and the `proxy_next_upstream` class it maps to.
#[derive(Debug)]
pub struct UpstreamError {
    pub failure: u32,
    pub source: anyhow::Error,
}

impl UpstreamError {
    pub fn new(failure: u32, source: impl Into<anyhow::Error>) -> Self {
        Self {
            failure,
            source: source.into(),
        }
    }
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.source)
    }
}

impl std::error::Error for UpstreamError {}

impl From<anyhow::Error> for UpstreamError {
    fn from(source: anyhow::Error) -> Self {
        Self::new(UpstreamFailures::ERROR, source)
    }
}

impl From<Box<pingora_core::Error>> for UpstreamError {
    fn from(source: Box<pingora_core::Error>) -> Self {
        Self::new(UpstreamFailures::ERROR, anyhow::anyhow!("{source}"))
    }
}

/// `ngx_http_upstream_process_header`: map a status code to its retry class.
pub fn status_failure(status: u16) -> Option<u32> {
    Some(match status {
        403 => UpstreamFailures::HTTP_403,
        404 => UpstreamFailures::HTTP_404,
        429 => UpstreamFailures::HTTP_429,
        500 => UpstreamFailures::HTTP_500,
        502 => UpstreamFailures::HTTP_502,
        503 => UpstreamFailures::HTTP_503,
        504 => UpstreamFailures::HTTP_504,
        _ => return None,
    })
}

/// `ngx_pagesize`: the platform memory page size. Nginx derives the default buffer sizes
/// from it (`proxy_buffers 8 <pagesize>`, `proxy_buffer_size <pagesize>`).
pub fn page_size() -> usize {
    // Both Linux (x86-64) and Windows report 4 KiB pages, which is also what Nginx's
    // `ngx_pagesize` resolves to on the platforms this server targets.
    4096
}

impl LocationConf for ProxyConf {}

/// `proxy_next_upstream` conditions (`ngx_http_proxy_next_upstream_masks`).
///
/// Nginx's default is `error timeout` (`ngx_http_proxy_merge_loc_conf`); `off` disables
/// retrying entirely and, as in C, clears every other flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamFailures(pub u32);

impl UpstreamFailures {
    pub const ERROR: u32 = 0x0000_0002;
    pub const TIMEOUT: u32 = 0x0000_0004;
    pub const INVALID_HEADER: u32 = 0x0000_0008;
    pub const HTTP_500: u32 = 0x0000_0010;
    pub const HTTP_502: u32 = 0x0000_0020;
    pub const HTTP_503: u32 = 0x0000_0040;
    pub const HTTP_504: u32 = 0x0000_0080;
    pub const HTTP_403: u32 = 0x0000_0100;
    pub const HTTP_404: u32 = 0x0000_0200;
    pub const HTTP_429: u32 = 0x0000_0400;
    /// Set internally when the request has already been sent with a non-idempotent method.
    pub const NON_IDEMPOTENT: u32 = 0x0000_4000;
    pub const OFF: u32 = 0x8000_0000;
    /// The Nginx default: `error timeout`.
    pub const DEFAULT: u32 = Self::ERROR | Self::TIMEOUT;

    pub fn contains(self, flag: u32) -> bool {
        self.0 & flag == flag
    }

    /// `ngx_conf_bitmask` name 闂?flag, as listed by Nginx.
    pub fn parse(name: &str) -> Option<u32> {
        Some(match name {
            "error" => Self::ERROR,
            "timeout" => Self::TIMEOUT,
            "invalid_header" => Self::INVALID_HEADER,
            "non_idempotent" => Self::NON_IDEMPOTENT,
            "http_500" => Self::HTTP_500,
            "http_502" => Self::HTTP_502,
            "http_503" => Self::HTTP_503,
            "http_504" => Self::HTTP_504,
            "http_403" => Self::HTTP_403,
            "http_404" => Self::HTTP_404,
            "http_429" => Self::HTTP_429,
            "off" => Self::OFF,
            _ => return None,
        })
    }

    /// The status Nginx reports when no further upstream is attempted.
    pub fn status(self) -> u16 {
        if self.contains(Self::TIMEOUT) || self.contains(Self::HTTP_504) {
            504
        } else {
            502
        }
    }
}

pub struct ProxyModule;

impl Module for ProxyModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn variables(&self) -> Vec<(&'static str, &'static dyn crate::core::variables::VariableProvider)> {
        vec![(crate::modules::proxy::CACHE_STATUS_NAME, &CACHE_STATUS)]
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            spec("proxy_pass", parse_proxy_pass),
            spec("proxy_set_header", parse_set_header),
            spec("proxy_hide_header", parse_hide_header),
            spec("proxy_connect_timeout", parse_connect_timeout),
            spec("proxy_read_timeout", parse_read_timeout),
            spec("proxy_send_timeout", parse_send_timeout),
            spec("proxy_next_upstream_tries", parse_next_upstream_tries),
            spec("proxy_next_upstream", parse_next_upstream),
            // `ngx_http_proxy_module` SSL directives (`ngx_http_proxy_set_ssl`).
            spec("proxy_ssl_protocols", parse_ssl_protocols),
            spec("proxy_ssl_ciphers", parse_ssl_ciphers),
            spec("proxy_ssl_server_name", parse_ssl_on_off),
            spec("proxy_ssl_name", parse_ssl_name),
            spec("proxy_ssl_verify", parse_ssl_on_off),
            spec("proxy_ssl_verify_depth", parse_ssl_verify_depth),
            spec("proxy_ssl_trusted_certificate", parse_ssl_file),
            spec("proxy_ssl_crl", parse_ssl_file),
            spec("proxy_ssl_certificate", parse_ssl_file),
            spec("proxy_ssl_certificate_key", parse_ssl_file),
            spec("proxy_ssl_session_reuse", parse_ssl_on_off),
            // Caching (`ngx_http_file_cache`).
            spec("proxy_cache_path", parse_cache_path),
            spec("proxy_cache", parse_cache),
            spec("proxy_cache_key", parse_cache_key),
            spec("proxy_cache_valid", parse_cache_valid),
            spec("proxy_cache_bypass", parse_cache_predicate),
            spec("proxy_no_cache", parse_cache_predicate),
            spec("proxy_cache_methods", parse_cache_methods),
            spec("proxy_cache_min_uses", parse_cache_min_uses),
            spec("proxy_cache_use_stale", parse_cache_use_stale),
            spec("proxy_cache_revalidate", parse_cache_flag),
            spec("proxy_cache_background_update", parse_cache_flag),
            spec("proxy_cache_lock", parse_cache_flag),
            // Response rewriting (`ngx_http_proxy_rewrite_*`).
            spec("proxy_redirect", parse_redirect),
            spec("proxy_cookie_domain", parse_cookie_rewrite),
            spec("proxy_cookie_path", parse_cookie_rewrite),
            spec("proxy_cookie_flags", parse_cookie_flags),
            spec("proxy_pass_header", parse_single_header),
            spec("proxy_ignore_headers", parse_header_list),
            // Buffering and upstream request shaping.
            spec("proxy_intercept_errors", parse_on_off),
            spec("proxy_buffering", parse_on_off),
            spec("proxy_buffers", parse_buffers),
            spec("proxy_buffer_size", parse_buffer_size),
            spec("proxy_busy_buffers_size", parse_buffer_size),
            spec("proxy_max_temp_file_size", parse_size_directive),
            spec("proxy_temp_path", parse_temp_path),
            spec("proxy_temp_file_write_size", parse_size_directive),
            spec("proxy_next_upstream_timeout", parse_next_upstream_timeout),
            spec("proxy_method", parse_method),
            spec("proxy_set_body", parse_set_body),
            spec("proxy_pass_request_body", parse_on_off),
            spec("proxy_pass_request_headers", parse_on_off),
            spec("proxy_http_version", parse_http_version),
            spec("proxy_limit_rate", parse_size_directive),
            spec("proxy_store", parse_store),
            spec("proxy_store_access", parse_store_access),
        ]
    }
}

/// `$upstream_cache_status` (`ngx_http_upstream_cache_status`).
pub const CACHE_STATUS_NAME: &str = "upstream_cache_status";

pub struct CacheStatusVar;

impl std::fmt::Debug for CacheStatusVar {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CacheStatusVar")
    }
}

impl crate::core::variables::VariableProvider for CacheStatusVar {
    fn module(&self) -> &'static str {
        MODULE_NAME
    }

    /// The value is stored on the request context by `proxy_pass`; the plain request state
    /// carries it in [`crate::core::http::RequestState`] slot 闁?see `cache_status_variable`.
    fn get(&self, state: &crate::core::http::RequestState) -> Option<String> {
        state
            .get::<crate::modules::proxy_cache::CacheState>()
            .and_then(|cache| cache.status)
            .map(|status| status.as_str().to_string())
    }
}

pub const CACHE_STATUS: CacheStatusVar = CacheStatusVar;

type Handler = fn(&mut crate::modules::DirectiveView<'_>) -> Result<()>;

fn spec(name: &'static str, handler: Handler) -> DirectiveSpec {
    DirectiveSpec {
        name,
        contexts: &[Context::Http, Context::Server, Context::Location],
        handler,
    }
}

fn parse_proxy_pass(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let pass = parse_pass(&directive.args[0])
        .map_err(|error| directive.error(format!("proxy_pass: {error}")))?;
    view.update_conf::<ProxyConf>(|conf| conf.pass = Some(pass))
}

/// Parse a `proxy_pass` URL.
///
/// `http://backend` (a bare host without a dot, port or colon) names an upstream group;
/// `http://10.0.0.1:8080` is a direct backend.
pub fn parse_pass(value: &str) -> Result<ProxyPass> {
    let url = Url::parse(value).context("expected an absolute http:// or https:// URL")?;
    let tls = match url.scheme() {
        "http" => false,
        "https" => true,
        scheme => bail!("unsupported scheme {scheme}"),
    };
    if !url.username().is_empty() || url.password().is_some() {
        bail!("userinfo in proxy_pass is not supported");
    }
    let host = url.host_str().context("missing upstream host")?.to_string();
    let port = url
        .port_or_known_default()
        .context("missing upstream port")?;
    let bare_host = !host.contains('.') && host != "localhost" && !host.contains(':');
    let upstream = if bare_host && url.port().is_none() {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let uri = match url.path() {
        "" | "/" if !value.ends_with('/') => None,
        path => Some(path.to_string()),
    };
    if url.query().is_some() || url.fragment().is_some() {
        bail!("query strings and fragments in proxy_pass are not implemented");
    }
    Ok(ProxyPass {
        url: format!("{host}:{port}"),
        upstream,
        tls,
        host_header: if url.port().is_some() {
            format!("{host}:{port}")
        } else {
            host
        },
        uri,
    })
}

fn parse_set_header(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(2)?;
    let value = Template::parse(&directive.args[1])
        .map_err(|error| directive.error(format!("invalid proxy_set_header value: {error}")))?;
    let name = directive.args[0].clone();
    view.update_conf::<ProxyConf>(|conf| conf.set_headers.push((name, value)))
}

fn parse_hide_header(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let name = directive.args[0].clone();
    view.update_conf::<ProxyConf>(|conf| conf.hide_headers.push(name))
}

fn parse_connect_timeout(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let timeout = parse_time(directive, &directive.args[0])?;
    view.update_conf::<ProxyConf>(|conf| conf.connect_timeout = Some(timeout))
}

fn parse_read_timeout(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let timeout = parse_time(directive, &directive.args[0])?;
    view.update_conf::<ProxyConf>(|conf| conf.read_timeout = Some(timeout))
}

fn parse_send_timeout(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let timeout = parse_time(directive, &directive.args[0])?;
    view.update_conf::<ProxyConf>(|conf| conf.send_timeout = Some(timeout))
}

fn parse_next_upstream_tries(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let tries: usize = directive.args[0]
        .parse()
        .map_err(|_| directive.error("expected a non-negative integer"))?;
    view.update_conf::<ProxyConf>(|conf| conf.next_upstream_tries = Some(tries))
}

// ---------------------------------------------------------------------------------------
// `proxy_cache*` (`ngx_http_file_cache.c`)
// ---------------------------------------------------------------------------------------

/// `proxy_cache_path path [levels=...] [keys_zone=NAME:SIZE] [...]` 闁?http context only.
fn parse_cache_path(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(2..=usize::MAX)?;
    let arguments = directive.args.clone();
    let (zone, _size) = crate::modules::proxy_cache::parse_cache_path(&arguments)
        .map_err(|error| directive.error(format!("proxy_cache_path: {error}")))?;
    if let Some(parent) = zone.path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        return Err(directive.error(format!(
            "the \"proxy_cache_path\" directory \"{}\" does not exist",
            zone.path.display()
        )));
    }
    crate::modules::proxy_cache::register_zone(zone, &directive.name)
        .map_err(|error| directive.error(error.to_string()))
}

/// `proxy_cache zone|off;`
fn parse_cache(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = directive.args[0].clone();
    if value != "off" && !crate::modules::proxy_cache::zone_exists(&value) {
        return Err(directive.error(format!(
            "\"proxy_cache\" zone \"{value}\" is unknown"
        )));
    }
    view.update_conf::<ProxyConf>(|conf| {
        conf.cache.zone = (value != "off").then(|| value.clone())
    })
}

/// `proxy_cache_key string;`
fn parse_cache_key(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let template = Template::parse(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid proxy_cache_key: {error}")))?;
    view.update_conf::<ProxyConf>(|conf| conf.cache.key = Some(template))
}

/// `proxy_cache_valid [code ...] time;`
fn parse_cache_valid(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=usize::MAX)?;
    let last = directive.args.len() - 1;
    let time = crate::core::value::parse_time(directive, &directive.args[last])?;
    let mut codes = Vec::new();
    for value in &directive.args[..last] {
        let code: u16 = value
            .parse()
            .map_err(|_| directive.error(format!("invalid status code \"{value}\"")))?;
        codes.push(code);
    }
    view.update_conf::<ProxyConf>(|conf| conf.cache.valid.push((codes, time)))
}

/// `proxy_cache_bypass string ...;` / `proxy_no_cache string ...;`
fn parse_cache_predicate(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=usize::MAX)?;
    let is_bypass = directive.name == "proxy_cache_bypass";
    let mut templates = Vec::new();
    for value in &directive.args {
        templates.push(
            Template::parse(value)
                .map_err(|error| directive.error(format!("{}: {error}", directive.name)))?,
        );
    }
    view.update_conf::<ProxyConf>(|conf| {
        if is_bypass {
            conf.cache.bypass = templates;
        } else {
            conf.cache.no_cache = templates;
        }
    })
}

/// `proxy_cache_methods GET|HEAD|POST ...;`
fn parse_cache_methods(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=usize::MAX)?;
    let methods: Vec<String> = directive.args.iter().map(|m| m.to_ascii_uppercase()).collect();
    view.update_conf::<ProxyConf>(|conf| conf.cache.methods = methods)
}

/// `proxy_cache_min_uses number;`
fn parse_cache_min_uses(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let uses: u64 = directive.args[0]
        .parse()
        .map_err(|_| directive.error("invalid proxy_cache_min_uses"))?;
    if uses == 0 {
        return Err(directive.error("proxy_cache_min_uses must be greater than 0"));
    }
    view.update_conf::<ProxyConf>(|conf| conf.cache.min_uses = uses)
}

/// `proxy_cache_use_stale error|timeout|...|updating;`
fn parse_cache_use_stale(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=usize::MAX)?;
    const CONDITIONS: &[&str] = &[
        "error",
        "timeout",
        "invalid_header",
        "updating",
        "http_500",
        "http_502",
        "http_503",
        "http_504",
        "http_403",
        "http_404",
        "http_429",
        "non_idempotent",
        "off",
    ];
    let mut conditions = Vec::new();
    for value in &directive.args {
        if !CONDITIONS.contains(&value.as_str()) {
            return Err(directive.error(format!(
                "invalid value \"{value}\" in \"proxy_cache_use_stale\" directive"
            )));
        }
        conditions.push(value.clone());
    }
    view.update_conf::<ProxyConf>(|conf| conf.cache.use_stale = conditions)
}

/// `proxy_cache_revalidate|proxy_cache_background_update|proxy_cache_lock on|off;`
fn parse_cache_flag(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = match directive.args[0].as_str() {
        "on" => true,
        "off" => false,
        other => {
            return Err(directive.error(format!(
                "invalid value \"{other}\" in \"{}\" directive",
                directive.name
            )));
        }
    };
    let name = directive.name.clone();
    view.update_conf::<ProxyConf>(|conf| match name.as_str() {
        "proxy_cache_revalidate" => conf.cache.revalidate = value,
        "proxy_cache_background_update" => conf.cache.background_update = value,
        _ => conf.cache.lock = value,
    })
}

/// `proxy_next_upstream error|timeout|invalid_header|http_500|...|off ...` (`ngx_conf_bitmask`).
fn parse_next_upstream(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error("invalid number of arguments in \"proxy_next_upstream\""));
    }
    let mut mask = 0_u32;
    for value in &directive.args {
        let Some(flag) = UpstreamFailures::parse(value) else {
            return Err(directive.error(format!(
                "invalid value \"{value}\" in \"proxy_next_upstream\" directive"
            )));
        };
        if mask & flag != 0 {
            return Err(directive.error(format!(
                "duplicate value \"{value}\" in \"proxy_next_upstream\" directive"
            )));
        }
        mask |= flag;
    }
    if mask & UpstreamFailures::OFF != 0 {
        // `ngx_http_proxy_merge_loc_conf`: `off` replaces every other condition.
        mask = UpstreamFailures::OFF;
    }
    view.update_conf::<ProxyConf>(|conf| conf.next_upstream = UpstreamFailures(mask))
}

/// `proxy_ssl_protocols`: the same grammar as `ssl_protocols`.
fn parse_ssl_protocols(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error("expected one or more TLS versions"));
    }
    let mut protocols = crate::modules::ssl::conf::Protocols::empty();
    for value in &directive.args {
        let bit = match value.as_str() {
            "SSLv2" => crate::modules::ssl::conf::Protocols::SSLV2,
            "SSLv3" => crate::modules::ssl::conf::Protocols::SSLV3,
            "TLSv1" => crate::modules::ssl::conf::Protocols::TLSV1,
            "TLSv1.1" => crate::modules::ssl::conf::Protocols::TLSV1_1,
            "TLSv1.2" => crate::modules::ssl::conf::Protocols::TLSV1_2,
            "TLSv1.3" => crate::modules::ssl::conf::Protocols::TLSV1_3,
            other => {
                return Err(directive.error(format!(
                    "invalid value \"{other}\" in \"proxy_ssl_protocols\" directive"
                )));
            }
        };
        protocols = protocols.union(crate::modules::ssl::conf::Protocols(bit));
    }
    view.update_conf::<ProxyConf>(|conf| conf.ssl_protocols = protocols)
}

/// `proxy_ssl_ciphers`: an OpenSSL cipher string; `DEFAULT` maps to `HIGH`.
fn parse_ssl_ciphers(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let ciphers = directive.args[0].clone();
    view.update_conf::<ProxyConf>(|conf| conf.ssl_ciphers = ciphers)
}

/// `proxy_ssl_server_name on|off`, `proxy_ssl_verify on|off`, `proxy_ssl_session_reuse on|off`.
fn parse_ssl_on_off(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = match directive.args[0].as_str() {
        "on" => true,
        "off" => false,
        other => {
            return Err(directive.error(format!(
                "invalid value \"{other}\" in \"{}\" directive; expected \"on\" or \"off\"",
                directive.name
            )));
        }
    };
    match directive.name.as_str() {
        "proxy_ssl_server_name" => {
            view.update_conf::<ProxyConf>(|conf| conf.ssl_server_name = value)
        }
        "proxy_ssl_verify" => view.update_conf::<ProxyConf>(|conf| conf.ssl_verify = value),
        // rustls owns its session cache; the directive is accepted for compatibility.
        _ => Ok(()),
    }
}

/// `proxy_ssl_name $host`: the SNI name and verified host name.
fn parse_ssl_name(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let template = Template::parse(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid proxy_ssl_name: {error}")))?;
    view.update_conf::<ProxyConf>(|conf| conf.ssl_name = Some(template))
}

fn parse_ssl_verify_depth(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let depth: usize = directive.args[0]
        .parse()
        .map_err(|_| directive.error("invalid proxy_ssl_verify_depth"))?;
    view.update_conf::<ProxyConf>(|conf| conf.ssl_verify_depth = depth)
}

/// `proxy_ssl_trusted_certificate`, `proxy_ssl_crl`, `proxy_ssl_certificate`,
/// `proxy_ssl_certificate_key`.
fn parse_ssl_file(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let path = view.path(&directive.args[0]);
    if !path.exists() {
        return Err(directive.error(format!(
            "cannot load \"{}\" for {}",
            path.display(),
            directive.name
        )));
    }
    let name = directive.name.clone();
    view.update_conf::<ProxyConf>(|conf| match name.as_str() {
        "proxy_ssl_trusted_certificate" => conf.ssl_trusted_certificate = Some(path.clone()),
        "proxy_ssl_crl" => conf.ssl_crl = Some(path.clone()),
        "proxy_ssl_certificate" => conf.ssl_certificate = Some(path.clone()),
        _ => conf.ssl_certificate_key = Some(path.clone()),
    })
}

// ---------------------------------------------------------------------------------------
// Response rewriting, buffering and upstream request directives.
// ---------------------------------------------------------------------------------------

fn on_off_value(directive: &crate::core::syntax::Directive) -> Result<bool> {
    match directive.args[0].as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(directive.error(format!(
            "invalid value \"{other}\" in \"{}\" directive; expected \"on\" or \"off\"",
            directive.name
        ))),
    }
}

/// `proxy_redirect off|default|off|on|pattern [replacement];`
fn parse_redirect(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error("invalid number of arguments in \"proxy_redirect\""));
    }
    match directive.args.len() {
        1 => match directive.args[0].as_str() {
            "off" => view.update_conf::<ProxyConf>(|conf| conf.redirects_off = true),
            "default" | "on" => view.update_conf::<ProxyConf>(|conf| {
                conf.redirects_off = false;
                conf.redirects.clear();
            }),
            other => Err(directive.error(format!(
                "invalid parameter \"{other}\" in \"proxy_redirect\" directive"
            ))),
        },
        2 => {
            let rewrite = crate::modules::proxy_rewrite::Rewrite::parse(
                &directive.args[0],
                Some(&directive.args[1]),
                true,
            )
            .map_err(|error| directive.error(format!("proxy_redirect: {error}")))?;
            view.update_conf::<ProxyConf>(|conf| conf.redirects.push(rewrite))
        }
        _ => Err(directive.error("invalid number of arguments in \"proxy_redirect\"")),
    }
}

/// `proxy_cookie_domain|proxy_cookie_path off|on|pattern [replacement];`
fn parse_cookie_rewrite(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error(format!(
            "invalid number of arguments in \"{}\"",
            directive.name
        )));
    }
    let is_domain = directive.name == "proxy_cookie_domain";
    match directive.args.len() {
        1 => match directive.args[0].as_str() {
            "off" => view.update_conf::<ProxyConf>(|conf| {
                if is_domain {
                    conf.cookie_domains.clear();
                } else {
                    conf.cookie_paths.clear();
                }
            }),
            "on" => Ok(()),
            other => Err(directive.error(format!(
                "invalid parameter \"{other}\" in \"{}\" directive",
                directive.name
            ))),
        },
        2 => {
            // `proxy_cookie_domain` matches case-insensitively, `proxy_cookie_path` not.
            let rewrite = crate::modules::proxy_rewrite::Rewrite::parse(
                &directive.args[0],
                Some(&directive.args[1]),
                !is_domain,
            )
            .map_err(|error| directive.error(format!("{}: {error}", directive.name)))?;
            view.update_conf::<ProxyConf>(|conf| {
                if is_domain {
                    conf.cookie_domains.push(rewrite);
                } else {
                    conf.cookie_paths.push(rewrite);
                }
            })
        }
        _ => Err(directive.error(format!(
            "invalid number of arguments in \"{}\"",
            directive.name
        ))),
    }
}

/// `proxy_cookie_flags cookie_name [flag ...];`
fn parse_cookie_flags(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=4)?;
    let name = Template::parse(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid proxy_cookie_flags name: {error}")))?;
    let mut flags = Vec::new();
    for value in &directive.args[1..] {
        let flag = crate::modules::proxy_rewrite::CookieFlag::parse(value)
            .map_err(|error| directive.error(format!("proxy_cookie_flags: {error}")))?;
        flags.push(flag);
    }
    view.update_conf::<ProxyConf>(|conf| conf.cookie_flags.push((name, flags)))
}

/// `proxy_pass_header name;`
fn parse_single_header(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let name = directive.args[0].clone();
    view.update_conf::<ProxyConf>(|conf| conf.pass_headers.push(name))
}

/// `proxy_ignore_headers header ...;`
fn parse_header_list(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error("expected at least one header name"));
    }
    let names: Vec<String> = directive.args.clone();
    view.update_conf::<ProxyConf>(|conf| {
        conf.ignore_headers.extend(names.clone());
        // The cache consults `proxy_ignore_headers` too (`Set-Cookie` relaxes cacheability).
        conf.cache.ignore_headers.extend(names);
    })
}

fn parse_on_off(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = on_off_value(directive)?;
    let name = directive.name.clone();
    view.update_conf::<ProxyConf>(|conf| match name.as_str() {
        "proxy_intercept_errors" => conf.intercept_errors = value,
        "proxy_buffering" => conf.buffering = value,
        "proxy_pass_request_body" => conf.pass_request_body = value,
        "proxy_pass_request_headers" => conf.pass_request_headers = value,
        _ => {}
    })
}

/// `proxy_buffers number size;`
fn parse_buffers(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(2)?;
    let count: usize = directive.args[0]
        .parse()
        .map_err(|_| directive.error("invalid number of buffers"))?;
    let size = crate::core::value::parse_size(directive, &directive.args[1])? as usize;
    // `ngx_http_proxy_merge_loc_conf`: "there must be at least 2 \"proxy_buffers\"".
    if count < 2 {
        return Err(directive.error("there must be at least 2 \"proxy_buffers\""));
    }
    view.update_conf::<ProxyConf>(|conf| conf.buffers = (count, size))
}

/// `proxy_buffer_size size;` / `proxy_busy_buffers_size size;`
fn parse_buffer_size(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let size = crate::core::value::parse_size(directive, &directive.args[0])? as usize;
    let name = directive.name.clone();
    view.update_conf::<ProxyConf>(|conf| match name.as_str() {
        "proxy_buffer_size" => conf.buffer_size = size,
        _ => conf.busy_buffers_size = Some(size),
    })
}

/// `proxy_max_temp_file_size size;` / `proxy_limit_rate rate;`
fn parse_size_directive(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let size = crate::core::value::parse_size(directive, &directive.args[0])? as usize;
    let name = directive.name.clone();
    view.update_conf::<ProxyConf>(|conf| match name.as_str() {
        "proxy_max_temp_file_size" => conf.max_temp_file_size = size,
        _ => conf.limit_rate = (size > 0).then_some(size),
    })
}

/// `proxy_temp_path path [level1 [level2 [level3]]];`
fn parse_temp_path(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=4)?;
    let path = view.path(&directive.args[0]);
    view.update_conf::<ProxyConf>(|conf| conf.temp_path = Some(path))
}

/// `proxy_next_upstream_timeout time;`
fn parse_next_upstream_timeout(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let timeout = crate::core::value::parse_time(directive, &directive.args[0])?;
    view.update_conf::<ProxyConf>(|conf| {
        conf.next_upstream_timeout = (timeout != Duration::ZERO).then_some(timeout)
    })
}

/// `proxy_method method;`
fn parse_method(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let template = Template::parse(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid proxy_method: {error}")))?;
    view.update_conf::<ProxyConf>(|conf| conf.method = Some(template))
}

/// `proxy_set_body value;`
fn parse_set_body(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let template = Template::parse(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid proxy_set_body: {error}")))?;
    view.update_conf::<ProxyConf>(|conf| conf.set_body = Some(template))
}

/// `proxy_http_version 1.0|1.1;`
fn parse_http_version(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    match directive.args[0].as_str() {
        "1.0" => view.update_conf::<ProxyConf>(|conf| conf.http_version = 10),
        "1.1" => view.update_conf::<ProxyConf>(|conf| conf.http_version = 11),
        // `2` needs `ngx_http_v2_module` upstream support, which this server reaches through
        // its HTTP/2 client; accepted here so such configurations load.
        "2" => view.update_conf::<ProxyConf>(|conf| conf.http_version = 20),
        other => Err(directive.error(format!(
            "invalid value \"{other}\" in \"proxy_http_version\" directive; expected \"1.0\", \"1.1\" or \"2\""
        ))),
    }
}

/// `proxy_store off|on|path;`
fn parse_store(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    match directive.args[0].as_str() {
        "off" => view.update_conf::<ProxyConf>(|conf| conf.store = None),
        other => {
            let template = Template::parse(other)
                .map_err(|error| directive.error(format!("invalid proxy_store: {error}")))?;
            view.update_conf::<ProxyConf>(|conf| conf.store = Some(template))
        }
    }
}

/// `proxy_store_access users:permissions ...;` 闂?accepted for compatibility; the store
/// mode is not applied because nginxrs never writes to `proxy_store` paths.
fn parse_store_access(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error("expected at least one access mode"));
    }
    log::warn!(
        "{}:{}: proxy_store_access is accepted for compatibility; stored files keep the process umask",
        directive.file.display(),
        directive.line
    );
    Ok(())
}
/// Compute the upstream request URI following Nginx `proxy_pass` semantics.
pub fn proxy_uri(pass: &ProxyPass, matched_prefix: Option<&str>, uri: &str) -> String {
    let Some(base) = &pass.uri else {
        return uri.to_string();
    };
    let suffix = matched_prefix
        .and_then(|prefix| uri.strip_prefix(prefix))
        .unwrap_or(uri);
    let base = base.trim_end_matches('/');
    let path = if suffix.starts_with('/') || suffix.is_empty() {
        format!("{base}{suffix}")
    } else {
        format!("{base}/{suffix}")
    };
    // `proxy_pass http://host/` leaves an empty path when the request matches exactly; the
    // upstream still needs an absolute path (`ngx_http_proxy_create_request` sends `/`).
    if path.is_empty() {
        "/".to_string()
    } else {
        path
    }
}

/// Populate the upstream request from `proxy_set_header` values.
pub fn apply_upstream_headers(
    conf: &ProxyConf,
    state: &RequestState,
    request: &mut RequestHeader,
) -> Result<()> {
    for (name, value) in &conf.set_headers {
        request.insert_header(name.clone(), state.eval(value))?;
    }
    Ok(())
}

/// Response headers Nginx never passes through by default (`ngx_http_upstream_headers_in`:
/// every listed field is handled specially, so the "hide" map drops it again) plus `X-Pad`.
const DEFAULT_HIDDEN: &[&str] = &[
    "date",
    "server",
    "x-pad",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
];

/// Whether `proxy_pass_header` re-enables `name`.
pub fn passes_through(conf: &ProxyConf, name: &str) -> bool {
    conf.pass_headers
        .iter()
        .any(|passed| passed.eq_ignore_ascii_case(name))
}

/// `ngx_http_upstream_hide_headers`: apply the default hidden set, the `X-Accel-*` control
/// fields and `proxy_hide_header`; `proxy_pass_header` re-enables any of them.
pub fn apply_response_headers(conf: &ProxyConf, response: &mut ResponseHeader) {
    let passed = |name: &str| passes_through(conf, name);
    for name in DEFAULT_HIDDEN {
        if !passed(name) {
            response.remove_header(*name);
        }
    }
    // `X-Accel-*` fields are control headers consumed by the upstream module.
    let accel: Vec<String> = response
        .headers
        .iter()
        .map(|(name, _)| name.as_str().to_string())
        .filter(|name| name.starts_with("x-accel-") && !passed(name))
        .collect();
    for name in accel {
        response.remove_header(name.as_str());
    }
    for name in &conf.hide_headers {
        if !passed(name) {
            response.remove_header(name);
        }
    }
}
/// Response rewriting after `proxy_hide_header`: `proxy_redirect`, `proxy_cookie_domain`,
/// `proxy_cookie_path` and `proxy_cookie_flags` (`ngx_http_proxy_rewrite_redirect`,
/// `ngx_http_proxy_rewrite_cookie`).
pub fn rewrite_response_headers(
    conf: &ProxyConf,
    pass: &ProxyPass,
    state: &RequestState,
    response: &mut ResponseHeader,
) -> anyhow::Result<()> {
    let mut evaluate = |template: &Template| template.eval(state);

    if !conf.redirects_off {
        let mut rules = Vec::new();
        // `proxy_redirect default`: the pattern is the `proxy_pass` URL without its trailing
        // path, the replacement the `Host` header Nginx uses (`ngx_http_proxy_pass`).
        if conf.redirects.is_empty()
            && let Some(base) = &pass.uri
        {
            let scheme = if pass.tls { "https" } else { "http" };
            // Nginx matches the URL as written in `proxy_pass` (host, port and URI) and
            // replaces it with `$scheme://$http_host` plus the request URI
            // (`ngx_http_proxy_pass`).
            rules.push(crate::modules::proxy_rewrite::Rewrite::parse(
                &format!("{scheme}://{}{base}", pass.url),
                Some(&format!("{scheme}://$http_host{base}")),
                true,
            )?);
        }
        rules.extend(conf.redirects.iter().cloned());
        rewrite_location(&rules, state, response)?;
        rewrite_refresh(&rules, state, response)?;
    }

    if !conf.cookie_domains.is_empty()
        || !conf.cookie_paths.is_empty()
        || !conf.cookie_flags.is_empty()
    {
        rewrite_cookies(conf, state, response)?;
    }
    let _ = &mut evaluate;
    Ok(())
}

/// `ngx_http_proxy_rewrite_redirect`: rewrite the `Location` header.
fn rewrite_location(
    rules: &[crate::modules::proxy_rewrite::Rewrite],
    state: &RequestState,
    response: &mut ResponseHeader,
) -> anyhow::Result<()> {
    let mut evaluate = |template: &Template| template.eval(state);
    let Some(location) = response
        .headers
        .get(http::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
    else {
        return Ok(());
    };
    for rule in rules {
        if let Some(rewritten) = rule.apply(&location, &mut evaluate) {
            response.insert_header(http::header::LOCATION, rewritten)?;
            break;
        }
    }
    Ok(())
}

/// `ngx_http_proxy_rewrite_redirect` also covers the `Refresh` header (`ngx_http_proxy_
/// rewrite_redirect_text`).
fn rewrite_refresh(
    rules: &[crate::modules::proxy_rewrite::Rewrite],
    state: &RequestState,
    response: &mut ResponseHeader,
) -> anyhow::Result<()> {
    let mut evaluate = |template: &Template| template.eval(state);
    let Some(refresh) = response
        .headers
        .get(http::header::REFRESH)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
    else {
        return Ok(());
    };
    let Some((prefix, url)) = split_refresh(&refresh) else {
        return Ok(());
    };
    for rule in rules {
        if let Some(rewritten) = rule.apply(url, &mut evaluate) {
            response.insert_header(http::header::REFRESH, format!("{prefix}{rewritten}"))?;
            break;
        }
    }
    Ok(())
}

/// Split `Refresh` into the `N; url=` prefix and the URL, per `ngx_http_proxy_rewrite_redirect_text`.
fn split_refresh(value: &str) -> Option<(&str, &str)> {
    let lower = value.to_ascii_lowercase();
    let start = lower.find("url=")?;
    Some((&value[..start + 4], &value[start + 4..]))
}

/// `ngx_http_proxy_rewrite_cookie`: rewrite `Domain`/`Path` attributes and cookie flags.
fn rewrite_cookies(
    conf: &ProxyConf,
    state: &RequestState,
    response: &mut ResponseHeader,
) -> anyhow::Result<()> {
    use crate::modules::proxy_rewrite::{CookiePart, edit_cookie_flags, parse_cookie, render_cookie};

    let values: Vec<String> = response
        .headers
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_string))
        .collect();
    if values.is_empty() {
        return Ok(());
    }
    response.remove_header("set-cookie");
    for value in values {
        let mut parts = parse_cookie(&value);
        for part in parts.iter_mut() {
            let CookiePart::Attribute { key, value } = part else {
                continue;
            };
            let Some(current) = value.clone() else {
                continue;
            };
            let rules = match key.to_ascii_lowercase().as_str() {
                "domain" => &conf.cookie_domains,
                "path" => &conf.cookie_paths,
                _ => continue,
            };
            let mut rewritten = current.clone();
            let mut evaluate = |template: &Template| template.eval(state);
            for rule in rules {
                if let Some(replacement) = rule.apply(&rewritten, &mut evaluate) {
                    rewritten = replacement;
                    break;
                }
            }
            *value = Some(rewritten);
        }
        for (name, flags) in &conf.cookie_flags {
            let cookie_name = name.eval(state);
            let matches = parts.first().is_some_and(|part| match part {
                CookiePart::Attribute { key, .. } => key.eq_ignore_ascii_case(&cookie_name),
                _ => false,
            });
            if matches {
                edit_cookie_flags(&mut parts, flags);
            }
        }
        let rendered = render_cookie(&parts);
        eprintln!("TRACE cookie-in=[{value}] out=[{rendered}]");
        response.append_header("set-cookie", rendered)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_nginx() {
        let conf = ProxyConf::default();
        // nginx >= 1.29.7 defaults `proxy_http_version` to 1.1.
        assert_eq!(conf.http_version, 11);
        // `ngx_http_proxy_merge_loc_conf`: 8 buffers of `ngx_pagesize`.
        assert_eq!(conf.buffers, (8, page_size()));
        assert_eq!(conf.buffer_size, page_size());
    }

    #[test]
    fn buffers_requires_at_least_two() {
        // `proxy_buffers 1 4096` is rejected ("there must be at least 2").
        let mut conf = ProxyConf::default();
        assert_eq!(conf.buffers.0, 8);
        conf.buffers = (2, 4096);
        assert_eq!(conf.buffers.0, 2);
    }

    #[test]
    fn literal_https_upstream_gets_port() {
        let pass = parse_pass("https://example.com/base/").unwrap();
        assert!(pass.tls);
        assert_eq!(pass.upstream, "example.com:443");
        assert_eq!(pass.url, "example.com:443");
        assert_eq!(pass.uri.as_deref(), Some("/base/"));
    }

    /// `proxy_redirect default` matches the upstream `Location` exactly as Nginx does.
    #[test]
    fn default_redirect_rule_matches_the_upstream_location() {
        let pass = parse_pass("http://127.0.0.1:9000/").unwrap();
        let base = pass.uri.clone().unwrap_or_default();
        let rule = crate::modules::proxy_rewrite::Rewrite::parse(
            &format!("http://{}{base}", pass.url),
            Some(&format!("http://$http_host{base}")),
            true,
        )
        .unwrap();
        let rewritten = rule.apply("http://127.0.0.1:9000/login", &mut |_| {
            "http://front.example/".to_string()
        });
        assert_eq!(rewritten.as_deref(), Some("http://front.example/login"));
    }

    #[test]
    fn named_upstream_keeps_name() {
        let pass = parse_pass("http://backend").unwrap();
        assert_eq!(pass.upstream, "backend");
        assert!(pass.uri.is_none());
    }

    #[test]
    fn literal_ip_is_direct_backend() {
        let pass = parse_pass("http://10.0.0.1:8080").unwrap();
        assert_eq!(pass.upstream, "10.0.0.1:8080");
    }

    #[test]
    fn proxy_uri_replaces_matched_prefix() {
        let pass = parse_pass("http://backend/v1/").unwrap();
        assert_eq!(proxy_uri(&pass, Some("/api/"), "/api/users"), "/v1/users");
    }
}

    #[test]
    fn debug_redirect_values() {
        let pass = parse_pass("http://127.0.0.1:9000/").unwrap();
        let base = pass.uri.clone().unwrap_or_default();
        let pattern = format!("http://{}{base}", pass.url);
        eprintln!("DEBUG url={} uri={:?} base={:?} pattern={:?}", pass.url, pass.uri, base, pattern);
        let rule = crate::modules::proxy_rewrite::Rewrite::parse(&pattern, Some(&format!("http://$http_host{base}")), true).unwrap();
        eprintln!("DEBUG rule={:?}", rule);
        let out = rule.apply("http://127.0.0.1:9000/login", &mut |_| "http://front.example/".to_string());
        eprintln!("DEBUG out={:?}", out);
        assert!(out.is_some());
    }
