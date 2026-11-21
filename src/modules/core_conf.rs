//! The `ngx_http_core_module` location settings that have no dedicated module.
//!
//! `server_tokens`, `keepalive_timeout`, `client_*_buffer(s)`, `client_*_timeout`,
//! `send_timeout`, `sendfile*`, `underscores_in_headers`, `max_ranges`, `types_hash_*` and
//! `server_names_hash_bucket_size` all live on `ngx_http_core_loc_conf_t` / `_srv_conf_t`;
//! this file holds their configuration types and directive handlers, so `http_core.rs` stays
//! focused on the server/location tree.
//!
//! Nginx source: `ngx_http_core_create_loc_conf`, `ngx_http_core_merge_loc_conf`,
//! `ngx_http_core_module.c` command table.

use crate::core::limits::RequestLimits;
use crate::core::value::{parse_on_off, parse_size, parse_time};
use crate::core::{Context, DirectiveSpec};
use crate::modules::location::LocationConf;
use anyhow::Result;
use std::time::Duration;

/// `ngx_http_server_tokens_t`: `server_tokens on|off|build;`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServerTokens {
    /// `Server: nginx` (`off`).
    Off,
    /// `Server: nginxrs/…` (`on`, the default).
    #[default]
    On,
    /// `Server: nginxrs/… (build)` (`build`).
    Build,
}

impl ServerTokens {
    /// The `Server` header value for this mode (`ngx_http_header_filter_module.c`).
    pub fn header_value(&self) -> String {
        match self {
            ServerTokens::Off => "nginx".to_string(),
            ServerTokens::On => crate::SERVER_NAME.to_string(),
            ServerTokens::Build => crate::server_build_name(),
        }
    }
}

/// `server_tokens` (location/server/http scope).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokensConf(pub ServerTokens);

impl LocationConf for TokensConf {}

/// `keepalive_timeout`, `keepalive_requests`, `client_header_timeout`, `client_body_timeout`
/// and `send_timeout` (location/server/http scope for the timeouts, `http` for requests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreTimeouts {
    pub keepalive_timeout: Option<Duration>,
    pub keepalive_requests: Option<u32>,
    pub client_header_timeout: Option<Duration>,
    pub client_body_timeout: Option<Duration>,
    pub send_timeout: Option<Duration>,
}

impl Default for CoreTimeouts {
    fn default() -> Self {
        Self {
            keepalive_timeout: None,
            keepalive_requests: None,
            client_header_timeout: None,
            client_body_timeout: None,
            send_timeout: None,
        }
    }
}

impl LocationConf for CoreTimeouts {}

impl CoreTimeouts {
    /// `ngx_http_core_merge_loc_conf` defaults applied to this request's connection.
    pub fn limits(&self) -> RequestLimits {
        let defaults = RequestLimits::default();
        RequestLimits {
            header_timeout: self.client_header_timeout.unwrap_or(defaults.header_timeout),
            keepalive_timeout: self.keepalive_timeout.unwrap_or(defaults.keepalive_timeout),
            keepalive_requests: self.keepalive_requests.unwrap_or(defaults.keepalive_requests),
        }
    }
}

/// Request-line/header buffer sizes: `client_header_buffer_size` and
/// `large_client_header_buffers`. `connection_pool_size` bounds `large_client_header_buffers`
/// the same way `ngx_http_core_merge_srv_conf` does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientBuffers {
    pub client_header_buffer_size: usize,
    pub large_client_header_buffers: (usize, usize),
}

impl Default for ClientBuffers {
    fn default() -> Self {
        Self {
            client_header_buffer_size: 1024,
            large_client_header_buffers: (4, 8192),
        }
    }
}

impl LocationConf for ClientBuffers {}

impl ClientBuffers {
    /// The largest request line or header line accepted before `414`/`400`.
    pub fn max_header_line(&self) -> usize {
        self.large_client_header_buffers
            .1
            .max(self.client_header_buffer_size)
    }
}

/// `sendfile`, `sendfile_max_chunk`: file-transfer tuning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendfileConf {
    pub sendfile: bool,
    pub sendfile_max_chunk: usize,
}

impl Default for SendfileConf {
    fn default() -> Self {
        Self {
            sendfile: false,
            sendfile_max_chunk: 2 * 1024 * 1024,
        }
    }
}

impl LocationConf for SendfileConf {}

/// `max_ranges` (`ngx_http_range_filter_module`): `0` disables `Range` handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxRanges(pub u32);

impl Default for MaxRanges {
    fn default() -> Self {
        Self(u32::MAX)
    }
}

impl LocationConf for MaxRanges {}

impl MaxRanges {
    /// Whether a `Range` request is honored for this many ranges.
    pub fn allows(&self, ranges: usize) -> bool {
        self.0 != 0 && ranges <= self.0 as usize
    }
}

/// `server_names_hash_bucket_size` and `types_hash_max_size`: hash table tuning.
///
/// nginxrs resolves names with exact maps, so these only need to be validated; keeping them
/// here documents that the value was accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HashTuning {
    pub server_names_hash_bucket_size: Option<usize>,
    pub types_hash_max_size: Option<usize>,
}

impl LocationConf for HashTuning {}

/// `underscores_in_headers`: whether `x_foo` header names are accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnderscoresInHeaders(pub bool);

impl LocationConf for UnderscoresInHeaders {}

/// The directive table contributed by this file.
pub fn directives() -> Vec<DirectiveSpec> {
    vec![
        spec(
            "server_tokens",
            &[Context::Http, Context::Server, Context::Location],
            parse_server_tokens,
        ),
        spec(
            "keepalive_timeout",
            &[Context::Http, Context::Server, Context::Location],
            parse_keepalive_timeout,
        ),
        spec(
            "keepalive_requests",
            &[Context::Http, Context::Server, Context::Location],
            parse_keepalive_requests,
        ),
        spec(
            "client_header_timeout",
            &[Context::Http, Context::Server],
            parse_client_header_timeout,
        ),
        spec(
            "client_body_timeout",
            &[Context::Http, Context::Server, Context::Location],
            parse_client_body_timeout,
        ),
        spec(
            "send_timeout",
            &[Context::Http, Context::Server, Context::Location],
            parse_send_timeout,
        ),
        spec("client_body_buffer_size", &[Context::Http, Context::Server, Context::Location], parse_accepted_size),
        spec(
            "client_header_buffer_size",
            &[Context::Http, Context::Server],
            parse_client_header_buffer_size,
        ),
        spec(
            "large_client_header_buffers",
            &[Context::Http, Context::Server],
            parse_large_client_header_buffers,
        ),
        spec(
            "sendfile",
            &[Context::Http, Context::Server, Context::Location],
            parse_sendfile,
        ),
        spec(
            "sendfile_max_chunk",
            &[Context::Http, Context::Server, Context::Location],
            parse_sendfile_max_chunk,
        ),
        spec(
            "max_ranges",
            &[Context::Http, Context::Server, Context::Location],
            parse_max_ranges,
        ),
        spec(
            "server_names_hash_bucket_size",
            &[Context::Http],
            parse_server_names_hash_bucket_size,
        ),
        spec(
            "server_names_hash_max_size",
            &[Context::Http],
            parse_accepted_uint,
        ),
        spec("types_hash_max_size", &[Context::Http], parse_types_hash_max_size),
        spec("types_hash_bucket_size", &[Context::Http], parse_accepted_uint),
        spec(
            "underscores_in_headers",
            &[Context::Http, Context::Server],
            parse_underscores_in_headers,
        ),
        spec("tcp_nopush", &[Context::Http, Context::Server, Context::Location], parse_accepted_flag),
        spec("tcp_nodelay", &[Context::Http, Context::Server, Context::Location], parse_accepted_flag),
        spec("socket_keepalive", &[Context::Http, Context::Server], parse_accepted_flag),
        spec("postpone_output", &[Context::Http, Context::Server, Context::Location], parse_accepted_size),
        spec("merge_slashes", &[Context::Http, Context::Server], parse_accepted_flag),
        spec("ignore_invalid_headers", &[Context::Http, Context::Server], parse_accepted_flag),
        spec("max_headers", &[Context::Http, Context::Server], parse_accepted_uint),
        spec("connection_pool_size", &[Context::Http, Context::Server], parse_accepted_size),
        spec("request_pool_size", &[Context::Http, Context::Server], parse_accepted_size),
        spec("reset_timedout_connection", &[Context::Http, Context::Server, Context::Location], parse_accepted_flag),
        spec("absolute_redirect", &[Context::Http, Context::Server, Context::Location], parse_accepted_flag),
        spec("server_name_in_redirect", &[Context::Http, Context::Server, Context::Location], parse_accepted_flag),
        spec("port_in_redirect", &[Context::Http, Context::Server, Context::Location], parse_accepted_flag),
        spec("etag", &[Context::Http, Context::Server, Context::Location], parse_accepted_flag),
    ]
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

fn parse_server_tokens(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let mode = match directive.args[0].as_str() {
        "on" => ServerTokens::On,
        "off" => ServerTokens::Off,
        "build" => ServerTokens::Build,
        other => return Err(directive.error(format!("invalid value \"{other}\""))),
    };
    view.update_conf::<TokensConf>(|conf| conf.0 = mode)
}

fn parse_keepalive_timeout(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=2)?;
    let timeout = parse_time(directive, &directive.args[0])?;
    if let Some(header) = directive.args.get(1) {
        // `keepalive_header` only changes the `Keep-Alive:` response header value.
        parse_time(directive, header)?;
    }
    view.update_conf::<CoreTimeouts>(|conf| conf.keepalive_timeout = Some(timeout))
}

fn parse_keepalive_requests(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let requests: u32 = directive.args[0]
        .parse()
        .map_err(|_| directive.error("invalid keepalive_requests"))?;
    view.update_conf::<CoreTimeouts>(|conf| conf.keepalive_requests = Some(requests))
}

fn parse_client_header_timeout(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let timeout = parse_time(directive, &directive.args[0])?;
    view.update_conf::<CoreTimeouts>(|conf| conf.client_header_timeout = Some(timeout))
}

fn parse_client_body_timeout(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let timeout = parse_time(directive, &directive.args[0])?;
    view.update_conf::<CoreTimeouts>(|conf| conf.client_body_timeout = Some(timeout))
}

fn parse_send_timeout(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let timeout = parse_time(directive, &directive.args[0])?;
    view.update_conf::<CoreTimeouts>(|conf| conf.send_timeout = Some(timeout))
}

fn parse_client_header_buffer_size(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let size = parse_size(directive, &directive.args[0])?;
    if size == 0 {
        return Err(directive.error("client_header_buffer_size must be greater than zero"));
    }
    view.update_conf::<ClientBuffers>(|conf| conf.client_header_buffer_size = size as usize)
}

fn parse_large_client_header_buffers(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(2)?;
    let count: usize = directive.args[0]
        .parse()
        .map_err(|_| directive.error("invalid large_client_header_buffers number"))?;
    let size = parse_size(directive, &directive.args[1])? as usize;
    if count < 2 {
        return Err(directive.error(
            "the \"large_client_header_buffers\" number must be equal to or greater than 2",
        ));
    }
    if size < 8192 {
        return Err(directive.error(
            "the size of the \"large_client_header_buffers\" must be equal to or greater than 8192",
        ));
    }
    view.update_conf::<ClientBuffers>(|conf| conf.large_client_header_buffers = (count, size))
}

fn parse_sendfile(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let enabled = parse_on_off(directive, &directive.args[0])?;
    view.update_conf::<SendfileConf>(|conf| conf.sendfile = enabled)
}

fn parse_sendfile_max_chunk(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let size = parse_size(directive, &directive.args[0])? as usize;
    view.update_conf::<SendfileConf>(|conf| conf.sendfile_max_chunk = size)
}

fn parse_max_ranges(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value: u32 = directive.args[0]
        .parse()
        .map_err(|_| directive.error("invalid max_ranges"))?;
    view.update_conf::<MaxRanges>(|conf| conf.0 = value)
}

fn parse_server_names_hash_bucket_size(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let size = parse_size(directive, &directive.args[0])? as usize;
    view.update_conf::<HashTuning>(|conf| conf.server_names_hash_bucket_size = Some(size))
}

fn parse_types_hash_max_size(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let size = parse_size(directive, &directive.args[0])? as usize;
    view.update_conf::<HashTuning>(|conf| conf.types_hash_max_size = Some(size))
}

fn parse_underscores_in_headers(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let enabled = parse_on_off(directive, &directive.args[0])?;
    view.update_conf::<UnderscoresInHeaders>(|conf| conf.0 = enabled)
}

/// Directives that are accepted and validated but only affect socket/kernel behaviour the
/// Pingora runtime owns.
fn parse_accepted_flag(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    parse_on_off(directive, &directive.args[0])?;
    Ok(())
}

fn parse_accepted_uint(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    directive.args[0]
        .parse::<u64>()
        .map_err(|_| directive.error("invalid number"))?;
    Ok(())
}

fn parse_accepted_size(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    parse_size(directive, &directive.args[0])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_tokens_header_values() {
        assert_eq!(ServerTokens::Off.header_value(), "nginx");
        assert!(ServerTokens::On.header_value().starts_with("nginxrs/"));
        assert!(ServerTokens::Build.header_value().contains('('));
    }

    #[test]
    fn timeouts_merge_into_request_limits() {
        let conf = CoreTimeouts {
            keepalive_timeout: Some(Duration::from_secs(120)),
            keepalive_requests: Some(500),
            client_header_timeout: Some(Duration::from_secs(30)),
            ..CoreTimeouts::default()
        };
        let limits = conf.limits();
        assert_eq!(limits.keepalive_timeout, Duration::from_secs(120));
        assert_eq!(limits.keepalive_requests, 500);
        assert_eq!(limits.header_timeout, Duration::from_secs(30));
    }

    #[test]
    fn max_ranges_gate() {
        assert!(MaxRanges::default().allows(3));
        assert!(!MaxRanges(0).allows(1));
        assert!(MaxRanges(1).allows(1));
        assert!(!MaxRanges(1).allows(2));
    }

    #[test]
    fn default_header_line_limit_covers_client_header_buffer() {
        let buffers = ClientBuffers {
            client_header_buffer_size: 128 * 1024,
            large_client_header_buffers: (4, 512 * 1024),
        };
        assert_eq!(buffers.max_header_line(), 512 * 1024);
        assert_eq!(ClientBuffers::default().max_header_line(), 8192);
    }
}
