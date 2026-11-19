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
    pub tls: bool,
    pub host_header: String,
    /// URI part of `proxy_pass`; `None` keeps the rewritten request URI.
    pub uri: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ProxyConf {
    pub pass: Option<ProxyPass>,
    pub set_headers: Vec<(String, Template)>,
    pub hide_headers: Vec<String>,
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub send_timeout: Option<Duration>,
    pub next_upstream_tries: Option<usize>,
}

impl LocationConf for ProxyConf {}

pub struct ProxyModule;

impl Module for ProxyModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
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
        ]
    }
}

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

/// Compute the upstream request URI following Nginx `proxy_pass` semantics.
pub fn proxy_uri(pass: &ProxyPass, matched_prefix: Option<&str>, uri: &str) -> String {
    let Some(base) = &pass.uri else {
        return uri.to_string();
    };
    let suffix = matched_prefix
        .and_then(|prefix| uri.strip_prefix(prefix))
        .unwrap_or(uri);
    let base = base.trim_end_matches('/');
    if suffix.starts_with('/') || suffix.is_empty() {
        format!("{base}{suffix}")
    } else {
        format!("{base}/{suffix}")
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

/// Apply `proxy_hide_header` to the upstream response.
pub fn apply_response_headers(conf: &ProxyConf, response: &mut ResponseHeader) {
    for name in &conf.hide_headers {
        response.remove_header(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_https_upstream_gets_port() {
        let pass = parse_pass("https://example.com/base/").unwrap();
        assert!(pass.tls);
        assert_eq!(pass.upstream, "example.com:443");
        assert_eq!(pass.uri.as_deref(), Some("/base/"));
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
