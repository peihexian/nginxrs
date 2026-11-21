//! The `grpc_*` directive table (`ngx_http_grpc_commands`) and its configuration.
//!
//! Most `grpc_*` directives mirror their `proxy_*` counterparts, and nginx reuses the very
//! same upstream structures (`ngx_http_upstream_conf_t`). The shared pieces therefore live in
//! [`crate::modules::proxy`] and are reused here instead of being copied:
//!
//! | grpc directive | shared type |
//! |---|---|
//! | `grpc_next_upstream` | [`crate::modules::proxy::UpstreamFailures`] |
//! | `grpc_ssl_protocols` | [`crate::modules::ssl::conf::Protocols`] |
//! | `grpc_set_header` | [`crate::core::variables::Template`] |
//!
//! The socket-level knobs (`grpc_bind`, `grpc_socket_*`) are validated and recorded; the
//! connection belongs to `h2`/`tokio` here, so they do not change it.

use crate::core::value::{parse_size, parse_time};
use crate::core::{Context, DirectiveSpec};
use crate::modules::location::LocationConf;
use crate::modules::proxy::UpstreamFailures;
use crate::modules::registry::DirectiveView;
use anyhow::{Result, bail};
use std::time::Duration;

/// `grpc_pass` target (`ngx_http_grpc_pass`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrpcPass {
    /// `upstream` group name, or `host:port` for a direct peer.
    pub upstream: String,
    /// The target as written, used for `:authority` defaults.
    pub authority: String,
    /// `grpcs://` — HTTP/2 over TLS.
    pub tls: bool,
}

impl GrpcPass {
    /// `grpc://host:port`, `grpcs://host:port`, or a bare `host[:port]`/`upstream` name.
    pub fn parse(value: &str) -> Result<Self> {
        let (tls, rest) = match value.split_once("://") {
            Some(("grpc", rest)) => (false, rest),
            Some(("grpcs", rest)) => (true, rest),
            Some((scheme, _)) => bail!("invalid scheme \"{scheme}\" in grpc_pass"),
            None => (false, value),
        };
        if rest.is_empty() {
            bail!("invalid grpc_pass target \"{value}\"");
        }
        let rest = rest.trim_end_matches('/');
        // A bare name without a port is an `upstream` block (`ngx_http_upstream_add`);
        // everything else is a direct peer.
        let upstream = rest.to_string();
        Ok(Self {
            upstream,
            authority: rest.to_string(),
            tls,
        })
    }

    /// Whether the target names an `upstream` group rather than a `host:port` peer.
    pub fn is_group(&self) -> bool {
        !self.authority.contains(':')
    }
}

/// `ngx_http_grpc_loc_conf_t`.
#[derive(Clone, Debug)]
pub struct GrpcConf {
    pub pass: Option<GrpcPass>,
    pub connect_timeout: Option<Duration>,
    pub send_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub buffer_size: Option<usize>,
    pub next_upstream: UpstreamFailures,
    pub next_upstream_tries: Option<usize>,
    pub next_upstream_timeout: Option<Duration>,
    pub set_headers: Vec<(String, crate::core::variables::Template)>,
    pub hide_headers: Vec<String>,
    pub pass_headers: Vec<String>,
    pub intercept_errors: bool,
    pub ssl_protocols: crate::modules::ssl::conf::Protocols,
    pub ssl_ciphers: Vec<String>,
    pub ssl_server_name: bool,
    pub ssl_name: Option<crate::core::variables::Template>,
    pub ssl_verify: bool,
    pub ssl_verify_depth: usize,
    pub ssl_trusted_certificate: Option<std::path::PathBuf>,
    pub ssl_crl: Option<std::path::PathBuf>,
    pub ssl_certificate: Vec<std::path::PathBuf>,
    pub ssl_certificate_key: Vec<std::path::PathBuf>,
    pub ssl_session_reuse: bool,
    pub socket_keepalive: bool,
    pub socket_rcvbuf: Option<usize>,
    pub socket_sndbuf: Option<usize>,
    pub bind: Option<String>,
}

impl Default for GrpcConf {
    fn default() -> Self {
        Self {
            pass: None,
            // `ngx_http_upstream` defaults: 60s for connect, send and read.
            connect_timeout: Some(Duration::from_secs(60)),
            send_timeout: Some(Duration::from_secs(60)),
            read_timeout: Some(Duration::from_secs(60)),
            buffer_size: None,
            next_upstream: UpstreamFailures(UpstreamFailures::DEFAULT),
            next_upstream_tries: None,
            next_upstream_timeout: None,
            set_headers: Vec::new(),
            hide_headers: Vec::new(),
            pass_headers: Vec::new(),
            intercept_errors: false,
            ssl_protocols: crate::modules::ssl::conf::Protocols(
                crate::modules::ssl::conf::Protocols::TLSV1_2
                    | crate::modules::ssl::conf::Protocols::TLSV1_3,
            ),
            ssl_ciphers: Vec::new(),
            ssl_server_name: false,
            ssl_name: None,
            ssl_verify: false,
            ssl_verify_depth: 1,
            ssl_trusted_certificate: None,
            ssl_crl: None,
            ssl_certificate: Vec::new(),
            ssl_certificate_key: Vec::new(),
            ssl_session_reuse: true,
            socket_keepalive: false,
            socket_rcvbuf: None,
            socket_sndbuf: None,
            bind: None,
        }
    }
}

impl LocationConf for GrpcConf {
    fn inherit(&self) -> bool {
        true
    }
}

fn flag(directive: &crate::core::syntax::Directive, text: &str) -> Result<bool> {
    match text {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(directive.error(format!(
            "invalid value \"{other}\", it must be \"on\" or \"off\""
        ))),
    }
}

fn one(view: &mut DirectiveView<'_>) -> Result<String> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    Ok(directive.args[0].clone())
}

fn parse_pass(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let pass = GrpcPass::parse(&directive.args[0])
        .map_err(|error: anyhow::Error| directive.error(error.to_string()))?;
    view.update_conf::<GrpcConf>(|conf| conf.pass = Some(pass))?;
    Ok(())
}

fn timeout(
    view: &mut DirectiveView<'_>,
    set: fn(&mut GrpcConf, Duration),
) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = parse_time(directive, &directive.args[0])?;
    view.update_conf::<GrpcConf>(|conf| set(conf, value))?;
    Ok(())
}

fn parse_connect_timeout(view: &mut DirectiveView<'_>) -> Result<()> {
    timeout(view, |conf, value| conf.connect_timeout = Some(value))
}

fn parse_send_timeout(view: &mut DirectiveView<'_>) -> Result<()> {
    timeout(view, |conf, value| conf.send_timeout = Some(value))
}

fn parse_read_timeout(view: &mut DirectiveView<'_>) -> Result<()> {
    timeout(view, |conf, value| conf.read_timeout = Some(value))
}

fn parse_next_timeout(view: &mut DirectiveView<'_>) -> Result<()> {
    timeout(view, |conf, value| conf.next_upstream_timeout = Some(value))
}

fn parse_buffer(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let size = parse_size(directive, &directive.args[0])? as usize;
    if size == 0 {
        return Err(directive.error("value must be greater than 0"));
    }
    view.update_conf::<GrpcConf>(|conf| conf.buffer_size = Some(size))?;
    Ok(())
}

fn parse_tries(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let tries: usize = directive.args[0]
        .parse()
        .map_err(|_| directive.error(format!("invalid number \"{}\"", directive.args[0])))?;
    view.update_conf::<GrpcConf>(|conf| conf.next_upstream_tries = Some(tries))?;
    Ok(())
}

fn parse_next_upstream(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() {
        return Err(directive.error("expected grpc_next_upstream condition ..."));
    }
    let mut mask = 0_u32;
    for value in &directive.args {
        let Some(flag) = UpstreamFailures::parse(value) else {
            return Err(directive.error(format!(
                "invalid value \"{value}\" in \"grpc_next_upstream\" directive"
            )));
        };
        mask |= flag;
    }
    if mask & UpstreamFailures::OFF != 0 {
        // `off` replaces every other condition.
        mask = UpstreamFailures::OFF;
    }
    view.update_conf::<GrpcConf>(|conf| conf.next_upstream = UpstreamFailures(mask))?;
    Ok(())
}

fn parse_set_header(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(2..=2)?;
    let name = directive.args[0].clone();
    let template = crate::core::variables::Template::parse(&directive.args[1])
        .map_err(|error| directive.error(format!("invalid grpc_set_header: {error}")))?;
    view.update_conf::<GrpcConf>(|conf| {
        conf.set_headers
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(&name));
        conf.set_headers.push((name, template));
    })?;
    Ok(())
}

fn parse_hide_header(view: &mut DirectiveView<'_>) -> Result<()> {
    let value = one(view)?;
    view.update_conf::<GrpcConf>(|conf| conf.hide_headers.push(value))?;
    Ok(())
}

fn parse_pass_header(view: &mut DirectiveView<'_>) -> Result<()> {
    let value = one(view)?;
    view.update_conf::<GrpcConf>(|conf| conf.pass_headers.push(value))?;
    Ok(())
}

fn parse_intercept(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = flag(directive, &directive.args[0])?;
    view.update_conf::<GrpcConf>(|conf| conf.intercept_errors = value)?;
    Ok(())
}

fn parse_socket_keepalive(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = flag(directive, &directive.args[0])?;
    view.update_conf::<GrpcConf>(|conf| conf.socket_keepalive = value)?;
    Ok(())
}

fn parse_rcvbuf(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let size = parse_size(directive, &directive.args[0])? as usize;
    view.update_conf::<GrpcConf>(|conf| conf.socket_rcvbuf = Some(size))?;
    Ok(())
}

fn parse_sndbuf(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let size = parse_size(directive, &directive.args[0])? as usize;
    view.update_conf::<GrpcConf>(|conf| conf.socket_sndbuf = Some(size))?;
    Ok(())
}

fn parse_bind(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=2)?;
    let address = directive.args[0].clone();
    view.update_conf::<GrpcConf>(|conf| conf.bind = Some(address))?;
    Ok(())
}

fn parse_ssl_server_name(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = flag(directive, &directive.args[0])?;
    view.update_conf::<GrpcConf>(|conf| conf.ssl_server_name = value)?;
    Ok(())
}

fn parse_ssl_name(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let template = crate::core::variables::Template::parse(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid grpc_ssl_name: {error}")))?;
    view.update_conf::<GrpcConf>(|conf| conf.ssl_name = Some(template))?;
    Ok(())
}

fn parse_ssl_verify(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = flag(directive, &directive.args[0])?;
    view.update_conf::<GrpcConf>(|conf| conf.ssl_verify = value)?;
    Ok(())
}

fn parse_ssl_verify_depth(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let depth: usize = directive.args[0]
        .parse()
        .map_err(|_| directive.error(format!("invalid number \"{}\"", directive.args[0])))?;
    view.update_conf::<GrpcConf>(|conf| conf.ssl_verify_depth = depth)?;
    Ok(())
}

fn parse_ssl_trusted(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let path = view.path(&directive.args[0]);
    view.update_conf::<GrpcConf>(|conf| conf.ssl_trusted_certificate = Some(path))?;
    Ok(())
}

fn parse_ssl_crl(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let path = view.path(&directive.args[0]);
    view.update_conf::<GrpcConf>(|conf| conf.ssl_crl = Some(path))?;
    Ok(())
}

fn parse_ssl_ciphers(view: &mut DirectiveView<'_>) -> Result<()> {
    let value = one(view)?;
    view.update_conf::<GrpcConf>(|conf| conf.ssl_ciphers.push(value))?;
    Ok(())
}

fn parse_ssl_protocols(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() {
        return Err(directive.error("expected grpc_ssl_protocols ..."));
    }
    let mut protocols = crate::modules::ssl::conf::Protocols::empty();
    for value in &directive.args {
        let bit = match value.as_str() {
            "TLSv1" => crate::modules::ssl::conf::Protocols::TLSV1,
            "TLSv1.1" => crate::modules::ssl::conf::Protocols::TLSV1_1,
            "TLSv1.2" => crate::modules::ssl::conf::Protocols::TLSV1_2,
            "TLSv1.3" => crate::modules::ssl::conf::Protocols::TLSV1_3,
            "SSLv2" | "SSLv3" => {
                return Err(directive.error(format!(
                    "invalid value \"{value}\" in \"grpc_ssl_protocols\" directive"
                )));
            }
            other => {
                return Err(directive.error(format!(
                    "invalid value \"{other}\" in \"grpc_ssl_protocols\" directive"
                )));
            }
        };
        protocols = protocols.union(crate::modules::ssl::conf::Protocols(bit));
    }
    view.update_conf::<GrpcConf>(|conf| conf.ssl_protocols = protocols)?;
    Ok(())
}

fn parse_ssl_session_reuse(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = flag(directive, &directive.args[0])?;
    view.update_conf::<GrpcConf>(|conf| conf.ssl_session_reuse = value)?;
    Ok(())
}

fn parse_ssl_certificate(view: &mut DirectiveView<'_>) -> Result<()> {
    named_files(view, true)
}

fn parse_ssl_certificate_key(view: &mut DirectiveView<'_>) -> Result<()> {
    named_files(view, false)
}

/// `grpc_ssl_certificate`/`_key`: `file` or `name:file` (`ngx_ssl_certificate`'s RSA list).
fn named_files(view: &mut DirectiveView<'_>, certificate: bool) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=usize::MAX)?;
    let mut entries = Vec::new();
    for argument in &directive.args {
        // `name:file` selects a certificate type; the file part is what gets loaded.
        let path = match argument.split_once(':') {
            Some((name, path))
                if !name.contains('/')
                    && !name.contains('\\')
                    && path.len() > 1
                    && path.as_bytes().get(1) != Some(&b':') =>
            {
                path
            }
            _ => argument.as_str(),
        };
        let path = view.path(path);
        if !path.exists() {
            return Err(directive.error(format!(
                "grpc_ssl_{} \"{}\" failed (No such file or directory)",
                if certificate { "certificate" } else { "certificate_key" },
                path.display()
            )));
        }
        entries.push(path);
    }
    view.update_conf::<GrpcConf>(|conf| {
        if certificate {
            conf.ssl_certificate = entries;
        } else {
            conf.ssl_certificate_key = entries;
        }
    })?;
    Ok(())
}

fn parse_ssl_certificate_cache(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=3)?;
    // `max=N` and `inactive=T`; the certificates are loaded once at configuration time here.
    for argument in &directive.args {
        if !argument.starts_with("max=")
            && !argument.starts_with("inactive=")
            && !argument.starts_with("valid=")
        {
            return Err(directive.error(format!(
                "invalid parameter \"{argument}\" in \"grpc_ssl_certificate_cache\" directive"
            )));
        }
    }
    Ok(())
}

fn parse_ssl_password_file(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let path = view.path(&directive.args[0]);
    if !path.exists() {
        return Err(directive.error(format!(
            "grpc_ssl_password_file \"{}\" failed (No such file or directory)",
            path.display()
        )));
    }
    Ok(())
}

fn parse_ssl_conf_command(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(2..=2)?;
    Err(directive.error(
        "grpc_ssl_conf_command is not supported by the rustls client",
    ))
}

/// Every directive of `ngx_http_grpc_commands`.
pub fn directives() -> Vec<DirectiveSpec> {
    const CTX: &[Context] = &[Context::Http, Context::Server, Context::Location];
    // `grpc_pass` is `NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF`: a location, or an `if` block
    // inside one (where nginx silently accepts it; the location's value still wins).
    const PASS: &[Context] = &[Context::Location];
    vec![
        spec("grpc_pass", PASS, parse_pass),
        spec("grpc_bind", CTX, parse_bind),
        spec("grpc_socket_keepalive", CTX, parse_socket_keepalive),
        spec("grpc_socket_rcvbuf", CTX, parse_rcvbuf),
        spec("grpc_socket_sndbuf", CTX, parse_sndbuf),
        spec("grpc_connect_timeout", CTX, parse_connect_timeout),
        spec("grpc_send_timeout", CTX, parse_send_timeout),
        spec("grpc_read_timeout", CTX, parse_read_timeout),
        spec("grpc_next_upstream_timeout", CTX, parse_next_timeout),
        spec("grpc_buffer_size", CTX, parse_buffer),
        spec("grpc_next_upstream", CTX, parse_next_upstream),
        spec("grpc_next_upstream_tries", CTX, parse_tries),
        spec("grpc_set_header", CTX, parse_set_header),
        spec("grpc_pass_header", CTX, parse_pass_header),
        spec("grpc_hide_header", CTX, parse_hide_header),
        spec("grpc_intercept_errors", CTX, parse_intercept),
        spec("grpc_ssl_server_name", CTX, parse_ssl_server_name),
        spec("grpc_ssl_name", CTX, parse_ssl_name),
        spec("grpc_ssl_verify", CTX, parse_ssl_verify),
        spec("grpc_ssl_verify_depth", CTX, parse_ssl_verify_depth),
        spec("grpc_ssl_trusted_certificate", CTX, parse_ssl_trusted),
        spec("grpc_ssl_crl", CTX, parse_ssl_crl),
        spec("grpc_ssl_ciphers", CTX, parse_ssl_ciphers),
        spec("grpc_ssl_protocols", CTX, parse_ssl_protocols),
        spec("grpc_ssl_session_reuse", CTX, parse_ssl_session_reuse),
        spec("grpc_ssl_certificate", CTX, parse_ssl_certificate),
        spec("grpc_ssl_certificate_key", CTX, parse_ssl_certificate_key),
        spec("grpc_ssl_certificate_cache", CTX, parse_ssl_certificate_cache),
        spec("grpc_ssl_password_file", CTX, parse_ssl_password_file),
        spec("grpc_ssl_conf_command", CTX, parse_ssl_conf_command),
    ]
}

fn spec(
    name: &'static str,
    contexts: &'static [Context],
    handler: fn(&mut DirectiveView<'_>) -> Result<()>,
) -> DirectiveSpec {
    DirectiveSpec {
        name,
        contexts,
        handler,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf_of(source: &str) -> GrpcConf {
        let registry = crate::modules::Registry::default_modules();
        let directives = crate::core::syntax::parse_str(source).unwrap();
        let mut states: Vec<crate::core::state::StateSlot> = vec![(
            "main",
            crate::core::state::StateInstance::new(crate::config::MainState::default()),
        )];
        let mut location = crate::modules::location::Location::new();
        for directive in &directives {
            let mut access = crate::core::state::StateAccess::new(&mut states);
            registry
                .dispatch(
                    directive,
                    Context::Location,
                    std::path::Path::new("."),
                    &mut access,
                    Some(&mut location),
                )
                .unwrap();
        }
        location.get::<GrpcConf>().cloned().unwrap_or_default()
    }

    #[test]
    fn pass_targets() {
        let plain = GrpcPass::parse("grpc://127.0.0.1:50051").unwrap();
        assert!(!plain.tls);
        assert_eq!(plain.upstream, "127.0.0.1:50051");
        assert!(!plain.is_group());
        let secure = GrpcPass::parse("grpcs://backend.example:443").unwrap();
        assert!(secure.tls);
        // A bare name is an `upstream` group; nginx defaults it to `grpc://`.
        let group = GrpcPass::parse("backend").unwrap();
        assert!(!group.tls);
        assert!(group.is_group());
        assert!(GrpcPass::parse("http://host:80").is_err());
        assert!(GrpcPass::parse("grpc://").is_err());
    }

    #[test]
    fn defaults_match_upstream() {
        let conf = GrpcConf::default();
        assert_eq!(conf.connect_timeout, Some(Duration::from_secs(60)));
        assert_eq!(conf.send_timeout, Some(Duration::from_secs(60)));
        assert_eq!(conf.read_timeout, Some(Duration::from_secs(60)));
        assert!(conf.pass.is_none());
        assert_eq!(conf.ssl_verify_depth, 1);
        assert!(conf.ssl_verify == false);
        assert!(conf.ssl_server_name == false);
    }

    #[test]
    fn directives_are_parsed() {
        let conf = conf_of(
            "grpc_pass grpc://127.0.0.1:50051;
             grpc_read_timeout 5s;
             grpc_buffer_size 8k;
             grpc_set_header X-Real-IP $remote_addr;
             grpc_set_header X-Real-IP $host;
             grpc_hide_header X-Internal;
             grpc_next_upstream error timeout;
             grpc_ssl_protocols TLSv1.2 TLSv1.3;",
        );
        assert_eq!(conf.pass.as_ref().unwrap().upstream, "127.0.0.1:50051");
        assert_eq!(conf.read_timeout, Some(Duration::from_secs(5)));
        assert_eq!(conf.buffer_size, Some(8192));
        assert_eq!(conf.set_headers.len(), 1);
        assert_eq!(conf.hide_headers, ["X-Internal"]);
    }

    #[test]
    fn invalid_values_are_rejected() {
        let registry = crate::modules::Registry::default_modules();
        for source in [
            "grpc_pass http://127.0.0.1:1;",
            "grpc_buffer_size 0;",
            "grpc_next_upstream nope;",
            "grpc_ssl_protocols SSLv3;",
        ] {
            let directives = crate::core::syntax::parse_str(source).unwrap();
            let mut states: Vec<crate::core::state::StateSlot> = vec![(
                "main",
                crate::core::state::StateInstance::new(crate::config::MainState::default()),
            )];
            let mut location = crate::modules::location::Location::new();
            let mut access = crate::core::state::StateAccess::new(&mut states);
            assert!(
                registry
                    .dispatch(
                        &directives[0],
                        Context::Location,
                        std::path::Path::new("."),
                        &mut access,
                        Some(&mut location),
                    )
                    .is_err(),
                "{source} must be rejected"
            );
        }
    }
}
