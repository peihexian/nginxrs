//! FastCGI, uWSGI and SCGI directives accepted for configuration compatibility.
//!
//! `ngx_http_fastcgi_module`, `ngx_http_uwsgi_module` and `ngx_http_scgi_module` speak their
//! own wire protocols. nginxrs does not implement those protocols yet, so this module parses
//! and validates their directives (the way `ngx_http_upstream_param_set_slot` and
//! `ngx_conf_set_msec_slot` do) and records them; a configuration that only carries leftovers
//! such as `uwsgi_read_timeout 600;` keeps loading instead of failing on an unknown directive.
//!
//! Each accepted directive is logged once at load time so operators can see that it has no
//! runtime effect here.

use crate::core::syntax::Directive;
use crate::core::value::{parse_on_off, parse_size, parse_time};
use crate::core::variables::Template;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use anyhow::Result;

/// Which upstream protocol a directive belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Fastcgi,
    Uwsgi,
    Scgi,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Protocol::Fastcgi => "fastcgi",
            Protocol::Uwsgi => "uwsgi",
            Protocol::Scgi => "scgi",
        }
    }
}

/// One parsed but not executed directive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedDirective {
    pub protocol: Protocol,
    pub directive: &'static str,
    pub args: Vec<String>,
}

/// Configuration of the three protocol modules (`loc_conf` in nginx).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParamsConf {
    pub accepted: Vec<AcceptedDirective>,
    /// `fastcgi_param NAME value [if_not_empty]` entries, in order.
    pub params: Vec<(String, Template, bool)>,
}

impl LocationConf for ParamsConf {}

pub struct ParamsModule;

impl Module for ParamsModule {
    fn name(&self) -> &'static str {
        "ngx_http_fastcgi_module"
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        let mut specs = Vec::new();
        for protocol in [Protocol::Fastcgi, Protocol::Uwsgi, Protocol::Scgi] {
            let prefix = protocol.name();
            // Which directives exist per protocol (the C command tables).
            let mut names: Vec<&'static str> = vec![
                "connect_timeout",
                "send_timeout",
                "read_timeout",
                "send_lowat",
                "buffer_size",
                "buffers",
                "busy_buffers_size",
                "max_temp_file_size",
                "temp_file_write_size",
                "temp_path",
                "next_upstream",
                "next_upstream_tries",
                "next_upstream_timeout",
                "next_upstream_statuses",
                "next_upstream_timeouts",
                "hide_header",
                "pass_header",
                "ignore_headers",
                "ignore_client_abort",
                "intercept_errors",
                "store",
                "store_access",
                "request_buffering",
                "pass_request_body",
                "pass_request_headers",
                "cache",
                "cache_key",
                "cache_valid",
                "cache_bypass",
                "no_cache",
                "cache_methods",
                "cache_min_uses",
                "cache_use_stale",
                "cache_revalidate",
                "cache_background_update",
                "cache_lock",
                "limit_rate",
                "socket_keepalive",
                "bind",
                "pass",
                "param",
                "params_file",
                "catch_stderr",
                "ssl_protocols",
                "ssl_ciphers",
                "ssl_certificate",
                "ssl_certificate_key",
                "ssl_verify",
                "ssl_trusted_certificate",
                "force_ranges",
            ];
            if protocol == Protocol::Uwsgi {
                names.push("modifier1");
                names.push("modifier2");
            }
            for suffix in names {
                let name: &'static str = Box::leak(format!("{prefix}_{suffix}").into_boxed_str());
                specs.push(DirectiveSpec {
                    name,
                    contexts: &[Context::Http, Context::Server, Context::Location],
                    handler: accept,
                });
            }
        }
        specs
    }
}

/// Accept one directive after checking its arguments like the nginx setter would.
fn accept(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    let (protocol, suffix) = split_name(&directive.name);
    let Some(protocol) = protocol else {
        return Err(directive.error("unknown upstream protocol directive"));
    };
    validate(directive, suffix)?;
    let args = directive.args.clone();
    view.update_conf::<ParamsConf>(|conf| {
        conf.accepted.push(AcceptedDirective {
            protocol,
            directive: known_name(&directive.name),
            args,
        })
    })
}

/// The `'static` directive name recorded in the accepted list.
///
/// `directives()` leaks every registered name, so the lookup always succeeds; a name that is
/// not registered (impossible through the dispatcher) is leaked once instead.
fn known_name(name: &str) -> &'static str {
    for protocol in [Protocol::Fastcgi, Protocol::Uwsgi, Protocol::Scgi] {
        let prefix = protocol.name();
        if let Some(suffix) = name.strip_prefix(prefix) {
            let _ = suffix;
            return Box::leak(name.to_string().into_boxed_str());
        }
    }
    Box::leak(name.to_string().into_boxed_str())
}

/// Split `fastcgi_read_timeout` into the protocol and its suffix.
fn split_name(name: &str) -> (Option<Protocol>, &str) {
    for (protocol, prefix) in [
        (Protocol::Fastcgi, "fastcgi_"),
        (Protocol::Uwsgi, "uwsgi_"),
        (Protocol::Scgi, "scgi_"),
    ] {
        if let Some(suffix) = name.strip_prefix(prefix) {
            return (Some(protocol), suffix);
        }
    }
    (None, name)
}

/// Argument validation per directive family.
fn validate(directive: &Directive, suffix: &str) -> Result<()> {
    let args = &directive.args;
    if suffix.ends_with("_timeout") || suffix == "send_lowat" || suffix == "read_timeout" {
        if args.len() != 1 {
            return Err(directive.error("invalid number of arguments in this directive"));
        }
        parse_time(directive, &args[0])?;
        return Ok(());
    }
    if matches!(
        suffix,
        "buffer_size" | "max_temp_file_size" | "temp_file_write_size" | "limit_rate" | "send_lowat"
    ) {
        if args.len() != 1 {
            return Err(directive.error("invalid number of arguments in this directive"));
        }
        parse_size(directive, &args[0])?;
        return Ok(());
    }
    if suffix == "buffers" || suffix == "busy_buffers_size" {
        if args.is_empty() {
            return Err(directive.error("invalid number of arguments in this directive"));
        }
        for arg in args {
            parse_size(directive, arg)?;
        }
        return Ok(());
    }
    if suffix == "param" {
        directive.expect_args_range(2..=3)?;
        if args.len() == 3 && args[2] != "if_not_empty" {
            return Err(directive.error(format!("invalid parameter \"{}\"", args[2])));
        }
        Template::parse(&args[1])
            .map_err(|error| directive.error(format!("invalid parameter value: {error}")))?;
        return Ok(());
    }
    if matches!(
        suffix,
        "ignore_client_abort"
            | "intercept_errors"
            | "request_buffering"
            | "pass_request_body"
            | "pass_request_headers"
            | "cache_revalidate"
            | "cache_background_update"
            | "cache_lock"
            | "socket_keepalive"
            | "ssl_verify"
            | "force_ranges"
            | "buffering"
    ) {
        if args.len() == 1 {
            parse_on_off(directive, &args[0])?;
        }
        return Ok(());
    }
    Ok(())
}

/// Diagnostic lines for every accepted directive, logged when the configuration loads.
pub fn warnings(conf: &ParamsConf) -> Vec<String> {
    conf.accepted
        .iter()
        .map(|entry| {
            format!(
                "{} {} {}: accepted for configuration compatibility, but nginxrs has no {} \
                 upstream support yet (the directive has no runtime effect)",
                entry.protocol.name(),
                entry.directive,
                entry.args.join(" "),
                entry.protocol.name()
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn protocol_directives_load_into_a_location() {
        let config = Config::parse(
            r#"
            http {
                server {
                    listen 8080;
                    location / {
                        uwsgi_send_timeout 600;
                        uwsgi_connect_timeout 600;
                        uwsgi_read_timeout 600;
                        proxy_pass http://127.0.0.1:9000;
                    }
                }
            }
            "#,
        )
        .unwrap();
        let location = &config.http.servers[0].locations[0];
        let conf = location
            .conf
            .get::<ParamsConf>()
            .expect("protocol directives are recorded");
        assert_eq!(conf.accepted.len(), 3);
        assert!(conf.accepted.iter().all(|entry| entry.protocol == Protocol::Uwsgi));
        assert_eq!(warnings(conf).len(), 3);
    }

    #[test]
    fn invalid_arguments_are_rejected() {
        for source in [
            "uwsgi_read_timeout 600x;",
            "fastcgi_param KEY;",
            "scgi_buffer_size 12qz;",
        ] {
            let config = Config::parse(&format!(
                "http {{ server {{ listen 8080; location / {{ {source} }} }} }}"
            ));
            assert!(config.is_err(), "{source} must be rejected");
        }
    }

    #[test]
    fn fastcgi_config_file_parses() {
        // The stock `fastcgi.conf` is a valid parameter file.
        let config = Config::parse(
            r#"
            http {
                server {
                    listen 8080;
                    location / {
                        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                        fastcgi_param QUERY_STRING $query_string;
                        fastcgi_param HTTPS $https if_not_empty;
                        fastcgi_pass 127.0.0.1:9000;
                    }
                }
            }
            "#,
        )
        .unwrap();
        let conf = config.http.servers[0].locations[0]
            .conf
            .get::<ParamsConf>()
            .unwrap();
        assert_eq!(conf.accepted.len(), 4);
    }
}
