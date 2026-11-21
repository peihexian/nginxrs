//! `upstream { keepalive … }` and `server … max_fails/fail_timeout`.
//!
//! `ngx_http_upstream_keepalive_module` keeps idle connections to the upstream and
//! `ngx_http_upstream_module`'s `server` parameters implement passive health checking:
//! nginx counts failures per peer and stops selecting a peer for `fail_timeout` once
//! `max_fails` failures happened (`ngx_http_upstream_rr_peer`). Both only need configuration
//! here; the connection pool itself is owned by the proxy exchange.

use crate::core::syntax::Directive;
use crate::core::value::parse_time;
use anyhow::Result;
use std::time::Duration;

/// `upstream … { keepalive N; keepalive_requests M; keepalive_timeout T; }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeepaliveConfig {
    /// `keepalive N`: idle connections per worker (0 = pooling disabled).
    pub connections: usize,
    /// `keepalive_requests M`: requests per connection (`1000` by default).
    pub requests: u32,
    /// `keepalive_timeout T`: idle timeout (`60s` by default).
    pub timeout: Duration,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            connections: 0,
            requests: 1000,
            timeout: Duration::from_secs(60),
        }
    }
}

impl KeepaliveConfig {
    /// Whether idle connections should be pooled.
    pub fn enabled(&self) -> bool {
        self.connections > 0
    }
}

/// Passive health check parameters of one `server` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassiveHealth {
    /// `max_fails N`: failures before the peer is skipped (`1` by default, `0` disables).
    pub max_fails: u32,
    /// `fail_timeout T`: how long a failed peer stays out (`10s` by default).
    pub fail_timeout: Duration,
}

impl Default for PassiveHealth {
    fn default() -> Self {
        Self {
            max_fails: 1,
            fail_timeout: Duration::from_secs(10),
        }
    }
}

impl PassiveHealth {
    pub fn enabled(&self) -> bool {
        self.max_fails > 0
    }
}

/// Parse one `server` option; `Ok(None)` when the option is not a health-check parameter.
pub fn parse_server_option(
    node: &Directive,
    option: &str,
    health: &mut PassiveHealth,
) -> Result<bool> {
    if let Some(value) = option.strip_prefix("max_fails=") {
        health.max_fails = value
            .parse()
            .map_err(|_| node.error("invalid max_fails"))?;
        return Ok(true);
    }
    if let Some(value) = option.strip_prefix("fail_timeout=") {
        health.fail_timeout = parse_time(node, value)?;
        return Ok(true);
    }
    Ok(false)
}

/// Parse one `keepalive*` directive inside an `upstream` block.
pub fn parse_directive(node: &Directive, config: &mut KeepaliveConfig) -> Result<bool> {
    match node.name.as_str() {
        "keepalive" => {
            node.expect_args(1)?;
            config.connections = node.args[0]
                .parse()
                .map_err(|_| node.error("invalid keepalive number"))?;
            Ok(true)
        }
        "keepalive_requests" => {
            node.expect_args(1)?;
            config.requests = node.args[0]
                .parse()
                .map_err(|_| node.error("invalid keepalive_requests"))?;
            Ok(true)
        }
        "keepalive_timeout" => {
            node.expect_args(1)?;
            config.timeout = parse_time(node, &node.args[0])?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::syntax::parse_str;

    fn node(source: &str) -> Directive {
        parse_str(source).unwrap().remove(0)
    }

    #[test]
    fn keepalive_defaults_and_parsing() {
        let mut config = KeepaliveConfig::default();
        assert!(!config.enabled());
        assert!(parse_directive(&node("keepalive 32;"), &mut config).unwrap());
        assert!(config.enabled());
        assert_eq!(config.connections, 32);
        assert!(parse_directive(&node("keepalive_timeout 30s;"), &mut config).unwrap());
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(parse_directive(&node("keepalive_requests 50;"), &mut config).unwrap());
        assert_eq!(config.requests, 50);
        assert!(!parse_directive(&node("least_conn;"), &mut config).unwrap());
    }

    #[test]
    fn server_options_parse() {
        let mut health = PassiveHealth::default();
        let directive = node("server 127.0.0.1:80;");
        assert!(
            parse_server_option(&directive, "max_fails=15", &mut health).unwrap()
        );
        assert_eq!(health.max_fails, 15);
        assert!(
            parse_server_option(&directive, "fail_timeout=10s", &mut health).unwrap()
        );
        assert_eq!(health.fail_timeout, Duration::from_secs(10));
        assert!(!parse_server_option(&directive, "weight=2", &mut health).unwrap());
        assert!(health.enabled());
        let disabled = PassiveHealth {
            max_fails: 0,
            ..PassiveHealth::default()
        };
        assert!(!disabled.enabled());
    }
}
