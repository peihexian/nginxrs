//! `ngx_http_realip_module` equivalent.
//!
//! Rewrites `$remote_addr`/`$remote_port` from a trusted proxy header. The module is a
//! pure function of the request state, so it is independent of the proxy, static and Lua
//! modules and can be composed with any of them.

use crate::core::http::RequestState;
use crate::core::variables::VariableProvider;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use anyhow::Result;
use http::HeaderName;
use std::net::IpAddr;

pub const MODULE_NAME: &str = "ngx_http_realip_module";

/// Trusted source specification from `set_real_ip_from`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustedSource {
    /// A single IP address.
    Address(IpAddr),
    /// A CIDR block, canonicalised to match Nginx's address comparisons.
    Cidr { network: IpAddr, prefix: u8 },
    /// `unix:` — accepted for compatibility but never matches TCP connections here.
    Unix,
}

impl TrustedSource {
    /// Parse one `set_real_ip_from` argument.
    ///
    /// Mirrors `ngx_http_realip_from`: `unix:` first, then CIDR, then a host name which is
    /// resolved at configuration time (`ngx_inet_resolve_host`). Host names produce one
    /// entry per resolved address, like the C array push.
    pub fn parse_all(value: &str) -> Result<Vec<Self>, String> {
        if value == "unix:" {
            return Ok(vec![TrustedSource::Unix]);
        }
        if let Some((network, prefix)) = value.split_once('/') {
            let network: IpAddr = network
                .parse()
                .map_err(|_| format!("invalid address \"{network}\""))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| format!("invalid prefix length \"{prefix}\""))?;
            let max = if network.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(format!("invalid prefix length \"{prefix}\""));
            }
            return Ok(vec![TrustedSource::Cidr { network, prefix }]);
        }
        if let Ok(address) = value.parse::<IpAddr>() {
            return Ok(vec![TrustedSource::Address(address)]);
        }
        // Host name: resolve now so every request uses a fixed trust list.
        let mut resolved: Vec<Self> = Vec::new();
        let addrs = std::net::ToSocketAddrs::to_socket_addrs(&(value, 0))
            .map_err(|error| format!("host \"{value}\" could not be resolved: {error}"))?;
        for address in addrs {
            let source = TrustedSource::Address(address.ip());
            if !resolved.contains(&source) {
                resolved.push(source);
            }
        }
        if resolved.is_empty() {
            return Err(format!("host \"{value}\" could not be resolved"));
        }
        Ok(resolved)
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match self {
            TrustedSource::Address(trusted) => *trusted == address,
            TrustedSource::Unix => false,
            TrustedSource::Cidr { network, prefix } => match (network, address) {
                (IpAddr::V4(network), IpAddr::V4(address)) => {
                    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
                    (u32::from(*network) & mask) == (u32::from(address) & mask)
                }
                (IpAddr::V6(network), IpAddr::V6(address)) => {
                    let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
                    (u128::from(*network) & mask) == (u128::from(address) & mask)
                }
                // IPv4-mapped IPv6 peers are compared against IPv4 networks.
                (IpAddr::V4(network), IpAddr::V6(address)) => {
                    address.to_ipv4_mapped().is_some_and(|mapped| {
                        Self::Cidr {
                            network: IpAddr::V4(*network),
                            prefix: *prefix,
                        }
                        .contains(IpAddr::V4(mapped))
                    })
                }
                _ => false,
            },
        }
    }

    /// Whether the address is a trusted proxy for this configuration
    /// (`ngx_cidr_match` over the `from` array).
    pub fn trusted(list: &[TrustedSource], address: IpAddr) -> bool {
        list.iter().any(|source| source.contains(address))
    }
}

/// `real_ip_header`, mirroring Nginx's `NGX_HTTP_REALIP_*` types.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum HeaderSource {
    #[default]
    XRealIp,
    XForwardedFor,
    /// `proxy_protocol` — requires the PROXY protocol listener, which is not implemented.
    ProxyProtocol,
    Custom(HeaderName),
}

impl HeaderSource {
    /// `real_ip_header` compares the literal `X-Real-IP`, `X-Forwarded-For` and
    /// `proxy_protocol` (case-sensitive, as in `ngx_http_realip`); anything else is a
    /// custom header name matched case-insensitively.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "X-Real-IP" => Ok(HeaderSource::XRealIp),
            "X-Forwarded-For" => Ok(HeaderSource::XForwardedFor),
            "proxy_protocol" => Ok(HeaderSource::ProxyProtocol),
            other => HeaderName::from_bytes(other.to_ascii_lowercase().as_bytes())
                .map(HeaderSource::Custom)
                .map_err(|_| format!("invalid header name \"{value}\"")),
        }
    }

    pub fn header_name(&self) -> Option<HeaderName> {
        match self {
            HeaderSource::XRealIp => Some(HeaderName::from_static("x-real-ip")),
            HeaderSource::XForwardedFor => Some(HeaderName::from_static("x-forwarded-for")),
            HeaderSource::ProxyProtocol => None,
            HeaderSource::Custom(name) => Some(name.clone()),
        }
    }
}

/// Configuration from `set_real_ip_from`, `real_ip_header` and `real_ip_recursive`.
///
/// Nginx allows these directives in `http`, `server` and `location`; the value is
/// inherited by nested contexts unless overridden (`ngx_http_realip_merge_loc_conf`).
/// `real_ip_header` is a duplicate if set twice in the same context, matching
/// `ngx_http_realip()`'s `is duplicate` check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealipConf {
    pub trusted: Vec<TrustedSource>,
    pub header: HeaderSource,
    /// `real_ip_header` was assigned in this context (needed for the duplicate check).
    pub header_set: bool,
    pub recursive: bool,
}

impl LocationConf for RealipConf {}

impl RealipConf {
    pub fn enabled(&self) -> bool {
        !self.trusted.is_empty()
    }
}

pub struct RealipModule;

impl Module for RealipModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            DirectiveSpec {
                name: "set_real_ip_from",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_set_real_ip_from,
            },
            DirectiveSpec {
                name: "real_ip_header",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_real_ip_header,
            },
            DirectiveSpec {
                name: "real_ip_recursive",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_real_ip_recursive,
            },
        ]
    }

    fn variables(&self) -> Vec<(&'static str, &'static dyn VariableProvider)> {
        vec![
            ("realip_remote_addr", &RealipRemoteAddr),
            ("realip_remote_port", &RealipRemotePort),
        ]
    }
}

pub struct RealipRemoteAddr;
pub struct RealipRemotePort;

pub static REALIP_REMOTE_ADDR: RealipRemoteAddr = RealipRemoteAddr;
pub static REALIP_REMOTE_PORT: RealipRemotePort = RealipRemotePort;

impl std::fmt::Debug for RealipRemoteAddr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("realip_remote_addr")
    }
}

impl std::fmt::Debug for RealipRemotePort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("realip_remote_port")
    }
}

impl VariableProvider for RealipRemoteAddr {
    fn module(&self) -> &'static str {
        MODULE_NAME
    }

    fn get(&self, state: &RequestState) -> Option<String> {
        Some(
            state
                .client
                .original_addr
                .map(|address| address.to_string())
                .unwrap_or_default(),
        )
    }
}

impl VariableProvider for RealipRemotePort {
    fn module(&self) -> &'static str {
        MODULE_NAME
    }

    fn get(&self, state: &RequestState) -> Option<String> {
        Some(state.client.original_port.to_string())
    }
}

fn parse_set_real_ip_from(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let sources = TrustedSource::parse_all(&directive.args[0])
        .map_err(|error| directive.error(format!("set_real_ip_from: {error}")))?;
    view.update_conf::<RealipConf>(|conf| {
        for source in sources {
            if !conf.trusted.contains(&source) {
                conf.trusted.push(source);
            }
        }
    })
}

fn parse_real_ip_header(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let header = HeaderSource::parse(&directive.args[0])
        .map_err(|error| directive.error(format!("real_ip_header: {error}")))?;
    let duplicate = view
        .location_conf::<RealipConf>()
        .is_some_and(|conf| conf.header_set);
    if duplicate {
        return Err(directive.error("\"real_ip_header\" is duplicate"));
    }
    view.update_conf::<RealipConf>(|conf| {
        conf.header = header;
        conf.header_set = true;
    })
}

fn parse_real_ip_recursive(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let recursive = crate::core::value::parse_on_off(directive, &directive.args[0])?;
    view.update_conf::<RealipConf>(|conf| conf.recursive = recursive)
}

/// Result of applying realip to one request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealipOutcome {
    pub changed: bool,
    pub addr: Option<IpAddr>,
    pub port: u16,
    pub original_addr: Option<IpAddr>,
    pub original_port: u16,
}

/// Apply realip semantics for one request (Nginx `ngx_http_realip_handler`).
///
/// The trusted list is checked against the current `$remote_addr`. With
/// `real_ip_recursive on` the address list is walked from the nearest hop towards the
/// client, skipping trusted proxies; the first untrusted address wins. Otherwise the
/// first header entry is used. `realip_remote_addr`/`realip_remote_port` always keep the
/// original peer.
pub fn apply(conf: &RealipConf, state: &mut RequestState) -> RealipOutcome {
    let original_addr = state.client.original_addr.or(state.connection.peer_ip);
    let original_port = if state.connection.peer_port == 0 {
        state.client.original_port
    } else {
        state.connection.peer_port
    };
    let current = state
        .client
        .addr
        .or(state.connection.peer_ip)
        .or(original_addr);
    let mut outcome = RealipOutcome {
        changed: false,
        addr: current,
        port: state.client.port,
        original_addr,
        original_port,
    };
    if !conf.enabled() {
        return outcome;
    }
    let Some(current_address) = current else {
        return outcome;
    };
    if !TrustedSource::trusted(&conf.trusted, current_address) {
        return outcome;
    }
    let Some(values) = header_values(state, &conf.header) else {
        return outcome;
    };
    // `ngx_http_get_forwarded_addr`: multiple header lines are walked last-to-first; an
    // address is only replaced while the current address is trusted.
    let mut address = current_address;
    let mut header_port = None;
    let mut found = false;
    for value in values.iter().rev() {
        match walk_forwarded(conf, address, value) {
            Some((walked, port)) => {
                address = walked;
                header_port = Some(port);
                found = true;
            }
            None => {
                if conf.recursive && found {
                    break;
                }
                return outcome;
            }
        }
        if !conf.recursive {
            break;
        }
    }
    if !found {
        return outcome;
    }
    outcome.changed = address != original_addr.unwrap_or(address);
    outcome.addr = Some(address);
    // `ngx_parse_addr_port` sets the port only when the header carried one; otherwise the
    // connection keeps its port (`$remote_port` reads `c->sockaddr`).
    outcome.port = header_port.flatten().unwrap_or(state.client.port);
    state.client.addr = Some(address);
    state.client.port = outcome.port;
    state.client.rewritten = true;
    outcome
}

struct Selected {
    address: IpAddr,
    port: Option<u16>,
}

/// One pass of `ngx_http_get_forwarded_addr_internal` over a single header value.
///
/// The C loop reads the *left-most* token first and moves right, accepting each token
/// while the current address stays trusted; `while (recursive && p > xff)` decides whether
/// it iterates again. The last token accepted is the final address.
fn walk_forwarded(
    conf: &RealipConf,
    mut addr: IpAddr,
    value: &str,
) -> Option<(IpAddr, Option<u16>)> {
    let tokens = split_addresses(value);
    let mut found = false;
    let mut last: Option<(IpAddr, Option<u16>)> = None;
    for (index, token) in tokens.iter().enumerate() {
        if !TrustedSource::trusted(&conf.trusted, addr) {
            return last.found_or(found);
        }
        let Some(parsed) = parse_entry(token) else {
            return last.found_or(found);
        };
        addr = parsed.address;
        last = Some((parsed.address, parsed.port));
        found = true;
        if !conf.recursive || index + 1 == tokens.len() {
            break;
        }
    }
    last
}

/// Helper so `walk_forwarded` reads naturally: return the last accepted token, or `None`.
trait FoundOr {
    fn found_or(self, found: bool) -> Option<(IpAddr, Option<u16>)>;
}

impl FoundOr for Option<(IpAddr, Option<u16>)> {
    fn found_or(self, found: bool) -> Option<(IpAddr, Option<u16>)> {
        if found { self } else { None }
    }
}

fn split_addresses(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// `ngx_parse_addr_port`: a bare address, `host:port`, `[v6]` or `[v6]:port`. The port must
/// be 1..=65535; entries without one keep `None`.
fn parse_entry(entry: &str) -> Option<Selected> {
    if let Ok(address) = entry.parse::<IpAddr>() {
        return Some(Selected {
            address,
            port: None,
        });
    }
    let (host, port) = if let Some(rest) = entry.strip_prefix('[') {
        let (address, tail) = rest.split_once(']')?;
        if tail.is_empty() {
            (address, None)
        } else {
            (address, Some(&tail[1..]))
        }
    } else if let Some((address, port)) = entry.rsplit_once(':') {
        (address, Some(port))
    } else {
        return None;
    };
    let address: IpAddr = host.parse().ok()?;
    let port = port
        .map(str::parse::<u16>)
        .transpose()
        .ok()?
        .filter(|port| *port > 0);
    Some(Selected { address, port })
}

fn header_values(state: &RequestState, source: &HeaderSource) -> Option<Vec<String>> {
    let name = source.header_name()?;
    let values: Vec<String> = state
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_string))
        .collect();
    if values.is_empty() {
        return None;
    }
    Some(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::{ConnectionState, RequestLine, RequestState};
    use http::{HeaderMap, HeaderName};

    fn request_state(peer: &str, header: Option<(&str, &str)>) -> RequestState {
        let request = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut headers = HeaderMap::new();
        if let Some((name, value)) = header {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        RequestState::new(
            ConnectionState {
                listen: "127.0.0.1:80".into(),
                peer_ip: Some(peer.parse().unwrap()),
                peer_port: 4000,
                local_ip: Some("127.0.0.1".parse().unwrap()),
                local_port: 80,
                scheme: "http".into(),
                tls: false,
            },
            RequestLine::from_header(&request),
            headers,
            &[],
        )
    }

    fn conf(trusted: &[&str], header: HeaderSource, recursive: bool) -> RealipConf {
        RealipConf {
            trusted: trusted
                .iter()
                .flat_map(|value| TrustedSource::parse_all(value).unwrap())
                .collect(),
            header,
            header_set: true,
            recursive,
        }
    }

    #[test]
    fn rewrites_from_trusted_proxy() {
        let mut state = request_state("10.0.0.5", Some(("x-real-ip", "203.0.113.9")));
        let outcome = apply(
            &conf(&["10.0.0.0/8"], HeaderSource::XRealIp, false),
            &mut state,
        );
        assert!(outcome.changed);
        assert_eq!(state.variable("remote_addr").unwrap(), "203.0.113.9");
        assert_eq!(state.variable("realip_remote_addr").unwrap(), "10.0.0.5");
    }

    #[test]
    fn ignores_untrusted_proxy() {
        let mut state = request_state("198.51.100.1", Some(("x-real-ip", "203.0.113.9")));
        let outcome = apply(
            &conf(&["10.0.0.0/8"], HeaderSource::XRealIp, false),
            &mut state,
        );
        assert!(!outcome.changed);
        assert_eq!(state.variable("remote_addr").unwrap(), "198.51.100.1");
    }

    #[test]
    fn x_forwarded_for_takes_first_hop() {
        let mut state = request_state(
            "10.0.0.5",
            Some(("x-forwarded-for", "203.0.113.9, 10.0.0.7")),
        );
        apply(
            &conf(&["10.0.0.0/8"], HeaderSource::XForwardedFor, false),
            &mut state,
        );
        assert_eq!(state.variable("remote_addr").unwrap(), "203.0.113.9");
    }

    #[test]
    fn recursive_skips_trusted_hops() {
        // Right-most trusted hop first: 10.0.0.7 is itself trusted, so the walk continues
        // left and stops at the first untrusted address.
        let mut state = request_state(
            "10.0.0.5",
            Some(("x-forwarded-for", "203.0.113.9, 10.0.0.7")),
        );
        apply(
            &conf(&["10.0.0.0/8"], HeaderSource::XForwardedFor, true),
            &mut state,
        );
        assert_eq!(state.variable("remote_addr").unwrap(), "203.0.113.9");

        // Every hop is trusted, so the walk accepts each token from left to right and the
        // last parsed address wins (`ngx_http_get_forwarded_addr_internal`).
        let mut state = request_state("10.0.0.5", Some(("x-forwarded-for", "10.0.0.7, 10.0.0.8")));
        apply(
            &conf(&["10.0.0.0/8"], HeaderSource::XForwardedFor, true),
            &mut state,
        );
        assert_eq!(state.variable("remote_addr").unwrap(), "10.0.0.8");

        // A right-most hop that is not trusted stops the walk immediately.
        let mut state = request_state("10.0.0.5", Some(("x-forwarded-for", "203.0.113.9")));
        apply(
            &conf(&["10.0.0.0/8"], HeaderSource::XForwardedFor, false),
            &mut state,
        );
        assert_eq!(state.variable("remote_addr").unwrap(), "203.0.113.9");
    }

    #[test]
    fn header_port_overrides_but_absent_port_keeps_peer_port() {
        let mut state = request_state("10.0.0.5", Some(("x-real-ip", "203.0.113.9:4444")));
        apply(
            &conf(&["10.0.0.0/8"], HeaderSource::XRealIp, false),
            &mut state,
        );
        assert_eq!(state.variable("remote_addr").unwrap(), "203.0.113.9");
        assert_eq!(state.variable("remote_port").unwrap(), "4444");

        // Without a port in the header the original connection port is kept.
        let mut state = request_state("10.0.0.5", Some(("x-real-ip", "203.0.113.9")));
        apply(
            &conf(&["10.0.0.0/8"], HeaderSource::XRealIp, false),
            &mut state,
        );
        assert_eq!(state.variable("remote_port").unwrap(), "4000");
        assert_eq!(state.variable("realip_remote_port").unwrap(), "4000");
    }

    #[test]
    fn multiple_header_lines_are_walked_last_to_first() {
        let request = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "203.0.113.9".parse().unwrap());
        headers.append("x-forwarded-for", "10.0.0.7".parse().unwrap());
        let mut state = RequestState::new(
            ConnectionState {
                listen: "127.0.0.1:80".into(),
                peer_ip: Some("10.0.0.5".parse().unwrap()),
                peer_port: 4000,
                local_ip: None,
                local_port: 80,
                scheme: "http".into(),
                tls: false,
            },
            RequestLine::from_header(&request),
            headers,
            &[],
        );
        apply(
            &conf(&["10.0.0.0/8"], HeaderSource::XForwardedFor, true),
            &mut state,
        );
        assert_eq!(state.variable("remote_addr").unwrap(), "203.0.113.9");
    }

    #[test]
    fn cidr_matches_and_rejects() {
        let cidr = TrustedSource::parse_all("2001:db8::/32").unwrap().remove(0);
        assert!(cidr.contains("2001:db8::1".parse().unwrap()));
        assert!(!cidr.contains("2001:db9::1".parse().unwrap()));
        let cidr = TrustedSource::parse_all("192.0.2.0/24").unwrap().remove(0);
        assert!(cidr.contains("192.0.2.200".parse().unwrap()));
        assert!(!cidr.contains("192.0.3.1".parse().unwrap()));
        assert!(TrustedSource::parse_all("10.0.0.0/33").is_err());
        assert_eq!(
            TrustedSource::parse_all("unix:").unwrap(),
            vec![TrustedSource::Unix]
        );
    }

    #[test]
    fn host_names_resolve_to_addresses() {
        let resolved = TrustedSource::parse_all("localhost").unwrap();
        assert!(!resolved.is_empty());
        assert!(
            resolved
                .iter()
                .all(|source| matches!(source, TrustedSource::Address(_)))
        );
        assert!(TrustedSource::parse_all("no-such-host.invalid").is_err());
    }

    #[test]
    fn duplicate_real_ip_header_is_rejected() {
        let registry = crate::modules::Registry::default_modules();
        let mut states: Vec<crate::core::state::StateSlot> = vec![(
            "main",
            crate::core::StateInstance::new(crate::config::MainState::default()),
        )];
        let mut location = crate::modules::location::Location::new();
        let first = crate::core::syntax::parse_str("real_ip_header X-Forwarded-For;").unwrap();
        let second = crate::core::syntax::parse_str("real_ip_header X-Real-IP;").unwrap();
        let mut dispatch = |directive| {
            let mut access = crate::core::state::StateAccess::new(&mut states);
            registry.dispatch(
                directive,
                crate::core::Context::Location,
                std::path::Path::new("."),
                &mut access,
                Some(&mut location),
            )
        };
        dispatch(&first[0]).unwrap();
        let error = dispatch(&second[0]).unwrap_err().to_string();
        assert!(error.contains("duplicate"), "{error}");
    }

    #[test]
    fn real_ip_header_names_match_nginx_case_rules() {
        assert_eq!(
            HeaderSource::parse("X-Real-IP").unwrap(),
            HeaderSource::XRealIp
        );
        assert_eq!(
            HeaderSource::parse("X-Forwarded-For").unwrap(),
            HeaderSource::XForwardedFor
        );
        // Custom names are case-insensitive header names.
        assert_eq!(
            HeaderSource::parse("X-Client-IP").unwrap(),
            HeaderSource::Custom(HeaderName::from_static("x-client-ip"))
        );
        assert_eq!(
            HeaderSource::parse("proxy_protocol").unwrap(),
            HeaderSource::ProxyProtocol
        );
        assert!(HeaderSource::ProxyProtocol.header_name().is_none());
    }

    #[test]
    fn disabled_without_trusted_sources() {
        let mut state = request_state("10.0.0.5", Some(("x-real-ip", "203.0.113.9")));
        let outcome = apply(&RealipConf::default(), &mut state);
        assert!(!outcome.changed);
        assert_eq!(state.variable("remote_addr").unwrap(), "10.0.0.5");
    }
}
