//! `ngx_http_access_module`: `allow` and `deny`.
//!
//! Rules are evaluated in declaration order at `NGX_HTTP_ACCESS_PHASE`; the first rule
//! whose network matches decides. `all` is IPv4 `0.0.0.0/0`, and IPv4-mapped IPv6 peers are
//! matched against IPv4 rules first, exactly like `ngx_http_access_handler`.

use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::ctx::ModuleCtx;
use crate::modules::location::LocationConf;
use anyhow::Result;
use std::net::IpAddr;

pub const MODULE_NAME: &str = "ngx_http_access_module";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessRule {
    /// `all`
    All(Access),
    /// `unix:` — always matches on a Unix domain socket, as in `ngx_http_access_unix`.
    Unix(Access),
    /// A CIDR block or single address (single addresses become a /32 or /128).
    Cidr {
        network: IpAddr,
        prefix: u8,
        access: Access,
    },
}

impl AccessRule {
    /// `ngx_ptocidr` compatible parse; `all` and `unix:` are handled by the caller.
    pub fn parse_cidr(value: &str, access: Access) -> Result<Self, String> {
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (value, None),
        };
        let network: IpAddr = address
            .parse()
            .map_err(|_| format!("invalid parameter \"{value}\""))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .map_err(|_| format!("invalid parameter \"{value}\""))?,
            None => max,
        };
        if prefix > max {
            return Err(format!("invalid parameter \"{value}\""));
        }
        // `ngx_ptocidr` zeroes the low bits and only warns about them.
        Ok(AccessRule::Cidr {
            network: mask_address(network, prefix),
            prefix,
            access,
        })
    }

    /// Whether the rule matches this peer address.
    pub fn matches(&self, address: IpAddr) -> bool {
        match self {
            AccessRule::All(_) => true,
            // Unix sockets are not supported by the listener, so they never match here.
            AccessRule::Unix(_) => false,
            AccessRule::Cidr {
                network, prefix, ..
            } => match (network, address) {
                (IpAddr::V4(network), IpAddr::V4(address)) => {
                    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
                    (u32::from(*network) & mask) == (u32::from(address) & mask)
                }
                (IpAddr::V6(network), IpAddr::V6(address)) => {
                    let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
                    (u128::from(*network) & mask) == (u128::from(address) & mask)
                }
                // IPv4-mapped peers are checked against IPv4 rules (`IN6_IS_ADDR_V4MAPPED`).
                (IpAddr::V4(_), IpAddr::V6(address)) => address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| self.matches(IpAddr::V4(mapped))),
                _ => false,
            },
        }
    }
}

fn mask_address(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            IpAddr::V4((u32::from(address) & mask).into())
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
            IpAddr::V6((u128::from(address) & mask).into())
        }
    }
}

/// Configuration: the ordered rule list, inherited by nested contexts
/// (`ngx_http_access_merge_loc_conf` copies the parent array when the child has none).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessConf {
    pub rules: Vec<AccessRule>,
}

impl LocationConf for AccessConf {}

impl AccessConf {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// `ngx_http_access_inet`/`ngx_http_access_inet6`: first matching rule wins.
    pub fn check(&self, address: IpAddr) -> Option<Access> {
        self.rules
            .iter()
            .find(|rule| rule.matches(address))
            .map(|rule| match rule {
                AccessRule::All(access)
                | AccessRule::Unix(access)
                | AccessRule::Cidr { access, .. } => *access,
            })
    }
}

pub struct AccessModule;

impl Module for AccessModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            DirectiveSpec {
                name: "allow",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_allow,
            },
            DirectiveSpec {
                name: "deny",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_deny,
            },
        ]
    }
}

fn parse_allow(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    parse_rule(view, Access::Allow)
}

fn parse_deny(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    parse_rule(view, Access::Deny)
}

fn parse_rule(view: &mut crate::modules::DirectiveView<'_>, access: Access) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let rule = match directive.args[0].as_str() {
        "all" => AccessRule::All(access),
        "unix:" => AccessRule::Unix(access),
        value => AccessRule::parse_cidr(value, access).map_err(|error| directive.error(error))?,
    };
    view.update_conf::<AccessConf>(|conf| conf.rules.push(rule))
}

/// `NGX_HTTP_ACCESS_PHASE`: returns `Some(403)` when a `deny` rule matched.
pub async fn handle(ctx: &mut ModuleCtx<'_>) -> Result<Option<u16>> {
    let Some(conf) = ctx.location.get::<AccessConf>() else {
        return Ok(None);
    };
    let Some(address) = ctx.state.client.addr else {
        return Ok(None);
    };
    Ok(match conf.check(address) {
        Some(Access::Deny) => Some(403),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str, access: Access) -> AccessRule {
        AccessRule::parse_cidr(value, access).unwrap()
    }

    #[test]
    fn cidr_rules_match_like_nginx() {
        let rule = parse("10.0.0.0/8", Access::Allow);
        assert!(rule.matches("10.255.1.2".parse().unwrap()));
        assert!(!rule.matches("11.0.0.1".parse().unwrap()));

        let rule = parse("192.0.2.7", Access::Deny);
        assert!(rule.matches("192.0.2.7".parse().unwrap()));
        assert!(!rule.matches("192.0.2.8".parse().unwrap()));

        let rule = parse("2001:db8::/32", Access::Allow);
        assert!(rule.matches("2001:db8::1".parse().unwrap()));
        assert!(!rule.matches("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn low_bits_are_masked_and_bad_inputs_rejected() {
        let rule = parse("10.1.2.3/8", Access::Allow);
        assert_eq!(
            rule,
            AccessRule::Cidr {
                network: "10.0.0.0".parse().unwrap(),
                prefix: 8,
                access: Access::Allow
            }
        );
        assert!(AccessRule::parse_cidr("10.0.0.0/33", Access::Allow).is_err());
        assert!(AccessRule::parse_cidr("example.com", Access::Allow).is_err());
    }

    #[test]
    fn ipv4_mapped_peers_match_ipv4_rules() {
        let conf = AccessConf {
            rules: vec![
                parse("198.51.100.0/24", Access::Deny),
                AccessRule::All(Access::Allow),
            ],
        };
        assert_eq!(
            conf.check("::ffff:198.51.100.7".parse().unwrap()),
            Some(Access::Deny)
        );
        assert_eq!(
            conf.check("203.0.113.1".parse().unwrap()),
            Some(Access::Allow)
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let conf = AccessConf {
            rules: vec![
                AccessRule::All(Access::Deny),
                parse("10.0.0.0/8", Access::Allow),
            ],
        };
        assert_eq!(conf.check("10.1.1.1".parse().unwrap()), Some(Access::Deny));
        let conf = AccessConf {
            rules: vec![
                parse("10.0.0.0/8", Access::Allow),
                AccessRule::All(Access::Deny),
            ],
        };
        assert_eq!(conf.check("10.1.1.1".parse().unwrap()), Some(Access::Allow));
        assert_eq!(
            conf.check("172.16.0.1".parse().unwrap()),
            Some(Access::Deny)
        );
    }

    #[test]
    fn unix_rule_parses_but_never_matches_tcp() {
        let conf = AccessConf {
            rules: vec![AccessRule::Unix(Access::Deny)],
        };
        assert_eq!(conf.check("127.0.0.1".parse().unwrap()), None);
    }
}
