//! `ngx_http_geoip_module`: GeoIP lookups from MaxMind databases.
//!
//! | File | Responsibility |
//! |---|---|
//! | `mod.rs` | directives, the sixteen variables, request-time address selection |
//! | [`conf`] | the compiled databases and the per-variable lookup rules |
//! | [`mmdb`] | a MaxMind DB reader (`MMDB_open`/`MMDB_lookup_sockaddr`/`MMDB_aget_value`) |
//!
//! nginx is usually built against libmaxminddb, and its legacy GeoIP API path uses the same
//! directive and variable names, so only the MaxMind DB path is implemented here:
//! `geoip_country`, `geoip_city` and `geoip_org` accept a `.mmdb` file, and the variables
//! read the fields the C module's `ngx_http_geoip_*_paths` tables name.
//!
//! ```nginx
//! geoip_country  /etc/nginx/geoip/GeoIP.dat;      # or GeoLite2-Country.mmdb
//! geoip_city     /etc/nginx/geoip/GeoLite2-City.mmdb;
//! geoip_org      /etc/nginx/geoip/GeoLite2-ASN.mmdb;
//! geoip_proxy    10.0.0.0/8;
//! geoip_proxy_recursive on;
//! ```

pub mod conf;
pub mod mmdb;

use crate::core::geo::{forwarded_addr, Cidr, CidrParse, parse_cidr};
use crate::core::http::RequestState;
use crate::core::state::StateInstance;
use crate::core::variables::VariableProvider;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::registry::DirectiveView;
use anyhow::Result;
use conf::{CityField, Conf, CountryField, Kind};
use std::borrow::Cow;

pub const MODULE_NAME: &str = "ngx_http_geoip_module";

pub struct GeoipModule;

impl Module for GeoipModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn http_state(&self) -> Option<StateInstance> {
        Some(StateInstance::new(Conf::default()))
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            DirectiveSpec {
                name: "geoip_country",
                // `NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12`
                contexts: &[Context::Http],
                handler: parse_country,
            },
            DirectiveSpec {
                name: "geoip_city",
                contexts: &[Context::Http],
                handler: parse_city,
            },
            DirectiveSpec {
                name: "geoip_org",
                contexts: &[Context::Http],
                handler: parse_org,
            },
            DirectiveSpec {
                name: "geoip_proxy",
                contexts: &[Context::Http],
                handler: parse_proxy,
            },
            DirectiveSpec {
                name: "geoip_proxy_recursive",
                contexts: &[Context::Http],
                handler: parse_proxy_recursive,
            },
        ]
    }

    fn variables(&self) -> Vec<(&'static str, &'static dyn VariableProvider)> {
        conf::variables()
    }
}

/// `geoip_country file [utf8];` — a Country edition.
fn parse_country(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=2)?;
    let path = view.path(&directive.args[0]);
    let charset = directive.args.get(1).map(String::as_str);
    let database = conf::open(&path, Kind::Country, charset)
        .map_err(|error| directive.error(error))?;
    view.state::<Conf>()?.set(Kind::Country, database);
    Ok(())
}

/// `geoip_city file [utf8];` — a City edition.
fn parse_city(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=2)?;
    let path = view.path(&directive.args[0]);
    let charset = directive.args.get(1).map(String::as_str);
    let database = conf::open(&path, Kind::City, charset)
        .map_err(|error| directive.error(error))?;
    view.state::<Conf>()?.set(Kind::City, database);
    Ok(())
}

/// `geoip_org file [utf8];` — an ASN/ISP/Org/Domain edition.
fn parse_org(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=2)?;
    let path = view.path(&directive.args[0]);
    let charset = directive.args.get(1).map(String::as_str);
    let database = conf::open(&path, Kind::Org, charset)
        .map_err(|error| directive.error(error))?;
    view.state::<Conf>()?.set(Kind::Org, database);
    Ok(())
}

/// `geoip_proxy address | CIDR;` (`ngx_http_geoip_cidr_value`: `255.255.255.255` is a host).
fn parse_proxy(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let text = &directive.args[0];
    let cidr = if text == "255.255.255.255" {
        Cidr {
            network: std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            prefix: 32,
        }
    } else {
        match parse_cidr(text) {
            Ok(CidrParse::Ok(cidr)) => cidr,
            Ok(CidrParse::MeaninglessBits(cidr)) => {
                log::warn!(
                    "{}:{}: low address bits of {} are meaningless",
                    directive.file.display(),
                    directive.line,
                    text
                );
                cidr
            }
            Err(_) => return Err(directive.error(format!("invalid network \"{text}\""))),
        }
    };
    view.state::<Conf>()?.proxies.push(cidr);
    Ok(())
}

/// `geoip_proxy_recursive on|off;`
fn parse_proxy_recursive(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = match directive.args[0].as_str() {
        "on" => true,
        "off" => false,
        other => {
            return Err(directive.error(format!(
                "invalid value \"{other}\" in \"geoip_proxy_recursive\" directive, it must be \"on\" or \"off\""
            )));
        }
    };
    view.state::<Conf>()?.proxy_recursive = value;
    Ok(())
}

/// Which database a variable reads and which field it returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    Country(CountryField),
    City(CityField),
    Org,
}

/// Every variable the module registers, with its lookup rule
/// (`ngx_http_geoip_vars` in the C module).
pub const LOOKUPS: &[(&str, Lookup)] = &[
    ("geoip_country_code", Lookup::Country(CountryField::Code)),
    ("geoip_country_code3", Lookup::Country(CountryField::Code3)),
    ("geoip_country_name", Lookup::Country(CountryField::Name)),
    ("geoip_city_continent_code", Lookup::City(CityField::ContinentCode)),
    ("geoip_city_country_code", Lookup::City(CityField::CountryCode)),
    ("geoip_city_country_code3", Lookup::City(CityField::CountryCode3)),
    ("geoip_city_country_name", Lookup::City(CityField::CountryName)),
    ("geoip_region", Lookup::City(CityField::Region)),
    ("geoip_region_name", Lookup::City(CityField::RegionName)),
    ("geoip_city", Lookup::City(CityField::City)),
    ("geoip_postal_code", Lookup::City(CityField::PostalCode)),
    ("geoip_latitude", Lookup::City(CityField::Latitude)),
    ("geoip_longitude", Lookup::City(CityField::Longitude)),
    ("geoip_city_metro_code", Lookup::City(CityField::MetroCode)),
    ("geoip_area_code", Lookup::City(CityField::AreaCode)),
    ("geoip_org", Lookup::Org),
];

/// `ngx_http_geoip_lookup`: the address to classify.
///
/// The connection address is used; `geoip_proxy` lines then walk `X-Forwarded-For` the same
/// way `realip` does. IPv4-mapped IPv6 addresses are folded to IPv4
/// (`MMDB_lookup_sockaddr` does the same before the lookup).
pub fn request_address(conf: &Conf, state: &RequestState) -> Option<std::net::IpAddr> {
    let base = state.client.addr.or(state.connection.peer_ip)?;
    let xff: Vec<String> = state
        .headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_string))
        .collect();
    let address = forwarded_addr(Some(base), &xff, &conf.proxies, conf.proxy_recursive)?;
    Some(match address {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, std::net::IpAddr::V4),
        other => other,
    })
}

/// The databases of the last successful configuration compile.
///
/// nginx reads `gcf` from the module's main configuration at request time; the equivalent
/// here is this cell, filled by [`publish`] after `http {}` is compiled. It keeps a lookup
/// working even when the request state was rebuilt from a snapshot.
static PUBLISHED: std::sync::OnceLock<Conf> = std::sync::OnceLock::new();

/// Record the compiled configuration for [`published`].
pub fn publish(conf: &Conf) {
    let _ = PUBLISHED.set(conf.clone());
}

pub fn published() -> Option<Conf> {
    PUBLISHED.get().cloned()
}

/// One `geoip_*` variable.
#[derive(Debug)]
pub struct GeoipVariable {
    pub lookup: Lookup,
    pub name: &'static str,
}

impl VariableProvider for GeoipVariable {
    fn module(&self) -> &'static str {
        MODULE_NAME
    }

    fn get(&self, state: &RequestState) -> Option<String> {
        // nginx keeps the databases in the module's main configuration (`gcf`); the runtime
        // copies them into the request state, so a lookup never needs the compiler.
        let conf = state
            .get::<Conf>()
            .map(Cow::Borrowed)
            .or_else(|| published().map(Cow::Owned))?;
        let address = request_address(conf.as_ref(), state)?;
        conf.value(self.lookup, address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_documented_variable_has_a_lookup() {
        let names: Vec<&str> = LOOKUPS.iter().map(|(name, _)| *name).collect();
        for expected in [
            "geoip_country_code",
            "geoip_country_code3",
            "geoip_country_name",
            "geoip_city_continent_code",
            "geoip_city_country_code",
            "geoip_city_country_code3",
            "geoip_city_country_name",
            "geoip_region",
            "geoip_region_name",
            "geoip_city",
            "geoip_postal_code",
            "geoip_latitude",
            "geoip_longitude",
            "geoip_city_metro_code",
            "geoip_area_code",
            "geoip_org",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
        assert_eq!(names.len(), 16);
    }

    #[test]
    fn providers_match_the_lookup_table() {
        let providers = GeoipModule.variables();
        assert_eq!(providers.len(), LOOKUPS.len());
        for (name, _) in LOOKUPS {
            assert!(providers.iter().any(|(registered, _)| registered == name), "{name}");
        }
    }
}
