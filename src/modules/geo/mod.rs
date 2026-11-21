//! `ngx_http_geo_module`: map a client address to a configuration value.
//!
//! ```nginx
//! geo $country {
//!     default ZZ;
//!     127.0.0.1/32 localhost;
//!     10.0.0.0/8  EU;
//!     include geo/networks.conf;
//! }
//!
//! geo $realip_remote_country $realip_remote_addr;   # classify a variable instead
//! geo $limited {                                    # ranges + trusted proxies
//!     ranges;
//!     proxy 10.0.0.0/8;
//!     proxy_recursive;
//!     10.0.0.0-10.0.0.255 yes;
//! }
//! ```
//!
//! | File | Responsibility |
//! |---|---|
//! | `mod.rs` | directives, variables, request-time address selection |
//! | [`conf`] | the compiled block and its value table |
//! | [`lookup`] | dual radix tree and the 65536-bucket range table |
//! | [`parser`] | the block parser (`ngx_http_geo`, `ngx_http_geo_cidr`, `ngx_http_geo_range`) |
//!
//! nginx registers the variable at `http {}` level and resolves it per request from that
//! block; the mapping itself is a pure function of the request address, so the runtime only
//! needs [`GeoBlock::value`] plus the address selection in [`request_address`].

pub mod conf;
pub mod lookup;
pub mod parser;

use crate::core::geo::forwarded_addr;
use crate::core::http::RequestState;
use crate::core::state::StateInstance;
use crate::core::variables::VariableProvider;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::registry::DirectiveView;
use anyhow::Result;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

pub use conf::{GeoBlock, GeoBlocks, Lookup, Values};

pub const MODULE_NAME: &str = "ngx_http_geo_module";

pub struct GeoModule;

impl Module for GeoModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn http_state(&self) -> Option<StateInstance> {
        Some(StateInstance::new(GeoBlocks::default()))
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![DirectiveSpec {
            name: "geo",
            // `NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12`, compiled by this handler.
            contexts: &[Context::Http],
            handler: parse_geo,
        }]
    }

    fn variables(&self) -> Vec<(&'static str, &'static dyn VariableProvider)> {
        // nginx adds one variable per `geo` block, so the providers are dynamic.
        Vec::new()
    }
}

/// `ngx_http_geo_block`: `geo $variable [$source]; { … }`.
fn parse_geo(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if !directive.has_block() || !(1..=2).contains(&directive.args.len()) {
        return Err(directive.error("invalid number of the geo parameters"));
    }
    let name = directive.args[0]
        .strip_prefix('$')
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            directive.error(format!("invalid variable name \"{}\"", directive.args[0]))
        })?
        .to_string();
    let source = match directive.args.get(1) {
        None => None,
        Some(value) => Some(
            value
                .strip_prefix('$')
                .filter(|source| !source.is_empty())
                .ok_or_else(|| directive.error(format!("invalid variable name \"{value}\"")))?
                .to_string(),
        ),
    };
    let base_dir = view.base_dir.to_path_buf();
    let nodes = directive.block()?.to_vec();
    let registry = view.registry;
    let mut builder = parser::Builder::new();
    builder.parse_block(registry, &base_dir, &nodes)?;
    let warnings = builder.take_warnings();
    let unsupported: Vec<&str> = warnings
        .iter()
        .map(|warning| {
            // Keep every entry; the vector outlives the borrow below.
            Box::leak(warning.render().into_boxed_str()) as &str
        })
        .collect();
    let block = builder.finish(name, source);
    let state = view.state::<GeoBlocks>()?;
    state.insert(block);
    // `low address bits … are meaningless` and other per-entry notes are warnings in nginx.
    for warning in unsupported {
        log::warn!("{warning}");
    }
    Ok(())
}

/// The address a `geo` variable classifies (`ngx_http_geo_addr`).
///
/// * With no `$source`, the connection address: `$remote_addr` after `realip`,
///   which is what the request state's `client.addr` holds.
/// * With `$source`, that variable's address; an unparsable value has no address.
/// * Trusted `proxy` lines then walk `X-Forwarded-For`, exactly like `realip`.
pub fn request_address(
    block: &GeoBlock,
    state: &RequestState,
) -> Option<IpAddr> {
    let base = match &block.source {
        None => state.client.addr.or(state.connection.peer_ip),
        Some(source) => state
            .variable(source)
            .and_then(|value| value.trim().parse::<IpAddr>().ok()),
    }?;
    let xff: Vec<String> = state
        .headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_string))
        .collect();
    forwarded_addr(Some(base), &xff, &block.proxies, block.proxy_recursive)
}

/// Variables registered by every `geo` block of one configuration.
///
/// nginx calls `ngx_http_add_variable` while parsing each block, so the set is only known
/// after compilation; [`crate::config`] asks for it through [`compile_variables`].
pub fn providers(blocks: &GeoBlocks) -> Vec<(&'static str, &'static dyn VariableProvider)> {
    let mut providers: Vec<(&'static str, &'static dyn VariableProvider)> = Vec::new();
    for block in &blocks.blocks {
        let name: &'static str = Box::leak(block.name.clone().into_boxed_str());
        let provider: &'static dyn VariableProvider =
            Box::leak(Box::new(GeoVariable { block: block.clone() }));
        providers.push((name, provider));
    }
    providers
}

/// One `geo` variable: returns its block's value for the request address.
#[derive(Debug)]
pub struct GeoVariable {
    block: Arc<GeoBlock>,
}

impl GeoVariable {
    /// The block this provider answers from, for tests and diagnostics.
    pub fn block(&self) -> &GeoBlock {
        &self.block
    }
}

impl VariableProvider for GeoVariable {
    fn module(&self) -> &'static str {
        MODULE_NAME
    }

    fn get(&self, state: &RequestState) -> Option<String> {
        let address = request_address(&self.block, state);
        let value = address.and_then(|address| self.block.value(address)).map(str::to_string);
        eprintln!("GEODBG name={} addr={:?} value={:?}", self.block.name, address, value);
        value
    }
}

/// Compiled `geo` blocks, shared with the runtime registry.
///
/// The configuration compiler stores [`GeoBlocks`] in the module state; this cell mirrors the
/// resolved provider list so log formats and `$geo_*` references work without a lookup per
/// request.
static COMPILED: OnceLock<Mutex<Vec<Arc<GeoBlock>>>> = OnceLock::new();

/// Record the compiled blocks for [`compiled_blocks`].
pub fn publish(blocks: &GeoBlocks) {
    let cell = COMPILED.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut cell) = cell.lock() {
        *cell = blocks.blocks.clone();
    }
}

/// The blocks recorded by the last successful configuration compile.
pub fn compiled_blocks() -> Vec<Arc<GeoBlock>> {
    COMPILED
        .get()
        .and_then(|cell| cell.lock().ok().map(|cell| cell.clone()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::{ConnectionState, RequestLine, RequestState};
    use http::HeaderMap;

    fn make_state(peer: &str, xff: Option<&str>) -> RequestState {
        let request = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut headers = HeaderMap::new();
        if let Some(value) = xff {
            headers.insert("x-forwarded-for", value.parse().unwrap());
        }
        RequestState::new(
            ConnectionState {
                listen: "127.0.0.1:80".into(),
                peer_ip: Some(peer.parse().unwrap()),
                peer_port: 1000,
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

    fn block(source: &str) -> GeoBlock {
        let registry = crate::modules::Registry::default_modules();
        let nodes = crate::core::syntax::parse_str(source).unwrap();
        let mut builder = parser::Builder::new();
        builder
            .parse_block(&registry, std::path::Path::new("."), &nodes)
            .unwrap();
        builder.finish("country".to_string(), None)
    }

    #[test]
    fn proxy_lines_rewrite_the_address() {
        let block = block("proxy 10.0.0.0/8; default ZZ; 203.0.113.0/24 US;");
        // Peer 10.0.0.1 is a trusted proxy, so the header value is classified.
        let state = make_state("10.0.0.1", Some("203.0.113.9"));
        let address = request_address(&block, &state).unwrap();
        assert_eq!(address.to_string(), "203.0.113.9");
        assert_eq!(block.value(address), Some("US"));
        // Without a header the peer itself is classified.
        let state = make_state("10.0.0.1", None);
        assert_eq!(
            block.value(request_address(&block, &state).unwrap()),
            Some("ZZ")
        );
    }

    #[test]
    fn recursive_proxy_walk_reaches_the_client() {
        let block = block("proxy 10.0.0.0/8; proxy_recursive; default ZZ; 198.51.100.0/24 CA;");
        let state = make_state("10.0.0.1", Some("198.51.100.7, 10.9.9.9"));
        assert_eq!(
            block.value(request_address(&block, &state).unwrap()),
            Some("CA")
        );
    }

    #[test]
    fn a_source_variable_replaces_the_connection_address() {
        let mut block = block("default ZZ; 10.0.0.0/8 LAN;");
        block.source = Some("custom_addr".to_string());
        let mut state = make_state("192.0.2.9", None);
        state.overrides.set("custom_addr", b"10.1.2.3".to_vec());
        assert_eq!(
            block.value(request_address(&block, &state).unwrap()),
            Some("LAN")
        );
        // An unusable source value yields "not found" instead of the peer address.
        state.overrides.set("custom_addr", b"not-an-address".to_vec());
        assert_eq!(request_address(&block, &state), None);
    }

    #[test]
    fn providers_answer_per_request() {
        let block = block("default ZZ; 10.0.0.0/8 LAN;");
        let provider = GeoVariable {
            block: Arc::new(block),
        };
        let state = make_state("10.9.9.9", None);
        assert_eq!(provider.get(&state).as_deref(), Some("LAN"));
        let state = make_state("192.0.2.9", None);
        assert_eq!(provider.get(&state).as_deref(), Some("ZZ"));
    }
}
