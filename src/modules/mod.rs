//! Module registry and the built-in module set.

pub mod access;
pub mod auth_basic;
pub mod balancer;
pub mod body;
pub mod ctx;
pub mod core_conf;
pub mod error_page;
pub mod expires;
pub mod filters;
pub mod geo;
pub mod geoip;
pub mod gunzip;
pub mod grpc;
pub mod gzip;
pub mod gzip_static;
pub mod headers;
pub mod http_core;
pub mod limit_conn;
pub mod limit_req;
pub mod location;
pub mod log;
pub mod lua;
pub mod proxy;
pub mod proxy_buffer;
pub mod proxy_cache;
pub mod proxy_rewrite;
pub mod proxy_tls;
pub mod realip;
pub mod registry;
pub mod respond;
pub mod server_state;
pub mod rewrite;
pub mod ssl;
pub mod static_files;
pub mod stub_status;
pub mod upstream;
pub mod upstream_protocols;
pub mod uri;
pub mod writer;

pub use registry::{DirectiveView, Registry};

/// A `(name, provider)` pair describing one variable.
pub type Provider = (
    &'static str,
    &'static dyn crate::core::variables::VariableProvider,
);

/// Variables registered while the configuration is compiled.
///
/// `geo` declares one variable per `geo` block (`ngx_http_add_variable` from
/// `ngx_http_geo_block`), so the names only exist after parsing; this table lets
/// [`crate::core::http::RequestState::variable`] reach them without giving the HTTP core a
/// dependency on the module.
static DYNAMIC_PROVIDERS: std::sync::OnceLock<Vec<Provider>> = std::sync::OnceLock::new();

/// Replace the dynamic provider table (called once after a successful compile).
pub fn set_dynamic_providers(providers: Vec<Provider>) {
    let _ = DYNAMIC_PROVIDERS.set(providers);
}

/// Every variable that was registered while parsing (`geo`).
pub fn dynamic_providers() -> &'static [Provider] {
    DYNAMIC_PROVIDERS
        .get()
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Variable providers contributed by the built-in modules, in Nginx module order.
///
/// The registry declares the same providers through [`crate::core::Module::variables`];
/// this table lets request-scoped helpers rebuild a [`crate::core::http::RequestState`]
/// without reaching into the registry.
pub const PROVIDERS: &[Provider] = &[
    ("realip_remote_addr", &realip::REALIP_REMOTE_ADDR),
    ("realip_remote_port", &realip::REALIP_REMOTE_PORT),
    ("upstream_cache_status", &proxy::CACHE_STATUS),
];
