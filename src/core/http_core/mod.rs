//! The HTTP request engine.
//!
//! This is the only place that knows the order of Nginx phases; concrete behaviour lives
//! in modules:
//!
//! 1. `POST_READ` — `realip` rewrites `$remote_addr` before configuration lookup.
//! 2. `FIND_CONFIG` — server and location selection.
//! 3. `REWRITE` — rewrite rules, restarting lookup on `last`.
//! 4. `CONTENT` — `return`, Lua, `proxy_pass` or static files.
//! 5. Response header filter — proxy hide/add headers plus the Lua header filter.
//!
//! # Layout
//!
//! The engine is split by concern so that no single file has to know every module:
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`types`] | Shared request/engine types and the `HttpCoreApp` view helpers |
//! | [`engine`] | Compiled-configuration lookups: server, location, upstream, realip |
//! | [`route`] | The phase engine (`ngx_http_core_run_phases`) |
//! | [`respond`] | Local responses: `error_page`, header filters, `answer` |
//! | [`content`] | `CONTENT` phase handlers (Lua, proxy dispatch, static files) |
//! | [`proxy`] | `proxy_pass`: request construction, upstream exchange, retries |
//! | [`cache`] | `ngx_http_file_cache` lookups and stores used by `proxy_pass` |
//! | [`bridge`] | Downstream transport: TLS termination, HTTP/1.1 and HTTP/2 loops |
//! | [`serve`] | The `ProxyHttp` implementation used by Pingora's own acceptor |

pub mod bridge;
pub mod cache;
pub mod content;
mod grpc;
pub mod engine;
pub mod proxy;
pub mod respond;
pub mod route;
pub mod serve;
pub mod types;

pub use bridge::Bridge;
pub use types::{
    CacheStatusCell, Engine, HttpCoreApp, ListenerTls, PhaseOutcome, RequestContext, Selected,
    ServerRuntime, TlsStats, VirtualHosts,
};

/// ssl_handshake_timeout default in Nginx.
pub(crate) const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

use crate::core::http::{ConnectionState, RequestState, RequestStateView};
use pingora_core::{Error, ErrorType};
use pingora_proxy::Session;

/// Build the connection facts of a downstream session.
pub(crate) fn connection_state(session: &Session, listen: &str) -> ConnectionState {
    let peer = session.client_addr().and_then(|address| address.as_inet());
    let local = session.server_addr().and_then(|address| address.as_inet());
    ConnectionState {
        listen: listen.to_string(),
        peer_ip: peer.map(|address| address.ip()),
        peer_port: peer.map_or(0, |address| address.port()),
        local_ip: local.map(|address| address.ip()),
        local_port: local.map_or(0, |address| address.port()),
        scheme: "http".to_string(),
        tls: false,
    }
}

/// Rebuild a full [`RequestState`] from a snapshot so module providers can run.
pub(crate) fn view_as_state(
    view: &RequestStateView,
    providers: &'static [(
        &'static str,
        &'static dyn crate::core::variables::VariableProvider,
    )],
) -> RequestState {
    view.clone().into_state(providers)
}

/// The host name used for upstream TLS and SNI (`Host` without its port).
pub(crate) fn parse_sni(host_header: &str) -> String {
    url::Url::parse(&format!("http://{host_header}"))
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| host_header.to_string())
}

/// Convert an `anyhow`-style failure into Pingora's error type.
pub(crate) fn engine_error(error: impl std::fmt::Display) -> Box<Error> {
    Error::explain(ErrorType::InternalError, error.to_string())
}
