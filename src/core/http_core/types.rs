//! Shared request and engine types.
//!
//! [`Engine`] is the compiled configuration; [`RequestContext`] is the per-request
//! counterpart of Nginx's `ngx_http_request_t`; [`Selected`] identifies the
//! `server`/`location` pair chosen by `FIND_CONFIG`.

use crate::core::http::{ConnectionState, RequestLine, RequestStateView};
use crate::modules::balancer::{SelectedBackend, Upstream};
use crate::modules::http_core::CompiledLocation;
use crate::modules::log::{AccessLogConfig, AccessLogWriter};
use arc_swap::ArcSwap;
use http::StatusCode;
use pingora_http::RequestHeader;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;


/// Everything the engine needs from the compiled configuration.
pub struct Engine {
    pub servers: Vec<ServerRuntime>,
    /// Listener 闂?server indices plus the default server index.
    pub listeners: BTreeMap<String, VirtualHosts>,
    pub upstreams: HashMap<String, Arc<Upstream>>,
    pub providers: &'static [(
        &'static str,
        &'static dyn crate::core::variables::VariableProvider,
    )],
    /// `types` / `default_type` from the `http {}` block.
    pub mime: crate::modules::http_core::MimeConfig,
    /// Process counters for `stub_status` and Prometheus.
    pub stats: Arc<crate::modules::stub_status::ServerStats>,
    pub access_log: Arc<AccessLogConfig>,
    pub access_writer: Option<Arc<AccessLogWriter>>,
    /// Runtime configuration handed to Pingora's `HttpProxy` (threads, retries, h2).
    pub server_conf: Arc<pingora_core::server::configuration::ServerConf>,
}

pub struct VirtualHosts {
    pub servers: Vec<usize>,
    pub default: usize,
}

/// Per-server view of the module configuration.
pub struct ServerRuntime {
    pub server_names: Vec<String>,
    pub locations: Vec<CompiledLocation>,
}

/// Selected server/location for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selected {
    pub server: usize,
    pub location: usize,
}

/// `$upstream_cache_status` shared between `proxy_pass` and the variable provider.
#[derive(Clone, Debug, Default)]
pub struct CacheStatusCell {
    inner: Arc<parking_lot::RwLock<Option<crate::modules::proxy_cache::CacheState>>>,
}

impl CacheStatusCell {
    pub fn set(&self, state: crate::modules::proxy_cache::CacheState) {
        *self.inner.write() = Some(state);
    }

    /// The status name (`HIT`, `MISS`, ...) as a `'static` string for the variable view.
    pub fn name(&self) -> Option<&'static str> {
        let guard = self.inner.read();
        guard.as_ref().and_then(|state| state.status).map(|status| status.as_str())
    }

    pub fn get(&self) -> Option<String> {
        let guard = self.inner.read();
        guard
            .as_ref()
            .and_then(|state| state.status)
            .map(|status| status.as_str().to_string())
    }
}

pub struct RequestContext {
    pub listen: String,
    pub request: RequestHeader,
    pub selected: Option<Selected>,
    pub proxying: Option<Selected>,
    /// Least-connections slot held while the request is in flight.
    pub backend: Option<SelectedBackend>,
    /// Realip state captured in the request filter (client address, original address).
    pub client: crate::core::http::ClientState,
    /// `limit_conn` slots held until the request finishes.
    pub connections: Option<crate::modules::limit_conn::HeldConnections>,
    pub host: String,
    pub server_name: String,
    pub started: std::time::Instant,
    /// TLS handshake facts of the downstream connection (`$ssl_*`), `None` on plain HTTP.
    pub ssl: Option<Arc<crate::modules::ssl::variables::SslSession>>,
    /// `server {}` selected by SNI at handshake time (`ngx_http_ssl_servername`).
    pub ssl_server: Option<usize>,
    /// Status to report when every upstream attempt failed (`ngx_http_upstream_next`).
    pub upstream_status: Option<StatusCode>,
    /// `$upstream_cache_status`, filled in by `proxy_pass` (`ngx_http_upstream_cache_status`).
    pub cache_status: CacheStatusCell,
    /// Set when `proxy_cache_bypass` matched.
    pub cache_bypassed: std::sync::atomic::AtomicBool,
    /// A snapshot of the request's variables, used for cache key/bypass evaluation.
    pub cache_state_source: Option<crate::core::http::RequestState>,
    /// `error_page` already produced this response (recursion guard).
    pub error_page_served: bool,
    /// `=code` of the matching `error_page` entry.
    pub error_page_status: Option<u16>,
    /// Upstream response withheld by `proxy_intercept_errors` (status, body, headers).
    #[allow(clippy::type_complexity)]
    pub intercepted: Option<(u16, Vec<u8>, Vec<(String, String)>)>,
}

/// Result of the request phase engine (`ngx_http_core_run_phases`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseOutcome {
    /// A response was written to the client.
    Answered,
    /// The `proxy_pass` content handler applies: hand the request to the proxy pipeline.
    Proxy,
}

pub struct HttpCoreApp {
    /// The active engine. Swapped atomically by configuration reload, so in-flight requests
    /// keep the snapshot they started with.
    pub(crate) engine: Arc<ArcSwap<Engine>>,
    pub(crate) listen: String,
    /// TLS handshake settings of this listener (`listen ... ssl`).
    pub(crate) tls: Option<Arc<ListenerTls>>,
}

/// TLS state of one listener: every virtual server bound to the address.
pub struct ListenerTls {
    pub hosts: crate::modules::ssl::config::TlsVirtualHosts,
    /// Session caches shared with the other listeners of the process.
    pub sessions: Arc<crate::modules::ssl::sessions::SharedCaches>,
    /// `ssl_buffer_size` of the answering server, used for the handshake buffer.
    pub buffer_size: usize,
    /// Handshake statistics (`$connections_*` style counters for TLS).
    pub stats: Arc<TlsStats>,
}

/// Counters kept for `stub_status`-like TLS reporting.
#[derive(Debug, Default)]
pub struct TlsStats {
    pub handshakes: std::sync::atomic::AtomicU64,
    pub handshake_failures: std::sync::atomic::AtomicU64,
    pub reused_sessions: std::sync::atomic::AtomicU64,
}

impl ListenerTls {
    /// Record one completed handshake.
    pub fn note_handshake(&self, facts: &crate::modules::ssl::variables::SslSession) {
        use std::sync::atomic::Ordering;
        self.stats.handshakes.fetch_add(1, Ordering::Relaxed);
        if facts.session_reused {
            self.stats.reused_sessions.fetch_add(1, Ordering::Relaxed);
        }
    }
}


impl HttpCoreApp {
    pub(crate) fn view(&self, ctx: &RequestContext) -> RequestStateView {
        RequestStateView {
            request: RequestLine::from_header(&ctx.request),
            client: ctx.client.clone(),
            connection: ConnectionState {
                listen: ctx.listen.clone(),
                peer_ip: ctx.client.original_addr,
                peer_port: ctx.client.original_port,
                local_ip: None,
                local_port: 0,
                scheme: "http".to_string(),
                tls: false,
            },
            headers: ctx.request.headers.clone(),
            server_name: ctx.server_name.clone(),
            status: None,
            started: ctx.started,
            upstream_addr: ctx
                .backend
                .as_ref()
                .map(|backend| backend.address().to_string())
                .unwrap_or_default(),
            body_bytes_sent: 0,
            limit_req_status: None,
            cache_status: ctx.cache_status.name(),
        }
    }

    pub(crate) fn real_addr(&self, ctx: &RequestContext) -> String {
        ctx.client
            .addr
            .map(|address| address.to_string())
            .unwrap_or_else(|| "-".to_string())
    }
}
