//! The HTTP request engine.
//!
//! This is the only place that knows the order of Nginx phases; concrete behaviour lives
//! in modules:
//!
//! 1. `POST_READ` 闂?`realip` rewrites `$remote_addr` before configuration lookup.
//! 2. `FIND_CONFIG` 闂?server and location selection.
//! 3. `REWRITE` 闂?rewrite rules, restarting lookup on `last`.
//! 4. `CONTENT` 闂?`return`, Lua, `proxy_pass` or static files.
//! 5. Response header filter 闂?proxy hide/add headers plus the Lua header filter.

use crate::SERVER_NAME;
use crate::core::http::{ConnectionState, RequestLine, RequestState, RequestStateView};
use crate::modules::balancer::{SelectedBackend, Upstream};
use crate::modules::headers::HeadersConf;
use crate::modules::http_core::{
    CompiledLocation, HttpConfig, normalize_host, select_location, server_matches_names,
    server_name_specificity,
};
use crate::modules::log::{AccessLogConfig, AccessLogWriter};
use crate::modules::lua::{self, LuaConf};
use crate::modules::proxy::{self, ProxyConf};
use crate::modules::realip::{self, RealipConf};
use crate::modules::rewrite::{self, RewriteConf};
use crate::modules::static_files::{self, StaticConf};
use crate::modules::uri;
use crate::modules::writer::ResponseWriter;
use arc_swap::ArcSwap;
use pingora_core::server::ShutdownWatch;

/// ssl_handshake_timeout default in Nginx.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
use async_trait::async_trait;
use http::{StatusCode, Uri};
use pingora_core::connectors::TransportConnector;
use pingora_core::upstreams::peer::{HttpPeer, PeerOptions};
use pingora_core::{Error, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

/// Retry state shared between `proxy_pass` and one upstream attempt
/// (`ngx_http_upstream_next`).
#[derive(Clone, Copy)]
struct RetryBudget {
    remaining: usize,
    mask: crate::modules::proxy::UpstreamFailures,
    timeout: Option<std::time::Duration>,
    started: std::time::Instant,
    non_idempotent: bool,
}

impl RetryBudget {
    /// Whether one more attempt is allowed for `class` (`ngx_http_upstream_next`): the
    /// condition must be enabled, an already-sent request is non-idempotent unless listed,
    /// and `proxy_next_upstream_tries`/`_timeout` still have to allow it.
    fn allows(&self, class: u32) -> bool {
        use crate::modules::proxy::UpstreamFailures as F;
        let mut effective = class;
        if self.non_idempotent {
            effective |= F::NON_IDEMPOTENT;
        }
        self.remaining > 0
            && self.mask.contains(effective)
            && self.mask.0 & F::OFF == 0
            && self
                .timeout
                .map(|limit| self.started.elapsed() < limit)
                .unwrap_or(true)
    }
}

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
    engine: Arc<ArcSwap<Engine>>,
    listen: String,
    /// TLS handshake settings of this listener (`listen ... ssl`).
    tls: Option<Arc<ListenerTls>>,
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
    /// The Nginx phase engine for one request (`ngx_http_core_run_phases`).
    ///
    /// POST_READ -> FIND_CONFIG -> REWRITE -> PREACCESS -> ACCESS -> CONTENT.
    pub async fn route_request(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> Result<PhaseOutcome> {
        // Snapshot the current configuration for this request.
        let current = self.engine.load();
        let engine = &*current;
        ctx.started = std::time::Instant::now();
        let request = session.req_header().clone();
        session.as_downstream_mut().enable_retry_buffering();
        ctx.request = request.clone();
        let host = request
            .headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .or_else(|| request.uri.authority().map(|authority| authority.as_str()))
            .unwrap_or_default()
            .to_string();
        ctx.host = host.clone();
        let mut state = RequestState::new(
            connection_state(session, &ctx.listen),
            RequestLine::from_header(&request),
            request.headers.clone(),
            engine.providers,
        );
        ctx.client = state.client.clone();
        {
            use crate::modules::stub_status::{ServerStats, StatsSnapshot};
            ServerStats::inc(&engine.stats.accepted);
            ServerStats::inc(&engine.stats.requests);
            ServerStats::inc(&engine.stats.handled);
            ServerStats::inc(&engine.stats.active);
            state.insert(StatsSnapshot::from_stats(&engine.stats));
        }

        // `return` (rewrite module) records the action here; PREACCESS/ACCESS handlers
        // still run before the response is generated, matching the C phase engine.
        let mut pending_return: Option<crate::modules::rewrite::ReturnAction> = None;

        for _ in 0..10 {
            let Some(server) = engine.select_server(&ctx.listen, &state.request.host) else {
                return self.respond(
                    &mut state,
                    session,
                    ctx,
                    StatusCode::NOT_FOUND,
                    "404 Not Found\n",
                    &[],
                )
                .await;
            };
            let Some(location) = engine.select_location(server, &state.request.path) else {
                return self.respond(
                    &mut state,
                    session,
                    ctx,
                    StatusCode::NOT_FOUND,
                    "404 Not Found\n",
                    &[],
                )
                .await;
            };
            let selected = Selected { server, location };
            let compiled = engine.location(selected).expect("selected location exists");
            state.server_name = engine.servers[server]
                .server_names
                .first()
                .cloned()
                .unwrap_or_default();
            ctx.server_name = state.server_name.clone();
            ctx.selected = Some(selected);

            // `NGX_HTTP_POST_READ_PHASE`: realip before anything observes `$remote_addr`.
            engine.apply_realip(compiled, &mut state);
            ctx.client = state.client.clone();

            // `NGX_HTTP_REWRITE_PHASE`.
            if let Some(conf) = compiled.conf.get::<RewriteConf>().cloned() {
                let mut module_ctx = crate::modules::ctx::ModuleCtx::new(
                    session,
                    &mut state,
                    &compiled.conf,
                    &ctx.server_name,
                );
                if let Some(outcome) =
                    rewrite::apply_rewrites(&mut module_ctx, &conf).map_err(engine_error)?
                {
                    match outcome {
                        rewrite::RewriteOutcome::Redirect { status, target } => {
                            let status = StatusCode::from_u16(status).map_err(engine_error)?;
                            let location_header = vec![("Location".to_string(), target)];
                            return self.respond(
                                &mut state,
                                session,
                                ctx,
                                status,
                                "",
                                &location_header,
                            )
                            .await;
                        }
                        rewrite::RewriteOutcome::Internal { target, restart } => {
                            let (path, args) = uri::split_target(&target);
                            state.request.path = path;
                            if let Some(args) = args {
                                state.request.args = args;
                            }
                            if restart {
                                continue;
                            }
                            let Some(new_location) =
                                engine.select_location(server, &state.request.path)
                            else {
                                return self.respond(
                                    &mut state,
                                    session,
                                    ctx,
                                    StatusCode::NOT_FOUND,
                                    "404 Not Found\n",
                                    &[],
                                )
                                .await;
                            };
                            return self
                                .content_phase(
                                    session,
                                    &mut state,
                                    ctx,
                                    Selected {
                                        server,
                                        location: new_location,
                                    },
                                )
                                .await;
                        }
                    }
                }
                if let Some(action) = rewrite::return_spec(&conf) {
                    // Keep the unevaluated action: Nginx evaluates the text in the content
                    // phase, after PREACCESS handlers such as `limit_req` ran, so
                    // `$limit_req_status` observes its final value.
                    pending_return = Some(action);
                }
            }
            // limit_req, then access control, matching Nginx's phase handlers.
            let conn_denied = {
                let mut module_ctx = crate::modules::ctx::ModuleCtx::new(
                    session,
                    &mut state,
                    &compiled.conf,
                    &ctx.server_name,
                );
                crate::modules::limit_conn::handle(&mut module_ctx)
                    .await
                    .map_err(engine_error)?
            };
            ctx.connections = state.take::<crate::modules::limit_conn::HeldConnections>();
            if let Some(status) = conn_denied {
                let status = StatusCode::from_u16(status).map_err(engine_error)?;
                return self.respond(
                    &mut state,
                    session,
                    ctx,
                    status,
                    "503 Service Temporarily Unavailable\n",
                    &[],
                )
                .await;
            }

            // `NGX_HTTP_PREACCESS_PHASE`: limit_req runs before access control, as in
            // Nginx's phase order, so rate-limited clients never reach auth checks.
            if let Some((status, wait)) = {
                let mut module_ctx = crate::modules::ctx::ModuleCtx::new(
                    session,
                    &mut state,
                    &compiled.conf,
                    &ctx.server_name,
                );
                crate::modules::limit_req::handle(&mut module_ctx)
                    .await
                    .map_err(engine_error)?
            } {
                if status == 0 {
                    if let Some(wait) = wait {
                        tokio::time::sleep(wait).await;
                    }
                } else {
                    let status = StatusCode::from_u16(status).map_err(engine_error)?;
                    return self.respond(
                        &mut state,
                        session,
                        ctx,
                        status,
                        &format!(
                            "{} {}\n",
                            status.as_u16(),
                            status.canonical_reason().unwrap_or("Limited")
                        ),
                        &[],
                    )
                    .await;
                }
            }
            let denied = {
                let mut module_ctx = crate::modules::ctx::ModuleCtx::new(
                    session,
                    &mut state,
                    &compiled.conf,
                    &ctx.server_name,
                );
                crate::modules::access::handle(&mut module_ctx)
                    .await
                    .map_err(engine_error)?
            };
            if let Some(status) = denied {
                let status = StatusCode::from_u16(status).map_err(engine_error)?;
                return self.respond(
                    &mut state,
                    session,
                    ctx,
                    status,
                    "403 Forbidden\n",
                    &[],
                )
                .await;
            }

            // `NGX_HTTP_ACCESS_PHASE` for `access_by_lua`.
            if let Some(hook) = compiled
                .conf
                .get::<LuaConf>()
                .and_then(|conf| conf.access.as_ref())
            {
                let outcome = lua::execute(hook, &state).map_err(engine_error)?;
                if !outcome.request_headers.is_empty() {
                    lua::apply_request_headers(&mut state.headers, &outcome.request_headers)
                        .map_err(engine_error)?;
                }
                if let Some(target) = &outcome.uri
                    && target != &state.request.path
                {
                    state.request.path = target.clone();
                    continue;
                }
                if outcome.exited || !outcome.body.is_empty() {
                    let status = StatusCode::from_u16(outcome.status.unwrap_or(200))
                        .map_err(engine_error)?;
                    return self.respond(
                        &mut state,
                        session,
                        ctx,
                        status,
                        &outcome.body,
                        &outcome.headers,
                    )
                    .await;
                }
            }
            // `return` recorded an action during the rewrite phase; access and limits have
            // now had their say, so evaluate and emit it instead of running a content
            // handler.
            if let Some(action) = pending_return.take() {
                let action = rewrite::evaluate_return(&action, &state);
                let status = StatusCode::from_u16(action.status).map_err(engine_error)?;
                let headers = action
                    .target
                    .clone()
                    .filter(|_| status.is_redirection())
                    .map(|target| vec![("Location".to_string(), target)])
                    .unwrap_or_default();
                let body = if status.is_redirection() {
                    String::new()
                } else {
                    action.target.unwrap_or_default()
                };
                return self.respond(
                    &mut state,
                    session,
                    ctx,
                    status,
                    &body,
                    &headers,
                )
                .await;
            }
            return self
                .content_phase(session, &mut state, ctx, selected)
                .await;
        }
        self.respond(
            &mut state,
            session,
            ctx,
            StatusCode::INTERNAL_SERVER_ERROR,
            "500 Rewrite or internal redirection cycle\n",
            &[],
        )
        .await
    }
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        http: &HttpConfig,
        mut upstreams: HashMap<String, Arc<Upstream>>,
        providers: &'static [(
            &'static str,
            &'static dyn crate::core::variables::VariableProvider,
        )],
        mime: crate::modules::http_core::MimeConfig,
        stats: Arc<crate::modules::stub_status::ServerStats>,
        access_log: Arc<AccessLogConfig>,
        access_writer: Option<Arc<AccessLogWriter>>,
        server_conf: Arc<pingora_core::server::configuration::ServerConf>,
    ) -> Self {
        // Direct `proxy_pass http://host:port` targets are not declared in an `upstream`
        // block; create a single-backend group for each so upstream selection and the
        // health-aware balancer work uniformly.
        for server in &http.servers {
            for location in &server.locations {
                let Some(pass) = location
                    .conf
                    .get::<ProxyConf>()
                    .and_then(|conf| conf.pass.as_ref())
                else {
                    continue;
                };
                if upstreams.contains_key(&pass.upstream) {
                    continue;
                }
                let config = crate::modules::upstream::UpstreamConfig {
                    name: pass.upstream.clone(),
                    backends: vec![crate::modules::upstream::BackendConfig {
                        address: pass.upstream.clone(),
                        weight: 1,
                        down: false,
                    }],
                    algorithm: crate::modules::upstream::LoadBalancingAlgorithm::RoundRobin,
                    health_check_interval: None,
                };
                if let Ok(upstream) = Upstream::new(&config) {
                    upstreams.insert(pass.upstream.clone(), Arc::new(upstream));
                }
            }
        }
        let mut listeners: BTreeMap<String, VirtualHosts> = BTreeMap::new();
        let mut servers = Vec::new();
        for server in &http.servers {
            let index = servers.len();
            servers.push(ServerRuntime {
                server_names: server.server_names.clone(),
                locations: server.locations.clone(),
            });
            for listen in &server.listens {
                let hosts = listeners
                    .entry(listen.address.clone())
                    .or_insert(VirtualHosts {
                        servers: Vec::new(),
                        default: 0,
                    });
                if listen.default_server {
                    hosts.default = hosts.servers.len();
                }
                hosts.servers.push(index);
            }
        }
        Self {
            servers,
            listeners,
            upstreams,
            providers,
            mime,
            stats,
            access_log,
            access_writer,
            server_conf,
        }
    }

    pub fn listeners(&self) -> impl Iterator<Item = &str> {
        self.listeners.keys().map(String::as_str)
    }

    /// `ngx_http_find_virtual_server`: pick the server by `Host`/SNI, then the
    /// `default_server` of the address.
    pub fn select_server(&self, listen: &str, host: &str) -> Option<usize> {
        let hosts = self.listeners.get(listen)?;
        let host = normalize_host(host);
        let mut best: Option<(usize, usize)> = None;
        for (order, index) in hosts.servers.iter().enumerate() {
            let server = &self.servers[*index];
            if !server_matches_names(&server.server_names, &host) {
                continue;
            }
            let specificity = server
                .server_names
                .iter()
                .map(|name| server_name_specificity(name, &host))
                .max()
                .unwrap_or(0);
            let better = best.is_none_or(|(score, previous_order)| {
                specificity > score || (specificity == score && order < previous_order)
            });
            if better {
                best = Some((specificity, order));
            }
        }
        best.map(|(_, order)| hosts.servers[order])
            .or_else(|| hosts.servers.get(hosts.default).copied())
    }

    pub fn select_location(&self, server: usize, uri: &str) -> Option<usize> {
        let runtime = self.servers.get(server)?;
        let entry = select_location(&runtime.locations, uri, |entry| &entry.matcher)?;
        runtime
            .locations
            .iter()
            .position(|candidate| std::ptr::eq(candidate, entry))
    }

    pub fn location(&self, selected: Selected) -> Option<&CompiledLocation> {
        self.servers
            .get(selected.server)?
            .locations
            .get(selected.location)
    }

    fn upstream_for(&self, location: &CompiledLocation) -> Option<Arc<Upstream>> {
        let pass = location.conf.get::<ProxyConf>()?.pass.as_ref()?;
        self.upstreams.get(&pass.upstream).cloned()
    }

    /// Rewrite the client address from a trusted proxy header (realip module).
    pub fn apply_realip(&self, location: &CompiledLocation, state: &mut RequestState) {
        if let Some(conf) = location.conf.get::<RealipConf>() {
            realip::apply(conf, state);
        }
    }
}

impl HttpCoreApp {
    /// Produce a complete response for one request and report the phase outcome.
    async fn respond(
        &self,
        state: &mut RequestState,
        session: &mut Session,
        ctx: &mut RequestContext,
        status: StatusCode,
        body: &str,
        headers: &[(String, String)],
    ) -> Result<PhaseOutcome> {
        // `ngx_http_special_response_handler`: an `error_page` entry for this status serves
        // that URI instead of the generated body (`ngx_http_send_error_page`).
        if status.as_u16() >= 300 && !ctx.error_page_served {
            ctx.error_page_served = true;
            if let Some(page) = self.error_page_for(ctx, status.as_u16()) {
                let target = page.eval_uri(&self.view(ctx), self.engine.load().providers);
                if self.error_page_location(ctx, &target).is_some() {
                    // An internal redirect re-runs the whole phase stack for the new URI
                    // (`ngx_http_internal_redirect`), so `return`, rewrite and content
                    // handlers of the target location all apply.
                    let previous = (state.request.path.clone(), state.request.args.clone());
                    let previous_uri = session.req_header().uri.clone();
                    crate::modules::uri::set_request_uri(
                        &mut state.request,
                        &target,
                        page.args.as_deref(),
                    );
                    // `ngx_http_internal_redirect` rewrites `r->uri`/`r->args`; the phase
                    // engine re-reads them from the request line.
                    let redirect_uri = state.request.uri.clone();
                    crate::modules::uri::set_uri(session.req_header_mut(), &redirect_uri).ok();
                    ctx.error_page_status = page.overwrite;
                    let outcome = Box::pin(self.route_request(session, ctx)).await;
                    crate::modules::uri::set_uri(session.req_header_mut(), &previous_uri.to_string()).ok();
                    state.request.path = previous.0;
                    state.request.args = previous.1;
                    return outcome;
                }
            }
        }
        let _ = self.answer(session, state, ctx, status, body, headers).await;
        Ok(PhaseOutcome::Answered)
    }
}

impl HttpCoreApp {
    /// The `error_page` entry of the selected location which answers `status`.
    fn error_page_for(
        &self,
        ctx: &RequestContext,
        status: u16,
    ) -> Option<crate::modules::error_page::ErrorPage> {
        let current = self.engine.load();
        let compiled = current.location(ctx.selected?)?;
        let conf = compiled
            .conf
            .get::<crate::modules::error_page::ErrorPageConf>()?;
        let page = conf.find(status)?.clone();
        // Only internal targets are implemented; an external URI would emit a redirect.
        if !page.uri.source().starts_with('/') {
            log::warn!(
                "error_page {status} target \"{}\" is not an internal URI",
                page.uri.source()
            );
            return None;
        }
        Some(page)
    }

    /// Resolve the server and location which serve the `error_page` target.
    fn error_page_location(&self, ctx: &RequestContext, target: &str) -> Option<(usize, usize)> {
        let current = self.engine.load();
        let engine = &*current;
        let server = engine.select_server(&ctx.listen, &ctx.host);
        let server = server?;
        let location = engine.select_location(server, target);
        Some((server, location?))
    }
}


impl HttpCoreApp {
    pub fn new(engine: Arc<ArcSwap<Engine>>, listen: String) -> Self {
        Self {
            engine,
            listen,
            tls: None,
        }
    }

    /// Mark this listener as TLS and install the handshake configuration.
    pub fn with_tls(mut self, tls: ListenerTls) -> Self {
        self.tls = Some(Arc::new(tls));
        self
    }

    /// Install (or remove) the TLS handshake settings of this listener.
    pub fn apply_tls(&mut self, tls: Option<ListenerTls>) {
        self.tls = tls.map(Arc::new);
    }

    /// The TLS handshake settings of this listener, when `listen ... ssl` applies.
    pub fn tls(&self) -> Option<&Arc<ListenerTls>> {
        self.tls.as_ref()
    }

    /// The listener address this service is bound to.
    pub fn listen(&self) -> &str {
        &self.listen
    }

    /// `new_ctx()` for a session served by [`Bridge`].
    pub fn new_request_context(&self) -> RequestContext {
        RequestContext {
            listen: self.listen.clone(),
            request: RequestHeader::build("GET", b"/", Some(0))
                .expect("placeholder request is valid"),
            selected: None,
            proxying: None,
            backend: None,
            client: crate::core::http::ClientState::default(),
            connections: None,
            host: String::new(),
            server_name: String::new(),
            started: std::time::Instant::now(),
            ssl: None,
            ssl_server: None,
            upstream_status: None,
            cache_status: CacheStatusCell::default(),
            cache_bypassed: std::sync::atomic::AtomicBool::new(false),
            cache_state_source: None,
            error_page_served: false,
            error_page_status: None,
            intercepted: None,
        }
    }

    /// `ngx_http_log_request`: emit the access log entry for a finished request.
    pub async fn log_request(
        &self,
        session: &mut Session,
        ctx: &RequestContext,
        error: Option<&Error>,
    ) {
        let current = self.engine.load();
        let engine = &*current;
        let status = session
            .response_written()
            .map_or(0, |response| response.status.as_u16());
        let view = self.view(ctx);
        let mut state = view_as_state(&view, engine.providers);
        state.body_bytes_sent = session.body_bytes_sent();
        state.status = session.response_written().map(|response| response.status);
        let message = error.map(|error| error.to_string());
        engine.access_log.log(
            engine.access_writer.as_deref(),
            &state,
            status,
            message.as_deref(),
        );
    }

    /// The `proxy_pass` content handler (`ngx_http_proxy_handler`).
    ///
    /// Chooses the peer (`ngx_http_upstream_init_request`), builds the upstream request
    /// (`ngx_http_proxy_create_request`), forwards the body and relays the response. Returns
    /// whether the downstream connection may be reused.
    pub async fn proxy_request(&self, session: &mut Session, ctx: &mut RequestContext) -> bool {
        let outcome = self.proxy_pass(session, ctx).await;
        // `proxy_intercept_errors`: the withheld upstream response is processed like a local
        // one, so `error_page` and the core's own error pages apply to it.
        if let Some((status, body, headers)) = ctx.intercepted.take() {
            let current = self.engine.load();
            let providers = current.providers;
            let text = String::from_utf8_lossy(&body).to_string();
            let view = self.view(ctx);
            let mut state = view_as_state(&view, providers);
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            if let Err(error) = self
                .respond(&mut state, session, ctx, status, &text, &headers)
                .await
            {
                log::error!("intercepted response failed: {error:#}");
            }
            return true;
        }
        match outcome {
            Ok(keepalive) => keepalive,
            Err(error) => {
                log::error!("proxy_pass failed: {error:#}");
                // `ngx_http_upstream_finalize_request`: report the upstream failure to the
                // client instead of dropping the connection. A timed-out attempt yields 504,
                // anything else 502 (see `UpstreamFailures::status`).
                let status = ctx
                    .upstream_status
                    .unwrap_or(StatusCode::BAD_GATEWAY);
                let (reason, body) = match status {
                    StatusCode::GATEWAY_TIMEOUT => ("Gateway Time-out", "504 Gateway Time-out"),
                    StatusCode::SERVICE_UNAVAILABLE => {
                        ("Service Temporarily Unavailable", "503 Service Temporarily Unavailable")
                    }
                    _ => ("Bad Gateway", "502 Bad Gateway"),
                };
                let mut response = match ResponseHeader::build(status, Some(4)) {
                    Ok(response) => response,
                    Err(error) => {
                        log::error!("cannot build the upstream error response: {error}");
                        return false;
                    }
                };
                response.insert_header("Content-Type", "text/html").ok();
                response
                    .insert_header("Content-Length", body.len().to_string())
                    .ok();
                response.insert_header("Connection", "close").ok();
                response.insert_header("Server", SERVER_NAME).ok();
                response.insert_header("X-Reason", reason).ok();
                let _ = session.write_response_header(Box::new(response), false).await;
                let _ = session.write_response_body(Some(body.into()), true).await;
                false
            }
        }
    }

    /// `ngx_http_upstream_init_request` + `ngx_http_upstream_next`.
    ///
    /// A request is attempted on one backend and retried on the next (`proxy_next_upstream`,
    /// `proxy_next_upstream_tries`, `proxy_next_upstream_timeout`) exactly as Nginx does:
    /// the failure class must be enabled, a non-idempotent request only retries when
    /// `non_idempotent` is listed, and tries/timeout bound the loop.
    async fn proxy_pass(&self, session: &mut Session, ctx: &mut RequestContext) -> anyhow::Result<bool> {
        let current = self.engine.load();
        let engine = &*current;
        let selected = ctx
            .proxying
            .ok_or_else(|| anyhow::anyhow!("no proxy location"))?;
        let compiled = engine
            .location(selected)
            .ok_or_else(|| anyhow::anyhow!("location disappeared"))?;
        let conf = compiled
            .conf
            .get::<ProxyConf>()
            .ok_or_else(|| anyhow::anyhow!("no proxy configuration"))?;
        let pass = conf
            .pass
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no proxy_pass"))?;
        let upstream = engine
            .upstream_for(compiled)
            .ok_or_else(|| anyhow::anyhow!("unknown upstream"))?;
        let key = ctx.client.addr.map(|ip| ip.to_string()).unwrap_or_default();

        // `ngx_http_proxy_create_request` is built once: a retry reuses the same request.
        let method = match &conf.method {
            Some(template) => {
                let value = template.eval(&view_as_state(&self.view(ctx), engine.providers));
                http::Method::from_bytes(value.as_bytes())?
            }
            None => session.req_header().method.clone(),
        };
        let mut request = RequestHeader::build(method.clone(), b"/", None)?;
        if conf.pass_request_headers {
            for (name, value) in session.req_header().headers.iter() {
                request.insert_header(name.clone(), value.clone())?;
            }
        }
        let path = proxy::proxy_uri(pass, compiled.matcher.matched_prefix(), session.req_header().uri.path());
        let target = match session.req_header().uri.query() {
            Some(query) if !query.is_empty() => format!("{path}?{query}"),
            _ => path,
        };
        request.set_uri(target.parse::<Uri>()?);
        request.set_version(if conf.http_version == 11 {
            http::Version::HTTP_11
        } else {
            http::Version::HTTP_10
        });
        request.insert_header("Host", pass.host_header.clone())?;
        request.insert_header("X-Real-IP", self.real_addr(ctx))?;
        let view = self.view(ctx);
        proxy::apply_upstream_headers(conf, &view_as_state(&view, engine.providers), &mut request)?;

        // `proxy_request_buffering`: read the body before connecting. Only requests that
        // frame a body are read, otherwise `read_request_body` waits for a body that never
        // arrives. `proxy_pass_request_body off` drops it, `proxy_set_body` replaces it.
        let mut body = Vec::new();
        let has_body = conf.pass_request_body
            && (session
                .req_header()
                .headers
                .contains_key(http::header::CONTENT_LENGTH)
                || session
                    .req_header()
                    .headers
                    .contains_key("transfer-encoding"));
        if has_body {
            while let Some(chunk) = session.read_request_body().await? {
                body.extend_from_slice(&chunk);
            }
        } else {
            session.drain_request_body().await.ok();
        }
        if let Some(template) = &conf.set_body {
            body = template
                .eval(&view_as_state(&self.view(ctx), engine.providers))
                .into_bytes();
        }
        if !conf.pass_request_body {
            body.clear();
            request.remove_header("content-length");
            request.remove_header("transfer-encoding");
        }
        if !body.is_empty() {
            request.insert_header("Content-Length", body.len().to_string())?;
        }

        // `ngx_http_upstream_init_request`: one attempt per peer, bounded by the directive.
        let mut tries = upstream.peer_count_hint().max(1);
        if let Some(limit) = conf.next_upstream_tries
            && limit > 0
        {
            tries = tries.min(limit);
        }
        let started = std::time::Instant::now();
        let mut tried: Vec<String> = Vec::new();
        // Shared with the attempt so a status-based failure only retries when a
        // further attempt is actually possible (`ngx_http_upstream_next`).
        let retry = RetryBudget {
            remaining: tries,
            mask: conf.next_upstream,
            timeout: conf.next_upstream_timeout,
            started,
            non_idempotent: !matches!(
                method,
                http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE
            ),
        };


        loop {
            let backend = upstream
                .select_avoiding(key.as_bytes(), &tried)
                .ok_or_else(|| anyhow::anyhow!("no live upstreams"))?;
            let backend_address = backend.address().to_string();
            tried.push(backend_address.clone());
            ctx.backend = Some(backend);

            let sni = parse_sni(&pass.host_header);
            let mut options = PeerOptions::new();
            options.connection_timeout = conf.connect_timeout;
            options.total_connection_timeout = conf.connect_timeout;
            options.read_timeout = conf.read_timeout;
            options.write_timeout = conf.send_timeout;
            let mut peer = HttpPeer::new(backend_address, pass.tls, sni);
            peer.options = options;

            match self
                .proxy_attempt(session, ctx, conf, pass, &peer, request.clone(), &body, retry)
                .await
            {
                Ok(()) => return Ok(true),
                Err(proxy::UpstreamError { failure, source }) => {
                    tries = tries.saturating_sub(1);
                    log::warn!(
                        "upstream failure ({failure:#x}) on {}: {source}",
                        peer.sni
                    );
                    // `ngx_http_upstream_next`: the class must be enabled, and a request that
                    // was already sent is non-idempotent unless listed.
                    let mut class = failure;
                    if !matches!(
                        method,
                        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE
                    ) {
                        class |= proxy::UpstreamFailures::NON_IDEMPOTENT;
                    }
                    let retryable = tries > 0
                        && conf.next_upstream.contains(class)
                        && !conf.next_upstream.contains(proxy::UpstreamFailures::OFF)
                        && conf
                            .next_upstream_timeout
                            .map(|limit| started.elapsed() < limit)
                            .unwrap_or(true);
                    if !retryable {
                        return Err(anyhow::anyhow!(
                            "no live upstreams after {failure:#x} ({source})"
                        ));
                    }
                }
            }
        }
    }

    /// One upstream attempt (`ngx_http_upstream_connect` 闂?`ngx_http_upstream_process_body`).
    #[allow(clippy::too_many_arguments)]
    async fn proxy_attempt(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        conf: &ProxyConf,
        pass: &proxy::ProxyPass,
        peer: &HttpPeer,
        request: RequestHeader,
        body: &[u8],
        retry: RetryBudget,
    ) -> std::result::Result<(), proxy::UpstreamError> {
        use proxy::UpstreamFailures as F;

        // `ngx_http_upstream_cache`: a fresh entry is served without contacting the peer.
        // The key and bypass predicates are script-evaluated, so the request variables are
        // snapshotted once here (`ngx_http_script_run`).
        if ctx.cache_state_source.is_none() && conf.cache.enabled() {
            let view = self.view(ctx);
            let providers = self.engine.load().providers;
            ctx.cache_state_source = Some(view_as_state(&view, providers));
        }
        let cache_request = cache_request_state(conf, session, ctx);
        if let Some(cache) = &cache_request {
            if let Some(entry) = cache_lookup(cache) {
                record_cache_state(ctx, cache, crate::modules::proxy_cache::CacheStatus::Hit);
                serve_cached(session, &entry).await?;
                return Ok(());
            }
            record_cache_state(ctx, cache, crate::modules::proxy_cache::CacheStatus::Miss);
        }

        let connector = TransportConnector::new(None);
        let stream = connector
            .new_stream(peer)
            .await
            .map_err(|error| proxy::UpstreamError::new(F::ERROR, error))?;
        let mut upstream_session = if peer.is_tls() {
            let tls = crate::modules::proxy_tls::client(peer, conf)
                .map_err(|error| proxy::UpstreamError::new(F::ERROR, error))?;
            let stream = crate::modules::proxy_tls::connect(&tls, stream, peer)
                .await
                .map_err(|error| proxy::UpstreamError::new(F::ERROR, error))?;
            pingora_core::protocols::http::v1::client::HttpSession::new(Box::new(stream))
        } else {
            pingora_core::protocols::http::v1::client::HttpSession::new(stream)
        };

        upstream_session
            .write_request_header(Box::new(request))
            .await
            .map_err(|error| proxy::UpstreamError::new(F::ERROR, error))?;
        if body.is_empty() {
            upstream_session
                .finish_body()
                .await
                .map_err(|error| proxy::UpstreamError::new(F::ERROR, error))?;
        } else {
            upstream_session
                .write_body(body)
                .await
                .map_err(|error| proxy::UpstreamError::new(F::ERROR, error))?;
            upstream_session
                .finish_body()
                .await
                .map_err(|error| proxy::UpstreamError::new(F::ERROR, error))?;
        }

        // `ngx_http_upstream_process_header`.
        upstream_session.read_response().await.map_err(|error| {
            let failure = if error.etype() == &ErrorType::ReadTimedout {
                F::TIMEOUT
            } else {
                F::INVALID_HEADER
            };
            proxy::UpstreamError::new(failure, error)
        })?;
        let mut response = upstream_session
            .resp_header()
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("upstream sent no valid HTTP/1.0 header")
            })?;

        // `ngx_http_upstream_process_header`: a status listed in `proxy_next_upstream`
        // releases the peer so the next attempt can run. When no further attempt is
        // possible, the upstream response itself is delivered (`ngx_http_upstream_next`
        // keeps `u->state->status` and the client sees that status).
        if let Some(failure) = proxy::status_failure(response.status.as_u16())
            && conf.next_upstream.contains(failure)
            && !conf.next_upstream.contains(proxy::UpstreamFailures::OFF)
        {
            if !retry.allows(failure) {
                ctx.upstream_status = Some(response.status);
            } else {
                upstream_session.shutdown().await;
                return Err(proxy::UpstreamError::new(
                    failure,
                    anyhow::anyhow!("upstream status {}", response.status.as_u16()),
                ));
            }
        }

        let view = self.view(ctx);
        let current = self.engine.load();
        let state = view_as_state(&view, current.providers);
        // `ngx_http_upstream_process_header`: the upstream `Server` is hidden by default,
        // so this server name replaces it unless `proxy_pass_header Server` kept it.
        if !proxy::passes_through(conf, "server") {
            response.insert_header("Server", SERVER_NAME)?;
        }
        proxy::apply_response_headers(conf, &mut response);
        proxy::rewrite_response_headers(conf, pass, &state, &mut response)?;
        if let Some(selected) = ctx.proxying
            && let Some(location) = current.location(selected)
            && let Some(headers) = location.conf.get::<HeadersConf>()
        {
            headers.apply(&mut response, &view)?;
        }
        let is_head = session.req_header().method == http::Method::HEAD;
        let mut ended = is_head || response.status == StatusCode::NO_CONTENT;
        // `ngx_http_upstream_cacheable`: the entry needs the full body and headers.
        let cacheable = cache_request
            .as_ref()
            .is_some_and(|request| !request.key.is_empty());
        let cached_headers: Vec<(String, String)> = if cacheable {
            response
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_string(),
                        value.to_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        let cached_status = response.status.as_u16();
        let mut collecting: Option<Vec<u8>> = cacheable.then(Vec::new);

        // `ngx_http_upstream_send_response`: with `proxy_buffering on` the body is collected
        // through the event pipe (memory, then `proxy_temp_path`), otherwise every chunk is
        // forwarded as it arrives (`ngx_http_upstream_process_non_buffered_upstream`).
        let mut buffer = crate::modules::proxy_buffer::ResponseBuffer::new(
            conf.buffering,
            conf.buffers,
            conf.busy_buffers_size,
            conf.max_temp_file_size,
            conf.temp_path.clone(),
            conf.limit_rate,
        );
        // `proxy_intercept_errors`: a response with status >= 300 is not sent to the
        // client; the body is read first so `error_page` can take over
        // (`ngx_http_upstream_intercept_errors`).
        if conf.intercept_errors && response.status.as_u16() >= 300 {
            let mut body = Vec::new();
            while let Ok(Some(chunk)) = upstream_session.read_body_bytes().await {
                body.extend_from_slice(&chunk);
                if upstream_session.is_body_done() {
                    break;
                }
            }
            upstream_session.shutdown().await;
            ctx.intercepted = Some((
                response.status.as_u16(),
                body,
                response
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_string(),
                            value.to_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect(),
            ));
            return Ok(());
        }

        session
            .write_response_header(Box::new(response), ended)
            .await?;
        while !ended {
            match upstream_session.read_body_bytes().await {
                Ok(Some(chunk)) => {
                    let done = upstream_session.is_body_done();
                    if let Some(collected) = collecting.as_mut() {
                        collected.extend_from_slice(&chunk);
                    }
                    match buffer.push(chunk.len()) {
                        crate::modules::proxy_buffer::Push::Buffered => {}
                        crate::modules::proxy_buffer::Push::Spooled => {
                            // `ngx_event_pipe_write_chain_to_temp_file`: the response is
                            // spooled to `proxy_temp_path`, so a large upstream body does not
                            // grow the process memory.
                            spool(&mut buffer, &chunk);
                        }
                    }
                    // `proxy_limit_rate` bounds the client side transfer.
                    if let Some(delay) = buffer.rate_delay(chunk.len()) {
                        tokio::time::sleep(delay).await;
                    }
                    let length = chunk.len();
                    session.write_response_body(Some(chunk), done).await?;
                    buffer.flush(length);
                    ended = done;
                }
                Ok(None) => {
                    session.write_response_body(None, true).await?;
                    ended = true;
                }
                Err(error) => {
                    // The response header is already sent, so the client sees a truncated
                    // body; `ngx_http_upstream_next` cannot retry at this point.
                    session.write_response_body(None, true).await.ok();
                    return Err(proxy::UpstreamError::new(F::ERROR, error));
                }
            }
        }
        upstream_session.shutdown().await;
        if let Some(path) = buffer.temp_file() {
            // `ngx_temp_file_delete`-like cleanup once the response has been relayed.
            let _ = std::fs::remove_file(path);
        }
        // `ngx_http_upstream_send_response` tail: store the entry when cacheable.
        if let (Some(request), Some(body)) = (&cache_request, collecting)
            && !request.key.is_empty()
            && !ctx.cache_bypassed.load(std::sync::atomic::Ordering::Relaxed)
        {
            cache_store(request, cached_status, &cached_headers, &body);
        }
        Ok(())
    }
}

/// Per-request cache decision (`ngx_http_upstream_cache`).
struct CacheRequest {
    zone: crate::modules::proxy_cache::CacheZone,
    conf: crate::modules::proxy_cache::CacheConf,
    key: String,
    file: std::path::PathBuf,
}

/// Build the cache lookup for this request, honouring `proxy_cache_methods` and
/// `proxy_cache_bypass`.
fn cache_request_state(
    conf: &ProxyConf,
    session: &Session,
    ctx: &RequestContext,
) -> Option<CacheRequest> {
    let cache = &conf.cache;
    let zone_name = cache.zone.as_ref()?;
    if !cache.caches_method(session.req_header().method.as_str()) {
        return None;
    }
    let zone = match crate::modules::proxy_cache::zone(zone_name) {
        Some(zone) => zone,
        None => {
            log::debug!("proxy_cache: zone {zone_name} is not registered");
            return None;
        }
    };
    let Some(state) = ctx.cache_state_source.as_ref() else {
        log::debug!("proxy_cache: no request snapshot for the cache decision");
        return None;
    };
    // `proxy_cache_bypass`: any non-empty evaluation bypasses the cache (`ngx_http_test_predicates`).
    if cache
        .bypass
        .iter()
        .any(|template| !template.eval(state).is_empty())
    {
        ctx.cache_bypassed.store(true, std::sync::atomic::Ordering::Relaxed);
        return Some(CacheRequest {
            file: zone.file_path(""),
            zone,
            conf: cache.clone(),
            key: String::new(),
        });
    }
    let key = cache.key_template().ok()?.eval(state);
    let file = zone.file_path(&key);
    Some(CacheRequest {
        zone,
        conf: cache.clone(),
        key,
        file,
    })
}

/// `ngx_http_file_cache_open`: read a fresh entry for this request.
fn cache_lookup(request: &CacheRequest) -> Option<crate::modules::proxy_cache::CacheEntry> {
    if request.key.is_empty() {
        return None;
    }
    let bytes = std::fs::read(&request.file).ok()?;
    let entry = crate::modules::proxy_cache::CacheEntry::decode(&bytes)?;
    let now = crate::modules::proxy_cache::now_seconds();
    entry.is_fresh(now).then_some(entry)
}

fn record_cache_state(
    ctx: &RequestContext,
    request: &CacheRequest,
    status: crate::modules::proxy_cache::CacheStatus,
) {
    let mut state = crate::modules::proxy_cache::CacheState {
        status: Some(status),
        key: Some(request.key.clone()),
        file: Some(request.file.clone()),
    };
    if request.key.is_empty() {
        state.status = Some(crate::modules::proxy_cache::CacheStatus::Bypass);
    }
    ctx.cache_status.set(state);
}

/// Serve a stored entry (`ngx_http_file_cache_read` + the normal body pipeline).
async fn serve_cached(
    session: &mut Session,
    entry: &crate::modules::proxy_cache::CacheEntry,
) -> anyhow::Result<()> {
    let mut response = ResponseHeader::build(
        StatusCode::from_u16(entry.status).unwrap_or(StatusCode::OK),
        None,
    )?;
    for (name, value) in &entry.headers {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            let _ = response.append_header(name, value);
        }
    }
    response.insert_header("Server", SERVER_NAME)?;
    response.insert_header("Content-Length", entry.body.len().to_string())?;
    let is_head = session.req_header().method == http::Method::HEAD;
    session
        .write_response_header(Box::new(response), is_head)
        .await?;
    if !is_head {
        session
            .write_response_body(Some(entry.body.clone().into()), true)
            .await?;
    }
    Ok(())
}

/// `ngx_http_file_cache_set_header` + the body: store a response for later hits.
fn cache_store(
    request: &CacheRequest,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) {
    use crate::modules::proxy_cache::CacheEntry;

    // `proxy_no_cache`: a non-empty value keeps the response out of the cache.
    let now = crate::modules::proxy_cache::now_seconds();
    let fresh = crate::modules::proxy_cache::freshness(headers, status, &request.conf, now);
    let Some(valid_until) = fresh else {
        return;
    };
    let etag = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("etag"))
        .map(|(_, value)| value.clone());
    let last_modified = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("last-modified"))
        .map(|(_, value)| value.clone());
    let entry = CacheEntry {
        status,
        headers: headers.to_vec(),
        body: body.to_vec(),
        valid_until,
        stored_at: now,
        etag,
        last_modified,
    };
    if let Some(parent) = request.file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = request.zone;
    let mut temporary = request.file.clone();
    temporary.set_extension("tmp");
    if std::fs::write(&temporary, entry.encode()).is_ok() {
        // `ngx_http_file_cache_set_header`: the entry becomes visible atomically.
        let _ = std::fs::rename(&temporary, &request.file);
    }
}

/// Append `chunk` to the buffering temp file, mirroring
/// `ngx_event_pipe_write_chain_to_temp_file`.
fn spool(buffer: &mut crate::modules::proxy_buffer::ResponseBuffer, chunk: &[u8]) {
    let path = match buffer.temp_file().map(std::path::Path::to_path_buf) {
        Some(path) => path,
        None => {
            let Some(template) = buffer.temp_file_path() else {
                return;
            };
            if let Some(parent) = template.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            buffer.set_temp_file(template.clone());
            template
        }
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = file.write_all(chunk);
    }
}

/// One listener's downstream service: TLS termination followed by the HTTP session loop.
///
/// Pingora's `HttpProxy` is itself the `ServerApp`, so it starts parsing HTTP as soon as a
/// connection is accepted. A `listen ... ssl` listener must complete the TLS handshake first
/// (SNI selects the `server {}` and produces the `$ssl_*` facts), so `Bridge` terminates the
/// connection and then runs the same session loop, exactly where Nginx runs `c->ssl->handler`
/// before `ngx_http_wait_request_handler`.
#[derive(Clone)]
pub struct Bridge {
    app: Arc<HttpCoreApp>,
}

impl Bridge {
    pub fn new(app: Arc<HttpCoreApp>) -> Self {
        Self { app }
    }
}

#[async_trait]
impl pingora_core::apps::ServerApp for Bridge {
    async fn process_new(
        self: &Arc<Self>,
        stream: pingora_core::protocols::Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<pingora_core::protocols::Stream> {
        // `c->ssl->handler`: terminate TLS before any HTTP byte is parsed.
        let stream: pingora_core::protocols::Stream = match self.app.tls() {
            None => stream,
            Some(listener_tls) => {
                match crate::core::tls::accept(stream, listener_tls, TLS_HANDSHAKE_TIMEOUT).await {
                    Ok(tls_stream) => Box::new(tls_stream),
                    Err(error) => {
                        log::info!("TLS handshake with {} failed: {error:#}", self.app.listen());
                        return None;
                    }
                }
            }
        };
        if stream.selected_alpn_proto() == Some(pingora_core::protocols::ALPN::H2) {
            return self.serve_h2(stream, shutdown).await;
        }
        self.serve_h1(stream, shutdown).await
    }
}

impl Bridge {
    /// `ngx_http_wait_request_handler` + `ngx_http_keepalive_handler` for HTTP/1.x.
    async fn serve_h1(
        self: &Arc<Self>,
        stream: pingora_core::protocols::Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<pingora_core::protocols::Stream> {
        let mut session = pingora_proxy::Session::new_h1(stream);
        session.set_keepalive(Some(60));
        loop {
            let request = tokio::select! {
                biased;
                request = session.read_request() => request,
                _ = shutdown_signal(shutdown) => return None,
            };
            match request {
                Ok(true) => {}
                Ok(false) => return None,
                Err(error) => {
                    log::debug!("HTTP server fails to read from downstream: {error}");
                    return None;
                }
            }
            session = match Box::pin(self.serve_request(session)).await {
                Some(session) => session,
                None => return None,
            };
        }
    }

    /// Route one parsed request (`Self::process_request`) to a response.
    async fn serve_request(
        self: &Arc<Self>,
        mut session: pingora_proxy::Session,
    ) -> Option<pingora_proxy::Session> {
        let mut ctx = self.app.new_request_context();
        let keep = match self.app.route_request(&mut session, &mut ctx).await {
            Ok(PhaseOutcome::Answered) => true,
            Ok(PhaseOutcome::Proxy) => self.app.proxy_request(&mut session, &mut ctx).await,
            Err(error) => {
                log::error!("request failed: {error}");
                false
            }
        };
        self.app.log_request(&mut session, &ctx, None).await;
        if !keep {
            return None;
        }
        // `HttpProxy::finish`: keep the connection for the next keepalive request.
        let downstream = session.downstream_session;
        let (stream, pipelined) = match downstream.finish().await {
            Ok(Some(reusable)) => reusable.into_parts(),
            _ => return None,
        };
        if pipelined.is_some_and(|prefix| !prefix.is_empty()) {
            return None;
        }
        Some(pingora_proxy::Session::new_h1(stream))
    }

    /// HTTP/2 (`ngx_http_v2_init`): one session per stream on a shared connection.
    ///
    /// `listen ... http2` advertises `h2` through ALPN; a client which selects it must be
    /// served or the connection would be closed without a response. Streams are accepted in
    /// a loop until the client closes the connection (`ngx_http_v2_read_handler`).
    async fn serve_h2(
        self: &Arc<Self>,
        stream: pingora_core::protocols::Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<pingora_core::protocols::Stream> {
        use pingora_core::protocols::http::v2::server;

        let digest = std::sync::Arc::new(pingora_core::protocols::Digest::default());
        let mut conn = match server::handshake(stream, Some(server::default_h2_options())).await {
            Ok(conn) => conn,
            Err(error) => {
                log::debug!("HTTP/2 handshake failed: {error}");
                return None;
            }
        };
        let mut malformed = 0usize;
        loop {
            let accepted = tokio::select! {
                biased;
                accepted = server::HttpSession::from_h2_conn(&mut conn, digest.clone()) => accepted,
                _ = shutdown_signal(shutdown) => return None,
            };
            match accepted {
                Ok(Some(server::H2Accept::Session(h2))) => {
                    self.serve_h2_stream(h2).await;
                }
                Ok(Some(server::H2Accept::Rejected)) => {
                    // The stream was answered or reset during acceptance; siblings continue.
                    malformed += 1;
                    if malformed >= 100 {
                        log::debug!("tearing down downstream h2 connection after {malformed} rejected streams");
                        return None;
                    }
                }
                Ok(None) => return None,
                Err(error) => {
                    log::debug!("HTTP/2 connection ended: {error}");
                    return None;
                }
            }
        }
    }

    /// Serve one HTTP/2 stream. Every stream is independent, so a failure only ends that
    /// stream (`ngx_http_v2_state_headers` → finalize request).
    ///
    /// `pingora_proxy::Session` has no public constructor taking an HTTP/2 stream, but its
    /// `downstream_session` field is public: a throwaway session is built from an empty
    /// stream and the real HTTP/2 flow replaces it. The placeholder is never read.
    async fn serve_h2_stream(
        self: &Arc<Self>,
        h2: pingora_core::protocols::http::v2::server::HttpSession,
    ) {
        // A real loopback socket is used as the throwaway placeholder: pingora's `IO` has no
        // in-memory implementation and the stream is never read after the swap.
        let placeholder: pingora_core::protocols::Stream = placeholder_stream()
            .await
            .expect("loopback placeholder stream");
        let mut session = pingora_proxy::Session::new_h1(placeholder);
        // The field is already a `Box<HttpSession>`; `into()` avoids a redundant allocation.
        session.downstream_session =
            pingora_core::protocols::http::ServerSession::new_http2(h2).into();
        let mut ctx = self.app.new_request_context();
        let keep = match self.app.route_request(&mut session, &mut ctx).await {
            Ok(PhaseOutcome::Answered) => true,
            Ok(PhaseOutcome::Proxy) => self.app.proxy_request(&mut session, &mut ctx).await,
            Err(error) => {
                log::error!("request failed: {error}");
                false
            }
        };
        self.app.log_request(&mut session, &ctx, None).await;
        let _ = keep;
    }
}

/// A throwaway connected loopback socket, used only as the placeholder downstream stream
/// of a `pingora_proxy::Session` whose real flow is swapped in afterwards.
async fn placeholder_stream() -> Option<pingora_core::protocols::Stream> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.ok()?;
    let address = listener.local_addr().ok()?;
    let (client, _accepted) = tokio::join!(
        tokio::net::TcpStream::connect(address),
        listener.accept()
    );
    let client: tokio::net::TcpStream = client.ok()?;
    let stream: pingora_core::protocols::Stream =
        Box::new(pingora_core::protocols::l4::stream::Stream::from(client));
    Some(stream)
}

/// Resolve when the service starts shutting down.
async fn shutdown_signal(shutdown: &ShutdownWatch) -> bool {
    loop {
        if *shutdown.borrow() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[async_trait]
impl ProxyHttp for HttpCoreApp {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            listen: self.listen.clone(),
            request: RequestHeader::build("GET", b"/", Some(0))
                .expect("placeholder request is valid"),
            selected: None,
            proxying: None,
            backend: None,
            client: crate::core::http::ClientState::default(),
            connections: None,
            host: String::new(),
            server_name: String::new(),
            started: std::time::Instant::now(),
            ssl: None,
            ssl_server: None,
            upstream_status: None,
            cache_status: CacheStatusCell::default(),
            cache_bypassed: std::sync::atomic::AtomicBool::new(false),
            cache_state_source: None,
            error_page_served: false,
            error_page_status: None,
            intercepted: None,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        match self.route_request(session, ctx).await? {
            PhaseOutcome::Answered => Ok(true),
            PhaseOutcome::Proxy => Ok(false),
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let current = self.engine.load();
        let engine = &*current;
        let selected = ctx
            .proxying
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no proxy location"))?;
        let compiled = engine
            .location(selected)
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "location disappeared"))?;
        let conf = compiled
            .conf
            .get::<ProxyConf>()
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no proxy configuration"))?;
        let pass = conf
            .pass
            .as_ref()
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "no proxy_pass"))?;
        let upstream = engine
            .upstream_for(compiled)
            .ok_or_else(|| Error::explain(ErrorType::HTTPStatus(502), "unknown upstream"))?;
        let key = ctx.client.addr.map(|ip| ip.to_string()).unwrap_or_default();
        let backend = upstream
            .select(key.as_bytes())
            .ok_or_else(|| Error::explain(ErrorType::HTTPStatus(502), "no healthy backend"))?;
        let sni = parse_sni(&pass.host_header);
        let mut peer = HttpPeer::new(backend.address().to_string(), pass.tls, sni);
        peer.options.connection_timeout = conf.connect_timeout;
        peer.options.total_connection_timeout = conf.connect_timeout;
        peer.options.read_timeout = conf.read_timeout;
        peer.options.write_timeout = conf.send_timeout;
        ctx.backend = Some(backend);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let current = self.engine.load();
        let engine = &*current;
        let Some(selected) = ctx.proxying else {
            return Ok(());
        };
        let Some(compiled) = engine.location(selected) else {
            return Ok(());
        };
        let Some(conf) = compiled.conf.get::<ProxyConf>() else {
            return Ok(());
        };
        let Some(pass) = &conf.pass else {
            return Ok(());
        };
        let path = proxy::proxy_uri(pass, compiled.matcher.matched_prefix(), request.uri.path());
        let target = match request.uri.query() {
            Some(query) if !query.is_empty() => format!("{path}?{query}"),
            _ => path,
        };
        request.set_uri(target.parse::<Uri>().map_err(engine_error)?);
        request.insert_header("Host", pass.host_header.clone())?;
        request.insert_header("X-Real-IP", self.real_addr(ctx))?;
        let view = self.view(ctx);
        proxy::apply_upstream_headers(conf, &view_as_state(&view, engine.providers), request)
            .map_err(engine_error)?;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let current = self.engine.load();
        let engine = &*current;
        response.insert_header("Server", SERVER_NAME)?;
        let Some(selected) = ctx.proxying.or(ctx.selected) else {
            return Ok(());
        };
        let Some(compiled) = engine.location(selected) else {
            return Ok(());
        };
        if let Some(conf) = compiled.conf.get::<ProxyConf>() {
            proxy::apply_response_headers(conf, response);
        }
        let view = self.view(ctx);
        if let Some(conf) = compiled.conf.get::<HeadersConf>() {
            conf.apply(response, &view).map_err(engine_error)?;
        }
        if let Some(hook) = compiled
            .conf
            .get::<LuaConf>()
            .and_then(|conf| conf.header_filter.as_ref())
        {
            let headers: Vec<(String, String)> = response
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.to_string(), value.to_str().ok()?.to_string()))
                })
                .collect();
            let state = view_as_state(&view, engine.providers);
            let outcome =
                lua::execute_header_filter(hook, response.status.as_u16(), &headers, &state)
                    .map_err(engine_error)?;
            if let Some(status) = outcome.status {
                response.set_status(StatusCode::from_u16(status).map_err(engine_error)?)?;
            }
            for (name, value) in outcome.headers {
                response.insert_header(name, value)?;
            }
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
        let current = self.engine.load();
        let engine = &*current;
        let status = session
            .response_written()
            .map_or(0, |response| response.status.as_u16());
        let view = self.view(ctx);
        let mut state = view_as_state(&view, engine.providers);
        state.body_bytes_sent = session.body_bytes_sent();
        state.status = session.response_written().map(|response| response.status);
        let message = error.map(|error| error.to_string());
        {
            use crate::modules::stub_status::ServerStats;
            ServerStats::add(
                &engine.stats.body_bytes_sent,
                session.body_bytes_sent() as u64,
            );
            ServerStats::dec(&engine.stats.active);
        }
        engine.access_log.log(
            engine.access_writer.as_deref(),
            &state,
            status,
            message.as_deref(),
        );
        // Release the least-connections slot before the context is dropped.
        ctx.backend = None;
    }
}

impl HttpCoreApp {
    fn view(&self, ctx: &RequestContext) -> RequestStateView {
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

    fn real_addr(&self, ctx: &RequestContext) -> String {
        ctx.client
            .addr
            .map(|address| address.to_string())
            .unwrap_or_else(|| "-".to_string())
    }

    /// `NGX_HTTP_CONTENT_PHASE`.
    async fn content_phase(
        &self,
        session: &mut Session,
        state: &mut RequestState,
        ctx: &mut RequestContext,
        selected: Selected,
    ) -> Result<PhaseOutcome> {
        let current = self.engine.load();
        let engine = &*current;
        let Some(compiled) = engine.location(selected) else {
            return self.respond(
                state,
                session,
                ctx,
                StatusCode::NOT_FOUND,
                "404 Not Found\n",
                &[],
            )
            .await;
        };
        // `stub_status` and `prometheus_metrics` answer directly from the counters.
        if let Some(format) = compiled
            .conf
            .get::<crate::modules::stub_status::StatusConf>()
            .and_then(|conf| conf.format())
        {
            let snapshot = crate::modules::stub_status::StatsSnapshot::from_stats(&engine.stats);
            let (body, content_type) = match format {
                crate::modules::stub_status::StatusFormat::Stub => (
                    crate::modules::stub_status::render_stub(&snapshot),
                    "text/plain",
                ),
                crate::modules::stub_status::StatusFormat::Prometheus => (
                    crate::modules::stub_status::render_prometheus(&snapshot),
                    "text/plain; version=0.0.4",
                ),
            };
            let mut response = ResponseHeader::build(StatusCode::OK, None).map_err(engine_error)?;
            response
                .insert_header("Content-Type", content_type)
                .map_err(engine_error)?;
            response
                .insert_header("Cache-Control", "no-cache")
                .map_err(engine_error)?;
            response
                .insert_header("Content-Length", body.len().to_string())
                .map_err(engine_error)?;
            let is_head = session.req_header().method == http::Method::HEAD;
            session
                .write_response_header(Box::new(response), is_head || body.is_empty())
                .await?;
            if !is_head && !body.is_empty() {
                session
                    .write_response_body(Some(bytes::Bytes::from(body)), true)
                    .await?;
            }
            return Ok(PhaseOutcome::Answered);
        }

        if let Some(hook) = compiled
            .conf
            .get::<LuaConf>()
            .and_then(|conf| conf.content.as_ref())
        {
            let outcome = lua::execute(hook, state).map_err(engine_error)?;
            let status =
                StatusCode::from_u16(outcome.status.unwrap_or(200)).map_err(engine_error)?;
            return self.respond(
                state,
                session,
                ctx,
                status,
                &outcome.body,
                &outcome.headers,
            )
            .await;
        }


        if engine.upstream_for(compiled).is_some() {
            ctx.proxying = Some(selected);
            return Ok(PhaseOutcome::Proxy);
        }
        if compiled
            .conf
            .get::<StaticConf>()
            .is_some_and(|conf| conf.root.is_some())
        {
            let mut module_ctx = crate::modules::ctx::ModuleCtx::new(
                session,
                state,
                &compiled.conf,
                &ctx.server_name,
            );
            if static_files::handle(&mut module_ctx).await? {
                return Ok(PhaseOutcome::Answered);
            }
        }
        self.respond(
            state,
            session,
            ctx,
            StatusCode::NOT_FOUND,
            "404 Not Found\n",
            &[],
        )
        .await
    }


    /// Write a locally generated response after running the header filter chain.
    async fn answer(
        &self,
        session: &mut Session,
        state: &mut RequestState,
        ctx: &mut RequestContext,
        status: StatusCode,
        body: &str,
        headers: &[(String, String)],
    ) -> bool {
        let current = self.engine.load();
        let engine = &*current;
        let mut writer = ResponseWriter::new(status);
        if !headers.is_empty() {
            writer
                .set_header("Content-Type", "text/plain; charset=utf-8".to_string())
                .ok();
        }
        for (name, value) in headers {
            writer.set_header(name, value.clone()).ok();
        }
        writer.write(body.as_bytes());
        if let Some(selected) = ctx.selected
            && let Some(compiled) = engine.location(selected)
        {
            let view = self.view(ctx);
            let mut response = ResponseHeader::build(writer.status, None).expect("valid status");
            for (name, value) in &writer.headers {
                response.insert_header(name.clone(), value.clone()).ok();
            }
            // Response header chain: `add_header`, then the Lua header filter, exactly
            // as for proxied and static responses.
            if let Some(conf) = compiled.conf.get::<HeadersConf>() {
                conf.apply(&mut response, &view).ok();
            }
            if let Some(hook) = compiled
                .conf
                .get::<LuaConf>()
                .and_then(|conf| conf.header_filter.as_ref())
            {
                let existing: Vec<(String, String)> = response
                    .headers
                    .iter()
                    .filter_map(|(name, value)| {
                        Some((name.to_string(), value.to_str().ok()?.to_string()))
                    })
                    .collect();
                let state = view_as_state(&view, engine.providers);
                if let Ok(outcome) =
                    lua::execute_header_filter(hook, response.status.as_u16(), &existing, &state)
                {
                    if let Some(status) = outcome.status
                        && let Ok(status) = StatusCode::from_u16(status)
                    {
                        response.set_status(status).ok();
                    }
                    for (name, value) in outcome.headers {
                        response.insert_header(name, value).ok();
                    }
                }
            }
            writer.status = response.status;
            writer.headers = response.headers.clone();
        }
        state.status = Some(status);
        writer.flush(session).await.is_ok()
    }
}

fn connection_state(session: &Session, listen: &str) -> ConnectionState {
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

fn view_as_state(
    view: &RequestStateView,
    providers: &'static [(
        &'static str,
        &'static dyn crate::core::variables::VariableProvider,
    )],
) -> RequestState {
    view.clone().into_state(providers)
}

fn parse_sni(host_header: &str) -> String {
    url::Url::parse(&format!("http://{host_header}"))
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| host_header.to_string())
}

fn engine_error(error: impl std::fmt::Display) -> Box<Error> {
    Error::explain(ErrorType::InternalError, error.to_string())
}