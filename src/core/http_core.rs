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
use async_trait::async_trait;
use http::{StatusCode, Uri};
use pingora_core::server::ShutdownWatch;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
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
        let _ = self.answer(session, state, ctx, status, body, headers).await;
        Ok(PhaseOutcome::Answered)
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

    /// HTTP server options handed to Pingora's proxy layer.
    fn server_options(&self) -> Arc<pingora_core::server::configuration::ServerConf> {
        self.engine.load().server_conf.clone()
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

#[allow(dead_code)]
fn _unused(_: IpAddr) {}
