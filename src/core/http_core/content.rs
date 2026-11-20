//! `CONTENT` phase handlers.
//!
//! Nginx lets a location name one content handler; this engine tries them in the order the
//! corresponding modules register: `stub_status`/`prometheus`, `content_by_lua`, the proxy
//! pipeline (`proxy_pass`), static files, and finally the core's own 404.

use super::types::*;
use super::{engine_error, view_as_state};
use pingora_core::Error;
use pingora_http::RequestHeader;
use arc_swap::ArcSwap;
use std::sync::Arc;
use crate::core::http::RequestState;
use crate::modules::lua::{self, LuaConf};
use crate::modules::static_files::{self, StaticConf};
use http::StatusCode;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

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

}

impl HttpCoreApp {
    /// `NGX_HTTP_CONTENT_PHASE`.
    pub(crate) async fn content_phase(
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
}
