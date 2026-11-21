//! Pingora's `ProxyHttp` integration.
//!
//! These handlers exist so `HttpCoreApp` can also be driven by Pingora's own acceptor
//! when that loop is used; the primary path is [`super::bridge::Bridge`], which calls
//! `route_request`/`proxy_request` directly.

use super::types::*;
use super::view_as_state;
use super::{engine_error, parse_sni};
use crate::modules::headers::HeadersConf;
use crate::modules::lua::{self, LuaConf};
use crate::modules::proxy::{self, ProxyConf};
use crate::SERVER_NAME;
use async_trait::async_trait;
use http::StatusCode;
use http::Uri;
use pingora_core::Error;
use pingora_core::ErrorType;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use std::result::Result as StdResult;

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
            grpc: false,
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

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> StdResult<bool, Box<Error>> {
        match self.route_request(session, ctx).await? {
            PhaseOutcome::Answered => Ok(true),
            PhaseOutcome::Proxy => Ok(false),
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> StdResult<Box<HttpPeer>, Box<Error>> {
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
    ) -> StdResult<(), Box<Error>> {
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
    ) -> StdResult<(), Box<Error>> {
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
