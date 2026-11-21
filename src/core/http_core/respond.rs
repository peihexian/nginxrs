//! Local responses: `error_page` dispatch and the header filter chain.
//!
//! `respond` is the single place where a locally generated response (from `return`, a
//! module, or an upstream error) becomes bytes; it is also where
//! `ngx_http_special_response_handler` applies `error_page`.

use super::types::*;
use super::view_as_state;
use crate::core::http::RequestState;
use crate::modules::headers::HeadersConf;
use crate::modules::lua::{self, LuaConf};
use crate::modules::writer::ResponseWriter;
use http::StatusCode;
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

impl HttpCoreApp {
    /// Produce a complete response for one request and report the phase outcome.
    pub(crate) async fn respond(
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
        // `ngx_http_header_filter`: the `Server` line is generated for every response unless
        // the location hides it (`server_tokens off`).
        writer
            .set_header("Server", self.server_header(ctx, engine))
            .ok();
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


