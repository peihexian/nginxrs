//! The phase engine (`ngx_http_core_run_phases`).
//!
//! `route_request` walks `POST_READ` -> `FIND_CONFIG` -> `REWRITE` -> `PREACCESS` ->
//! `ACCESS` -> `CONTENT`, letting each module's handler decide whether to defer or
//! answer. Modules never see this order; they only implement their phase hook.

use super::types::*;
use super::{connection_state, engine_error};
use crate::core::http::{RequestLine, RequestState};
use crate::modules::lua::{self, LuaConf};
use crate::modules::rewrite;
use crate::modules::rewrite::RewriteConf;
use crate::modules::uri;
use http::StatusCode;
use pingora_core::Result;
use pingora_proxy::Session;

/// What the phase engine must do after a rewrite action (`ngx_http_script` outcomes).
enum RewriteStep {
    /// `rewrite … last`: re-run configuration lookup from the top of the loop.
    Restart,
    /// The request is finished (`return`, redirect) or handed to a content phase.
    Answered(PhaseOutcome),
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
                // `if`/`set`/`break` actions are compiled into the same script as the plain
                // rewrite rules; nginx runs them in declaration order, so run them first.
                let mut module_ctx = crate::modules::ctx::ModuleCtx::new(
                    session,
                    &mut state,
                    &compiled.conf,
                    &ctx.server_name,
                );
                if let Some(outcome) = rewrite::apply_actions(&mut module_ctx, &conf) {
                    match self
                        .apply_rewrite_outcome(session, &mut state, ctx, outcome)
                        .await?
                    {
                        RewriteStep::Restart => continue,
                        RewriteStep::Answered(outcome) => return Ok(outcome),
                    }
                }
                let mut module_ctx = crate::modules::ctx::ModuleCtx::new(
                    session,
                    &mut state,
                    &compiled.conf,
                    &ctx.server_name,
                );
                if let Some(outcome) =
                    rewrite::apply_rewrites(&mut module_ctx, &conf).map_err(engine_error)?
                {
                    match self
                        .apply_rewrite_outcome(session, &mut state, ctx, outcome)
                        .await?
                    {
                        RewriteStep::Restart => continue,
                        RewriteStep::Answered(outcome) => return Ok(outcome),
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

            // `NGX_HTTP_ACCESS_PHASE`: `ngx_http_auth_basic_handler` runs before the Lua
            // hook, exactly like the handler order in the C module's access phase.
            if let Some(conf) = compiled
                .conf
                .get::<crate::modules::auth_basic::AuthBasicConf>()
                .filter(|conf| conf.enabled())
                .cloned()
            {
                let realm = conf.realm(&state).unwrap_or_default();
                match crate::modules::auth_basic::handle(&conf, &state).await {
                    crate::modules::auth_basic::AuthOutcome::Skip => {}
                    crate::modules::auth_basic::AuthOutcome::Allowed => {}
                    crate::modules::auth_basic::AuthOutcome::Rejected(failure) => {
                        let status = StatusCode::from_u16(failure.status()).map_err(engine_error)?;
                        let headers = if status == StatusCode::UNAUTHORIZED {
                            vec![(
                                "WWW-Authenticate".to_string(),
                                crate::modules::auth_basic::challenge(&realm),
                            )]
                        } else {
                            Vec::new()
                        };
                        let body = format!(
                            "{}\n",
                            status.canonical_reason().unwrap_or("Denied")
                        );
                        return self
                            .respond(&mut state, session, ctx, status, &body, &headers)
                            .await;
                    }
                }
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


impl HttpCoreApp {
    /// Apply one rewrite outcome: emit the response or pick the next location.
    async fn apply_rewrite_outcome(
        &self,
        session: &mut Session,
        state: &mut RequestState,
        ctx: &mut RequestContext,
        outcome: rewrite::RewriteOutcome,
    ) -> Result<RewriteStep> {
        match outcome {
            rewrite::RewriteOutcome::Redirect { status, target } => {
                let status = StatusCode::from_u16(status).map_err(engine_error)?;
                let headers = vec![("Location".to_string(), target)];
                self.respond(state, session, ctx, status, "", &headers)
                    .await
                    .map(RewriteStep::Answered)
            }
            rewrite::RewriteOutcome::Return(evaluated) => {
                let status = StatusCode::from_u16(evaluated.status).map_err(engine_error)?;
                let headers = evaluated
                    .target
                    .clone()
                    .filter(|_| status.is_redirection())
                    .map(|target| vec![("Location".to_string(), target)])
                    .unwrap_or_default();
                let body = if status.is_redirection() {
                    String::new()
                } else {
                    evaluated.target.unwrap_or_default()
                };
                self.respond(state, session, ctx, status, &body, &headers)
                    .await
                    .map(RewriteStep::Answered)
            }
            rewrite::RewriteOutcome::Internal { target, restart } => {
                let (path, args) = uri::split_target(&target);
                state.request.path = path;
                if let Some(args) = args {
                    state.request.args = args;
                }
                if restart {
                    return Ok(RewriteStep::Restart);
                }
                let Some(server) = ctx.selected.map(|selected| selected.server) else {
                    return self
                        .respond(state, session, ctx, StatusCode::NOT_FOUND, "404 Not Found\n", &[])
                        .await
                        .map(RewriteStep::Answered);
                };
                let current = self.engine.load();
                let Some(location) = current.select_location(server, &state.request.path) else {
                    return self
                        .respond(state, session, ctx, StatusCode::NOT_FOUND, "404 Not Found\n", &[])
                        .await
                        .map(RewriteStep::Answered);
                };
                self.content_phase(session, state, ctx, Selected { server, location })
                    .await
                    .map(RewriteStep::Answered)
            }
        }
    }
}
