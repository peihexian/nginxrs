//! `proxy_pass`: the upstream exchange (`ngx_http_proxy_handler`).
//!
//! One `proxy_request` corresponds to Nginx's `ngx_http_proxy_handler`:
//! `ngx_http_upstream_init_request` picks the peer, `ngx_http_proxy_create_request` builds
//! the upstream request, and `ngx_http_upstream_next` retries on the next peer according to
//! `proxy_next_upstream`.

use super::cache::*;
use super::types::*;
use super::{parse_sni, view_as_state};
use crate::SERVER_NAME;
use crate::modules::headers::HeadersConf;
use crate::modules::proxy::{self, ProxyConf};
use http::{StatusCode, Uri};
use pingora_core::ErrorType;
use pingora_core::connectors::TransportConnector;
use pingora_core::upstreams::peer::{HttpPeer, PeerOptions};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

#[derive(Clone, Copy)]
pub struct RetryBudget {
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

impl HttpCoreApp {
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

