//! `ngx_http_grpc_handler`: the `grpc_pass` content handler.
//!
//! The request becomes one HTTP/2 call: the body is read (gRPC frames are small and
//! `proxy_request_buffering`-like by default), the head is built by
//! [`request::build`], the stream is relayed as it arrives, and the trailers carry the final
//! `grpc-status`. Retries follow `grpc_next_upstream` exactly like `proxy_pass`: a connection
//! error or one of the listed statuses releases the peer and the next one is tried.

use crate::core::http_core::{HttpCoreApp, RequestContext, engine_error, view_as_state};
use crate::modules::grpc::{client, conf::GrpcConf, request, response};
use crate::modules::proxy::{self, UpstreamFailures};
use http::StatusCode;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::Session;
use std::time::Instant;

impl HttpCoreApp {
    /// `ngx_http_grpc_handler`.
    pub(crate) async fn grpc_pass(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> anyhow::Result<bool> {
        let current = self.engine.load();
        let engine = &*current;
        let selected = ctx
            .proxying
            .ok_or_else(|| anyhow::anyhow!("no grpc_pass location"))?;
        let compiled = engine
            .location(selected)
            .ok_or_else(|| anyhow::anyhow!("location disappeared"))?;
        let conf = compiled
            .conf
            .get::<GrpcConf>()
            .ok_or_else(|| anyhow::anyhow!("no gRPC configuration"))?;
        let pass = conf
            .pass
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no grpc_pass"))?;
        let upstream = engine
            .upstream_for(compiled)
            .ok_or_else(|| anyhow::anyhow!("unknown upstream"))?;
        let key = ctx.client.addr.map(|ip| ip.to_string()).unwrap_or_default();

        // Read the client body first: nginx buffers the gRPC request (`r->request_body`)
        // before the upstream connection so a retry can resend it.
        let mut body = Vec::new();
        while let Some(chunk) = session.read_request_body().await? {
            body.extend_from_slice(&chunk);
        }
        let view = self.view(ctx);
        let state = view_as_state(&view, engine.providers);
        let scheme = if pass.tls { "https" } else { "http" };
        let call = request::build(conf, &state, &body, scheme);

        let mut tries = upstream.peer_count_hint().max(1);
        if let Some(limit) = conf.next_upstream_tries
            && limit > 0
        {
            tries = tries.min(limit);
        }
        let started = Instant::now();
        let mut tried: Vec<String> = Vec::new();

        loop {
            let backend = upstream
                .select_avoiding(key.as_bytes(), &tried)
                .ok_or_else(|| anyhow::anyhow!("no live upstreams"))?;
            let address = backend.address().to_string();
            tried.push(address.clone());
            ctx.backend = Some(backend);

            let sni = crate::core::http_core::parse_sni(&pass.authority);
            let mut options = pingora_core::upstreams::peer::PeerOptions::new();
            options.connection_timeout = conf.connect_timeout;
            options.total_connection_timeout = conf.connect_timeout;
            options.read_timeout = conf.read_timeout;
            options.write_timeout = conf.send_timeout;
            let mut peer = HttpPeer::new(address, pass.tls, sni);
            peer.options = options;

            match self
                .grpc_attempt(session, ctx, conf, &peer, clone_call(&call))
                .await
            {
                Ok(()) => return Ok(false),
                Err(failure) => {
                    tries = tries.saturating_sub(1);
                    log::warn!(
                        "gRPC upstream failure ({:#x}) on {}: {}",
                        failure.class.0,
                        peer.sni,
                        failure.source
                    );
                    let retryable = tries > 0
                        && conf.next_upstream.contains(failure.class.0)
                        && !conf.next_upstream.contains(UpstreamFailures::OFF)
                        && conf
                            .next_upstream_timeout
                            .map(|limit| started.elapsed() < limit)
                            .unwrap_or(true);
                    if !retryable {
                        ctx.upstream_status = failure.status;
                        return Err(failure.source);
                    }
                }
            }
        }
    }

    /// One upstream attempt: connect, call, relay (`ngx_http_upstream_connect` through
    /// `ngx_http_upstream_process_body`).
    async fn grpc_attempt(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        conf: &GrpcConf,
        peer: &HttpPeer,
        call: client::Call,
    ) -> std::result::Result<(), GrpcFailure> {
        let mut connection = client::connect(peer, conf)
            .await
            .map_err(grpc_engine_error)?;
        // The `grpc_read_timeout` bounds the header exchange; the body follows the same
        // deadline per chunk.
        let mut stream = connection
            .call(call, conf.read_timeout)
            .await
            .map_err(|source| {
                let class = if format!("{source}").contains("grpc_read_timeout") {
                    UpstreamFailures::TIMEOUT
                } else {
                    UpstreamFailures::ERROR
                };
                GrpcFailure::new(class, source)
            })?;
        // `ngx_http_grpc_process_header`: a non-200 `:status` is an upstream error.
        let status = stream.head.status();
        if !status.is_success() {
            return Err(GrpcFailure {
                class: UpstreamFailures(proxy::status_failure(status.as_u16()).unwrap_or(UpstreamFailures::ERROR)),
                source: anyhow::anyhow!("upstream status {}", status.as_u16()),
                status: Some(status),
            });
        }
        // `grpc-status` arrives in the trailers, which `h2` only yields after the last DATA
        // frame; the body is therefore collected first so the trailers can be folded into the
        // response headers (`ngx_http_grpc_filter` does the same before the body is relayed).
        let (body, trailers) = client::read_body(&mut stream)
            .await
            .map_err(grpc_engine_error)?;
        let mut response = response::to_response_header(conf, &stream.head, &trailers)
            .map_err(grpc_engine_error)?;
        if let Some(code) = response::status_code(&stream.head, &trailers) {
            log::debug!("gRPC call finished with grpc-status {code}");
            if code != 0 {
                // `ngx_http_grpc_filter`: a non-zero `grpc-status` is still a valid gRPC
                // response; the client reads it from the headers, so nothing changes here.
                ctx.upstream_status = Some(status);
            }
        }
        let is_head = session.req_header().method == http::Method::HEAD;
        let empty = is_head || body.is_empty();
        if !empty {
            response
                .insert_header("Content-Length", body.len().to_string())
                .ok();
        }
        session
            .write_response_header(Box::new(response), empty)
            .await
            .map_err(grpc_engine_error)?;
        if !empty {
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await
                .map_err(grpc_engine_error)?;
        }
        Ok(())
    }
}

/// Convert an engine error into one attempt's failure.
fn grpc_engine_error<E: std::fmt::Display>(source: E) -> GrpcFailure {
    GrpcFailure::new(UpstreamFailures::ERROR, anyhow::anyhow!("{source}"))
}

/// A retry resends the same request head and body (`ngx_http_grpc_create_request` runs once).
fn clone_call(call: &client::Call) -> client::Call {
    client::Call {
        method: call.method.clone(),
        scheme: call.scheme,
        path: call.path.clone(),
        authority: call.authority.clone(),
        headers: call.headers.clone(),
        body: call.body.clone(),
    }
}
/// One attempt's failure, with the `grpc_next_upstream` class.
struct GrpcFailure {
    class: UpstreamFailures,
    source: anyhow::Error,
    status: Option<StatusCode>,
}

impl GrpcFailure {
    fn new(class: u32, source: anyhow::Error) -> Self {
        Self {
            class: UpstreamFailures(class),
            source,
            status: None,
        }
    }
}

impl From<anyhow::Error> for GrpcFailure {
    fn from(source: anyhow::Error) -> Self {
        Self::new(UpstreamFailures::ERROR, source)
    }
}

/// Keep the engine helper used by the proxy path reachable from here as well.
#[allow(dead_code)]
fn assert_engine_error(error: impl std::fmt::Display) -> Box<pingora_core::Error> {
    engine_error(error)
}
