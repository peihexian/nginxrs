//! Downstream transport: TLS termination followed by the HTTP session loops.
//!
//! Pingora's `HttpProxy` is itself the `ServerApp`, so it starts parsing HTTP as soon as a
//! connection is accepted. A `listen ... ssl` listener must complete the TLS handshake
//! first (SNI selects the `server {}` and produces the `$ssl_*` facts), so [`Bridge`]
//! terminates the connection and then runs the same session loop, exactly where Nginx runs
//! `c->ssl->handler`.

use super::types::*;
use super::TLS_HANDSHAKE_TIMEOUT;
use async_trait::async_trait;
use pingora_core::server::ShutdownWatch;
use std::sync::Arc;

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
    /// stream (`ngx_http_v2_state_headers` 閳?finalize request).
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

