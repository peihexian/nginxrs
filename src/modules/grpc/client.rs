//! The HTTP/2 client transport.
//!
//! nginx writes the frame sequence of `ngx_http_grpc_connection_start` by hand:
//!
//! ```text
//! PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
//! SETTINGS [HEADER_TABLE_SIZE=0, ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=0x7fffffff]
//! WINDOW_UPDATE [stream 0, 0x7fff0000]
//! ```
//!
//! Here the `h2` crate speaks the protocol: it sends the preface, negotiates settings, does
//! HPACK, and handles flow control, PING and GOAWAY. The settings above map onto
//! `initial_window_size`/`initial_connection_window_size`.

use crate::modules::grpc::conf::GrpcConf;
use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use h2::client::SendRequest;
use http::{HeaderMap, Method, Request, Response, Uri};
use std::time::Duration;

/// One established HTTP/2 connection to a gRPC peer.
pub struct Connection {
    send: SendRequest<Bytes>,
    /// The connection driver owns the socket; dropping this handle tears it down.
    driver: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("grpc::client::Connection")
    }
}

/// A stream opened for one request.
#[derive(Debug)]
pub struct Stream {
    pub sender: h2::SendStream<Bytes>,
    pub response: h2::RecvStream,
    pub head: Response<()>,
}

/// One gRPC call (`ngx_http_grpc_create_request`).
#[derive(Debug)]
pub struct Call {
    pub method: Method,
    /// `:scheme` — `http` for `grpc://`, `https` for `grpcs://`.
    pub scheme: &'static str,
    /// `:path` — the request URI, query included.
    pub path: String,
    /// `:authority` — the `Host`/`:authority` value.
    pub authority: String,
    /// Regular HTTP/2 fields (`te: trailers` included).
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// Connect to `peer` and perform the HTTP/2 handshake.
///
/// `grpcs://` wraps the socket in TLS first; `grpc://` uses "prior knowledge" cleartext
/// HTTP/2, exactly like nginx's preface bytes on a plain socket.
pub async fn connect(
    peer: &pingora_core::upstreams::peer::HttpPeer,
    conf: &GrpcConf,
) -> Result<Connection> {
    use pingora_core::connectors::TransportConnector;
    let connector = TransportConnector::new(None);
    let stream = connector
        .new_stream(peer)
        .await
        .context("cannot connect to the gRPC upstream")?;
    if peer.is_tls() {
        let tls = crate::modules::proxy_tls::client(peer, &proxy_conf(conf))?;
        let stream = crate::modules::proxy_tls::connect(
            &Arc::new(tls),
            stream,
            peer,
        )
        .await
        .context("TLS handshake with the gRPC upstream failed")?;
        handshake(stream).await
    } else {
        handshake(stream).await
    }
}

/// Map the `grpc_ssl_*` settings onto the shared upstream TLS configuration
/// (`ngx_http_grpc_module` uses the same `ngx_ssl_create_connection` fields).
pub fn proxy_conf(conf: &GrpcConf) -> crate::modules::proxy::ProxyConf {
    crate::modules::proxy::ProxyConf {
        ssl_protocols: conf.ssl_protocols,
        ssl_ciphers: conf.ssl_ciphers.join(":"),
        ssl_server_name: conf.ssl_server_name,
        ssl_name: conf.ssl_name.clone(),
        ssl_verify: conf.ssl_verify,
        ssl_verify_depth: conf.ssl_verify_depth,
        ssl_trusted_certificate: conf.ssl_trusted_certificate.clone(),
        ssl_crl: conf.ssl_crl.clone(),
        ssl_certificate: conf.ssl_certificate.first().cloned(),
        ssl_certificate_key: conf.ssl_certificate_key.first().cloned(),
        ..crate::modules::proxy::ProxyConf::default()
    }
}

use std::sync::Arc;

async fn handshake<S>(stream: S) -> Result<Connection>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (send, connection) = h2::client::Builder::new()
        // `SETTINGS_INITIAL_WINDOW_SIZE: 0x7fffffff` and the connection `WINDOW_UPDATE` of
        // `ngx_http_grpc_connection_start`.
        .initial_window_size(0x7fff_ffff)
        .initial_connection_window_size(0x7fff_0000)
        .handshake(tokio::io::BufReader::new(stream))
        .await
        .context("HTTP/2 handshake with the gRPC upstream failed")?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(Connection {
        send,
        driver: Some(driver),
    })
}

impl Connection {
    /// Open a stream and send the request (`ngx_http_grpc_send_request`).
    pub async fn call(&mut self, call: Call, timeout: Option<Duration>) -> Result<Stream> {
        let uri: Uri = format!("{}://{}{}", call.scheme, call.authority, call.path)
            .parse()
            .with_context(|| format!("invalid gRPC request URI \"{}\"", call.path))?;
        let mut request = Request::builder()
            .method(call.method.clone())
            .uri(uri)
            .body(())
            .context("cannot build the gRPC request")?;
        *request.headers_mut() = call.headers;
        // `end_of_stream` is true when there is no body to follow; otherwise the DATA frame
        // goes out right after the HEADERS frame (`ngx_http_grpc_send_frame`).
        let (response, mut sender) = match self.send.send_request(request, call.body.is_empty()) {
            Ok(pair) => pair,
            Err(error) => bail!("gRPC request failed: {error}"),
        };
        if !call.body.is_empty() {
            sender
                .send_data(Bytes::from(call.body), true)
                .context("cannot send the gRPC request body")?;
        }
        let response = tokio::time::timeout(timeout.unwrap_or(Duration::from_secs(60)), response)
            .await
            .map_err(|_| anyhow::anyhow!("grpc_read_timeout exceeded before the response headers"))?
            .context("cannot read the gRPC response headers")?;
        let (head, body) = response.into_parts();
        Ok(Stream {
            sender,
            response: body,
            head: Response::from_parts(head, ()),
        })
    }
}

/// Read the whole body and the trailers (`ngx_http_grpc_process_body`).
pub async fn read_body(stream: &mut Stream) -> Result<(Vec<u8>, HeaderMap)> {
    let mut body = Vec::new();
    loop {
        match stream.response.data().await {
            Some(Ok(chunk)) => {
                // `ngx_http_v2_state_headers` releases the window as data is consumed.
                let _ = stream.response.flow_control().release_capacity(chunk.len());
                body.extend_from_slice(&chunk);
            }
            Some(Err(error)) => return Err(anyhow::anyhow!("cannot read the gRPC body: {error}")),
            None => break,
        }
    }
    // `grpc-status`/`grpc-message` arrive in the trailers (`ngx_http_grpc_filter`).
    let trailers = match stream.response.trailers().await {
        Ok(trailers) => trailers,
        Err(_) => None,
    };
    let mut headers = HeaderMap::new();
    if let Some(trailers) = trailers {
        for (name, value) in trailers.iter() {
            headers.append(name.clone(), value.clone());
        }
    }
    Ok((body, headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_uris_are_built_from_scheme_and_authority() {
        let uri: Uri = format!("{}://{}{}", "http", "127.0.0.1:50051", "/pkg.Svc/Method?x=1")
            .parse()
            .unwrap();
        assert_eq!(uri.scheme_str(), Some("http"));
        assert_eq!(uri.authority().unwrap().as_str(), "127.0.0.1:50051");
        assert_eq!(uri.path(), "/pkg.Svc/Method");
        assert_eq!(uri.query(), Some("x=1"));
    }
}
