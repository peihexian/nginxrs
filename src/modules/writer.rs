//! Buffered response writer used by modules that generate a response locally.
//!
//! A module builds a [`ResponseWriter`], and the core flushes it after the header filter
//! chain ran (Nginx's `ngx_http_send_header` + `ngx_http_output_filter`). Streaming
//! content such as static files can still write directly to the session.

use http::{HeaderMap, Method, StatusCode};
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

#[derive(Default)]
pub struct ResponseWriter {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub headers_committed: bool,
    pub finished: bool,
}

impl ResponseWriter {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }

    pub fn set_header(&mut self, name: &str, value: String) -> anyhow::Result<()> {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| anyhow::anyhow!("invalid header name {name}: {error}"))?;
        let value = http::header::HeaderValue::from_str(&value)
            .map_err(|error| anyhow::anyhow!("invalid header value: {error}"))?;
        self.headers.insert(name, value);
        Ok(())
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.body.extend_from_slice(bytes);
    }

    /// Send the buffered response downstream.
    pub async fn flush(self, session: &mut Session) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        let head = session.req_header().method == Method::HEAD;
        let mut response = ResponseHeader::build(self.status, None)?;
        for (name, value) in &self.headers {
            response.insert_header(name.clone(), value.clone())?;
        }
        if !self.headers.contains_key(http::header::CONTENT_TYPE) && !self.body.is_empty() {
            response.insert_header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")?;
        }
        response.insert_header(http::header::CONTENT_LENGTH, self.body.len().to_string())?;
        session
            .write_response_header(Box::new(response), head || self.body.is_empty())
            .await?;
        if !head && !self.body.is_empty() {
            session
                .write_response_body(Some(bytes::Bytes::from(self.body)), true)
                .await?;
        }
        Ok(())
    }
}
