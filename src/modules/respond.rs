//! Response helpers shared by modules that answer a request themselves.

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, StatusCode};
use pingora_core::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

/// Write a plain-text response (`HEAD` requests get the headers only).
pub async fn text(
    session: &mut Session,
    status: StatusCode,
    body: &str,
    headers: &[(String, String)],
) -> Result<()> {
    let head = session.req_header().method == Method::HEAD;
    let mut response = ResponseHeader::build(status, None)?;
    response.insert_header(CONTENT_TYPE.as_str(), "text/plain; charset=utf-8")?;
    response.insert_header(CONTENT_LENGTH.as_str(), body.len().to_string())?;
    for (name, value) in headers {
        response.insert_header(name.clone(), value.clone())?;
    }
    session
        .write_response_header(Box::new(response), head || body.is_empty())
        .await?;
    if !head && !body.is_empty() {
        session
            .write_response_body(Some(Bytes::copy_from_slice(body.as_bytes())), true)
            .await?;
    }
    Ok(())
}

/// Write a `return`-style response, redirecting when the status implies a URL.
pub async fn redirect(session: &mut Session, status: StatusCode, location: &str) -> Result<()> {
    text(
        session,
        status,
        "",
        &[("Location".to_string(), location.to_string())],
    )
    .await
}
