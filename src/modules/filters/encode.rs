//! The output chain around a completed response body: `gunzip`, then `gzip`.
//!
//! nginx chains the two filters on the body:
//!
//! ```text
//! ngx_http_gunzip_filter_module  →  ngx_http_gzip_filter_module  →  client
//! ```
//!
//! `gunzip` strips a `Content-Encoding: gzip` the client did not ask for, and `gzip`
//! re-compresses the (now plain) body for a client that does. Both run after `add_header`,
//! so the response is transformed once, with its final headers in place.
//!
//! This module owns that single step so the static, proxy and `return` paths agree.

use crate::core::http::{RequestState, RequestStateView};
use crate::modules::location::Location;
use pingora_http::ResponseHeader;

/// A response body as it leaves the content phase.
pub struct Body {
    pub bytes: Vec<u8>,
}

impl Body {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

/// Whether the location has an encoding filter (`gunzip` or `gzip`) turned on.
pub fn enabled(location: &Location) -> bool {
    location
        .get::<crate::modules::gzip::conf::GzipConf>()
        .is_some_and(|conf| conf.enabled)
        || location
            .get::<crate::modules::gunzip::GunzipConf>()
            .is_some_and(|conf| conf.enabled)
}

/// Apply `gunzip` and `gzip` to a finished response.
///
/// Returns `true` when the body changed, so the caller can skip a rewrite it would repeat.
/// `header_only` (a `HEAD` request) still lets both filters decide, but the body is not
/// transformed: the header filters of nginx run for `HEAD` too, while the body filters are
/// skipped by `r->header_only`.
pub fn apply(
    response: &mut ResponseHeader,
    body: &mut Body,
    view: &RequestStateView,
    location: &Location,
    state: &RequestState,
    header_only: bool,
) -> anyhow::Result<bool> {
    // A `HEAD` request still carries the header decisions (`r->header_only` only stops the
    // body filters), so the length the gzip filter sees is the declared one.
    let declared = response
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if header_only {
        if let Some(length) = declared {
            body.bytes.reserve(0);
            let _ = length;
        }
    }
    let mut changed = crate::modules::gunzip::filter::decompress(
        response,
        body,
        view,
        location,
        state,
        header_only,
    )?;
    changed |= crate::modules::gzip::filter::compress_response(
        response,
        body,
        view,
        location,
        state,
        header_only,
    )?;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    #[test]
    fn body_wrapper_reports_length() {
        let body = super::Body::new(b"abc".to_vec());
        assert_eq!(body.len(), 3);
        assert!(!body.is_empty());
        assert!(super::Body::new(Vec::new()).is_empty());
    }
}
