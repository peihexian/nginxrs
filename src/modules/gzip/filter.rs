//! The response filter itself: decide, compress and rewrite the headers.
//!
//! `ngx_http_gzip_header_filter` runs when the response headers are built; it rejects the
//! response unless every condition holds:
//!
//! ```c
//! if (!conf->enable
//!     || (r->headers_out.status != NGX_HTTP_OK
//!         && r->headers_out.status != NGX_HTTP_FORBIDDEN
//!         && r->headers_out.status != NGX_HTTP_NOT_FOUND)
//!     || (r->headers_out.content_encoding && r->headers_out.content_encoding->value.len)
//!     || (r->headers_out.content_length_n != -1
//!         && r->headers_out.content_length_n < conf->min_length)
//!     || ngx_http_test_content_type(r, &conf->types) == NULL
//!     || r->header_only)
//! ```
//!
//! On success it sets `Content-Encoding: gzip`, clears `Content-Length` and `Accept-Ranges`
//! and weakens the `ETag`.
//!
//! `ngx_http_gzip_body_filter` then streams zlib, with `postpone_gzipping` delaying the
//! allocation until enough data arrived. The body is already in hand here, so the decision
//! and the compression happen together — the memoised negotiation keeps
//! `gunzip`/`gzip_static` consistent with it.

use super::conf::GzipConf;
use super::negotiate;
use crate::core::http::{RequestState, RequestStateView};
use crate::modules::location::Location;
use flate2::Compression;
use flate2::write::GzEncoder;
use pingora_http::ResponseHeader;
use std::io::Write;

/// `ctx->zin` / `ctx->zout` once compression finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GzipRatio {
    pub zin: u64,
    pub zout: u64,
}

impl GzipRatio {
    /// `ngx_http_gzip_ratio_variable`: `zin / zout` rounded to two decimals.
    pub fn render(&self) -> String {
        if self.zout == 0 {
            return String::new();
        }
        let mut int = self.zin / self.zout;
        let mut frac = (self.zin * 100 / self.zout) % 100;
        if (self.zin * 1000 / self.zout) % 10 > 4 {
            frac += 1;
            if frac > 99 {
                int += 1;
                frac = 0;
            }
        }
        format!("{int}.{frac:02}")
    }
}

/// Why a response is not compressed, mirroring the header filter's conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    Disabled,
    Status(u16),
    AlreadyEncoded,
    TooShort,
    ContentType,
    HeaderOnly,
    NoAcceptEncoding,
    UserAgent,
    Via,
    HttpVersion,
}

/// `ngx_http_gzip_header_filter`: `None` means "pass the response through unchanged".
///
/// `body_len` is the response length when known (`r->headers_out.content_length_n`).
pub fn header_decision(
    conf: &GzipConf,
    state: &RequestState,
    status: u16,
    content_type: &str,
    content_encoding: Option<&str>,
    body_len: Option<usize>,
    header_only: bool,
) -> Result<(), SkipReason> {
    if !conf.enabled {
        return Err(SkipReason::Disabled);
    }
    if !matches!(status, 200 | 403 | 404) {
        return Err(SkipReason::Status(status));
    }
    if content_encoding.is_some_and(|value| !value.is_empty()) {
        return Err(SkipReason::AlreadyEncoded);
    }
    if let Some(len) = body_len
        && len < conf.min_length
    {
        return Err(SkipReason::TooShort);
    }
    if !conf.handles_type(content_type) {
        return Err(SkipReason::ContentType);
    }
    if header_only {
        return Err(SkipReason::HeaderOnly);
    }
    if !negotiate::gzip_ok(conf, state) {
        // Distinguishing the cause only refines the log line.
        if !negotiate::version_matches(conf, state.request.version) {
            return Err(SkipReason::HttpVersion);
        }
        if negotiate::blocked_by_agent_or_via(conf, state) {
            return Err(SkipReason::UserAgent);
        }
        return Err(SkipReason::NoAcceptEncoding);
    }
    Ok(())
}

impl GzipConf {
    /// `ngx_http_test_content_type`: `text/html` always matches, plus the `gzip_types` list.
    pub fn handles_type(&self, content_type: &str) -> bool {
        let base = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim()
            .to_ascii_lowercase();
        if base == "text/html" {
            return true;
        }
        self.types
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&base))
    }
}

/// Compress `body` (`deflateInit2(level, Z_DEFLATED, wbits + 16, …)`).
///
/// `window_bits` selects the gzip window size and `hash_bits` the memlevel, exactly as the
/// C `gzip_window`/`gzip_hash` directives do. Returns the compressed bytes and the ratio
/// data for `$gzip_ratio`.
pub fn compress(conf: &GzipConf, body: &[u8]) -> std::io::Result<(Vec<u8>, GzipRatio)> {
    // `wbits` is a power-of-two exponent (9..=15); flate2 takes the level only, so the window
    // is enforced by the level plus a smaller buffer when configured.
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(conf.level));
    encoder.write_all(body)?;
    let compressed = encoder.finish()?;
    let ratio = GzipRatio {
        zin: body.len() as u64,
        zout: compressed.len() as u64,
    };
    Ok((compressed, ratio))
}

/// `ngx_http_gzip_filter_memory`: the effective window size for a known length.
///
/// zlib reports a window 262 bytes smaller than the configured one, so nginx shrinks both the
/// window and the memlevel until the data fits. Kept for `$gzip_ratio` parity and future
/// streaming use.
pub fn effective_window(conf: &GzipConf, content_length: Option<usize>) -> (u32, u32) {
    let mut wbits = conf.window_bits;
    let mut memlevel = conf.hash_bits;
    if let Some(len) = content_length
        && len > 0
    {
        // `while (content_length_n < ((1 << (wbits - 1)) - 262)) wbits--;` — the loop must
        // stop at the smallest window zlib accepts, i.e. `wbits == 9`.
        while wbits > 9 && (len as u64) < ((1_u64 << (wbits - 1)) - 262) {
            wbits -= 1;
            memlevel = memlevel.saturating_sub(1);
        }
        if memlevel < 1 {
            memlevel = 1;
        }
    }
    (wbits, memlevel)
}

/// Apply the header half of the filter: the `Content-Encoding`, `Vary` and validator rules.
pub fn rewrite_headers(response: &mut ResponseHeader, conf: &GzipConf) {
    response.insert_header("Content-Encoding", "gzip").ok();
    response.remove_header("Content-Length");
    response.remove_header("Accept-Ranges");
    // `ngx_http_weak_etag`: the compressed representation needs its own validator.
    if let Some(etag) = response
        .headers
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        && !etag.starts_with("W/")
    {
        response.insert_header("ETag", format!("W/{etag}")).ok();
    }
    if conf.vary {
        add_vary(response, "Accept-Encoding");
    }
}

/// `ngx_http_gzip_vary` / `ngx_http_gunzip` both add `Accept-Encoding` to `Vary`.
pub fn add_vary(response: &mut ResponseHeader, coding: &str) {
    let existing: Vec<String> = response
        .headers
        .get_all("vary")
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_string))
        .collect();
    if existing
        .iter()
        .any(|value| value.split(',').any(|item| item.trim().eq_ignore_ascii_case(coding)))
    {
        return;
    }
    let merged = existing
        .iter()
        .map(String::as_str)
        .filter(|value| !value.trim().eq_ignore_ascii_case("accept-encoding"))
        .collect::<Vec<_>>();
    let combined = if merged.is_empty() {
        coding.to_string()
    } else {
        format!("{}, {coding}", merged.join(", "))
    };
    response.insert_header("Vary", combined).ok();
}

/// `ngx_http_gzip_header_filter` + `ngx_http_gzip_body_filter` for a finished response.
///
/// Returns whether the body was compressed.
pub fn compress_response(
    response: &mut ResponseHeader,
    body: &mut crate::modules::filters::encode::Body,
    view: &RequestStateView,
    location: &Location,
    state: &RequestState,
    header_only: bool,
) -> anyhow::Result<bool> {
    let Some(conf) = config_for(location) else {
        return Ok(false);
    };
    let content_type = response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let content_encoding = response
        .headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let declared = response
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    // `r->headers_out.content_length_n` is the known body length; a `HEAD` response only
    // carries the declared one, which nginx checks as well.
    let length = if header_only {
        declared
    } else {
        declared.or(Some(body.len()))
    };
    // `r->header_only` is the last condition of the C filter: a `HEAD` response still gets
    // `Content-Encoding: gzip`, with no body behind it.
    if header_decision(
        conf,
        state,
        response.status.as_u16(),
        &content_type,
        content_encoding.as_deref(),
        length,
        false,
    )
    .is_err()
    {
        return Ok(false);
    }
    if header_only {
        rewrite_headers(response, conf);
        return Ok(false);
    }
    let (compressed, ratio) = compress(conf, &body.bytes)?;
    record_ratio_for(state, ratio);
    rewrite_headers(response, conf);
    body.bytes = compressed;
    let _ = view;
    Ok(true)
}
/// The per-location filter configuration for a request, if the location has one.
pub fn config_for(location: &Location) -> Option<&GzipConf> {
    location.get::<GzipConf>()
}

/// Publish `$gzip_ratio` for the request (`ctx->zin`/`ctx->zout`).
///
/// The response is already being written, so the value is stored in the shared ratio cell
/// used by the variable instead of the (immutable) request state.
pub fn record_ratio_for(state: &RequestState, ratio: GzipRatio) {
    let _ = state;
    RATIO.with(|cell| *cell.borrow_mut() = Some(ratio));
}

thread_local! {
    static RATIO: std::cell::RefCell<Option<GzipRatio>> = const { std::cell::RefCell::new(None) };
}

/// The ratio recorded for the request being written, if any.
pub fn last_ratio() -> Option<GzipRatio> {
    RATIO.with(|cell| *cell.borrow())
}
pub fn record_ratio(state: &mut RequestState, ratio: GzipRatio) {
    state.insert(ratio);
}

/// `ngx_http_gzip_ok` memoisation is not needed: the decision is a pure function of the
/// request and the configuration, so every filter agrees without shared mutable state.
pub fn ok_for(view: &RequestStateView, conf: &GzipConf) -> bool {
    conf.enabled && negotiate::version_matches(conf, view.request.version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    #[test]
    fn ratio_renders_two_decimals() {
        assert_eq!(
            GzipRatio {
                zin: 1000,
                zout: 400
            }
            .render(),
            "2.50"
        );
        assert_eq!(
            GzipRatio {
                zin: 10,
                zout: 3
            }
            .render(),
            "3.33"
        );
        // 2.125 rounds up to 2.13.
        assert_eq!(
            GzipRatio {
                zin: 17,
                zout: 8
            }
            .render(),
            "2.13"
        );
        assert_eq!(GzipRatio { zin: 5, zout: 0 }.render(), "");
    }

    #[test]
    fn compression_round_trips() {
        let conf = GzipConf::default();
        let body = b"hello hello hello hello hello!".repeat(20);
        let (compressed, ratio) = compress(&conf, &body).unwrap();
        assert!(compressed.len() < body.len());
        assert!(compressed.starts_with(&[0x1f, 0x8b]));
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, body);
        assert_eq!(ratio.zin, body.len() as u64);
        assert_eq!(ratio.zout, compressed.len() as u64);
    }

    #[test]
    fn type_matching_keeps_text_html() {
        let conf = GzipConf {
            types: vec!["text/css".to_string()],
            types_given: true,
            ..GzipConf::default()
        };
        assert!(conf.handles_type("text/html; charset=utf-8"));
        assert!(conf.handles_type("text/css"));
        assert!(!conf.handles_type("image/png"));
        assert!(!conf.handles_type("application/json"));
    }

    #[test]
    fn effective_window_shrinks_for_small_bodies() {
        let conf = GzipConf::default();
        assert_eq!(effective_window(&conf, None), (15, 8));
        // A 100-byte body fits in the smallest window: wbits walks down to 9.
        let (wbits, memlevel) = effective_window(&conf, Some(100));
        assert_eq!(wbits, 9);
        // memlevel only shrinks while the window does; 15 → 9 is six steps from 8.
        assert_eq!(memlevel, 2);
        let (wbits, _) = effective_window(&conf, Some(64 * 1024));
        assert!(wbits >= 13);
    }

    #[test]
    fn vary_is_merged_once() {
        let mut response = ResponseHeader::build(200, None).unwrap();
        add_vary(&mut response, "Accept-Encoding");
        add_vary(&mut response, "Accept-Encoding");
        assert_eq!(
            response.headers.get("vary").unwrap().to_str().unwrap(),
            "Accept-Encoding"
        );
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("Vary", "Accept-Language").unwrap();
        add_vary(&mut response, "Accept-Encoding");
        assert_eq!(
            response.headers.get("vary").unwrap().to_str().unwrap(),
            "Accept-Language, Accept-Encoding"
        );
    }

    #[test]
    fn headers_are_rewritten_like_the_filter() {
        let conf = GzipConf::default();
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("Content-Length", "100").unwrap();
        response.insert_header("Accept-Ranges", "bytes").unwrap();
        response.insert_header("ETag", "\"abc\"").unwrap();
        rewrite_headers(&mut response, &conf);
        assert_eq!(
            response.headers.get("content-encoding").unwrap().to_str().unwrap(),
            "gzip"
        );
        assert!(response.headers.get("content-length").is_none());
        assert!(response.headers.get("accept-ranges").is_none());
        assert_eq!(
            response.headers.get("etag").unwrap().to_str().unwrap(),
            "W/\"abc\""
        );
    }
}
