//! The gunzip decision and the inflate step (`inflateInit2(MAX_WBITS + 16)`).

use super::GunzipConf;
use crate::core::http::{RequestState, RequestStateView};
use crate::modules::filters::encode::Body;
use crate::modules::location::Location;
use flate2::read::MultiGzDecoder;
use pingora_http::ResponseHeader;
use std::io::Read;

/// `ngx_http_gunzip_filter_module`'s per-request state: whether the body was inflated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GunzipOutcome {
    pub decompressed: bool,
}

/// `ngx_http_gunzip_header_filter`: should the body be inflated?
///
/// The C filter compares the literal value `gzip` (exactly four characters, case-insensitive),
/// then consults `ngx_http_gzip_ok(r)` and only proceeds when that **fails** — a client that
/// accepts gzip keeps the compressed body.
pub fn should_decompress(
    conf: &GunzipConf,
    state: &RequestState,
    content_encoding: Option<&str>,
) -> bool {
    if !conf.enabled {
        return false;
    }
    let Some(encoding) = content_encoding else {
        return false;
    };
    if encoding.len() != 4 || !encoding.eq_ignore_ascii_case("gzip") {
        return false;
    }
    // `ngx_http_gzip_ok` with the location's own `gzip` settings; without a `gzip` block the
    // defaults apply (`gzip_http_version 1.1`).
    let gzip_conf = crate::modules::gzip::conf::GzipConf::default();
    !crate::modules::gzip::negotiate::gzip_ok(&gzip_conf, state)
}

/// Apply `gunzip` to a finished response.
pub fn decompress(
    response: &mut ResponseHeader,
    body: &mut Body,
    view: &RequestStateView,
    location: &Location,
    state: &RequestState,
    header_only: bool,
) -> anyhow::Result<bool> {
    let Some(conf) = location.get::<GunzipConf>() else {
        return Ok(false);
    };
    let encoding = response
        .headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    if !should_decompress(conf, state, encoding.as_deref()) {
        return Ok(false);
    }
    if header_only {
        // `r->header_only`: the body filters never run, yet the header filter already
        // removed `Content-Encoding`.
        strip_encoding_headers(response);
        return Ok(false);
    }
    let inflated = inflate(&body.bytes).map_err(|error| {
        anyhow::anyhow!("gunzip: inflate() failed: {error}")
    })?;
    strip_encoding_headers(response);
    response
        .insert_header("Content-Length", inflated.len().to_string())
        .ok();
    body.bytes = inflated;
    let _ = view;
    Ok(true)
}

/// Undo the encoded representation (`ngx_http_clear_content_length` & friends).
fn strip_encoding_headers(response: &mut ResponseHeader) {
    response.remove_header("Content-Encoding");
    response.remove_header("Content-Length");
    response.remove_header("Accept-Ranges");
    // `ngx_http_weak_etag`: the plain representation gets its own validator.
    if let Some(etag) = response
        .headers
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        && !etag.starts_with("W/")
    {
        response.insert_header("ETag", format!("W/{etag}")).ok();
    }
    // `ngx_http_gunzip_header_filter` sets `r->gzip_vary`.
    crate::modules::gzip::filter::add_vary(response, "Accept-Encoding");
}

/// `inflateInit2(&zstream, MAX_WBITS + 16)`: gzip framing, all members.
pub fn inflate(body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = MultiGzDecoder::new(body);
    let mut output = Vec::with_capacity(body.len() * 4);
    decoder.read_to_end(&mut output)?;
    Ok(output)
}

/// Record the outcome on the request (mirrors `ctx->done`).
pub fn record(state: &mut RequestState, decompressed: bool) {
    state.insert(GunzipOutcome { decompressed });
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn inflate_round_trips_and_accepts_multiple_members() {
        let plain = b"the quick brown fox".repeat(10);
        let compressed = gzip(&plain);
        assert_eq!(inflate(&compressed).unwrap(), plain);
        // Two gzip members in a row (`MultiGzDecoder`).
        let mut twice = gzip(&plain);
        twice.extend_from_slice(&gzip(b"tail"));
        let mut expected = plain.clone();
        expected.extend_from_slice(b"tail");
        assert_eq!(inflate(&twice).unwrap(), expected);
    }

    #[test]
    fn invalid_input_is_an_error() {
        assert!(inflate(b"not gzip at all").is_err());
    }

    #[test]
    fn only_gzip_encoding_is_handled() {
        let conf = GunzipConf {
            enabled: true,
            ..GunzipConf::default()
        };
        let mut conf = conf;
        let request = request_state(&[("accept-encoding", "identity")]);
        assert!(should_decompress(&conf, &request, Some("gzip")));
        assert!(should_decompress(&conf, &request, Some("GZIP")));
        assert!(!should_decompress(&conf, &request, Some("br")));
        assert!(!should_decompress(&conf, &request, Some("gzip, identity")));
        assert!(!should_decompress(&conf, &request, None));
        conf.enabled = false;
        assert!(!should_decompress(&conf, &request, Some("gzip")));
    }

    #[test]
    fn a_client_that_accepts_gzip_keeps_the_body() {
        let conf = GunzipConf {
            enabled: true,
            ..GunzipConf::default()
        };
        let request = request_state(&[("accept-encoding", "gzip")]);
        assert!(!should_decompress(&conf, &request, Some("gzip")));
    }

    fn request_state(headers: &[(&str, &str)]) -> RequestState {
        let mut request = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        request.set_version(http::Version::HTTP_11);
        let mut map = http::HeaderMap::new();
        for (name, value) in headers {
            map.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        RequestState::new(
            crate::core::http::ConnectionState {
                listen: "127.0.0.1:80".into(),
                peer_ip: Some("127.0.0.1".parse().unwrap()),
                peer_port: 1000,
                local_ip: Some("127.0.0.1".parse().unwrap()),
                local_port: 80,
                scheme: "http".into(),
                tls: false,
            },
            crate::core::http::RequestLine::from_header(&request),
            map,
            &[],
        )
    }

    #[test]
    fn headers_are_cleared_after_inflation() {
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("Content-Encoding", "gzip").unwrap();
        response.insert_header("Content-Length", "42").unwrap();
        response.insert_header("ETag", "\"x\"").unwrap();
        strip_encoding_headers(&mut response);
        assert!(response.headers.get("content-encoding").is_none());
        assert!(response.headers.get("content-length").is_none());
        assert_eq!(
            response.headers.get("etag").unwrap().to_str().unwrap(),
            "W/\"x\""
        );
        assert_eq!(
            response.headers.get("vary").unwrap().to_str().unwrap(),
            "Accept-Encoding"
        );
    }
}
