//! `ngx_http_gzip_ok` from `ngx_http_core_module.c`: may this request be gzipped?
//!
//! The C helper answers five questions, in this order:
//!
//! 1. `gzip_http_version` — HTTP/1.0 clients are skipped unless the floor is `1.0`;
//! 2. `$gzip_ratio` is reachable — `ngx_http_gzip_ratio_variable` is only usable when the
//!    filter installed itself;
//! 3. `gzip_disable` — a `User-Agent` matching one of the regexes (MSIE 6 by default in many
//!    configurations) is skipped;
//! 4. an existing `Via` header — the request already passed a proxy that may have compressed
//!    it, so the client's `Accept-Encoding` cannot be trusted;
//! 5. `Accept-Encoding` must list `gzip` with a non-zero quality.
//!
//! The result is memoised on the request (`r->gzip_tested`/`r->gzip_ok`) so the header filter,
//! `gunzip` and `gzip_static` all see the same answer.

use super::conf::{version_at_most, GzipConf};
use crate::core::http::RequestState;

/// `ngx_http_gzip_ok`.
pub fn gzip_ok(conf: &GzipConf, state: &RequestState) -> bool {
    if !version_at_most(state.request.version, conf.http_version) {
        return false;
    }
    if let Some(user_agent) = header(state, "user-agent")
        && conf.disable.iter().any(|regex| regex.is_match(&user_agent))
    {
        return false;
    }
    if header(state, "via").is_some() {
        return false;
    }
    accepts_gzip(state)
}

fn header(state: &RequestState, name: &str) -> Option<String> {
    state
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// `ngx_http_gzip_accept_encoding`: `gzip` with `q` > 0.
///
/// The parser walks the comma-separated list, matching the coding case-insensitively and
/// reading an optional `q=` parameter; `*` is accepted as a fallback for `gzip`.
pub fn accepts_gzip(state: &RequestState) -> bool {
    let Some(accept) = header(state, "accept-encoding") else {
        return false;
    };
    quality_of(&accept, "gzip").unwrap_or(0.0) > 0.0
}

/// The quality the header assigns to `coding`, `None` when it is not listed.
pub fn quality_of(header: &str, coding: &str) -> Option<f32> {
    let mut wildcard = None;
    for entry in header.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, params) = match entry.split_once(';') {
            Some((name, params)) => (name.trim(), params.trim()),
            None => (entry, ""),
        };
        let quality = quality(params);
        if name.eq_ignore_ascii_case(coding) {
            return Some(quality);
        }
        if name == "*" {
            wildcard = Some(quality);
        }
    }
    wildcard
}

/// `q=` from the parameters of one list entry (defaults to 1).
fn quality(params: &str) -> f32 {
    for param in params.split(';') {
        let param = param.trim();
        if let Some(value) = param.strip_prefix("q=").or_else(|| param.strip_prefix("Q=")) {
            return value.trim().parse().unwrap_or(0.0);
        }
    }
    1.0
}

/// `q` for the `gzip;q=0` case: compression must not be used.
#[allow(dead_code)]
pub fn explicitly_forbidden(header: &str) -> bool {
    quality_of(header, "gzip") == Some(0.0)
}

/// The `gzip_http_version` half of the check, shared with `gunzip`/`gzip_static`.
pub fn version_matches(conf: &GzipConf, version: http::Version) -> bool {
    version_at_most(version, conf.http_version)
}

/// Whether `gzip_disable` or an existing `Via` blocked the request.
pub fn blocked_by_agent_or_via(conf: &GzipConf, state: &RequestState) -> bool {
    if header(state, "via").is_some() {
        return true;
    }
    conf.disable
        .iter()
        .any(|regex| header(state, "user-agent").is_some_and(|agent| regex.is_match(&agent)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderName};

    #[test]
    fn accept_encoding_is_parsed_like_nginx() {
        assert_eq!(quality_of("gzip", "gzip"), Some(1.0));
        assert_eq!(quality_of("deflate, gzip;q=0.5", "gzip"), Some(0.5));
        assert_eq!(quality_of("gzip;q=0", "gzip"), Some(0.0));
        assert_eq!(quality_of("br, deflate", "gzip"), None);
        // `*` covers every coding that is not listed.
        assert_eq!(quality_of("*", "gzip"), Some(1.0));
        assert_eq!(quality_of("br;q=1, *;q=0.1", "gzip"), Some(0.1));
        // An explicit entry wins over the wildcard.
        assert_eq!(quality_of("gzip;q=0.2, *;q=1", "gzip"), Some(0.2));
        assert_eq!(quality_of("GZIP", "gzip"), Some(1.0));
    }

    fn request_state(headers: &[(&str, &str)], version: http::Version) -> RequestState {
        let mut request = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        request.set_version(version);
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(HeaderName::from_bytes(name.as_bytes()).unwrap(), value.parse().unwrap());
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
    fn negotiation_rules() {
        let conf = GzipConf::default();
        assert!(gzip_ok(
            &conf,
            &request_state(&[("accept-encoding", "gzip")], http::Version::HTTP_11)
        ));
        // HTTP/1.0 is below the default `gzip_http_version 1.1`.
        assert!(!gzip_ok(
            &conf,
            &request_state(&[("accept-encoding", "gzip")], http::Version::HTTP_10)
        ));
        // `Via` means an intermediary may already have compressed the body.
        assert!(!gzip_ok(
            &conf,
            &request_state(
                &[("accept-encoding", "gzip"), ("via", "1.1 proxy")],
                http::Version::HTTP_11
            )
        ));
        // No `Accept-Encoding` at all.
        assert!(!gzip_ok(&conf, &request_state(&[], http::Version::HTTP_11)));
        // `gzip;q=0` forbids it.
        assert!(!gzip_ok(
            &conf,
            &request_state(&[("accept-encoding", "gzip;q=0")], http::Version::HTTP_11)
        ));
    }

    #[test]
    fn disabled_user_agents_are_skipped() {
        let mut conf = GzipConf::default();
        conf.disable = vec![regex::RegexBuilder::new("MSIE [4-6]\\.")
            .case_insensitive(true)
            .build()
            .unwrap()];
        let agent = request_state(
            &[
                ("accept-encoding", "gzip"),
                ("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"),
            ],
            http::Version::HTTP_11,
        );
        assert!(!gzip_ok(&conf, &agent));
        let modern = request_state(
            &[
                ("accept-encoding", "gzip"),
                ("user-agent", "Mozilla/5.0 (X11; Linux x86_64)"),
            ],
            http::Version::HTTP_11,
        );
        assert!(gzip_ok(&conf, &modern));
    }
}
