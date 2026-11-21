//! `ngx_http_grpc_process_header`: translate an HTTP/2 response into the client response.
//!
//! nginx keeps `:status` and the regular fields, folds the trailers into `headers_out` when
//! they arrive, and lets `grpc_hide_header`/`grpc_pass_header` decide which upstream fields
//! reach the client. `grpc-status` and `grpc-message` are forwarded — a gRPC client reads the
//! final status from the trailers, so dropping them would break every call.
//!
//! | nginx | here |
//! |---|---|
//! | `ngx_http_grpc_filter` (trailers merged into `r->headers_out`) | [`merge_trailers`] |
//! | `ngx_http_upstream_process_headers` | [`to_response_header`] |
//! | `ngx_http_grpc_hide_headers` | [`hidden`] |

use crate::modules::grpc::conf::GrpcConf;
use http::HeaderMap;
use pingora_http::ResponseHeader;

/// Fields hidden by default (`ngx_http_grpc_hide_headers`).
pub const DEFAULT_HIDDEN: &[&str] = &[
    "Date",
    "Server",
    "X-Accel-Expires",
    "X-Accel-Redirect",
    "X-Accel-Limit-Rate",
    "X-Accel-Buffering",
    "X-Accel-Charset",
];

/// Whether `name` is hidden for this location (`grpc_hide_header`, then `grpc_pass_header`).
pub fn hidden(conf: &GrpcConf, name: &str) -> bool {
    if conf
        .pass_headers
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(name))
    {
        return false;
    }
    if conf
        .hide_headers
        .iter()
        .any(|hidden| hidden.eq_ignore_ascii_case(name))
    {
        return true;
    }
    DEFAULT_HIDDEN
        .iter()
        .any(|hidden| hidden.eq_ignore_ascii_case(name))
}

/// Build the client-facing header from the HTTP/2 response head and its trailers.
///
/// `grpc-status` from the trailers overrides a value sent in the headers, and
/// `grpc-message` follows it: that is where the backend reports the final status.
pub fn to_response_header(
    conf: &GrpcConf,
    head: &http::Response<()>,
    trailers: &HeaderMap,
) -> anyhow::Result<ResponseHeader> {
    let status = head.status();
    let mut response = ResponseHeader::build(status.as_u16(), None)?;
    for (name, value) in head.headers() {
        let name_text = name.as_str();
        if name_text.starts_with(':') || hidden(conf, name_text) {
            continue;
        }
        // `grpc-status`/`grpc-message` are re-applied after the trailers.
        if is_grpc_status(name_text) {
            continue;
        }
        response.append_header(name.clone(), value.clone())?;
    }
    for (name, value) in trailers {
        let name_text = name.as_str();
        if hidden(conf, name_text) && !is_grpc_status(name_text) {
            continue;
        }
        response.append_header(name.clone(), value.clone())?;
    }
    Ok(response)
}

/// `grpc-status`, `grpc-message` and the trailing metadata a client needs.
fn is_grpc_status(name: &str) -> bool {
    name.eq_ignore_ascii_case("grpc-status") || name.eq_ignore_ascii_case("grpc-message")
}

/// Merge trailers into the response header (`ngx_http_grpc_filter`), used when the body was
/// already relayed and only the final status remains.
pub fn merge_trailers(
    conf: &GrpcConf,
    response: &mut ResponseHeader,
    trailers: &HeaderMap,
) -> anyhow::Result<()> {
    for (name, value) in trailers {
        let name_text = name.as_str();
        if hidden(conf, name_text) && !is_grpc_status(name_text) {
            continue;
        }
        response.insert_header(name.clone(), value.clone())?;
    }
    Ok(())
}

/// The gRPC status code, when the upstream reported one (`grpc-status: 0` is OK).
pub fn status_code(head: &http::Response<()>, trailers: &HeaderMap) -> Option<u32> {
    trailers
        .get("grpc-status")
        .or_else(|| head.headers().get("grpc-status"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf() -> GrpcConf {
        GrpcConf::default()
    }

    #[test]
    fn default_hidden_fields() {
        let conf = conf();
        assert!(hidden(&conf, "Server"));
        assert!(hidden(&conf, "X-Accel-Redirect"));
        assert!(!hidden(&conf, "Content-Type"));
        assert!(!hidden(&conf, "grpc-status"));
    }

    #[test]
    fn pass_header_overrides_hide() {
        let mut conf = conf();
        conf.pass_headers.push("server".to_string());
        assert!(!hidden(&conf, "Server"));
        conf.hide_headers.push("x-internal".to_string());
        assert!(hidden(&conf, "X-Internal"));
    }

    #[test]
    fn trailers_supply_the_final_status() {
        let conf = conf();
        let head = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .header("server", "grpc-backend")
            .body(())
            .unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        trailers.insert("grpc-message", "ok".parse().unwrap());
        let response = to_response_header(&conf, &head, &trailers).unwrap();
        assert_eq!(response.status.as_u16(), 200);
        assert_eq!(response.headers.get("content-type").unwrap(), "application/grpc");
        // `Server` is hidden by default (`ngx_http_grpc_hide_headers`).
        assert!(response.headers.get("server").is_none());
        assert_eq!(response.headers.get("grpc-status").unwrap(), "0");
        assert_eq!(response.headers.get("grpc-message").unwrap(), "ok");
        assert_eq!(status_code(&head, &trailers), Some(0));
    }
}
