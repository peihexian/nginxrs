//! `ngx_http_grpc_create_request`: build the HTTP/2 field list of a gRPC call.
//!
//! nginx writes these fields, in this order (`ngx_http_grpc_send_request`):
//!
//! | field | source |
//! |---|---|
//! | `:method` | the client method, inherited |
//! | `:scheme` | `http`/`https`, from the `grpc_pass` scheme |
//! | `:path` | the unparsed request URI |
//! | `:authority` | `grpc_set_header Host`, else the client `Host`, else the pass target |
//! | `grpc-accept-encoding` | the client's value when it sent one |
//! | `te: trailers` | always (unless the client set `TE`, which nginx forwards) |
//! | `Content-Length`/`Content-Type` | inherited |
//! | `grpc-timeout` | `grpc_set_header` only |
//!
//! and hides connection-specific fields (`Connection`, `Keep-Alive`, `Transfer-Encoding`,
//! `Upgrade`, `Expect`, `Proxy-Connection`). The `Host` header becomes `:authority` and is not
//! forwarded as a regular field, exactly like `ngx_http_grpc_process_request_headers`.

use crate::core::http::RequestState;
use crate::modules::grpc::client::Call;
use crate::modules::grpc::conf::GrpcConf;
use http::{HeaderMap, HeaderName, HeaderValue, Method};

/// Fields never forwarded to an HTTP/2 peer (connection-specific, or handled as pseudo
/// headers). The list matches `ngx_http_grpc_headers` and the `HTTP/2` spec.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "expect",
    "host",
    // Sent explicitly below.
    "te",
    "grpc-accept-encoding",
    "content-length",
];

/// Build the call for one request.
pub fn build(
    conf: &GrpcConf,
    state: &RequestState,
    body: &[u8],
    scheme: &'static str,
) -> Call {
    let mut headers = HeaderMap::new();
    for (name, value) in state.headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) {
            continue;
        }
        // Header names with uppercase letters are legal in HTTP/1.1 but must be lowercased
        // for HTTP/2; `h2` does that, so the value is copied as-is.
        headers.append(name.clone(), value.clone());
    }
    // `ngx_http_grpc_headers`: `TE: $grpc_internal_trailers`, which is `trailers` unless the
    // client sent its own `TE` value.
    if let Some(te) = state
        .headers
        .get("te")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    {
        if let Ok(value) = HeaderValue::from_str(te) {
            headers.insert(HeaderName::from_static("te"), value);
        }
    } else {
        headers.insert(HeaderName::from_static("te"), HeaderValue::from_static("trailers"));
    }
    // `grpc-accept-encoding` lets the backend answer with a compressed message.
    if let Some(accept) = state
        .headers
        .get("grpc-accept-encoding")
        .and_then(|value| value.to_str().ok())
        && let Ok(value) = HeaderValue::from_str(accept)
    {
        headers.insert(HeaderName::from_static("grpc-accept-encoding"), value);
    }
    // `Content-Length` is regenerated from the body that is actually sent.
    if !body.is_empty()
        && let Ok(value) = HeaderValue::from_str(&body.len().to_string())
    {
        headers.insert(http::header::CONTENT_LENGTH, value);
    }
    // `grpc_set_header` replaces the inherited value (or adds the field).
    for (name, template) in &conf.set_headers {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let value = template.eval(state);
        if value.is_empty() {
            headers.remove(&name);
            continue;
        }
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(name, value);
        }
    }

    // `:authority` — `grpc_set_header Host` wins, then the client `Host`, then the target.
    let authority = headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            conf.set_headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("host"))
                .map(|(_, template)| template.eval(state))
                .filter(|value| !value.is_empty())
        })
        .or_else(|| Some(state.request.host.clone()))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            conf.pass
                .as_ref()
                .map(|pass| pass.authority.clone())
                .unwrap_or_default()
        });
    headers.remove(http::header::HOST);

    Call {
        method: state.request.method.clone(),
        scheme,
        path: uri_of(state),
        authority,
        headers,
        body: body.to_vec(),
    }
}

/// `:path` — the request URI as the client sent it, query included.
fn uri_of(state: &RequestState) -> String {
    let path = &state.request.path;
    match &state.request.args {
        args if args.is_empty() => path.clone(),
        args => format!("{path}?{args}"),
    }
}

/// `$grpc_internal_trailers`: the `TE` value nginx generates.
pub fn internal_trailers() -> &'static str {
    "trailers"
}

/// The method used for a request; kept for symmetry with `proxy_method`.
pub fn method_of(state: &RequestState) -> Method {
    state.request.method.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::{ConnectionState, RequestLine, RequestState};
    use crate::modules::grpc::conf::GrpcPass;

    fn state(headers: &[(&str, &str)]) -> RequestState {
        let mut request = pingora_http::RequestHeader::build("POST", b"/pkg.Svc/Call?x=1", None)
            .unwrap();
        request.set_version(http::Version::HTTP_2);
        request.insert_header("host", "grpc.example");
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        RequestState::new(
            ConnectionState {
                listen: "127.0.0.1:80".into(),
                peer_ip: Some("127.0.0.1".parse().unwrap()),
                peer_port: 1000,
                local_ip: Some("127.0.0.1".parse().unwrap()),
                local_port: 80,
                scheme: "http".into(),
                tls: false,
            },
            RequestLine::from_header(&request),
            map,
            &[],
        )
    }

    fn conf() -> GrpcConf {
        GrpcConf {
            pass: Some(GrpcPass::parse("grpc://127.0.0.1:50051").unwrap()),
            ..GrpcConf::default()
        }
    }

    #[test]
    fn builds_the_pseudo_headers_and_payload() {
        let call = build(&conf(), &state(&[]), b"\x00\x00\x00\x00\x00", "http");
        assert_eq!(call.method, Method::POST);
        assert_eq!(call.scheme, "http");
        assert_eq!(call.path, "/pkg.Svc/Call?x=1");
        assert_eq!(call.authority, "grpc.example");
        assert_eq!(call.body.len(), 5);
        // `te: trailers` is always present, and the body length is regenerated.
        assert_eq!(call.headers.get("te").unwrap(), "trailers");
        assert_eq!(call.headers.get("content-length").unwrap(), "5");
        // `Host` is turned into `:authority` and not forwarded.
        assert!(call.headers.get("host").is_none());
    }

    #[test]
    fn drops_hop_by_hop_fields() {
        let request = state(&[
            ("connection", "keep-alive"),
            ("upgrade", "h2c"),
            ("expect", "100-continue"),
            ("x-trace", "abc"),
        ]);
        let call = build(&conf(), &request, &[], "http");
        for name in ["connection", "upgrade", "expect"] {
            assert!(call.headers.get(name).is_none(), "{name}");
        }
        assert_eq!(call.headers.get("x-trace").unwrap(), "abc");
    }

    #[test]
    fn a_client_te_value_is_forwarded() {
        let call = build(&conf(), &state(&[("te", "trailers, deflate")]), &[], "http");
        assert_eq!(call.headers.get("te").unwrap(), "trailers, deflate");
    }

    #[test]
    fn set_header_overrides_and_removes() {
        let mut conf = conf();
        conf.set_headers = vec![
            (
                "x-real-ip".to_string(),
                crate::core::variables::Template::parse("$remote_addr").unwrap(),
            ),
            (
                "x-drop".to_string(),
                crate::core::variables::Template::parse("").unwrap(),
            ),
        ];
        let mut request = state(&[("x-drop", "value")]);
        request
            .headers
            .insert("x-drop", HeaderValue::from_static("value"));
        let call = build(&conf, &request, &[], "http");
        assert_eq!(call.headers.get("x-real-ip").unwrap(), "127.0.0.1");
        // An empty value removes the inherited field (`ngx_http_grpc_set_header`).
        assert!(call.headers.get("x-drop").is_none());
    }

    #[test]
    fn authority_falls_back_to_the_target() {
        let mut request = state(&[]);
        request.headers.remove("host");
        request.request.host = String::new();
        let call = build(&conf(), &request, &[], "http");
        assert_eq!(call.authority, "127.0.0.1:50051");
    }
}
