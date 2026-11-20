//! `ngx_http_core_module`: request-line URI operations shared by modules.

use http::Uri;

/// Replace the current URI of a request while preserving its query string.
pub fn with_original_args(target: &str, args: &str) -> String {
    if args.is_empty() || target.contains('?') {
        target.to_string()
    } else {
        format!("{target}?{args}")
    }
}

/// Split a rewrite target into path and optional args.
pub fn split_target(target: &str) -> (String, Option<String>) {
    target
        .split_once('?')
        .map(|(path, args)| (path.to_string(), Some(args.to_string())))
        .unwrap_or_else(|| (target.to_string(), None))
}

/// Set the request-line path and arguments (`ngx_http_set_exten` + `r->args`).
pub fn set_request_uri(
    request: &mut crate::core::http::RequestLine,
    path: &str,
    args: Option<&str>,
) {
    let (path, target_args) = split_target(path);
    request.path = path.clone();
    request.args = args
        .map(str::to_string)
        .or(target_args)
        .unwrap_or_default();
    request.uri = if request.args.is_empty() {
        path
    } else {
        format!("{}?{}", request.path, request.args)
    };
}

/// Set the URI on a pingora request header.
pub fn set_uri(
    request: &mut pingora_http::RequestHeader,
    target: &str,
) -> pingora_core::Result<()> {
    request.set_uri(target.parse::<Uri>().map_err(|error| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("invalid URI \"{target}\": {error}"),
        )
    })?);
    Ok(())
}
