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
