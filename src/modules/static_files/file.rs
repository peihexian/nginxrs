//! File resolution, range handling and streaming for the static module.
//!
//! Files are streamed in fixed-size chunks with a seek for ranged requests, so a 4 GiB
//! movie never lands in memory. Path resolution canonicalizes the root and rejects any
//! symlink or `..` escape before opening the file.

use crate::core::http::RequestStateView;
use crate::modules::headers::HeadersConf;
use crate::modules::filters::encode;
use crate::modules::http_core::MimeConfig;
use crate::modules::lua::{LuaConf, execute_header_filter};
use bytes::Bytes;
use http::header::{
    CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH,
    LAST_MODIFIED, RANGE,
};
use http::{HeaderMap, StatusCode};
use mime_guess::MimeGuess;
use percent_encoding::percent_decode_str;
use pingora_core::{Error, ErrorType, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use std::fs::Metadata;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const CHUNK_SIZE: usize = 64 * 1024;

pub enum Resolved {
    File(PathBuf),
    Directory(PathBuf),
}

/// Resolve one `try_files` candidate inside `root`.
pub async fn resolve(
    root: &Path,
    original_uri: &str,
    candidate: &str,
    indexes: Option<&[String]>,
) -> std::result::Result<Option<Resolved>, StatusCode> {
    resolve_in(root, MapMode::Root, original_uri, candidate, indexes).await
}

/// How a location maps a URI to the filesystem (`clcf->root` + `clcf->alias`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MapMode {
    /// `root path;`: the URI is appended to `root`.
    Root,
    /// `alias path;` with a prefix location: the matched prefix is replaced by `alias`.
    Alias {
        /// The location prefix whose length is dropped from the URI.
        prefix_len: usize,
    },
    /// `alias path;` inside a regex location: the whole URI is appended to `alias`.
    AliasAll,
}

impl MapMode {
    /// The filesystem path for `uri` under `root`.
    pub fn map(&self, root: &Path, uri: &str) -> Option<PathBuf> {
        let relative = match self {
            MapMode::Root => uri,
            MapMode::Alias { prefix_len } => uri.get(*prefix_len..)?,
            MapMode::AliasAll => uri,
        };
        Some(root.join(relative.trim_start_matches('/')))
    }
}

/// Resolve a candidate with an explicit root/alias mapping (`ngx_http_map_uri_to_path`).
pub async fn resolve_in(
    root: &Path,
    mode: MapMode,
    original_uri: &str,
    candidate: &str,
    indexes: Option<&[String]>,
) -> std::result::Result<Option<Resolved>, StatusCode> {
    let target = if candidate.is_empty() {
        original_uri
    } else {
        candidate
    };
    let relative = sanitize_uri(target)?;
    let canonical_root = tokio::fs::canonicalize(root)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    // Build paths from the configured root: on Windows `canonicalize` returns a verbatim
    // `\\?\` path whose components do not concatenate like the original one.
    let base = std::path::absolute(root).unwrap_or_else(|_| root.to_path_buf());
    let prefix_len = match &mode {
        MapMode::Root => 0,
        MapMode::Alias { prefix_len } => *prefix_len,
        MapMode::AliasAll => 0,
    };
    let alias_relative = target.get(prefix_len..).unwrap_or(target);
    let path = match &mode {
        MapMode::Root => base.join(relative),
        MapMode::Alias { .. } | MapMode::AliasAll => {
            // `ngx_http_map_uri_to_path`: the matched prefix is replaced by the alias and the
            // rest of the request URI (or the `try_files` candidate) is appended.
            let rest = sanitize_uri(alias_relative)?;
            if rest.as_os_str().is_empty() {
                base.clone()
            } else {
                base.join(rest)
            }
        }
    };
    let Ok(canonical) = tokio::fs::canonicalize(&path).await else {
        return Ok(None);
    };

    if !canonical.starts_with(&canonical_root) {
        return Err(StatusCode::FORBIDDEN);
    }
    let metadata = tokio::fs::metadata(&canonical)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if metadata.is_file() {
        return Ok(Some(Resolved::File(canonical)));
    }
    if !metadata.is_dir() {
        return Ok(None);
    }
    for index in indexes.unwrap_or(&[]) {
        if index.contains('/') || index.contains('\\') {
            continue;
        }
        if let Ok(index_path) = tokio::fs::canonicalize(canonical.join(index)).await
            && index_path.starts_with(&canonical_root)
            && tokio::fs::metadata(&index_path)
                .await
                .is_ok_and(|metadata| metadata.is_file())
        {
            return Ok(Some(Resolved::File(index_path)));
        }
    }
    Ok(Some(Resolved::Directory(canonical)))
}

pub fn sanitize_uri(uri: &str) -> std::result::Result<PathBuf, StatusCode> {
    let path = uri.split('?').next().unwrap_or(uri);
    let decoded = percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut result = PathBuf::new();
    for component in Path::new(decoded.as_ref()).components() {
        match component {
            Component::Normal(value) => {
                if value.to_string_lossy().contains(['\0', '\\']) {
                    return Err(StatusCode::BAD_REQUEST);
                }
                result.push(value);
            }
            Component::CurDir | Component::RootDir => {}
            _ => return Err(StatusCode::FORBIDDEN),
        }
    }
    if decoded.contains('\0') {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(result)
}

pub async fn serve(
    session: &mut Session,
    path: &Path,
    head: bool,
    view: &RequestStateView,
    location: &crate::modules::location::Location,
    state: &crate::core::http::RequestState,
    mime: &MimeConfig,
) -> Result<()> {
    let ssi = assert_ssi(location, path, mime);
    if ssi.is_some() && !head {
        return serve_through_ssi(session, path, view, location, state, mime).await;
    }
    let metadata = tokio::fs::metadata(path).await.map_err(internal)?;
    if !metadata.is_file() {
        return Err(Error::explain(
            ErrorType::InternalError,
            "resolved path is not a file",
        ));
    }
    let file_len = metadata.len();
    let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
    let etag = make_etag(&metadata);
    let request_headers = &view.headers;
    if not_modified(request_headers, &etag, modified) {
        let mut response = ResponseHeader::build(StatusCode::NOT_MODIFIED, None)?;
        insert(&mut response, ETAG.as_str(), &etag)?;
        insert(
            &mut response,
            LAST_MODIFIED.as_str(),
            &httpdate::fmt_http_date(modified),
        )?;
        apply_filters(&mut response, view, location, state)?;
        session
            .write_response_header(Box::new(response), true)
            .await?;
        return Ok(());
    }

    // `ngx_http_range_filter`: `max_ranges 0` disables the filter, and a location-level
    // setting overrides the server one.
    let max_ranges = location
        .get::<crate::modules::core_conf::MaxRanges>()
        .copied()
        .unwrap_or_default();
    let range = request_headers
        .get(RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_range_with_limit(value, file_len, &max_ranges));
    let (status, start, body_len) = match range {
        Some((start, end)) => (StatusCode::PARTIAL_CONTENT, start, end - start + 1),
        None => (StatusCode::OK, 0, file_len),
    };
    let mut response = ResponseHeader::build(status, None)?;
    insert(
        &mut response,
        CONTENT_TYPE.as_str(),
        &content_type(path, mime),
    )?;
    insert(
        &mut response,
        CONTENT_LENGTH.as_str(),
        &body_len.to_string(),
    )?;
    insert(&mut response, ETAG.as_str(), &etag)?;
    insert(
        &mut response,
        LAST_MODIFIED.as_str(),
        &httpdate::fmt_http_date(modified),
    )?;
    insert(&mut response, "Accept-Ranges", "bytes")?;
    // `r->gzip_vary` (`gzip_static on`) makes every response from this location vary.
    if crate::modules::gzip_static::varies(location) {
        crate::modules::gzip::filter::add_vary(&mut response, "Accept-Encoding");
    }
    if let Some((start, end)) = range {
        insert(
            &mut response,
            CONTENT_RANGE.as_str(),
            &format!("bytes {start}-{end}/{file_len}"),
        )?;
    }
    apply_filters(&mut response, view, location, state)?;

    // `ngx_http_gunzip_filter_module` / `ngx_http_gzip_filter_module` run after the header
    // filters and need the whole body, so the file is read before it is written.
    if encode::enabled(location) {
        let bytes = if head {
            Vec::new()
        } else {
            read_range(path, start, body_len).await?
        };
        return relay_encoded(
            session,
            response,
            encode::Body::new(bytes),
            view,
            location,
            state,
            head,
        )
        .await;
    }

    session
        .write_response_header(Box::new(response), head || body_len == 0)
        .await?;
    if head || body_len == 0 {
        return Ok(());
    }

    let mut file = File::open(path).await.map_err(internal)?;
    file.seek(std::io::SeekFrom::Start(start))
        .await
        .map_err(internal)?;
    let mut limited = file.take(body_len);
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    loop {
        let count = limited.read(&mut buffer).await.map_err(internal)?;
        if count == 0 {
            break;
        }
        session
            .write_response_body(Some(Bytes::copy_from_slice(&buffer[..count])), false)
            .await?;
    }
    session.finish_body().await?;
    Ok(())
}

/// Write a response whose body goes through the encoding filters (`gunzip`, then `gzip`).
///
/// The header was already rewritten by `add_header`; the filters update `Content-Encoding`,
/// `Content-Length`, `Vary` and the validators in place.
async fn relay_encoded(
    session: &mut Session,
    mut response: ResponseHeader,
    mut payload: crate::modules::filters::encode::Body,
    view: &RequestStateView,
    location: &crate::modules::location::Location,
    state: &crate::core::http::RequestState,
    head: bool,
) -> Result<()> {
    crate::modules::filters::encode::apply(
        &mut response,
        &mut payload,
        view,
        location,
        state,
        head,
    )
    .map_err(internal)?;
    let empty = head || payload.is_empty();
    if !empty {
        response
            .insert_header("Content-Length", payload.len().to_string())
            .ok();
    }
    session
        .write_response_header(Box::new(response), empty)
        .await?;
    if !empty {
        session
            .write_response_body(Some(Bytes::from(payload.bytes)), true)
            .await?;
    }
    Ok(())
}

/// Serve a pre-compressed file (`ngx_http_gzip_static_module`).
///
/// The `.gz` file's own metadata names the representation: its `Content-Length`, `ETag` and
/// `Last-Modified` are sent, and `Content-Encoding: gzip` says how to read it. A `HEAD`
/// request stops after the header.
#[allow(clippy::too_many_arguments)]
pub async fn serve_precompressed(
    session: &mut Session,
    path: &Path,
    metadata: &std::fs::Metadata,
    head: bool,
    view: &RequestStateView,
    location: &crate::modules::location::Location,
    state: &crate::core::http::RequestState,
) -> Result<()> {
    let len = metadata.len();
    let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
    let etag = make_etag(metadata);
    let mut response = ResponseHeader::build(StatusCode::OK, None)?;
    // `ngx_http_set_content_type` uses the *uncompressed* URI's extension, so the type comes
    // from the requested path, not from `.gz`.
    let (original, _) = (path, ());
    let requested = original
        .to_string_lossy()
        .trim_end_matches(".gz")
        .to_string();
    let content_type = mime_guess::from_path(&requested)
        .first_or_octet_stream()
        .to_string();
    insert(&mut response, CONTENT_TYPE.as_str(), &content_type)?;
    insert(&mut response, CONTENT_LENGTH.as_str(), &len.to_string())?;
    insert(&mut response, ETAG.as_str(), &etag)?;
    insert(
        &mut response,
        LAST_MODIFIED.as_str(),
        &httpdate::fmt_http_date(modified),
    )?;
    insert(&mut response, "Content-Encoding", "gzip")?;
    insert(&mut response, "Accept-Ranges", "bytes")?;
    // `r->gzip_vary = 1` for `gzip_static on`; `always` serves the file regardless.
    crate::modules::gzip::filter::add_vary(&mut response, "Accept-Encoding");
    apply_filters(&mut response, view, location, state)?;
    session
        .write_response_header(Box::new(response), head || len == 0)
        .await?;
    if head || len == 0 {
        return Ok(());
    }
    let mut file = File::open(path).await.map_err(internal)?;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    loop {
        let count = file.read(&mut buffer).await.map_err(internal)?;
        if count == 0 {
            break;
        }
        session
            .write_response_body(Some(Bytes::copy_from_slice(&buffer[..count])), false)
            .await?;
    }
    session.finish_body().await?;
    Ok(())
}

/// Read `len` bytes at `start` (`ngx_read_file` over the response range).
async fn read_range(path: &Path, start: u64, len: u64) -> Result<Vec<u8>> {
    let mut file = File::open(path).await.map_err(internal)?;
    file.seek(std::io::SeekFrom::Start(start))
        .await
        .map_err(internal)?;
    let mut limited = file.take(len);
    let mut body = Vec::with_capacity(len.min(1024 * 1024) as usize);
    limited.read_to_end(&mut body).await.map_err(internal)?;
    Ok(body)
}

/// The SSI configuration when the file is filtered (`ssi on` + a handled content type).
fn assert_ssi(
    location: &crate::modules::location::Location,
    path: &Path,
    mime: &MimeConfig,
) -> Option<crate::modules::filters::ssi::SsiConf> {
    let conf = location.get::<crate::modules::filters::ssi::SsiConf>()?;
    if !conf.enable {
        return None;
    }
    let content_type = content_type(path, mime);
    conf.handles_type(&content_type).then(|| conf.clone())
}

/// Serve a file through the SSI filter: read it, render the directives, relay the result.
///
/// nginx streams the file through `ngx_http_ssi_body_filter`; the rendered output is sent
/// with the same headers minus `Content-Length`, `Accept-Ranges`, `Last-Modified` and
/// `ETag` (the size and validators change with every render).
async fn serve_through_ssi(
    session: &mut Session,
    path: &Path,
    view: &RequestStateView,
    location: &crate::modules::location::Location,
    state: &crate::core::http::RequestState,
    mime: &MimeConfig,
) -> Result<()> {
    let Some(conf) = assert_ssi(location, path, mime) else {
        return Ok(());
    };
    let body = tokio::fs::read(path).await.map_err(internal)?;
    let mut renderer = crate::modules::filters::ssi::Renderer::new(&conf, state);
    let mut resolver = crate::modules::filters::ssi::LocationIncludes {
        conf: &conf,
        location,
        state,
    };
    let rendered = renderer.render(&body, &mut resolver);
    for message in renderer.errors() {
        log::error!("SSI: {message}");
    }
    let mut response = ResponseHeader::build(StatusCode::OK, None)?;
    insert(
        &mut response,
        "Server",
        &crate::modules::core_conf::TokensConf::default()
            .0
            .header_value(),
    )?;
    insert(&mut response, CONTENT_TYPE.as_str(), &content_type(path, mime))?;
    insert(
        &mut response,
        CONTENT_LENGTH.as_str(),
        &rendered.len().to_string(),
    )?;
    apply_filters(&mut response, view, location, state)?;
    session
        .write_response_header(Box::new(response), rendered.is_empty())
        .await?;
    if !rendered.is_empty() {
        session
            .write_response_body(Some(Bytes::from(rendered)), true)
            .await?;
    }
    Ok(())
}

/// `add_header` (headers module) and the Lua header filter for a static response.
fn apply_filters(
    response: &mut ResponseHeader,
    view: &RequestStateView,
    location: &crate::modules::location::Location,
    state: &crate::core::http::RequestState,
) -> Result<()> {
    if let Some(conf) = location.get::<HeadersConf>() {
        conf.apply(response, view).map_err(internal)?;
    }
    if let Some(hook) = location
        .get::<LuaConf>()
        .and_then(|conf| conf.header_filter.as_ref())
    {
        let headers: Vec<(String, String)> = response
            .headers
            .iter()
            .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_string())))
            .collect();
        let outcome = execute_header_filter(hook, response.status.as_u16(), &headers, state)
            .map_err(internal)?;
        if let Some(status) = outcome.status {
            response
                .set_status(StatusCode::from_u16(status).map_err(internal)?)
                .map_err(internal)?;
        }
        for (name, value) in outcome.headers {
            response.insert_header(name, value)?;
        }
    }
    Ok(())
}
pub async fn serve_autoindex(
    session: &mut Session,
    path: &Path,
    uri: &str,
    head: bool,
) -> Result<()> {
    let mut entries = tokio::fs::read_dir(path).await.map_err(internal)?;
    let mut rows = Vec::new();
    while let Some(entry) = entries.next_entry().await.map_err(internal)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        let metadata = entry.metadata().await.map_err(internal)?;
        let suffix = if metadata.is_dir() { "/" } else { "" };
        rows.push((name, suffix, metadata.len(), metadata.modified().ok()));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Index of {0}</title></head><body><h1>Index of {0}</h1><hr><ul>",
        html_escape(uri)
    );
    for (name, suffix, size, modified) in rows {
        body.push_str(&format!(
            "<li><a href=\"{}{}\">{}{}</a> {} bytes {}</li>\n",
            html_escape(&name),
            suffix,
            html_escape(&name),
            suffix,
            size,
            modified.map(httpdate::fmt_http_date).unwrap_or_default()
        ));
    }
    body.push_str("</ul><hr></body></html>\n");
    let mut response = ResponseHeader::build(StatusCode::OK, None)?;
    insert(
        &mut response,
        CONTENT_TYPE.as_str(),
        "text/html; charset=utf-8",
    )?;
    insert(
        &mut response,
        CONTENT_LENGTH.as_str(),
        &body.len().to_string(),
    )?;
    session
        .write_response_header(Box::new(response), head)
        .await?;
    if !head {
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
    }
    Ok(())
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Content type resolution, in Nginx order: configured `types`, the built-in streaming
/// types, then the `mime_guess` table, then `default_type`.
fn content_type(path: &Path, mime: &MimeConfig) -> String {
    if let Some(configured) = mime.content_type(path) {
        return configured.to_string();
    }
    if let Some(extension) = path.extension().and_then(|value| value.to_str()) {
        match extension.to_ascii_lowercase().as_str() {
            "m3u8" => return "application/vnd.apple.mpegurl".to_string(),
            "mpd" => return "application/dash+xml".to_string(),
            "ts" => return "video/mp2t".to_string(),
            "m4s" => return "video/iso.segment".to_string(),
            _ => {}
        }
    }
    MimeGuess::from_path(path)
        .first_raw()
        .map(str::to_string)
        .unwrap_or_else(|| {
            if mime.default_type.is_empty() {
                "application/octet-stream".to_string()
            } else {
                mime.default_type.clone()
            }
        })
}

fn make_etag(metadata: &Metadata) -> String {
    let timestamp = metadata
        .modified()
        .unwrap_or(UNIX_EPOCH)
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("\"{:x}-{:x}\"", metadata.len(), timestamp)
}

fn not_modified(headers: &HeaderMap, etag: &str, modified: SystemTime) -> bool {
    if let Some(value) = headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        return value.split(',').any(|candidate| {
            let candidate = candidate.trim();
            candidate == "*" || candidate == etag || candidate.strip_prefix("W/") == Some(etag)
        });
    }
    headers
        .get(IF_MODIFIED_SINCE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| httpdate::parse_http_date(value).ok())
        .is_some_and(|since| {
            modified.duration_since(since).unwrap_or_default().as_secs() == 0 || since >= modified
        })
}

/// `ngx_http_range_parse` for tests and single-range callers.
#[cfg(test)]
fn parse_range(value: &str, len: u64) -> Option<(u64, u64)> {
    parse_range_with_limit(value, len, &crate::modules::core_conf::MaxRanges::default())
}

/// `ngx_http_range_parse` with the `max_ranges` bound: too many ranges means "ignore Range"
/// (`max_ranges 0` disables ranges entirely).
fn parse_range_with_limit(
    value: &str,
    len: u64,
    max_ranges: &crate::modules::core_conf::MaxRanges,
) -> Option<(u64, u64)> {
    let range = value.strip_prefix("bytes=")?;
    let count = range.split(',').filter(|part| !part.trim().is_empty()).count();
    if !max_ranges.allows(count.max(1)) {
        return None;
    }
    if range.contains(',') {
        // A server may ignore Range; ignoring multi-range avoids multipart overhead.
        return None;
    }
    let (start, end) = range.split_once('-')?;
    if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        if suffix == 0 || len == 0 {
            return None;
        }
        return Some((len.saturating_sub(suffix), len - 1));
    }
    let start: u64 = start.parse().ok()?;
    if start >= len {
        return None;
    }
    let end = if end.is_empty() {
        len - 1
    } else {
        end.parse::<u64>().ok()?.min(len - 1)
    };
    (start <= end).then_some((start, end))
}

fn insert(response: &mut ResponseHeader, name: &str, value: &str) -> Result<()> {
    response.insert_header(name.to_string(), value.to_string())
}

fn internal(error: impl std::fmt::Display) -> Box<Error> {
    Error::explain(ErrorType::InternalError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_mapping_replaces_the_location_prefix() {
        let root = Path::new("/srv");
        assert_eq!(
            MapMode::Root.map(root, "/a/b.css"),
            Some(PathBuf::from("/srv/a/b.css"))
        );
        // `alias /www/acmvue/` on `location ~ ^/index.php/(.*)/VueMain/(.*)` keeps the URI.
        assert_eq!(
            MapMode::AliasAll.map(root, "/index.php/x"),
            Some(PathBuf::from("/srv/index.php/x"))
        );
        // `alias /data/` on `location /static/` drops the prefix.
        assert_eq!(
            MapMode::Alias { prefix_len: 8 }.map(root, "/static/app.js"),
            Some(PathBuf::from("/srv/app.js"))
        );
    }

    #[test]
    fn range_supports_normal_open_and_suffix_forms() {
        assert_eq!(parse_range("bytes=2-5", 10), Some((2, 5)));
        assert_eq!(parse_range("bytes=7-", 10), Some((7, 9)));
        assert_eq!(parse_range("bytes=-3", 10), Some((7, 9)));
        assert_eq!(parse_range("bytes=-30", 10), Some((0, 9)));
        assert_eq!(parse_range("bytes=20-30", 10), None);
        assert_eq!(parse_range("bytes=0-1,4-5", 10), None);
    }

    #[test]
    fn traversal_is_rejected_after_percent_decoding() {
        assert_eq!(sanitize_uri("/safe/../secret"), Err(StatusCode::FORBIDDEN));
        assert_eq!(sanitize_uri("/%2e%2e/secret"), Err(StatusCode::FORBIDDEN));
        assert_eq!(
            sanitize_uri("/safe/file.txt").unwrap(),
            PathBuf::from("safe/file.txt")
        );
    }

    #[test]
    fn media_types() {
        let mime = MimeConfig::default();
        assert_eq!(
            content_type(Path::new("a.m3u8"), &mime),
            "application/vnd.apple.mpegurl"
        );
        assert_eq!(
            content_type(Path::new("a.mpd"), &mime),
            "application/dash+xml"
        );
        assert_eq!(content_type(Path::new("a.ts"), &mime), "video/mp2t");
    }

    #[test]
    fn configured_types_and_default_type_win() {
        let mut mime = MimeConfig {
            default_type: "application/x-custom".to_string(),
            ..MimeConfig::default()
        };
        mime.types
            .insert("txt".to_string(), "text/x-note".to_string());
        assert_eq!(content_type(Path::new("note.TXT"), &mime), "text/x-note");
        assert_eq!(
            content_type(Path::new("blob.unknown-ext"), &mime),
            "application/x-custom"
        );
    }
}
