//! File resolution, range handling and streaming for the static module.
//!
//! Files are streamed in fixed-size chunks with a seek for ranged requests, so a 4 GiB
//! movie never lands in memory. Path resolution canonicalizes the root and rejects any
//! symlink or `..` escape before opening the file.

use crate::core::http::RequestStateView;
use crate::modules::headers::HeadersConf;
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
    let relative = sanitize_uri(if candidate.is_empty() {
        original_uri
    } else {
        candidate
    })?;
    let canonical_root = tokio::fs::canonicalize(root)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let path = canonical_root.join(relative);
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

    let range = request_headers
        .get(RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_range(value, file_len));
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
    if let Some((start, end)) = range {
        insert(
            &mut response,
            CONTENT_RANGE.as_str(),
            &format!("bytes {start}-{end}/{file_len}"),
        )?;
    }
    apply_filters(&mut response, view, location, state)?;
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

fn parse_range(value: &str, len: u64) -> Option<(u64, u64)> {
    let range = value.strip_prefix("bytes=")?;
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
