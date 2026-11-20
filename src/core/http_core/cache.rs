//! Response caching for `proxy_pass` (`ngx_http_file_cache`).
//!
//! The cache decision happens before the upstream connection (`ngx_http_upstream_cache`)
//! and the store happens once the response headers are known
//! (`ngx_http_upstream_send_response`). Both live here so the proxy exchange stays focused
//! on the request/response conversation.

use super::types::*;
use crate::SERVER_NAME;
use crate::modules::proxy::ProxyConf;
use http::StatusCode;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

pub(crate) struct CacheRequest {
    zone: crate::modules::proxy_cache::CacheZone,
    conf: crate::modules::proxy_cache::CacheConf,
    pub(crate) key: String,
    file: std::path::PathBuf,
}

/// Build the cache lookup for this request, honouring `proxy_cache_methods` and
/// `proxy_cache_bypass`.
pub(crate) fn cache_request_state(
    conf: &ProxyConf,
    session: &Session,
    ctx: &RequestContext,
) -> Option<CacheRequest> {
    let cache = &conf.cache;
    let zone_name = cache.zone.as_ref()?;
    if !cache.caches_method(session.req_header().method.as_str()) {
        return None;
    }
    let zone = match crate::modules::proxy_cache::zone(zone_name) {
        Some(zone) => zone,
        None => {
            log::debug!("proxy_cache: zone {zone_name} is not registered");
            return None;
        }
    };
    let Some(state) = ctx.cache_state_source.as_ref() else {
        log::debug!("proxy_cache: no request snapshot for the cache decision");
        return None;
    };
    // `proxy_cache_bypass`: any non-empty evaluation bypasses the cache (`ngx_http_test_predicates`).
    if cache
        .bypass
        .iter()
        .any(|template| !template.eval(state).is_empty())
    {
        ctx.cache_bypassed.store(true, std::sync::atomic::Ordering::Relaxed);
        return Some(CacheRequest {
            file: zone.file_path(""),
            zone,
            conf: cache.clone(),
            key: String::new(),
        });
    }
    let key = cache.key_template().ok()?.eval(state);
    let file = zone.file_path(&key);
    Some(CacheRequest {
        zone,
        conf: cache.clone(),
        key,
        file,
    })
}

/// `ngx_http_file_cache_open`: read a fresh entry for this request.
pub(crate) fn cache_lookup(request: &CacheRequest) -> Option<crate::modules::proxy_cache::CacheEntry> {
    if request.key.is_empty() {
        return None;
    }
    let bytes = std::fs::read(&request.file).ok()?;
    let entry = crate::modules::proxy_cache::CacheEntry::decode(&bytes)?;
    let now = crate::modules::proxy_cache::now_seconds();
    entry.is_fresh(now).then_some(entry)
}

pub(crate) fn record_cache_state(
    ctx: &RequestContext,
    request: &CacheRequest,
    status: crate::modules::proxy_cache::CacheStatus,
) {
    let mut state = crate::modules::proxy_cache::CacheState {
        status: Some(status),
        key: Some(request.key.clone()),
        file: Some(request.file.clone()),
    };
    if request.key.is_empty() {
        state.status = Some(crate::modules::proxy_cache::CacheStatus::Bypass);
    }
    ctx.cache_status.set(state);
}

/// Serve a stored entry (`ngx_http_file_cache_read` + the normal body pipeline).
pub(crate) async fn serve_cached(
    session: &mut Session,
    entry: &crate::modules::proxy_cache::CacheEntry,
) -> anyhow::Result<()> {
    let mut response = ResponseHeader::build(
        StatusCode::from_u16(entry.status).unwrap_or(StatusCode::OK),
        None,
    )?;
    for (name, value) in &entry.headers {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            let _ = response.append_header(name, value);
        }
    }
    response.insert_header("Server", SERVER_NAME)?;
    response.insert_header("Content-Length", entry.body.len().to_string())?;
    let is_head = session.req_header().method == http::Method::HEAD;
    session
        .write_response_header(Box::new(response), is_head)
        .await?;
    if !is_head {
        session
            .write_response_body(Some(entry.body.clone().into()), true)
            .await?;
    }
    Ok(())
}

/// `ngx_http_file_cache_set_header` + the body: store a response for later hits.
pub(crate) fn cache_store(
    request: &CacheRequest,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) {
    use crate::modules::proxy_cache::CacheEntry;

    // `proxy_no_cache`: a non-empty value keeps the response out of the cache.
    let now = crate::modules::proxy_cache::now_seconds();
    let fresh = crate::modules::proxy_cache::freshness(headers, status, &request.conf, now);
    let Some(valid_until) = fresh else {
        return;
    };
    let etag = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("etag"))
        .map(|(_, value)| value.clone());
    let last_modified = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("last-modified"))
        .map(|(_, value)| value.clone());
    let entry = CacheEntry {
        status,
        headers: headers.to_vec(),
        body: body.to_vec(),
        valid_until,
        stored_at: now,
        etag,
        last_modified,
    };
    if let Some(parent) = request.file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = request.zone;
    let mut temporary = request.file.clone();
    temporary.set_extension("tmp");
    if std::fs::write(&temporary, entry.encode()).is_ok() {
        // `ngx_http_file_cache_set_header`: the entry becomes visible atomically.
        let _ = std::fs::rename(&temporary, &request.file);
    }
}

/// Append `chunk` to the buffering temp file, mirroring
/// `ngx_event_pipe_write_chain_to_temp_file`.
pub(crate) fn spool(buffer: &mut crate::modules::proxy_buffer::ResponseBuffer, chunk: &[u8]) {
    let path = match buffer.temp_file().map(std::path::Path::to_path_buf) {
        Some(path) => path,
        None => {
            let Some(template) = buffer.temp_file_path() else {
                return;
            };
            if let Some(parent) = template.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            buffer.set_temp_file(template.clone());
            template
        }
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = file.write_all(chunk);
    }
}

