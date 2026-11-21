//! `ngx_http_static_module`: static files, `try_files`, `index`, `autoindex` and
//! `root`.
//!
//! Large media files (HLS segments, DASH fragments, MP4) are streamed in fixed-size
//! chunks; only a single byte range is honored, which is exactly what players request.

use crate::core::value::{parse_on_off, resolve_path};
use crate::core::variables::Template;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::gzip_static;
use crate::modules::PROVIDERS;
use crate::modules::ctx::ModuleCtx;
use crate::modules::location::LocationConf;
use crate::modules::static_files::file::{MapMode, Resolved, resolve_in, serve, serve_autoindex};
use anyhow::Result;
use http::{Method, StatusCode};
use pingora_core::Result as PingoraResult;
use std::path::PathBuf;

pub mod file;

pub const MODULE_NAME: &str = "ngx_http_static_module";

#[derive(Clone, Debug, Default)]
pub struct StaticConf {
    pub root: Option<PathBuf>,
    /// `alias path;`: replaces the location prefix (or the whole URI for a regex location)
    /// with `path`, per `ngx_http_map_uri_to_path`.
    pub alias: Option<PathBuf>,
    pub index: Option<Vec<String>>,
    pub try_files: Option<Vec<Template>>,
    pub autoindex: Option<bool>,
}

impl LocationConf for StaticConf {}

pub struct StaticModule;

impl Module for StaticModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            spec("root", parse_root),
            spec("alias", parse_alias),
            spec("index", parse_index),
            spec("try_files", parse_try_files),
            spec("autoindex", parse_autoindex),
        ]
    }
}

type Handler = fn(&mut crate::modules::DirectiveView<'_>) -> Result<()>;

fn spec(name: &'static str, handler: Handler) -> DirectiveSpec {
    DirectiveSpec {
        name,
        contexts: &[Context::Http, Context::Server, Context::Location],
        handler,
    }
}

fn parse_root(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let root = resolve_path(view.base_dir, &directive.args[0]);
    view.update_conf::<StaticConf>(|conf| conf.root = Some(root))
}

/// `alias path;`: the URI prefix is dropped and `path` is used instead of `root`.
fn parse_alias(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let alias = resolve_path(view.base_dir, &directive.args[0]);
    view.update_conf::<StaticConf>(|conf| conf.alias = Some(alias))
}

fn parse_index(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.has_block() || directive.args.is_empty() {
        return Err(directive.error("expected one or more index files"));
    }
    let index = directive.args.clone();
    view.update_conf::<StaticConf>(|conf| conf.index = Some(index))
}

fn parse_try_files(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.has_block() || directive.args.len() < 2 {
        return Err(directive.error("expected try_files file ... fallback;"));
    }
    let candidates = directive
        .args
        .iter()
        .map(|value| Template::parse(value))
        .collect::<anyhow::Result<Vec<_>>>()
        .map_err(|error| directive.error(format!("invalid try_files value: {error}")))?;
    view.update_conf::<StaticConf>(|conf| conf.try_files = Some(candidates))
}

fn parse_autoindex(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let enabled = parse_on_off(directive, &directive.args[0])?;
    view.update_conf::<StaticConf>(|conf| conf.autoindex = Some(enabled))
}

/// Serve the request from the filesystem when this location has a `root`.
///
/// Returns `true` when a response was written. The caller runs the header filter chain
/// for that response afterwards where possible.
pub async fn handle(ctx: &mut ModuleCtx<'_>) -> PingoraResult<bool> {
    let Some(conf) = ctx.location.get::<StaticConf>() else {
        return Ok(false);
    };
    // `ngx_http_map_uri_to_path`: `alias` replaces the location prefix, `root` is prepended.
    // A regex location with `alias` appends the whole URI (`alias == NGX_MAX_SIZE_T_VALUE`).
    let (root, mode) = match (&conf.alias, &conf.root) {
        (Some(alias), _) => {
            let prefix = ctx.prefix.clone();
            // A regex location (`~ …`, `~* …`) aliases the whole URI; a prefix location
            // drops its own pattern (`ngx_http_map_uri_to_path`).
            let bare = prefix.trim();
            let mode = if bare.starts_with('~') || bare.starts_with('^') {
                MapMode::AliasAll
            } else if let Some(rest) = bare.strip_prefix("^~") {
                MapMode::Alias {
                    prefix_len: rest.trim().len(),
                }
            } else if let Some(rest) = bare.strip_prefix('=') {
                MapMode::Alias {
                    prefix_len: rest.trim().len(),
                }
            } else {
                MapMode::Alias {
                    prefix_len: bare.len(),
                }
            };
            (alias.clone(), mode)
        }
        (None, Some(root)) => (root.clone(), MapMode::Root),
        (None, None) => return Ok(false),
    };
    let uri = ctx.state.request.path.clone();
    // `ngx_http_gzip_static_handler` runs before the static handler in the content phase
    // (`NGX_HTTP_CONTENT_PHASE` handlers are tried in order).
    if gzip_static::try_serve(ctx, &root, &mode, &uri)
        .await
        .map_err(crate::core::http_core::engine_error)?
    {
        return Ok(true);
    }

    let method = ctx.session.req_header().method.clone();
    if method != Method::GET && method != Method::HEAD {
        crate::modules::respond::text(
            ctx.session,
            StatusCode::METHOD_NOT_ALLOWED,
            "405 Method Not Allowed\n",
            &[],
        )
        .await?;
        return Ok(true);
    }
    let candidates: Vec<String> = conf
        .try_files
        .as_ref()
        .map(|list| {
            list.iter()
                .map(|template| ctx.state.eval(template))
                .collect()
        })
        .unwrap_or_else(|| vec![uri.clone()]);
    let mut fallback = StatusCode::NOT_FOUND;
    for candidate in candidates {
        if let Some(code) = candidate.strip_prefix('=') {
            if let Ok(code) = code.parse::<u16>() {
                fallback = StatusCode::from_u16(code).unwrap_or(StatusCode::NOT_FOUND);
            }
            continue;
        }
        match resolve_in(&root, mode.clone(), &uri, &candidate, conf.index.as_deref()).await {
            Ok(Some(Resolved::File(path))) => {
                let snapshot = ctx.state.clone_for_headers();
                let location = ctx.location.clone();
                let state = ctx.state.clone_for_headers().into_state(PROVIDERS);
                let mime = ctx.mime.clone();
                serve(
                    ctx.session,
                    &path,
                    method == Method::HEAD,
                    &snapshot,
                    &location,
                    &state,
                    &mime,
                )
                .await?;
                return Ok(true);
            }

            Ok(Some(Resolved::Directory(path))) => {
                if !uri.ends_with('/') {
                    let query = ctx
                        .session
                        .req_header()
                        .uri
                        .query()
                        .map(|query| format!("?{query}"))
                        .unwrap_or_default();
                    crate::modules::respond::text(
                        ctx.session,
                        StatusCode::MOVED_PERMANENTLY,
                        "301 Moved Permanently\n",
                        &[("Location".to_string(), format!("{uri}/{query}"))],
                    )
                    .await?;
                    return Ok(true);
                }
                if conf.autoindex.unwrap_or(false) {
                    serve_autoindex(ctx.session, &path, &uri, method == Method::HEAD).await?;
                    return Ok(true);
                }
                fallback = StatusCode::FORBIDDEN;
            }
            Ok(None) => {}
            Err(status) => fallback = status,
        }
    }
    let body = format!(
        "{}\n",
        fallback.canonical_reason().unwrap_or("Request failed")
    );
    crate::modules::respond::text(ctx.session, fallback, &body, &[]).await?;
    Ok(true)
}
