//! `ngx_http_gzip_static_module`: serve a pre-compressed `.gz` file.
//!
//! The module is a **content handler** (`NGX_HTTP_CONTENT_PHASE`), not a filter: it is
//! consulted before the static handler and, when the `name.gz` sibling exists and the client
//! accepts gzip, it serves that file with `Content-Encoding: gzip`.
//!
//! ```nginx
//! gzip_static on;      # only for clients that accept gzip
//! gzip_static always;  # unconditionally (the client is told what it gets)
//! gzip_static off;     # default
//! ```
//!
//! `on` sets `r->gzip_vary`, so the response carries `Vary: Accept-Encoding` even when a
//! plain file is sent. A `HEAD` request is answered from the `.gz` file's metadata, and the
//! file's own `ETag`/`Last-Modified` name the compressed representation.

use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use crate::modules::registry::DirectiveView;
use anyhow::Result;

pub const MODULE_NAME: &str = "ngx_http_gzip_static_module";

pub struct GzipStaticModule;

impl Module for GzipStaticModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![DirectiveSpec {
            name: "gzip_static",
            contexts: &[Context::Http, Context::Server, Context::Location],
            handler: parse_enable,
        }]
    }
}

/// `ngx_http_gzip_static_conf_t` (`NGX_HTTP_GZIP_STATIC_ON|OFF|ALWAYS`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Off,
    On,
    Always,
}

impl Mode {
    pub fn enabled(self) -> bool {
        !matches!(self, Mode::Off)
    }
}

impl LocationConf for Mode {
    fn inherit(&self) -> bool {
        true
    }
}

fn parse_enable(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let mode = match directive.args[0].as_str() {
        "on" => Mode::On,
        "off" => Mode::Off,
        "always" => Mode::Always,
        other => {
            return Err(directive.error(format!(
                "invalid value \"{other}\", it must be \"on\", \"off\" or \"always\""
            )));
        }
    };
    view.update_conf::<Mode>(|conf| *conf = mode)?;
    Ok(())
}

/// The location's mode (`off` when the directive is absent).
pub fn mode(location: &crate::modules::location::Location) -> Mode {
    location.get::<Mode>().copied().unwrap_or_default()
}

/// The `.gz` sibling of a mapped path (`ngx_http_map_uri_to_path` + `".gz"`).
pub fn compressed_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".gz");
    std::path::PathBuf::from(name)
}

/// `ngx_http_gzip_static_handler`: try the `.gz` sibling of the mapped path.
///
/// Returns `true` when the response was written (a `.gz` file was served); `false` lets the
/// static handler continue with the plain file.
pub async fn try_serve(
    ctx: &mut crate::modules::ctx::ModuleCtx<'_>,
    root: &std::path::Path,
    mode: &crate::modules::static_files::file::MapMode,
    uri: &str,
) -> anyhow::Result<bool> {
    let location = &ctx.location;
    let enabled = mode_enabled(location);
    if !enabled {
        return Ok(false);
    }
    // `if (r->uri.data[r->uri.len - 1] == ') return NGX_DECLINED;` — a directory URI never
    // gets a `.gz` sibling.
    if uri.ends_with('/') {
        return Ok(false);
    }
    let method = &ctx.session.req_header().method;
    if method != http::Method::GET && method != http::Method::HEAD {
        return Ok(false);
    }
    // `on` requires a client that accepts gzip; `always` does not.
    let accepts = match location.get::<Mode>().copied().unwrap_or_default() {
        Mode::Off => return Ok(false),
        Mode::Always => true,
        Mode::On => {
            let conf = location
                .get::<crate::modules::gzip::conf::GzipConf>()
                .cloned()
                .unwrap_or_default();
            crate::modules::gzip::negotiate::gzip_ok(&conf, &ctx.state)
        }
    };
    // `ngx_http_map_uri_to_path` + ".gz"; the map already checked the URI is safe to join.
    let Some(plain) = mode.map(root, uri) else {
        return Ok(false);
    };
    let candidate = compressed_path(&plain);
    let Ok(metadata) = tokio::fs::metadata(&candidate).await else {
        return Ok(false);
    };
    if !metadata.is_file() {
        return Ok(false);
    }
    if !accepts {
        // `on` with a client that cannot read gzip: the plain file is served, but `Vary`
        // still announces that the answer depends on `Accept-Encoding` (`r->gzip_vary`).
        return Ok(false);
    }
    let head = ctx.session.req_header().method == http::Method::HEAD;
    crate::modules::static_files::file::serve_precompressed(
        ctx.session,
        &candidate,
        &metadata,
        head,
        &ctx.state.clone_for_headers(),
        location,
        &ctx.state,
    )
    .await?;
    Ok(true)
}

fn mode_enabled(location: &crate::modules::location::Location) -> bool {
    location
        .get::<Mode>()
        .copied()
        .unwrap_or_default()
        .enabled()
}

/// `r->gzip_vary = 1` when `gzip_static on` is set for the location: every response from
/// there varies on `Accept-Encoding`, whether the `.gz` file was used or not.
pub fn varies(location: &crate::modules::location::Location) -> bool {
    matches!(
        location.get::<Mode>().copied().unwrap_or_default(),
        Mode::On
    )
}

/// `ngx_http_gzip_ok` decides whether `on` sends the compressed file.
pub fn accepts(
    location: &crate::modules::location::Location,
    state: &crate::core::http::RequestState,
) -> bool {
    match mode(location) {
        Mode::Off => false,
        Mode::Always => true,
        Mode::On => {
            let conf = location
                .get::<crate::modules::gzip::conf::GzipConf>()
                .cloned()
                .unwrap_or_default();
            crate::modules::gzip::negotiate::gzip_ok(&conf, state)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_values() {
        assert!(!Mode::default().enabled());
        assert!(!Mode::Off.enabled());
        assert!(Mode::On.enabled());
        assert!(Mode::Always.enabled());
    }

    #[test]
    fn the_sibling_adds_gz() {
        let path = std::path::Path::new("/srv/www/app.js");
        assert_eq!(
            compressed_path(path),
            std::path::PathBuf::from("/srv/www/app.js.gz")
        );
    }

    #[test]
    fn directives_are_parsed() {
        let registry = crate::modules::Registry::default_modules();
        for (source, expected) in [
            ("gzip_static on;", Mode::On),
            ("gzip_static off;", Mode::Off),
            ("gzip_static always;", Mode::Always),
        ] {
            let directives = crate::core::syntax::parse_str(source).unwrap();
            let mut states: Vec<crate::core::state::StateSlot> = vec![(
                "main",
                crate::core::state::StateInstance::new(crate::config::MainState::default()),
            )];
            let mut location = crate::modules::location::Location::new();
            let mut access = crate::core::state::StateAccess::new(&mut states);
            registry
                .dispatch(
                    &directives[0],
                    Context::Location,
                    std::path::Path::new("."),
                    &mut access,
                    Some(&mut location),
                )
                .unwrap();
            assert_eq!(mode(&location), expected, "{source}");
        }
    }

    #[test]
    fn invalid_values_are_rejected() {
        let registry = crate::modules::Registry::default_modules();
        let directives = crate::core::syntax::parse_str("gzip_static yes;").unwrap();
        let mut states: Vec<crate::core::state::StateSlot> = vec![(
            "main",
            crate::core::state::StateInstance::new(crate::config::MainState::default()),
        )];
        let mut location = crate::modules::location::Location::new();
        let mut access = crate::core::state::StateAccess::new(&mut states);
        assert!(
            registry
                .dispatch(
                    &directives[0],
                    Context::Location,
                    std::path::Path::new("."),
                    &mut access,
                    Some(&mut location),
                )
                .is_err()
        );
    }
}
