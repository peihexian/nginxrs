//! `ngx_http_gunzip_filter_module`: undo a `Content-Encoding: gzip` the client cannot read.
//!
//! `ngx_http_gunzip_header_filter` only acts when
//!
//! * `gunzip on` is set for the location,
//! * the upstream body is `Content-Encoding: gzip`,
//! * and `ngx_http_gzip_ok(r)` says the client does **not** accept gzip.
//!
//! It then drops the `Content-Encoding` header (so the response looks plain), clears
//! `Content-Length`/`Accept-Ranges`, weakens the `ETag` and sets `Vary: Accept-Encoding`.
//! The body filter inflates with `deflateInit2(Z_DEFLATED)` — `inflateInit2(MAX_WBITS + 16)`
//! — so multi-member gzip input works the same way zlib does.

pub mod filter;

use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use crate::modules::registry::DirectiveView;
use anyhow::Result;

pub const MODULE_NAME: &str = "ngx_http_gunzip_filter_module";

pub struct GunzipModule;

impl Module for GunzipModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            DirectiveSpec {
                name: "gunzip",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_enable,
            },
            DirectiveSpec {
                name: "gunzip_buffers",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_buffers,
            },
        ]
    }
}

/// `ngx_http_gunzip_conf_t`.
#[derive(Clone, Debug)]
pub struct GunzipConf {
    pub enabled: bool,
    /// `gunzip_buffers number size`.
    pub buffers: (usize, usize),
}

impl Default for GunzipConf {
    fn default() -> Self {
        // `ngx_http_gunzip_merge_conf`: `(32 4k)` — `(128k / pagesize) pagesize`.
        Self {
            enabled: false,
            buffers: (32, 4096),
        }
    }
}

impl LocationConf for GunzipConf {
    fn inherit(&self) -> bool {
        true
    }
}

fn parse_enable(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = crate::modules::gzip::conf::flag(directive, &directive.args[0])?;
    view.update_conf::<GunzipConf>(|conf| conf.enabled = value)?;
    Ok(())
}

fn parse_buffers(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(2..=2)?;
    let number: usize = directive.args[0]
        .parse()
        .map_err(|_| directive.error(format!("invalid number \"{}\"", directive.args[0])))?;
    let size = crate::core::value::parse_size(directive, &directive.args[1])? as usize;
    view.update_conf::<GunzipConf>(|conf| conf.buffers = (number, size))?;
    Ok(())
}
