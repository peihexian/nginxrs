//! `ngx_http_gzip_filter_module`: gzip the response body.
//!
//! | nginx | here |
//! |---|---|
//! | `ngx_http_gzip_conf_t` | [`conf::GzipConf`] |
//! | `ngx_http_gzip_header_filter` | [`filter::header_decision`] |
//! | `ngx_http_gzip_body_filter` (zlib streaming) | [`filter::compress`] (flate2) |
//! | `ngx_http_gzip_ratio` | [`variable`] |
//! | `ngx_http_gzip_ok` (`ngx_http_core_module.c`) | [`negotiate`] |
//!
//! The C module is a body filter over an `ngx_chain_t`: it starts zlib lazily, may buffer the
//! first bytes (`postpone_gzipping`) and emits flushes. Responses here are assembled from
//! memory or from a file before they are written, so the whole body can be compressed in one
//! pass; the observable rules — when gzip applies, which headers change, `$gzip_ratio` — are
//! kept identical.

pub mod conf;
pub mod filter;
pub mod negotiate;

use crate::core::variables::VariableProvider;
use crate::core::{DirectiveSpec, Module, ModuleKind};
use crate::modules::registry::DirectiveView;
use anyhow::Result;

pub const MODULE_NAME: &str = "ngx_http_gzip_filter_module";

pub struct GzipModule;

impl Module for GzipModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        conf::directives()
    }

    fn variables(&self) -> Vec<(&'static str, &'static dyn VariableProvider)> {
        vec![("gzip_ratio", &GZIP_RATIO)]
    }
}

pub const GZIP_RATIO: RatioVariable = RatioVariable;

/// `$gzip_ratio`: `zin / zout` with two decimals, or "not found" when nothing was compressed.
#[derive(Debug)]
pub struct RatioVariable;

impl VariableProvider for RatioVariable {
    fn module(&self) -> &'static str {
        MODULE_NAME
    }

    fn get(&self, state: &crate::core::http::RequestState) -> Option<String> {
        let ratio = state.get::<filter::GzipRatio>()?;
        Some(ratio.render())
    }
}

/// `gzip on|off;` and friends all live in [`conf`].
pub fn parse_flag(view: &mut DirectiveView<'_>, set: fn(&mut conf::GzipConf, bool)) -> Result<()> {
    let directive = view.directive;
    let value = conf::flag(directive, &directive.args[0])?;
    view.update_conf::<conf::GzipConf>(|conf| set(conf, value))?;
    Ok(())
}
