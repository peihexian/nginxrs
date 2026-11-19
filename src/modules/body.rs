//! `ngx_http_body_module`: request body handling for Lua and local handlers.
//!
//! Upstream proxying streams bodies through Pingora untouched; this module only
//! provides bounded body reading for modules that process the body themselves.

use crate::core::value::parse_size;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use anyhow::Result;

pub const MODULE_NAME: &str = "ngx_http_body_module";

#[derive(Clone, Debug, Default)]
pub struct BodyConf {
    /// `client_max_body_size`; `None` means the Nginx default of 1m.
    pub max_size: Option<u64>,
}

impl BodyConf {
    pub fn limit(&self) -> u64 {
        self.max_size.unwrap_or(1024 * 1024)
    }
}

impl LocationConf for BodyConf {}

pub struct BodyModule;

impl Module for BodyModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![DirectiveSpec {
            name: "client_max_body_size",
            contexts: &[Context::Http, Context::Server, Context::Location],
            handler: parse_client_max_body_size,
        }]
    }
}

fn parse_client_max_body_size(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let size = parse_size(directive, &directive.args[0])?;
    view.update_conf::<BodyConf>(|conf| conf.max_size = Some(size))
}
