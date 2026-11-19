//! `ngx_http_headers_module`: `add_header`, `expires`, `add_trailer`.
//!
//! Responses produced by local modules (static files, `return`, Lua content) pass through
//! the same header chain as proxied responses, so the filter lives here once.

use crate::core::http::RequestStateView;
use crate::core::variables::Template;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use anyhow::Result;
use http::StatusCode;
use pingora_http::ResponseHeader;

pub const MODULE_NAME: &str = "ngx_http_headers_module";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderValue {
    pub name: String,
    pub value: Template,
    /// `add_header ... always`: apply regardless of response status.
    pub always: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeadersConf {
    pub headers: Vec<HeaderValue>,
}

impl LocationConf for HeadersConf {}

impl HeadersConf {
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Add matching headers to a response, following Nginx's status filter
    /// (`200, 201, 204, 206, 301, 302, 303, 304, 307, 308` unless `always`).
    pub fn apply(
        &self,
        response: &mut ResponseHeader,
        view: &RequestStateView,
    ) -> anyhow::Result<()> {
        for header in &self.headers {
            if !header.always && !add_header_allowed(response.status) {
                continue;
            }
            let value = header.value.eval_with(&mut |name| view.variable(name));
            response.insert_header(header.name.clone(), value)?;
        }
        Ok(())
    }
}

pub fn add_header_allowed(status: StatusCode) -> bool {
    matches!(
        status.as_u16(),
        200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308
    )
}

pub struct HeadersModule;

impl Module for HeadersModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![DirectiveSpec {
            name: "add_header",
            contexts: &[Context::Http, Context::Server, Context::Location],
            handler: parse_add_header,
        }]
    }
}

fn parse_add_header(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(2..=3)?;
    let always = match directive.args.get(2).map(String::as_str) {
        None => false,
        Some("always") => true,
        Some(other) => {
            return Err(directive.error(format!("invalid add_header flag {other}")));
        }
    };
    let value = Template::parse(&directive.args[1])
        .map_err(|error| directive.error(format!("invalid add_header value: {error}")))?;
    view.update_conf::<HeadersConf>(|conf| {
        conf.headers.push(HeaderValue {
            name: directive.args[0].clone(),
            value,
            always,
        });
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_filter_matches_nginx() {
        assert!(add_header_allowed(StatusCode::OK));
        assert!(add_header_allowed(StatusCode::NOT_MODIFIED));
        assert!(!add_header_allowed(StatusCode::NOT_FOUND));
        assert!(!add_header_allowed(StatusCode::INTERNAL_SERVER_ERROR));
    }
}
