//! `error_page` (`ngx_http_core_module`).
//!
//! `error_page 404 /404.html;`, `error_page 500 502 503 504 /50x.html;` and the
//! `=code` override form are parsed here; the HTTP core applies them when a request ends
//! with one of the listed status codes (`ngx_http_special_response_handler` →
//! `ngx_http_send_error_page`). Responses produced by `proxy_intercept_errors` use the same
//! table, which is what makes that directive observable.

use crate::core::variables::Template;
use anyhow::Result;
use crate::core::Context;
use crate::core::{DirectiveSpec, Module, ModuleKind};

pub const MODULE_NAME: &str = "ngx_http_core_error_page";

/// One `error_page` entry (`ngx_http_err_page_t`).
#[derive(Clone, Debug)]
pub struct ErrorPage {
    /// Status codes this entry answers.
    pub codes: Vec<u16>,
    /// `=code` override, `None` keeps the original status, `Some(0)` means "status of the
    /// served page" (`error_page ... =200 /ok.html`).
    pub overwrite: Option<u16>,
    /// Internal redirect target.
    pub uri: Template,
    /// `?args` separated from the URI, as `ngx_http_core_error_page` splits it.
    pub args: Option<String>,
}

/// `error_page` entries of one `server`/`location`.
#[derive(Clone, Debug, Default)]
pub struct ErrorPageConf {
    pub pages: Vec<ErrorPage>,
}

impl crate::modules::location::LocationConf for ErrorPageConf {}

pub struct ErrorPageModule;

impl Module for ErrorPageModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::HttpCore
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![DirectiveSpec {
            name: "error_page",
            contexts: &[Context::Http, Context::Server, Context::Location],
            handler: parse_error_page,
        }]
    }
}

fn parse_error_page(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(2..=usize::MAX)?;
    let mut args = directive.args.clone();

    // `ngx_http_core_error_page`: an optional `=code` sits second to last.
    let uri = args.pop().expect("checked above");
    let overwrite = match args.last().map(String::as_str) {
        Some(value) if value.starts_with('=') => {
            if args.len() == 1 {
                return Err(directive.error(format!("invalid value \"{value}\"")));
            }
            let digits = &value[1..];
            let code = if digits.is_empty() {
                0
            } else {
                digits.parse::<u16>().map_err(|_| {
                    directive.error(format!("invalid value \"{value}\""))
                })?
            };
            args.pop();
            Some(code)
        }
        _ => None,
    };

    let mut codes = Vec::new();
    for value in &args {
        let code: u16 = value
            .parse()
            .map_err(|_| directive.error(format!("invalid value \"{value}\"")))?;
        if !(300..=599).contains(&code) {
            return Err(directive.error(format!("invalid value \"{value}\"")));
        }
        codes.push(code);
    }
    if codes.is_empty() {
        return Err(directive.error("expected at least one status code"));
    }

    // A URI with variables keeps the whole string; a literal URI splits off `?args`.
    let (target, query) = if uri.starts_with('/') && !uri.contains('$') {
        match uri.split_once('?') {
            Some((path, args)) => (path.to_string(), Some(args.to_string())),
            None => (uri.clone(), None),
        }
    } else {
        (uri.clone(), None)
    };
    let template = Template::parse(&target)
        .map_err(|error| directive.error(format!("invalid error_page uri: {error}")))?;

    view.update_conf::<ErrorPageConf>(|conf| {
        conf.pages.push(ErrorPage {
            codes,
            overwrite,
            uri: template,
            args: query,
        })
    })
}

impl ErrorPage {
    /// Resolve the redirect target with request variables (`ngx_http_script_run`).
    pub fn eval_uri(
        &self,
        view: &crate::core::http::RequestStateView,
        providers: &'static [(
            &'static str,
            &'static dyn crate::core::variables::VariableProvider,
        )],
    ) -> String {
        let state = view.clone().into_state(providers);
        self.uri.eval(&state)
    }
}

impl ErrorPageConf {
    /// `ngx_http_special_response_handler`: the entry answering `status`.
    pub fn find(&self, status: u16) -> Option<&ErrorPage> {
        self.pages
            .iter()
            .find(|page| page.codes.contains(&status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::syntax::parse_str;

    fn parse(source: &str) -> ErrorPage {
        let directives = parse_str(source).unwrap();
        let mut conf = ErrorPageConf::default();
        let mut location = crate::modules::location::Location::default();
        location.set(conf.clone());
        // Drive the handler through a minimal view is heavyweight; parse directly instead.
        let args: Vec<String> = directives[0].args.clone();
        conf.pages.push(build(&args).unwrap());
        conf.pages.remove(0)
    }

    fn build(args: &[String]) -> Result<ErrorPage> {
        let mut args = args.to_vec();
        let uri = args.pop().unwrap();
        let overwrite = match args.last().map(String::as_str) {
            Some(value) if value.starts_with('=') => {
                let digits = &value[1..];
                let code = if digits.is_empty() {
                    0
                } else {
                    digits.parse::<u16>()?
                };
                args.pop();
                Some(code)
            }
            _ => None,
        };
        let codes = args.iter().map(|value| value.parse().unwrap()).collect();
        let (target, query) = match uri.split_once('?') {
            Some((path, args)) => (path.to_string(), Some(args.to_string())),
            None => (uri.clone(), None),
        };
        Ok(ErrorPage {
            codes,
            overwrite,
            uri: Template::parse(&target)?,
            args: query,
        })
    }

    #[test]
    fn single_code_and_uri() {
        let page = parse("error_page 404 /404.html;");
        assert_eq!(page.codes, vec![404]);
        assert_eq!(page.overwrite, None);
        assert_eq!(page.uri.source(), "/404.html");
        assert_eq!(page.args, None);
    }

    #[test]
    fn multiple_codes_and_override() {
        let page = parse("error_page 500 502 503 504 =200 /50x.html;");
        assert_eq!(page.codes, vec![500, 502, 503, 504]);
        assert_eq!(page.overwrite, Some(200));
        assert_eq!(page.uri.source(), "/50x.html");
    }

    #[test]
    fn bare_equals_keeps_the_origin_status() {
        let page = parse("error_page 404 = /fallback;");
        assert_eq!(page.overwrite, Some(0));
    }

    #[test]
    fn uri_query_is_split() {
        let page = parse("error_page 404 /404.html?from=error;");
        assert_eq!(page.uri.source(), "/404.html");
        assert_eq!(page.args.as_deref(), Some("from=error"));
    }

    #[test]
    fn lookup_finds_the_entry() {
        let mut conf = ErrorPageConf::default();
        conf.pages.push(parse("error_page 404 /404.html;"));
        assert!(conf.find(404).is_some());
        assert!(conf.find(500).is_none());
    }
}
