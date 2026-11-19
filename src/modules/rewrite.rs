//! `ngx_http_rewrite_module`: `rewrite` and `return`.
//!
//! The phase handler applies rewrite rules in declaration order and reports the Nginx
//! rewrite flag through the request state, where the core's phase engine consumes it.

use crate::core::http::RequestState;
use crate::core::value::parse_status;
use crate::core::variables::Template;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::ctx::ModuleCtx;
use crate::modules::location::LocationConf;
use anyhow::Result;
use regex::Regex;

pub const MODULE_NAME: &str = "ngx_http_rewrite_module";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewriteFlag {
    Last,
    Break,
    Redirect,
    Permanent,
}

#[derive(Clone, Debug)]
pub struct RewriteRule {
    pub regex: Regex,
    pub replacement: Template,
    pub flag: RewriteFlag,
}

#[derive(Clone, Debug)]
pub struct ReturnAction {
    pub status: u16,
    pub target: Option<Template>,
}

#[derive(Clone, Debug, Default)]
pub struct RewriteConf {
    pub rules: Vec<RewriteRule>,
    pub return_action: Option<ReturnAction>,
}

impl LocationConf for RewriteConf {}

impl RewriteConf {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.return_action.is_none()
    }
}

/// Rewrite flags for the current request, consumed by the phase engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewriteRequestFlag {
    Rewritten,
    Last,
    Break,
    Redirect(u16),
}

pub struct RewriteModule;

impl Module for RewriteModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            DirectiveSpec {
                name: "rewrite",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_rewrite,
            },
            DirectiveSpec {
                name: "return",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_return,
            },
        ]
    }
}

fn parse_rewrite(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if !(2..=3).contains(&directive.args.len()) {
        return Err(
            directive.error("expected rewrite regex replacement [last|break|redirect|permanent];")
        );
    }
    let regex = Regex::new(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid rewrite regex: {error}")))?;
    let flag = match directive.args.get(2).map(String::as_str) {
        None | Some("last") => RewriteFlag::Last,
        Some("break") => RewriteFlag::Break,
        Some("redirect") => RewriteFlag::Redirect,
        Some("permanent") => RewriteFlag::Permanent,
        Some(other) => return Err(directive.error(format!("invalid rewrite flag {other}"))),
    };
    let replacement = Template::parse(&directive.args[1])
        .map_err(|error| directive.error(format!("invalid rewrite target: {error}")))?;
    view.update_conf::<RewriteConf>(|conf| {
        conf.rules.push(RewriteRule {
            regex,
            replacement,
            flag,
        });
    })
}

fn parse_return(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=2)?;
    let status = parse_status(directive, &directive.args[0])?;
    if !matches!(
        status,
        301 | 302 | 303 | 307 | 308 | 200 | 400..=499 | 500..=599
    ) && (300..=399).contains(&status)
    {
        return Err(directive.error("unsupported redirect status for return"));
    }
    let target = directive
        .args
        .get(1)
        .map(|value| Template::parse(value))
        .transpose()
        .map_err(|error| directive.error(format!("invalid return target: {error}")))?;
    view.update_conf::<RewriteConf>(|conf| {
        conf.return_action = Some(ReturnAction { status, target });
    })
}

/// Apply the rewrite phase for the selected location.
///
/// Regex capture groups (`$1`…) are expanded by the regex engine, then variables
/// (`$uri`, ...) are evaluated against the request state. The caller consumes the
/// outcome to restart configuration lookup (`last`) or emit a redirect.
pub fn apply_rewrites(
    ctx: &mut ModuleCtx<'_>,
    conf: &RewriteConf,
) -> Result<Option<RewriteOutcome>> {
    for rule in &conf.rules {
        let Some(captures) = rule.regex.captures(&ctx.state.request.path) else {
            continue;
        };
        let mut expanded = String::new();
        captures.expand(rule.replacement.source(), &mut expanded);
        let target = evaluate_template(&rule.replacement, &expanded, ctx.state);
        return Ok(Some(match rule.flag {
            RewriteFlag::Redirect => RewriteOutcome::Redirect {
                status: 302,
                target: keep_original_args(target, &ctx.state.request.args),
            },
            RewriteFlag::Permanent => RewriteOutcome::Redirect {
                status: 301,
                target: keep_original_args(target, &ctx.state.request.args),
            },
            RewriteFlag::Last => RewriteOutcome::Internal {
                target: keep_original_args(target, &ctx.state.request.args),
                restart: true,
            },
            RewriteFlag::Break => RewriteOutcome::Internal {
                target,
                restart: false,
            },
        }));
    }
    Ok(None)
}

/// Nginx keeps the original query string when a rewrite target has none.
fn keep_original_args(target: String, args: &str) -> String {
    if args.is_empty() || target.contains('?') {
        target
    } else {
        format!("{target}?{args}")
    }
}

/// The evaluated `return` directive of the selected location, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedReturn {
    pub status: u16,
    pub target: Option<String>,
}

/// The `return` directive of the selected location, unevaluated.
///
/// Nginx evaluates `return`'s text when the response is generated (in the content phase),
/// after PREACCESS handlers such as `limit_req` have run, so variables like
/// `$limit_req_status` observe their final value. Keep the template and evaluate it later
/// with [`evaluate_return`].
pub fn return_spec(conf: &RewriteConf) -> Option<ReturnAction> {
    conf.return_action.clone()
}

/// Evaluate a previously returned [`ReturnAction`] against the finished request state.
pub fn evaluate_return(action: &ReturnAction, state: &RequestState) -> EvaluatedReturn {
    EvaluatedReturn {
        status: action.status,
        target: action.target.as_ref().map(|target| state.eval(target)),
    }
}

/// Same as [`evaluate_return`] for snapshots taken after the phase engine finished.
pub fn evaluate_return_view(
    action: &ReturnAction,
    view: &crate::core::http::RequestStateView,
) -> EvaluatedReturn {
    EvaluatedReturn {
        status: action.status,
        target: action
            .target
            .as_ref()
            .map(|target| target.eval_with(&mut |name| view.variable(name))),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RewriteOutcome {
    Internal { target: String, restart: bool },
    Redirect { status: u16, target: String },
}

/// Evaluate a replacement which already had `$1`… expanded, resolving Nginx variables.
fn evaluate_template(template: &Template, expanded: &str, state: &RequestState) -> String {
    if template.is_literal() {
        // Literal replacement; the regex engine still expanded `$1` style references.
        return expanded.to_string();
    }
    Template::parse(expanded)
        .map(|parsed| state.eval(&parsed))
        .unwrap_or_else(|_| expanded.to_string())
}
