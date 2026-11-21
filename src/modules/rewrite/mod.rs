//! `ngx_http_rewrite_module`: `rewrite`, `return`, `if`, `set` and `break`.
//!
//! The phase handler applies rewrite rules in declaration order and reports the Nginx
//! rewrite flag through the request state, where the core's phase engine consumes it.
//! `if`/`set`/nested actions are compiled by [`condition`] into [`Action`] lists that the
//! same handler evaluates.
//!
//! | File | Responsibility |
//! |---|---|
//! | `mod.rs` | directives, `rewrite`/`return` parsing, the phase handler |
//! | [`condition`] | `if` conditions, `set`, `break` and their evaluation |

use crate::core::http::RequestState;
use crate::core::syntax::Directive;
use crate::core::value::parse_status;
use crate::core::variables::Template;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::ctx::ModuleCtx;
use crate::modules::location::LocationConf;
use anyhow::Result;
use regex::Regex;

pub mod condition;

use condition::{Action, ActionOutcome, Condition, FileOp};

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnAction {
    pub status: u16,
    pub target: Option<Template>,
}

#[derive(Clone, Debug, Default)]
pub struct RewriteConf {
    pub rules: Vec<RewriteRule>,
    pub return_action: Option<ReturnAction>,
    /// `if` blocks, `set` and `break` in declaration order (`ngx_http_rewrite_if`).
    pub actions: Vec<Action>,
}

impl LocationConf for RewriteConf {}

impl RewriteConf {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.return_action.is_none() && self.actions.is_empty()
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
        let every = &[Context::Http, Context::Server, Context::Location][..];
        let block = &[Context::Server, Context::Location][..];
        vec![
            DirectiveSpec {
                name: "rewrite",
                contexts: every,
                handler: parse_rewrite,
            },
            DirectiveSpec {
                name: "return",
                contexts: every,
                handler: parse_return,
            },
            DirectiveSpec {
                name: "if",
                contexts: block,
                handler: parse_if,
            },
            DirectiveSpec {
                name: "set",
                contexts: block,
                handler: parse_set,
            },
            DirectiveSpec {
                name: "break",
                contexts: block,
                handler: parse_break,
            },
            // Logging knobs accepted for configuration compatibility.
            DirectiveSpec {
                name: "rewrite_log",
                contexts: every,
                handler: parse_flag,
            },
            DirectiveSpec {
                name: "uninitialized_variable_warn",
                contexts: every,
                handler: parse_flag,
            },
        ]
    }
}

/// `if (condition) { … }`: one condition plus the actions inside the block.
fn parse_if(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    let condition = parse_condition(directive)?;
    let mut actions = Vec::new();
    for child in directive.block()? {
        actions.push(parse_action(child)?);
    }
    view.update_conf::<RewriteConf>(|conf| {
        conf.actions.push(Action::If { condition, actions })
    })
}

/// `set $name value;`.
fn parse_set(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    let action = parse_set_action(directive)?;
    view.update_conf::<RewriteConf>(|conf| conf.actions.push(action))
}

fn parse_break(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(0)?;
    view.update_conf::<RewriteConf>(|conf| conf.actions.push(Action::Break))
}

/// `rewrite_log on|off;`, `uninitialized_variable_warn on|off;`.
fn parse_flag(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    crate::core::value::parse_on_off(directive, &directive.args[0])?;
    Ok(())
}

/// `ngx_http_rewrite_if_condition`: `(`, variable, operator, value, `)`.
fn parse_condition(directive: &Directive) -> Result<Condition> {
    if directive.children.is_none() || directive.args.is_empty() {
        return Err(directive.error("invalid condition"));
    }
    // `if ( $a = b )` splits the condition across arguments, so join and trim the parens.
    let mut words = directive.args.clone();
    let first = words.first_mut().expect("checked non-empty");
    if !first.starts_with('(') {
        return Err(directive.error(format!("invalid condition \"{first}\"")));
    }
    *first = first.trim_start_matches('(').to_string();
    let last = words.last_mut().expect("checked non-empty");
    if !last.ends_with(')') {
        return Err(directive.error(format!("invalid condition \"{last}\"")));
    }
    *last = last.trim_end_matches(')').to_string();
    words.retain(|word| !word.is_empty());
    if words.is_empty() {
        return Err(directive.error("invalid condition"));
    }
    let template = |value: &str| {
        Template::parse(value)
            .map_err(|error| directive.error(format!("invalid condition value: {error}")))
    };
    // `-f file`, `!-f file`, `-d file`, `-e file`, `-x file`.
    if words.len() == 2
        && let Some((negative, op)) = FileOp::parse(&words[0])
    {
        return Ok(Condition::File {
            path: template(&words[1])?,
            op,
            negative,
        });
    }
    let head = words[0].clone();
    if !head.starts_with('$') {
        return Err(directive.error(format!("invalid condition \"{head}\"")));
    }
    let left = template(&head)?;
    match words.len() {
        1 => Ok(Condition::Variable(left)),
        3 => apply_operator(directive, left, &words[1], &words[2]),
        _ => Err(directive.error(format!("invalid condition \"{head}\""))),
    }
}

fn apply_operator(
    directive: &Directive,
    left: Template,
    operator: &str,
    right: &str,
) -> Result<Condition> {
    let template = |value: &str| {
        Template::parse(value)
            .map_err(|error| directive.error(format!("invalid condition value: {error}")))
    };
    match operator {
        "=" => Ok(Condition::Equal {
            left,
            right: template(right)?,
        }),
        "!=" => Ok(Condition::NotEqual {
            left,
            right: template(right)?,
        }),
        "~" | "~*" | "!~" | "!~*" => {
            let regex = regex::RegexBuilder::new(right)
                .case_insensitive(operator.ends_with('*'))
                .build()
                .map_err(|error| directive.error(format!("invalid condition regex: {error}")))?;
            Ok(Condition::Match {
                left,
                regex,
                negative: operator.starts_with('!'),
            })
        }
        other => Err(directive.error(format!("unexpected \"{other}\" in condition"))),
    }
}

/// Record an `if` child that nginxrs accepts but cannot apply at request time.
/// Record an `if` child that nginxrs accepts but cannot apply at request time.
fn note_unsupported_if_child(directive: &Directive, name: &str) {
    let message = format!(
        "{}:{}: {} inside an if block is accepted, but nginxrs only evaluates rewrite/return/set/break there and skips it",
        directive.file.display(),
        directive.line,
        name
    );
    log::warn!("{message}");
}

/// Parse a `set $name value;` statement into its action.
fn parse_set_action(directive: &Directive) -> Result<Action> {
    directive.expect_args(2)?;
    let name = directive.args[0]
        .strip_prefix('$')
        .filter(|name| !name.is_empty())
        .ok_or_else(|| directive.error(format!("invalid variable name \"{}\"", directive.args[0])))?;
    let value = Template::parse(&directive.args[1])
        .map_err(|error| directive.error(format!("invalid set value: {error}")))?;
    Ok(Action::Set {
        name: name.to_string(),
        value,
    })
}

/// Parse one statement inside an `if` block.
fn parse_action(directive: &Directive) -> Result<Action> {
    match directive.name.as_str() {
        "set" => parse_set_action(directive),
        "break" => {
            directive.expect_args(0)?;
            Ok(Action::Break)
        }
        "return" => Ok(Action::Return(parse_return_action(directive)?)),
        "rewrite" => Ok(Action::Rewrite(parse_rewrite_rule(directive)?)),
        "if" => {
            let parsed = parse_condition(directive)?;
            let mut actions = Vec::new();
            for child in directive.block()? {
                actions.push(parse_action(child)?);
            }
            Ok(Action::If {
                condition: parsed,
                actions,
            })
        }
        // Other directives inside `if`: nginx allows them in `LIF_CONF`, but their effect
        // depends on module configuration that cannot be rebuilt at request time here, so the
        // statement is accepted and noted instead of being silently ignored.
        other => {
            crate::modules::rewrite::note_unsupported_if_child(directive, other);
            Ok(Action::Break)
        }
    }
}

fn parse_rewrite(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    let rule = parse_rewrite_rule(directive)?;
    view.update_conf::<RewriteConf>(|conf| conf.rules.push(rule))
}

/// `ngx_http_rewrite`: `rewrite regex replacement [last|break|redirect|permanent];`.
fn parse_rewrite_rule(directive: &Directive) -> Result<RewriteRule> {
    if !(2..=3).contains(&directive.args.len()) {
        return Err(
            directive.error("expected rewrite regex replacement [last|break|redirect|permanent];")
        );
    }
    let regex = Regex::new(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid rewrite regex: {error}")))?;
    let flag = match directive.args.get(2).map(String::as_str) {
        // A replacement starting with `http://`, `https://` or `$scheme` redirects even
        // without a flag (`ngx_http_rewrite`), unless `break` says otherwise.
        None => {
            if is_redirect_target(&directive.args[1]) {
                RewriteFlag::Redirect
            } else {
                RewriteFlag::Last
            }
        }
        Some("last") => RewriteFlag::Last,
        Some("break") => RewriteFlag::Break,
        Some("redirect") => RewriteFlag::Redirect,
        Some("permanent") => RewriteFlag::Permanent,
        Some(other) => return Err(directive.error(format!("invalid parameter \"{other}\""))),
    };
    let replacement = Template::parse(&directive.args[1])
        .map_err(|error| directive.error(format!("invalid rewrite target: {error}")))?;
    Ok(RewriteRule {
        regex,
        replacement,
        flag,
    })
}

/// Whether a replacement target implies an external redirect.
fn is_redirect_target(target: &str) -> bool {
    target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("$scheme")
}

fn parse_return(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    let action = parse_return_action(directive)?;
    view.update_conf::<RewriteConf>(|conf| conf.return_action = Some(action))
}

/// `ngx_http_rewrite_return`: `return status [text];` or `return URL;`.
fn parse_return_action(directive: &Directive) -> Result<ReturnAction> {
    directive.expect_args_range(1..=2)?;
    let status = match parse_status(directive, &directive.args[0]) {
        Ok(status) => status,
        Err(_) if directive.args.len() == 1 && is_redirect_target(&directive.args[0]) => 302,
        Err(error) => return Err(error),
    };
    let target = directive
        .args
        .get(1)
        .map(|value| Template::parse(value))
        .transpose()
        .map_err(|error| directive.error(format!("invalid return target: {error}")))?;
    Ok(ReturnAction { status, target })
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

/// Run `if`/`set`/`break` actions for the selected location (`ngx_http_rewrite_handler`
/// with the `ngx_http_script_if_code` blocks compiled into the same script).
pub fn apply_actions(ctx: &mut ModuleCtx<'_>, conf: &RewriteConf) -> Option<RewriteOutcome> {
    match condition::run(&conf.actions, ctx.state) {
        ActionOutcome::Continue | ActionOutcome::Break => None,
        ActionOutcome::Rewrite { target, restart, .. } => Some(RewriteOutcome::Internal {
            target,
            restart,
        }),
        ActionOutcome::Redirect { status, target } => Some(RewriteOutcome::Redirect { status, target }),
        // `return` inside an `if`: recorded exactly like a top-level `return`.
        ActionOutcome::Return(action) => {
            let state = &mut *ctx.state;
            let mut conf_actions = None::<()>;
            let _ = &mut conf_actions;
            let evaluated = evaluate_return(&action, state);
            Some(RewriteOutcome::Return(evaluated))
        }
    }
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
        // `ngx_http_script` removes the trailing `?` of a compiled complex value.
        target: action.target.as_ref().map(|target| target.eval_trimmed(state)),
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
    Internal {
        target: String,
        restart: bool,
    },
    Redirect {
        status: u16,
        target: String,
    },
    /// A `return` inside an `if` block fired.
    Return(EvaluatedReturn),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::syntax::parse_str;

    fn conf(source: &str) -> RewriteConf {
        let mut conf = RewriteConf::default();
        let directives = parse_str(source).unwrap();
        for directive in directives {
            // Parse actions directly, like the directive handlers do.
            let action = parse_action(&directive).unwrap();
            conf.actions.push(action);
        }
        conf
    }

    #[test]
    fn if_set_and_return_are_parsed() {
        let parsed = conf(
            "if ($backend) { return 403; }
             if ($request_uri ~* \"^/index\\.php\") { set $hit 1; }
             break;",
        );
        assert_eq!(parsed.actions.len(), 3);
        assert!(matches!(parsed.actions[0], Action::If { .. }));
        assert!(matches!(parsed.actions[2], Action::Break));
    }

    #[test]
    fn invalid_conditions_are_rejected() {
        for source in ["if (no-dollar) { set $a 1; }", "if ($a = = b) { }"] {
            let directives = parse_str(source).unwrap();
            assert!(parse_action(&directives[0]).is_err(), "{source}");
        }
        // A condition without a block never parses as a directive at all.
        assert!(parse_str("if ($a)").is_err());
    }

    #[test]
    fn redirect_replacement_without_flag_is_a_redirect() {
        let directives = parse_str("rewrite ^(.*)$ https://example.test$1;").unwrap();
        let rule = parse_rewrite_rule(&directives[0]).unwrap();
        assert_eq!(rule.flag, RewriteFlag::Redirect);
        let directives = parse_str("rewrite ^(.*)$ /local$1;").unwrap();
        let rule = parse_rewrite_rule(&directives[0]).unwrap();
        assert_eq!(rule.flag, RewriteFlag::Last);
    }
}
