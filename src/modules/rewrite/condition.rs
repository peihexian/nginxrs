//! `if` conditions and the `set` action (`ngx_http_rewrite_module`).
//!
//! Nginx compiles the `if` block into the same rewrite script as its siblings, prefixed by a
//! jump (`ngx_http_script_if_code`) and a condition (`ngx_http_rewrite_if_condition`); the
//! actions inside the block run only when the condition holds. The Rust model keeps the
//! action list of the block next to the condition instead:
//!
//! | nginx | here |
//! |---|---|
//! | `$var` | [`Condition::Variable`] |
//! | `$var = value` / `$var != value` | [`Condition::Equal`] / [`Condition::NotEqual`] |
//! | `$var ~ re` / `~*` / `!~` / `!~*` | [`Condition::Match`] |
//! | `-f`, `!-f`, `-d`, `-e`, `-x` … | [`Condition::File`] |
//! | `set $var value` | [`Action::Set`] |
//! | `rewrite`, `return`, `break`, nested `if` | [`Action`] variants |
//!
//! `ngx_http_rewrite_value` compares a literal right-hand side numerically when it parses as
//! a number (`$a = 0` is true for an empty `$a`), which [`value_matches`] reproduces.

use crate::core::http::RequestState;
use crate::core::variables::Template;
use crate::modules::rewrite::{ReturnAction, RewriteFlag, RewriteRule};
use regex::Regex;
use std::path::Path;

/// `ngx_http_script_file_op_e`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOp {
    /// `-f`
    Plain,
    /// `-d`
    Dir,
    /// `-e`
    Exists,
    /// `-x`
    Exec,
}

impl FileOp {
    pub fn parse(value: &str) -> Option<(bool, Self)> {
        let (negative, rest) = match value.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, value),
        };
        let op = match rest {
            "-f" => FileOp::Plain,
            "-d" => FileOp::Dir,
            "-e" => FileOp::Exists,
            "-x" => FileOp::Exec,
            _ => return None,
        };
        Some((negative, op))
    }

    /// `ngx_http_script_file_code`: the `stat` test for `path`.
    pub fn matches(&self, path: &Path) -> bool {
        let Ok(metadata) = std::fs::metadata(path) else {
            return false;
        };
        match self {
            FileOp::Plain => metadata.is_file(),
            FileOp::Dir => metadata.is_dir(),
            FileOp::Exists => true,
            // A shell-style "is executable" test is unavailable on every platform nginxrs
            // runs on (Windows has no mode bits); an existing file is the closest portable
            // answer.
            FileOp::Exec => metadata.is_file(),
        }
    }
}

/// One `if` condition.
#[derive(Clone, Debug)]
pub enum Condition {
    /// `if ($var)`: true when the value is non-empty and not `0`.
    Variable(Template),
    /// `if ($var = value)`.
    Equal { left: Template, right: Template },
    /// `if ($var != value)`.
    NotEqual { left: Template, right: Template },
    /// `if ($var ~* re)` and friends.
    Match {
        left: Template,
        regex: Regex,
        negative: bool,
    },
    /// `if (-f file)` and friends.
    File {
        path: Template,
        op: FileOp,
        negative: bool,
    },
}

/// An action inside an `if` block or at the location level.
#[derive(Clone, Debug)]
pub enum Action {
    /// `set $var value`
    Set { name: String, value: Template },
    /// `rewrite regex replacement [flag]`
    Rewrite(RewriteRule),
    /// `return status [text]`
    Return(ReturnAction),
    /// `break`
    Break,
    /// An `if` block: its actions run when the condition holds.
    If {
        condition: Condition,
        actions: Vec<Action>,
    },
}

/// `ngx_http_rewrite_value` truthiness: non-empty and not `"0"`.
pub fn is_true(value: &[u8]) -> bool {
    !value.is_empty() && value != b"0"
}

/// Compare a variable value with a configured value (`ngx_http_script_equal_code`).
///
/// A right-hand side that parses as an integer is compared numerically, so `$x = 0` matches an
/// empty `$x` exactly as nginx does (`ngx_atoi` succeeds on both).
pub fn value_matches(left: &[u8], right: &[u8]) -> bool {
    if let (Some(a), Some(b)) = (parse_integer(left), parse_integer(right)) {
        return a == b;
    }
    left == right
}

fn parse_integer(value: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(value).ok()?.trim();
    if text.is_empty() {
        return Some(0);
    }
    text.parse::<i64>().ok()
}

impl Condition {
    /// `ngx_http_rewrite_if_condition` compiled to a runtime test.
    pub fn evaluate(&self, state: &RequestState) -> bool {
        match self {
            Condition::Variable(template) => is_true(template.eval(state).as_bytes()),
            Condition::Equal { left, right } => {
                value_matches(left.eval(state).as_bytes(), right.eval(state).as_bytes())
            }
            Condition::NotEqual { left, right } => {
                !value_matches(left.eval(state).as_bytes(), right.eval(state).as_bytes())
            }
            Condition::Match {
                left,
                regex,
                negative,
            } => regex.is_match(&left.eval(state)) != *negative,
            Condition::File {
                path,
                op,
                negative,
            } => op.matches(Path::new(&path.eval(state))) != *negative,
        }
    }
}

/// Outcome of running a list of actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionOutcome {
    /// Continue with the rest of the list.
    Continue,
    /// `break`: stop this list but keep the location.
    Break,
    /// A `rewrite … last` / `rewrite … break` was applied.
    Rewrite {
        target: String,
        restart: bool,
        /// True for `break` (keep the current location and stop rewriting).
        stop: bool,
    },
    /// A redirect (`rewrite … redirect|permanent`).
    Redirect { status: u16, target: String },
    /// A `return` was reached; it is evaluated later, in the content phase.
    Return(ReturnAction),
}

/// Run `actions` in order, honouring nested `if` blocks and `break`.
pub fn run(actions: &[Action], state: &mut RequestState) -> ActionOutcome {
    for action in actions {
        let outcome = match action {
            Action::Set { name, value } => {
                let evaluated = value.eval(state);
                state.overrides.set(name, evaluated.into_bytes());
                ActionOutcome::Continue
            }
            Action::If { condition, actions } => {
                if condition.evaluate(state) {
                    match run(actions, state) {
                        ActionOutcome::Continue => ActionOutcome::Continue,
                        other => other,
                    }
                } else {
                    ActionOutcome::Continue
                }
            }
            Action::Break => ActionOutcome::Break,
            Action::Return(action) => ActionOutcome::Return(action.clone()),
            Action::Rewrite(rule) => match apply_rewrite(rule, state) {
                Some(outcome) => outcome,
                None => ActionOutcome::Continue,
            },
        };
        if !matches!(outcome, ActionOutcome::Continue) {
            return outcome;
        }
    }
    ActionOutcome::Continue
}

/// `ngx_http_script_regex_start_code` for one `rewrite` rule.
fn apply_rewrite(rule: &RewriteRule, state: &mut RequestState) -> Option<ActionOutcome> {
    let captures = rule.regex.captures(&state.request.path)?;
    let mut expanded = String::new();
    captures.expand(rule.replacement.source(), &mut expanded);
    let mut target = if rule.replacement.is_literal() {
        expanded.clone()
    } else {
        Template::parse(&expanded)
            .map(|template| template.eval(state))
            .unwrap_or(expanded)
    };
    // A trailing `?` in the replacement drops the original query string
    // (`ngx_http_rewrite`: `value[2].data[value[2].len - 1] == '?'`).
    let drop_args = target.ends_with('?');
    if drop_args {
        target.pop();
    }
    if !drop_args && !state.request.args.is_empty() && !target.contains('?') {
        target.push('?');
        target.push_str(&state.request.args);
    }
    Some(match rule.flag {
        RewriteFlag::Last => ActionOutcome::Rewrite {
            target,
            restart: true,
            stop: false,
        },
        RewriteFlag::Break => ActionOutcome::Rewrite {
            target,
            restart: false,
            stop: true,
        },
        RewriteFlag::Redirect => ActionOutcome::Redirect { status: 302, target },
        RewriteFlag::Permanent => ActionOutcome::Redirect { status: 301, target },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::{ConnectionState, RequestLine, RequestState};
    use http::HeaderMap;

    fn state(uri: &str) -> RequestState {
        let request = pingora_http::RequestHeader::build("GET", uri.as_bytes(), None).unwrap();
        RequestState::new(
            ConnectionState {
                listen: "127.0.0.1:80".into(),
                peer_ip: Some("203.0.113.9".parse().unwrap()),
                peer_port: 1000,
                local_ip: Some("127.0.0.1".parse().unwrap()),
                local_port: 80,
                scheme: "http".into(),
                tls: false,
            },
            RequestLine::from_header(&request),
            HeaderMap::new(),
            &[],
        )
    }

    fn template(value: &str) -> Template {
        Template::parse(value).unwrap()
    }

    #[test]
    fn truthiness_and_numeric_comparisons() {
        assert!(!is_true(b""));
        assert!(!is_true(b"0"));
        assert!(is_true(b"on"));
        // `$a = 0` matches an empty variable, as `ngx_atoi` succeeds on both.
        assert!(value_matches(b"", b"0"));
        assert!(value_matches(b"07", b"7"));
        assert!(!value_matches(b"abc", b"0"));
        assert!(value_matches(b"abc", b"abc"));
    }

    #[test]
    fn conditions_cover_every_form() {
        let mut state = state("/index.php/site");
        state.overrides.set("backend", b"http://a".to_vec());
        assert!(Condition::Variable(template("$backend")).evaluate(&state));
        assert!(!Condition::Variable(template("$missing")).evaluate(&state));
        assert!(
            Condition::Equal {
                left: template("$backend"),
                right: template("http://a"),
            }
            .evaluate(&state)
        );
        assert!(
            Condition::NotEqual {
                left: template("$backend"),
                right: template("http://b"),
            }
            .evaluate(&state)
        );
        assert!(
            Condition::Match {
                left: template("$uri"),
                regex: Regex::new("^/index\\.php").unwrap(),
                negative: false,
            }
            .evaluate(&state)
        );
        assert!(
            Condition::Match {
                left: template("$uri"),
                regex: Regex::new("^/Other").unwrap(),
                negative: true,
            }
            .evaluate(&state)
        );
        assert!(
            Condition::File {
                path: template("$document_root$uri"),
                op: FileOp::Plain,
                negative: true,
            }
            .evaluate(&state),
            "a path that never exists makes !-f true"
        );
    }

    #[test]
    fn file_ops_parse_with_negation() {
        assert_eq!(FileOp::parse("-f"), Some((false, FileOp::Plain)));
        assert_eq!(FileOp::parse("!-d"), Some((true, FileOp::Dir)));
        assert_eq!(FileOp::parse("-e"), Some((false, FileOp::Exists)));
        assert_eq!(FileOp::parse("-x"), Some((false, FileOp::Exec)));
        assert_eq!(FileOp::parse("-z"), None);
        assert!(FileOp::Exists.matches(Path::new(".")));
    }

    #[test]
    fn set_and_nested_if_run_in_order() {
        let mut state = state("/");
        let actions = vec![
            Action::Set {
                name: "backend".into(),
                value: template("http://a"),
            },
            Action::If {
                condition: Condition::Equal {
                    left: template("$backend"),
                    right: template("http://a"),
                },
                actions: vec![
                    Action::Set {
                        name: "chosen".into(),
                        value: template("yes"),
                    },
                    Action::Break,
                ],
            },
            Action::Set {
                name: "after".into(),
                value: template("ran"),
            },
        ];
        assert_eq!(run(&actions, &mut state), ActionOutcome::Break);
        assert_eq!(state.variable("chosen").as_deref(), Some("yes"));
        assert_eq!(state.variable("after"), None, "break stops the list");
    }

    #[test]
    fn rewrite_keeps_or_drops_the_query_string() {
        let mut state = state("/lm/index.html?x=1");
        state.request.path = "/lm/index.html".into();
        let rule = RewriteRule {
            regex: Regex::new("^/lm(.*)$").unwrap(),
            replacement: template("$1"),
            flag: RewriteFlag::Break,
        };
        let outcome = apply_rewrite(&rule, &mut state).unwrap();
        assert_eq!(
            outcome,
            ActionOutcome::Rewrite {
                target: "/index.html?x=1".to_string(),
                restart: false,
                stop: true,
            }
        );
        let rule = RewriteRule {
            regex: Regex::new("^/lm(.*)$").unwrap(),
            replacement: template("$1?"),
            flag: RewriteFlag::Last,
        };
        let outcome = apply_rewrite(&rule, &mut state).unwrap();
        assert_eq!(
            outcome,
            ActionOutcome::Rewrite {
                target: "/index.html".to_string(),
                restart: true,
                stop: false,
            }
        );
    }

    #[test]
    fn redirect_rules_report_the_status() {
        let mut state = state("/old");
        let rule = RewriteRule {
            regex: Regex::new("^/old$").unwrap(),
            replacement: template("https://example.test/new"),
            flag: RewriteFlag::Permanent,
        };
        assert_eq!(
            apply_rewrite(&rule, &mut state).unwrap(),
            ActionOutcome::Redirect {
                status: 301,
                target: "https://example.test/new".to_string(),
            }
        );
    }
}
