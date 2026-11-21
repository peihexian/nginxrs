//! Nginx variable support: templates, evaluation, and the per-request state the
//! HTTP core exposes to modules.
//!
//! Variables are evaluated lazily against [`RequestState`]. Modules may register new
//! variables (see [`VariableProvider`]) so later modules, logs and directives can use
//! them without touching the core.

use crate::core::http::RequestState;
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::net::IpAddr;

/// Per-request variable values written by `set` (`ngx_http_script_set_var_code`) and by the
/// SSI `set`/`include set=` commands.
///
/// Values are stored raw because nginx strings are byte strings; `$request_body`, header
/// values and certificates are not required to be UTF-8.
#[derive(Clone, Debug, Default)]
pub struct VariableOverrides {
    values: Vec<(String, Vec<u8>)>,
}

impl VariableOverrides {
    /// Record a value, replacing an earlier one with the same (case-insensitive) name.
    pub fn set(&mut self, name: &str, value: impl Into<Vec<u8>>) {
        let name = name.to_ascii_lowercase();
        let value = value.into();
        if let Some(entry) = self
            .values
            .iter_mut()
            .find(|(existing, _)| *existing == name)
        {
            entry.1 = value;
        } else {
            self.values.push((name, value));
        }
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        let name = name.to_ascii_lowercase();
        self.values
            .iter()
            .find(|(existing, _)| *existing == name)
            .map(|(_, value)| value.as_slice())
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Copy the values, for snapshots used by header filters.
    pub fn clone_values(&self) -> Vec<(String, Vec<u8>)> {
        self.values.clone()
    }

    /// Restore from a snapshot.
    pub fn from_values(values: Vec<(String, Vec<u8>)>) -> Self {
        Self { values }
    }
}

/// A parsed template such as `"$remote_addr:$server_port"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    parts: Vec<Part>,
    source: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Part {
    Literal(String),
    Variable(String),
}

impl Template {
    pub fn parse(source: &str) -> Result<Self> {
        let mut parts = Vec::new();
        let mut literal = String::new();
        let chars: Vec<char> = source.chars().collect();
        let mut index = 0;
        while index < chars.len() {
            let ch = chars[index];
            if ch != '$' {
                literal.push(ch);
                index += 1;
                continue;
            }
            // `$$` is an escaped literal dollar, as in Nginx `log_format`.
            if chars.get(index + 1) == Some(&'$') {
                literal.push('$');
                index += 2;
                continue;
            }
            let (name, next) = parse_variable_name(&chars, index);
            if name.is_empty() {
                literal.push('$');
                index += 1;
                continue;
            }
            if !literal.is_empty() {
                parts.push(Part::Literal(std::mem::take(&mut literal)));
            }
            parts.push(Part::Variable(name));
            index = next;
        }
        if !literal.is_empty() {
            parts.push(Part::Literal(literal));
        }
        Ok(Self {
            parts,
            source: source.to_string(),
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// Drop a trailing query separator: nginx `ngx_http_script_compile` removes the last `?`
    /// of a compiled complex value (`sc +zero`), so `return 301 /target?` produces a target
    /// without a dangling `?`.
    pub fn into_trimmed_bytes(self) -> Vec<u8> {
        let mut bytes = self.source.into_bytes();
        if bytes.last() == Some(&b'?') {
            bytes.pop();
        }
        bytes
    }

    /// Evaluate a variable template through the given request state, then drop the trailing
    /// `?` exactly like [`Template::into_trimmed_bytes`].
    pub fn eval_trimmed(&self, state: &RequestState) -> String {
        let mut value = self.eval(state);
        if value.ends_with('?') {
            value.pop();
        }
        value
    }

    pub fn is_literal(&self) -> bool {
        self.parts
            .iter()
            .all(|part| matches!(part, Part::Literal(_)))
    }

    /// Names referenced in this template, in order.
    pub fn variables(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().filter_map(|part| match part {
            Part::Variable(name) => Some(name.as_str()),
            Part::Literal(_) => None,
        })
    }

    pub fn eval_with(&self, lookup: &mut dyn FnMut(&str) -> Option<String>) -> String {
        let mut output = String::with_capacity(self.source.len());
        for part in &self.parts {
            match part {
                Part::Literal(value) => output.push_str(value),
                // Unset variables expand to an empty string, matching Nginx.
                Part::Variable(name) => output.push_str(&lookup(name).unwrap_or_default()),
            }
        }
        output
    }

    pub fn eval(&self, state: &RequestState) -> String {
        self.eval_with(&mut |name| state.variable(name))
    }

    pub fn eval_once(&self) -> Result<String> {
        if self.is_literal() {
            Ok(self.source.clone())
        } else {
            bail!("expected a constant value, got dynamic \"{}\"", self.source)
        }
    }

    pub fn eval_with_state(&self, state: &RequestState) -> Result<String> {
        Ok(self.eval(state))
    }
}

fn parse_variable_name(chars: &[char], dollar: usize) -> (String, usize) {
    let mut index = dollar + 1;
    if chars.get(index) == Some(&'{') {
        let start = index + 1;
        let mut end = start;
        while end < chars.len() && chars[end] != '}' {
            end += 1;
        }
        if end >= chars.len() {
            return (String::new(), dollar + 1);
        }
        let name: String = chars[start..end].iter().collect();
        return (name, end + 1);
    }
    let start = index;
    while index < chars.len() && (chars[index].is_ascii_alphanumeric() || chars[index] == '_') {
        index += 1;
    }
    (chars[start..index].iter().collect(), index)
}

/// A template which may contain a relative redirect target (`redirect` flag).
#[derive(Clone, Debug)]
pub enum RedirectTarget {
    /// A full URL or path produced by a rewrite rule.
    Template(Template),
}

impl Template {
    pub fn parse_secure(source: &str) -> Result<Self> {
        Self::parse(source).with_context(|| format!("invalid template \"{source}\""))
    }
}

/// Provider object referenced by the compiled [`Variables`] registry.
///
/// Providers are defined as `static` values by modules and borrowed for the life of the
/// process, which keeps request evaluation free of locking.
pub type SharedProvider = &'static dyn VariableProvider;

/// Registry of variables contributed by HTTP modules.
///
/// The core variables are resolved by [`RequestState`] itself; modules add their own
/// (for example `realip_remote_addr` and `realip_remote_port`) here.
#[derive(Default)]
pub struct Variables {
    providers: Vec<(&'static str, SharedProvider)>,
    by_name: HashMap<&'static str, usize>,
}

impl Variables {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider for one variable name. The most recently registered
    /// provider wins, mirroring Nginx module registration order.
    pub fn register(&mut self, name: &'static str, provider: SharedProvider) {
        let index = self.providers.len();
        self.providers.push((name, provider));
        self.by_name.insert(name, index);
    }

    pub fn providers(&self) -> &[(&'static str, SharedProvider)] {
        &self.providers
    }

    pub fn provider(&self, name: &str) -> Option<&SharedProvider> {
        self.by_name
            .get(name)
            .and_then(|index| self.providers.get(*index))
            .map(|(_, provider)| provider)
    }
}

/// Implemented by modules which add variables.
pub trait VariableProvider: std::fmt::Debug + Send + Sync {
    /// Module name for diagnostics.
    fn module(&self) -> &'static str;

    /// Evaluate the variable for this request, or `None` when unset.
    fn get(&self, state: &RequestState) -> Option<String>;

    /// Variable is a string (true) or a packed binary value (false). Nginx uses this
    /// for `log_format escape`/`*_escape` handling.
    fn is_string(&self) -> bool {
        true
    }
}

/// Connection-level facts gathered from a live Pingora session.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub listen: String,
    pub peer_ip: IpAddr,
    pub peer_port: u16,
    pub local_ip: Option<IpAddr>,
    pub local_port: u16,
}

/// Log variable formatting (`log_format ... escape=default|json|none`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EscapeMode {
    Default,
    Json,
    None,
}

impl EscapeMode {
    pub fn render(&self, state: &RequestState, template: &Template) -> String {
        template.eval_with(&mut |name| {
            let value = state.variable(name)?;
            Some(match self {
                EscapeMode::None => value,
                EscapeMode::Default => escape_default(&value),
                EscapeMode::Json => escape_json(&value),
            })
        })
    }
}

fn escape_default(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch < ' ' || ch == '\x7f' => output.push_str(&format!("\\x{:02x}", ch as u32)),
            ch => output.push(ch),
        }
    }
    output
}

fn escape_json(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            ch if ch < ' ' => output.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => output.push(ch),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_variable_syntaxes() {
        let template = Template::parse("/a/${uri}?x=$args$$lit").unwrap();
        let mut map = HashMap::new();
        map.insert("uri".to_string(), "/index".to_string());
        map.insert("args".to_string(), "a=1".to_string());
        assert_eq!(
            template.eval_with(&mut |name| map.get(name).cloned()),
            "/a//index?x=a=1$lit"
        );
    }

    #[test]
    fn unset_variables_expand_to_empty() {
        let template = Template::parse("[$missing]").unwrap();
        assert_eq!(template.eval_with(&mut |_| None), "[]");
        assert!(!template.is_literal());
    }

    #[test]
    fn escape_modes() {
        assert_eq!(escape_default("a\"b\n"), "a\\\"b\\n");
        assert_eq!(escape_json("a\"b"), "\"a\\\"b\"");
    }
}
