//! SSI expressions: value expansion and `if` expressions.
//!
//! `ngx_http_ssi_evaluate_string` and `ngx_http_ssi_if` combined: an SSI parameter value is a
//! small unix-shell-like string where `$var`, `${var}` and regex captures (`$1`) expand, `\`
//! escapes the next character and quotes group a literal. `if`/`elif` compare the left and
//! right side either literally (`=`, `!=`) or as a regex match (`= /re/`, `!= /re/`).

pub mod template;

use crate::core::http::RequestState;

/// Dollar sign: the variable-reference marker.
const DOLLAR: u8 = 0x24;
/// `{` of a bracketed variable name.
const BRACE_OPEN: u8 = 0x7b;
/// `}` closing a bracketed variable name.
const BRACE_CLOSE: u8 = 0x7d;
/// Double quote.
const QUOTE_DOUBLE: u8 = 0x22;
/// Single quote.
const QUOTE_SINGLE: u8 = 0x27;
/// Backslash used as the escape character.
const BACKSLASH: u8 = 0x5c;

/// Values visible to one rendered page: SSI `set` results and regex captures.
///
/// `ngx_http_ssi_get_variable` looks these up before nginx's own variable system, so a `set`
/// shadows a same-named nginx variable for the rest of the page.
#[derive(Clone, Debug, Default)]
pub struct Variables {
    values: Vec<(String, Vec<u8>)>,
    /// Captures of the last successful `if` regex: index 0 is the whole match.
    captures: Vec<Option<Vec<u8>>>,
}

impl Variables {
    pub fn set(&mut self, name: &str, value: Vec<u8>) {
        let name = name.to_ascii_lowercase();
        if let Some((_, existing)) = self
            .values
            .iter_mut()
            .find(|(candidate, _)| *candidate == name)
        {
            *existing = value;
        } else {
            self.values.push((name, value));
        }
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        let name = name.to_ascii_lowercase();
        // `$0`…`$9` resolve to captures before the variable list (`ngx_http_ssi_get_variable`).
        if name.len() == 1 && name.as_bytes()[0].is_ascii_digit() {
            let index = usize::from(name.as_bytes()[0] - b'0');
            return self.captures.get(index).and_then(|value| value.as_deref());
        }
        self.values
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, value)| value.as_slice())
    }

    /// Record the captures of one successful regex match.
    pub fn set_captures(&mut self, captures: Vec<Option<Vec<u8>>>) {
        self.captures = captures;
    }
}

/// Flags for [`evaluate`].
#[derive(Clone, Copy, Debug, Default)]
pub struct EvalFlags {
    /// `NGX_HTTP_SSI_ADD_PREFIX`: prepend the directory of the current URI to a relative value.
    pub add_prefix: bool,
    /// `NGX_HTTP_SSI_ADD_ZERO`: append one NUL byte (used before anchoring a regex).
    pub add_zero: bool,
}

/// Errors from evaluating a value (`NGX_HTTP_SSI_ERROR`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalError {
    /// `the closing bracket in "%V" variable is missing`.
    MissingBracket(String),
    /// `invalid variable name in "%V"`.
    InvalidVariable(String),
}

impl EvalError {
    pub fn message(&self) -> String {
        match self {
            EvalError::MissingBracket(name) => {
                format!("the closing bracket in \"{name}\" variable is missing")
            }
            EvalError::InvalidVariable(name) => format!("invalid variable name in \"{name}\""),
        }
    }
}

/// `ngx_http_ssi_evaluate_string` on raw bytes.
pub fn evaluate(
    text: &[u8],
    state: &RequestState,
    variables: &Variables,
    flags: EvalFlags,
) -> Result<Vec<u8>, EvalError> {
    let mut out: Vec<u8> = Vec::with_capacity(text.len());
    if flags.add_prefix && text.first() != Some(&b'/') {
        out.extend_from_slice(uri_directory(&state.request.path).as_bytes());
    }
    let mut index = 0;
    while index < text.len() {
        if text[index] != DOLLAR {
            index += copy_literal(text, index, &mut out);
            continue;
        }
        index += 1;
        let bracketed = text.get(index) == Some(&BRACE_OPEN);
        if bracketed {
            index += 1;
        }
        let name_start = index;
        let mut closed = !bracketed;
        while index < text.len() {
            let byte = text[index];
            if bracketed && byte == BRACE_CLOSE {
                closed = true;
                index += 1;
                break;
            }
            if byte.is_ascii_alphanumeric() || byte == b'_' {
                index += 1;
                continue;
            }
            break;
        }
        if !closed {
            return Err(EvalError::MissingBracket(
                String::from_utf8_lossy(&text[name_start..]).into_owned(),
            ));
        }
        // The closing brace is not part of the name.
        let name_end = if bracketed { index - 1 } else { index };
        if name_end == name_start {
            return Err(EvalError::InvalidVariable(
                String::from_utf8_lossy(text).into_owned(),
            ));
        }
        let name = String::from_utf8_lossy(&text[name_start..name_end]).into_owned();
        if let Some(value) = variables.get(&name) {
            out.extend_from_slice(value);
        } else if let Some(value) = state.variable_bytes(&name) {
            out.extend_from_slice(&value);
        }
        // An unset variable contributes nothing (`vv->not_found` → `continue`).
    }
    if flags.add_zero {
        out.push(0);
    }
    Ok(out)
}

/// Copy literal text starting at `index`; returns how many bytes were consumed.
///
/// Stops at the next unescaped `$`. Quotes group a literal run and are removed, as the nginx
/// script compiler does (`$backend = "http://a"` compares `http://a`). A backslash escapes the
/// next character and is kept in front of regex-significant characters (`\.`, `\d`).
pub fn copy_literal(text: &[u8], index: usize, out: &mut Vec<u8>) -> usize {
    let mut cursor = index;
    let mut quoting = false;
    while cursor < text.len() {
        let byte = text[cursor];
        if byte == BACKSLASH {
            match text.get(cursor + 1).copied() {
                Some(next) => {
                    let escapes_self =
                        next == BACKSLASH || next == QUOTE_SINGLE || next == QUOTE_DOUBLE;
                    if !escapes_self && next != DOLLAR {
                        out.push(BACKSLASH);
                    }
                    out.push(next);
                    cursor += 2;
                }
                None => {
                    out.push(BACKSLASH);
                    cursor += 1;
                }
            }
            quoting = false;
            continue;
        }
        if byte == QUOTE_DOUBLE || byte == QUOTE_SINGLE {
            quoting = !quoting;
            cursor += 1;
            continue;
        }
        if byte == DOLLAR && !quoting {
            break;
        }
        out.push(byte);
        cursor += 1;
    }
    cursor - index
}

/// `r->uri` without its last component, used by `NGX_HTTP_SSI_ADD_PREFIX`.
pub fn uri_directory(uri: &str) -> String {
    match uri.rfind('/') {
        Some(index) => uri[..=index].to_string(),
        None => String::new(),
    }
}

/// Result of evaluating an `if`/`elif` expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfResult {
    pub matched: bool,
    /// Captures from the regex form (`= /re/`), if it ran.
    pub captures: Option<Vec<Option<Vec<u8>>>>,
}

/// `ngx_http_ssi_if`: evaluate `expr` and decide whether the block is emitted.
///
/// The expression is `left`, `left = right`, `left != right`, or the regex forms
/// `left = /re/` / `left != /re/` (case-sensitive, no flags).
pub fn evaluate_if(
    expr: &[u8],
    state: &RequestState,
    variables: &Variables,
) -> Result<IfResult, String> {
    // `left` is the leading run of `[A-Za-z0-9 $ {} _ " ']`, lowercased as the C code does.
    let mut index = 0;
    let mut lowered = Vec::with_capacity(expr.len());
    while index < expr.len() {
        let byte = expr[index];
        if byte.is_ascii_uppercase() {
            lowered.push(byte.to_ascii_lowercase());
        } else if byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(
                byte,
                DOLLAR | BRACE_OPEN | BRACE_CLOSE | QUOTE_DOUBLE | QUOTE_SINGLE | b'_'
            )
        {
            lowered.push(byte);
        } else {
            break;
        }
        index += 1;
    }
    while index < expr.len() && expr[index] == b' ' {
        index += 1;
    }
    let left = evaluate(&lowered, state, variables, EvalFlags::default())
        .map_err(|error| error.message())?;
    if index == expr.len() {
        return Ok(IfResult {
            matched: !left.is_empty(),
            captures: None,
        });
    }
    let negative = if expr[index] == b'=' {
        index += 1;
        false
    } else if expr.len() > index + 1 && expr[index] == b'!' && expr[index + 1] == b'=' {
        index += 2;
        true
    } else {
        return Err(invalid(expr));
    };
    while index < expr.len() && expr[index] == b' ' {
        index += 1;
    }
    let mut tail = &expr[index..];
    let regex_form = tail.len() >= 2 && tail[0] == b'/' && *tail.last().unwrap() == b'/';
    let mut flags = EvalFlags::default();
    if regex_form {
        tail = &tail[1..tail.len() - 1];
        flags.add_zero = true;
    } else if tail.len() > 1 && tail[0] == BACKSLASH && tail[1] == b'/' {
        tail = &tail[1..];
    }
    let right = evaluate(tail, state, variables, flags).map_err(|error| error.message())?;
    if !regex_form {
        return Ok(IfResult {
            matched: (left == right) != negative,
            captures: None,
        });
    }
    // nginx NUL-terminates the pattern, so a NUL ends it; the subject is the evaluated left.
    let pattern_end = right.iter().position(|byte| *byte == 0).unwrap_or(right.len());
    let pattern = String::from_utf8_lossy(&right[..pattern_end]).into_owned();
    let haystack = String::from_utf8_lossy(&left).into_owned();
    let Ok(regex) = regex::Regex::new(&pattern) else {
        log::error!("SSI: invalid regex \"{pattern}\"");
        return Err(invalid(expr));
    };
    match regex.captures(&haystack) {
        Some(captures) => {
            let values = (0..captures.len())
                .map(|group| captures.get(group).map(|m| m.as_str().as_bytes().to_vec()))
                .collect();
            Ok(IfResult { matched: !negative, captures: Some(values) })
        }
        None => Ok(IfResult { matched: negative, captures: Some(Vec::new()) }),
    }
}

fn invalid(expr: &[u8]) -> String {
    format!("invalid expression in \"{}\"", String::from_utf8_lossy(expr))
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

    fn eval(text: &str, variables: &Variables) -> String {
        let state = state("/dir/page.html");
        let value = evaluate(text.as_bytes(), &state, variables, EvalFlags::default()).unwrap();
        String::from_utf8(value).unwrap()
    }

    #[test]
    fn variables_and_escapes() {
        let mut variables = Variables::default();
        variables.set("name", b"x&y".to_vec());
        assert_eq!(eval("$name", &variables), "x&y");
        assert_eq!(eval("${name}!", &variables), "x&y!");
        assert_eq!(eval("\\$name", &variables), "$name");
        // A backslash before an ordinary character is kept, as nginx does.
        assert_eq!(eval("a\\d", &variables), "a\\d");
        // Unset variables expand to nothing.
        assert_eq!(eval("[${missing}]", &variables), "[]");
        // nginx request variables are visible too.
        assert_eq!(eval("$request_method", &variables), "GET");
        // A quoted literal keeps its content but loses the quotes.
        assert_eq!(eval("\"x y\"", &variables), "x y");
    }

    #[test]
    fn prefix_flag_prepends_the_current_directory() {
        let state = state("/dir/page.html");
        let variables = Variables::default();
        let flags = EvalFlags {
            add_prefix: true,
            add_zero: false,
        };
        let relative = evaluate(b"part.html", &state, &variables, flags).unwrap();
        assert_eq!(relative, b"/dir/part.html".to_vec());
        let absolute = evaluate(b"/abs.html", &state, &variables, flags).unwrap();
        assert_eq!(absolute, b"/abs.html".to_vec());
    }

    #[test]
    fn invalid_variables_are_reported() {
        let state = state("/");
        let variables = Variables::default();
        assert_eq!(
            evaluate(b"${name", &state, &variables, EvalFlags::default()),
            Err(EvalError::MissingBracket("name".to_string()))
        );
        assert!(matches!(
            evaluate(b"$", &state, &variables, EvalFlags::default()),
            Err(EvalError::InvalidVariable(_))
        ));
    }

    #[test]
    fn if_expression_forms() {
        let state = state("/");
        let mut variables = Variables::default();
        variables.set("backend", b"http://a".to_vec());
        let ok = |expr: &str| {
            evaluate_if(expr.as_bytes(), &state, &variables)
                .unwrap()
                .matched
        };
        assert!(ok("$backend"));
        assert!(!ok("$missing"));
        assert!(ok("$backend = http://a"));
        assert!(!ok("$backend = http://b"));
        assert!(ok("$backend != http://b"));
        // Regex form: `/re/` needs both slashes.
        assert!(ok("$backend = /a/"));
        assert!(!ok("$backend = /z/"));
        assert!(ok("$backend != /z/"));
    }

    #[test]
    fn if_regex_captures_are_available() {
        let state = state("/");
        let mut variables = Variables::default();
        variables.set("uri", b"/index.php/x/y".to_vec());
        let result = evaluate_if(b"$uri = /^\\/index\\.php\\/(.*)/", &state, &variables).unwrap();
        assert!(result.matched);
        variables.set_captures(result.captures.unwrap());
        assert_eq!(variables.get("1"), Some(&b"x/y"[..]));
        assert_eq!(eval("$1", &variables), "x/y");
    }
}
