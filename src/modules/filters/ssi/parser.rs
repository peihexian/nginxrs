//! The SSI tokenizer: a direct port of `ngx_http_ssi_parse`.
//!
//! The C implementation is a byte-level state machine that can pause between buffers
//! (`NGX_AGAIN`) and resume exactly where it stopped. The Rust version runs on the whole
//! response body instead, which keeps the same state transitions minus the buffering
//! bookkeeping: the caller simply gets every complete directive in order, plus the rule that
//! incomplete or malformed directives are reported as [`ParseError::Incomplete`] or
//! [`ParseError::Malformed`].
//!
//! Behaviour that matters to real pages:
//!
//! * `<!--#` starts a directive only when it appears literally; `<!--` followed by anything
//!   else is ordinary text (states `ssi_comment0_state` … `ssi_sharp_state`).
//! * A directive is `<!--#command param="value" … -->`; `-->` may be preceded by spaces.
//! * Parameter values are double-quoted, single-quoted or bare symbols; `\` escapes the next
//!   character inside quotes and bare values.
//! * Values are capped at `ssi_value_length` bytes, keys at 32 bytes, commands at 32 bytes.

/// Maximum command name length (`NGX_HTTP_SSI_COMMAND_LEN`).
pub const COMMAND_LEN: usize = 32;
/// Maximum parameter name length (`NGX_HTTP_SSI_PARAM_LEN`).
pub const PARAM_LEN: usize = 32;
/// Maximum number of parameters per command (`NGX_HTTP_SSI_MAX_PARAMS`).
pub const MAX_PARAMS: usize = 16;

/// One parsed parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub value: Vec<u8>,
}

/// One parsed directive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directive {
    pub name: String,
    pub params: Vec<Param>,
    /// Byte range of the whole directive in the input, for diagnostics.
    pub range: std::ops::Range<usize>,
}

/// Result of scanning a body.
#[derive(Debug, Default)]
pub struct Parsed {
    /// Directives in source order.
    pub directives: Vec<Directive>,
    /// First problem met, if any; later directives are still returned when scanning could
    /// continue, exactly like the C filter which only emits one message per broken tag.
    pub error: Option<ParseError>,
    /// The broken tag's span: nginx replaces this text with rrmsg.
    pub error_range: Option<std::ops::Range<usize>>,
}

/// Why a directive could not be parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The body ended inside a directive (unterminated tag).
    Incomplete,
    /// A malformed tag: `-->` missing, unknown parameter syntax, value too long, …
    Malformed(String),
    /// The parser could not keep up with the configured limits.
    Limit(String),
}

impl ParseError {
    pub fn message(&self) -> String {
        match self {
            ParseError::Incomplete => "unterminated SSI directive".to_string(),
            ParseError::Malformed(reason) => reason.clone(),
            ParseError::Limit(reason) => reason.clone(),
        }
    }
}

/// Scanning stops with an error unless the tag terminator was found (`skip_tag`).
type ScanResult<T> = Result<T, (ParseError, Option<usize>)>;

/// Scan `body`, returning every complete directive and the first parse problem.
pub fn scan(body: &[u8], value_len: usize) -> Parsed {
    let mut parsed = Parsed::default();
    let mut pos = 0usize;
    while pos < body.len() {
        let Some(offset) = find_directive_start(&body[pos..]) else {
            break;
        };
        let start = pos + offset;
        match parse_directive(body, start, value_len) {
            Ok((directive, end)) => {
                parsed.directives.push(directive);
                pos = end;
            }
            Err((error, resume)) => {
                if parsed.error.is_none() {
                    parsed.error = Some(error);
                    parsed.error_range = Some(start..resume.unwrap_or(body.len()));
                }
                match resume {
                    Some(next) => pos = next,
                    None => break,
                }
            }
        }
    }
    parsed
}

/// `ssi_start_state` … `ssi_sharp_state`: the next literal `<!--#`.
fn find_directive_start(body: &[u8]) -> Option<usize> {
    let mut index = 0;
    while index + 4 <= body.len() {
        match body[index..].iter().position(|byte| *byte == b'<') {
            Some(offset) => index += offset,
            None => return None,
        }
        if body[index..].starts_with(b"<!--") {
            if body.get(index + 4) == Some(&b'#') {
                return Some(index);
            }
            // `ssi_sharp_state`: a `<!--` that is not a directive keeps the four characters.
            index += 4;
        } else {
            index += 1;
        }
    }
    None
}

/// Parse one directive starting at `start` (which points at `<!--#`).
///
/// Returns the directive and the position just past `-->`. On error the second tuple item
/// is where scanning should resume, or `None` when the body ended inside the tag.
fn parse_directive(
    body: &[u8],
    start: usize,
    value_len: usize,
) -> ScanResult<(Directive, usize)> {
    match parse_directive_inner(body, start, value_len) {
        Ok(parsed) => Ok(parsed),
        Err((error, resume)) => {
            log::error!(
                "SSI: {} (in \"{}\")",
                error.message(),
                String::from_utf8_lossy(&body[start..])
            );
            Err((error, resume))
        }
    }
}

fn parse_directive_inner(
    body: &[u8],
    start: usize,
    value_len: usize,
) -> ScanResult<(Directive, usize)> {
    // `ssi_precommand_state`: spaces/CR/LF/TAB after `#`.
    let mut pos = start + 5;
    while matches!(body.get(pos), Some(b' ') | Some(b'\r') | Some(b'\n') | Some(b'\t')) {
        pos += 1;
    }
    // `ssi_command_state`: the name ends at whitespace or at the `--` that closes the tag, so
    // a command may legitimately end in `-` (`else-->`, `endif-->`).
    let command_start = pos;
    while let Some(byte) = body.get(pos) {
        match byte {
            b' ' | b'\r' | b'\n' | b'\t' => break,
            b'-' if body.get(pos + 1) == Some(&b'-') => break,
            _ => pos += 1,
        }
    }
    if pos - command_start > COMMAND_LEN {
        return Err((
            ParseError::Limit(format!(
                "the \"{}...\" SSI command is too long",
                String::from_utf8_lossy(&body[command_start..command_start + COMMAND_LEN])
            )),
            skip_tag(body, pos),
        ));
    }
    if pos == command_start {
        return Err((
            ParseError::Malformed("empty SSI command".to_string()),
            skip_tag(body, pos),
        ));
    }
    let name = String::from_utf8_lossy(&body[command_start..pos]).into_owned();

    let mut params = Vec::new();
    // `ssi_preparam_state` and friends.
    let mut end = None;
    while pos < body.len() {
        match body[pos] {
            b' ' | b'\r' | b'\n' | b'\t' => pos += 1,
            b'-' => {
                // `ssi_comment_end0_state` / `ssi_comment_end1_state`: expect `->`.
                if body.get(pos + 1) == Some(&b'-') && body.get(pos + 2) == Some(&b'>') {
                    end = Some(pos + 3);
                    break;
                }
                return Err((
                    ParseError::Malformed(format!("unexpected \"-\" symbol in \"{name}\" SSI command")),
                    skip_tag(body, pos),
                ));
            }
            _ => {
                let (param, next) = parse_param(body, pos, &name, value_len)?;
                if params.len() >= MAX_PARAMS {
                    return Err((
                        ParseError::Limit(format!("too many SSI command parameters: \"{name}\"")),
                        skip_tag(body, next),
                    ));
                }
                params.push(param);
                pos = next;
            }
        }
    }
    let Some(end) = end else {
        return Err((ParseError::Incomplete, None));
    };
    Ok((
        Directive {
            name,
            params,
            range: start..end,
        },
        end,
    ))
}

/// `ssi_param_state` … `ssi_postparam_state`: one `name=value` pair.
fn parse_param(
    body: &[u8],
    start: usize,
    command: &str,
    value_len: usize,
) -> ScanResult<(Param, usize)> {
    let mut pos = start;
    // Key, up to `=`, whitespace or `-`.
    while let Some(byte) = body.get(pos) {
        match byte {
            b'=' | b' ' | b'\r' | b'\n' | b'\t' => break,
            b'-' => {
                return Err((
                    ParseError::Malformed(format!(
                        "unexpected \"-\" symbol after \"{}\" parameter in \"{command}\" SSI command",
                        String::from_utf8_lossy(&body[start..pos])
                    )),
                    skip_tag(body, pos),
                ));
            }
            _ => pos += 1,
        }
    }
    let name_end = pos;
    if name_end - start > PARAM_LEN {
        return Err((
            ParseError::Limit(format!(
                "too long \"{}...\" parameter in \"{command}\" SSI command",
                String::from_utf8_lossy(&body[start..start + PARAM_LEN])
            )),
            skip_tag(body, pos),
        ));
    }
    let name_bytes = &body[start..name_end];
    // `ssi_preequal_state`.
    while matches!(body.get(pos), Some(b' ') | Some(b'\r') | Some(b'\n') | Some(b'\t')) {
        pos += 1;
    }
    if body.get(pos) != Some(&b'=') {
        return Err((
            ParseError::Malformed(format!(
                "unexpected symbol after \"{}\" parameter in \"{command}\" SSI command",
                String::from_utf8_lossy(name_bytes)
            )),
            skip_tag(body, pos),
        ));
    }
    pos += 1;
    // `ssi_prevalue_state`.
    while matches!(body.get(pos), Some(b' ') | Some(b'\r') | Some(b'\n') | Some(b'\t')) {
        pos += 1;
    }
    let mut value = Vec::new();
    match body.get(pos).copied() {
        None => return Err((ParseError::Incomplete, None)),
        Some(quote @ (b'"' | b'\'')) => {
            pos += 1;
            loop {
                let Some(byte) = body.get(pos).copied() else {
                    return Err((ParseError::Incomplete, None));
                };
                pos += 1;
                if byte == quote {
                    break;
                }
                if byte == b'\\' {
                    let Some(escaped) = body.get(pos).copied() else {
                        return Err((ParseError::Incomplete, None));
                    };
                    pos += 1;
                    push_value(&mut value, escaped, value_len, command)?;
                } else {
                    push_value(&mut value, byte, value_len, command)?;
                }
            }
        }
        Some(b'-') => {
            return Err((
                ParseError::Malformed(format!(
                    "unexpected \"-\" symbol before value of parameter in \"{command}\" SSI command"
                )),
                skip_tag(body, pos),
            ));
        }
        Some(_) => {
            // `ssi_quoted_symbol_state` without quotes: a bare symbol.
            loop {
                let Some(byte) = body.get(pos).copied() else {
                    return Err((ParseError::Incomplete, None));
                };
                match byte {
                    b' ' | b'\r' | b'\n' | b'\t' => break,
                    b'-' => break,
                    b'\\' => {
                        let Some(escaped) = body.get(pos + 1).copied() else {
                            return Err((ParseError::Incomplete, None));
                        };
                        pos += 2;
                        push_value(&mut value, escaped, value_len, command)?;
                    }
                    _ => {
                        pos += 1;
                        push_value(&mut value, byte, value_len, command)?;
                    }
                }
            }
        }
    }
    Ok((
        Param {
            name: String::from_utf8_lossy(name_bytes).into_owned(),
            value,
        },
        pos,
    ))
}

fn push_value(value: &mut Vec<u8>, byte: u8, value_len: usize, command: &str) -> ScanResult<()> {
    if value.len() >= value_len {
        return Err((
            ParseError::Limit(format!(
                "too long parameter value in \"{command}\" SSI command"
            )),
            None,
        ));
    }
    value.push(byte);
    Ok(())
}

/// Find the end of a broken tag so scanning can continue; `None` means the body ended.
fn skip_tag(body: &[u8], from: usize) -> Option<usize> {
    let mut index = from;
    while index + 3 <= body.len() {
        if &body[index..index + 3] == b"-->" {
            return Some(index + 3);
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(directive: &Directive) -> Vec<(&str, &str)> {
        directive
            .params
            .iter()
            .map(|param| {
                (
                    param.name.as_str(),
                    std::str::from_utf8(&param.value).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn parses_echo_with_variables() {
        let parsed = scan(b"a<!--#echo var=\"uri\" -->b", 255);
        assert_eq!(parsed.error, None);
        assert_eq!(parsed.directives.len(), 1);
        let directive = &parsed.directives[0];
        assert_eq!(directive.name, "echo");
        assert_eq!(params(directive), vec![("var", "uri")]);
    }

    #[test]
    fn comment_without_hash_is_text() {
        let parsed = scan(b"<!-- plain comment --> <!--#endif -->", 255);
        assert_eq!(parsed.directives.len(), 1);
        assert_eq!(parsed.directives[0].name, "endif");
    }

    #[test]
    fn quoted_symbols_and_spaces_are_kept() {
        let parsed = scan(b"<!--#if expr=\"$a = 'x y'\" -->", 255);
        assert_eq!(params(&parsed.directives[0]), vec![("expr", "$a = 'x y'")]);
        let parsed = scan(b"<!--#set var=x value=\"a\\\"b\" -->", 255);
        assert_eq!(params(&parsed.directives[0]), vec![("var", "x"), ("value", "a\"b")]);
    }

    #[test]
    fn bare_value_ends_at_space() {
        let parsed = scan(b"<!--#include virtual=/a/b?x=1 -->", 255);
        assert_eq!(params(&parsed.directives[0]), vec![("virtual", "/a/b?x=1")]);
    }

    #[test]
    fn unterminated_tag_is_incomplete() {
        let parsed = scan(b"x<!--#echo var=\"uri\"", 255);
        assert_eq!(parsed.error, Some(ParseError::Incomplete));
        assert!(parsed.directives.is_empty());
    }

    #[test]
    fn malformed_tag_recovers_at_its_end() {
        let parsed = scan(b"<!--#echo uri -->ok<!--#echo var=\"a\"-->", 255);
        assert!(matches!(parsed.error, Some(ParseError::Malformed(_))));
        assert_eq!(parsed.directives.len(), 1);
        assert_eq!(parsed.directives[0].name, "echo");
    }

    #[test]
    fn missing_equals_is_malformed() {
        let parsed = scan(b"<!--#echo var \"uri\" -->", 255);
        assert!(matches!(parsed.error, Some(ParseError::Malformed(_))));
    }

    #[test]
    fn value_length_limit_is_enforced() {
        let parsed = scan(b"<!--#echo var=\"abcdef\"-->", 4);
        assert!(matches!(parsed.error, Some(ParseError::Limit(_))));
    }
}





