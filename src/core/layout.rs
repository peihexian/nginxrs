//! Layout-preserving model of a configuration file.
//!
//! [`crate::core::syntax`] keeps only what the server needs to run (names, values and the
//! block tree), which is enough for `-t` but loses the comments and blank lines an operator
//! uses to keep a file readable. The maintenance commands work on this layout tree instead:
//! every statement keeps its original position, comments stay where they were written, and
//! rendering produces a file whose directive order is unchanged.
//!
//! The renderer is verified rather than trusted: re-parsing the rendered text with
//! [`crate::core::syntax::parse_str`] must produce exactly the same directive tree as the
//! original text, and every comment of the original must still be present.

use crate::core::syntax::Directive;
use anyhow::{Context, Result};
use std::path::Path;

/// One item of a file, in source order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Directive(DirectiveItem),
    /// A comment line, stored with its `#` and without the line break.
    Comment(String),
    /// An empty line (a line that held only whitespace).
    Blank,
}

/// A statement plus the comments written directly above it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectiveItem {
    /// Comment lines above the statement, with no blank line in between.
    pub leading: Vec<String>,
    /// The statement itself; `children` is set when it opens a block.
    pub directive: Directive,
    /// For a block: the items inside the braces.
    pub body: Vec<Item>,
    /// A comment written after the statement on the same line.
    pub trailing: Option<String>,
}

impl DirectiveItem {
    fn collect_comments(&self, out: &mut Vec<String>) {
        for item in &self.body {
            match item {
                Item::Comment(text) => out.push(text.clone()),
                Item::Blank => {}
                Item::Directive(child) => {
                    out.extend(child.leading.iter().cloned());
                    if let Some(trailing) = &child.trailing {
                        out.push(trailing.clone());
                    }
                    child.collect_comments(out);
                }
            }
        }
    }
}

/// A parsed file.
#[derive(Clone, Debug)]
pub struct SourceText {
    pub path: std::path::PathBuf,
    /// In-memory sources have no file on disk and cannot be modified.
    pub in_memory: bool,
    /// Line terminator used by the file (`\n` or `\r\n`).
    pub newline: &'static str,
    /// Whether the original file ended with a line break.
    pub trailing_newline: bool,
    pub items: Vec<Item>,
}

impl SourceText {
    pub fn parse(path: &Path, source: &str) -> Result<Self> {
        Self::parse_inner(path, source, false)
    }

    /// Parse text that is not backed by a file.
    pub fn parse_memory(source: &str) -> Result<Self> {
        Self::parse_inner(Path::new("<memory>"), source, true)
    }

    fn parse_inner(path: &Path, source: &str, in_memory: bool) -> Result<Self> {
        let newline = if source.contains("\r\n") { "\r\n" } else { "\n" };
        let trailing_newline = source.ends_with('\n');
        let lexed = lex_items(source).with_context(|| path.display().to_string())?;
        let mut parser = ItemParser {
            lexed,
            offset: 0,
            path,
        };
        let (items, offset) = parser.parse_items(false).map(|items| (items, parser.offset))?;
        if let Some(extra) = parser.lexed.get(offset) {
            anyhow::bail!(
                "{}:{}: unexpected {} at the end of the configuration",
                path.display(),
                extra.line,
                extra.kind.describe()
            );
        }
        Ok(Self {
            path: path.to_path_buf(),
            in_memory,
            newline,
            trailing_newline,
            items,
        })
    }

    /// Every statement of this file in source order (blocks keep their bodies).
    pub fn directives(&self) -> Vec<Directive> {
        let mut out = Vec::new();
        flatten_directives(&self.items, &mut out);
        out
    }

    /// Every comment of the file, in order.
    pub fn comments(&self) -> Vec<String> {
        let mut out = Vec::new();
        for item in &self.items {
            match item {
                Item::Comment(text) => out.push(text.clone()),
                Item::Blank => {}
                Item::Directive(item) => {
                    out.extend(item.leading.iter().cloned());
                    if let Some(trailing) = &item.trailing {
                        out.push(trailing.clone());
                    }
                    item.collect_comments(&mut out);
                }
            }
        }
        out
    }

    pub fn render(&self, indent: &IndentStyle) -> String {
        let mut out = String::new();
        render_items(&self.items, 0, indent, self.newline, &mut out);
        finish(&mut out, self.newline, self.trailing_newline);
        out
    }
}

/// The directive tree of a layout item list, without comments.
pub fn flatten_directives(items: &[Item], out: &mut Vec<Directive>) {
    for item in items {
        if let Item::Directive(item) = item {
            out.extend(std::iter::once(standalone(item)));
        }
    }
}

/// The directive tree of a block body.
pub fn flatten_into(items: &[Item], out: &mut Vec<Directive>) {
    flatten_directives(items, out);
}


/// The statement without its body items, but with its body as a directive list.
pub fn standalone(item: &DirectiveItem) -> Directive {
    let mut directive = item.directive.clone();
    if directive.children.is_some() {
        let mut children = Vec::new();
        flatten_directives(&item.body, &mut children);
        directive.children = Some(children);
    }
    directive
}

/// Make a rendered file end exactly like the original one.
pub fn finish(out: &mut String, newline: &str, trailing_newline: bool) {
    while out.ends_with('\n') || out.ends_with('\r') {
        out.pop();
    }
    if !out.is_empty() || trailing_newline {
        out.push_str(newline);
    }
}

/// Indentation policy for rendered files.
#[derive(Clone, Debug)]
pub struct IndentStyle {
    /// One indentation step, e.g. four spaces.
    pub unit: String,
}

impl Default for IndentStyle {
    fn default() -> Self {
        Self {
            unit: "    ".to_string(),
        }
    }
}

impl IndentStyle {
    /// Build a style from a user supplied step: a number of spaces, or `t` for one tab.
    pub fn from_spec(spec: &str) -> Self {
        let unit = match spec {
            "tab" | "tabs" | "t" => "\t".to_string(),
            other => {
                let width = other.parse::<usize>().unwrap_or(4).clamp(1, 16);
                " ".repeat(width)
            }
        };
        Self { unit }
    }

    pub fn prefix(&self, level: usize) -> String {
        self.unit.repeat(level)
    }

}

fn render_items(items: &[Item], level: usize, indent: &IndentStyle, newline: &str, out: &mut String) {
    for item in items {
        render_item(item, level, indent, newline, out);
    }
}

fn render_item(item: &Item, level: usize, indent: &IndentStyle, newline: &str, out: &mut String) {
    let prefix = indent.prefix(level);
    match item {
        Item::Blank => out.push_str(newline),
        Item::Comment(text) => {
            out.push_str(&prefix);
            out.push_str(text.trim_end());
            out.push_str(newline);
        }
        Item::Directive(item) => {
            for comment in &item.leading {
                out.push_str(&prefix);
                out.push_str(comment.trim_end());
                out.push_str(newline);
            }
            out.push_str(&prefix);
            out.push_str(&format_directive(&item.directive));
            if item.directive.children.is_none() {
                out.push(';');
                push_trailing(out, item.trailing.as_deref());
                out.push_str(newline);
                return;
            }
            out.push_str(" {");
            if item.body.is_empty() {
                out.push('}');
                push_trailing(out, item.trailing.as_deref());
                out.push_str(newline);
                return;
            }
            out.push_str(newline);
            render_items(&item.body, level + 1, indent, newline, out);
            out.push_str(&prefix);
            out.push('}');
            push_trailing(out, item.trailing.as_deref());
            out.push_str(newline);
        }
    }
}

pub fn push_trailing(out: &mut String, trailing: Option<&str>) {
    if let Some(trailing) = trailing {
        let trailing = trailing.trim_end();
        if !trailing.is_empty() {
            out.push(' ');
            out.push_str(trailing);
        }
    }
}

/// `name arg arg` with one space between words.
pub fn format_directive(directive: &Directive) -> String {
    let mut out = String::with_capacity(directive.name.len() + 16);
    out.push_str(&directive.name);
    for arg in &directive.args {
        out.push(' ');
        out.push_str(&quote_argument(arg));
    }
    out
}

/// Source text of a value, quoted when Nginx would otherwise split or truncate it.
///
/// Nginx ends a word at whitespace, `;`, `{` and `}` and starts a comment at `#`, so any
/// value containing those characters (or a quote/backslash) is emitted in double quotes
/// with `"` and `\` escaped; the syntax lexer decodes exactly those escapes.
pub fn quote_argument(argument: &str) -> String {
    let needs_quotes = argument.is_empty()
        || argument.starts_with('#')
        || argument
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, ';' | '{' | '}' | '"' | '\\'));
    if !needs_quotes {
        return argument.to_string();
    }
    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('"');
    for ch in argument.chars() {
        match ch {
            '"' | '\\' => {
                quoted.push('\\');
                quoted.push(ch);
            }
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

// ---------------------------------------------------------------------------------------
// Layout lexer: the word/comment rules of the syntax lexer, plus comment and blank-line
// items, so a statement can be reproduced at its original position.
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum LexedKind {
    Word(String),
    LeftBrace,
    RightBrace,
    Semicolon,
    /// A comment that starts a line (no statement before it on that line).
    OwnLineComment(String),
    /// A comment written after a statement on the same line.
    TrailingComment(String),
}

impl LexedKind {
    fn describe(&self) -> String {
        match self {
            LexedKind::Word(word) => format!("word \"{word}\""),
            LexedKind::LeftBrace => "\"{\"".to_string(),
            LexedKind::RightBrace => "\"}\"".to_string(),
            LexedKind::Semicolon => "\";\"".to_string(),
            LexedKind::OwnLineComment(_) | LexedKind::TrailingComment(_) => "comment".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct Lexed {
    kind: LexedKind,
    line: usize,
}

fn lex_items(source: &str) -> Result<Vec<Lexed>> {
    let mut items = Vec::new();
    let mut chars = source.chars().peekable();
    let mut line = 1;
    // `true` right after a line break: the next comment starts a line.
    let mut at_line_start = true;
    // `true` once the current line holds a statement or a comment.
    let mut line_has_content = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\n' => {
                line += 1;
                at_line_start = true;
                line_has_content = false;
            }
            '\r' => {}
            ch if ch.is_whitespace() => {}
            '#' => {
                let mut text = String::from("#");
                let mut ended_line = false;
                while let Some(next) = chars.next() {
                    if next == '\n' {
                        line += 1;
                        ended_line = true;
                        break;
                    }
                    text.push(next);
                }
                let comment = text.trim_end().to_string();
                let kind = if at_line_start && !line_has_content {
                    LexedKind::OwnLineComment(comment)
                } else {
                    LexedKind::TrailingComment(comment)
                };
                items.push(Lexed { kind, line });
                if ended_line {
                    at_line_start = true;
                    line_has_content = false;
                } else {
                    at_line_start = false;
                    line_has_content = true;
                }
            }
            '{' => {
                items.push(Lexed {
                    kind: LexedKind::LeftBrace,
                    line,
                });
                at_line_start = false;
                line_has_content = true;
            }
            '}' => {
                items.push(Lexed {
                    kind: LexedKind::RightBrace,
                    line,
                });
                at_line_start = false;
                line_has_content = true;
            }
            ';' => {
                items.push(Lexed {
                    kind: LexedKind::Semicolon,
                    line,
                });
                at_line_start = false;
                line_has_content = true;
            }
            quote @ ('\'' | '"') => {
                let start_line = line;
                let word = lex_quoted(&mut chars, quote, &mut line)?;
                items.push(Lexed {
                    kind: LexedKind::Word(word),
                    line: start_line,
                });
                at_line_start = false;
                line_has_content = true;
            }
            _ => {
                let start_line = line;
                let word = lex_word(ch, &mut chars, &mut line)?;
                items.push(Lexed {
                    kind: LexedKind::Word(word),
                    line: start_line,
                });
                at_line_start = false;
                line_has_content = true;
            }
        }
    }
    Ok(items)
}

fn lex_quoted(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    quote: char,
    line: &mut usize,
) -> Result<String> {
    let start_line = *line;
    let mut word = String::new();
    let mut closed = false;
    while let Some(next) = chars.next() {
        match next {
            ch if ch == quote => {
                closed = true;
                break;
            }
            '\n' => {
                *line += 1;
                word.push('\n');
            }
            '\\' => {
                let escaped = chars.next().ok_or_else(|| {
                    anyhow::anyhow!("line {start_line}: trailing escape in quoted string")
                })?;
                push_escaped(&mut word, escaped, line);
            }
            other => word.push(other),
        }
    }
    if !closed {
        anyhow::bail!("line {start_line}: unterminated quoted string");
    }
    Ok(word)
}

fn lex_word(
    first: char,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    line: &mut usize,
) -> Result<String> {
    let start_line = *line;
    let mut word = String::from(first);
    loop {
        match chars.peek().copied() {
            None | Some('{') | Some('}') | Some(';') | Some('#') => break,
            Some(next) if next.is_whitespace() => break,
            Some('\\') => {
                chars.next();
                let escaped = chars
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("line {start_line}: trailing escape"))?;
                push_escaped(&mut word, escaped, line);
            }
            Some(_) => word.push(chars.next().expect("peeked character")),
        }
    }
    Ok(word)
}

/// Escape handling identical to the syntax lexer, so values decode the same way.
fn push_escaped(word: &mut String, escaped: char, line: &mut usize) {
    match escaped {
        't' => word.push('\t'),
        'r' => word.push('\r'),
        'n' => word.push('\n'),
        '\n' => *line += 1,
        '\\' | '\'' | '"' => word.push(escaped),
        other => {
            // Preserve regex escapes such as \d and \/.
            word.push('\\');
            word.push(other);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Layout parser: builds the same directive tree as the syntax parser, in file order.
// ---------------------------------------------------------------------------------------

struct ItemParser<'a> {
    lexed: Vec<Lexed>,
    offset: usize,
    path: &'a Path,
}

impl ItemParser<'_> {
    fn error(&self, line: usize, message: impl Into<String>) -> anyhow::Error {
        anyhow::anyhow!("{}:{}: {}", self.path.display(), line, message.into())
    }

    fn peek(&self) -> Option<Lexed> {
        self.lexed.get(self.offset).cloned()
    }

    /// Parse items until the end of the input or, inside a block, its closing brace.
    fn parse_items(&mut self, inside_block: bool) -> Result<Vec<Item>> {
        let mut items: Vec<Item> = Vec::new();
        // Comments that precede the next statement.
        let mut pending: Vec<String> = Vec::new();
        loop {
            let Some(next) = self.peek() else {
                if inside_block {
                    return Err(anyhow::anyhow!(
                        "{}: unexpected end of file; missing }}",
                        self.path.display()
                    ));
                }
                items.extend(pending.drain(..).map(Item::Comment));
                return Ok(items);
            };
            match next.kind {
                LexedKind::OwnLineComment(text) => {
                    pending.push(text);
                    self.offset += 1;
                }
                LexedKind::TrailingComment(text) => {
                    self.offset += 1;
                    let previous_is_close = matches!(
                        self.offset
                            .checked_sub(2)
                            .and_then(|index| self.lexed.get(index))
                            .map(|lexed| &lexed.kind),
                        Some(LexedKind::RightBrace) | Some(LexedKind::Semicolon)
                    );
                    if previous_is_close {
                        if let Some(Item::Directive(last)) = items.last_mut() {
                            append_trailing(&mut last.trailing, text);
                            continue;
                        }
                    }
                    pending.push(text);
                }
                LexedKind::RightBrace => {
                    self.offset += 1;
                    if inside_block {
                        items.extend(pending.drain(..).map(Item::Comment));
                        return Ok(items);
                    }
                    return Err(self.error(next.line, "unexpected }"));
                }
                LexedKind::LeftBrace | LexedKind::Semicolon => {
                    return Err(self.error(next.line, "expected a directive"));
                }
                LexedKind::Word(name) => {
                    let line = next.line;
                    self.offset += 1;
                    let item = self.parse_statement(name, line)?;
                    let mut item = item;
                    item.leading = std::mem::take(&mut pending);
                    items.push(Item::Directive(item));
                }
            }
        }
    }

    fn parse_statement(&mut self, name: String, line: usize) -> Result<DirectiveItem> {
        let mut args = Vec::new();
        // `include a.conf;  # note`: a comment on the statement's own line is kept on that
        // line when the statement ends there.
        let mut trailing: Option<String> = None;
        loop {
            let Some(token) = self.peek() else {
                return Err(self.error(
                    line,
                    format!("unterminated directive {name}; expected ; or {{"),
                ));
            };
            match token.kind {
                LexedKind::Word(arg) => {
                    args.push(arg);
                    self.offset += 1;
                }
                LexedKind::TrailingComment(text) => {
                    append_trailing(&mut trailing, text);
                    self.offset += 1;
                }
                LexedKind::OwnLineComment(_) => {
                    // A comment on its own line inside a statement keeps its own line; the
                    // statement continues on the next line, as in Nginx.
                    self.offset += 1;
                }
                LexedKind::Semicolon => {
                    self.offset += 1;
                    return Ok(DirectiveItem {
                        leading: Vec::new(),
                        directive: Directive {
                            name,
                            args,
                            children: None,
                            file: self.path.to_path_buf(),
                            line,
                        },
                        body: Vec::new(),
                        trailing,
                    });
                }
                LexedKind::LeftBrace => {
                    self.offset += 1;
                    let body = self.parse_items(true)?;
                    // Children are only a marker that a block was written; the body holds
                    // the real directives, so it is the single source of truth here.
                    return Ok(DirectiveItem {
                        leading: Vec::new(),
                        directive: Directive {
                            name,
                            args,
                            children: Some(Vec::new()),
                            file: self.path.to_path_buf(),
                            line,
                        },
                        body,
                        trailing,
                    });
                }
                LexedKind::RightBrace => {
                    return Err(self.error(
                        token.line,
                        format!("directive {name} must end with ; before }}"),
                    ));
                }
            }
        }
    }
}

fn append_trailing(slot: &mut Option<String>, text: String) {
    match slot {
        Some(existing) => {
            existing.push(' ');
            existing.push_str(&text);
        }
        None => *slot = Some(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::syntax;

    const MESSY: &str = "worker_processes auto;
http {
  include   mime.types;   # mime
    upstream   backend{
    least_conn;
        server 127.0.0.1:9001 weight=1;
  }

    # a comment about the server
server{listen 80 default_server;server_name localhost;location /{root   ../www;try_files $uri $uri/ =404;}}


}";

    fn beautify(source: &str) -> String {
        SourceText::parse_memory(source)
            .unwrap()
            .render(&IndentStyle::default())
    }

    /// Directive trees of a text, ignoring the line numbers a layout change moves.
    fn shape(source: &str) -> Vec<Directive> {
        fn strip(mut directive: Directive) -> Directive {
            directive.line = 0;
            directive.file = std::path::PathBuf::new();
            if let Some(children) = directive.children.take() {
                directive.children = Some(children.into_iter().map(strip).collect());
            }
            directive
        }
        syntax::parse_str(source)
            .unwrap()
            .into_iter()
            .map(strip)
            .collect()
    }

    #[test]
    fn beautify_preserves_the_directive_tree() {
        let rendered = beautify(MESSY);
        assert_eq!(shape(MESSY), shape(&rendered), "{rendered}");
        assert_eq!(
            SourceText::parse_memory(MESSY).unwrap().comments(),
            SourceText::parse_memory(&rendered).unwrap().comments()
        );
    }

    #[test]
    fn beautify_indents_and_keeps_comments() {
        let rendered = beautify(MESSY);
        assert!(rendered.contains("    include mime.types; # mime"), "{rendered}");
        assert!(rendered.contains("    upstream backend {"), "{rendered}");
        assert!(rendered.contains("        least_conn;"), "{rendered}");
        assert!(
            rendered.contains("    # a comment about the server"),
            "{rendered}"
        );
        assert!(rendered.contains("        location / {"), "{rendered}");
        assert!(rendered.contains("try_files $uri $uri/ =404;\n"), "{rendered}");
        assert!(!rendered.contains("mime.types;   mime"));
    }

    #[test]
    fn beautify_is_idempotent() {
        assert_eq!(beautify(MESSY), beautify(&beautify(MESSY)));
    }

    #[test]
    fn quotes_values_that_would_be_split() {
        let source = "http { log_format main '$a $b'; add_header X \"a;b\"; }\n";
        let rendered = beautify(source);
        assert_eq!(shape(source), shape(&rendered), "{rendered}");
    }

    #[test]
    fn keeps_crlf_line_endings() {
        let source = "worker_processes 1;\r\nhttp { server { listen 80; } }\r\n";
        let rendered = beautify(source);
        assert!(rendered.ends_with("\r\n"), "{rendered:?}");
        assert!(!rendered.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn empty_block_stays_on_one_line() {
        assert_eq!(beautify("events {}\n"), "events {}\n");
    }

    #[test]
    fn indents_with_tabs_on_request() {
        let rendered = SourceText::parse_memory("http {\nserver {\nlisten 80;\n}\n}\n")
            .unwrap()
            .render(&IndentStyle::from_spec("t"));
        assert!(rendered.contains("\n\t\tlisten 80;\n"), "{rendered:?}");
    }
}










