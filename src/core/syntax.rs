//! Nginx-compatible directive syntax.
//!
//! The lexer/parser is module agnostic: it produces a tree of [`Directive`] values and
//! each [`crate::modules`] implementation decides which names are valid in which context.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    pub children: Option<Vec<Directive>>,
    pub file: PathBuf,
    pub line: usize,
}

impl Directive {
    pub fn error(&self, message: impl AsRef<str>) -> anyhow::Error {
        anyhow::anyhow!(
            "{}:{}: {}: {}",
            self.file.display(),
            self.line,
            self.name,
            message.as_ref()
        )
    }

    pub fn has_block(&self) -> bool {
        self.children.is_some()
    }

    pub fn block(&self) -> Result<&[Directive]> {
        self.children
            .as_deref()
            .ok_or_else(|| self.error("expected a block"))
    }

    pub fn expect_args(&self, count: usize) -> Result<()> {
        if self.args.len() == count && self.children.is_none() {
            Ok(())
        } else {
            Err(self.error(format!(
                "invalid number of arguments in this directive (expected {count})"
            )))
        }
    }

    pub fn expect_args_range(&self, range: std::ops::RangeInclusive<usize>) -> Result<()> {
        if range.contains(&self.args.len()) && self.children.is_none() {
            Ok(())
        } else {
            Err(self.error("invalid number of arguments in this directive"))
        }
    }

    pub fn expect_block_only(&self) -> Result<()> {
        if self.args.is_empty() && self.children.is_some() {
            Ok(())
        } else {
            Err(self.error("expected a block"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TokenKind {
    Word(String),
    LeftBrace,
    RightBrace,
    Semicolon,
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    line: usize,
}

pub fn parse_file(path: &Path) -> Result<Vec<Directive>> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("cannot open configuration {}", path.display()))?;
    let mut include_stack = Vec::new();
    parse_file_inner(&canonical, &mut include_stack)
}

fn parse_file_inner(path: &Path, include_stack: &mut Vec<PathBuf>) -> Result<Vec<Directive>> {
    if include_stack.contains(&path.to_path_buf()) {
        bail!("include cycle detected at {}", path.display());
    }
    include_stack.push(path.to_path_buf());
    let result = (|| {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read configuration {}", path.display()))?;
        let tokens = lex(&source).with_context(|| path.display().to_string())?;
        let mut parser = Parser {
            tokens,
            offset: 0,
            file: path.to_path_buf(),
        };
        let nodes = parser.parse(false)?;
        expand_includes(nodes, path, include_stack)
    })();
    include_stack.pop();
    result
}

fn expand_includes(
    nodes: Vec<Directive>,
    including_file: &Path,
    include_stack: &mut Vec<PathBuf>,
) -> Result<Vec<Directive>> {
    let mut expanded = Vec::new();
    for mut node in nodes {
        if node.name == "include" {
            node.expect_args(1)?;
            let base = including_file.parent().unwrap_or_else(|| Path::new("."));
            let pattern = Path::new(&node.args[0]);
            let pattern = if pattern.is_absolute() {
                pattern.to_path_buf()
            } else {
                base.join(pattern)
            };
            let pattern_text = pattern.to_string_lossy();
            if pattern_text.contains(['*', '?', '[']) {
                let mut paths = Vec::new();
                for entry in glob::glob(&pattern_text)
                    .with_context(|| format!("invalid include pattern {pattern_text}"))?
                {
                    paths.push(entry?);
                }
                paths.sort();
                for path in paths {
                    expanded.extend(parse_file_inner(&path, include_stack)?);
                }
            } else {
                expanded.extend(parse_file_inner(&pattern, include_stack)?);
            }
        } else {
            if let Some(children) = node.children.take() {
                node.children = Some(expand_includes(children, including_file, include_stack)?);
            }
            expanded.push(node);
        }
    }
    Ok(expanded)
}

pub fn parse_str(source: &str) -> Result<Vec<Directive>> {
    Parser {
        tokens: lex(source)?,
        offset: 0,
        file: PathBuf::from("<memory>"),
    }
    .parse(false)
}

struct Parser {
    tokens: Vec<Token>,
    offset: usize,
    file: PathBuf,
}

impl Parser {
    fn parse(&mut self, inside_block: bool) -> Result<Vec<Directive>> {
        let mut directives = Vec::new();
        loop {
            let Some(token) = self.tokens.get(self.offset).cloned() else {
                if inside_block {
                    bail!(
                        "{}: unexpected end of file; missing }}",
                        self.file.display()
                    );
                }
                return Ok(directives);
            };
            match token.kind {
                TokenKind::RightBrace => {
                    self.offset += 1;
                    if inside_block {
                        return Ok(directives);
                    }
                    bail!("{}:{}: unexpected }}", self.file.display(), token.line);
                }
                TokenKind::LeftBrace | TokenKind::Semicolon => {
                    bail!(
                        "{}:{}: expected a directive",
                        self.file.display(),
                        token.line
                    )
                }
                TokenKind::Word(name) => {
                    self.offset += 1;
                    let mut args = Vec::new();
                    loop {
                        let Some(next) = self.tokens.get(self.offset).cloned() else {
                            bail!(
                                "{}:{}: unterminated directive {name}; expected ; or {{",
                                self.file.display(),
                                token.line
                            );
                        };
                        match next.kind {
                            TokenKind::Word(arg) => {
                                args.push(arg);
                                self.offset += 1;
                            }
                            TokenKind::Semicolon => {
                                self.offset += 1;
                                directives.push(Directive {
                                    name,
                                    args,
                                    children: None,
                                    file: self.file.clone(),
                                    line: token.line,
                                });
                                break;
                            }
                            TokenKind::LeftBrace => {
                                self.offset += 1;
                                let children = self.parse(true)?;
                                directives.push(Directive {
                                    name,
                                    args,
                                    children: Some(children),
                                    file: self.file.clone(),
                                    line: token.line,
                                });
                                break;
                            }
                            TokenKind::RightBrace => {
                                bail!(
                                    "{}:{}: directive {name} must end with ; before }}",
                                    self.file.display(),
                                    next.line
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

fn lex(source: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = source.chars().peekable();
    let mut line = 1;
    while let Some(ch) = chars.next() {
        match ch {
            '\n' => line += 1,
            ch if ch.is_whitespace() => {}
            '#' => {
                for comment in chars.by_ref() {
                    if comment == '\n' {
                        line += 1;
                        break;
                    }
                }
            }
            '{' => tokens.push(Token {
                kind: TokenKind::LeftBrace,
                line,
            }),
            '}' => tokens.push(Token {
                kind: TokenKind::RightBrace,
                line,
            }),
            ';' => tokens.push(Token {
                kind: TokenKind::Semicolon,
                line,
            }),
            '\'' | '"' => {
                let quote = ch;
                let start_line = line;
                let mut word = String::new();
                let mut closed = false;
                while let Some(next) = chars.next() {
                    match next {
                        ch if ch == quote => {
                            closed = true;
                            break;
                        }
                        '\n' => {
                            line += 1;
                            word.push('\n');
                        }
                        '\\' => {
                            let escaped = chars.next().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "line {start_line}: trailing escape in quoted string"
                                )
                            })?;
                            push_escaped(&mut word, escaped, &mut line);
                        }
                        other => word.push(other),
                    }
                }
                if !closed {
                    bail!("line {start_line}: unterminated quoted string");
                }
                tokens.push(Token {
                    kind: TokenKind::Word(word),
                    line: start_line,
                });
            }
            _ => {
                let start_line = line;
                let mut word = String::from(ch);
                loop {
                    match chars.peek().copied() {
                        None | Some('{') | Some('}') | Some(';') | Some('#') => break,
                        Some(next) if next.is_whitespace() => break,
                        Some('\\') => {
                            chars.next();
                            let escaped = chars.next().ok_or_else(|| {
                                anyhow::anyhow!("line {start_line}: trailing escape")
                            })?;
                            push_escaped(&mut word, escaped, &mut line);
                        }
                        Some(_) => word.push(chars.next().expect("peeked character")),
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::Word(word),
                    line: start_line,
                });
            }
        }
    }
    Ok(tokens)
}

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
