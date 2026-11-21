//! The SSI renderer: `ngx_http_ssi_body_filter` and the command handlers.
//!
//! Nginx streams the response through the filter, holding back the maximum possible
//! length of a directive (`<!--#` + command + params + `-->`, i.e. 255 bytes less than the
//! tag) while it waits for the rest of a tag. Because the filter is a text transform of the
//! whole body, nginx resolves subrequests (`include`) in order and shows the final page.
//! This module renders the same way: it walks the body from start to end, keeps the state the
//! C context keeps (`output`, `output_chosen`, `conditional`, `block`, captures, variables,
//! `timefmt`, `errmsg`) and calls back into [`IncludeResolver`] for `include`.
//!
//! Supported commands: `include` (`virtual`/`file`, `wait`, `set`, `stub`), `echo`
//! (`var`, `default`, `encoding`), `config` (`timefmt`, `errmsg`), `set`, `if`/`elif`/`else`/
//! `endif`, `block`/`endblock`.

use super::conf::commands::{self, Command, Conditional};
use super::expr::{self, EvalFlags, Variables};
use super::parser::{self, ParseError};
use super::strftime::{self, DEFAULT_TIMEFMT};
use crate::core::bytes::{escape_html, escape_uri_html};
use crate::core::http::RequestState;

/// Default `errmsg` (`ngx_http_ssi_buf_error`).
pub const DEFAULT_ERRMSG: &str = "[an error occurred while processing the directive]";

/// `NGX_HTTP_SSI_NO_ENCODING` / `_URL_ENCODING` / `_ENTITY_ENCODING`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    None,
    Url,
    Entity,
}

/// One `block name=…`…`endblock` capture.
#[derive(Clone, Debug)]
struct Block {
    name: Vec<u8>,
    body: Vec<Vec<u8>>,
    count: usize,
}

/// Resolves `include` targets for a page.
///
/// The SSI filter never opens files itself; nginx issues a subrequest. The resolver is the
/// boundary between the filter and the content pipeline.
pub trait IncludeResolver {
    /// Render the response body of `uri` as a subrequest of the current request.
    ///
    /// `file` is true when the include used `file=`/a relative path: the target is resolved
    /// against the current location `root` rather than by location matching.
    fn resolve(&mut self, uri: &str, file: bool) -> Result<Vec<u8>, String>;
}

/// Renderer state, the Rust counterpart of `ngx_http_ssi_ctx_t`.
pub struct Renderer<'a> {
    conf: &'a super::conf::SsiConf,
    state: &'a RequestState,
    value_len: usize,
    timefmt: Vec<u8>,
    errmsg: Vec<u8>,
    encoding: Encoding,
    output: bool,
    output_chosen: bool,
    conditional: Option<Conditional>,
    blocks: Vec<Block>,
    variables: Variables,
    /// Set once an `include` saw a broken value; nginx keeps rendering after a broken tag.
    errors: Vec<String>,
}

impl<'a> Renderer<'a> {
    pub fn new(conf: &'a super::conf::SsiConf, state: &'a RequestState) -> Self {
        Self {
            conf,
            state,
            value_len: conf.value_len,
            timefmt: DEFAULT_TIMEFMT.as_bytes().to_vec(),
            errmsg: DEFAULT_ERRMSG.as_bytes().to_vec(),
            encoding: Encoding::Entity,
            output: true,
            output_chosen: false,
            conditional: None,
            blocks: Vec::new(),
            variables: Variables::default(),
            errors: Vec::new(),
        }
    }

    /// Render `body` through the SSI filter.
    pub fn render(&mut self, body: &[u8], resolver: &mut dyn IncludeResolver) -> Vec<u8> {
        let parsed = parser::scan(body, self.value_len);
        let mut out: Vec<u8> = Vec::with_capacity(body.len());
        let mut cursor = 0usize;
        for directive in &parsed.directives {
            self.emit_literal(&body[cursor..directive.range.start], &mut out);
            cursor = directive.range.end;
            if let Some(message) = self.run(directive, resolver, &mut out) {
                self.errors.push(message);
                // `ssi_error`: the directive text is replaced by `errmsg` unless silent.
                if !self.conf.silent_errors {
                    let errmsg = self.errmsg.clone();
                    self.emit(&errmsg, &mut out);
                }
            }
        }
        // `ssi_error`: a broken tag is replaced by `errmsg` (unless `ssi_silent_errors`).
        match &parsed.error_range {
            Some(range) => {
                self.emit_literal(&body[cursor..range.start], &mut out);
                if !self.conf.silent_errors {
                    let errmsg = self.errmsg.clone();
                    self.emit(&errmsg, &mut out);
                }
                self.emit_literal(&body[range.end..], &mut out);
            }
            None => self.emit_literal(&body[cursor..], &mut out),
        }
        out
    }

    /// Diagnostics collected while rendering (logged by the caller).
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// Record a parser diagnostic for the caller's log.
    pub fn note(&mut self, error: &ParseError) {
        self.errors.push(error.message());
    }

    /// Emit text, honouring the current `output` flag and a pending `block` capture.
    fn emit_literal(&mut self, text: &[u8], out: &mut Vec<u8>) {
        if text.is_empty() {
            return;
        }
        if !self.output {
            if let Some(block) = self.blocks.last_mut() {
                block.body.push(text.to_vec());
            }
            return;
        }
        out.extend_from_slice(text);
    }

    /// Emit generated content, honouring the `output` flag and blocks the same way.
    fn emit(&mut self, piece: &[u8], out: &mut Vec<u8>) {
        self.emit_literal(piece, out);
    }

    /// Run one directive; returns a diagnostic when the command failed.
    fn run(
        &mut self,
        directive: &parser::Directive,
        resolver: &mut dyn IncludeResolver,
        out: &mut Vec<u8>,
    ) -> Option<String> {
        let Some(command) = commands::find(directive.name.as_bytes()) else {
            // The C filter only reports invalid commands while output is on.
            if self.output {
                return Some(format!("invalid SSI command: \"{}\"", directive.name));
            }
            return None;
        };
        // `!ctx->output && !cmd->block`: inside a hidden block, non-block commands are kept
        // verbatim for `stub` replay, or dropped when not capturing.
        if !self.output && !command.block {
            if self.blocks.last().is_some() {
                let rebuilt = rebuild(directive);
                if let Some(block) = self.blocks.last_mut() {
                    block.body.push(rebuilt);
                }
                return None;
            }
            if command.conditional.is_none() {
                return None;
            }
        }
        // Conditional context checks (`invalid context of SSI command`).
        if let Some(required) = command.conditional {
            // `elif`/`else` need an open `if`; `endif` needs `if` or `else`.
            let valid = match required {
                Conditional::If => self.conditional == Some(Conditional::If),
                Conditional::Else => self.conditional.is_some(),
            };
            if !valid {
                return Some(format!(
                    "invalid context of SSI command: \"{}\"",
                    directive.name
                ));
            }
            if directive.name == "elif" && self.conditional == Some(Conditional::Else) {
                return Some(format!(
                    "invalid context of SSI command: \"{}\"",
                    directive.name
                ));
            }
        }
        let Some(params) = bind(command, directive) else {
            return Some(format!(
                "invalid parameters in \"{}\" SSI command",
                directive.name
            ));
        };
        // `if` inside `if` is rejected before the output check.
        if directive.name == "if" && self.conditional.is_some() {
            return Some("the \"if\" command inside the \"if\" command".to_string());
        }
        match directive.name.as_str() {
            "include" => self.include(&params, resolver, out),
            "echo" => self.echo(&params, out),
            "config" => self.config(&params),
            "set" => self.set(&params),
            "if" | "elif" => self.if_command(directive, &params),
            "else" => {
                self.output = !self.output_chosen;
                self.conditional = Some(Conditional::Else);
                None
            }
            "endif" => {
                self.output = true;
                self.output_chosen = false;
                self.conditional = None;
                None
            }
            "block" => {
                self.blocks.push(Block {
                    name: params[commands::BLOCK_NAME].clone().unwrap_or_default(),
                    body: Vec::new(),
                    count: 0,
                });
                self.output = false;
                None
            }
            "endblock" => {
                self.output = true;
                None
            }
            _ => None,
        }
    }

    /// `ngx_http_ssi_include`.
    fn include(
        &mut self,
        params: &Params,
        resolver: &mut dyn IncludeResolver,
        out: &mut Vec<u8>,
    ) -> Option<String> {
        let uri = params[commands::INCLUDE_VIRTUAL].as_ref();
        let file = params[commands::INCLUDE_FILE].as_ref();
        let wait = params[commands::INCLUDE_WAIT].as_ref();
        let set = params[commands::INCLUDE_SET].as_ref();
        let stub = params[commands::INCLUDE_STUB].as_ref();
        if uri.is_some() && file.is_some() {
            return Some("inclusion may be either virtual=... or file=...".to_string());
        }
        if uri.is_none() && file.is_none() {
            return Some("no parameter in \"include\" SSI command".to_string());
        }
        if set.is_some() && stub.is_some() {
            return Some(
                "\"set\" and \"stub\" cannot be used together in \"include\" SSI command"
                    .to_string(),
            );
        }
        let (target, target_is_file) = match (uri, file) {
            (Some(uri), _) => (uri.clone(), false),
            (None, Some(file)) => (file.clone(), true),
            _ => unreachable!("one of virtual/file is present"),
        };
        let flags = EvalFlags {
            add_prefix: target_is_file,
            add_zero: false,
        };
        let Ok(path) = expr::evaluate(&target, self.state, &self.variables, flags) else {
            return Some("invalid variable in \"include\" SSI command".to_string());
        };
        // nginx rejects URLs with control characters (`ngx_http_parse_unsafe_uri`).
        if path.iter().any(|byte| *byte < 0x20 || *byte == 0x7f) {
            return Some("invalid URI in \"include\" SSI command".to_string());
        }
        let path = String::from_utf8_lossy(&path).into_owned();
        if let Some(stub_name) = stub {
            let Some(block) = self
                .blocks
                .iter()
                .position(|block| block.name == *stub_name)
            else {
                return Some(format!(
                    "\"stub\"=\"{}\" for \"include\" not found",
                    String::from_utf8_lossy(stub_name)
                ));
            };
            let body = self.blocks[block].body.clone();
            self.blocks[block].count += 1;
            if let Some(set) = set {
                self.variables.set(&String::from_utf8_lossy(set), slice_join(&body));
                return None;
            }
            if wait.is_none() {
                for piece in &body {
                    self.emit(piece, out);
                }
                return None;
            }
            for piece in &body {
                self.emit(piece, out);
            }
            return None;
        }
        match resolver.resolve(&path, target_is_file) {
            Ok(body) => {
                if let Some(set) = set {
                    self.variables.set(&String::from_utf8_lossy(set), body);
                    return None;
                }
                self.emit(&body, out);
                None
            }
            Err(reason) => Some(format!(
                "subrequest \"{path}\" failed: {reason}"
            )),
        }
    }

    /// `ngx_http_ssi_echo`.
    fn echo(&mut self, params: &Params, out: &mut Vec<u8>) -> Option<String> {
        let variable = params[commands::ECHO_VAR].as_ref()?;
        let name = String::from_utf8_lossy(variable).into_owned();
        let value: Option<Vec<u8>> = if let Some(stored) = self.variables.get(&name) {
            Some(stored.to_vec())
        } else if let Some(fetched) = self.state.variable_bytes(&name) {
            Some(fetched)
        } else if name == "date_local" {
            Some(strftime::now_formatted(&String::from_utf8_lossy(&self.timefmt)).into_bytes())
        } else if name == "date_gmt" {
            Some(strftime::now_formatted(&String::from_utf8_lossy(&self.timefmt)).into_bytes())
        } else {
            None
        };
        let value = match value {
            Some(value) if !value.is_empty() => value,
            Some(_) => return None,
            None => match params[commands::ECHO_DEFAULT].as_ref() {
                Some(default) if !default.is_empty() => default.clone(),
                Some(_) => return None,
                None => b"(none)".to_vec(),
            },
        };
        if let Some(encoding) = params[commands::ECHO_ENCODING].as_ref() {
            match encoding.as_slice() {
                b"none" => self.encoding = Encoding::None,
                b"url" => self.encoding = Encoding::Url,
                b"entity" => self.encoding = Encoding::Entity,
                _ => self.errors.push(format!(
                    "unknown encoding \"{}\" in the \"echo\" command",
                    String::from_utf8_lossy(encoding)
                )),
            }
        }
        let encoded = match self.encoding {
            Encoding::None => value,
            Encoding::Url => escape_uri_html(&value),
            Encoding::Entity => escape_html(&value),
        };
        self.emit(&encoded, out);
        None
    }

    /// `ngx_http_ssi_config`: `timefmt` and `errmsg` persist for the rest of the page.
    fn config(&mut self, params: &Params) -> Option<String> {
        if let Some(timefmt) = params[commands::CONFIG_TIMEFMT].as_ref() {
            self.timefmt = timefmt.clone();
        }
        if let Some(errmsg) = params[commands::CONFIG_ERRMSG].as_ref() {
            self.errmsg = errmsg.clone();
        }
        None
    }

    /// `ngx_http_ssi_set`.
    fn set(&mut self, params: &Params) -> Option<String> {
        let name = params[commands::SET_VAR].as_ref()?.clone();
        let value = params[commands::SET_VALUE].as_ref()?.clone();
        let Ok(evaluated) =
            expr::evaluate(&value, self.state, &self.variables, EvalFlags::default())
        else {
            return Some("invalid variable in \"set\" SSI command".to_string());
        };
        self.variables
            .set(&String::from_utf8_lossy(&name), evaluated);
        None
    }

    /// `ngx_http_ssi_if` (shared by `if` and `elif`).
    fn if_command(&mut self, directive: &parser::Directive, params: &Params) -> Option<String> {
        if self.output_chosen {
            // `ctx->output_chosen` short-circuits: the branch was already decided.
            self.output = false;
            return None;
        }
        let expression = params[commands::IF_EXPR].as_ref()?;
        match expr::evaluate_if(expression, self.state, &self.variables) {
            Ok(result) => {
                self.output = result.matched;
                if result.matched {
                    self.output_chosen = true;
                }
                if let Some(captures) = result.captures {
                    if !captures.is_empty() {
                        self.variables.set_captures(captures);
                    }
                }
                self.conditional = Some(Conditional::If);
                let _ = directive;
                None
            }
            Err(message) => Some(message),
        }
    }

    /// `errmsg` plus `silent_errors` handling, applied by the caller when a tag failed.
    pub fn errmsg(&self) -> &[u8] {
        &self.errmsg
    }

    /// Whether broken tags should stay silent (`ssi_silent_errors on`).
    pub fn silent_errors(&self) -> bool {
        self.conf.silent_errors
    }
}

/// Parameter slots of one directive (`ngx_str_t *params[NGX_HTTP_SSI_MAX_PARAMS + 1]`).
struct Params {
    slots: Vec<Option<Vec<u8>>>,
}

impl std::ops::Index<usize> for Params {
    type Output = Option<Vec<u8>>;

    fn index(&self, index: usize) -> &Self::Output {
        self.slots.get(index).unwrap_or(&None)
    }
}

/// Bind directive parameters to command slots, rejecting unknown/duplicate/missing ones.
fn bind(command: &'static Command, directive: &parser::Directive) -> Option<Params> {
    if directive.params.len() > parser::MAX_PARAMS {
        return None;
    }
    let mut slots: Vec<Option<Vec<u8>>> = vec![None; parser::MAX_PARAMS + 1];
    for param in &directive.params {
        let Some(spec) = command
            .params
            .iter()
            .find(|candidate| candidate.name.as_bytes() == param.name.as_bytes())
        else {
            log::error!(
                "SSI: invalid parameter name: \"{}\" in \"{}\" SSI command",
                param.name,
                command.name
            );
            return None;
        };
        if !spec.multiple {
            if slots[spec.index].is_some() {
                log::error!(
                    "SSI: duplicate \"{}\" parameter in \"{}\" SSI command",
                    param.name,
                    command.name
                );
                return None;
            }
            slots[spec.index] = Some(param.value.clone());
        } else {
            let mut index = spec.index;
            while slots[index].is_some() {
                index += 1;
            }
            slots[index] = Some(param.value.clone());
        }
    }
    for spec in command.params {
        if spec.mandatory && slots[spec.index].is_none() {
            log::error!(
                "SSI: mandatory \"{}\" parameter is absent in \"{}\" SSI command",
                spec.name,
                command.name
            );
            return None;
        }
    }
    Some(Params { slots })
}

/// Rebuild a directive's text (`reconstruct the SSI command text` in the C filter).
fn rebuild(directive: &parser::Directive) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + directive.name.len());
    out.extend_from_slice(b"<!--#");
    out.extend_from_slice(directive.name.as_bytes());
    for param in &directive.params {
        out.push(b' ');
        out.extend_from_slice(param.name.as_bytes());
        out.extend_from_slice(b"=\"");
        out.extend_from_slice(&param.value);
        out.push(b'"');
    }
    out.extend_from_slice(b" -->");
    out
}

fn slice_join(pieces: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in pieces {
        out.extend_from_slice(piece);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::{ConnectionState, RequestLine, RequestState};
    use crate::modules::filters::ssi::conf::SsiConf;
    use http::HeaderMap;

    struct NoIncludes;

    impl IncludeResolver for NoIncludes {
        fn resolve(&mut self, _uri: &str, _file: bool) -> Result<Vec<u8>, String> {
            Err("not used".to_string())
        }
    }

    struct Includes(std::collections::HashMap<String, Vec<u8>>);

    impl IncludeResolver for Includes {
        fn resolve(&mut self, uri: &str, _file: bool) -> Result<Vec<u8>, String> {
            self.0
                .get(uri)
                .cloned()
                .ok_or_else(|| format!("no such include {uri}"))
        }
    }

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

    fn render(body: &str) -> String {
        let conf = SsiConf {
            enable: true,
            ..SsiConf::default()
        };
        let state = state("/index.html");
        let mut renderer = Renderer::new(&conf, &state);
        String::from_utf8(renderer.render(body.as_bytes(), &mut NoIncludes)).unwrap()
    }

    #[test]
    fn plain_text_passes_through() {
        assert_eq!(render("hello <b>world</b>"), "hello <b>world</b>");
    }

    #[test]
    fn echo_encodes_like_nginx() {
        // `$request_method` is "GET"; the default encoding is entity.
        assert_eq!(render("<!--#echo var=\"request_method\" -->"), "GET");
        assert_eq!(
            render("<!--#echo var=\"request_method\" encoding=\"none\" -->"),
            "GET"
        );
        assert_eq!(render("<!--#echo var=\"missing\" -->"), "(none)");
        assert_eq!(
            render("<!--#echo var=\"missing\" default=\"fallback\" -->"),
            "fallback"
        );
    }

    #[test]
    fn set_and_if_branch() {
        let page = "<!--#set var=\"backend\" value=\"on\" -->\
                    <!--#if expr=\"$backend\" -->ENABLED<!--#else -->DISABLED<!--#endif -->";
        assert_eq!(render(page), "ENABLED");
        let page = "<!--#if expr=\"$nothing\" -->A<!--#else -->B<!--#endif -->";
        assert_eq!(render(page), "B");
    }

    #[test]
    fn elif_chain_selects_one_branch() {
        let page = "<!--#set var=\"n\" value=\"2\" -->\
                    <!--#if expr=\"$n = 1\" -->one\
                    <!--#elif expr=\"$n = 2\" -->two\
                    <!--#elif expr=\"$n = 3\" -->three\
                    <!--#else -->other<!--#endif -->";
        assert_eq!(render(page), "two");
    }

    #[test]
    fn blocks_capture_and_stub_replays() {
        let page = "<!--#block name=\"b\" -->stub-body<!--#endblock -->\
                    x<!--#include virtual=\"/missing\" stub=\"b\" -->y\
                    <!--#include virtual=\"/missing\" stub=\"b\" -->";
        assert_eq!(render(page), "xstub-bodyystub-body");
    }

    #[test]
    fn includes_are_resolved() {
        let conf = SsiConf {
            enable: true,
            ..SsiConf::default()
        };
        let state = state("/index.html");
        let mut renderer = Renderer::new(&conf, &state);
        let mut resolver = Includes(std::collections::HashMap::from([(
            "/header.html".to_string(),
            b"<h1>hi</h1>".to_vec(),
        )]));
        let out = renderer.render(
            b"[<!--#include virtual=\"/header.html\" -->]",
            &mut resolver,
        );
        assert_eq!(out, b"[<h1>hi</h1>]".to_vec());
        assert!(renderer.errors().is_empty(), "{:?}", renderer.errors());
    }

    #[test]
    fn include_sets_a_variable() {
        let conf = SsiConf {
            enable: true,
            ..SsiConf::default()
        };
        let state = state("/index.html");
        let mut renderer = Renderer::new(&conf, &state);
        let mut resolver = Includes(std::collections::HashMap::from([(
            "/api".to_string(),
            b"42".to_vec(),
        )]));
        let out = renderer.render(
            b"<!--#include virtual=\"/api\" set=\"v\" -->v=<!--#echo var=\"v\" -->",
            &mut resolver,
        );
        assert_eq!(out, b"v=42".to_vec());
    }

    #[test]
    fn broken_tag_emits_errmsg() {
        assert_eq!(
            render("a<!--#echo uri -->b"),
            format!("a{DEFAULT_ERRMSG}b")
        );
    }
}
