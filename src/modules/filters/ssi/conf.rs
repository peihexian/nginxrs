//! `ngx_http_ssi_filter_module` configuration and command tables.
//!
//! Directives and defaults mirror `ngx_http_ssi_create_loc_conf` /
//! `ngx_http_ssi_merge_loc_conf` and the `ngx_http_ssi_filter_commands` / command /
//! parameter tables in `c/nginx/src/http/modules/ngx_http_ssi_filter_module.c`.

use crate::core::value::{parse_on_off, parse_size};
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use anyhow::Result;

pub const MODULE_NAME: &str = "ngx_http_ssi_filter_module";

/// Content types SSI processes unless `ssi_types` overrides them
/// (`ngx_http_html_default_types`).
pub const DEFAULT_TYPES: &[&str] = &["text/html"];

/// `ngx_http_ssi_loc_conf_t`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsiConf {
    /// `ssi on|off` (`off` by default).
    pub enable: bool,
    /// `ssi_silent_errors`: drop the error message instead of emitting `errmsg`.
    pub silent_errors: bool,
    /// `ssi_ignore_recycled_buffers` (accepted; pingora has no recycled buffers).
    pub ignore_recycled_buffers: bool,
    /// `ssi_last_modified`: keep `Last-Modified`/`ETag` (weak ETag) on included output.
    pub last_modified: bool,
    /// `ssi_min_file_chunk` (1024 by default; buffering hint only).
    pub min_file_chunk: usize,
    /// `ssi_value_length`: maximum length of one parameter value (255 by default).
    pub value_len: usize,
    /// `ssi_types`: response content types the filter applies to.
    pub types: Vec<String>,
}

impl Default for SsiConf {
    fn default() -> Self {
        Self {
            enable: false,
            silent_errors: false,
            ignore_recycled_buffers: false,
            last_modified: false,
            min_file_chunk: 1024,
            value_len: 255,
            types: DEFAULT_TYPES.iter().map(|value| value.to_string()).collect(),
        }
    }
}

impl LocationConf for SsiConf {}

impl SsiConf {
    /// `ngx_http_test_content_type`: whether SSI filters a response of this type.
    pub fn handles_type(&self, content_type: &str) -> bool {
        let body = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim()
            .to_ascii_lowercase();
        self.types
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&body))
    }
}

/// The SSI commands, with their parameters, from `ngx_http_ssi_commands`.
pub mod commands {
    /// Parameter slots and attributes of one command (`ngx_http_ssi_param_t`).
    pub struct Param {
        pub name: &'static str,
        pub index: usize,
        pub mandatory: bool,
        /// `multiple` is always 0 in nginx; kept for completeness.
        pub multiple: bool,
    }

    /// SSI condition classes (`NGX_HTTP_SSI_COND_IF` / `_ELSE`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Conditional {
        If,
        Else,
    }

    /// `ngx_http_ssi_command_t`.
    pub struct Command {
        pub name: &'static str,
        pub params: &'static [Param],
        pub conditional: Option<Conditional>,
        pub block: bool,
        pub flush: bool,
    }

    pub const INCLUDE_VIRTUAL: usize = 0;
    pub const INCLUDE_FILE: usize = 1;
    pub const INCLUDE_WAIT: usize = 2;
    pub const INCLUDE_SET: usize = 3;
    pub const INCLUDE_STUB: usize = 4;

    pub const ECHO_VAR: usize = 0;
    pub const ECHO_DEFAULT: usize = 1;
    pub const ECHO_ENCODING: usize = 2;

    pub const CONFIG_ERRMSG: usize = 0;
    pub const CONFIG_TIMEFMT: usize = 1;

    pub const SET_VAR: usize = 0;
    pub const SET_VALUE: usize = 1;

    pub const IF_EXPR: usize = 0;

    pub const BLOCK_NAME: usize = 0;

    const INCLUDE_PARAMS: &[Param] = &[
        Param { name: "virtual", index: INCLUDE_VIRTUAL, mandatory: false, multiple: false },
        Param { name: "file", index: INCLUDE_FILE, mandatory: false, multiple: false },
        Param { name: "wait", index: INCLUDE_WAIT, mandatory: false, multiple: false },
        Param { name: "set", index: INCLUDE_SET, mandatory: false, multiple: false },
        Param { name: "stub", index: INCLUDE_STUB, mandatory: false, multiple: false },
    ];

    const ECHO_PARAMS: &[Param] = &[
        Param { name: "var", index: ECHO_VAR, mandatory: true, multiple: false },
        Param { name: "default", index: ECHO_DEFAULT, mandatory: false, multiple: false },
        Param { name: "encoding", index: ECHO_ENCODING, mandatory: false, multiple: false },
    ];

    const CONFIG_PARAMS: &[Param] = &[
        Param { name: "errmsg", index: CONFIG_ERRMSG, mandatory: false, multiple: false },
        Param { name: "timefmt", index: CONFIG_TIMEFMT, mandatory: false, multiple: false },
    ];

    const SET_PARAMS: &[Param] = &[
        Param { name: "var", index: SET_VAR, mandatory: true, multiple: false },
        Param { name: "value", index: SET_VALUE, mandatory: true, multiple: false },
    ];

    const IF_PARAMS: &[Param] = &[
        Param { name: "expr", index: IF_EXPR, mandatory: true, multiple: false },
    ];

    const BLOCK_PARAMS: &[Param] = &[
        Param { name: "name", index: BLOCK_NAME, mandatory: true, multiple: false },
    ];

    const NO_PARAMS: &[Param] = &[];

    pub const SSI_COMMANDS: &[Command] = &[        Command {
            name: "include",
            params: INCLUDE_PARAMS,
            conditional: None,
            block: false,
            flush: true,
        },
        Command { name: "echo", params: ECHO_PARAMS, conditional: None, block: false, flush: false },
        Command {
            name: "config",
            params: CONFIG_PARAMS,
            conditional: None,
            block: false,
            flush: false,
        },
        Command { name: "set", params: SET_PARAMS, conditional: None, block: false, flush: false },
        Command { name: "if", params: IF_PARAMS, conditional: None, block: false, flush: false },
        Command {
            name: "elif",
            params: IF_PARAMS,
            conditional: Some(Conditional::If),
            block: false,
            flush: false,
        },
        Command {
            name: "else",
            params: NO_PARAMS,
            conditional: Some(Conditional::If),
            block: false,
            flush: false,
        },
        Command {
            name: "endif",
            params: NO_PARAMS,
            conditional: Some(Conditional::Else),
            block: false,
            flush: false,
        },
        Command {
            name: "block",
            params: BLOCK_PARAMS,
            conditional: None,
            block: false,
            flush: false,
        },
        Command {
            name: "endblock",
            params: NO_PARAMS,
            conditional: None,
            block: true,
            flush: false,
        },
    ];

    /// `ngx_hash_find(&smcf->hash, ...)`: the command named `name`, if any.
    pub fn find(name: &[u8]) -> Option<&'static Command> {
        SSI_COMMANDS
            .iter()
            .find(|command| command.name.as_bytes() == name)
    }
}

pub struct SsiModule;

impl Module for SsiModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            spec("ssi", &[Context::Http, Context::Server, Context::Location], parse_enable),
            spec(
                "ssi_silent_errors",
                &[Context::Http, Context::Server, Context::Location],
                parse_silent_errors,
            ),
            spec(
                "ssi_ignore_recycled_buffers",
                &[Context::Http, Context::Server, Context::Location],
                parse_ignore_recycled,
            ),
            spec(
                "ssi_min_file_chunk",
                &[Context::Http, Context::Server, Context::Location],
                parse_min_file_chunk,
            ),
            spec(
                "ssi_value_length",
                &[Context::Http, Context::Server, Context::Location],
                parse_value_length,
            ),
            spec("ssi_types", &[Context::Http, Context::Server, Context::Location], parse_types),
        ]
    }
}

fn spec(
    name: &'static str,
    contexts: &'static [Context],
    handler: fn(&mut crate::modules::DirectiveView<'_>) -> Result<()>,
) -> DirectiveSpec {
    DirectiveSpec {
        name,
        contexts,
        handler,
    }
}

fn parse_enable(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let enabled = parse_on_off(directive, &directive.args[0])?;
    view.update_conf::<SsiConf>(|conf| conf.enable = enabled)
}

fn parse_silent_errors(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let enabled = parse_on_off(directive, &directive.args[0])?;
    view.update_conf::<SsiConf>(|conf| conf.silent_errors = enabled)
}

fn parse_ignore_recycled(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let enabled = parse_on_off(directive, &directive.args[0])?;
    view.update_conf::<SsiConf>(|conf| conf.ignore_recycled_buffers = enabled)
}

fn parse_min_file_chunk(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = parse_size(directive, &directive.args[0])?;
    view.update_conf::<SsiConf>(|conf| conf.min_file_chunk = value as usize)
}

fn parse_value_length(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let value = parse_size(directive, &directive.args[0])?;
    if value == 0 {
        return Err(directive.error("ssi_value_length must be greater than zero"));
    }
    view.update_conf::<SsiConf>(|conf| conf.value_len = value as usize)
}

fn parse_types(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.has_block() || directive.args.is_empty() {
        return Err(directive.error("expected ssi_types mime-type ...;"));
    }
    let types = directive.args.clone();
    view.update_conf::<SsiConf>(|conf| conf.types = types)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_table_matches_nginx() {
        let names: Vec<&str> = commands::SSI_COMMANDS.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            vec!["include", "echo", "config", "set", "if", "elif", "else", "endif", "block", "endblock"]
        );
        assert!(commands::find(b"include").is_some());
        assert!(commands::find(b"Include").is_none(), "command lookup is case sensitive");
        let include = commands::find(b"include").unwrap();
        assert!(include.flush, "include flushes buffered output");
        let endif = commands::find(b"endif").unwrap();
        assert_eq!(endif.conditional, Some(commands::Conditional::Else));
    }

    #[test]
    fn defaults_follow_nginx() {
        let conf = SsiConf::default();
        assert!(!conf.enable);
        assert!(!conf.silent_errors);
        assert_eq!(conf.value_len, 255);
        assert_eq!(conf.min_file_chunk, 1024);
        assert!(conf.handles_type("text/html"));
        assert!(conf.handles_type("text/html; charset=utf-8"));
        assert!(!conf.handles_type("application/json"));
    }
}

