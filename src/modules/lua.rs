//! Lua request hooks (`access_by_lua`, `content_by_lua`, `header_filter_by_lua`).
//!
//! Each request gets a fresh Lua 5.4 state. Only a small, explicit `ngx` API is exposed;
//! OS and process libraries are not loaded, and hooks are syntax-checked at `-t` time.

use crate::core::http::RequestState;
use crate::core::syntax::Directive;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use anyhow::{Context as _, Result};
use http::{HeaderMap, HeaderName};
use mlua::{Lua, LuaOptions, StdLib, Table, Value, Variadic};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub const MODULE_NAME: &str = "ngx_http_lua_module";

#[derive(Clone, Debug)]
pub struct LuaHook {
    pub source: String,
    pub name: String,
}

#[derive(Clone, Debug, Default)]
pub struct LuaConf {
    pub access: Option<LuaHook>,
    pub content: Option<LuaHook>,
    pub header_filter: Option<LuaHook>,
}

impl LocationConf for LuaConf {}

pub struct LuaModule;

impl Module for LuaModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            spec("access_by_lua_block", HookKind::Access, false),
            spec("access_by_lua_file", HookKind::Access, true),
            spec("rewrite_by_lua_block", HookKind::Access, false),
            spec("rewrite_by_lua_file", HookKind::Access, true),
            spec("content_by_lua_block", HookKind::Content, false),
            spec("content_by_lua_file", HookKind::Content, true),
            spec("header_filter_by_lua_block", HookKind::HeaderFilter, false),
            spec("header_filter_by_lua_file", HookKind::HeaderFilter, true),
        ]
    }
}

#[derive(Clone, Copy)]
enum HookKind {
    Access,
    Content,
    HeaderFilter,
}

fn spec(name: &'static str, kind: HookKind, from_file: bool) -> DirectiveSpec {
    DirectiveSpec {
        name,
        contexts: &[Context::Http, Context::Server, Context::Location],
        handler: match (kind, from_file) {
            (HookKind::Access, false) => parse_access_block,
            (HookKind::Access, true) => parse_access_file,
            (HookKind::Content, false) => parse_content_block,
            (HookKind::Content, true) => parse_content_file,
            (HookKind::HeaderFilter, false) => parse_header_filter_block,
            (HookKind::HeaderFilter, true) => parse_header_filter_file,
        },
    }
}

fn parse_access_block(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    store(view, HookKind::Access, inline(view.directive)?)
}

fn parse_access_file(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let hook = load_file(view.directive, view.base_dir)?;
    store(view, HookKind::Access, hook)
}

fn parse_content_block(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    store(view, HookKind::Content, inline(view.directive)?)
}

fn parse_content_file(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let hook = load_file(view.directive, view.base_dir)?;
    store(view, HookKind::Content, hook)
}

fn parse_header_filter_block(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    store(view, HookKind::HeaderFilter, inline(view.directive)?)
}

fn parse_header_filter_file(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let hook = load_file(view.directive, view.base_dir)?;
    store(view, HookKind::HeaderFilter, hook)
}

fn store(
    view: &mut crate::modules::DirectiveView<'_>,
    kind: HookKind,
    hook: LuaHook,
) -> Result<()> {
    view.update_conf::<LuaConf>(|conf| match kind {
        HookKind::Access => conf.access = Some(hook),
        HookKind::Content => conf.content = Some(hook),
        HookKind::HeaderFilter => conf.header_filter = Some(hook),
    })
}

fn inline(directive: &Directive) -> Result<LuaHook> {
    directive.expect_args(1)?;
    let source = directive.args[0].clone();
    validate(
        &source,
        &format!("{}:{}", directive.file.display(), directive.line),
    )
    .map_err(|error| directive.error(format!("invalid Lua: {error}")))?;
    Ok(LuaHook {
        source,
        name: format!("{}:{}", directive.file.display(), directive.line),
    })
}

fn load_file(directive: &Directive, base_dir: &Path) -> Result<LuaHook> {
    directive.expect_args(1)?;
    let path = crate::core::value::resolve_path(base_dir, &directive.args[0]);
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read Lua hook {}", path.display()))?;
    validate(&source, &path.to_string_lossy())
        .map_err(|error| directive.error(format!("invalid Lua: {error}")))?;
    Ok(LuaHook {
        source,
        name: path.display().to_string(),
    })
}

fn validate(source: &str, name: &str) -> mlua::Result<()> {
    Lua::new_with(
        StdLib::COROUTINE | StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8,
        LuaOptions::default(),
    )?
    .load(source)
    .set_name(name)
    .into_function()
    .map(|_| ())
}

#[derive(Clone, Debug, Default)]
pub struct LuaOutcome {
    pub uri: Option<String>,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub request_headers: Vec<(String, Option<String>)>,
    pub body: String,
    pub exited: bool,
}

/// Run a request hook against the current request.
pub fn execute(hook: &LuaHook, state: &RequestState) -> Result<LuaOutcome> {
    let lua = sandboxed_lua()?;
    let outcome = Arc::new(Mutex::new(LuaOutcome::default()));
    install_ngx(&lua, state, outcome.clone())?;
    run(&lua, hook, &outcome)?;
    Ok(outcome.lock().expect("Lua state mutex").clone())
}

/// Run a header filter hook over an existing response header set.
pub fn execute_header_filter(
    hook: &LuaHook,
    status: u16,
    headers: &[(String, String)],
    state: &RequestState,
) -> Result<LuaOutcome> {
    let lua = sandboxed_lua()?;
    let initial = LuaOutcome {
        status: Some(status),
        headers: headers.to_vec(),
        ..LuaOutcome::default()
    };
    let outcome = Arc::new(Mutex::new(initial));
    install_ngx(&lua, state, outcome.clone())?;
    run(&lua, hook, &outcome)?;
    Ok(outcome.lock().expect("Lua state mutex").clone())
}

fn run(lua: &Lua, hook: &LuaHook, outcome: &Arc<Mutex<LuaOutcome>>) -> Result<()> {
    match lua.load(&hook.source).set_name(&hook.name).exec() {
        Ok(()) => Ok(()),
        Err(error) => {
            let exited = outcome.lock().expect("Lua state mutex").exited;
            if exited {
                Ok(())
            } else {
                Err(error).with_context(|| format!("Lua hook {} failed", hook.name))
            }
        }
    }
}

fn sandboxed_lua() -> Result<Lua> {
    Lua::new_with(
        StdLib::COROUTINE | StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8,
        LuaOptions::default(),
    )
    .context("cannot initialize Lua 5.4 runtime")
}

fn install_ngx(lua: &Lua, state: &RequestState, outcome: Arc<Mutex<LuaOutcome>>) -> Result<()> {
    let ngx = lua.create_table()?;
    let var = lua.create_table()?;
    for name in [
        "uri",
        "request_uri",
        "host",
        "remote_addr",
        "remote_port",
        "realip_remote_addr",
        "args",
        "query_string",
        "scheme",
        "server_name",
        "request_method",
    ] {
        var.set(name, state.variable(name).unwrap_or_default())?;
    }
    ngx.set("var", var)?;

    let req = lua.create_table()?;
    let uri = state.request.path.clone();
    req.set(
        "get_uri",
        lua.create_function(move |_, ()| Ok(uri.clone()))?,
    )?;
    let method = state.request.method.to_string();
    req.set(
        "get_method",
        lua.create_function(move |_, ()| Ok(method.clone()))?,
    )?;
    let uri_state = outcome.clone();
    req.set(
        "set_uri",
        lua.create_function(move |_, uri: String| {
            if !uri.starts_with('/') {
                return Err(mlua::Error::external(
                    "ngx.req.set_uri expects an absolute path",
                ));
            }
            uri_state.lock().expect("Lua state mutex").uri = Some(uri);
            Ok(())
        })?,
    )?;
    let request_headers = state.headers.clone();
    req.set(
        "get_headers",
        lua.create_function(move |lua, ()| header_table(lua, &request_headers))?,
    )?;
    let header_state = outcome.clone();
    req.set(
        "set_header",
        lua.create_function(move |_, (name, value): (String, String)| {
            header_state
                .lock()
                .expect("Lua state mutex")
                .request_headers
                .push((name, Some(value)));
            Ok(())
        })?,
    )?;
    let header_state = outcome.clone();
    req.set(
        "clear_header",
        lua.create_function(move |_, name: String| {
            header_state
                .lock()
                .expect("Lua state mutex")
                .request_headers
                .push((name, None));
            Ok(())
        })?,
    )?;
    ngx.set("req", req)?;

    // `ngx.header` uses a metatable so ordinary Lua assignment updates Rust state.
    let header = lua.create_table()?;
    let metatable = lua.create_table()?;
    let header_state = outcome.clone();
    metatable.set(
        "__newindex",
        lua.create_function(move |_, (_table, name, value): (Table, String, String)| {
            header_state
                .lock()
                .expect("Lua state mutex")
                .headers
                .push((name, value));
            Ok(())
        })?,
    )?;
    let header_state = outcome.clone();
    metatable.set(
        "__index",
        lua.create_function(move |_, (_table, name): (Table, String)| {
            let outcome = header_state.lock().expect("Lua state mutex");
            Ok(outcome
                .headers
                .iter()
                .rev()
                .find(|(key, _)| key.eq_ignore_ascii_case(&name))
                .map(|(_, value)| value.clone()))
        })?,
    )?;
    header.set_metatable(Some(metatable))?;
    ngx.set("header", header)?;

    let body_state = outcome.clone();
    ngx.set(
        "say",
        lua.create_function(move |_, values: Variadic<Value>| {
            let mut outcome = body_state.lock().expect("Lua state mutex");
            for value in values {
                outcome.body.push_str(&lua_value_string(value)?);
            }
            outcome.body.push('\n');
            Ok(())
        })?,
    )?;
    let body_state = outcome.clone();
    ngx.set(
        "print",
        lua.create_function(move |_, values: Variadic<Value>| {
            let mut outcome = body_state.lock().expect("Lua state mutex");
            for value in values {
                outcome.body.push_str(&lua_value_string(value)?);
            }
            Ok(())
        })?,
    )?;
    let exit_state = outcome.clone();
    ngx.set(
        "exit",
        lua.create_function(move |_, status: Option<u16>| {
            let mut outcome = exit_state.lock().expect("Lua state mutex");
            outcome.status = status.or(outcome.status);
            outcome.exited = true;
            Err::<(), _>(mlua::Error::external("NGINXRS_EXIT"))
        })?,
    )?;
    let redirect_state = outcome.clone();
    ngx.set(
        "redirect",
        lua.create_function(move |_, (uri, status): (String, Option<u16>)| {
            let status = status.unwrap_or(302);
            if status != 301 && status != 302 {
                return Err(mlua::Error::external(
                    "ngx.redirect supports status 301 or 302",
                ));
            }
            let mut outcome = redirect_state.lock().expect("Lua state mutex");
            outcome.status = Some(status);
            outcome.headers.push(("Location".into(), uri));
            outcome.exited = true;
            Err::<(), _>(mlua::Error::external("NGINXRS_EXIT"))
        })?,
    )?;
    ngx.set(
        "log",
        lua.create_function(|_, (_level, values): (Value, Variadic<Value>)| {
            let message = values
                .into_iter()
                .map(lua_value_string)
                .collect::<mlua::Result<Vec<_>>>()?
                .join("");
            log::info!(target: "nginxrs::lua", "{message}");
            Ok(())
        })?,
    )?;
    for (name, value) in [
        ("OK", 0),
        ("ERROR", -1),
        ("DECLINED", -2),
        ("INFO", 6),
        ("NOTICE", 5),
        ("WARN", 4),
        ("ERR", 3),
        ("HTTP_OK", 200),
        ("HTTP_FORBIDDEN", 403),
        ("HTTP_NOT_FOUND", 404),
        ("HTTP_INTERNAL_SERVER_ERROR", 500),
    ] {
        ngx.set(name, value)?;
    }
    let status_meta = lua.create_table()?;
    let status_state = outcome.clone();
    status_meta.set(
        "__newindex",
        lua.create_function(move |_, (_table, key, value): (Table, String, u16)| {
            if key == "status" {
                status_state.lock().expect("Lua state mutex").status = Some(value);
            }
            Ok(())
        })?,
    )?;
    let status_state = outcome.clone();
    status_meta.set(
        "__index",
        lua.create_function(move |_, (_table, key): (Table, String)| {
            if key == "status" {
                Ok(status_state.lock().expect("Lua state mutex").status)
            } else {
                Ok(None)
            }
        })?,
    )?;
    ngx.set_metatable(Some(status_meta))?;
    lua.globals().set("ngx", ngx)?;
    Ok(())
}

fn header_table(lua: &Lua, headers: &HeaderMap) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            table.set(name.as_str().to_ascii_lowercase(), value)?;
        }
    }
    Ok(table)
}

fn lua_value_string(value: Value) -> mlua::Result<String> {
    match value {
        Value::Nil => Ok(String::new()),
        Value::Boolean(value) => Ok(value.to_string()),
        Value::Integer(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => Ok(value.to_str()?.to_owned()),
        other => Err(mlua::Error::external(format!(
            "cannot convert Lua {} to a response string",
            other.type_name()
        ))),
    }
}

/// Apply Lua-written request header changes to a header map.
pub fn apply_request_headers(
    map: &mut HeaderMap,
    changes: &[(String, Option<String>)],
) -> Result<()> {
    for (name, value) in changes {
        match value {
            Some(value) => {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|error| anyhow::anyhow!("invalid header name {name}: {error}"))?;
                map.insert(name, value.parse()?);
            }
            None => {
                map.remove(name.as_str());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::{ConnectionState, RequestLine, RequestState};

    fn state() -> RequestState {
        let request = pingora_http::RequestHeader::build("GET", b"/old?a=1", None).unwrap();
        RequestState::new(
            ConnectionState {
                listen: "127.0.0.1:80".into(),
                peer_ip: Some("127.0.0.1".parse().unwrap()),
                peer_port: 1000,
                local_ip: Some("127.0.0.1".parse().unwrap()),
                local_port: 80,
                scheme: "http".into(),
                tls: false,
            },
            RequestLine::from_header(&request),
            request.headers.clone(),
            &[],
        )
    }

    #[test]
    fn lua_can_rewrite_set_headers_and_respond() {
        let hook = LuaHook {
            source: r#"
                ngx.req.set_uri("/new")
                ngx.header["X-Lua"] = "yes"
                ngx.req.set_header("X-From-Lua", "yes")
                ngx.say("hello ", 42)
                ngx.status = 201
            "#
            .into(),
            name: "test".into(),
        };
        let outcome = execute(&hook, &state()).unwrap();
        assert_eq!(outcome.uri.as_deref(), Some("/new"));
        assert_eq!(outcome.status, Some(201));
        assert_eq!(outcome.body, "hello 42\n");
        assert!(outcome.headers.contains(&("X-Lua".into(), "yes".into())));
        assert!(
            outcome
                .request_headers
                .contains(&("X-From-Lua".into(), Some("yes".into())))
        );
    }

    #[test]
    fn exit_stops_script() {
        let hook = LuaHook {
            source: "ngx.exit(403); ngx.say('unreachable')".into(),
            name: "test".into(),
        };
        let outcome = execute(&hook, &state()).unwrap();
        assert_eq!(outcome.status, Some(403));
        assert!(outcome.exited);
        assert!(outcome.body.is_empty());
    }

    #[test]
    fn header_filter_sees_existing_headers() {
        let hook = LuaHook {
            source: "ngx.header['X-Filtered'] = tostring(ngx.header['X-In'])".into(),
            name: "test".into(),
        };
        let outcome = execute_header_filter(
            &hook,
            200,
            &[("X-In".to_string(), "v".to_string())],
            &state(),
        )
        .unwrap();
        assert!(outcome.headers.contains(&("X-Filtered".into(), "v".into())));
    }
}
