//! `ngx_http_core_module`: process configuration, request line and the server /
//! location tree.
//!
//! This module owns `worker_processes`, `events`, `http`, `server`, `listen`,
//! `server_name` and `location`. Every other directive found inside those blocks is
//! dispatched through the [`Registry`](crate::modules::registry::Registry), so the HTTP
//! core never hard-codes the name of another module.

use crate::core::state::{StateAccess, StateSlot};
use crate::core::syntax::Directive;
use crate::core::value::parse_listen_address;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::Location;
use crate::modules::registry::Registry;
use anyhow::{Context as _, Result, bail};
use regex::{Regex, RegexBuilder};
use std::path::{Path, PathBuf};

/// `ngx_http_core_module`: process configuration, request line and the server / location
/// tree.
///
/// The module owns `worker_processes`, `events`, `http`, `server`, `listen`,
/// `server_name` and `location`. Every other directive found inside those blocks is
/// dispatched through [`Registry`](crate::modules::registry::Registry), so the HTTP core
/// never hard-codes the name of another module.
pub struct HttpCoreModule;

pub const MODULE_NAME: &str = "ngx_http_core_module";

impl Module for HttpCoreModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::HttpCore
    }

    fn http_state(&self) -> Option<crate::core::StateInstance> {
        Some(crate::core::StateInstance::new(MimeConfig::default()))
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        let mut specs = vec![
            spec("worker_processes", &[Context::Main], handler_main_directive),
            spec("user", &[Context::Main], handler_main_directive),
            spec("pid", &[Context::Main], handler_pid),
            spec("error_log", &[Context::Main], handler_main_directive),
            spec("daemon", &[Context::Main], handler_main_directive),
            spec("master_process", &[Context::Main], handler_main_directive),
            spec(
                "worker_rlimit_nofile",
                &[Context::Main],
                handler_main_directive,
            ),
            spec("events", &[Context::Main], handler_events),
            spec("types", &[Context::Http], handler_types),
            spec("default_type", &[Context::Http], handler_default_type),
            spec(
                "worker_connections",
                &[Context::Events],
                handler_events_child,
            ),
            spec("multi_accept", &[Context::Events], handler_events_child),
            spec("use", &[Context::Events], handler_events_child),
        ];
        // Structural directives are compiled by `HttpCompiler`, never by dispatch.
        for (name, contexts) in [
            ("http", &[Context::Main][..]),
            ("server", &[Context::Http][..]),
            ("listen", &[Context::Server][..]),
            ("server_name", &[Context::Server][..]),
            ("location", &[Context::Server, Context::Location][..]),
        ] {
            specs.push(DirectiveSpec {
                name,
                contexts,
                handler: dispatch_to_compiler,
            });
        }
        specs
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

/// Marker stating that a directive must be handled by the compiler itself.
fn dispatch_to_compiler(_: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    unreachable!(
        "ngx_http_core_module directives are compiled by HttpCompiler, not by the generic dispatcher"
    )
}

/// `http {}`-level MIME configuration (`types`, `default_type`).
#[derive(Clone, Debug, Default)]
pub struct MimeConfig {
    /// extension (lowercase) → content type
    pub types: std::collections::HashMap<String, String>,
    pub default_type: String,
}

impl MimeConfig {
    pub fn content_type(&self, path: &std::path::Path) -> Option<&str> {
        let extension = path.extension()?.to_str()?.to_ascii_lowercase();
        self.types.get(&extension).map(String::as_str)
    }
}

/// Registered as the `ngx_http_core_module` state, since `types` and `default_type` are
/// core directives in Nginx.
pub type HttpCoreState = MimeConfig;

/// The compiled `http {}` configuration.
#[derive(Debug)]
pub struct HttpConfig {
    pub servers: Vec<ServerConfig>,
    pub warnings: Vec<String>,
}

impl HttpConfig {
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listens: Vec<ListenConfig>,
    pub server_names: Vec<String>,
    pub locations: Vec<CompiledLocation>,
    /// `listen ... http2`: advertise `h2` through ALPN (`ssl_alpn`).
    pub http2: bool,
}

#[derive(Clone, Debug)]
pub struct ListenConfig {
    pub address: String,
    pub default_server: bool,
    /// `listen ... ssl`: served by the SSL module over TLS.
    pub tls: bool,
    /// `listen ... http2`: ALPN offers `h2` on this TLS listener.
    pub http2: bool,
}

#[derive(Clone, Debug)]
pub struct CompiledLocation {
    pub matcher: LocationMatcher,
    pub conf: Location,
    /// Location pattern for diagnostics, e.g. `^~ /media/`.
    pub pattern: String,
}

#[derive(Clone, Debug)]
pub enum LocationMatcher {
    Prefix { value: String, no_regex: bool },
    Exact(String),
    Regex { regex: Regex, case_sensitive: bool },
}

impl LocationMatcher {
    pub fn matched_prefix(&self) -> Option<&str> {
        match self {
            LocationMatcher::Prefix { value, .. } => Some(value),
            LocationMatcher::Exact(value) => Some(value),
            LocationMatcher::Regex { .. } => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            LocationMatcher::Prefix { value, no_regex } => {
                if *no_regex {
                    format!("^~ {value}")
                } else {
                    value.clone()
                }
            }
            LocationMatcher::Exact(value) => format!("= {value}"),
            LocationMatcher::Regex {
                regex,
                case_sensitive,
            } => format!("{}{regex}", if *case_sensitive { "~ " } else { "~* " }),
        }
    }
}

/// Compiler state threaded through the whole `http {}` tree.
pub struct HttpCompiler<'a> {
    registry: &'a Registry,
    base_dir: PathBuf,
    pub http: HttpConfig,
    /// Defaults inherited from `http {}` into every server.
    http_location: Location,
    /// `http {}`-level SSL settings (`ngx_http_ssl_merge_srv_conf` parent).
    http_tls: Option<crate::modules::ssl::conf::TlsServerConf>,
}

impl<'a> HttpCompiler<'a> {
    pub fn new(registry: &'a Registry, base_dir: &Path) -> Self {
        Self {
            registry,
            base_dir: base_dir.to_path_buf(),
            http: HttpConfig::new(),
            http_location: Location::new(),
            http_tls: None,
        }
    }

    pub fn registry(&self) -> &Registry {
        self.registry
    }

    pub fn warnings(&self) -> &[String] {
        &self.http.warnings
    }

    /// Compile the main configuration into the `http {}` structure, mutating module
    /// state in place. Returns the compiler so the caller can take the result with
    /// [`HttpCompiler::finish`], keeping the owning state vector intact.
    pub fn run(
        registry: &'a Registry,
        base_dir: &Path,
        nodes: &[Directive],
        states: &mut [StateSlot],
    ) -> Result<Self> {
        let mut compiler = Self::new(registry, base_dir);
        for node in nodes {
            match node.name.as_str() {
                "http" => compiler.compile_http(node, states)?,
                "events" => {
                    node.expect_block_only()?;
                    for child in node.block()? {
                        let base_dir = compiler.base_dir.clone();
                        let mut access = StateAccess::new(states);
                        Registry::dispatch(
                            registry,
                            child,
                            Context::Events,
                            &base_dir,
                            &mut access,
                            None,
                        )?;
                    }
                }
                _ => {
                    let base_dir = compiler.base_dir.clone();
                    let mut access = StateAccess::new(states);
                    Registry::dispatch(
                        registry,
                        node,
                        Context::Main,
                        &base_dir,
                        &mut access,
                        None,
                    )?;
                }
            }
        }
        if compiler.http.servers.is_empty() {
            bail!("configuration has no server block");
        }
        Ok(compiler)
    }

    fn compile_http(&mut self, directive: &Directive, states: &mut [StateSlot]) -> Result<()> {
        directive.expect_block_only()?;
        let children = directive.block()?.to_vec();
        // Nginx resolves `limit_req` zone references during configuration merge, so
        // declaration order must not matter. Register zones before pass 1.
        {
            let mut access = StateAccess::new(states);
            crate::modules::limit_conn::prescan_zones(&children, &mut access)?;
            crate::modules::limit_req::prescan_zones(&children, &mut access)?;
        }
        // Pass 1: shared definitions and `http`-level defaults.
        for child in &children {
            match child.name.as_str() {
                "server" => continue,
                "worker_processes" | "events" | "http" => {
                    return Err(crate::modules::registry::wrong_context(
                        child,
                        Context::Http,
                    ));
                }
                _ => {
                    let base_dir = self.base_dir.clone();
                    let mut access = StateAccess::new(states);
                    Registry::dispatch(
                        self.registry,
                        child,
                        Context::Http,
                        &base_dir,
                        &mut access,
                        Some(&mut self.http_location),
                    )?;
                }
            }
        }
        // Pass 2: virtual hosts.
        for child in &children {
            if child.name == "server" {
                self.compile_server(child, states)?;
            }
        }
        Ok(())
    }

    /// The `http {}`-level TLS defaults, captured after pass 1.
    fn capture_http_tls(&mut self, states: &[StateSlot]) {
        let access = StateAccess::new_readonly(states);
        if let Some(tls) = crate::modules::ssl::state_ref(&access) {
            let index = tls.current_server();
            self.http_tls = tls.server(index).cloned();
        }
    }

    /// Return the compiled HTTP tree plus the module states, discarding the compiler.
    pub fn finish(self) -> HttpConfig {
        self.http
    }

    fn compile_server(&mut self, directive: &Directive, states: &mut [StateSlot]) -> Result<()> {
        directive.expect_block_only()?;
        let mut listens = Vec::new();
        let mut server_names = Vec::new();
        let mut location_nodes = Vec::new();
        let mut secure_listens: Vec<String> = Vec::new();
        let server_index = self.http.servers.len();
        {
            // Tell the SSL module which server the upcoming directives belong to.
            let mut access = StateAccess::new(states);
            if let Some(tls) = crate::modules::ssl::state_mut(&mut access) {
                tls.begin_server(server_index);
            }
        }
        let mut server_location = Location::new();
        server_location.inherit_from(&self.http_location);
        for child in directive.block()? {
            match child.name.as_str() {
                "listen" => {
                    let listen = parse_listen(child)?;
                    if listen.tls {
                        secure_listens.push(listen.address.clone());
                    }
                    listens.push(listen);
                }
                "server_name" => {
                    if child.has_block() || child.args.is_empty() {
                        return Err(child.error("expected one or more server names"));
                    }
                    server_names.extend(child.args.iter().cloned());
                }
                "location" => location_nodes.push(child),
                _ => {
                    let base_dir = self.base_dir.clone();
                    let mut access = StateAccess::new(states);
                    Registry::dispatch(
                        self.registry,
                        child,
                        Context::Server,
                        &base_dir,
                        &mut access,
                        Some(&mut server_location),
                    )?;
                }
            }
        }
        if listens.is_empty() {
            listens.push(ListenConfig {
                address: "0.0.0.0:80".to_string(),
                default_server: false,
                tls: false,
                http2: false,
            });
        }
        if server_names.is_empty() {
            server_names.push(String::new());
        }
        let mut locations = Vec::new();
        for node in location_nodes {
            locations.push(self.compile_location(node, states, &server_location)?);
        }
        if locations.is_empty() {
            locations.push(CompiledLocation {
                matcher: LocationMatcher::Prefix {
                    value: "/".to_string(),
                    no_regex: false,
                },
                conf: server_location,
                pattern: "/".to_string(),
            });
        }
        {
            let mut access = StateAccess::new(states);
            if let Some(tls) = crate::modules::ssl::state_mut(&mut access) {
                let secure: Vec<String> = listens
                    .iter()
                    .filter(|listen| listen.tls)
                    .map(|listen| listen.address.clone())
                    .collect();
                let inherited = self.http_tls.clone();
                tls.finish_server(
                    server_index,
                    inherited.as_ref(),
                    &secure,
                    &server_names,
                )?;
            }
        }
        self.http.servers.push(ServerConfig {
            http2: listens.iter().any(|listen| listen.http2),
            listens,
            server_names,
            locations,
        });
        Ok(())
    }

    fn compile_location(
        &mut self,
        node: &Directive,
        states: &mut [StateSlot],
        server_location: &Location,
    ) -> Result<CompiledLocation> {
        if !node.has_block() || node.args.is_empty() || node.args.len() > 2 {
            return Err(node.error("expected location [=|^~|~|~*] uri { ... }"));
        }
        let matcher = parse_location_matcher(node)?;
        let mut location = Location::new();
        location.inherit_from(server_location);
        for child in node.block()? {
            match child.name.as_str() {
                "location" => {
                    return Err(
                        child.error("nested locations are not implemented; use one location")
                    );
                }
                _ => {
                    let base_dir = self.base_dir.clone();
                    let mut access = StateAccess::new(states);
                    Registry::dispatch(
                        self.registry,
                        child,
                        Context::Location,
                        &base_dir,
                        &mut access,
                        Some(&mut location),
                    )?;
                }
            }
        }
        Ok(CompiledLocation {
            pattern: matcher.describe(),
            matcher,
            conf: location,
        })
    }
}

/// Parse the `types { ... }` block: `type { ext ext; }` entries.
fn handler_types(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if !directive.args.is_empty() || directive.children.is_none() {
        return Err(directive.error("expected types { ... }"));
    }
    for entry in directive.block()? {
        if entry.children.is_some() || entry.args.is_empty() {
            return Err(entry.error("expected MIME-type extension ...;"));
        }
        let content_type = entry.name.clone();
        for extension in &entry.args {
            view.state::<HttpCoreState>()?
                .types
                .insert(extension.to_ascii_lowercase(), content_type.clone());
        }
    }
    Ok(())
}

fn handler_default_type(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    view.state::<HttpCoreState>()?.default_type = directive.args[0].clone();
    Ok(())
}

/// `worker_processes` and the process-level directives that Pingora owns.
fn handler_main_directive(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.name == "worker_processes" {
        directive.expect_args(1)?;
        let value = if directive.args[0] == "auto" {
            std::thread::available_parallelism().map_or(1, usize::from)
        } else {
            directive.args[0]
                .parse()
                .context("invalid worker_processes")?
        };
        view.state::<crate::config::MainState>()?.worker_processes = Some(value);
        return Ok(());
    }
    view.state::<crate::config::MainState>()?
        .warnings
        .push(format!(
            "{}:{}: {} is accepted for compatibility but is managed by the Pingora process/runtime",
            directive.file.display(),
            directive.line,
            directive.name
        ));
    Ok(())
}

/// `pid` names the pid file that `nginxrs -s reload|stop` uses.
fn handler_pid(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let path = view.path(&directive.args[0]);
    view.state::<crate::config::MainState>()?.pid_file = Some(path);
    Ok(())
}

fn handler_events(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    view.directive.expect_block_only()
}

fn handler_events_child(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    log::warn!(
        "{}:{}: events/{} is accepted for syntax compatibility; Pingora owns the event loop",
        directive.file.display(),
        directive.line,
        directive.name
    );
    Ok(())
}

pub fn parse_listen(directive: &Directive) -> Result<ListenConfig> {
    if directive.has_block() || directive.args.is_empty() {
        return Err(directive.error("expected listen address[:port] [default_server];"));
    }
    let mut default_server = false;
    let mut tls = false;
    let mut http2 = false;
    let mut options = directive.args[1..].iter();
    while let Some(option) = options.next() {
        match option.as_str() {
            "default_server" | "default" => default_server = true,
            // `ssl` marks the listener for the SSL module; `http2` advertises h2 through
            // ALPN (Nginx 1.25+ prefers a separate `http2 on;` but still accepts this form).
            "ssl" => tls = true,
            "http2" => http2 = true,
            "reuseport" | "proxy_protocol" | "deferred" | "bind" => {}
            "so_keepalive" | "keepalive_timeout" => {}
            "ipv6only" | "so_rcvbuf" | "so_sndbuf" | "setfib" | "fastopen" | "backlog"
            | "accept_filter" | "rcvbuf" | "sndbuf" => {}
            other => return Err(directive.error(format!("unknown listen option {other}"))),
        }
    }
    let address = parse_listen_address(directive, &directive.args[0])?;
    Ok(ListenConfig {
        address,
        default_server,
        tls,
        http2,
    })
}

fn parse_location_matcher(node: &Directive) -> Result<LocationMatcher> {
    match node.args.as_slice() {
        [value] => Ok(LocationMatcher::Prefix {
            value: value.clone(),
            no_regex: false,
        }),
        [modifier, value] if modifier == "=" => Ok(LocationMatcher::Exact(value.clone())),
        [modifier, value] if modifier == "^~" => Ok(LocationMatcher::Prefix {
            value: value.clone(),
            no_regex: true,
        }),
        [modifier, value] if modifier == "~" || modifier == "~*" => {
            let case_sensitive = modifier == "~";
            let regex = RegexBuilder::new(value)
                .case_insensitive(!case_sensitive)
                .build()
                .with_context(|| {
                    format!(
                        "{}:{}: invalid location regex",
                        node.file.display(),
                        node.line
                    )
                })?;
            Ok(LocationMatcher::Regex {
                regex,
                case_sensitive,
            })
        }
        _ => Err(node.error("invalid location modifier")),
    }
}

/// Nginx location selection: exact match, then the longest prefix (stopping on
/// `^~`), then the first matching regex, then the longest prefix.
pub fn select_location<'a, T>(
    locations: &'a [T],
    uri: &str,
    matcher: impl Fn(&'a T) -> &'a LocationMatcher,
) -> Option<&'a T> {
    if let Some(location) = locations
        .iter()
        .find(|entry| matches!(matcher(entry), LocationMatcher::Exact(value) if value == uri))
    {
        return Some(location);
    }
    let longest_prefix = locations
        .iter()
        .filter(|entry| {
            matches!(matcher(entry), LocationMatcher::Prefix { value, .. } if uri.starts_with(value))
        })
        .max_by_key(|entry| match matcher(entry) {
            LocationMatcher::Prefix { value, .. } => value.len(),
            _ => 0,
        });
    if let Some(location) = longest_prefix
        && matches!(
            matcher(location),
            LocationMatcher::Prefix { no_regex: true, .. }
        )
    {
        return Some(location);
    }
    if let Some(location) = locations.iter().find(|entry| {
        matches!(matcher(entry), LocationMatcher::Regex { regex, .. } if regex.is_match(uri))
    }) {
        return Some(location);
    }
    longest_prefix
}

/// Parse the `host` used for server selection (lowercased, port stripped).
pub fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.');
    if let Some(rest) = host.strip_prefix('[') {
        return rest
            .find(']')
            .map(|end| rest[..end].to_ascii_lowercase())
            .unwrap_or_else(|| rest.to_ascii_lowercase());
    }
    host.split_once(':')
        .map(|(name, _)| name)
        .unwrap_or(host)
        .to_ascii_lowercase()
}

pub fn server_matches(server: &ServerConfig, host: &str) -> bool {
    server_matches_names(&server.server_names, host)
}

/// `server_name` matching without needing a full [`ServerConfig`].
pub fn server_matches_names(names: &[String], host: &str) -> bool {
    names.iter().any(|name| {
        let name = name.to_ascii_lowercase();
        name.is_empty()
            || name == "_"
            || name == host
            || name == "*"
            || name
                .strip_prefix("*.")
                .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
            || name
                .strip_prefix('.')
                .is_some_and(|suffix| host == suffix || host.ends_with(&format!(".{suffix}")))
            || name
                .strip_suffix(".*")
                .is_some_and(|prefix| host.starts_with(&format!("{prefix}.")))
    })
}

pub fn server_name_specificity(name: &str, host: &str) -> usize {
    let name = name.to_ascii_lowercase();
    if name == host {
        20_000 + name.len()
    } else if name.contains('*') {
        10_000 + name.len()
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Debug, Default, PartialEq)]
    struct TestConf(String);
    impl crate::modules::location::LocationConf for TestConf {}

    #[test]
    fn location_precedence_matches_nginx() {
        let mut plain = Location::new();
        plain.set(TestConf("/".into()));
        let mut exact = Location::new();
        exact.set(TestConf("/health".into()));
        let mut no_regex = Location::new();
        no_regex.set(TestConf("/assets/".into()));
        let mut regex = Location::new();
        regex.set(TestConf("regex-assets".into()));
        let locations = vec![
            CompiledLocation {
                matcher: LocationMatcher::Prefix {
                    value: "/".into(),
                    no_regex: false,
                },
                conf: plain,
                pattern: "/".into(),
            },
            CompiledLocation {
                matcher: LocationMatcher::Exact("/health".into()),
                conf: exact,
                pattern: "= /health".into(),
            },
            CompiledLocation {
                matcher: LocationMatcher::Prefix {
                    value: "/assets/".into(),
                    no_regex: true,
                },
                conf: no_regex,
                pattern: "^~ /assets/".into(),
            },
            CompiledLocation {
                matcher: LocationMatcher::Regex {
                    regex: Regex::new("assets").unwrap(),
                    case_sensitive: true,
                },
                conf: regex,
                pattern: "~ assets".into(),
            },
        ];
        let pick = |uri: &str| {
            select_location(&locations, uri, |entry| &entry.matcher)
                .and_then(|entry| entry.conf.get::<TestConf>())
                .map(|conf| conf.0.clone())
                .unwrap()
        };
        assert_eq!(pick("/health"), "/health");
        assert_eq!(pick("/assets/app.js"), "/assets/");
        assert_eq!(pick("/other/assets"), "regex-assets");
        assert_eq!(pick("/index.html"), "/");
    }

    #[test]
    fn server_names_match_wildcards() {
        let server = ServerConfig {
            listens: Vec::new(),
            server_names: vec!["example.com".into(), "*.example.org".into()],
            locations: Vec::new(),
        };
        assert!(server_matches(&server, "example.com"));
        assert!(server_matches(&server, "a.example.org"));
        assert!(!server_matches(&server, "example.net"));
        assert_eq!(normalize_host("Example.COM:8080"), "example.com");
    }

    #[test]
    fn registry_rejects_duplicate_directives() {
        struct Dup;
        impl Module for Dup {
            fn name(&self) -> &'static str {
                "dup"
            }
            fn kind(&self) -> ModuleKind {
                ModuleKind::Http
            }
            fn directives(&self) -> Vec<DirectiveSpec> {
                let handler = |_: &mut crate::modules::DirectiveView<'_>| Ok(());
                vec![
                    DirectiveSpec {
                        name: "dup_directive",
                        contexts: &[Context::Http],
                        handler,
                    },
                    DirectiveSpec {
                        name: "dup_directive",
                        contexts: &[Context::Http],
                        handler,
                    },
                ]
            }
        }
        let result =
            std::panic::catch_unwind(|| Registry::new(vec![Arc::new(Dup) as Arc<dyn Module>]));
        assert!(result.is_err());
    }
}
