//! Building blocks shared by all Nginx-compatible modules.

pub mod http;
pub mod http_core;
pub mod layout;
pub mod maintain;
pub mod reload;
pub mod runner;
pub mod source;
pub mod state;
pub mod syntax;
pub mod tls;
pub mod value;
pub mod variables;

pub use state::{StateInstance, States};
pub use variables::{ConnectionInfo, Template, VariableProvider, Variables};

/// Pingora application traits a service implementation implements.
pub mod apps {
    pub use pingora_core::apps::ServerApp;
}

/// Where a directive may appear. Mirrors `NGX_MAIN_CONF`, `NGX_HTTP_LOC_CONF`,
/// `NGX_HTTP_SRV_CONF` and `NGX_HTTP_MAIN_CONF` checks in Nginx modules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Context {
    Main,
    Events,
    Http,
    Server,
    Location,
    Upstream,
}

/// Module-level classification used by `-t` output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleKind {
    /// `ngx_core_module` / `ngx_events_module` style process configuration.
    Core,
    /// `ngx_http_core_module`: request line, servers, locations.
    HttpCore,
    /// Optional HTTP module such as realip, rewrite, proxy.
    Http,
}

/// HTTP request phases exposed to modules, ordered like Nginx's `ngx_http_phases`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// `NGX_HTTP_POST_READ_PHASE`: runs right after the request line is read.
    PostRead,
    /// `NGX_HTTP_SERVER_REWRITE_PHASE`.
    ServerRewrite,
    /// `NGX_HTTP_FIND_CONFIG_PHASE`.
    FindConfig,
    /// `NGX_HTTP_REWRITE_PHASE`.
    Rewrite,
    /// `NGX_HTTP_PREACCESS_PHASE`.
    PreAccess,
    /// `NGX_HTTP_ACCESS_PHASE`.
    Access,
    /// `NGX_HTTP_POST_ACCESS_PHASE`.
    PostAccess,
    /// `NGX_HTTP_PRECONTENT_PHASE`.
    PreContent,
    /// `NGX_HTTP_CONTENT_PHASE`.
    Content,
}

/// Result of one phase handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Continue with the next handler/phase.
    Defer,
    /// A response has been produced; stop processing this request.
    Stop,
}

pub type PhaseResult = anyhow::Result<Outcome>;

/// The module contract. New Nginx modules implement this trait and are registered in
/// [`crate::modules::registry::Registry`]; the HTTP core never knows module names.
pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn kind(&self) -> ModuleKind;

    /// `'static` form of [`Module::name`], used to key compiled state.
    fn name_static(&self) -> &'static str {
        Box::leak(self.name().to_string().into_boxed_str())
    }

    /// The module's process/`http {}`-level state type, if it has one.
    fn http_state(&self) -> Option<StateInstance> {
        None
    }

    /// Directives provided by the module, in declaration order.
    fn directives(&self) -> Vec<DirectiveSpec> {
        Vec::new()
    }

    /// Variables registered by this module.
    fn variables(&self) -> Vec<(&'static str, &'static dyn VariableProvider)> {
        Vec::new()
    }
}

/// Directive registry entry.
pub struct DirectiveSpec {
    pub name: &'static str,
    pub contexts: &'static [Context],
    pub handler: fn(&mut crate::modules::registry::DirectiveView<'_>) -> anyhow::Result<()>,
}


