//! Module registry and directive dispatch.
//!
//! Every supported directive belongs to exactly one [`Module`]. The registry is the
//! single source of truth for "which module owns this directive and in which contexts",
//! mirroring Nginx's `ngx_command_t` tables without one global mega-match. The HTTP core
//! only knows this table, never individual module names.

use crate::core::state::StateAccess;
use crate::core::syntax::Directive;
use crate::core::{Context, DirectiveSpec, Module};
use crate::modules::location::Location;
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

pub struct Registry {
    modules: Vec<Arc<dyn Module>>,
    /// `(module index, directive index)` keyed by directive name.
    lookup: HashMap<&'static str, (usize, usize)>,
    /// Directive tables, built once and reused for every context check.
    tables: Vec<Vec<DirectiveSpec>>,
}

impl Registry {
    pub fn new(modules: Vec<Arc<dyn Module>>) -> Self {
        let mut tables = Vec::with_capacity(modules.len());
        let mut lookup = HashMap::new();
        for (module_index, module) in modules.iter().enumerate() {
            let table = module.directives();
            for (spec_index, spec) in table.iter().enumerate() {
                if let Some((owner, _)) = lookup.insert(spec.name, (module_index, spec_index)) {
                    panic!(
                        "duplicate directive \"{}\" registered by {} and {}",
                        spec.name,
                        modules[owner].name(),
                        module.name()
                    );
                }
            }
            tables.push(table);
        }
        Self {
            modules,
            lookup,
            tables,
        }
    }

    /// The module set shipped with nginxrs, in Nginx-like order.
    ///
    /// To add a new Nginx module: implement [`Module`] in its own file, add it to
    /// [`crate::modules`], and add one line here.
    pub fn default_modules() -> Self {
        use crate::modules::{
            access, body, headers, http_core, limit_conn, limit_req, log, lua, proxy, realip,
            rewrite, ssl, static_files, stub_status, upstream,
        };
        Self::new(vec![
            Arc::new(http_core::HttpCoreModule),
            Arc::new(rewrite::RewriteModule),
            Arc::new(realip::RealipModule),
            Arc::new(access::AccessModule),
            Arc::new(limit_conn::LimitConnModule),
            Arc::new(limit_req::LimitReqModule),
            Arc::new(log::AccessLogModule),
            Arc::new(headers::HeadersModule),
            Arc::new(lua::LuaModule),
            Arc::new(upstream::UpstreamModule),
            Arc::new(proxy::ProxyModule),
            Arc::new(ssl::SslModule),
            Arc::new(static_files::StaticModule),
            Arc::new(stub_status::StubStatusModule),
            Arc::new(body::BodyModule),
        ])
    }

    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    pub fn owner(&self, name: &str) -> Option<&Arc<dyn Module>> {
        let (module_index, _) = *self.lookup.get(name)?;
        Some(&self.modules[module_index])
    }

    pub fn is_known(&self, name: &str) -> bool {
        self.lookup.contains_key(name)
    }

    /// Resolve a directive for a context, returning the owning module and its spec.
    pub fn resolve(
        &self,
        name: &str,
        context: Context,
    ) -> Option<(Arc<dyn Module>, &DirectiveSpec)> {
        let (module_index, spec_index) = *self.lookup.get(name)?;
        let spec = self.tables[module_index].get(spec_index)?;
        if !spec.contexts.contains(&context) {
            return None;
        }
        Some((self.modules[module_index].clone(), spec))
    }

    /// Directives accepted in `context`, for `-t` diagnostics.
    pub fn supported_in(&self, context: Context) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self
            .tables
            .iter()
            .flatten()
            .filter(|spec| spec.contexts.contains(&context))
            .map(|spec| spec.name)
            .collect();
        names.sort_unstable();
        names
    }

    /// Call one directive handler.
    pub fn dispatch<'a>(
        &self,
        directive: &'a Directive,
        context: Context,
        base_dir: &'a Path,
        states: &'a mut StateAccess<'a>,
        location: Option<&'a mut Location>,
    ) -> Result<()> {
        let Some((module, spec)) = self.resolve(&directive.name, context) else {
            return if self.is_known(&directive.name) {
                Err(wrong_context(directive, context))
            } else {
                Err(unknown_directive(directive))
            };
        };
        let mut view = DirectiveView {
            module: module.name(),
            directive,
            context,
            base_dir,
            states,
            location,
        };
        (spec.handler)(&mut view)
    }
}

/// Handle to one directive during configuration parsing.
pub struct DirectiveView<'a> {
    /// Name of the owning module, used to locate its state.
    pub module: &'static str,
    pub directive: &'a Directive,
    pub context: Context,
    /// Base directory for relative paths (directory of the main configuration file).
    pub base_dir: &'a Path,
    /// Every module's configuration bucket.
    pub states: &'a mut StateAccess<'a>,
    /// Location being built, when the directive is in an HTTP scope.
    pub location: Option<&'a mut Location>,
}

impl<'a> DirectiveView<'a> {
    pub fn path(&self, value: &str) -> std::path::PathBuf {
        crate::core::value::resolve_path(self.base_dir, value)
    }

    /// The owning module's own state.
    ///
    /// Process-level directives registered by the HTTP core module
    /// (`worker_processes`, `user`, `pid`, ...) live in the dedicated `main` slot.
    pub fn state<T: 'static>(&mut self) -> Result<&mut T> {
        let module = if matches!(self.context, Context::Main | Context::Events) {
            "main"
        } else {
            self.module
        };
        self.states.get_mut::<T>(module).ok_or_else(|| {
            self.directive
                .error(format!("module {module} has no state of the expected type"))
        })
    }

    /// Read the owning module's location configuration without creating it.
    pub fn location_conf<T: crate::modules::location::LocationConf>(&self) -> Option<&T> {
        self.location
            .as_deref()
            .and_then(|location| location.get::<T>())
    }

    /// Attach (or update) this location's configuration of type `T`.
    pub fn update_conf<T>(&mut self, update: impl FnOnce(&mut T)) -> Result<()>
    where
        T: crate::modules::location::LocationConf + Default,
    {
        let directive = self.directive;
        let location = self.location.as_deref_mut().ok_or_else(|| {
            directive.error("directive is only valid in a location or server context")
        })?;
        if !location.has::<T>() {
            location.set(T::default());
        }
        let Some(conf) = location.get_mut::<T>() else {
            return Err(directive.error("module configuration type mismatch"));
        };
        update(conf);
        Ok(())
    }
}

/// Report an unknown directive with file and line.
pub fn unknown_directive(directive: &Directive) -> anyhow::Error {
    directive.error("unknown directive")
}

/// Report a directive used outside its allowed contexts.
pub fn wrong_context(directive: &Directive, context: Context) -> anyhow::Error {
    directive.error(format!(
        "directive is not allowed here (context: {context:?})"
    ))
}
