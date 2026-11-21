//! Module registry and directive dispatch.
//!
//! Every supported directive belongs to exactly one [`Module`]. The registry is the
//! single source of truth for "which module owns this directive and in which contexts",
//! mirroring Nginx's `ngx_command_t` tables without one global mega-match. The HTTP core
//! only knows this table, never individual module names.
//!
//! A module may declare one directive name several times for *disjoint* contexts (nginx's
//! `error_log` exists in `main` and in `http`/`server`/`location`); the registry merges those
//! context lists and dispatches to the first owner. Overlapping contexts are a programming
//! error and panic at startup.

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
    /// Every context each directive is registered in (merged across disjoint declarations).
    contexts: HashMap<&'static str, Vec<Context>>,
}

impl Registry {
    pub fn new(modules: Vec<Arc<dyn Module>>) -> Self {
        let mut tables: Vec<Vec<DirectiveSpec>> = Vec::with_capacity(modules.len());
        let mut lookup: HashMap<&'static str, (usize, usize)> = HashMap::new();
        let mut contexts: HashMap<&'static str, Vec<Context>> = HashMap::new();
        for (module_index, module) in modules.iter().enumerate() {
            let table = module.directives();
            for (spec_index, spec) in table.iter().enumerate() {
                let declared = contexts.entry(spec.name).or_default();
                if let Some(overlap) = spec
                    .contexts
                    .iter()
                    .find(|context| declared.contains(context))
                {
                    let owner = lookup
                        .get(spec.name)
                        .and_then(|(owner, _)| modules.get(*owner))
                        .map(|owner| owner.name())
                        .unwrap_or(module.name());
                    panic!(
                        "duplicate directive \"{}\" registered by {} for context {:?}",
                        spec.name, owner, overlap
                    );
                }
                declared.extend_from_slice(spec.contexts);
                lookup.entry(spec.name).or_insert((module_index, spec_index));
            }
            tables.push(table);
        }
        Self {
            modules,
            lookup,
            tables,
            contexts,
        }
    }

    /// The module set shipped with nginxrs, in Nginx-like order.
    ///
    /// To add a new Nginx module: implement [`Module`] in its own file, add it to
    /// [`crate::modules`], and add one line here.
    pub fn default_modules() -> Self {
        use crate::modules::{
            access, auth_basic, body, error_page, filters, geo, geoip, grpc, gunzip, gzip,
            gzip_static,
            headers,
            http_core,
            limit_conn,
            limit_req, log, lua, proxy, realip, rewrite, ssl, static_files, stub_status, upstream,
            upstream_protocols,
        };
        Self::new(vec![
            Arc::new(http_core::HttpCoreModule),
            Arc::new(error_page::ErrorPageModule),
            Arc::new(rewrite::RewriteModule),
            Arc::new(realip::RealipModule),
            Arc::new(access::AccessModule),
            Arc::new(auth_basic::AuthBasicModule),
            Arc::new(filters::ssi::SsiModule),
            Arc::new(geo::GeoModule),
            Arc::new(grpc::GrpcModule),
            Arc::new(gunzip::GunzipModule),
            Arc::new(gzip::GzipModule),
            Arc::new(gzip_static::GzipStaticModule),
            Arc::new(geoip::GeoipModule),
            Arc::new(limit_conn::LimitConnModule),
            Arc::new(limit_req::LimitReqModule),
            Arc::new(log::AccessLogModule),
            Arc::new(headers::HeadersModule),
            Arc::new(lua::LuaModule),
            Arc::new(upstream::UpstreamModule),
            Arc::new(upstream_protocols::ParamsModule),
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
        let allowed = self
            .contexts
            .get(name)
            .is_some_and(|contexts| contexts.contains(&context));
        if !allowed {
            return None;
        }
        Some((self.modules[module_index].clone(), spec))
    }

    /// Directives accepted in `context`, for `-t` diagnostics.
    pub fn supported_in(&self, context: Context) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self
            .contexts
            .iter()
            .filter(|(_, contexts)| contexts.contains(&context))
            .map(|(name, _)| *name)
            .collect();
        names.sort_unstable();
        names
    }

    /// Call one directive handler.
    pub fn dispatch<'a>(
        &'a self,
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
            registry: self,
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
    /// The owning table, for directives that parse their own sub-statements (`geo`).
    pub registry: &'a Registry,
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
        // Process-level directives (`worker_processes`, `user`, `pid`, the compatibility
        // list) always live in the `main` slot, whichever module declares them; `events`
        // shares it too. Module configuration uses the module's own slot.
        let module = if matches!(self.context, Context::Main | Context::Events) {
            "main"
        } else {
            self.module
        };
        let directive = self.directive;
        self.states.get_mut::<T>(module).ok_or_else(|| {
            anyhow::anyhow!(
                "{}:{}: {}: module {module} has no state of the expected type",
                directive.file.display(),
                directive.line,
                directive.name
            )
        })
    }

    /// The process-wide (`main`) state, available from any context.
    pub fn process_state(&mut self) -> Result<&mut crate::config::MainState> {
        self.states
            .get_mut::<crate::config::MainState>("main")
            .ok_or_else(|| self.directive.error("the process state slot is not initialized"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ModuleKind;

    struct Single {
        name: &'static str,
        contexts: &'static [Context],
    }

    impl Module for Single {
        fn name(&self) -> &'static str {
            self.name
        }

        fn kind(&self) -> ModuleKind {
            ModuleKind::Http
        }

        fn directives(&self) -> Vec<DirectiveSpec> {
            vec![DirectiveSpec {
                name: "thing",
                contexts: self.contexts,
                handler: |_| Ok(()),
            }]
        }
    }

    #[test]
    fn disjoint_contexts_merge_into_one_entry() {
        let registry = Registry::new(vec![
            Arc::new(Single {
                name: "a",
                contexts: &[Context::Main],
            }) as Arc<dyn Module>,
            Arc::new(Single {
                name: "b",
                contexts: &[Context::Http, Context::Location],
            }) as Arc<dyn Module>,
        ]);
        assert!(registry.resolve("thing", Context::Main).is_some());
        assert!(registry.resolve("thing", Context::Location).is_some());
        assert!(registry.resolve("thing", Context::Server).is_none());
        assert_eq!(registry.owner("thing").unwrap().name(), "a");
        assert_eq!(
            registry.supported_in(Context::Location),
            vec!["thing"]
        );
    }

    #[test]
    fn overlapping_contexts_panic() {
        let result = std::panic::catch_unwind(|| {
            Registry::new(vec![
                Arc::new(Single {
                    name: "a",
                    contexts: &[Context::Http],
                }) as Arc<dyn Module>,
                Arc::new(Single {
                    name: "b",
                    contexts: &[Context::Http, Context::Server],
                }) as Arc<dyn Module>,
            ])
        });
        assert!(result.is_err());
    }
}
