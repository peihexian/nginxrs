//! Configuration entry point.
//!
//! Parsing has two independent stages:
//! 1. [`crate::core::syntax`] turns files into a directive tree (comments, quoting,
//!    `include`).
//! 2. [`crate::modules::http_core::HttpCompiler`] walks that tree and dispatches each
//!    directive to the module registered for its context, so adding a module never
//!    touches this file.

use crate::core::StateInstance;
use crate::core::syntax::{self, Directive};
use crate::core::value::resolve_path;
use crate::core::variables::Variables;
use crate::modules::http_core::{CompiledLocation, HttpCompiler, HttpConfig};
use crate::modules::registry::Registry;
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Process-level configuration (`ngx_core_module`).
#[derive(Debug, Default)]
pub struct MainState {
    pub worker_processes: Option<usize>,
    /// `pid <file>`: where the pid file and control descriptor live.
    pub pid_file: Option<PathBuf>,
    pub warnings: Vec<String>,
}

/// A fully compiled nginxrs configuration.
pub struct Config {
    pub worker_processes: Option<usize>,
    pub http: HttpConfig,
    pub variables: Variables,
    /// Module configuration state keyed by module name; modules exposing process-wide
    /// settings (access logs, upstreams, ...) read their state from here.
    pub module_states: ModuleStates,
    pub warnings: Vec<String>,
    pub base_dir: PathBuf,
}

/// Type-erased lookup over compiled module state.
#[derive(Default)]
pub struct ModuleStates {
    states: HashMap<&'static str, Box<dyn std::any::Any + Send>>,
}

impl ModuleStates {
    pub fn get<T: 'static>(&self, module: &str) -> Option<&T> {
        self.states
            .get(module)
            .and_then(|state| state.downcast_ref::<T>())
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let nodes = syntax::parse_file(path)?;
        let base_dir = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf())
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Self::from_directives(nodes, &base_dir)
    }

    pub fn parse(source: &str) -> Result<Self> {
        Self::parse_at(source, Path::new("."))
    }

    pub fn parse_at(source: &str, base_dir: &Path) -> Result<Self> {
        Self::from_directives(syntax::parse_str(source)?, base_dir)
    }

    /// Compile a directive tree with the default module set.
    pub fn from_directives(nodes: Vec<Directive>, base_dir: &Path) -> Result<Self> {
        let registry = Registry::default_modules();
        Self::with_registry(&registry, nodes, base_dir)
    }

    pub fn with_registry(
        registry: &Registry,
        nodes: Vec<Directive>,
        base_dir: &Path,
    ) -> Result<Self> {
        // Every module starts with a fresh state bucket; the state type is chosen by the
        // module. `None` means the module has no process-wide configuration.
        let mut states: Vec<(&'static str, StateInstance)> = Vec::new();
        for module in registry.modules() {
            if let Some(state) = module.http_state() {
                states.push((module.name_static(), state));
            }
        }
        states.push(("main", StateInstance::new(MainState::default())));

        let compiler = HttpCompiler::run(registry, base_dir, &nodes, &mut states)?;

        let mut variables = Variables::new();
        for module in registry.modules() {
            for (name, provider) in module.variables() {
                variables.register(name, provider);
            }
        }
        // `geo` blocks declare their variable while the block is parsed
        // (`ngx_http_geo_block` → `ngx_http_add_variable`), so they are only known now.
        if let Some(geo) = states
            .iter()
            .find(|(name, _)| *name == crate::modules::geo::MODULE_NAME)
            .and_then(|(_, state)| state.get_ref::<crate::modules::geo::GeoBlocks>())
        {
            let providers = crate::modules::geo::providers(geo);
            for (name, provider) in providers.iter().copied() {
                variables.register(name, provider);
            }
            crate::modules::set_dynamic_providers(providers);
        }
        if let Some(geoip) = states
            .iter()
            .find(|(name, _)| *name == crate::modules::geoip::MODULE_NAME)
            .and_then(|(_, state)| state.get_ref::<crate::modules::geoip::conf::Conf>())
        {
            crate::modules::geoip::publish(geoip);
        }

        let mut module_states = ModuleStates::default();
        let mut warnings = Vec::new();
        for (name, state) in states {
            let any = state.into_any();
            if let Some(main) = any.downcast_ref::<MainState>() {
                warnings.extend(main.warnings.iter().cloned());
            }
            module_states.states.insert(name, any);
        }
        warnings.extend(compiler.warnings().iter().cloned());
        let worker_processes = module_states
            .get::<MainState>("main")
            .and_then(|state| state.worker_processes);
        Ok(Self {
            worker_processes,
            http: compiler.finish(),
            variables,
            module_states,
            warnings,
            base_dir: base_dir.to_path_buf(),
        })
    }

    /// Every listener address which must be bound.
    pub fn listeners(&self) -> Vec<String> {
        let mut addresses: Vec<String> = self
            .http
            .servers
            .iter()
            .flat_map(|server| server.listens.iter().map(|listen| listen.address.clone()))
            .collect();
        addresses.sort();
        addresses.dedup();
        addresses
    }

    /// The location whose module configuration applies to `uri` on `server`.
    pub fn location_for(&self, server: usize, uri: &str) -> Option<&CompiledLocation> {
        let server = self.http.servers.get(server)?;
        crate::modules::http_core::select_location(&server.locations, uri, |entry| &entry.matcher)
    }

    pub fn path(&self, value: &str) -> PathBuf {
        resolve_path(&self.base_dir, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_state_slot_is_usable() {
        let mut states: Vec<crate::core::state::StateSlot> =
            vec![("main", StateInstance::new(MainState::default()))];
        let mut access = crate::core::state::StateAccess::new(&mut states);
        assert!(access.get_mut::<MainState>("main").is_some());
    }

    #[test]
    fn compiles_worker_processes() {
        let config = Config::parse(
            "worker_processes 3; http { server { listen 8080; location / { return 200; } } }",
        )
        .unwrap();
        assert_eq!(config.worker_processes, Some(3));
    }
}

#[cfg(test)]
mod limit_config_tests {
    use super::*;

    #[test]
    fn limit_req_is_stored_in_the_compiled_location() {
        let config = Config::parse(
            r#"
            http {
                limit_req_zone $binary_remote_addr zone=one:1m rate=1r/s;
                server {
                    listen 8080;
                    location = /limited {
                        limit_req zone=one burst=1 nodelay;
                        limit_req_status 429;
                        return 200 "x";
                    }
                }
            }
            "#,
        )
        .unwrap();
        let location = &config.http.servers[0].locations[0];
        let conf = location
            .conf
            .get::<crate::modules::limit_req::LimitReqConf>()
            .expect("limit_req configuration is attached to the location");
        assert_eq!(conf.limits.len(), 1);
        assert_eq!(conf.status, 429);
    }
}
