//! Compiled-configuration lookups.
//!
//! [`Engine`] keeps the per-listener virtual host table and the compiled locations; this
//! module implements the selection rules Nginx applies in `FIND_CONFIG` (server name
//! matching, location precedence) plus the realip hook.

use super::types::*;
use crate::core::http::RequestState;
use crate::modules::balancer::Upstream;
use crate::modules::http_core::{
    CompiledLocation, HttpConfig, normalize_host, select_location, server_matches_names,
    server_name_specificity,
};
use crate::modules::log::{AccessLogConfig, AccessLogWriter};
use crate::modules::proxy::ProxyConf;
use crate::modules::realip::{self, RealipConf};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        http: &HttpConfig,
        mut upstreams: HashMap<String, Arc<Upstream>>,
        providers: &'static [(
            &'static str,
            &'static dyn crate::core::variables::VariableProvider,
        )],
        mime: crate::modules::http_core::MimeConfig,
        stats: Arc<crate::modules::stub_status::ServerStats>,
        access_log: Arc<AccessLogConfig>,
        access_writer: Option<Arc<AccessLogWriter>>,
        server_conf: Arc<pingora_core::server::configuration::ServerConf>,
    ) -> Self {
        // Direct `proxy_pass http://host:port` targets are not declared in an `upstream`
        // block; create a single-backend group for each so upstream selection and the
        // health-aware balancer work uniformly.
        for server in &http.servers {
            for location in &server.locations {
                let Some(pass) = location
                    .conf
                    .get::<ProxyConf>()
                    .and_then(|conf| conf.pass.as_ref())
                else {
                    continue;
                };
                if upstreams.contains_key(&pass.upstream) {
                    continue;
                }
                let config = crate::modules::upstream::UpstreamConfig {
                    name: pass.upstream.clone(),
                    backends: vec![crate::modules::upstream::BackendConfig {
                        address: pass.upstream.clone(),
                        weight: 1,
                        down: false,
                    }],
                    algorithm: crate::modules::upstream::LoadBalancingAlgorithm::RoundRobin,
                    health_check_interval: None,
                };
                if let Ok(upstream) = Upstream::new(&config) {
                    upstreams.insert(pass.upstream.clone(), Arc::new(upstream));
                }
            }
        }
        let mut listeners: BTreeMap<String, VirtualHosts> = BTreeMap::new();
        let mut servers = Vec::new();
        for server in &http.servers {
            let index = servers.len();
            servers.push(ServerRuntime {
                server_names: server.server_names.clone(),
                locations: server.locations.clone(),
            });
            for listen in &server.listens {
                let hosts = listeners
                    .entry(listen.address.clone())
                    .or_insert(VirtualHosts {
                        servers: Vec::new(),
                        default: 0,
                    });
                if listen.default_server {
                    hosts.default = hosts.servers.len();
                }
                hosts.servers.push(index);
            }
        }
        Self {
            servers,
            listeners,
            upstreams,
            providers,
            mime,
            stats,
            access_log,
            access_writer,
            server_conf,
        }
    }

    pub fn listeners(&self) -> impl Iterator<Item = &str> {
        self.listeners.keys().map(String::as_str)
    }

    /// `ngx_http_find_virtual_server`: pick the server by `Host`/SNI, then the
    /// `default_server` of the address.
    pub fn select_server(&self, listen: &str, host: &str) -> Option<usize> {
        let hosts = self.listeners.get(listen)?;
        let host = normalize_host(host);
        let mut best: Option<(usize, usize)> = None;
        for (order, index) in hosts.servers.iter().enumerate() {
            let server = &self.servers[*index];
            if !server_matches_names(&server.server_names, &host) {
                continue;
            }
            let specificity = server
                .server_names
                .iter()
                .map(|name| server_name_specificity(name, &host))
                .max()
                .unwrap_or(0);
            let better = best.is_none_or(|(score, previous_order)| {
                specificity > score || (specificity == score && order < previous_order)
            });
            if better {
                best = Some((specificity, order));
            }
        }
        best.map(|(_, order)| hosts.servers[order])
            .or_else(|| hosts.servers.get(hosts.default).copied())
    }

    pub fn select_location(&self, server: usize, uri: &str) -> Option<usize> {
        let runtime = self.servers.get(server)?;
        let entry = select_location(&runtime.locations, uri, |entry| &entry.matcher)?;
        runtime
            .locations
            .iter()
            .position(|candidate| std::ptr::eq(candidate, entry))
    }

    pub fn location(&self, selected: Selected) -> Option<&CompiledLocation> {
        self.servers
            .get(selected.server)?
            .locations
            .get(selected.location)
    }

    pub(crate) fn upstream_for(&self, location: &CompiledLocation) -> Option<Arc<Upstream>> {
        let pass = location.conf.get::<ProxyConf>()?.pass.as_ref()?;
        self.upstreams.get(&pass.upstream).cloned()
    }

    /// Rewrite the client address from a trusted proxy header (realip module).
    pub fn apply_realip(&self, location: &CompiledLocation, state: &mut RequestState) {
        if let Some(conf) = location.conf.get::<RealipConf>() {
            realip::apply(conf, state);
        }
    }
}

