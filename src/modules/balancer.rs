//! Backend selection for `upstream` groups.
//!
//! Pingora already provides weighted round robin, random and FNV selection. This module
//! adds least-connections on top of Pingora's health-aware `LoadBalancer`, so the proxy
//! never selects a backend the health checker marked down.

use crate::modules::upstream::{BackendConfig, LoadBalancingAlgorithm, UpstreamConfig};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::FutureExt;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use pingora_load_balancing::discovery;
use pingora_load_balancing::health_check::TcpHealthCheck;
use pingora_load_balancing::selection::{
    BackendIter, BackendSelection, FNVHash, Random, RoundRobin,
};
use pingora_load_balancing::{Backend, LoadBalancer};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A selected backend. Dropping it releases its least-connections slot.
pub struct SelectedBackend {
    pub backend: Backend,
    address: String,
    connections: Option<Arc<Mutex<HashMap<String, usize>>>>,
}

impl SelectedBackend {
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Drop for SelectedBackend {
    fn drop(&mut self) {
        if let Some(connections) = &self.connections {
            let mut connections = connections.lock().expect("connection counter mutex");
            if let Some(count) = connections.get_mut(&self.address) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    connections.remove(&self.address);
                }
            }
        }
    }
}

pub struct Upstream {
    name: String,
    algorithm: LoadBalancingAlgorithm,
    balancer: Balancer,
    connections: Arc<Mutex<HashMap<String, usize>>>,
}

enum Balancer {
    RoundRobin(LoadBalancer<RoundRobin>),
    Random(LoadBalancer<Random>),
    IpHash(LoadBalancer<FNVHash>),
    LeastConn(LoadBalancer<LeastConnections>),
}

impl Upstream {
    pub fn new(config: &UpstreamConfig) -> Result<Self> {
        let backends = backend_set(&config.backends)?;
        let views = || {
            let backends: BTreeSet<Backend> = backends.clone();
            pingora_load_balancing::Backends::new(discovery::Static::new(backends))
        };
        let connections = Arc::new(Mutex::new(HashMap::new()));
        let mut balancer = match config.algorithm {
            LoadBalancingAlgorithm::RoundRobin => {
                Balancer::RoundRobin(LoadBalancer::from_backends(views()))
            }
            LoadBalancingAlgorithm::Random => {
                Balancer::Random(LoadBalancer::from_backends(views()))
            }
            LoadBalancingAlgorithm::IpHash => {
                Balancer::IpHash(LoadBalancer::from_backends(views()))
            }
            LoadBalancingAlgorithm::LeastConn => Balancer::LeastConn(
                LoadBalancer::from_backends_with_config(views(), Some(connections.clone())),
            ),
        };
        if config.health_check_interval.is_some() {
            set_health_check(&mut balancer);
        }
        set_frequency(&mut balancer, config.health_check_interval);
        // Populate the selector before the first request arrives.
        match &balancer {
            Balancer::RoundRobin(lb) => initialize(lb),
            Balancer::Random(lb) => initialize(lb),
            Balancer::IpHash(lb) => initialize(lb),
            Balancer::LeastConn(lb) => initialize(lb),
        }
        Ok(Self {
            name: config.name.clone(),
            algorithm: config.algorithm,
            balancer,
            connections,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Number of configured backends, used to bound `proxy_next_upstream_tries` the way
    /// `ngx_http_upstream_init_request` uses `peer.init`'s peer count.
    pub fn peer_count_hint(&self) -> usize {
        match &self.balancer {
            Balancer::RoundRobin(lb) => lb.backends().get_backend().len(),
            Balancer::Random(lb) => lb.backends().get_backend().len(),
            Balancer::IpHash(lb) => lb.backends().get_backend().len(),
            Balancer::LeastConn(lb) => lb.backends().get_backend().len(),
        }
    }

    /// Select a healthy backend, excluding addresses that already failed this request
    /// (`ngx_http_upstream_next` frees the failed peer before the next attempt).
    pub fn select_avoiding(&self, key: &[u8], avoid: &[String]) -> Option<SelectedBackend> {
        if avoid.is_empty() {
            return self.select(key);
        }
        for offset in 0..self.peer_count_hint().max(1) {
            let mut attempt_key = key.to_vec();
            attempt_key.push(b'#');
            attempt_key.extend_from_slice(offset.to_string().as_bytes());
            let selected = self.select(&attempt_key)?;
            if !avoid.iter().any(|address| address == &selected.address) {
                return Some(selected);
            }
        }
        None
    }

    /// Select a healthy backend. `key` feeds hash-based algorithms and retry variation.
    pub fn select(&self, key: &[u8]) -> Option<SelectedBackend> {
        let backend = match &self.balancer {
            Balancer::RoundRobin(lb) => lb.select(key, 256),
            Balancer::Random(lb) => lb.select(key, 256),
            Balancer::IpHash(lb) => lb.select(key, 256),
            Balancer::LeastConn(lb) => lb.select(key, 256),
        }?;
        let address = backend.addr.to_string();
        let connections =
            (self.algorithm == LoadBalancingAlgorithm::LeastConn).then(|| self.connections.clone());
        if let Some(connections) = &connections {
            *connections
                .lock()
                .expect("connection counter mutex")
                .entry(address.clone())
                .or_default() += 1;
        }
        Some(SelectedBackend {
            backend,
            address,
            connections,
        })
    }
}

#[async_trait]
impl BackgroundService for Upstream {
    async fn start(&self, shutdown: ShutdownWatch) {
        match &self.balancer {
            Balancer::RoundRobin(lb) => lb.run(shutdown, None).await,
            Balancer::Random(lb) => lb.run(shutdown, None).await,
            Balancer::IpHash(lb) => lb.run(shutdown, None).await,
            Balancer::LeastConn(lb) => lb.run(shutdown, None).await,
        }
    }
}

fn set_health_check(balancer: &mut Balancer) {
    match balancer {
        Balancer::RoundRobin(lb) => lb.set_health_check(TcpHealthCheck::new()),
        Balancer::Random(lb) => lb.set_health_check(TcpHealthCheck::new()),
        Balancer::IpHash(lb) => lb.set_health_check(TcpHealthCheck::new()),
        Balancer::LeastConn(lb) => lb.set_health_check(TcpHealthCheck::new()),
    }
}

fn set_frequency(balancer: &mut Balancer, interval: Option<Duration>) {
    fn apply<S>(lb: &mut LoadBalancer<S>, interval: Option<Duration>)
    where
        S: BackendSelection + 'static,
        S::Iter: BackendIter,
    {
        lb.health_check_frequency = interval;
        lb.parallel_health_check = true;
    }
    match balancer {
        Balancer::RoundRobin(lb) => apply(lb, interval),
        Balancer::Random(lb) => apply(lb, interval),
        Balancer::IpHash(lb) => apply(lb, interval),
        Balancer::LeastConn(lb) => apply(lb, interval),
    }
}

fn initialize<S>(lb: &LoadBalancer<S>)
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    lb.update()
        .now_or_never()
        .expect("static backend discovery must not block")
        .expect("static backend discovery must succeed");
}

fn backend_set(configs: &[BackendConfig]) -> Result<BTreeSet<Backend>> {
    let mut result = BTreeSet::new();
    for config in configs {
        let backend = Backend::new_with_weight(&config.address, config.weight)
            .with_context(|| format!("invalid backend {}", config.address))?;
        result.insert(backend);
    }
    Ok(result)
}

/// Orders candidates by `active_connections / weight`, then by address.
pub struct LeastConnections {
    backends: Box<[Backend]>,
    connections: Arc<Mutex<HashMap<String, usize>>>,
}

impl BackendSelection for LeastConnections {
    type Iter = LeastConnectionsIter;
    type Config = Arc<Mutex<HashMap<String, usize>>>;

    fn build(backends: &BTreeSet<Backend>) -> Self {
        Self::build_with_config(backends, &Arc::new(Mutex::new(HashMap::new())))
    }

    fn build_with_config(backends: &BTreeSet<Backend>, connections: &Self::Config) -> Self {
        Self {
            backends: backends.iter().cloned().collect(),
            connections: connections.clone(),
        }
    }

    fn iter(self: &Arc<Self>, _key: &[u8]) -> Self::Iter {
        let counts = self.connections.lock().expect("connection counter mutex");
        let mut ordered = self.backends.to_vec();
        ordered.sort_by_key(|backend| {
            let address = backend.addr.to_string();
            let active = counts.get(&address).copied().unwrap_or(0);
            (active / backend.weight.max(1), active, address)
        });
        drop(counts);
        LeastConnectionsIter { ordered, offset: 0 }
    }
}

pub struct LeastConnectionsIter {
    ordered: Vec<Backend>,
    offset: usize,
}

impl BackendIter for LeastConnectionsIter {
    fn next(&mut self) -> Option<&Backend> {
        let backend = self.ordered.get(self.offset);
        self.offset += usize::from(backend.is_some());
        backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(algorithm: LoadBalancingAlgorithm) -> UpstreamConfig {
        UpstreamConfig {
            name: "test".into(),
            backends: vec![
                BackendConfig {
                    address: "127.0.0.1:8001".into(),
                    weight: 1,
                    down: false,
                    health: Default::default(),
                },
                BackendConfig {
                    address: "127.0.0.1:8002".into(),
                    weight: 1,
                    down: false,
                    health: Default::default(),
                },
            ],
            algorithm,
            health_check_interval: None,
            keepalive: Default::default(),
        }
    }

    #[test]
    fn round_robin_visits_all_backends() {
        let upstream = Upstream::new(&config(LoadBalancingAlgorithm::RoundRobin)).unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..4 {
            seen.insert(upstream.select(b"key").unwrap().address().to_string());
        }
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn least_connections_prefers_idle_backend() {
        let upstream = Upstream::new(&config(LoadBalancingAlgorithm::LeastConn)).unwrap();
        let first = upstream.select(b"").unwrap();
        let second = upstream.select(b"").unwrap();
        assert_ne!(first.address(), second.address());
        drop(second);
        drop(first);
        assert!(upstream.connections.lock().unwrap().is_empty());
    }

    #[test]
    fn ip_hash_is_sticky() {
        let upstream = Upstream::new(&config(LoadBalancingAlgorithm::IpHash)).unwrap();
        let first = upstream
            .select(b"203.0.113.9")
            .unwrap()
            .address()
            .to_string();
        for _ in 0..10 {
            assert_eq!(upstream.select(b"203.0.113.9").unwrap().address(), first);
        }
    }
}
