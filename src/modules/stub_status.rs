//! `ngx_http_stub_status_module` and Prometheus metrics.
//!
//! Both endpoints are backed by one set of atomic counters maintained by the engine:
//!
//! * `stub_status` prints Nginx's exact three-line format;
//! * `prometheus` (extension) renders `nginxrs_*` counters for scraping.
//!
//! The C module exposes `$connections_active`, `$connections_reading`,
//! `$connections_writing` and `$connections_waiting`; those variables are provided here
//! too.

use crate::core::variables::VariableProvider;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::location::LocationConf;
use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};

pub const MODULE_NAME: &str = "ngx_http_stub_status_module";

/// Process-wide counters shared by the engine and the status endpoints.
#[derive(Debug, Default)]
pub struct ServerStats {
    pub accepted: AtomicU64,
    pub handled: AtomicU64,
    pub requests: AtomicU64,
    pub active: AtomicU64,
    pub reading: AtomicU64,
    pub writing: AtomicU64,
    pub waiting: AtomicU64,
    /// Bytes written to downstream connections.
    pub body_bytes_sent: AtomicU64,
    /// Requests answered by the proxy module.
    pub proxy_requests: AtomicU64,
    /// Failed connections to upstreams.
    pub upstream_failures: AtomicU64,
    /// Requests answered from the cache of a content module (reserved).
    pub cache_hits: AtomicU64,
}

/// Plain copy of the counters for one request, so `$connections_*` variables need no
/// global state and the status endpoints can render without atomics.
#[derive(Clone, Copy, Debug, Default)]
pub struct StatsSnapshot {
    pub active: u64,
    pub accepted: u64,
    pub handled: u64,
    pub requests: u64,
    pub reading: u64,
    pub writing: u64,
    pub waiting: u64,
    pub body_bytes_sent: u64,
    pub proxy_requests: u64,
    pub upstream_failures: u64,
}

impl StatsSnapshot {
    pub fn from_stats(stats: &ServerStats) -> Self {
        Self {
            active: ServerStats::get(&stats.active),
            accepted: ServerStats::get(&stats.accepted),
            handled: ServerStats::get(&stats.handled),
            requests: ServerStats::get(&stats.requests),
            reading: ServerStats::get(&stats.reading),
            writing: ServerStats::get(&stats.writing),
            waiting: ServerStats::get(&stats.waiting),
            body_bytes_sent: ServerStats::get(&stats.body_bytes_sent),
            proxy_requests: ServerStats::get(&stats.proxy_requests),
            upstream_failures: ServerStats::get(&stats.upstream_failures),
        }
    }
}

impl ServerStats {
    pub fn inc(stat: &AtomicU64) {
        stat.fetch_add(1, Ordering::Relaxed);
    }

    /// Saturating decrement that stays within the crate's MSRV.
    pub fn dec(stat: &AtomicU64) {
        let mut current = stat.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return;
            }
            match stat.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn get(stat: &AtomicU64) -> u64 {
        stat.load(Ordering::Relaxed)
    }

    pub fn add(stat: &AtomicU64, value: u64) {
        stat.fetch_add(value, Ordering::Relaxed);
    }
}
/// The status endpoint flavour enabled for one location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusFormat {
    /// Nginx `stub_status` text.
    Stub,
    /// Prometheus text exposition format.
    Prometheus,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StatusConf {
    pub enabled: Option<StatusFormat>,
}

impl LocationConf for StatusConf {}

impl StatusConf {
    pub fn format(&self) -> Option<StatusFormat> {
        self.enabled
    }
}

pub struct StubStatusModule;

impl Module for StubStatusModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn http_state(&self) -> Option<crate::core::StateInstance> {
        Some(crate::core::StateInstance::new(std::sync::Arc::new(
            ServerStats::default(),
        )))
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            DirectiveSpec {
                name: "stub_status",
                contexts: &[Context::Server, Context::Location],
                handler: parse_stub_status,
            },
            DirectiveSpec {
                name: "prometheus_metrics",
                contexts: &[Context::Server, Context::Location],
                handler: parse_prometheus,
            },
        ]
    }

    fn variables(&self) -> Vec<(&'static str, &'static dyn VariableProvider)> {
        vec![
            ("connections_active", &CONNECTIONS_ACTIVE),
            ("connections_reading", &CONNECTIONS_READING),
            ("connections_writing", &CONNECTIONS_WRITING),
            ("connections_waiting", &CONNECTIONS_WAITING),
        ]
    }
}

fn parse_stub_status(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    view.directive.expect_args(0)?;
    view.update_conf::<StatusConf>(|conf| conf.enabled = Some(StatusFormat::Stub))
}

fn parse_prometheus(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    view.directive.expect_args(0)?;
    view.update_conf::<StatusConf>(|conf| conf.enabled = Some(StatusFormat::Prometheus))
}

/// Render Nginx's `stub_status` body.
pub fn render_stub(stats: &StatsSnapshot) -> String {
    format!(
        "Active connections: {} \nserver accepts handled requests\n {} {} {} \nReading: {} Writing: {} Waiting: {} \n",
        stats.active,
        stats.accepted,
        stats.handled,
        stats.requests,
        stats.reading,
        stats.writing,
        stats.waiting,
    )
}

/// Render Prometheus text exposition format.
pub fn render_prometheus(stats: &StatsSnapshot) -> String {
    let metrics = [
        (
            "nginxrs_connections_active",
            "gauge",
            "Active client connections.",
            stats.active,
        ),
        (
            "nginxrs_connections_accepted_total",
            "counter",
            "Accepted client connections.",
            stats.accepted,
        ),
        (
            "nginxrs_connections_handled_total",
            "counter",
            "Handled client connections.",
            stats.handled,
        ),
        (
            "nginxrs_connections_reading",
            "gauge",
            "Connections reading a request.",
            stats.reading,
        ),
        (
            "nginxrs_connections_writing",
            "gauge",
            "Connections writing a response.",
            stats.writing,
        ),
        (
            "nginxrs_connections_waiting",
            "gauge",
            "Idle keepalive connections.",
            stats.waiting,
        ),
        (
            "nginxrs_requests_total",
            "counter",
            "Client requests.",
            stats.requests,
        ),
        (
            "nginxrs_body_bytes_sent_total",
            "counter",
            "Bytes sent to clients.",
            stats.body_bytes_sent,
        ),
        (
            "nginxrs_proxy_requests_total",
            "counter",
            "Requests forwarded to an upstream.",
            stats.proxy_requests,
        ),
        (
            "nginxrs_upstream_failures_total",
            "counter",
            "Failed upstream selections.",
            stats.upstream_failures,
        ),
    ];
    let mut output = String::new();
    for (name, kind, help, value) in metrics {
        output.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    }
    output
}

struct StatsVariable(fn(&StatsSnapshot) -> u64);

impl std::fmt::Debug for StatsVariable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("connections_*")
    }
}

impl VariableProvider for StatsVariable {
    fn module(&self) -> &'static str {
        MODULE_NAME
    }

    fn get(&self, state: &crate::core::http::RequestState) -> Option<String> {
        // The engine installs a counters snapshot into the request state, so variables stay
        // request-scoped and need no global mutable state.
        let stats = state.get::<StatsSnapshot>()?;
        Some((self.0)(stats).to_string())
    }
}

static CONNECTIONS_ACTIVE: StatsVariable = StatsVariable(|stats| stats.active);
static CONNECTIONS_READING: StatsVariable = StatsVariable(|stats| stats.reading);
static CONNECTIONS_WRITING: StatsVariable = StatsVariable(|stats| stats.writing);
static CONNECTIONS_WAITING: StatsVariable = StatsVariable(|stats| stats.waiting);
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_status_matches_nginx_layout() {
        let stats = ServerStats::default();
        ServerStats::inc(&stats.accepted);
        ServerStats::inc(&stats.handled);
        ServerStats::inc(&stats.requests);
        ServerStats::inc(&stats.active);
        ServerStats::inc(&stats.reading);
        let snapshot = StatsSnapshot::from_stats(&stats);
        let body = render_stub(&snapshot);
        assert!(body.starts_with("Active connections: 1 \n"));
        assert!(body.contains("server accepts handled requests\n 1 1 1 \n"));
        assert!(body.contains("Reading: 1 Writing: 0 Waiting: 0 \n"));
    }

    #[test]
    fn prometheus_output_has_help_type_and_value() {
        let stats = ServerStats::default();
        ServerStats::inc(&stats.requests);
        let snapshot = StatsSnapshot::from_stats(&stats);
        let body = render_prometheus(&snapshot);
        assert!(body.contains("# TYPE nginxrs_requests_total counter"));
        assert!(body.contains("nginxrs_requests_total 1"));
    }
}
