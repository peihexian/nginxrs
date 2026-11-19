//! `ngx_http_upstream_module`: `upstream` blocks.
//!
//! This module owns the configuration syntax for upstreams and produces the groups the
//! proxy module resolves at runtime. Backend selection itself lives in
//! [`crate::modules::balancer`], keeping configuration and selection independently
//! testable.

use crate::core::syntax::Directive;
use crate::core::value::{parse_time, parse_upstream_address};
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use anyhow::Result;
use std::time::Duration;

pub const MODULE_NAME: &str = "ngx_http_upstream_module";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LoadBalancingAlgorithm {
    #[default]
    RoundRobin,
    Random,
    IpHash,
    LeastConn,
}

#[derive(Clone, Debug)]
pub struct BackendConfig {
    pub address: String,
    pub weight: usize,
    pub down: bool,
}

#[derive(Clone, Debug)]
pub struct UpstreamConfig {
    pub name: String,
    pub backends: Vec<BackendConfig>,
    pub algorithm: LoadBalancingAlgorithm,
    pub health_check_interval: Option<Duration>,
}

/// `http {}`-level upstream definitions.
#[derive(Default)]
pub struct Upstreams {
    pub groups: Vec<UpstreamConfig>,
}

impl Upstreams {
    pub fn find(&self, name: &str) -> Option<&UpstreamConfig> {
        self.groups.iter().find(|group| group.name == name)
    }
}

pub struct UpstreamModule;

impl Module for UpstreamModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn http_state(&self) -> Option<crate::core::StateInstance> {
        Some(crate::core::StateInstance::new(Upstreams::default()))
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![DirectiveSpec {
            name: "upstream",
            contexts: &[Context::Http],
            handler: parse_upstream_block,
        }]
    }
}

fn parse_upstream_block(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.len() != 1 || !directive.has_block() {
        return Err(directive.error("expected upstream name { ... }"));
    }
    let name = directive.args[0].clone();
    let mut group = UpstreamConfig {
        name: name.clone(),
        backends: Vec::new(),
        algorithm: LoadBalancingAlgorithm::RoundRobin,
        health_check_interval: None,
    };
    for child in directive.block()? {
        match child.name.as_str() {
            "server" => group.backends.push(parse_backend(child)?),
            "least_conn" => {
                child.expect_args(0)?;
                group.algorithm = LoadBalancingAlgorithm::LeastConn;
            }
            "ip_hash" => {
                child.expect_args(0)?;
                group.algorithm = LoadBalancingAlgorithm::IpHash;
            }
            "random" => {
                child.expect_args(0)?;
                group.algorithm = LoadBalancingAlgorithm::Random;
            }
            "health_check" => {
                if child.has_block() || child.args.len() != 1 {
                    return Err(child.error("expected health_check interval=5s;"));
                }
                let interval = child.args[0]
                    .strip_prefix("interval=")
                    .ok_or_else(|| child.error("expected health_check interval=5s;"))?;
                group.health_check_interval = Some(parse_time(child, interval)?);
            }
            "keepalive" | "keepalive_requests" | "keepalive_timeout" => {
                return Err(child.error("upstream keepalive tuning is not implemented yet"));
            }
            other => {
                return Err(child.error(format!("unknown upstream directive \"{other}\"")));
            }
        }
    }
    group.backends.retain(|backend| !backend.down);
    if group.backends.is_empty() {
        return Err(directive.error("upstream has no enabled servers"));
    }
    if view.state::<Upstreams>()?.find(&name).is_some() {
        return Err(directive.error(format!("duplicate upstream \"{name}\"")));
    }
    view.state::<Upstreams>()?.groups.push(group);
    Ok(())
}

fn parse_backend(node: &Directive) -> Result<BackendConfig> {
    if node.has_block() || node.args.is_empty() {
        return Err(node.error("expected server address [weight=N] [down];"));
    }
    let address = parse_upstream_address(node, &node.args[0])?;
    let mut backend = BackendConfig {
        address,
        weight: 1,
        down: false,
    };
    for option in &node.args[1..] {
        if let Some(weight) = option.strip_prefix("weight=") {
            backend.weight = weight.parse().map_err(|_| node.error("invalid weight"))?;
            if backend.weight == 0 {
                return Err(node.error("weight must be greater than zero"));
            }
        } else if option == "down" {
            backend.down = true;
        } else {
            return Err(node.error(format!("unsupported server option {option}")));
        }
    }
    Ok(backend)
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    #[test]
    fn parses_upstream_blocks() {
        let config = Config::parse(
            r#"
            http {
                upstream backend {
                    least_conn;
                    server 127.0.0.1:9001 weight=2;
                    server 127.0.0.1:9002;
                    server 127.0.0.1:9003 down;
                    health_check interval=2s;
                }
                server { listen 8080; location / { return 200; } }
            }
            "#,
        )
        .unwrap();
        let upstreams = config
            .module_states
            .get::<super::Upstreams>(super::MODULE_NAME)
            .unwrap();
        let group = upstreams.find("backend").unwrap();
        assert_eq!(group.backends.len(), 2);
        assert_eq!(group.backends[0].weight, 2);
        assert_eq!(group.algorithm, super::LoadBalancingAlgorithm::LeastConn);
        assert_eq!(
            group.health_check_interval,
            Some(std::time::Duration::from_secs(2))
        );
    }

    #[test]
    fn rejects_unknown_upstream_directive() {
        let error = Config::parse(
            "http { upstream a { made_up; server 127.0.0.1:9001; } server { listen 8080; location / { return 200; } } }",
        )
        .err()
        .expect("unknown directive must be rejected")
        .to_string();
        assert!(error.contains("made_up"));
    }
}
