//! `ngx_http_limit_conn_module`: limit concurrent connections per key.
//!
//! Mirrors `ngx_http_limit_conn_handler`: each zone counts live connections per key, a
//! request whose key already reached `limit_conn` is rejected with `limit_conn_status`
//! (default 503), and the count is released when the request finishes.

use crate::core::value::{parse_on_off, parse_size, parse_u64};
use crate::core::variables::Template;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::ctx::ModuleCtx;
use crate::modules::location::LocationConf;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const MODULE_NAME: &str = "ngx_http_limit_conn_module";

/// A shared zone (`limit_conn_zone <key> zone=NAME:SIZE`).
pub struct ConnZone {
    pub name: String,
    pub size: u64,
    pub key: Template,
    counts: Mutex<HashMap<String, usize>>,
}

impl ConnZone {
    pub fn new(name: String, size: u64, key: Template) -> Self {
        Self {
            name,
            size,
            key,
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Try to take one connection slot. `limit` is the configured maximum.
    pub fn acquire(&self, key: &str, limit: usize) -> bool {
        let mut counts = self.counts.lock().expect("limit_conn zone mutex");
        let current = counts.get(key).copied().unwrap_or(0);
        if current >= limit {
            return false;
        }
        // Approximate slab accounting: refuse to grow past the zone size.
        let capacity = (self.size / 64).max(1) as usize;
        if !counts.contains_key(key) && counts.len() >= capacity {
            return false;
        }
        counts.insert(key.to_string(), current + 1);
        true
    }

    /// Release a slot taken by [`ConnZone::acquire`].
    pub fn release(&self, key: &str) {
        let mut counts = self.counts.lock().expect("limit_conn zone mutex");
        if let Some(current) = counts.get_mut(key) {
            *current = current.saturating_sub(1);
            if *current == 0 {
                counts.remove(key);
            }
        }
    }

    pub fn count(&self, key: &str) -> usize {
        self.counts
            .lock()
            .expect("limit_conn zone mutex")
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    pub fn total(&self) -> usize {
        self.counts.lock().expect("limit_conn zone mutex").len()
    }
}

#[derive(Clone)]
pub struct ConnSpec {
    pub zone: Arc<ConnZone>,
    pub limit: usize,
}

impl std::fmt::Debug for ConnSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnSpec")
            .field("zone", &self.zone.name)
            .field("limit", &self.limit)
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct LimitConnConf {
    pub limits: Vec<ConnSpec>,
    pub status: u16,
    pub dry_run: bool,
}

impl LocationConf for LimitConnConf {}

/// Process-wide zones declared with `limit_conn_zone`.
#[derive(Default)]
pub struct LimitConnZones {
    zones: HashMap<String, Arc<ConnZone>>,
}

impl LimitConnZones {
    pub fn declare(&mut self, definition: &ConnZoneDefinition) {
        self.zones
            .entry(definition.name.clone())
            .or_insert_with(|| {
                Arc::new(ConnZone::new(
                    definition.name.clone(),
                    definition.size,
                    definition.key.clone(),
                ))
            });
    }

    pub fn get(&self, name: &str) -> Option<Arc<ConnZone>> {
        self.zones.get(name).cloned()
    }

    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.zones.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn total(&self) -> usize {
        self.zones.values().map(|zone| zone.total()).sum()
    }
}

/// A parsed `limit_conn_zone` directive.
#[derive(Clone, Debug)]
pub struct ConnZoneDefinition {
    pub name: String,
    pub size: u64,
    pub key: Template,
}

/// Slots held by one request, released when the request context is dropped.
#[derive(Clone, Default)]
pub struct HeldConnections(pub Vec<(Arc<ConnZone>, String)>);

impl std::fmt::Debug for HeldConnections {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_list()
            .entries(self.0.iter().map(|(zone, key)| (zone.name.as_str(), key)))
            .finish()
    }
}

impl Drop for HeldConnections {
    fn drop(&mut self) {
        for (zone, key) in &self.0 {
            zone.release(key);
        }
    }
}

/// `$limit_conn_status` request slot (Nginx keeps this on `r->main`).
#[derive(Clone, Copy, Debug)]
pub struct LimitConnStatusSlot(pub LimitConnStatus);

/// `$limit_conn_status`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitConnStatus {
    Passed,
    Rejected,
    RejectedDryRun,
}

impl LimitConnStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            LimitConnStatus::Passed => "PASSED",
            LimitConnStatus::Rejected => "REJECTED",
            LimitConnStatus::RejectedDryRun => "REJECTED_DRY_RUN",
        }
    }
}

pub struct LimitConnModule;

impl Module for LimitConnModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn http_state(&self) -> Option<crate::core::StateInstance> {
        Some(crate::core::StateInstance::new(LimitConnZones::default()))
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            DirectiveSpec {
                name: "limit_conn_zone",
                contexts: &[Context::Http],
                handler: parse_zone,
            },
            DirectiveSpec {
                name: "limit_conn",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_limit,
            },
            DirectiveSpec {
                name: "limit_conn_status",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_status,
            },
            DirectiveSpec {
                name: "limit_conn_dry_run",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_dry_run,
            },
        ]
    }
}

/// Register every `limit_conn_zone` before the first compile pass, so declaration order
/// relative to `limit_conn` does not matter.
pub fn prescan_zones(
    http: &[crate::core::syntax::Directive],
    states: &mut crate::core::state::StateAccess<'_>,
) -> Result<()> {
    let mut definitions: Vec<ConnZoneDefinition> = Vec::new();
    for directive in http
        .iter()
        .filter(|directive| directive.name == "limit_conn_zone")
    {
        let definition = parse_zone_definition(directive)?;
        if definitions
            .iter()
            .any(|existing| existing.name == definition.name)
        {
            return Err(directive.error("is duplicate"));
        }
        definitions.push(definition);
    }
    if let Some(zones) = states.get_mut::<LimitConnZones>(MODULE_NAME) {
        for definition in &definitions {
            zones.declare(definition);
        }
    }
    Ok(())
}

fn parse_zone(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    let definition = parse_zone_definition(directive)?;
    // Registered up front by `prescan_zones`, which performs the duplicate check.
    view.state::<LimitConnZones>()?.declare(&definition);
    Ok(())
}

pub fn parse_zone_definition(
    directive: &crate::core::syntax::Directive,
) -> Result<ConnZoneDefinition> {
    if directive.args.len() < 2 || directive.has_block() {
        return Err(directive.error("expected key zone=NAME:SIZE"));
    }
    // `args[0]` is the key; `zone=NAME:SIZE` follows.
    let key = Template::parse(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid limit_conn_zone key: {error}")))?;
    let mut name = String::new();
    let mut size = 0;
    for argument in &directive.args[1..] {
        if let Some(zone_value) = argument.strip_prefix("zone=") {
            let (zone_name, zone_size) = zone_value
                .split_once(':')
                .ok_or_else(|| directive.error("invalid zone size"))?;
            name = zone_name.to_string();
            size = parse_size(directive, zone_size)
                .map_err(|error| directive.error(format!("invalid zone size: {error}")))?;
            if size == 0 {
                return Err(directive.error("invalid zone size"));
            }
        } else {
            return Err(directive.error(format!("invalid parameter \"{argument}\"")));
        }
    }
    if name.is_empty() {
        return Err(directive.error("\"zone\" parameter is required"));
    }
    Ok(ConnZoneDefinition { name, size, key })
}

fn parse_limit(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(2)?;
    // Nginx syntax is `limit_conn zone_name number`.
    let zone_name = directive.args[0].as_str();
    let limit = parse_u64(directive, &directive.args[1])? as usize;
    if limit == 0 {
        return Err(directive.error("invalid number of connections"));
    }
    let zone = view
        .state::<LimitConnZones>()?
        .get(zone_name)
        .ok_or_else(|| directive.error(format!("unknown limit_conn_zone \"{zone_name}\"")))?;
    let duplicate = view.location_conf::<LimitConnConf>().is_some_and(|conf| {
        conf.limits
            .iter()
            .any(|limit| Arc::ptr_eq(&limit.zone, &zone))
    });
    if duplicate {
        return Err(directive.error("is duplicate"));
    }
    view.update_conf::<LimitConnConf>(|conf| conf.limits.push(ConnSpec { zone, limit }))
}

fn parse_status(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let status = directive.args[0]
        .parse::<u16>()
        .map_err(|_| directive.error("invalid status"))?;
    if !(400..=599).contains(&status) {
        return Err(directive.error("invalid status"));
    }
    view.update_conf::<LimitConnConf>(|conf| conf.status = status)
}

fn parse_dry_run(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let enabled = parse_on_off(directive, &directive.args[0])?;
    view.update_conf::<LimitConnConf>(|conf| conf.dry_run = enabled)
}

/// `NGX_HTTP_PREACCESS_PHASE` connection limiting.
///
/// On success the taken slots are stored in the request so they are released when the
/// request finishes. Returns the rejection status when the limit is exceeded.
pub async fn handle(ctx: &mut ModuleCtx<'_>) -> Result<Option<u16>> {
    let Some(conf) = ctx.location.get::<LimitConnConf>().cloned() else {
        return Ok(None);
    };
    if conf.limits.is_empty() {
        return Ok(None);
    }
    let status_code = if conf.status == 0 { 503 } else { conf.status };
    ctx.state
        .insert(LimitConnStatusSlot(LimitConnStatus::Passed));
    let mut held: Vec<(Arc<ConnZone>, String)> = Vec::new();
    for spec in &conf.limits {
        let key = ctx.state.eval(&spec.zone.key);
        if key.is_empty() {
            continue;
        }
        if key.len() > 255 {
            log::error!(
                target: "nginxrs::limit_conn",
                "the value of the limit_conn_zone key is more than 255 bytes"
            );
            continue;
        }
        if spec.zone.acquire(&key, spec.limit) {
            held.push((spec.zone.clone(), key));
            continue;
        }
        // Release anything taken so far before answering, like `cleanup_all`.
        drop(std::mem::take(&mut held));
        log::warn!(
            target: "nginxrs::limit_conn",
            "limiting connections{} by zone \"{}\"",
            if conf.dry_run { ", dry run" } else { "" },
            spec.zone.name
        );
        ctx.state.insert(LimitConnStatusSlot(if conf.dry_run {
            LimitConnStatus::RejectedDryRun
        } else {
            LimitConnStatus::Rejected
        }));
        if conf.dry_run {
            continue;
        }
        return Ok(Some(status_code));
    }
    ctx.state.insert(HeldConnections(held));
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(limit_key: &str) -> ConnZone {
        ConnZone::new(
            "test".into(),
            1024 * 1024,
            Template::parse(limit_key).unwrap(),
        )
    }

    #[test]
    fn counts_connections_per_key() {
        let zone = zone("$remote_addr");
        assert!(zone.acquire("a", 2));
        assert!(zone.acquire("a", 2));
        assert!(!zone.acquire("a", 2));
        assert!(zone.acquire("b", 2));
        assert_eq!(zone.count("a"), 2);
        zone.release("a");
        assert!(zone.acquire("a", 2));
    }

    #[test]
    fn release_removes_empty_entries() {
        let zone = zone("$remote_addr");
        assert!(zone.acquire("a", 1));
        zone.release("a");
        assert_eq!(zone.count("a"), 0);
        assert_eq!(zone.total(), 0);
    }

    #[test]
    fn zone_definition_parses_key_and_zone() {
        let directive =
            crate::core::syntax::parse_str("limit_conn_zone $binary_remote_addr zone=addr:10m;")
                .unwrap()
                .remove(0);
        let definition = parse_zone_definition(&directive).unwrap();
        assert_eq!(definition.name, "addr");
        assert_eq!(definition.size, 10 * 1024 * 1024);
    }
}
