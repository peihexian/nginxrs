//! `ngx_http_limit_req_module`: request-rate limiting with a leaky bucket.
//!
//! The algorithm follows `ngx_http_limit_req_lookup` / `ngx_http_limit_req_account`:
//! each key stores an `excess` in milli-requests and a `last` timestamp. A request adds
//! 1000 milli-requests and subtracts `rate * elapsed_ms / 1000`; excess above `burst`
//! rejects with `limit_req_status`, excess above `delay` delays the response by
//! `(excess - delay) * 1000 / rate` milliseconds.

use crate::core::http::RequestState;
use crate::core::value::{parse_on_off, parse_size, parse_u64};
use crate::core::variables::Template;
use crate::core::{Context, DirectiveSpec, Module, ModuleKind};
use crate::modules::ctx::ModuleCtx;
use crate::modules::location::LocationConf;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MODULE_NAME: &str = "ngx_http_limit_req_module";

/// Entries idle longer than this are pruned (`LRU_TIME_OUT` is 60s in the C module).
const LRU_TIME_OUT: Duration = Duration::from_secs(60);

/// A shared limit zone (`limit_req_zone <key> zone=NAME:SIZE rate=RATE`).
///
/// Nginx keeps an rbtree in shared memory; a mutex-protected map plays the same role in a
/// single-process server while keeping the same accounting rules.
pub struct LimitZone {
    pub name: String,
    pub size: u64,
    pub key: Template,
    /// Requests per second.
    pub rate: u64,
    entries: Mutex<HashMap<String, LimitNode>>,
}

#[derive(Clone, Copy, Debug)]
struct LimitNode {
    excess: u64,
    last: Instant,
}

/// Result of one lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Exceeds `burst`: reject with `limit_req_status` (`NGX_BUSY`).
    Busy { excess: u64 },
    /// Passes, but must be delayed (`NGX_AGAIN` with a delay).
    Delay { excess: u64, wait: Duration },
    /// Passes immediately (`NGX_OK` / `NGX_DECLINED` with no delay).
    Passed,
}

impl LimitZone {
    pub fn new(name: String, size: u64, rate: u64, key: Template) -> Self {
        Self {
            name,
            size,
            key,
            rate,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Evaluate one key. `burst` and `delay` are milliseconds of allowed excess
    /// (`limit->burst * 1000` in `ngx_http_limit_req`).
    ///
    /// Follows `ngx_http_limit_req_lookup`: an existing node has its excess decayed and
    /// then incremented by 1000; a brand-new node starts at 0, `account` adds 1000, and the
    /// caller (`ngx_http_limit_req_account`) then decides on the delay. Both paths are
    /// folded here so the first request is never "delayed" by a stale timestamp.
    pub fn check(&self, key: &str, burst: u64, delay: u64) -> Lookup {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("limit_req zone mutex");
        self.prune(&mut entries, now);
        let existing = entries.get(key).map(|node| (node.excess, node.last));
        let (mut excess, mut last) = existing.unwrap_or((0, now));
        let elapsed_ms = existing.map_or(0, |(_, last)| {
            now.saturating_duration_since(last)
                .as_millis()
                .min(u128::from(u64::MAX)) as u64
        });
        // `excess = lr->excess - rate * ms / 1000 + 1000`
        //
        // Allowance is tracked in milli-requests so a slow rate (for example 1 r/s) drains
        // smoothly instead of truncating every sub-second interval to zero.
        // `excess` is in milli-requests: `rate` (requests/second) * `elapsed_ms` already
        // yields milli-requests, so a 1 r/s zone drains 1000 per second.
        let drained = self.rate.saturating_mul(elapsed_ms);
        excess = excess.saturating_sub(drained).saturating_add(1000);
        if existing.is_none() || elapsed_ms > 0 {
            last = now;
        }
        if excess > burst {
            // Keep the inflated excess so repeated attempts stay limited.
            entries.insert(key.to_string(), LimitNode { excess, last });
            return Lookup::Busy { excess };
        }
        entries.insert(key.to_string(), LimitNode { excess, last });
        if excess > delay {
            // `burst`/`delay` are already in milliseconds, so the wait is just the excess
            // above the delay divided by the rate.
            let wait_ms = (excess - delay) / self.rate.max(1);
            Lookup::Delay {
                excess,
                wait: Duration::from_millis(wait_ms),
            }
        } else {
            Lookup::Passed
        }
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("limit_req zone mutex").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop idle entries and enforce the zone capacity.
    fn prune(&self, entries: &mut HashMap<String, LimitNode>, now: Instant) {
        entries.retain(|_, node| now.saturating_duration_since(node.last) < LRU_TIME_OUT);
        // Approximate slab accounting: only entries up to the configured zone size remain.
        let capacity = (self.size / 64).max(1) as usize;
        while entries.len() > capacity {
            let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, node)| node.last)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            entries.remove(&oldest);
        }
    }
}

/// One `limit_req` entry for a location.
#[derive(Clone)]
pub struct LimitSpec {
    pub zone: Arc<LimitZone>,
    pub burst: u64,
    pub delay: u64,
}

impl std::fmt::Debug for LimitSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LimitSpec")
            .field("zone", &self.zone.name)
            .field("burst", &(self.burst / 1000))
            .field("delay", &(self.delay / 1000))
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct LimitReqConf {
    pub limits: Vec<LimitSpec>,
    /// `limit_req_status`, default 503.
    pub status: u16,
    pub dry_run: bool,
}

impl LocationConf for LimitReqConf {}

/// Per-request `$limit_req_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitStatus {
    Passed,
    Delayed,
    Rejected,
    DelayedDryRun,
    RejectedDryRun,
}

impl LimitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            LimitStatus::Passed => "PASSED",
            LimitStatus::Delayed => "DELAYED",
            LimitStatus::Rejected => "REJECTED",
            LimitStatus::DelayedDryRun => "DELAYED_DRY_RUN",
            LimitStatus::RejectedDryRun => "REJECTED_DRY_RUN",
        }
    }
}

/// `limit_req` result stored on the request for the variable and for logging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitReqOutcome {
    pub status: LimitStatus,
    /// Zone that produced the result.
    pub zone: &'static str,
}

/// Process-wide zones declared with `limit_req_zone`.
#[derive(Default)]
pub struct LimitReqZones {
    zones: HashMap<String, Arc<LimitZone>>,
}

impl LimitReqZones {
    pub fn get(&self, name: &str) -> Option<Arc<LimitZone>> {
        self.zones.get(name).cloned()
    }

    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.zones.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn total_entries(&self) -> usize {
        self.zones.values().map(|zone| zone.len()).sum()
    }

    /// Register a zone.
    ///
    /// `limit_req` runs in `http`/`server`/`location` during the compiler's *first* pass,
    /// before `limit_req_zone` in the second; registering zones up front makes declaration
    /// order irrelevant, as in Nginx.
    pub fn declare(&mut self, zone: &ZoneDefinition) {
        self.zones.entry(zone.name.clone()).or_insert_with(|| {
            Arc::new(LimitZone::new(
                zone.name.clone(),
                zone.size,
                zone.rate,
                zone.key.clone(),
            ))
        });
    }

    pub fn declare_all(&mut self, zones: &[ZoneDefinition]) {
        for zone in zones {
            self.declare(zone);
        }
    }
}

/// A parsed `limit_req_zone` directive.
#[derive(Clone, Debug)]
pub struct ZoneDefinition {
    pub name: String,
    pub size: u64,
    pub rate: u64,
    pub key: Template,
}

pub struct LimitReqModule;

impl Module for LimitReqModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn kind(&self) -> ModuleKind {
        ModuleKind::Http
    }

    fn http_state(&self) -> Option<crate::core::StateInstance> {
        Some(crate::core::StateInstance::new(LimitReqZones::default()))
    }

    fn directives(&self) -> Vec<DirectiveSpec> {
        vec![
            DirectiveSpec {
                name: "limit_req_zone",
                contexts: &[Context::Http],
                handler: parse_zone,
            },
            DirectiveSpec {
                name: "limit_req",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_limit,
            },
            DirectiveSpec {
                name: "limit_req_status",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_status,
            },
            DirectiveSpec {
                name: "limit_req_dry_run",
                contexts: &[Context::Http, Context::Server, Context::Location],
                handler: parse_dry_run,
            },
        ]
    }
}

fn parse_zone(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    let zone = parse_zone_definition(directive)?;
    // The zone was already registered by `prescan_zones`, which validates duplicates.
    view.state::<LimitReqZones>()?.declare(&zone);
    Ok(())
}

/// Parse `limit_req_zone <key> zone=NAME:SIZE rate=RATE`.
pub fn parse_zone_definition(directive: &crate::core::syntax::Directive) -> Result<ZoneDefinition> {
    if directive.args.len() < 3 || directive.has_block() {
        return Err(directive.error("expected key zone=NAME:SIZE rate=Nr/s"));
    }
    // `args[0]` is the key expression; options start at `args[1]`.
    let key = Template::parse(&directive.args[0])
        .map_err(|error| directive.error(format!("invalid limit_req_zone key: {error}")))?;
    let mut name = String::new();
    let mut size = 0;
    let mut rate = 0;
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
        } else if let Some(rate_value) = argument.strip_prefix("rate=") {
            rate = parse_rate(directive, rate_value)?;
        } else {
            return Err(directive.error(format!("invalid parameter \"{argument}\"")));
        }
    }
    if name.is_empty() {
        return Err(directive.error("\"zone\" parameter is required"));
    }
    if rate == 0 {
        return Err(directive.error("\"rate\" parameter is required"));
    }
    Ok(ZoneDefinition {
        name,
        size,
        rate,
        key,
    })
}

/// `rate=Nr/s` or `rate=Nr/m`, converted to requests per second like `ctx->rate`.
fn parse_rate(directive: &crate::core::syntax::Directive, value: &str) -> Result<u64> {
    // `find` returns the index of the first non-digit; `Err` means the value is all digits.
    let (number, unit) = match value.find(|ch: char| !ch.is_ascii_digit()) {
        Some(index) => value.split_at(index),
        None => (value, ""),
    };
    let number = parse_u64(directive, number)?;
    if number == 0 {
        return Err(directive.error("zero rate is not allowed"));
    }
    match unit {
        "r/s" => Ok(number),
        "r/m" => Ok(number.div_ceil(60)),
        other => Err(directive.error(format!("invalid rate unit \"{other}\""))),
    }
}

fn parse_limit(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() || directive.has_block() {
        return Err(directive.error("expected zone=NAME [burst=N] [delay=N|nodelay]"));
    }
    let mut zone_name = None;
    let mut burst = 0;
    let mut delay = 0;
    let mut nodelay = false;
    for argument in &directive.args {
        if let Some(value) = argument.strip_prefix("zone=") {
            zone_name = Some(value.to_string());
        } else if let Some(value) = argument.strip_prefix("burst=") {
            burst = parse_u64(directive, value)?;
        } else if let Some(value) = argument.strip_prefix("delay=") {
            delay = parse_u64(directive, value)?;
        } else if argument == "nodelay" {
            // `NGX_MAX_INT_T_VALUE / 1000`: never delay, only reject.
            nodelay = true;
            delay = u64::MAX / 1000;
        } else {
            return Err(directive.error(format!("invalid parameter \"{argument}\"")));
        }
    }
    let zone_name = zone_name.ok_or_else(|| directive.error("\"zone\" parameter is required"))?;
    if !nodelay && delay > burst {
        return Err(directive.error("\"delay\" parameter must be less than or equal to \"burst\""));
    }
    // Zones live in the `http {}` state, which is filled by the first compiler pass.
    let zones = view.state::<LimitReqZones>()?;
    let zone = zones
        .get(&zone_name)
        .ok_or_else(|| directive.error(format!("unknown limit_req_zone \"{zone_name}\"")))?;
    let duplicate = view.location_conf::<LimitReqConf>().is_some_and(|conf| {
        conf.limits
            .iter()
            .any(|limit| Arc::ptr_eq(&limit.zone, &zone))
    });
    if duplicate {
        return Err(directive.error("is duplicate"));
    }
    view.update_conf::<LimitReqConf>(|conf| {
        conf.limits.push(LimitSpec {
            zone,
            burst: burst.saturating_mul(1000),
            delay: delay.saturating_mul(1000),
        });
    })
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
    view.update_conf::<LimitReqConf>(|conf| conf.status = status)
}

fn parse_dry_run(view: &mut crate::modules::DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args(1)?;
    let enabled = parse_on_off(directive, &directive.args[0])?;
    view.update_conf::<LimitReqConf>(|conf| conf.dry_run = enabled)
}

/// `NGX_HTTP_PREACCESS_PHASE`.
///
/// Returns `Some((status, wait))` when the request must be rejected or delayed. `wait` is
/// `None` for a rejection.
pub async fn handle(ctx: &mut ModuleCtx<'_>) -> Result<Option<(u16, Option<Duration>)>> {
    let Some(conf) = ctx.location.get::<LimitReqConf>().cloned() else {
        return Ok(None);
    };
    if conf.limits.is_empty() {
        return Ok(None);
    }
    let status_code = if conf.status == 0 { 503 } else { conf.status };
    // `r->main->limit_req_status` is set once per request; the variable then reports it.
    // Nginx stores `limit_req_status` on `r->main`, which is shared by subrequests; here the
    // engine runs the phase once per request, so no early return is needed.
    for limit in &conf.limits {
        let key = ctx.state.eval(&limit.zone.key);
        if key.is_empty() {
            continue;
        }
        if key.len() > 65535 {
            log::error!(
                target: "nginxrs::limit_req",
                "the value of the limit_req_zone key is more than 65535 bytes"
            );
            continue;
        }
        match limit.zone.check(&key, limit.burst, limit.delay) {
            Lookup::Busy { excess } => {
                ctx.state.set_limit_req_status(if conf.dry_run {
                    LimitStatus::RejectedDryRun
                } else {
                    LimitStatus::Rejected
                });
                log::warn!(
                    target: "nginxrs::limit_req",
                    "limiting requests{}, excess: {}.{:03} by zone \"{}\"",
                    if conf.dry_run { ", dry run" } else { "" },
                    excess / 1000,
                    excess % 1000,
                    limit.zone.name
                );
                if conf.dry_run {
                    continue;
                }
                return Ok(Some((status_code, None)));
            }
            Lookup::Delay { excess, wait } => {
                ctx.state.set_limit_req_status(if conf.dry_run {
                    LimitStatus::DelayedDryRun
                } else {
                    LimitStatus::Delayed
                });
                log::info!(
                    target: "nginxrs::limit_req",
                    "delaying requests{}, excess: {}.{:03} by zone \"{}\"",
                    if conf.dry_run { ", dry run" } else { "" },
                    excess / 1000,
                    excess % 1000,
                    limit.zone.name
                );
                if conf.dry_run {
                    continue;
                }
                return Ok(Some((0, Some(wait))));
            }
            Lookup::Passed => {
                ctx.state.set_limit_req_status(LimitStatus::Passed);
            }
        }
    }
    Ok(None)
}

/// Collect every `limit_req_zone` from an `http {}` block before compiling its contents.
///
/// Nginx resolves `limit_req` zone references during configuration merge, so declaration
/// order does not matter. The compiler calls this first to register the zones.
pub fn prescan_zones(
    http: &[crate::core::syntax::Directive],
    states: &mut crate::core::state::StateAccess<'_>,
) -> Result<()> {
    let mut definitions = Vec::new();
    for directive in http
        .iter()
        .filter(|directive| directive.name == "limit_req_zone")
    {
        let zone = parse_zone_definition(directive)?;
        if definitions
            .iter()
            .any(|existing: &ZoneDefinition| existing.name == zone.name)
        {
            return Err(directive.error("is duplicate"));
        }
        definitions.push(zone);
    }
    if let Some(zones) = states.get_mut::<LimitReqZones>(MODULE_NAME) {
        zones.declare_all(&definitions);
    }
    Ok(())
}

#[allow(dead_code)]
fn _state(_: &RequestState) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(rate: u64) -> LimitZone {
        LimitZone::new(
            "test".into(),
            1024 * 1024,
            rate,
            Template::parse("$remote_addr").unwrap(),
        )
    }

    #[test]
    fn burst_allows_up_to_limit_then_rejects() {
        let zone = zone(10);
        // burst=1 -> 1000ms of excess; delays disabled.
        let burst = 1000;
        let delay = 1000;
        assert_eq!(zone.check("k", burst, delay), Lookup::Passed);
        assert!(matches!(zone.check("k", burst, delay), Lookup::Busy { .. }));
        // A different key has its own bucket.
        assert_eq!(zone.check("other", burst, delay), Lookup::Passed);
    }

    #[test]
    fn rate_drains_excess_over_time() {
        // 1 r/s: each request costs 1000ms of excess, draining at 1ms per millisecond.
        let zone = zone(1);
        let burst = 1000; // burst=1
        assert_eq!(zone.check("k", burst, burst), Lookup::Passed);
        assert!(matches!(zone.check("k", burst, burst), Lookup::Busy { .. }));
        // 1 r/s drains 1000ms of excess per second; excess was 2000, so wait > 2s.
        std::thread::sleep(Duration::from_millis(3100));
        assert_eq!(zone.check("k", burst, burst), Lookup::Passed);
    }

    #[test]
    fn delay_is_reported_for_excess_above_delay() {
        // 10 r/s, delay=0: even the first request carries 1000ms of excess, so it is
        // delayed by 1000/10 = 100ms — the same as Nginx's `limit_req` with `delay=0`.
        let zone = zone(10);
        match zone.check("k", 5000, 0) {
            Lookup::Delay { excess, wait } => {
                assert_eq!(excess, 1000);
                assert_eq!(wait, Duration::from_millis(100));
            }
            other => panic!("expected delay, got {other:?}"),
        }
        // With a delay allowance of 2s, two requests pass without waiting and the third
        // only has to be delayed.
        let second = super::tests::zone(10);
        assert_eq!(second.check("k", 5000, 2000), Lookup::Passed);
        assert_eq!(second.check("k", 5000, 2000), Lookup::Passed);
        assert!(matches!(
            second.check("k", 5000, 2000),
            Lookup::Delay { .. }
        ));
    }

    #[test]
    fn nodelay_never_delays_only_rejects() {
        // `nodelay` maps to delay = (u64::MAX / 1000) * 1000, so no excess is ever delayed.
        let zone = zone(1);
        let nodelay = (u64::MAX / 1000).saturating_mul(1000);
        // burst=1 allows the first request; the second exceeds it and is rejected.
        assert_eq!(zone.check("k", 1000, nodelay), Lookup::Passed);
        assert!(matches!(
            zone.check("k", 1000, nodelay),
            Lookup::Busy { .. }
        ));
    }

    #[test]
    fn zone_capacity_bounds_entries() {
        let zone = LimitZone::new(
            "small".into(),
            640, // ~10 entries with the 64-byte accounting
            100,
            Template::parse("$remote_addr").unwrap(),
        );
        for index in 0..50 {
            zone.check(&format!("k{index}"), 0, 0);
        }
        // The newest entry is inserted after pruning, so the zone keeps at most capacity.
        assert!(zone.len() <= 11, "zone kept {} entries", zone.len());
    }

    #[test]
    fn rate_units_convert_to_requests_per_second() {
        let directive = crate::core::syntax::parse_str(
            "limit_req_zone $binary_remote_addr zone=z:10m rate=30r/m;",
        )
        .unwrap()
        .remove(0);
        let zone = parse_zone_definition(&directive).unwrap();
        assert_eq!(zone.rate, 1); // 30 requests/minute round up to 1/s
        assert_eq!(zone.name, "z");
    }

    #[test]
    fn zone_definition_requires_zone_and_rate() {
        let directive = crate::core::syntax::parse_str("limit_req_zone $remote_addr;")
            .unwrap()
            .remove(0);
        assert!(parse_zone_definition(&directive).is_err());
    }
}

#[cfg(test)]
mod status_slot_tests {
    use super::*;

    #[test]
    fn status_round_trips_through_request_state() {
        let request = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut state = crate::core::http::RequestState::new(
            crate::core::http::ConnectionState::default(),
            crate::core::http::RequestLine::from_header(&request),
            request.headers.clone(),
            &[],
        );
        assert_eq!(state.limit_req_status(), None);
        state.set_limit_req_status(LimitStatus::Passed);
        assert_eq!(state.limit_req_status(), Some(LimitStatus::Passed));
        let template = Template::parse("$limit_req_status").unwrap();
        assert_eq!(state.eval(&template), "PASSED");
    }
}
