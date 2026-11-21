//! `gzip`, `gzip_buffers`, `gzip_comp_level`, `gzip_disable`, `gzip_http_version`,
//! `gzip_min_length`, `gzip_proxied`, `gzip_types`, `gzip_vary`, `gzip_window`, `gzip_hash`,
//! `postpone_gzipping`, `gzip_no_buffer`.
//!
//! Defaults follow `ngx_http_gzip_merge_conf`:
//!
//! | directive | default |
//! |---|---|
//! | `gzip` | `off` |
//! | `gzip_buffers` | `(128k / pagesize) pagesize` (represented as one 128 KiB budget) |
//! | `gzip_comp_level` | `1` |
//! | `gzip_min_length` | `20` |
//! | `gzip_http_version` | `1.1` |
//! | `gzip_types` | `text/html` (always, even when the list is given) |
//! | `gzip_proxied` | `off` |
//! | `gzip_vary` | `off` |
//! | `gzip_window` / `gzip_hash` | `MAX_WBITS` / `MAX_MEM_LEVEL - 1` |
//! | `postpone_gzipping` / `gzip_no_buffer` | `0` / `off` |

use crate::core::value::parse_size;
use crate::core::{Context, DirectiveSpec};
use crate::modules::location::LocationConf;
use crate::modules::registry::DirectiveView;
use anyhow::Result;
use std::time::Duration;

/// `ngx_http_gzip_proxied` bitmask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proxied {
    pub off: bool,
    pub expired: bool,
    pub no_cache: bool,
    pub no_store: bool,
    pub private: bool,
    pub no_last_modified: bool,
    pub no_etag: bool,
    pub auth: bool,
    pub any: bool,
}

impl Default for Proxied {
    fn default() -> Self {
        Self {
            off: true,
            expired: false,
            no_cache: false,
            no_store: false,
            private: false,
            no_last_modified: false,
            no_etag: false,
            auth: false,
            any: false,
        }
    }
}

impl Proxied {
    /// Set one mask bit (the `ngx_conf_set_bitmask_slot` of `gzip_proxied`).
    pub fn insert(&mut self, token: &str) -> Result<(), String> {
        // The first token replaces the `off` default, like `ngx_conf_set_bitmask_slot`
        // clearing the `NGX_CONF_UNSET_UINT` default.
        self.off = false;
        let bit = match token {
            "off" => &mut self.off,
            "expired" => &mut self.expired,
            "no-cache" => &mut self.no_cache,
            "no-store" => &mut self.no_store,
            "private" => &mut self.private,
            "no_last_modified" => &mut self.no_last_modified,
            "no_etag" => &mut self.no_etag,
            "auth" => &mut self.auth,
            "any" => &mut self.any,
            other => return Err(format!("invalid value \"{other}\"")),
        };
        if *bit {
            return Err(format!("duplicate value \"{token}\""));
        }
        *bit = true;
        Ok(())
    }
}

/// `ngx_http_gzip_conf_t`.
#[derive(Clone, Debug)]
pub struct GzipConf {
    pub enabled: bool,
    pub no_buffer: bool,
    /// `gzip_buffers number size` — the output budget (`number * size`).
    pub buffers: (usize, usize),
    pub postpone_gzipping: usize,
    pub level: u32,
    /// Window bits derived from `gzip_window`.
    pub window_bits: u32,
    /// `gzip_hash` in memlevel terms.
    pub hash_bits: u32,
    pub min_length: usize,
    pub types: Vec<String>,
    /// `gzip_types` was given explicitly; the default `text/html` still applies.
    pub types_given: bool,
    pub http_version: HttpVersion,
    pub proxied: Proxied,
    pub vary: bool,
    /// `gzip_disable` regexes (MSIE 6.)
    pub disable: Vec<regex::Regex>,
}

/// `gzip_http_version`: requests at or below this version are not gzipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HttpVersion {
    Http10,
    Http11,
}

impl Default for GzipConf {
    fn default() -> Self {
        Self {
            enabled: false,
            no_buffer: false,
            buffers: (32, 4096),
            postpone_gzipping: 0,
            level: 1,
            window_bits: 15,
            hash_bits: 8,
            min_length: 20,
            types: vec!["text/html".to_string()],
            types_given: false,
            http_version: HttpVersion::Http11,
            proxied: Proxied::default(),
            vary: false,
            disable: Vec::new(),
        }
    }
}

impl GzipConf {
    /// `ngx_http_gzip_merge_conf`: fold the parent block into this one.
    ///
    /// `ngx_http_merge_types` keeps the implicit `text/html` even when a block lists its own
    /// types, so a location without `gzip_types` inherits the parent list as-is.
    pub fn merge_from(&mut self, parent: &GzipConf) {
        // `ngx_conf_merge_types`: a block that kept the default list inherits the parent's
        // explicit list, so `gzip_types` in `http {}` reaches every location.
        if self.types_given {
            // A location's own list still keeps the implicit `text/html`.
            if !self.types.iter().any(|kind| kind == "text/html") {
                self.types.push("text/html".to_string());
            }
        } else if parent.types_given {
            self.types = parent.types.clone();
        }
        if self.proxied.off && !self.proxied.any {
            self.proxied = parent.proxied.clone();
        }
        if self.disable.is_empty() {
            self.disable = parent.disable.clone();
        }
    }
}

impl LocationConf for GzipConf {
    fn inherit(&self) -> bool {
        true
    }
}

/// `ngx_conf_check_num_bounds` for `gzip_comp_level` (1..=9).
fn comp_level(directive: &crate::core::syntax::Directive, text: &str) -> Result<u32> {
    let level: u32 = text
        .parse()
        .map_err(|_| directive.error(format!("invalid number \"{text}\"")))?;
    if !(1..=9).contains(&level) {
        return Err(directive.error(format!(
            "\"{text}\" must be between 1 and 9"
        )));
    }
    Ok(level)
}

/// `ngx_http_gzip_window`: the window size as a power of two from 512 to 32k.
fn window(directive: &crate::core::syntax::Directive, text: &str) -> Result<u32> {
    let size = parse_size(directive, text)?;
    let mut bits = 15;
    let mut candidate = 32 * 1024;
    while candidate > 256 {
        if candidate as u64 == size {
            return Ok(bits);
        }
        bits -= 1;
        candidate >>= 1;
    }
    Err(directive.error("must be 512, 1k, 2k, 4k, 8k, 16k, or 32k"))
}

/// `ngx_http_gzip_hash`: the hash size as a power of two from 512 to 128k.
fn hash(directive: &crate::core::syntax::Directive, text: &str) -> Result<u32> {
    let size = parse_size(directive, text)?;
    let mut bits = 9;
    let mut candidate = 128 * 1024;
    while candidate > 256 {
        if candidate as u64 == size {
            return Ok(bits);
        }
        bits -= 1;
        candidate >>= 1;
    }
    Err(directive.error("must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k"))
}

/// `gzip_buffers number size` (`ngx_conf_set_bufs_slot`).
fn buffers(directive: &crate::core::syntax::Directive, args: &[String]) -> Result<(usize, usize)> {
    if args.len() != 2 {
        return Err(directive.error("expected gzip_buffers number size"));
    }
    let number: usize = args[0]
        .parse()
        .map_err(|_| directive.error(format!("invalid number \"{}\"", args[0])))?;
    let size = parse_size(directive, &args[1])?;
    Ok((number, size as usize))
}

/// `on`/`off` (`ngx_conf_set_flag_slot`).
pub fn flag(directive: &crate::core::syntax::Directive, text: &str) -> Result<bool> {
    match text {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(directive.error(format!(
            "invalid value \"{other}\", it must be \"on\" or \"off\""
        ))),
    }
}

fn set_enabled(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = flag(directive, &directive.args[0])?;
    view.update_conf::<GzipConf>(|conf| conf.enabled = value)?;
    Ok(())
}

fn set_no_buffer(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = flag(directive, &directive.args[0])?;
    view.update_conf::<GzipConf>(|conf| conf.no_buffer = value)?;
    Ok(())
}

fn set_vary(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = flag(directive, &directive.args[0])?;
    view.update_conf::<GzipConf>(|conf| conf.vary = value)?;
    Ok(())
}

fn set_buffers(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    let value = buffers(directive, &directive.args)?;
    view.update_conf::<GzipConf>(|conf| conf.buffers = value)?;
    Ok(())
}

fn set_level(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = comp_level(directive, &directive.args[0])?;
    view.update_conf::<GzipConf>(|conf| conf.level = value)?;
    Ok(())
}

fn set_window(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = window(directive, &directive.args[0])?;
    view.update_conf::<GzipConf>(|conf| conf.window_bits = value)?;
    Ok(())
}

fn set_hash(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = hash(directive, &directive.args[0])?;
    view.update_conf::<GzipConf>(|conf| conf.hash_bits = value)?;
    Ok(())
}

fn set_postpone(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = parse_size(directive, &directive.args[0])?;
    view.update_conf::<GzipConf>(|conf| conf.postpone_gzipping = value as usize)?;
    Ok(())
}

fn set_min_length(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let value = parse_size(directive, &directive.args[0])?;
    view.update_conf::<GzipConf>(|conf| conf.min_length = value as usize)?;
    Ok(())
}

fn set_types(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() {
        return Err(directive.error("expected gzip_types mime-type ..."));
    }
    let entries: Vec<String> = directive
        .args
        .iter()
        .map(|entry| entry.to_ascii_lowercase())
        .collect();
    view.update_conf::<GzipConf>(|conf| {
        conf.types = entries.clone();
        conf.types_given = true;
    })?;
    Ok(())
}

fn set_http_version(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    directive.expect_args_range(1..=1)?;
    let version = match directive.args[0].as_str() {
        "1.0" => HttpVersion::Http10,
        "1.1" => HttpVersion::Http11,
        other => return Err(directive.error(format!("invalid value \"{other}\""))),
    };
    view.update_conf::<GzipConf>(|conf| conf.http_version = version)?;
    Ok(())
}

fn set_proxied(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    // `ngx_conf_set_bitmask_slot`: every token sets one bit, and the first token clears the
    // `off` default.
    let mut state = Proxied {
        off: false,
        ..Proxied::default()
    };
    for token in &directive.args {
        state.insert(token).map_err(|error| directive.error(error))?;
    }
    view.update_conf::<GzipConf>(|conf| conf.proxied = state)?;
    Ok(())
}

fn set_disable(view: &mut DirectiveView<'_>) -> Result<()> {
    let directive = view.directive;
    if directive.args.is_empty() {
        return Err(directive.error("expected gzip_disable regex ..."));
    }
    let mut compiled = Vec::new();
    for pattern in &directive.args {
        // `ngx_regex_compile` with `NGX_REGEX_CASELESS`.
        let regex = regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .map_err(|error| directive.error(format!("invalid regex \"{pattern}\": {error}")))?;
        compiled.push(regex);
    }
    view.update_conf::<GzipConf>(|conf| conf.disable = compiled)?;
    Ok(())
}

/// Every directive of the module (`ngx_http_gzip_filter_commands`).
pub fn directives() -> Vec<DirectiveSpec> {
    const CTX: &[Context] = &[
        Context::Http,
        Context::Server,
        Context::Location,
    ];
    vec![
        DirectiveSpec {
            name: "gzip",
            contexts: CTX,
            handler: set_enabled,
        },
        DirectiveSpec {
            name: "gzip_buffers",
            contexts: CTX,
            handler: set_buffers,
        },
        DirectiveSpec {
            name: "gzip_comp_level",
            contexts: CTX,
            handler: set_level,
        },
        DirectiveSpec {
            name: "gzip_disable",
            contexts: CTX,
            handler: set_disable,
        },
        DirectiveSpec {
            name: "gzip_hash",
            contexts: CTX,
            handler: set_hash,
        },
        DirectiveSpec {
            name: "gzip_http_version",
            contexts: CTX,
            handler: set_http_version,
        },
        DirectiveSpec {
            name: "gzip_min_length",
            contexts: CTX,
            handler: set_min_length,
        },
        DirectiveSpec {
            name: "gzip_no_buffer",
            contexts: CTX,
            handler: set_no_buffer,
        },
        DirectiveSpec {
            name: "gzip_proxied",
            contexts: CTX,
            handler: set_proxied,
        },
        DirectiveSpec {
            name: "gzip_types",
            contexts: CTX,
            handler: set_types,
        },
        DirectiveSpec {
            name: "gzip_vary",
            contexts: CTX,
            handler: set_vary,
        },
        DirectiveSpec {
            name: "gzip_window",
            contexts: CTX,
            handler: set_window,
        },
        DirectiveSpec {
            name: "postpone_gzipping",
            contexts: CTX,
            handler: set_postpone,
        },
    ]
}

/// `gzip_http_version` helpers used by the negotiation.
pub fn version_at_most(request: http::Version, limit: HttpVersion) -> bool {
    match limit {
        HttpVersion::Http10 => true,
        HttpVersion::Http11 => matches!(
            request,
            http::Version::HTTP_11 | http::Version::HTTP_2 | http::Version::HTTP_3
        ),
    }
}

/// `gzip_proxied` uses `ngx_http_test_connection`-style facts; time is not part of it.
pub fn is_expired(_expires: Option<Duration>) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::syntax::parse_str;

    fn conf_of(source: &str) -> GzipConf {
        let registry = crate::modules::Registry::default_modules();
        let directives = parse_str(source).unwrap();
        let mut states: Vec<crate::core::state::StateSlot> = vec![(
            "main",
            crate::core::state::StateInstance::new(crate::config::MainState::default()),
        )];
        let mut location = crate::modules::location::Location::new();
        for directive in &directives {
            let mut access = crate::core::state::StateAccess::new(&mut states);
            registry
                .dispatch(
                    directive,
                    Context::Location,
                    std::path::Path::new("."),
                    &mut access,
                    Some(&mut location),
                )
                .unwrap();
        }
        location
            .get::<GzipConf>()
            .cloned()
            .unwrap_or_default()
    }

    #[test]
    fn defaults_follow_the_merge_rules() {
        let conf = GzipConf::default();
        assert!(!conf.enabled);
        assert_eq!(conf.level, 1);
        assert_eq!(conf.min_length, 20);
        assert_eq!(conf.window_bits, 15);
        assert_eq!(conf.hash_bits, 8);
        assert_eq!(conf.types, ["text/html"]);
        assert!(conf.proxied.off);
        assert_eq!(conf.http_version, HttpVersion::Http11);
    }

    #[test]
    fn directives_are_parsed_with_nginx_bounds() {
        let conf = conf_of(
            "gzip on; gzip_comp_level 5; gzip_min_length 1000; gzip_vary on;
             gzip_types text/css application/javascript; gzip_window 8k; gzip_hash 32k;",
        );
        assert!(conf.enabled);
        assert_eq!(conf.level, 5);
        assert_eq!(conf.min_length, 1000);
        assert!(conf.vary);
        assert_eq!(conf.types, ["text/css", "application/javascript"]);
        assert_eq!(conf.window_bits, 13);
        assert_eq!(conf.hash_bits, 7);
        // `gzip_proxied` keeps its `off` default unless the block names other tokens.
        assert!(conf.proxied.off);
    }

    #[test]
    fn invalid_values_are_rejected() {
        for source in [
            "gzip_comp_level 0;",
            "gzip_comp_level 10;",
            "gzip_window 1000;",
            "gzip_hash 300k;",
            "gzip on1;",
            "gzip_http_version 2.0;",
            "gzip_proxied nope;",
            "gzip_types;",
        ] {
            let registry = crate::modules::Registry::default_modules();
            let directives = parse_str(source).unwrap();
            let mut states: Vec<crate::core::state::StateSlot> = vec![(
                "main",
                crate::core::state::StateInstance::new(crate::config::MainState::default()),
            )];
            let mut location = crate::modules::location::Location::new();
            let mut access = crate::core::state::StateAccess::new(&mut states);
            assert!(
                registry
                    .dispatch(
                        &directives[0],
                        Context::Location,
                        std::path::Path::new("."),
                        &mut access,
                        Some(&mut location),
                    )
                    .is_err(),
                "{source} must be rejected"
            );
        }
    }

    #[test]
    fn inherited_types_reach_the_location() {
        let mut parent = GzipConf {
            types: vec!["text/css".to_string()],
            types_given: true,
            ..GzipConf::default()
        };
        parent.types.push("text/html".to_string());
        let mut child = GzipConf::default();
        child.merge_from(&parent);
        assert!(child.types.contains(&"text/css".to_string()));
        // A location's own list keeps `text/html`.
        let mut own = GzipConf {
            types: vec!["application/json".to_string()],
            types_given: true,
            ..GzipConf::default()
        };
        own.merge_from(&parent);
        assert!(own.types.contains(&"text/html".to_string()));
        assert!(!own.types.contains(&"text/css".to_string()));
    }

    #[test]
    fn proxied_tokens_set_the_mask() {
        let conf = conf_of("gzip_proxied any auth;");
        assert!(conf.proxied.any);
        assert!(conf.proxied.auth);
        assert!(!conf.proxied.off);
    }

    #[test]
    fn http_version_floor() {
        assert!(version_at_most(http::Version::HTTP_10, HttpVersion::Http10));
        assert!(!version_at_most(http::Version::HTTP_10, HttpVersion::Http11));
        assert!(version_at_most(http::Version::HTTP_11, HttpVersion::Http11));
        assert!(version_at_most(http::Version::HTTP_2, HttpVersion::Http11));
    }
}
