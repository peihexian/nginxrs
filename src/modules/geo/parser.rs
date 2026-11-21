//! `ngx_http_geo_block` / `ngx_http_geo` / `ngx_http_geo_cidr` / `ngx_http_geo_range`:
//! the `geo` block parser.
//!
//! A `geo` block is not a normal directive scope: nginx installs `ngx_http_geo` as the block
//! handler and feeds it every child statement, where
//!
//! * one-word statements are switches (`ranges`, `proxy_recursive`, `volatile`),
//! * `include name;` parses another file with the same handler (before trying `name.bin`),
//! * `proxy addr;` adds a trusted proxy,
//! * everything else is an entry: `network value;` or, inside `ranges`, `start-end value;`,
//!   `delete network;` and `default value;`.
//!
//! The parser runs here rather than through [`crate::modules::registry`] because those child
//! statements share directive names (`default`, `delete`, `proxy`) with unrelated modules and
//! must only be interpreted inside this block.

use super::conf::{GeoBlock, Lookup, Values};
use super::lookup::{RadixTree, RangeError, RangeTable};
use crate::core::geo::{parse_cidr, CidrParse, Cidr};
use crate::core::syntax::{self, Directive};
use anyhow::{Result, bail};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// The diagnostic messages nginx reports for one problematic entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub file: PathBuf,
    pub line: usize,
    pub message: String,
}

impl Warning {
    pub fn render(&self) -> String {
        format!("{}:{}: {}", self.file.display(), self.line, self.message)
    }
}

/// Mutable parser state, the Rust counterpart of `ngx_http_geo_conf_ctx_t`.
pub struct Builder {
    values: Values,
    tree4: RadixTree,
    tree6: RadixTree,
    table: Option<RangeTable>,
    ranges: bool,
    /// `ranges` must be the first statement of the block.
    seen_entry: bool,
    pub proxies: Vec<Cidr>,
    pub proxy_recursive: bool,
    pub no_cacheable: bool,
    warnings: Vec<Warning>,
    /// Networks inserted so far, so a `ranges` switch can detect earlier entries.
    tree4_count: usize,
    tree6_count: usize,
    /// Files already parsed, to keep an accidental cycle from recursing forever.
    stack: Vec<PathBuf>,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            values: Values::new(),
            tree4: RadixTree::new(),
            tree6: RadixTree::new(),
            table: None,
            ranges: false,
            seen_entry: false,
            proxies: Vec::new(),
            proxy_recursive: false,
            no_cacheable: false,
            warnings: Vec::new(),
            tree4_count: 0,
            tree6_count: 0,
            stack: Vec::new(),
        }
    }

    fn warn(&mut self, directive: &Directive, message: impl Into<String>) {
        self.warnings.push(Warning {
            file: directive.file.clone(),
            line: directive.line,
            message: message.into(),
        });
    }

    /// Parse the statements of one `geo` block (or an included file).
    pub fn parse_block(
        &mut self,
        registry: &crate::modules::Registry,
        base_dir: &Path,
        nodes: &[Directive],
    ) -> Result<()> {
        for node in nodes {
            self.parse_statement(registry, base_dir, node)?;
        }
        Ok(())
    }

    fn parse_statement(
        &mut self,
        registry: &crate::modules::Registry,
        base_dir: &Path,
        node: &Directive,
    ) -> Result<()> {
        if node.children.is_some() {
            return Err(node.error("unexpected block inside geo"));
        }
        // nginx's `ngx_http_geo` inspects the *argument count* of the statement line: the
        // entry name (network, range, `include`, `proxy`, ...) is not an argument.
        // `proxy address;` is `NGX_CONF_TAKE1` and must win over the entry forms below, which
        // also accept one argument.
        if node.name == "proxy" {
            let address = node
                .args
                .first()
                .filter(|_| node.args.len() == 1)
                .ok_or_else(|| node.error("invalid number of the geo parameters"))?;
            let cidr = cidr_value(node, address)?;
            self.proxies.push(cidr);
            return Ok(());
        }
        match node.args.len() {
            0 => match node.name.as_str() {
                "ranges" => {
                    // `ranges` must precede every entry of the block.
                    if self.seen_entry || self.has_entries() {
                        return Err(node.error(
                            "the \"ranges\" directive must be the first directive inside \"geo\" block",
                        ));
                    }
                    self.ranges = true;
                    Ok(())
                }
                "proxy_recursive" => {
                    self.proxy_recursive = true;
                    Ok(())
                }
                "volatile" => {
                    self.no_cacheable = true;
                    Ok(())
                }
                _ => Err(node.error("invalid number of the geo parameters")),
            },
            1 => {
                // `include file;`, `network value;`, `start-end value;` and the `delete` /
                // `default` forms all carry exactly one argument.
                if node.name == "include" {
                    return self.include(registry, base_dir, &node.args[0]);
                }
                self.seen_entry = true;
                if self.ranges {
                    self.range_entry(node)
                } else {
                    self.cidr_entry(node)
                }
            }
            2 => Err(node.error("invalid number of the geo parameters")),
            _ => Err(node.error("invalid number of the geo parameters")),
        }
    }

    /// Whether the block already holds a network or range entry.
    fn has_entries(&self) -> bool {
        self.seen_entry || self.table.is_some() || self.tree4_count > 0 || self.tree6_count > 0
    }

    /// `include name;`: nginx looks for `name.bin` first (a binary base), then parses `name`.
    fn include(
        &mut self,
        registry: &crate::modules::Registry,
        base_dir: &Path,
        name: &str,
    ) -> Result<()> {
        if name.contains(['*', '?', '[']) {
            // `ngx_conf_include` with a glob: each match is parsed with the geo handler.
            let pattern = crate::core::value::resolve_path(base_dir, name);
            let pattern = pattern.to_string_lossy().replace('\\', "/");
            for path in glob::glob(&pattern)
                .map_err(|error| anyhow::anyhow!("invalid include pattern \"{name}\": {error}"))?
                .flatten()
            {
                self.parse_file(registry, &path)?;
            }
            return Ok(());
        }
        let path = crate::core::value::resolve_path(base_dir, name);
        self.parse_file(registry, &path)
    }

    fn parse_file(
        &mut self,
        registry: &crate::modules::Registry,
        path: &Path,
    ) -> Result<()> {
        let _ = registry;
        let canonical = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf());
        if self.stack.contains(&canonical) {
            bail!("geo include cycle detected at {}", path.display());
        }
        self.stack.push(canonical);
        let result = (|| {
            let nodes = syntax::parse_file(path)?;
            let base = path.parent().unwrap_or_else(|| Path::new("."));
            self.parse_block(registry, base, &nodes)
        })();
        self.stack.pop();
        result
    }

    /// `ngx_http_geo_cidr`: `network value;`, `default value;`, `delete network;`.
    fn cidr_entry(&mut self, node: &Directive) -> Result<()> {
        if node.name == "default" {
            let value = self.values.intern(&node.args[0]);
            // `default` is `0.0.0.0/0` (IPv4) and `::/0` (IPv6), inserted with a warning when
            // it was already set explicitly (`NGX_BUSY` is acceptable here).
            let _ = self.tree4.insert_v4(0, 0, value);
            let _ = self.tree6.insert_v6(0, 0, value);
            return Ok(());
        }
        let (net, delete) = if node.name == "delete" {
            (self.network_of(node, &node.args[0])?, true)
        } else {
            (self.network_of(node, &node.name)?, false)
        };
        if delete {
            let removed = match net.network {
                IpAddr::V4(_) => self.tree4.delete_cidr(net),
                IpAddr::V6(_) => self.tree6.delete_cidr(net),
            };
            if !removed {
                self.warn(node, format!("no network \"{}\" to delete", describe(net)));
            }
            return Ok(());
        }
        self.note_insert(net);
        let value = self.values.intern(&node.args[0]);
        let result = match net.network {
            IpAddr::V4(_) => self.tree4.insert_cidr(net, value),
            IpAddr::V6(_) => self.tree6.insert_cidr(net, value),
        };
        if result.is_err() {
            // `NGX_BUSY`: the network exists; nginx warns and replaces the value.
            self.warn(
                node,
                format!(
                    "duplicate network \"{}\", value: \"{}\", old value: \"{}\"",
                    describe(net),
                    &node.args[0],
                    self.existing(net).unwrap_or_default()
                ),
            );
            let _ = match net.network {
                IpAddr::V4(_) => self.tree4.delete_cidr(net),
                IpAddr::V6(_) => self.tree6.delete_cidr(net),
            };
            let replaced = match net.network {
                IpAddr::V4(_) => self.tree4.insert_cidr(net, value),
                IpAddr::V6(_) => self.tree6.insert_cidr(net, value),
            };
            replaced.map_err(|()| node.error("invalid radix tree"))?;
        }
        Ok(())
    }

    fn existing(&self, net: Cidr) -> Option<String> {
        let index = self.tree_cidr_lookup(net)?;
        self.values.get(index).map(str::to_string)
    }

    fn note_insert(&mut self, net: Cidr) {
        match net.network {
            IpAddr::V4(_) => self.tree4_count += 1,
            IpAddr::V6(_) => self.tree6_count += 1,
        }
    }

    fn tree_cidr_lookup(&self, net: Cidr) -> Option<usize> {
        self.tree4.find_ip(net.network).or_else(|| self.tree6.find_ip(net.network))
    }

    fn network_of(&self, node: &Directive, text: &str) -> Result<Cidr> {
        match cidr_value(node, text) {
            Ok(cidr) => Ok(cidr),
            Err(error) => Err(error),
        }
    }

    /// `ngx_http_geo_range`: `start-end value;`, `default value;`, `delete start-end;`.
    fn range_entry(&mut self, node: &Directive) -> Result<()> {
        if node.name == "default" {
            let value = self.values.intern(&node.args[0]);
            let had_default = self
                .table
                .as_ref()
                .is_some_and(|table| table.default_value().is_some());
            if had_default {
                self.warn(node, "duplicate default geo range value");
            }
            self.table.get_or_insert_with(RangeTable::new).set_default(value);
            return Ok(());
        }
        let (range, delete) = if node.name == "delete" {
            (parse_range(node, &node.args[0])?, true)
        } else {
            (parse_range(node, &node.name)?, false)
        };
        let table = self.table.get_or_insert_with(RangeTable::new);
        if delete {
            if !table.remove(range.0, range.1) {
                self.warn(node, format!("no address range \"{}\" to delete", node.args[0]));
            }
            return Ok(());
        }
        let value = self.values.intern(&node.args[0]);
        match table.insert(range.0, range.1, value) {
            Ok(()) => Ok(()),
            Err(RangeError::Overlap { existing }) => Err(node.error(format!(
                "range \"{}\" overlaps \"{}\"",
                &node.name,
                describe_v4_range(existing)
            ))),
        }
    }

    /// `ngx_http_geo_block`'s tail: turn the parsed state into a [`GeoBlock`].
    pub fn finish(self, name: String, source: Option<String>) -> GeoBlock {
        let lookup = if self.ranges {
            Lookup::Ranges(self.table.unwrap_or_else(RangeTable::new))
        } else {
            Lookup::Cidr {
                tree4: self.tree4,
                tree6: self.tree6,
            }
        };
        GeoBlock {
            name,
            source,
            proxies: self.proxies,
            proxy_recursive: self.proxy_recursive,
            no_cacheable: self.no_cacheable,
            values: self.values,
            lookup,
        }
    }

    pub fn take_warnings(&mut self) -> Vec<Warning> {
        std::mem::take(&mut self.warnings)
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// `ngx_http_geo_cidr_value`: `255.255.255.255` is a literal host network; otherwise
/// `ngx_ptocidr`, where cleared low bits produce `low address bits of … are meaningless`.
fn cidr_value(node: &Directive, text: &str) -> Result<Cidr> {
    if text == "255.255.255.255" {
        return Ok(Cidr {
            network: IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            prefix: 32,
        });
    }
    match parse_cidr(text) {
        Ok(CidrParse::Ok(cidr)) => Ok(cidr),
        Ok(CidrParse::MeaninglessBits(cidr)) => {
            log::warn!(
                "{}:{}: low address bits of {} are meaningless",
                node.file.display(),
                node.line,
                text
            );
            Ok(cidr)
        }
        Err(_) => Err(node.error(format!("invalid network \"{text}\""))),
    }
}

/// `start-end` of two IPv4 addresses in host order.
fn parse_range(node: &Directive, text: &str) -> Result<(u32, u32)> {
    let (start_text, end_text) = text
        .split_once('-')
        .ok_or_else(|| node.error(format!("invalid range \"{text}\"")))?;
    let start: std::net::Ipv4Addr = start_text
        .parse()
        .map_err(|_| node.error(format!("invalid range \"{text}\"")))?;
    let end: std::net::Ipv4Addr = end_text
        .parse()
        .map_err(|_| node.error(format!("invalid range \"{text}\"")))?;
    let start = u32::from(start);
    let end = u32::from(end);
    if start > end {
        return Err(node.error(format!("invalid range \"{text}\"")));
    }
    Ok((start, end))
}

fn describe(cidr: Cidr) -> String {
    match cidr.network {
        IpAddr::V4(address) => format!("{address}/{}", cidr.prefix),
        IpAddr::V6(address) => format!("{address}/{}", cidr.prefix),
    }
}

/// Render `(start, end)` in the basket of the bucket containing `start`, as nginx does.
fn describe_v4_range((start, end): (u32, u32)) -> String {
    let high = start >> 16;
    format!(
        "{}.{}.{}.{}-{}.{}.{}.{}",
        high >> 8,
        high & 0xff,
        (start & 0xffff) >> 8,
        start & 0xff,
        high >> 8,
        high & 0xff,
        (end & 0xffff) >> 8,
        end & 0xff
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::syntax::parse_str;
    use std::net::IpAddr;

    fn build(source: &str) -> (GeoBlock, Vec<Warning>) {
        let registry = crate::modules::Registry::default_modules();
        let nodes = parse_str(source).unwrap();
        let mut builder = Builder::new();
        builder.parse_block(&registry, Path::new("."), &nodes).unwrap();
        let warnings = builder.take_warnings();
        (builder.finish("test".to_string(), None), warnings)
    }

    fn lookup(block: &GeoBlock, address: &str) -> Option<String> {
        block
            .value(address.parse::<IpAddr>().unwrap())
            .map(str::to_string)
    }

    #[test]
    fn cidr_entries_use_the_radix_tree() {
        let (block, warnings) = build(
            "default XX;
             127.0.0.1/32 localhost;
             10.0.0.0/8 EU;
             10.1.0.0/16 FR;
             2001:db8::/32 ipv6;",
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(lookup(&block, "10.1.2.3").as_deref(), Some("FR"));
        assert_eq!(lookup(&block, "10.2.3.4").as_deref(), Some("EU"));
        assert_eq!(lookup(&block, "127.0.0.1").as_deref(), Some("localhost"));
        assert_eq!(lookup(&block, "203.0.113.9").as_deref(), Some("XX"));
        assert_eq!(lookup(&block, "2001:db8::1").as_deref(), Some("ipv6"));
        // An IPv4-mapped peer resolves through the IPv4 tree.
        assert_eq!(lookup(&block, "::ffff:10.1.2.3").as_deref(), Some("FR"));
    }

    #[test]
    fn ranges_mode_covers_ranges_defaults_and_delete() {
        // `delete` removes exactly one stored entry (`ngx_http_geo_delete_range`); deleting
        // part of a range keeps it and reports "no address range … to delete".
        let (block, warnings) = build(
            "ranges;
             default ZZ;
             10.0.0.0-10.0.0.127 EU;
             10.0.0.128-10.0.0.255 GONE;
             10.0.1.0-10.0.1.255 DE;
             delete 10.0.0.128-10.0.0.255;",
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(lookup(&block, "10.0.0.1").as_deref(), Some("EU"));
        assert_eq!(lookup(&block, "10.0.0.200").as_deref(), Some("ZZ"));
        assert_eq!(lookup(&block, "10.0.1.7").as_deref(), Some("DE"));
        assert_eq!(lookup(&block, "192.0.2.1").as_deref(), Some("ZZ"));
        // Non-IPv4 addresses fall back to the default in `ranges` mode.
        assert_eq!(lookup(&block, "2001:db8::1").as_deref(), Some("ZZ"));
    }

    #[test]
    fn ranges_must_be_first() {
        let registry = crate::modules::Registry::default_modules();
        let nodes = parse_str("10.0.0.0/8 EU; ranges;").unwrap();
        let mut builder = Builder::new();
        let error = builder
            .parse_block(&registry, Path::new("."), &nodes)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be the first"), "{error}");
    }

    #[test]
    fn duplicate_networks_warn_and_replace() {
        let (block, warnings) = build("10.0.0.0/8 EU; 10.0.0.0/8 DE;");
        assert_eq!(lookup(&block, "10.1.1.1").as_deref(), Some("DE"));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("duplicate network"), "{warnings:?}");
    }

    #[test]
    fn overlapping_ranges_are_rejected() {
        let registry = crate::modules::Registry::default_modules();
        let nodes = parse_str("ranges; 10.0.0.0-10.0.0.255 EU; 10.0.0.128-10.0.1.0 DE;").unwrap();
        let mut builder = Builder::new();
        let error = builder
            .parse_block(&registry, Path::new("."), &nodes)
            .unwrap_err()
            .to_string();
        assert!(error.contains("overlaps"), "{error}");
    }

    #[test]
    fn invalid_networks_are_rejected() {
        for source in ["10.0.0.0/33 EU;", "not-a-network EU;", "ranges; 10.0.1.0-10.0.0.0 EU;"] {
            let registry = crate::modules::Registry::default_modules();
            let nodes = parse_str(source).unwrap();
            let mut builder = Builder::new();
            assert!(
                builder.parse_block(&registry, Path::new("."), &nodes).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn proxies_and_switches_are_collected() {
        let (block, _) = build(
            "ranges;
             volatile;
             proxy 10.0.0.0/8;
             proxy_recursive;
             default ZZ;",
        );
        assert!(block.no_cacheable);
        assert!(block.proxy_recursive);
        assert_eq!(block.proxies.len(), 1);
    }

    #[test]
    fn meaningless_low_bits_are_cleared() {
        let (block, _) = build("192.0.2.7/24 LAN;");
        assert_eq!(lookup(&block, "192.0.2.9").as_deref(), Some("LAN"));
    }
}
