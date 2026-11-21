//! The compiled form of one `geo` block and the values its variable can return.

use super::lookup::{RadixTree, RangeTable};
use crate::core::geo::Cidr;
use std::net::IpAddr;
use std::sync::Arc;

/// One distinct value of a `geo` variable (`ngx_http_geo_variable_value_node_t`).
///
/// nginx deduplicates values through a CRC32-keyed string rbtree so that many thousand
/// networks share a handful of allocations; a `Vec` of strings per block reproduces that
/// sharing, and the runtime only ever holds an index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Values {
    entries: Vec<String>,
}

impl Values {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// `ngx_http_geo_value`: the index of `value`, appending it when new.
    pub fn intern(&mut self, value: &str) -> usize {
        if let Some(index) = self.entries.iter().position(|existing| existing == value) {
            return index;
        }
        self.entries.push(value.to_string());
        self.entries.len() - 1
    }

    pub fn get(&self, index: usize) -> Option<&str> {
        self.entries.get(index).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for Values {
    fn default() -> Self {
        Self::new()
    }
}

/// Which structure a `geo` block uses (`ctx->ranges`).
#[derive(Clone, Debug)]
pub enum Lookup {
    /// Plain `network value;` entries, looked up in the dual radix tree.
    Cidr {
        tree4: RadixTree,
        tree6: RadixTree,
    },
    /// `ranges;` entries, looked up in the 65536-bucket range table.
    Ranges(RangeTable),
}

/// One compiled `geo` block: the variable's lookup plus everything needed at runtime.
#[derive(Clone, Debug)]
pub struct GeoBlock {
    /// The variable name, without `$`.
    pub name: String,
    /// `geo $value $addr;`: classify `$addr` instead of the connection address.
    pub source: Option<String>,
    /// `proxy` lines: trusted proxies that may set `X-Forwarded-For`.
    pub proxies: Vec<Cidr>,
    /// `proxy_recursive`.
    pub proxy_recursive: bool,
    /// `volatile`: mark the variable uncacheable (`NGX_HTTP_VAR_NOCACHEABLE`).
    pub no_cacheable: bool,
    pub values: Values,
    pub lookup: Lookup,
}

/// How an address is turned into `(family, integer)` for the radix tree lookup.
fn split(address: IpAddr) -> IpAddr {
    // `ngx_http_geo_cidr_variable`: an IPv4-mapped IPv6 address is looked up as IPv4.
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

impl GeoBlock {
    /// `ngx_http_geo_cidr_variable` / `ngx_http_geo_range_variable`: the value index.
    pub fn lookup(&self, address: IpAddr) -> Option<usize> {
        match &self.lookup {
            Lookup::Cidr { tree4, tree6 } => match split(address) {
                IpAddr::V4(v4) => tree4.find_v4(u32::from(v4)),
                IpAddr::V6(v6) => tree6.find_v6(u128::from(v6)),
            },
            Lookup::Ranges(table) => {
                let low = match split(address) {
                    IpAddr::V4(v4) => u32::from(v4),
                    // `ranges` only covers IPv4; anything else is `INADDR_NONE`.
                    IpAddr::V6(_) => u32::MAX,
                };
                table.lookup(low).or_else(|| table.default_value())
            }
        }
    }

    /// `IN6_IS_ADDR_V4MAPPED` handling for the `ranges` default: nginx parses the address to
    /// `INADDR_NONE` (`255.255.255.255`) and that bucket can never be filled by a valid
    /// `start-end` (start > end is rejected), so it always yields the default value.
    pub fn value(&self, address: IpAddr) -> Option<&str> {
        self.lookup(address).and_then(|index| self.values.get(index))
    }

    /// The default value of a `ranges` block (`ctx.high.default_value`), when the lookup
    /// produced no value at all.
    pub fn default_value(&self) -> Option<&str> {
        match &self.lookup {
            Lookup::Ranges(table) => table.default_value().and_then(|index| self.values.get(index)),
            Lookup::Cidr { .. } => None,
        }
    }
}

/// Every `geo` block of one configuration, keyed by variable name.
#[derive(Clone, Debug, Default)]
pub struct GeoBlocks {
    pub blocks: Vec<Arc<GeoBlock>>,
    /// Configuration warnings collected while parsing (`duplicate network`, ...).
    pub warnings: Vec<String>,
}

impl GeoBlocks {
    pub fn find(&self, name: &str) -> Option<&Arc<GeoBlock>> {
        self.blocks.iter().find(|block| block.name == name)
    }

    /// `ngx_http_add_variable(…, NGX_HTTP_VAR_CHANGEABLE)`: a second `geo` block may
    /// replace the variable, so later blocks win.
    pub fn insert(&mut self, block: GeoBlock) {
        self.blocks.retain(|existing| existing.name != block.name);
        self.blocks.push(Arc::new(block));
        self.blocks.sort_by(|left, right| left.name.cmp(&right.name));
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}
