//! The two lookup structures of `ngx_http_geo_module.c`.
//!
//! nginx picks one of them per `geo` block:
//!
//! | Block form | Structure | Runtime lookup |
//! |---|---|---|
//! | plain entries (`10.0.0.0/8 EU;`) | dual radix tree (`ngx_radix_tree_t`) | [`RadixTree::lookup`] — longest prefix wins |
//! | `geo $v { ranges; … }` | 65536 buckets of `start-end` ranges (`ngx_http_geo_range_t`) | [`RangeTable::lookup`] — first covering range wins |
//!
//! Both key on the address as `in_addr_t` in host order (`ntohl(sin_addr)`) for IPv4 and on
//! the 16-byte address for IPv6; IPv4-mapped IPv6 peers are folded to IPv4 in
//! [`crate::core::geo`] before the lookup, exactly like `ngx_http_geo_cidr_variable`.

use crate::core::geo::Cidr;
use std::net::IpAddr;

/// One bucket of the range table: sorted, non-overlapping `start..=end` fills with values.
///
/// `ngx_http_geo_add_range` keeps every bucket sorted and rejects overlaps, then
/// `ngx_http_geo_range_variable` scans a bucket linearly (`do { … } while ((++range)->value)`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bucket {
    fills: Vec<Fill>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fill {
    start: u16,
    end: u16,
    value: usize,
}

impl Bucket {
    fn position(&self, low: u16) -> usize {
        self.fills.partition_point(|fill| fill.start <= low)
    }
}

/// `ctx.high`: the 65536-bucket range table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeTable {
    buckets: Vec<Option<Bucket>>,
    default: Option<usize>,
}

/// Why a range entry could not be stored, with the nginx diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeError {
    /// `range "…" overlaps "…"`
    Overlap { existing: (u32, u32) },
}

impl RangeTable {
    pub fn new() -> Self {
        Self {
            buckets: vec![None; 0x1_0000],
            default: None,
        }
    }

    /// `default value;` (only meaningful in `ranges` mode).
    pub fn set_default(&mut self, value: usize) {
        self.default = Some(value);
    }

    pub fn default_value(&self) -> Option<usize> {
        self.default
    }

    /// `ngx_http_geo_add_range`: insert `start..=end` (host order) split across buckets.
    ///
    /// Overlapping ranges are an error in nginx; an identical range replaces the old value
    /// with a warning.
    pub fn insert(&mut self, start: u32, end: u32, value: usize) -> Result<(), RangeError> {
        let mut n = start;
        loop {
            let bucket_index = (n >> 16) as usize;
            let low = if n == start { n as u16 } else { 0 };
            let high = if (n | 0xffff) > end { end as u16 } else { 0xffff };
            self.buckets[bucket_index].get_or_insert_with(Bucket::default);
            insert_into(&mut self.buckets, bucket_index, low, high, value)?;
            if bucket_index == 0xffff {
                break;
            }
            let next = n.wrapping_add(0x1_0000) & 0xffff_0000;
            if next > end || next <= n {
                break;
            }
            n = next;
        }
        Ok(())
    }

    /// `ngx_http_geo_delete_range`: remove exactly `start..=end`; `false` when absent.
    pub fn remove(&mut self, start: u32, end: u32) -> bool {
        // Every bucket slice the range touches must hold exactly that slice; nginx's delete
        // removes one whole bucket entry at a time and reports "no address range to delete"
        // when a slice is missing (or only part of a bigger fill).
        let mut slices = Vec::new();
        let mut n = start;
        loop {
            let bucket_index = (n >> 16) as usize;
            let low = if n == start { n as u16 } else { 0 };
            let high = if (n | 0xffff) > end { end as u16 } else { 0xffff };
            slices.push((bucket_index, low, high));
            if bucket_index == 0xffff {
                break;
            }
            let next = n.wrapping_add(0x1_0000) & 0xffff_0000;
            if next > end || next <= n {
                break;
            }
            n = next;
        }

        // `ngx_http_geo_delete_range` matches `s`/`e` in the bucket of the first address
        // (`h = start >> 16`) and walks up bucket by bucket; a range that does not line up
        // with bucket boundaries is only removed when the entry is exactly that slice.
        let Some((first_bucket, first_low, first_high)) = slices.first().copied() else {
            return false;
        };
        let bucket = self.buckets[first_bucket].as_ref();
        let present = bucket.is_some_and(|bucket| {
            bucket
                .fills
                .iter()
                .any(|fill| fill.start == first_low && fill.end == first_high)
        });
        if !present {
            return false;
        }
        for (index, low, high) in slices {
            if let Some(bucket) = self.buckets[index].as_mut() {
                // `position` is the insertion point; the fill that may start at `low` is the
                // one before it.
                let previous = bucket.position(low).checked_sub(1);
                if let Some(previous) = previous
                    && bucket.fills[previous].start == low
                    && bucket.fills[previous].end == high
                {
                    bucket.fills.remove(previous);
                }
            }
        }
        true
    }

    /// `ngx_http_geo_range_variable`: the value of the first range covering `address`.
    pub fn lookup(&self, address: u32) -> Option<usize> {
        let high = (address >> 16) as usize;
        let low = address as u16;
        let bucket = self.buckets[high].as_ref()?;
        // `position` is the insertion point; fills are sorted and non-overlapping, so the fill
        // that may cover `low` is the one before it.
        let candidate = bucket.position(low).checked_sub(1)?;
        let fill = bucket.fills.get(candidate)?;
        (low <= fill.end).then_some(fill.value)
    }

    /// Bucket count used by `default` in `ranges` mode (nginx counts `entries`).
    pub fn range_count(&self) -> usize {
        self.buckets.iter().flatten().map(|bucket| bucket.fills.len()).sum()
    }
}

fn insert_into(
    buckets: &mut [Option<Bucket>],
    bucket_index: usize,
    low: u16,
    high: u16,
    value: usize,
) -> Result<(), RangeError> {
    // Kept as one lookup site so the borrow checker sees a single mutable borrow of the slot.
    let bucket = buckets[bucket_index]
        .as_mut()
        .expect("bucket was created before the insertion");
    let position = bucket.position(low);
    // The fill immediately before `position` may still cover `low`.
    if let Some(previous) = position.checked_sub(1).and_then(|i| bucket.fills.get(i).copied())
        && previous.end >= low
    {
        if previous.start == low && previous.end == high {
            // Identical range: nginx warns and replaces the value.
            bucket.fills[position - 1].value = value;
            return Ok(());
        }
        return Err(RangeError::Overlap {
            existing: (
                (u32::from(low & !0) | u32::from(previous.start)) | 0,
                u32::from(previous.end),
            ),
        });
    }
    // A fill starting inside the new range but not covered by its start.
    bucket.fills.insert(
        position,
        Fill {
            start: low,
            end: high,
            value,
        },
    );
    Ok(())
}

/// `ngx_radix_tree_t` for one address family, storing values at prefixes.
///
/// `ngx_radix32tree_find` follows the address bits as far as the tree goes and returns the
/// last value seen, i.e. the longest matching prefix. The tree starts with the empty prefix
/// (`0.0.0.0/0` and `::/0`) pointing at the "not found" sentinel.
#[derive(Clone, Debug, Default)]
pub struct RadixTree {
    root: Option<Box<RadixNode>>,
}

#[derive(Clone, Debug, Default)]
struct RadixNode {
    children: [Option<Box<RadixNode>>; 2],
    value: Option<usize>,
}

impl RadixTree {
    /// An empty tree whose root holds the `0.0.0.0/0` / `::/0` sentinel value `0`, exactly
    /// like `ngx_http_geo_block` inserts `ngx_http_variable_null_value` at prefix length 0.
    pub fn new() -> Self {
        Self {
            root: Some(Box::new(RadixNode {
                children: [None, None],
                value: Some(0),
            })),
        }
    }

    /// `ngx_radix32tree_insert`: `Err(())` means `NGX_BUSY` (the prefix already exists).
    pub fn insert_v4(&mut self, network: u32, prefix: u8, value: usize) -> Result<(), ()> {
        self.insert_bits(&bits32(network), prefix, value)
    }

    /// `ngx_radix128tree_insert`.
    pub fn insert_v6(&mut self, network: u128, prefix: u8, value: usize) -> Result<(), ()> {
        self.insert_bits(&bits128(network), prefix, value)
    }

    fn insert_bits(&mut self, bits: &[u8], prefix: u8, value: usize) -> Result<(), ()> {
        let root = self.root.get_or_insert_with(|| Box::new(RadixNode::default()));
        insert_node(root, bits, prefix, value)
    }

    /// `ngx_radix32tree_delete`: `Ok(())` when the prefix existed.
    pub fn delete_v4(&mut self, network: u32, prefix: u8) -> bool {
        self.delete_bits(&bits32(network), prefix)
    }

    pub fn delete_v6(&mut self, network: u128, prefix: u8) -> bool {
        self.delete_bits(&bits128(network), prefix)
    }

    fn delete_bits(&mut self, bits: &[u8], prefix: u8) -> bool {
        let Some(root) = self.root.as_mut() else {
            return false;
        };
        delete_node(root, bits, prefix)
    }

    /// `ngx_radix32tree_find`: the value of the longest matching prefix.
    pub fn find_v4(&self, address: u32) -> Option<usize> {
        self.find_bits(&bits32(address))
    }

    /// `ngx_radix128tree_find`.
    pub fn find_v6(&self, address: u128) -> Option<usize> {
        self.find_bits(&bits128(address))
    }

    fn find_bits(&self, bits: &[u8]) -> Option<usize> {
        let mut node = self.root.as_deref()?;
        let mut value = node.value;
        for bit in bits {
            let Some(child) = node.children[usize::from(*bit)].as_deref() else {
                break;
            };
            node = child;
            if child.value.is_some() {
                value = child.value;
            }
        }
        value
    }

    /// Insert a parsed network, translating the address family.
    pub fn insert_cidr(&mut self, cidr: Cidr, value: usize) -> Result<(), ()> {
        match cidr.network {
            IpAddr::V4(address) => self.insert_v4(u32::from(address), cidr.prefix, value),
            IpAddr::V6(address) => self.insert_v6(u128::from(address), cidr.prefix, value),
        }
    }

    /// Delete a parsed network.
    pub fn delete_cidr(&mut self, cidr: Cidr) -> bool {
        match cidr.network {
            IpAddr::V4(address) => self.delete_v4(u32::from(address), cidr.prefix),
            IpAddr::V6(address) => self.delete_v6(u128::from(address), cidr.prefix),
        }
    }

    /// Look up a `RequestState` address family (`ngx_http_geo_cidr_variable`).
    pub fn find_ip(&self, address: IpAddr) -> Option<usize> {
        match address {
            IpAddr::V4(address) => self.find_v4(u32::from(address)),
            IpAddr::V6(address) => self.find_v6(u128::from(address)),
        }
    }
}

fn bits32(value: u32) -> Vec<u8> {
    (0..32).map(|index| ((value >> (31 - index)) & 1) as u8).collect()
}

fn bits128(value: u128) -> Vec<u8> {
    (0..128)
        .map(|index| ((value >> (127 - index)) & 1) as u8)
        .collect()
}

fn insert_node(node: &mut RadixNode, bits: &[u8], prefix: u8, value: usize) -> Result<(), ()> {
    let mut current = node;
    for bit in &bits[..usize::from(prefix)] {
        let index = usize::from(*bit);
        current = current.children[index].get_or_insert_with(|| Box::new(RadixNode::default()));
    }
    if current.value.is_some() {
        return Err(());
    }
    current.value = Some(value);
    Ok(())
}

fn delete_node(node: &mut RadixNode, bits: &[u8], prefix: u8) -> bool {
    let mut current = node;
    for bit in &bits[..usize::from(prefix)] {
        let Some(next) = current.children[usize::from(*bit)].as_mut() else {
            return false;
        };
        current = next;
    }
    current.value.take().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tree whose root already holds the `0.0.0.0/0` sentinel (index 0).
    fn tree() -> RadixTree {
        RadixTree::new()
    }

    #[test]
    fn radix_longest_prefix_wins() {
        let mut tree = tree();
        tree.insert_v4(u32::from(std::net::Ipv4Addr::new(10, 0, 0, 0)), 8, 1)
            .unwrap();
        tree.insert_v4(u32::from(std::net::Ipv4Addr::new(10, 1, 0, 0)), 16, 2)
            .unwrap();
        let lookup = |address: &str| tree.find_v4(u32::from(address.parse::<std::net::Ipv4Addr>().unwrap()));
        assert_eq!(lookup("10.1.2.3"), Some(2), "more specific prefix");
        assert_eq!(lookup("10.2.3.4"), Some(1), "fallback to /8");
        // The default entry answers for everything outside the configured prefixes.
        assert_eq!(lookup("192.0.2.1"), Some(0));
    }

    #[test]
    fn radix_duplicate_and_delete() {
        let mut tree = tree();
        let net = u32::from(std::net::Ipv4Addr::new(192, 0, 2, 0));
        tree.insert_v4(net, 24, 7).unwrap();
        assert_eq!(tree.insert_v4(net, 24, 8), Err(()), "NGX_BUSY");
        assert_eq!(tree.find_v4(net + 1), Some(7));
        assert!(tree.delete_v4(net, 24));
        assert_eq!(tree.find_v4(net + 1), Some(0), "falls back to the default");
        assert!(!tree.delete_v4(net, 24));
    }

    #[test]
    fn radix_ipv6() {
        let mut tree = tree();
        let net: u128 = "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap().into();
        tree.insert_v6(net, 32, 5).unwrap();
        let hit: u128 = "2001:db8:1::1".parse::<std::net::Ipv6Addr>().unwrap().into();
        let miss: u128 = "2001:db9::1".parse::<std::net::Ipv6Addr>().unwrap().into();
        assert_eq!(tree.find_v6(hit), Some(5));
        assert_eq!(tree.find_v6(miss), Some(0));
    }

    #[test]
    fn ranges_split_across_buckets_and_lookup() {
        let mut table = RangeTable::new();
        table.set_default(9);
        // 10.0.0.0 - 10.1.0.5 spans two buckets.
        let start = u32::from(std::net::Ipv4Addr::new(10, 0, 0, 0));
        let end = u32::from(std::net::Ipv4Addr::new(10, 1, 0, 5));
        table.insert(start, end, 3).unwrap();
        let lookup = |address: &str| {
            table.lookup(u32::from(address.parse::<std::net::Ipv4Addr>().unwrap()))
        };
        assert_eq!(lookup("10.0.0.0"), Some(3));
        assert_eq!(lookup("10.0.255.255"), Some(3));
        assert_eq!(lookup("10.1.0.5"), Some(3));
        assert_eq!(lookup("10.1.0.6"), None);
        assert_eq!(lookup("11.0.0.1"), None);
        assert_eq!(table.default_value(), Some(9));
        assert_eq!(table.range_count(), 2);
    }

    #[test]
    fn ranges_reject_overlaps_and_allow_identical_updates() {
        let mut table = RangeTable::new();
        let start = u32::from(std::net::Ipv4Addr::new(192, 168, 0, 0));
        let end = u32::from(std::net::Ipv4Addr::new(192, 168, 0, 255));
        table.insert(start, end, 1).unwrap();
        // Identical range: value replaced (nginx warns, then adopts the new value).
        table.insert(start, end, 2).unwrap();
        assert_eq!(table.lookup(start), Some(2));
        // Overlapping range: an error.
        assert!(table.insert(start + 10, end + 10, 3).is_err());
        // Adjacent ranges are fine.
        table.insert(end + 1, end + 100, 3).unwrap();
        assert_eq!(table.lookup(end + 50), Some(3));
    }

    #[test]
    fn ranges_delete() {
        let mut table = RangeTable::new();
        let start = u32::from(std::net::Ipv4Addr::new(172, 16, 0, 0));
        let end = u32::from(std::net::Ipv4Addr::new(172, 16, 0, 15));
        table.insert(start, end, 4).unwrap();
        assert_eq!(table.lookup(start), Some(4), "lookup after insert");
        assert!(table.remove(start, end), "remove failed");
        assert_eq!(table.lookup(start), None);
        assert!(!table.remove(start, end));
    }
}
