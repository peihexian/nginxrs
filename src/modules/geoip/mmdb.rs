//! A MaxMind DB (`.mmdb`) reader, the Rust counterpart of the libmaxminddb calls
//! `ngx_http_geoip_module.c` makes: `MMDB_open`, `MMDB_lookup_sockaddr` and
//! `MMDB_aget_value`.
//!
//! The format is documented in MaxMind's *MaxMind DB File Format Specification*. What this
//! reader needs is:
//!
//! * a binary search tree of `(left, right)` record pairs over the address bits, where a
//!   record at or below `node_count` is another node and anything above it is the offset of a
//!   data-section entry;
//! * a data section of typed values, with an extended type table and a pointer type that
//!   shares sub-values;
//! * a metadata document at the end, located by the `\xab\xcd\xefMaxMind.com` marker.
//!
//! Reading only: no writes, no network, no unsafe code.

use std::collections::BTreeMap;
use std::path::Path;

/// The metadata marker that locates the metadata section.
pub const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

/// Decoded value of one data-section entry.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Text(String),
    Double(f64),
    Float(f32),
    Bytes(Vec<u8>),
    Uint16(u16),
    Uint32(u32),
    Int32(i32),
    Uint64(u64),
    Uint128(u128),
    Map(BTreeMap<String, Value>),
    Array(Vec<Value>),
    Bool(bool),
}

impl Value {
    /// The text of a string entry; `ngx_http_geoip_str` only accepts strings.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    /// A numeric entry as `f64`, accepting the types `ngx_http_geoip_float` accepts.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Double(value) => Some(*value),
            Value::Float(value) => Some(f64::from(*value)),
            _ => None,
        }
    }

    /// A numeric entry as `i64`, accepting the types `ngx_http_geoip_int` accepts.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Uint16(value) => Some(i64::from(*value)),
            Value::Uint32(value) => Some(i64::from(*value)),
            Value::Int32(value) => Some(i64::from(*value)),
            _ => None,
        }
    }

    /// Map lookup by key.
    pub fn field(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(map) => map.get(key),
            _ => None,
        }
    }

    /// Array element by decimal index (`subdivisions.0`).
    pub fn item(&self, index: &str) -> Option<&Value> {
        let index = index.parse::<usize>().ok()?;
        match self {
            Value::Array(items) => items.get(index),
            _ => None,
        }
    }
}

/// Errors that keep a database from being used (the `MMDB_*_ERROR` codes nginx reports).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmdbError {
    /// `MMDB_INVALID_METADATA_ERROR` / `MMDB_UNKNOWN_DATABASE_FORMAT_ERROR`.
    NotMaxMindDb(String),
    /// `MMDB_FILE_OPEN_ERROR`
    Open(String),
    /// `MMDB_CORRUPT_SEARCH_TREE_ERROR` and friends.
    Corrupt(String),
}

impl std::fmt::Display for MmdbError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MmdbError::NotMaxMindDb(message)
            | MmdbError::Open(message)
            | MmdbError::Corrupt(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for MmdbError {}

/// Database metadata (`MMDB_metadata_s`).
#[derive(Clone, Debug, PartialEq)]
pub struct Metadata {
    pub node_count: u32,
    pub record_size: u16,
    /// `4` for IPv4-only editions, `6` for dual-stack editions.
    pub ip_version: u16,
    pub database_type: String,
    pub languages: Vec<String>,
    pub binary_format_major_version: u16,
    pub binary_format_minor_version: u16,
    pub build_epoch: u64,
    pub description: BTreeMap<String, String>,
}

/// An open database: the file bytes plus the decoded metadata.
#[derive(Clone, Debug)]
pub struct Mmdb {
    data: Vec<u8>,
    metadata: Metadata,
    search_tree_size: usize,
    data_section_start: usize,
    ipv4_start_node: usize,
}

/// One lookup result (`MMDB_lookup_result_s.entry`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub offset: usize,
}

impl Mmdb {
    /// `MMDB_open`: read and validate the database.
    pub fn open(path: &Path) -> Result<Self, MmdbError> {
        let data = std::fs::read(path).map_err(|error| MmdbError::Open(error.to_string()))?;
        Self::from_bytes(data)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self, MmdbError> {
        let marker = data
            .windows(METADATA_MARKER.len())
            .rposition(|window| window == METADATA_MARKER)
            .ok_or_else(|| MmdbError::NotMaxMindDb("metadata section not found".to_string()))?;
        let mut position = marker + METADATA_MARKER.len();
        let metadata_value = decode_value(&data, &mut position)?
            .ok_or_else(|| MmdbError::NotMaxMindDb("empty metadata".to_string()))?;
        let metadata = read_metadata(&metadata_value)?;
        let node_count = usize::try_from(metadata.node_count)
            .map_err(|_| MmdbError::Corrupt("node count is too large".to_string()))?;
        // A node holds two records of `record_size` bits each.
        let node_size = usize::from(metadata.record_size) / 4;
        let search_tree_size = node_count
            .checked_mul(node_size)
            .ok_or_else(|| MmdbError::Corrupt("search tree is too large".to_string()))?;
        if search_tree_size > data.len() {
            return Err(MmdbError::Corrupt(
                "search tree is larger than the file".to_string(),
            ));
        }
        let ipv4_start_node = if metadata.ip_version == 6 {
            find_ipv4_start(&data, &metadata)?
        } else {
            0
        };
        Ok(Self {
            data,
            metadata,
            search_tree_size,
            data_section_start: search_tree_size,
            ipv4_start_node,
        })
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// `MMDB_lookup_sockaddr`: the data entry for `address`.
    pub fn lookup(&self, address: std::net::IpAddr) -> Result<Option<Lookup>, MmdbError> {
        let (bits, bit_count, start) = match address {
            std::net::IpAddr::V4(v4) => {
                if self.metadata.ip_version == 6 {
                    (u128::from(u32::from(v4)), 32, self.ipv4_start_node)
                } else {
                    (u128::from(u32::from(v4)), 32, 0)
                }
            }
            std::net::IpAddr::V6(v6) => {
                if self.metadata.ip_version == 4 {
                    // `ngx_http_geoip_lookup` declines IPv6 for an IPv4 database.
                    return Ok(None);
                }
                (u128::from(v6), 128, 0)
            }
        };
        let node_count = self.metadata.node_count as usize;
        let mut node = start;
        for index in 0..bit_count {
            if node >= node_count {
                break;
            }
            let bit = (bits >> (127 - index)) & 1 == 1;
            let record = self.record(node, bit)?;
            if record == node_count {
                // The "not found" record.
                return Ok(None);
            }
            if record > node_count {
                // Data-section offsets are stored relative to the end of the tree, plus 16.
                return Ok(Some(Lookup {
                    offset: record - node_count - 16,
                }));
            }
            node = record;
        }
        Ok(None)
    }

    /// `MMDB_aget_value`: follow a path of map keys and array indices from the entry.
    pub fn get(&self, lookup: &Lookup, path: &[&str]) -> Result<Option<Value>, MmdbError> {
        let Some(mut value) = self.value(lookup)? else {
            return Ok(None);
        };
        for key in path {
            let next = value.field(key).or_else(|| value.item(key)).cloned();
            match next {
                Some(next) => value = next,
                None => return Ok(None),
            }
        }
        Ok(Some(value))
    }

    /// The decoded data entry itself.
    pub fn value(&self, lookup: &Lookup) -> Result<Option<Value>, MmdbError> {
        let mut position = self
            .data_section_start
            .checked_add(lookup.offset)
            .filter(|position| *position < self.data.len())
            .ok_or_else(|| MmdbError::Corrupt("data offset out of range".to_string()))?;
        decode_value(&self.data, &mut position)
    }

    /// One record of the search tree (`read_node`).
    fn record(&self, node: usize, right: bool) -> Result<usize, MmdbError> {
        let record_size = usize::from(self.metadata.record_size);
        let node_size = record_size / 4;
        let start = node
            .checked_mul(node_size)
            .filter(|start| start + node_size <= self.search_tree_size)
            .ok_or_else(|| MmdbError::Corrupt("node out of range".to_string()))?;
        Ok(match record_size {
            24 => read_uint_be(&self.data, start + if right { 3 } else { 0 }, 3) as usize,
            28 => {
                let middle = usize::from(self.data[start + 3] >> 4);
                let select = read_uint_be(&self.data, start + 1 + if right { 3 } else { 0 }, 3);
                (middle << 24) | select as usize
            }
            32 => read_uint_be(&self.data, start + if right { 4 } else { 0 }, 4) as usize,
            other => {
                return Err(MmdbError::Corrupt(format!(
                    "unsupported record size {other}"
                )));
            }
        })
    }
}

fn read_uint_be(data: &[u8], start: usize, size: usize) -> u128 {
    data[start..start + size]
        .iter()
        .fold(0u128, |value, byte| (value << 8) | u128::from(*byte))
}

/// `find_ipv4_start_node`: follow 96 zero bits from the root of an IPv6 tree.
fn find_ipv4_start(data: &[u8], metadata: &Metadata) -> Result<usize, MmdbError> {
    let node_count = metadata.node_count as usize;
    let record_size = usize::from(metadata.record_size);
    let node_size = record_size / 4;
    let tree_size = node_count * node_size;
    let record = |node: usize| -> Result<usize, MmdbError> {
        let start = node
            .checked_mul(node_size)
            .filter(|start| start + node_size <= tree_size)
            .ok_or_else(|| MmdbError::Corrupt("node out of range".to_string()))?;
        Ok(match record_size {
            24 => read_uint_be(data, start, 3) as usize,
            28 => {
                let middle = usize::from(data[start + 3] >> 4);
                (middle << 24) | read_uint_be(data, start + 1, 3) as usize
            }
            32 => read_uint_be(data, start, 4) as usize,
            _ => return Err(MmdbError::Corrupt("unsupported record size".to_string())),
        })
    };
    let mut node = 0usize;
    for _ in 0..96 {
        if node >= node_count {
            return Ok(node);
        }
        node = record(node)?;
    }
    Ok(node)
}

fn read_metadata(value: &Value) -> Result<Metadata, MmdbError> {
    let Value::Map(map) = value else {
        return Err(MmdbError::NotMaxMindDb("metadata is not a map".to_string()));
    };
    let uint = |key: &str| -> Option<u128> {
        match map.get(key)? {
            Value::Uint16(value) => Some(u128::from(*value)),
            Value::Uint32(value) => Some(u128::from(*value)),
            Value::Uint64(value) => Some(u128::from(*value)),
            Value::Uint128(value) => Some(*value),
            _ => None,
        }
    };
    let node_count = uint("node_count")
        .ok_or_else(|| MmdbError::NotMaxMindDb("missing node_count".to_string()))?;
    let record_size = uint("record_size")
        .ok_or_else(|| MmdbError::NotMaxMindDb("missing record_size".to_string()))?;
    let ip_version = uint("ip_version")
        .ok_or_else(|| MmdbError::NotMaxMindDb("missing ip_version".to_string()))?;
    let database_type = match map.get("database_type") {
        Some(Value::Text(value)) => value.clone(),
        _ => return Err(MmdbError::NotMaxMindDb("missing database_type".to_string())),
    };
    if record_size != 24 && record_size != 28 && record_size != 32 {
        return Err(MmdbError::NotMaxMindDb(format!(
            "invalid record_size {record_size}"
        )));
    }
    if ip_version != 4 && ip_version != 6 {
        return Err(MmdbError::NotMaxMindDb(format!(
            "invalid ip_version {ip_version}"
        )));
    }
    Ok(Metadata {
        node_count: u32::try_from(node_count)
            .map_err(|_| MmdbError::NotMaxMindDb("node_count too large".to_string()))?,
        record_size: record_size as u16,
        ip_version: ip_version as u16,
        database_type,
        languages: match map.get("languages") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        },
        binary_format_major_version: uint("binary_format_major_version").unwrap_or(2) as u16,
        binary_format_minor_version: uint("binary_format_minor_version").unwrap_or(0) as u16,
        build_epoch: uint("build_epoch").unwrap_or(0) as u64,
        description: match map.get("description") {
            Some(Value::Map(entries)) => entries
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|text| (key.clone(), text.to_string()))
                })
                .collect(),
            _ => BTreeMap::new(),
        },
    })
}

/// Decode one value at `position`, advancing past it.
///
/// Returns `Ok(None)` when the value has no data (`has_data == 0` in libmaxminddb terms).
pub fn decode_value(data: &[u8], position: &mut usize) -> Result<Option<Value>, MmdbError> {
    let start = *position;
    match decode_typed(data, position) {
        Ok(value) => Ok(value),
        Err(error) => {
            *position = start;
            Err(error)
        }
    }
}

fn decode_typed(data: &[u8], position: &mut usize) -> Result<Option<Value>, MmdbError> {
    let control = read_byte(data, position)?;
    let type_bits = control >> 5;
    // A pointer anywhere in a value resolves to the value it points at.
    if type_bits == 1 {
        return decode_pointer(data, position, control);
    }
    let (type_id, size_bits) = if type_bits == 0 {
        let extended = read_byte(data, position)?;
        // The extended byte is the type number relative to the fixed table (8 is `int32`).
        (extended.saturating_add(7), control & 0x1f)
    } else {
        (type_bits, control & 0x1f)
    };
    let size = read_size(data, position, size_bits)?;
    match type_id {
        // Types 2..=7 come from the control byte.
        2 => Ok(Some(Value::Text(read_text(data, position, size)?))),
        3 => Ok(Some(Value::Double(read_f64(data, position)?))),
        // Type 4 is `bytes`; `uint32` is type 6.
        4 => Ok(Some(Value::Bytes(read_bytes(data, position, size)?))),
        5 => Ok(Some(Value::Uint16(
            read_uint(data, position, size)? as u16,
        ))),
        6 => Ok(Some(Value::Uint32(
            read_uint(data, position, size)? as u32,
        ))),
        7 => Ok(Some(Value::Map(read_map(data, position, size)?))),
        // Types 8 and above come from the extended table.
        8 => Ok(Some(Value::Int32(read_i32(data, position, size)?))),
        9 => Ok(Some(Value::Uint64(
            read_uint(data, position, size)? as u64,
        ))),
        10 => Ok(Some(Value::Uint128(read_uint(data, position, size)?))),
        11 => Ok(Some(Value::Array(read_array(data, position, size)?))),
        // `bool` carries its value in the size field, not in a body byte.
        14 => Ok(Some(Value::Bool(size != 0))),
        17 => Ok(Some(Value::Bytes(read_bytes(data, position, size)?))),
        _ => Ok(None),
    }
}

/// A pointer's control bits select its width; the target is an absolute file offset.
fn decode_pointer(
    data: &[u8],
    position: &mut usize,
    control: u8,
) -> Result<Option<Value>, MmdbError> {
    let width = (control >> 3) & 0x3;
    let high = usize::from(control & 0x7);
    let target = match width {
        0 => (high << 8) | read_uint(data, position, 1)? as usize,
        1 => ((high << 16) | read_uint(data, position, 2)? as usize) + 2048,
        2 => ((high << 24) | read_uint(data, position, 3)? as usize) + 526_336,
        _ => (high << 24) | read_uint(data, position, 3)? as usize,
    };
    let mut target = target;
    if target >= data.len() {
        return Err(MmdbError::Corrupt("pointer out of range".to_string()));
    }
    decode_value(data, &mut target)
}

fn read_size(data: &[u8], position: &mut usize, size_bits: u8) -> Result<usize, MmdbError> {
    Ok(match size_bits {
        value @ 0..=28 => usize::from(value),
        29 => 29 + usize::from(read_byte(data, position)?),
        30 => 285 + usize::from(read_byte(data, position)?),
        _ => 65_821 + usize::from(read_byte(data, position)?),
    })
}

fn read_byte(data: &[u8], position: &mut usize) -> Result<u8, MmdbError> {
    let byte = data
        .get(*position)
        .copied()
        .ok_or_else(|| MmdbError::Corrupt("value out of range".to_string()))?;
    *position += 1;
    Ok(byte)
}

fn read_bytes(data: &[u8], position: &mut usize, size: usize) -> Result<Vec<u8>, MmdbError> {
    let end = position
        .checked_add(size)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| MmdbError::Corrupt("value out of range".to_string()))?;
    let bytes = data[*position..end].to_vec();
    *position = end;
    Ok(bytes)
}

fn read_text(data: &[u8], position: &mut usize, size: usize) -> Result<String, MmdbError> {
    let bytes = read_bytes(data, position, size)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_uint(data: &[u8], position: &mut usize, size: usize) -> Result<u128, MmdbError> {
    let bytes = read_bytes(data, position, size)?;
    Ok(bytes
        .iter()
        .fold(0u128, |value, byte| (value << 8) | u128::from(*byte)))
}

#[allow(dead_code)]
fn read_f32(data: &[u8], position: &mut usize) -> Result<f32, MmdbError> {
    let bytes = read_bytes(data, position, 4)?;
    Ok(f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_f64(data: &[u8], position: &mut usize) -> Result<f64, MmdbError> {
    let bytes = read_bytes(data, position, 8)?;
    Ok(f64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_i32(data: &[u8], position: &mut usize, size: usize) -> Result<i32, MmdbError> {
    let bytes = read_bytes(data, position, size)?;
    Ok(match size {
        0 => 0,
        1 => i32::from(bytes[0] as i8),
        2 => i32::from(i16::from_be_bytes([bytes[0], bytes[1]])),
        3 => {
            // Sign-extend a 24-bit value.
            let value =
                (i32::from(bytes[0]) << 16) | (i32::from(bytes[1]) << 8) | i32::from(bytes[2]);
            (value << 8) >> 8
        }
        _ => i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    })
}

fn read_map(
    data: &[u8],
    position: &mut usize,
    size: usize,
) -> Result<BTreeMap<String, Value>, MmdbError> {
    let mut map = BTreeMap::new();
    for _ in 0..size {
        let key = match decode_value(data, position)? {
            Some(Value::Text(key)) => key,
            _ => return Err(MmdbError::Corrupt("map key is not a string".to_string())),
        };
        if let Some(value) = decode_value(data, position)? {
            map.insert(key, value);
        }
    }
    Ok(map)
}

fn read_array(data: &[u8], position: &mut usize, size: usize) -> Result<Vec<Value>, MmdbError> {
    let mut items = Vec::with_capacity(size.min(1024));
    for _ in 0..size {
        if let Some(value) = decode_value(data, position)? {
            items.push(value);
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_text(out: &mut Vec<u8>, text: &str) {
        let bytes = text.as_bytes();
        assert!(bytes.len() < 29);
        out.push(0x40 | bytes.len() as u8); // type 2, small size
        out.extend_from_slice(bytes);
    }

    fn push_uint16(out: &mut Vec<u8>, value: u16) {
        out.push(0xA0 | 2); // type 5, size 2
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_uint32(out: &mut Vec<u8>, value: u32) {
        out.push(0xC0 | 4); // type 6, size 4
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_map(out: &mut Vec<u8>, pairs: usize) {
        out.push(0xE0 | pairs as u8); // type 7
    }

    /// `{"country": {"iso_code": CODE}}` — the shape `geoip_country_code` reads.
    fn country_entry(code: &str) -> Vec<u8> {
        let mut out = Vec::new();
        push_map(&mut out, 1);
        push_text(&mut out, "country");
        push_map(&mut out, 1);
        push_text(&mut out, "iso_code");
        push_text(&mut out, code);
        out
    }

    fn metadata_map(node_count: u32, ip_version: u16, database_type: &str) -> Vec<u8> {
        let mut out = Vec::new();
        push_map(&mut out, 5);
        push_text(&mut out, "node_count");
        push_uint32(&mut out, node_count);
        push_text(&mut out, "record_size");
        push_uint16(&mut out, 32);
        push_text(&mut out, "ip_version");
        push_uint16(&mut out, ip_version);
        push_text(&mut out, "database_type");
        push_text(&mut out, database_type);
        push_text(&mut out, "binary_format_major_version");
        push_uint16(&mut out, 2);
        out
    }

    /// A synthetic database: one node whose left record is the data entry and whose right
    /// record is the "not found" sentinel (`node_count`).
    fn synthetic(ip_version: u16, database_type: &str, entry: Vec<u8>) -> Vec<u8> {
        let node_count: u32 = 1;
        let data_offset = node_count as usize + 16;
        let mut file = Vec::new();
        file.extend_from_slice(&(data_offset as u32).to_be_bytes());
        file.extend_from_slice(&node_count.to_be_bytes());
        file.extend_from_slice(&entry);
        file.extend_from_slice(METADATA_MARKER);
        file.extend_from_slice(&metadata_map(node_count, ip_version, database_type));
        file
    }

    #[test]
    fn opens_and_reads_a_synthetic_database() {
        let db = Mmdb::from_bytes(synthetic(4, "GeoIP2-Country", country_entry("AA"))).unwrap();
        assert_eq!(db.metadata().database_type, "GeoIP2-Country");
        assert_eq!(db.metadata().ip_version, 4);
        assert_eq!(db.metadata().node_count, 1);
        let lookup = db
            .lookup("203.0.113.9".parse().unwrap())
            .unwrap()
            .expect("left record holds the data entry");
        let value = db.get(&lookup, &["country", "iso_code"]).unwrap();
        assert_eq!(
            value.and_then(|value| value.as_str().map(str::to_string)),
            Some("AA".to_string())
        );
    }

    #[test]
    fn an_ipv4_database_declines_ipv6() {
        let db = Mmdb::from_bytes(synthetic(4, "GeoIP2-Country", country_entry("AA"))).unwrap();
        assert!(db.lookup("2001:db8::1".parse().unwrap()).unwrap().is_none());
    }

    #[test]
    fn rejects_non_mmdb_files() {
        assert!(matches!(
            Mmdb::from_bytes(b"not a database".to_vec()),
            Err(MmdbError::NotMaxMindDb(_))
        ));
    }

    #[test]
    fn decodes_scalar_types() {
        let mut bytes = Vec::new();
        push_uint16(&mut bytes, 7);
        push_uint32(&mut bytes, 70_000);
        // Extended `int32` (type 8), size 4, value -2.
        bytes.extend_from_slice(&[0x04, 0x01, 0xFF, 0xFF, 0xFF, 0xFE]);
        bytes.push(0x68); // double, size 8
        bytes.extend_from_slice(&1.5f64.to_be_bytes());
        push_text(&mut bytes, "hi");
        // Extended `bool` (type 14), true: the size field holds the value.
        // `bool` is extended type 14: control `0x00`, selector `7`, value in the size bits.
        bytes.extend_from_slice(&[0x01, 0x07]);
        let mut position = 0;
        assert_eq!(
            decode_value(&bytes, &mut position).unwrap(),
            Some(Value::Uint16(7))
        );
        assert_eq!(
            decode_value(&bytes, &mut position).unwrap(),
            Some(Value::Uint32(70_000))
        );
        assert_eq!(
            decode_value(&bytes, &mut position).unwrap(),
            Some(Value::Int32(-2))
        );
        assert_eq!(
            decode_value(&bytes, &mut position).unwrap(),
            Some(Value::Double(1.5))
        );
        assert_eq!(
            decode_value(&bytes, &mut position).unwrap(),
            Some(Value::Text("hi".to_string()))
        );
        assert_eq!(
            decode_value(&bytes, &mut position).unwrap(),
            Some(Value::Bool(true))
        );
    }

    #[test]
    fn numeric_accessors_match_the_c_module() {
        assert_eq!(Value::Double(45.0).as_f64(), Some(45.0));
        assert_eq!(Value::Float(1.25).as_f64(), Some(1.25));
        assert_eq!(Value::Uint16(7).as_i64(), Some(7));
        assert_eq!(Value::Int32(-2).as_i64(), Some(-2));
        // `ngx_http_geoip_str` declines a numeric field.
        assert_eq!(Value::Uint32(1).as_str(), None);
    }
}
