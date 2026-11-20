//! Upstream response caching (`proxy_cache`, `proxy_cache_path`, `proxy_cache_key`,
//! `proxy_cache_valid`, `proxy_cache_bypass`, `proxy_cache_methods`,
//! `proxy_cache_min_uses`, `proxy_cache_use_stale`, `proxy_cache_revalidate`,
//! `proxy_cache_background_update`, `proxy_cache_lock`) and `$upstream_cache_status`.
//!
//! Semantics follow `c/nginx/src/http/ngx_http_file_cache.c`: keys are the MD5 of
//! `proxy_cache_key`, entries are one file per key, freshness comes from `X-Accel-Expires`,
//! `Expires`/`Cache-Control` and finally `proxy_cache_valid`, and the status names are
//! `ngx_http_upstream_cache_status` (`MISS`, `BYPASS`, `EXPIRED`, `STALE`, `UPDATING`,
//! `REVALIDATED`, `HIT`, `SCARCE`).

use crate::core::variables::Template;
use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// `ngx_http_upstream_cache_status` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheStatus {
    Miss,
    Bypass,
    Expired,
    Stale,
    Updating,
    Revalidated,
    Hit,
    Scarce,
}

impl CacheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Miss => "MISS",
            Self::Bypass => "BYPASS",
            Self::Expired => "EXPIRED",
            Self::Stale => "STALE",
            Self::Updating => "UPDATING",
            Self::Revalidated => "REVALIDATED",
            Self::Hit => "HIT",
            Self::Scarce => "SCARCE",
        }
    }
}

/// Process-wide `proxy_cache_path` zones, keyed by name (`proxy_cache_path` is `http`-only in
/// Nginx, and every `server`/`location` refers to a zone by name).
static ZONES: std::sync::LazyLock<parking_lot::RwLock<std::collections::HashMap<String, CacheZone>>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

/// Register a zone; a duplicate name is a configuration error (`ngx_http_file_cache_set_slot`
/// rejects a second zone with the same name).
pub fn register_zone(zone: CacheZone, directive: &str) -> Result<()> {
    let mut zones = ZONES.write();
    if zones.contains_key(&zone.name) {
        bail!("\"{directive}\" defines a duplicate zone \"{}\"", zone.name);
    }
    zones.insert(zone.name.clone(), zone);
    Ok(())
}

pub fn zone_exists(name: &str) -> bool {
    ZONES.read().contains_key(name)
}

pub fn zone(name: &str) -> Option<CacheZone> {
    ZONES.read().get(name).cloned()
}

/// Drop every registered zone (configuration reload starts from a clean slate).
pub fn clear_zones() {
    ZONES.write().clear();
}

/// One `proxy_cache_path` zone (`ngx_http_file_cache_t`).
#[derive(Clone, Debug)]
pub struct CacheZone {
    pub name: String,
    pub path: PathBuf,
    pub levels: Vec<usize>,
    pub inactive: Duration,
    pub max_size: u64,
    pub use_temp_path: bool,
}

impl CacheZone {
    /// `ngx_http_file_cache_name`: the cache file for a key, distributed over `levels`.
    pub fn file_path(&self, key: &str) -> PathBuf {
        let digest = md5_hex(key);
        let mut path = self.path.clone();
        let mut rest = digest.as_str();
        for depth in &self.levels {
            if rest.len() < *depth {
                break;
            }
            let (prefix, tail) = rest.split_at(*depth);
            path.push(prefix);
            rest = tail;
        }
        path.push(rest);
        path
    }
}

/// `proxy_cache` plus the per-location cache configuration.
#[derive(Clone, Debug, Default)]
pub struct CacheConf {
    /// `proxy_cache <zone>`; empty means caching is off (`proxy_cache off`).
    pub zone: Option<String>,
    /// `proxy_cache_key` (`$scheme$proxy_host$request_uri` by default).
    pub key: Option<Template>,
    /// `proxy_cache_valid [code ...] time` entries, in declaration order.
    pub valid: Vec<(Vec<u16>, Duration)>,
    /// `proxy_cache_bypass` predicates: a non-empty value bypasses the cache.
    pub bypass: Vec<Template>,
    /// `proxy_cache_no_cache` predicates: a non-empty value marks the response uncacheable.
    pub no_cache: Vec<Template>,
    /// `proxy_cache_methods`.
    pub methods: Vec<String>,
    /// `proxy_cache_min_uses`.
    pub min_uses: u64,
    /// `proxy_cache_use_stale` conditions (by name).
    pub use_stale: Vec<String>,
    /// `proxy_ignore_headers` names, which also relax the cacheability rules.
    pub ignore_headers: Vec<String>,
    pub revalidate: bool,
    pub background_update: bool,
    pub lock: bool,
}

impl CacheConf {
    /// The effective `proxy_cache_key`, following `ngx_http_proxy_merge_loc_conf`.
    pub fn key_template(&self) -> Result<Template> {
        match &self.key {
            Some(template) => Ok(template.clone()),
            None => Template::parse("$scheme$proxy_host$request_uri")
                .context("default proxy_cache_key"),
        }
    }

    pub fn enabled(&self) -> bool {
        self.zone.is_some()
    }

    /// `proxy_cache_valid`: the TTL for a status code (0 when unlisted).
    pub fn valid_for(&self, status: u16) -> Option<Duration> {
        for (codes, ttl) in &self.valid {
            if codes.is_empty() || codes.contains(&status) || (codes.contains(&0) && is_cacheable(status))
            {
                return Some(*ttl);
            }
        }
        None
    }

    /// `proxy_ignore_headers` membership (the cache cares about `Set-Cookie`,
    /// `Cache-Control`, `Expires` and `X-Accel-Expires`).
    pub fn ignores_header(&self, name: &str) -> bool {
        self.ignore_headers
            .iter()
            .any(|listed| listed.eq_ignore_ascii_case(name))
    }

    /// `proxy_cache_methods`: GET and HEAD are always cached.
    pub fn caches_method(&self, method: &str) -> bool {
        matches!(method, "GET" | "HEAD")
            || self
                .methods
                .iter()
                .any(|listed| listed.eq_ignore_ascii_case(method))
    }
}

/// A stored response (`ngx_http_file_cache_header_t` plus the variant).
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Unix seconds at which the entry stops being fresh.
    pub valid_until: u64,
    /// Unix seconds of the stored response (`r->cache->date`).
    pub stored_at: u64,
    /// `ETag`/`Last-Modified` for `proxy_cache_revalidate`.
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl CacheEntry {
    pub fn is_fresh(&self, now: u64) -> bool {
        now < self.valid_until
    }

    /// Serialised form: a small header block followed by the body, the same layout idea as
    /// `ngx_http_file_cache_set_header`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("NGINXRS-CACHE 1\n");
        out.push_str(&format!("status {}\n", self.status));
        out.push_str(&format!("valid {}\n", self.valid_until));
        out.push_str(&format!("stored {}\n", self.stored_at));
        if let Some(etag) = &self.etag {
            out.push_str(&format!("etag {etag}\n"));
        }
        if let Some(last_modified) = &self.last_modified {
            out.push_str(&format!("last-modified {last_modified}\n"));
        }
        for (name, value) in &self.headers {
            out.push_str(&format!("h {}: {}\n", name.replace('\n', " "), value.replace('\n', " ")));
        }
        out.push_str(&format!("len {}\n\n", self.body.len()));
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let split = find_header_end(bytes)?;
        let (head, body) = bytes.split_at(split);
        let head = String::from_utf8_lossy(head);
        let mut entry = Self {
            status: 200,
            headers: Vec::new(),
            body: body[2..].to_vec(),
            valid_until: 0,
            stored_at: 0,
            etag: None,
            last_modified: None,
        };
        for line in head.lines().skip(1) {
            let Some((key, value)) = line.split_once(' ') else {
                continue;
            };
            match key {
                "status" => entry.status = value.parse().ok()?,
                "valid" => entry.valid_until = value.parse().ok()?,
                "stored" => entry.stored_at = value.parse().ok()?,
                "etag" => entry.etag = Some(value.to_string()),
                "last-modified" => entry.last_modified = Some(value.to_string()),
                "len" => {
                    let length: usize = value.parse().ok()?;
                    if entry.body.len() > length {
                        entry.body.truncate(length);
                    }
                }
                "h" => {
                    if let Some((name, value)) = value.split_once(": ") {
                        entry.headers.push((name.to_string(), value.to_string()));
                    }
                }
                _ => {}
            }
        }
        Some(entry)
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\n\n")
}

/// The cache state of one request (`r->cache`).
#[derive(Clone, Debug, Default)]
pub struct CacheState {
    pub status: Option<CacheStatus>,
    pub key: Option<String>,
    pub file: Option<PathBuf>,
}

/// Compute the `$upstream_cache_status` value for a request.
pub fn status_str(status: Option<CacheStatus>) -> String {
    status.map(|status| status.as_str().to_string()).unwrap_or_default()
}

/// MD5 hex digest, as used for cache file names (`ngx_http_file_cache_name`).
pub fn md5_hex(value: &str) -> String {
    // A compact MD5 implementation: the digest is only used as a file name, but Nginx's
    // layout must be reproduced so a cache directory is interchangeable.
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut message = value.as_bytes().to_vec();
    let bit_len = (message.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    for chunk in message.chunks(64) {
        let mut m = [0_u32; 16];
        for (index, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f
                .wrapping_add(a)
                .wrapping_add(K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut digest = String::with_capacity(32);
    for word in [a0, b0, c0, d0] {
        for byte in word.to_le_bytes() {
            digest.push_str(&format!("{byte:02x}"));
        }
    }
    digest
}

/// `ngx_http_file_cache_valid`: pick a TTL from `X-Accel-Expires`, `Expires`/`Cache-Control`
/// or `proxy_cache_valid`.
///
/// Returns `(valid_until, cacheable)`. `None` means "not cacheable".
pub fn freshness(
    headers: &[(String, String)],
    status: u16,
    conf: &CacheConf,
    now: u64,
) -> Option<u64> {
    let find = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_string())
    };

    // `X-Accel-Expires` wins (`ngx_http_upstream_process_accel_expires`).
    if let Some(value) = find("X-Accel-Expires") {
        if let Ok(seconds) = value.parse::<i64>() {
            // `X-Accel-Expires: 0` disables caching; negative is "cache but do not serve
            // without revalidation".
            if seconds == 0 {
                return None;
            }
            return Some(now.saturating_add_signed(seconds));
        }
        if let Some(date) = parse_http_date(&value) {
            return Some(date);
        }
    }

    // `Cache-Control: no-cache`/`no-store`/`private` make it uncacheable.
    if let Some(cache_control) = find("Cache-Control") {
        for directive in cache_control.split(',') {
            let directive = directive.trim().to_ascii_lowercase();
            if directive == "no-cache" || directive == "no-store" || directive == "private" {
                return None;
            }
            if let Some(value) = directive.strip_prefix("max-age=")
                && let Ok(seconds) = value.parse::<i64>()
            {
                return Some(now.saturating_add_signed(seconds));
            }
        }
    }

    if let Some(expires) = find("Expires").and_then(|value| parse_http_date(&value)) {
        return Some(expires);
    }

    // `ngx_http_upstream_process_set_cookie`: a response carrying `Set-Cookie` is not
    // cacheable unless `proxy_ignore_headers Set-Cookie` clears that flag.
    if find("Set-Cookie").is_some() && !conf.ignores_header("Set-Cookie") {
        return None;
    }

    conf.valid_for(status)
        .map(|ttl| now.saturating_add(ttl.as_secs()))
}

/// Parse an HTTP date (`Expires`/`Last-Modified`) into Unix seconds.
pub fn parse_http_date(value: &str) -> Option<u64> {
    // RFC 1123: `Sun, 06 Nov 1994 08:49:37 GMT`.
    let value = value.trim();
    let rest = value.split_once(',').map(|(_, rest)| rest).unwrap_or(value);
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let day: u32 = parts[0].parse().ok()?;
    let month = match parts[1].to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[2].parse().ok()?;
    let time: Vec<&str> = parts[3].split(':').collect();
    if time.len() != 3 {
        return None;
    }
    let hour: i64 = time[0].parse().ok()?;
    let minute: i64 = time[1].parse().ok()?;
    let second: i64 = time[2].parse().ok()?;
    Some(unix_from_utc(year, month, day, hour, minute, second))
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm).
fn unix_from_utc(year: i64, month: u32, day: u32, hour: i64, minute: i64, second: i64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    if seconds < 0 {
        0
    } else {
        seconds as u64
    }
}

/// `proxy_cache_path path [levels=...] [inactive=...] [max_size=...] [use_temp_path=...] keys_zone=NAME:SIZE`
pub fn parse_cache_path(arguments: &[String]) -> Result<(CacheZone, usize)> {
    let Some(path) = arguments.first() else {
        bail!("expected a cache directory");
    };
    let mut zone = CacheZone {
        name: String::new(),
        path: PathBuf::from(path),
        levels: vec![1, 2],
        inactive: Duration::from_secs(600),
        max_size: u64::MAX,
        use_temp_path: true,
    };
    let mut size = 0_usize;
    for argument in &arguments[1..] {
        let Some((key, value)) = argument.split_once('=') else {
            bail!("invalid parameter \"{argument}\"");
        };
        match key {
            "levels" => {
                zone.levels = value
                    .split(':')
                    .map(|level| level.parse::<usize>().map_err(|_| anyhow::anyhow!("invalid levels")))
                    .collect::<Result<Vec<_>>>()?;
            }
            "inactive" => {
                zone.inactive = parse_time(value)?;
            }
            "max_size" => {
                zone.max_size = parse_size(value)?;
            }
            "use_temp_path" => {
                zone.use_temp_path = match value {
                    "on" => true,
                    "off" => false,
                    other => bail!("invalid use_temp_path \"{other}\""),
                };
            }
            "keys_zone" => {
                let (name, size_value) = value
                    .split_once(':')
                    .context("keys_zone must be NAME:SIZE")?;
                zone.name = name.to_string();
                size = parse_size(size_value)? as usize;
            }
            "manager_files" | "manager_sleep" | "manager_threshold" | "loader_files"
            | "loader_sleep" | "loader_threshold" | "min_free" => {
                // Accepted for compatibility: the manager/loader processes are not emulated.
            }
            other => bail!("invalid parameter \"{other}\""),
        }
    }
    if zone.name.is_empty() {
        bail!("keys_zone is required");
    }
    Ok((zone, size))
}

fn parse_time(value: &str) -> Result<Duration> {
    let (number, unit) = split_unit(value)?;
    let number: u64 = number.parse().map_err(|_| anyhow::anyhow!("invalid time"))?;
    Ok(match unit {
        "" | "s" => Duration::from_secs(number),
        "m" => Duration::from_secs(number * 60),
        "h" => Duration::from_secs(number * 3600),
        "d" => Duration::from_secs(number * 86_400),
        "w" => Duration::from_secs(number * 7 * 86_400),
        "M" => Duration::from_secs(number * 30 * 86_400),
        "y" => Duration::from_secs(number * 365 * 86_400),
        other => bail!("invalid time unit \"{other}\""),
    })
}

fn parse_size(value: &str) -> Result<u64> {
    let (number, unit) = split_unit(value)?;
    let number: u64 = number.parse().map_err(|_| anyhow::anyhow!("invalid size"))?;
    Ok(match unit {
        "" => number,
        "k" | "K" => number * 1024,
        "m" | "M" => number * 1024 * 1024,
        "g" | "G" => number * 1024 * 1024 * 1024,
        other => bail!("invalid size unit \"{other}\""),
    })
}

fn split_unit(value: &str) -> Result<(&str, &str)> {
    let digits = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(digits);
    if number.is_empty() {
        bail!("invalid value \"{value}\"");
    }
    Ok((number, unit))
}

/// Current time in Unix seconds.
pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|now| now.as_secs())
        .unwrap_or_default()
}

/// Status codes Nginx caches by default when `proxy_cache_valid` names no codes.
fn is_cacheable(status: u16) -> bool {
    matches!(status, 200 | 203 | 204 | 206 | 300 | 301 | 302 | 303 | 304 | 307 | 308)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_known_digests() {
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex("httplocalhost/uri"),
            md5_hex("httplocalhost/uri")
        );
    }

    #[test]
    fn cache_file_path_uses_levels() {
        let zone = CacheZone {
            name: "z".into(),
            path: PathBuf::from("/cache"),
            levels: vec![1, 2],
            inactive: Duration::from_secs(600),
            max_size: u64::MAX,
            use_temp_path: true,
        };
        let path = zone.file_path("abc");
        let digest = md5_hex("abc");
        assert_eq!(
            path,
            PathBuf::from(format!("/cache/{}/{}/{}", &digest[..1], &digest[1..3], &digest[3..]))
        );
    }

    #[test]
    fn entry_round_trips() {
        let entry = CacheEntry {
            status: 200,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: b"hello".to_vec(),
            valid_until: 1_700_000_000,
            stored_at: 1_699_999_000,
            etag: Some("\"abc\"".into()),
            last_modified: None,
        };
        let decoded = CacheEntry::decode(&entry.encode()).unwrap();
        assert_eq!(decoded.status, 200);
        assert_eq!(decoded.body, b"hello");
        assert_eq!(decoded.valid_until, 1_700_000_000);
        assert_eq!(decoded.etag.as_deref(), Some("\"abc\""));
        assert_eq!(decoded.headers.len(), 1);
    }

    #[test]
    fn accel_expires_wins() {
        let conf = CacheConf::default();
        let headers = vec![
            ("X-Accel-Expires".to_string(), "60".to_string()),
            ("Cache-Control".to_string(), "max-age=10".to_string()),
        ];
        assert_eq!(freshness(&headers, 200, &conf, 1000), Some(1060));
    }

    #[test]
    fn zero_accel_expires_disables_caching() {
        let conf = CacheConf::default();
        let headers = vec![("X-Accel-Expires".to_string(), "0".to_string())];
        assert_eq!(freshness(&headers, 200, &conf, 1000), None);
    }

    #[test]
    fn cache_control_directives_disable_caching() {
        let conf = CacheConf::default();
        for value in ["no-cache", "no-store", "private", "public, no-cache"] {
            let headers = vec![("Cache-Control".to_string(), value.to_string())];
            assert_eq!(freshness(&headers, 200, &conf, 1000), None, "{value}");
        }
    }

    #[test]
    fn set_cookie_disables_caching_unless_ignored() {
        let conf = CacheConf {
            valid: vec![(vec![200], Duration::from_secs(60))],
            ..Default::default()
        };
        let headers = vec![("Set-Cookie".to_string(), "sid=1".to_string())];
        assert_eq!(freshness(&headers, 200, &conf, 1000), None);

        // `proxy_ignore_headers Set-Cookie` restores cacheability (`u->cacheable` stays 1).
        let conf = CacheConf {
            valid: vec![(vec![200], Duration::from_secs(60))],
            ignore_headers: vec!["Set-Cookie".to_string()],
            ..Default::default()
        };
        assert_eq!(freshness(&headers, 200, &conf, 1000), Some(1060));
    }

    #[test]
    fn proxy_cache_valid_supplies_the_ttl() {
        let conf = CacheConf {
            valid: vec![(vec![200], Duration::from_secs(30))],
            ..Default::default()
        };
        assert_eq!(freshness(&[], 200, &conf, 1000), Some(1030));
        assert_eq!(freshness(&[], 404, &conf, 1000), None);
    }

    #[test]
    fn http_dates_parse() {
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784111777));
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:01 GMT"), Some(1));
    }

    #[test]
    fn cache_path_parses_nginx_syntax() {
        let (zone, size) = parse_cache_path(&[
            "/var/cache/nginx".to_string(),
            "levels=1:2".to_string(),
            "keys_zone=NAME:10m".to_string(),
            "inactive=1h".to_string(),
            "max_size=1g".to_string(),
            "use_temp_path=off".to_string(),
        ])
        .unwrap();
        assert_eq!(zone.name, "NAME");
        assert_eq!(size, 10 * 1024 * 1024);
        assert_eq!(zone.levels, vec![1, 2]);
        assert_eq!(zone.inactive, Duration::from_secs(3600));
        assert_eq!(zone.max_size, 1024 * 1024 * 1024);
        assert!(!zone.use_temp_path);
    }

    #[test]
    fn cache_methods_always_include_get_and_head() {
        let conf = CacheConf::default();
        assert!(conf.caches_method("GET"));
        assert!(conf.caches_method("HEAD"));
        assert!(!conf.caches_method("POST"));
        let conf = CacheConf {
            methods: vec!["POST".into()],
            ..Default::default()
        };
        assert!(conf.caches_method("POST"));
    }

    #[test]
    fn cache_status_names_match_nginx() {
        assert_eq!(CacheStatus::Hit.as_str(), "HIT");
        assert_eq!(CacheStatus::Miss.as_str(), "MISS");
        assert_eq!(CacheStatus::Stale.as_str(), "STALE");
        assert_eq!(CacheStatus::Bypass.as_str(), "BYPASS");
        assert_eq!(CacheStatus::Expired.as_str(), "EXPIRED");
        assert_eq!(CacheStatus::Revalidated.as_str(), "REVALIDATED");
    }
}
