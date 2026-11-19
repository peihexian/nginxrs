//! Shared value parsers used by every module's directive parser.

use crate::core::syntax::Directive;
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn parse_on_off(node: &Directive, value: &str) -> Result<bool> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(node.error("expected \"on\" or \"off\"")),
    }
}

/// Parse a time following Nginx rules (default unit seconds, `ms`, `s`, `m`, `h`,
/// `d`, `w`, `M`, `y`).
pub fn parse_time(node: &Directive, value: &str) -> Result<Duration> {
    scan_compound(node, value, time_multiplier, "time").map(Duration::from_millis)
}

/// Parse a size following Nginx rules: `k`/`K`, `m`/`M`, `g`/`G`.
pub fn parse_size(node: &Directive, value: &str) -> Result<u64> {
    scan_compound(node, value, size_multiplier, "size")
}

fn time_multiplier(unit: &str) -> Option<u64> {
    match unit {
        "" | "s" => Some(1000),
        "ms" => Some(1),
        "m" => Some(60 * 1000),
        "h" => Some(60 * 60 * 1000),
        "d" => Some(24 * 60 * 60 * 1000),
        "w" => Some(7 * 24 * 60 * 60 * 1000),
        "M" => Some(30 * 24 * 60 * 60 * 1000),
        "y" => Some(365 * 24 * 60 * 60 * 1000),
        _ => None,
    }
}

fn size_multiplier(unit: &str) -> Option<u64> {
    match unit {
        "" => Some(1),
        "k" | "K" => Some(1024),
        "m" | "M" => Some(1024 * 1024),
        "g" | "G" => Some(1024 * 1024 * 1024),
        _ => None,
    }
}

fn scan_compound(
    node: &Directive,
    value: &str,
    multiplier: fn(&str) -> Option<u64>,
    what: &str,
) -> Result<u64> {
    if value.is_empty() {
        return Err(node.error(format!("invalid {what} \"{value}\"")));
    }
    let mut total = 0_u64;
    let mut rest = value;
    while !rest.is_empty() {
        let digits = rest
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits == 0 {
            return Err(node.error(format!("invalid {what} \"{value}\"")));
        }
        let (number, tail) = rest.split_at(digits);
        let unit_len = tail
            .find(|ch: char| ch.is_ascii_digit())
            .unwrap_or(tail.len());
        let (unit, next) = tail.split_at(unit_len);
        let number: u64 = number
            .parse()
            .map_err(|_| node.error(format!("invalid {what} \"{value}\"")))?;
        let factor = multiplier(unit)
            .ok_or_else(|| node.error(format!("invalid {what} unit \"{unit}\"")))?;
        total = number
            .checked_mul(factor)
            .and_then(|part| total.checked_add(part))
            .ok_or_else(|| node.error(format!("{what} \"{value}\" is too large")))?;
        rest = next;
    }
    Ok(total)
}

pub fn parse_u64(node: &Directive, value: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| node.error(format!("invalid number \"{value}\"")))
}

pub fn parse_usize(node: &Directive, value: &str) -> Result<usize> {
    value
        .parse()
        .map_err(|_| node.error(format!("invalid number \"{value}\"")))
}

pub fn parse_status(node: &Directive, value: &str) -> Result<u16> {
    let status: u16 = value
        .parse()
        .map_err(|_| node.error("invalid HTTP status"))?;
    if (100..=599).contains(&status) {
        Ok(status)
    } else {
        Err(node.error("invalid HTTP status"))
    }
}

/// Parse `address[:port]` for a `listen` directive and require a numeric address.
pub fn parse_listen_address(node: &Directive, value: &str) -> Result<String> {
    let address = normalize_address(value, 80);
    address.parse::<SocketAddr>().map_err(|_| {
        node.error(format!(
            "listen currently requires a numeric IP address, got {address}"
        ))
    })?;
    Ok(address)
}

/// Parse an upstream `host:port` and require a numeric address.
pub fn parse_upstream_address(node: &Directive, value: &str) -> Result<String> {
    let address = normalize_address(value, 80);
    address.parse::<SocketAddr>().map_err(|_| {
        node.error("upstream server currently requires a numeric IP address and port")
    })?;
    Ok(address)
}

pub fn parse_ip(node: &Directive, value: &str) -> Result<IpAddr> {
    value
        .parse()
        .map_err(|_| node.error(format!("invalid IP address \"{value}\"")))
}

pub fn resolve_path(base_dir: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn normalize_address(value: &str, default_port: u16) -> String {
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        format!("0.0.0.0:{value}")
    } else if let Some(port) = value.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else if !value.starts_with('[') && value.matches(':').count() > 1 {
        format!("[{value}]:{default_port}")
    } else if value.starts_with('[') && !value.contains("]:") {
        format!("{value}:{default_port}")
    } else if value.contains(':') {
        value.to_string()
    } else {
        format!("{value}:{default_port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::syntax::parse_str;

    fn node() -> Directive {
        parse_str("x 1;").unwrap().remove(0)
    }

    #[test]
    fn duration_units_follow_nginx() {
        assert_eq!(parse_time(&node(), "2s").unwrap(), Duration::from_secs(2));
        assert_eq!(
            parse_time(&node(), "1m30s").unwrap(),
            Duration::from_secs(90)
        );
        assert_eq!(
            parse_time(&node(), "1h").unwrap(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            parse_time(&node(), "500ms").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(parse_time(&node(), "10").unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn size_units_and_sums() {
        assert_eq!(parse_size(&node(), "10k").unwrap(), 10 * 1024);
        assert_eq!(parse_size(&node(), "2M").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size(&node(), "1k512").unwrap(), 1536);
    }

    #[test]
    fn rejects_bad_values() {
        assert!(parse_time(&node(), "abc").is_err());
        assert!(parse_size(&node(), "10x").is_err());
    }

    #[test]
    fn listen_address_normalization() {
        assert_eq!(
            parse_listen_address(&node(), "8080").unwrap(),
            "0.0.0.0:8080"
        );
        assert_eq!(
            parse_listen_address(&node(), "127.0.0.1:9000").unwrap(),
            "127.0.0.1:9000"
        );
        assert_eq!(parse_listen_address(&node(), "[::1]").unwrap(), "[::1]:80");
    }
}
