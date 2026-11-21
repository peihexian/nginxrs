//! Network ranges and trusted-proxy address selection shared by the geo modules.
//!
//! Two pieces of `c/nginx/src` are reproduced here:
//!
//! | nginx | here |
//! |---|---|
//! | `ngx_ptocidr` (`ngx_inet.c`) | [`parse_cidr`] |
//! | `ngx_http_get_forwarded_addr` (`ngx_http_core_module.c`) | [`forwarded_addr`] |
//!
//! Both the `geo` module (`proxy`, `proxy_recursive`) and the `geoip` module
//! (`geoip_proxy`, `geoip_proxy_recursive`) use the forwarded-address walk, and its rules are
//! subtle enough to deserve one implementation: the header is walked from the *right* (the
//! nearest hop) towards the client, and every hop is only accepted while the address
//! currently held is a trusted proxy.

use std::net::IpAddr;

/// One parsed `address[/prefix]` network (`ngx_cidr_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    /// Network address with the low bits zeroed, as `ngx_ptocidr` stores it.
    pub network: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// A single address (`/32` or `/128`).
    pub fn host(address: IpAddr) -> Self {
        Self {
            network: address,
            prefix: if address.is_ipv4() { 32 } else { 128 },
        }
    }

    /// `ngx_ptocidr` + `ngx_cidr_match`: does `address` fall inside this network?
    ///
    /// An IPv4-mapped IPv6 address is compared against IPv4 networks, exactly like the C
    /// `ngx_cidr_match` (`IN6_IS_ADDR_V4MAPPED`).
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = mask32(self.prefix);
                (u32::from(network) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = mask128(self.prefix);
                (u128::from(network) & mask) == (u128::from(address) & mask)
            }
            (IpAddr::V4(network), IpAddr::V6(address)) => address.to_ipv4_mapped().is_some_and(
                |mapped| {
                    let mask = mask32(self.prefix);
                    (u32::from(network) & mask) == (u32::from(mapped) & mask)
                },
            ),
            (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

fn mask32(prefix: u8) -> u32 {
    u32::MAX.checked_shl(u32::from(32_u8.saturating_sub(prefix))).unwrap_or(0)
}

fn mask128(prefix: u8) -> u128 {
    u128::MAX
        .checked_shl(u32::from(128_u8.saturating_sub(prefix)))
        .unwrap_or(0)
}

/// The result of parsing one network, mirroring `ngx_ptocidr`'s return codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CidrParse {
    /// `NGX_OK`
    Ok(Cidr),
    /// `NGX_DONE`: parsed, but the low address bits were not zero and got cleared.
    MeaninglessBits(Cidr),
}

/// `ngx_ptocidr`: parse `address`, `address/prefix` or `address/mask`.
///
/// A `/` suffix that contains a dot is an IPv4 netmask (`192.0.2.0/255.255.255.0`); the mask
/// must cover the address range, as in `ngx_ptocidr`.
pub fn parse_cidr(value: &str) -> Result<CidrParse, String> {
    let (address, suffix) = match value.split_once('/') {
        Some((address, suffix)) => (address, Some(suffix)),
        None => (value, None),
    };
    // `sin_or_sin6` parsing is only needed for the socket form; the config form is plain.
    if address.contains(':') {
        return parse_cidr6(address, suffix);
    }
    let network: std::net::Ipv4Addr = address
        .parse()
        .map_err(|_| format!("invalid network \"{value}\""))?;
    let prefix = match suffix {
        None => 32,
        Some(suffix) if suffix.contains('.') => {
            let mask: std::net::Ipv4Addr = suffix
                .parse()
                .map_err(|_| format!("invalid network \"{value}\""))?;
            let bits = u32::from(mask);
            let ones = bits.count_ones();
            // A netmask must be a contiguous run of leading ones.
            if bits != mask32(ones as u8) {
                return Err(format!("invalid network \"{value}\""));
            }
            ones as u8
        }
        Some(suffix) => suffix
            .parse::<u8>()
            .ok()
            .filter(|prefix| *prefix <= 32)
            .ok_or_else(|| format!("invalid network \"{value}\""))?,
    };
    let bits = u32::from(network);
    let network = std::net::Ipv4Addr::from(bits & mask32(prefix));
    let cidr = Cidr {
        network: IpAddr::V4(network),
        prefix,
    };
    Ok(if bits & mask32(prefix) == bits {
        CidrParse::Ok(cidr)
    } else {
        CidrParse::MeaninglessBits(cidr)
    })
}

fn parse_cidr6(address: &str, suffix: Option<&str>) -> Result<CidrParse, String> {
    let address = address.trim_start_matches('[').trim_end_matches(']');
    let network: std::net::Ipv6Addr = address
        .parse()
        .map_err(|_| format!("invalid network \"{address}\""))?;
    let prefix = match suffix {
        None => 128,
        Some(suffix) if suffix.contains('.') => {
            // An IPv4 mask after an IPv6 literal is meaningless in nginx too.
            return Err(format!("invalid network \"{address}/{suffix}\""));
        }
        Some(suffix) => suffix
            .parse::<u8>()
            .ok()
            .filter(|prefix| *prefix <= 128)
            .ok_or_else(|| format!("invalid network \"{address}/{suffix}\""))?,
    };
    let bits = u128::from(network);
    let network = std::net::Ipv6Addr::from(bits & mask128(prefix));
    let cidr = Cidr {
        network: IpAddr::V6(network),
        prefix,
    };
    Ok(if bits & mask128(prefix) == bits {
        CidrParse::Ok(cidr)
    } else {
        CidrParse::MeaninglessBits(cidr)
    })
}

/// Whether `address` matches any network in `nets` (`ngx_cidr_match` over the list).
pub fn trusted(nets: &[Cidr], address: IpAddr) -> bool {
    nets.iter().any(|net| net.contains(address))
}

/// The address a geo lookup should classify, given the peer and the trusted proxies.
///
/// Panics are impossible here: the peer always exists for a live connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selected {
    pub address: IpAddr,
}

/// `ngx_http_get_forwarded_addr`: pick the client address from `X-Forwarded-For`.
///
/// The header value is walked from its *right-most* entry towards the left: while the address
/// currently held is one of `proxies`, the next entry to the left replaces it. With
/// `recursive` off the walk stops after the first replacement, so only the nearest hop is
/// trusted. Entries are never validated against their own trust; the walk simply ends when a
/// new hop is not required any more.
///
/// `xff` holds every `X-Forwarded-For` line in the order the client sent them; nginx walks
/// the lines last-to-first (`ngx_http_geo` passes the whole header), so later lines win.
pub fn forwarded_addr(
    peer: Option<IpAddr>,
    xff: &[String],
    proxies: &[Cidr],
    recursive: bool,
) -> Option<IpAddr> {
    let mut addr = peer?;
    if xff.is_empty() || proxies.is_empty() {
        return Some(addr);
    }
    for line in xff.iter().rev() {
        let Some((next, changed)) = walk_line(addr, line, proxies, recursive) else {
            break;
        };
        addr = next;
        if !changed {
            break;
        }
    }
    Some(addr)
}

/// One pass over one header line. Returns the resulting address and whether it was replaced.
fn walk_line(
    mut addr: IpAddr,
    line: &str,
    proxies: &[Cidr],
    recursive: bool,
) -> Option<(IpAddr, bool)> {
    let tokens: Vec<&str> = line
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    let mut replaced = false;
    // The C loop starts from the end of the header and moves left while the current address
    // is a trusted proxy; the first hop it cannot justify ends the walk.
    for token in tokens.iter().rev() {
        if !trusted(proxies, addr) {
            break;
        }
        let Some(parsed) = parse_entry(token) else {
            break;
        };
        addr = parsed;
        replaced = true;
        if !recursive {
            break;
        }
    }
    Some((addr, replaced))
}

/// `ngx_parse_addr`: a bare address, `host:port`, `[v6]`, or `[v6]:port`.
fn parse_entry(entry: &str) -> Option<IpAddr> {
    if let Ok(address) = entry.parse::<IpAddr>() {
        return Some(address);
    }
    let host = if let Some(rest) = entry.strip_prefix('[') {
        rest.split_once(']').map(|(host, _)| host)?
    } else if let Some((host, port)) = entry.rsplit_once(':') {
        port.parse::<u16>().ok().map(|_| host)?
    } else {
        return None;
    };
    host.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn cidr(value: &str) -> Cidr {
        match parse_cidr(value).unwrap() {
            CidrParse::Ok(cidr) | CidrParse::MeaninglessBits(cidr) => cidr,
        }
    }

    #[test]
    fn cidr_parsing_matches_ngx_ptocidr() {
        assert_eq!(
            cidr("192.0.2.0/24"),
            Cidr {
                network: ip("192.0.2.0"),
                prefix: 24
            }
        );
        assert_eq!(cidr("192.0.2.7").prefix, 32);
        // A dotted suffix is a netmask.
        assert_eq!(cidr("192.0.2.1/255.255.255.0").prefix, 24);
        // Low bits set: cleared, reported as NGX_DONE.
        assert_eq!(
            parse_cidr("192.0.2.7/24").unwrap(),
            CidrParse::MeaninglessBits(Cidr {
                network: ip("192.0.2.0"),
                prefix: 24
            })
        );
        assert!(parse_cidr("192.0.2.0/33").is_err());
        assert!(parse_cidr("192.0.2.0/255.0.255.0").is_err());
        assert!(parse_cidr("not-an-address").is_err());
        // IPv6 and the bracketed form.
        assert_eq!(cidr("::1").prefix, 128);
        assert_eq!(cidr("[2001:db8::]/32").network, ip("2001:db8::"));
    }

    #[test]
    fn cidr_matching_including_v4_mapped() {
        let v4 = cidr("10.0.0.0/8");
        assert!(v4.contains(ip("10.1.2.3")));
        assert!(!v4.contains(ip("11.0.0.0")));
        // `::ffff:10.1.2.3` matches the IPv4 network, as `ngx_cidr_match` does.
        assert!(v4.contains(ip("::ffff:10.1.2.3")));
        let v6 = cidr("2001:db8::/32");
        assert!(v6.contains(ip("2001:db8:1::1")));
        assert!(!v6.contains(ip("2001:db9::1")));
        assert!(!v6.contains(ip("10.1.2.3")));
    }

    fn xff(value: &str) -> Vec<String> {
        vec![value.to_string()]
    }

    #[test]
    fn forwarded_addr_without_proxies_keeps_the_peer() {
        assert_eq!(
            forwarded_addr(
                Some(ip("10.0.0.1")),
                &xff("203.0.113.9"),
                &[],
                false
            ),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn forwarded_addr_takes_the_nearest_hop_unless_recursive() {
        let proxies = [cidr("10.0.0.0/8")];
        // Peer 10.0.0.1 is trusted → the right-most entry becomes the address.
        assert_eq!(
            forwarded_addr(
                Some(ip("10.0.0.1")),
                &xff("203.0.113.9, 198.51.100.7"),
                &proxies,
                false
            ),
            Some(ip("198.51.100.7"))
        );
        // Recursive: 198.51.100.7 is not trusted, so the walk stops there as well.
        assert_eq!(
            forwarded_addr(
                Some(ip("10.0.0.1")),
                &xff("203.0.113.9, 198.51.100.7"),
                &proxies,
                true
            ),
            Some(ip("198.51.100.7"))
        );
        // With a trusted right-most hop the recursive walk continues to the left.
        assert_eq!(
            forwarded_addr(
                Some(ip("10.0.0.1")),
                &xff("203.0.113.9, 10.9.9.9"),
                &proxies,
                true
            ),
            Some(ip("203.0.113.9"))
        );
        // An untrusted peer ignores the header completely.
        assert_eq!(
            forwarded_addr(
                Some(ip("192.0.2.1")),
                &xff("203.0.113.9"),
                &proxies,
                true
            ),
            Some(ip("192.0.2.1"))
        );
    }

    #[test]
    fn forwarded_addr_handles_ports_and_several_lines() {
        let proxies = [cidr("10.0.0.0/8")];
        assert_eq!(
            forwarded_addr(
                Some(ip("10.0.0.1")),
                &xff("203.0.113.9:1234"),
                &proxies,
                false
            ),
            Some(ip("203.0.113.9"))
        );
        // The last header line is considered first.
        assert_eq!(
            forwarded_addr(
                Some(ip("10.0.0.1")),
                &["203.0.113.9".to_string(), "198.51.100.7".to_string()],
                &proxies,
                false
            ),
            Some(ip("198.51.100.7"))
        );
    }
}
