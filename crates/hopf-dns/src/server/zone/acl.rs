// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Source-address access control for zone operations.

use std::net::IpAddr;
use std::str::FromStr;

/// A network in CIDR notation, or a single host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Whether `ip` is inside this network. IPv4-mapped IPv6 addresses are
    /// compared as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, unmap(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                mask_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                mask_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn mask_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    rem == 0 || (a[full] ^ b[full]) >> (8 - rem) == 0
}

impl FromStr for Cidr {
    type Err = String;

    /// `192.0.2.0/24`, `2001:db8::/32`, or a bare address (a /32 or /128).
    fn from_str(s: &str) -> Result<Self, String> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| format!("bad address in {s:?}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().ok().filter(|&p| p <= max).ok_or_else(|| format!("bad prefix in {s:?}"))?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }
}

/// Who may perform a zone operation (transfer, update).
///
/// The default is [`Acl::none`]: nothing is allowed until configured, so a
/// freshly loaded zone cannot be dumped or rewritten by anyone who can reach
/// the port.
#[derive(Debug, Clone, Default)]
pub struct Acl {
    any: bool,
    nets: Vec<Cidr>,
    tsig_keys: Vec<String>,
}

impl Acl {
    /// Allow nobody.
    pub fn none() -> Self {
        Self::default()
    }

    /// Allow every source. Only sensible when a TSIG key is required, or on
    /// a closed network.
    pub fn any() -> Self {
        Self {
            any: true,
            ..Self::default()
        }
    }

    /// Allow the listed networks, e.g. `["192.0.2.0/24", "2001:db8::1"]`.
    pub fn from_cidrs<'a>(cidrs: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        Ok(Self {
            nets: cidrs.into_iter().map(str::parse).collect::<Result<_, _>>()?,
            ..Self::default()
        })
    }

    /// Allow requests authenticated with the TSIG key `name` (RFC 8945),
    /// from any source address. Combine with networks by chaining
    /// [`Acl::from_cidrs`] first: the request is allowed if *either* matches.
    pub fn or_tsig_key(mut self, name: &str) -> Self {
        self.tsig_keys.push(crate::wire::normalize_name(name));
        self
    }

    /// Allow only requests signed with the TSIG key `name`.
    pub fn tsig_key(name: &str) -> Self {
        Self::none().or_tsig_key(name)
    }

    /// Whether a request from `ip`, authenticated (if at all) with TSIG key
    /// `tsig_key`, is permitted.
    pub fn allows(&self, ip: IpAddr, tsig_key: Option<&str>) -> bool {
        self.any
            || self.nets.iter().any(|n| n.contains(ip))
            || tsig_key.is_some_and(|k| self.tsig_keys.iter().any(|a| a == k))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_matching() {
        let acl = Acl::from_cidrs(["192.0.2.0/24", "2001:db8::/32", "10.1.2.3"]).unwrap();
        assert!(acl.allows(ip("192.0.2.200"), None));
        assert!(!acl.allows(ip("192.0.3.1"), None));
        assert!(acl.allows(ip("2001:db8:ffff::1"), None));
        assert!(!acl.allows(ip("2001:db9::1"), None));
        assert!(acl.allows(ip("10.1.2.3"), None));
        assert!(!acl.allows(ip("10.1.2.4"), None));
        assert!(acl.allows(ip("::ffff:192.0.2.9"), None), "IPv4-mapped source");
        assert!(Acl::from_cidrs(["300.0.0.1"]).is_err());
        assert!(Acl::from_cidrs(["10.0.0.0/33"]).is_err());
    }

    #[test]
    fn default_allows_nobody_and_any_allows_everybody() {
        assert!(!Acl::none().allows(ip("127.0.0.1"), None));
        assert!(!Acl::default().allows(ip("::1"), None));
        assert!(Acl::any().allows(ip("203.0.113.9"), None));
    }

    #[test]
    fn tsig_keys_authorise_from_any_address_and_combine_with_networks() {
        let only_key = Acl::tsig_key("Transfer.Key.");
        assert!(!only_key.allows(ip("127.0.0.1"), None));
        assert!(!only_key.allows(ip("127.0.0.1"), Some("other")));
        assert!(only_key.allows(ip("203.0.113.9"), Some("transfer.key")));
        let both = Acl::from_cidrs(["10.0.0.0/8"]).unwrap().or_tsig_key("k");
        assert!(both.allows(ip("10.1.1.1"), None));
        assert!(both.allows(ip("198.51.100.1"), Some("k")));
        assert!(!both.allows(ip("198.51.100.1"), None));
    }

    #[test]
    fn non_byte_aligned_prefixes() {
        let acl = Acl::from_cidrs(["192.0.2.128/25"]).unwrap();
        assert!(acl.allows(ip("192.0.2.129"), None));
        assert!(!acl.allows(ip("192.0.2.1"), None));
    }
}
