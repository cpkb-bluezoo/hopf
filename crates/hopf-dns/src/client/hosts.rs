// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! System hosts file parser.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::RwLock;

static ENTRIES: RwLock<Option<HashMap<String, Vec<IpAddr>>>> = RwLock::new(None);

/// Hosts file lookups (POSIX-style priority over DNS).
pub struct HostsFile;

impl HostsFile {
    /// Warm the process-wide cache. Called automatically by
    /// `DnsResolver::new` (issue #183) — exposed publicly too, for callers
    /// who want the first real lookup to be fast without constructing a
    /// resolver first, or who want to eagerly re-warm after `reload()`.
    pub fn warm() {
        let _ = Self::lookup("localhost");
    }

    /// Lookup hostname (case-insensitive).
    pub fn lookup(hostname: &str) -> Option<Vec<IpAddr>> {
        let key = hostname.to_ascii_lowercase();
        {
            let g = ENTRIES.read().unwrap();
            if let Some(map) = g.as_ref() {
                return map.get(&key).cloned();
            }
        }
        let map = load_hosts().unwrap_or_default();
        let result = map.get(&key).cloned();
        *ENTRIES.write().unwrap() = Some(map);
        result
    }

    /// Reload from disk.
    pub fn reload() {
        *ENTRIES.write().unwrap() = None;
    }
}

/// Parse a literal IP without DNS.
pub fn parse_literal_ip(s: &str) -> Option<IpAddr> {
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    if let Ok(v6) = s.parse::<Ipv6Addr>() {
        return Some(IpAddr::V6(v6));
    }
    None
}

fn hosts_path() -> &'static Path {
    #[cfg(windows)]
    {
        Path::new(r"C:\Windows\System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        Path::new("/etc/hosts")
    }
}

fn load_hosts() -> std::io::Result<HashMap<String, Vec<IpAddr>>> {
    let file = File::open(hosts_path())?;
    let reader = BufReader::new(file);
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(addr_s) = parts.next() else {
            continue;
        };
        let Some(ip) = parse_literal_ip(addr_s) else {
            continue;
        };
        for name in parts {
            map.entry(name.to_ascii_lowercase())
                .or_default()
                .push(ip);
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue #183: `DnsResolver::new` calls this so the first real
    /// `lookup()` (possibly made while holding the resolver's
    /// query-serializing mutex) never has to block on `/etc/hosts` itself
    /// — confirm it actually populates the cache, robust to whether
    /// `/etc/hosts` exists in the test environment (`load_hosts` falls
    /// back to an empty map on any read error).
    #[test]
    fn warm_populates_the_cache() {
        HostsFile::warm();
        assert!(ENTRIES.read().unwrap().is_some());
    }

    #[test]
    fn parse_literals() {
        assert_eq!(
            parse_literal_ip("127.0.0.1"),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            parse_literal_ip("::1"),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }
}
