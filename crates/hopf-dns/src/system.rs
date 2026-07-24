// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! System nameserver discovery (`/etc/resolv.conf`).

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};

use crate::client::DEFAULT_DNS_PORT;

/// Parse nameserver lines from `/etc/resolv.conf` (Unix).
pub fn system_nameservers() -> io::Result<Vec<SocketAddr>> {
    #[cfg(windows)]
    {
        // Fallback: public resolvers on Windows without WMI for now.
        Ok(vec![
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), DEFAULT_DNS_PORT),
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), DEFAULT_DNS_PORT),
        ])
    }
    #[cfg(not(windows))]
    {
        let file = match File::open("/etc/resolv.conf") {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(vec![SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                    DEFAULT_DNS_PORT,
                )]);
            }
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            let line = line.split('#').next().unwrap_or("").trim();
            let mut parts = line.split_whitespace();
            if parts.next() != Some("nameserver") {
                continue;
            }
            if let Some(ip_s) = parts.next() {
                if let Ok(ip) = ip_s.parse::<IpAddr>() {
                    out.push(SocketAddr::new(ip, DEFAULT_DNS_PORT));
                }
            }
        }
        if out.is_empty() {
            out.push(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                DEFAULT_DNS_PORT,
            ));
        }
        Ok(out)
    }
}
