// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Relay target authorization.

use std::net::IpAddr;

/// Approves or denies a SOCKS relay target.
///
/// There is deliberately no permissive default — an open SOCKS proxy is
/// not something an application should get by omission. Implement this to
/// state explicitly which targets you're willing to relay to.
///
/// Checked against every *resolved* address when the request named a
/// hostname, not just the first one: if any resolved address is denied,
/// the whole request is rejected, rather than silently connecting to
/// whichever resolved address happens to be allowed. Checking only one
/// address (or only the first) would let a multi-answer DNS response bypass
/// the destination filter simply by placing an allowed address first.
pub trait SocksPolicy: Send + Sync {
    /// Whether relaying to `(addr, port)` is allowed.
    fn is_target_allowed(&self, addr: IpAddr, port: u16) -> bool;
}
