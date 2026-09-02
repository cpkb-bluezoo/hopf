// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! CONNECT-UDP relay target authorization.

use std::net::IpAddr;

/// Approves or denies a CONNECT-UDP relay target.
///
/// There is deliberately no permissive default — an open UDP relay is not
/// something an application should get by omission. Implement this to
/// state explicitly which targets you're willing to relay UDP traffic to.
///
/// Checked against the *resolved* address, not the original hostname —
/// implement DNS-rebinding-style protections here if you need them (e.g.
/// rejecting private/loopback ranges for a public-facing relay).
pub trait ConnectUdpPolicy: Send + Sync {
    /// Whether relaying to `(addr, port)` is allowed.
    fn is_target_allowed(&self, addr: IpAddr, port: u16) -> bool;
}
