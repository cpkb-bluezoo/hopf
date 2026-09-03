// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! CONNECT-IP relay target authorization.

use crate::ip_target::{IpProto, IpTarget};

/// Approves or denies a CONNECT-IP relay request, before any tunnel is
/// established.
///
/// Deliberately separate from [`crate::ConnectUdpPolicy`]: CONNECT-UDP's
/// target is always a concrete, DNS-resolved `(host, port)` pair, but
/// CONNECT-IP's `target`/`ipproto` are each optionally wildcarded and
/// `target` is never resolved by this crate at all (RFC 9484 leaves what a
/// hostname/prefix target even means to the forwarding implementation) —
/// sharing one trait would mean one side or the other ignoring fields it
/// doesn't need.
///
/// There is deliberately no permissive default — an open IP relay is not
/// something an application should get by omission.
pub trait ConnectIpPolicy: Send + Sync {
    /// Whether a tunnel scoped to `target`/`ipproto` is allowed.
    fn is_target_allowed(&self, target: &IpTarget, ipproto: &IpProto) -> bool;
}
