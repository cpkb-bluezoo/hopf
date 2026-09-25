// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-zone configuration.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use super::acl::Acl;
use crate::tsig::TsigKey;

/// Whether changes to a zone are written back to its zone file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneFileMode {
    /// The file is only read. Dynamic updates and transfers change the
    /// in-memory zone; a restart returns to the file's contents.
    ReadOnly,
    /// Every successful update (and, on a secondary, every completed
    /// transfer) is written back atomically. On a secondary this is the
    /// secondary's *own* file, never the primary's.
    ReadWrite,
}

/// A NOTIFY destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NotifyTarget {
    /// One address.
    Addr(SocketAddr),
    /// A name resolved afresh each time a NOTIFY is sent, so every address
    /// it currently has gets one.
    Host(String, u16),
}

/// Options for one served zone. The defaults are closed: nobody may
/// transfer or update the zone until [`allow_transfer`](Self::allow_transfer)
/// or [`allow_update`](Self::allow_update) says so.
#[derive(Debug, Clone)]
pub struct ZoneOptions {
    pub(super) allow_transfer: Acl,
    pub(super) allow_update: Acl,
    pub(super) also_notify: Vec<NotifyTarget>,
    pub(super) notify_ns_records: bool,
    pub(super) persist: Option<(PathBuf, ZoneFileMode)>,
    pub(super) tsig_key: Option<TsigKey>,
}

impl Default for ZoneOptions {
    fn default() -> Self {
        Self {
            allow_transfer: Acl::none(),
            allow_update: Acl::none(),
            also_notify: Vec::new(),
            notify_ns_records: true,
            persist: None,
            tsig_key: None,
        }
    }
}

impl ZoneOptions {
    /// Closed defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Who may AXFR/IXFR the zone.
    pub fn allow_transfer(mut self, acl: Acl) -> Self {
        self.allow_transfer = acl;
        self
    }

    /// Who may send RFC 2136 updates. Ignored on a secondary, which always
    /// refuses them.
    pub fn allow_update(mut self, acl: Acl) -> Self {
        self.allow_update = acl;
        self
    }

    /// Send a NOTIFY to `peer` whenever the zone changes (RFC 1996).
    pub fn also_notify(mut self, peer: SocketAddr) -> Self {
        self.also_notify.push(NotifyTarget::Addr(peer));
        self
    }

    /// Send a NOTIFY to *every* address `host` resolves to, looked up afresh
    /// on each change. Point this at a name that lists all replicas (a
    /// headless service, a multi-address record) rather than at one address
    /// behind a load balancer, which would deliver the NOTIFY to only one
    /// secondary. A secondary that misses a NOTIFY still catches up on its
    /// SOA REFRESH timer.
    pub fn also_notify_host(mut self, host: &str, port: u16) -> Self {
        self.also_notify.push(NotifyTarget::Host(host.to_string(), port));
        self
    }

    /// Also NOTIFY the in-zone name servers listed in the apex NS set that
    /// have address records here (port 53), other than the primary itself.
    /// On by default.
    pub fn notify_ns_records(mut self, enabled: bool) -> Self {
        self.notify_ns_records = enabled;
        self
    }

    /// TSIG key (RFC 8945) for this server's own requests about the zone: a
    /// secondary signs its SOA queries and transfer requests to the primary
    /// (and requires the answers to verify), and NOTIFYs sent after a change
    /// are signed. The primary must be configured with the same key.
    pub fn tsig_key(mut self, key: TsigKey) -> Self {
        self.tsig_key = Some(key);
        self
    }

    /// Zone file for this zone and whether changes are written back to it.
    /// A secondary loads it at start-up to serve while its primary is
    /// unreachable, and rewrites it after each transfer when read-write.
    pub fn persist(mut self, path: impl AsRef<Path>, mode: ZoneFileMode) -> Self {
        self.persist = Some((path.as_ref().to_path_buf(), mode));
        self
    }
}
