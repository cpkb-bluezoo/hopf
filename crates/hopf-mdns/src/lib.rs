// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Multicast DNS (RFC 6762) and DNS-SD (RFC 6763) for Hopf.
//!
//! Gumdrop-parity in spirit (reuses `hopf-dns`'s wire types exactly as
//! Gumdrop's `mdns` package reuses its own `dns` package's), but with a
//! push-based service API rather than Gumdrop's central-registry pull:
//! Gumdrop's `DNSSDAdvertiser` walks the whole server's own listener
//! registry (`Gumdrop.getInstance().getServices()`) to decide what to
//! advertise; Hopf has no such registry (every protocol is an independent
//! crate), so applications call [`MdnsService::register_service`]
//! explicitly instead.
//!
//! Entirely async/non-blocking, like the rest of Hopf: every timer
//! (probe/announce cadence, cache refresh, query timeout) is a one-shot
//! [`hopf_core::ReactorHandle::schedule_timer`] callback that re-arms
//! itself on firing (there is no repeating-timer primitive to lean on
//! instead), and every send goes through
//! [`hopf_core::ReactorHandle::udp_send`], which only enqueues — never
//! blocks the caller. The one inherently synchronous stretch is one-time
//! socket setup (bind/multicast join/`register_udp`'s bounded mpsc round
//! trip) — see [`socket::listen_mdns_udp`] — the same shape
//! `hopf-dns`'s own `listen_dns_udp` already uses for every UDP listener
//! in this workspace.
//!
//! IPv6 mDNS (`ff02::fb`) is out of scope for now, matching Gumdrop's own
//! stated limitation.

#![warn(missing_docs)]

pub mod bits;
pub mod cache;
pub mod dnssd;
pub mod responder;
pub mod socket;

pub use dnssd::{BrowseEvent, BrowseHandle, ServiceHandle, ServiceRegistration};
pub use responder::{MdnsService, Timing};
