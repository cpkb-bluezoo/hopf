// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS stub resolver and caching forwarder for Hopf.
//!
//! # Modules
//!
//! - [`wire`] — RFC 1035 message / RR codecs
//! - [`client`] — reactor-affine [`client::DnsResolver`] (UDP/TCP; DoT/DoQ/DoH features)
//! - [`server`] — caching forwarder (`server` feature) + UDP/DoT/DoQ listeners
//! - [`dnssec`] — cryptographic validation (`dnssec` feature): RSASHA256/512,
//!   ECDSAP256/384, Ed25519; IANA root DS anchors
//!
//! Gumdrop parity: stub resolver + caching proxy — not an authoritative nameserver.

#![warn(missing_docs)]

pub mod bailiwick;
pub mod cache;
pub mod client;
pub mod cookie;
pub mod multi_qtype;
pub mod multi_qtype_cache;
pub mod system;
pub mod wire;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "dnssec")]
pub mod dnssec;

pub use bailiwick::{
    filter_answers_in_bailiwick, filter_authorities_in_bailiwick, is_within_bailiwick, names_equal,
};
pub use cache::DnsCache;
pub use client::{
    parse_literal_ip, BatchResultCallback, DnsResolver, HostsFile, QueryCallback, ResolveCallback,
    RuntimeDnsExt, DEFAULT_DNS_PORT, DEFAULT_TIMEOUT,
};
pub use cookie::DnsCookie;
pub use multi_qtype::{
    encode_mqtype_query_option, encode_mqtype_response_option, find_mqtype_option,
    EDNS_OPTION_MQTYPE_QUERY, EDNS_OPTION_MQTYPE_RESPONSE,
};
pub use multi_qtype_cache::MultiQTypeCache;
pub use wire::{
    DnsClass, DnsFormatError, DnsMessage, DnsQueryIdGenerator, DnsQuestion, DnsResourceRecord,
    DnsType,
};

pub use hopf_core::VERSION;
