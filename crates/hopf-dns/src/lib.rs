// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS stub resolver and DNS server for Hopf.
//!
//! # Modules
//!
//! - [`wire`] — RFC 1035 message / RR codecs
//! - [`client`] — reactor-affine [`client::DnsResolver`] (UDP/TCP; DoT/DoQ/DoH features)
//! - [`server`] — DNS server shell with pluggable handlers (`server` feature):
//!   caching forwarder, authoritative zones (zone files, NOTIFY, UPDATE,
//!   AXFR/IXFR, secondaries) and UDP/TCP/DoT/DoQ listeners
//! - [`tsig`] — RFC 8945 transaction signatures for zone transfers and updates
//! - [`dnssec`] — cryptographic validation (`dnssec` feature): RSASHA256/512,
//!   ECDSAP256/384, Ed25519; IANA root DS anchors
//!

#![warn(missing_docs)]

pub mod bailiwick;
pub mod cache;
pub mod client;
pub mod cookie;
pub mod ech;
pub mod multi_qtype;
pub mod multi_qtype_cache;
pub mod system;
pub mod wire;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "server")]
pub mod tsig;

#[cfg(feature = "dnssec")]
pub mod dnssec;

#[cfg(feature = "dane")]
pub mod dane;

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
    DnsType, TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage,
};

pub use hopf_core::VERSION;
