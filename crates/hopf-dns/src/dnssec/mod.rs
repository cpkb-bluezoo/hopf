// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNSSEC validation (feature `dnssec`) — validation only, no signing.
//!
//! Supported signature algorithms (via `ring`):
//! - RSASHA256 (8), RSASHA512 (10)
//! - ECDSAP256SHA256 (13), ECDSAP384SHA384 (14)
//! - Ed25519 (15)
//!
//! Ed448 (16) is recognized but not verified (`ring` has no Ed448).

mod algorithm;
mod crypto;
mod status;
mod trust_anchor;
mod validator;

pub use algorithm::DnssecAlgorithm;
pub use status::DnssecStatus;
pub use trust_anchor::{AnchorDs, DnssecTrustAnchor};
pub use validator::{
    find_matching_dnskey, find_rrsigs, is_rrsig_current, verify_ds, verify_rrsig,
    DnssecChainValidator, DnssecValidator,
};
