// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNSSEC validation (feature `dnssec`) — validation only, no signing.
//!
//! Supported signature algorithms:
//! - RSASHA256 (8), RSASHA512 (10), ECDSAP256SHA256 (13),
//!   ECDSAP384SHA384 (14), Ed25519 (15) — via `aws-lc-rs`
//! - Ed448 (16) — via the pure-Rust `ed448-goldilocks-plus` (`aws-lc-rs` has no
//!   Ed448 support)

mod algorithm;
mod crypto;
mod denial;
mod status;
mod trust_anchor;
mod validator;

pub use algorithm::DnssecAlgorithm;
pub use crypto::{compute_ds_digest, nsec3_hash};
pub use denial::verify_denial;
pub use status::DnssecStatus;
pub use trust_anchor::{AnchorDs, DnssecTrustAnchor};
pub use validator::{
    find_matching_dnskey, find_rrsigs, is_rrsig_current, verify_ds, verify_rrsig, ChainStep,
    DnssecChainWalk, DnssecValidator,
};
