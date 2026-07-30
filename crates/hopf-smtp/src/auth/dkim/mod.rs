// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DKIM — DomainKeys Identified Mail (RFC 6376, Ed25519 per RFC 8463).

pub mod canon;
mod rsa_der;
pub mod sign;
pub mod verify;

pub use canon::{Canonicalization, IncrementalBodyCanon};
pub use sign::{DkimPrivateKey, DkimSigner};
pub use verify::{
    required_body_hash_keys, verify_all, verify_all_with_body_hashes, verify_first, BodyHashMap,
    DkimAllCallback, DkimCallback, DkimResult, DkimSignatureResult,
};
