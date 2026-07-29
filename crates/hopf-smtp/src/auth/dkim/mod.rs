// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DKIM — DomainKeys Identified Mail (RFC 6376, Ed25519 per RFC 8463).

pub mod canon;
mod rsa_der;
pub mod sign;
pub mod verify;

pub use canon::Canonicalization;
pub use sign::{DkimPrivateKey, DkimSigner};
pub use verify::{
    verify_all, verify_first, DkimAllCallback, DkimCallback, DkimResult, DkimSignatureResult,
};
