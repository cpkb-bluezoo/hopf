// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AWS-LC crypto facade — synchronous primitives only.
//!
//! Protocol crates call this module instead of `aws-lc-rs` directly. Hopf does
//! **not** reimplement algorithms here; operations delegate to AWS-LC via
//! `aws-lc-rs` (or [`ed448`](ed448) for DNSSEC Ed448 where libcrypto has no
//! support).

#![warn(missing_docs)]

pub mod cert;
pub mod digest;
pub mod rand;
pub mod signature;
pub mod trust;

#[cfg(feature = "ed448")]
pub mod ed448;

pub use cert::{sha256_fingerprint_hex, spki_sha256};
pub use digest::{hash, Digest, HashAlgorithm, Sha256Context};
pub use rand::SystemRandom;
pub use signature::{
    ecdsa_p256_sha256_verify, ecdsa_p384_sha384_verify, ed25519_sign, ed25519_verify,
    rsa_dnskey_to_spki_der, rsa_sign_pkcs1_sha256, rsa_verify_dnskey, rsa_verify_pkcs1_sha256,
    rsa_verify_pkcs1_sha512, Ed25519PrivateKey, Ed25519PublicKey, KeyError, RsaPrivateKey,
    RsaPublicKeyComponents, SignError,
};
pub use trust::TrustStore;
