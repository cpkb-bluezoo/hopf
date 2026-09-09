// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AWS-LC crypto facade — synchronous primitives only.
//!
//! Protocol crates call this module instead of `aws-lc-rs` directly. Hopf does
//! **not** reimplement algorithms here; operations delegate to AWS-LC via
//! `aws-lc-rs` (or [`ed448`](ed448) for DNSSEC Ed448 where libcrypto has no
//! support).

#![warn(missing_docs)]

pub mod aead;
pub mod cert;
pub mod digest;
pub mod hkdf;
pub mod kx;
pub mod kx_policy;
pub mod prf;
pub mod rand;
pub mod signature;
pub mod trust;
pub mod x509;

#[cfg(feature = "ed448")]
pub mod ed448;

pub use aead::{AeadError, Aes128GcmKey, AesGcmKey, ChaCha20Poly1305Key};
pub use cert::{sha256_fingerprint_hex, spki_sha256};
pub use digest::{hash, Digest, HashAlgorithm, Sha256Context};
pub use hkdf::{empty_hash, expand_label, extract, extract_derived, quic_expand_label, HkdfPrk, TLS13_HKDF};
pub use kx::{
    server_agree, EphemeralKeyPair, EphemeralP256KeyPair, HybridKeyPair, LocalKeyShare, NamedGroup,
    StaticKeyPair, MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAP_LEN, X25519_PUBLIC_LEN,
};
pub use kx_policy::KxPolicy;
pub use prf::{prf, PrfHash};
pub use rand::SystemRandom;
pub use signature::{
    ecdsa_p256_sha256_verify, ecdsa_p256_sha256_verify_spki, ecdsa_p256_sign,
    ecdsa_p384_sha384_verify, ecdsa_p384_sha384_verify_spki, ecdsa_p384_sign, ed25519_sign,
    ed25519_verify, rsa_dnskey_to_spki_der, rsa_pss_sha256_verify_spki, rsa_sign_pkcs1_sha256,
    rsa_sign_pss_sha256, rsa_verify_dnskey, rsa_verify_pkcs1_sha256, rsa_verify_pkcs1_sha512,
    EcdsaP256PrivateKey, EcdsaP384PrivateKey, Ed25519PrivateKey, Ed25519PublicKey, KeyError,
    RsaPrivateKey, RsaPublicKeyComponents, SignError,
};
pub use trust::{
    public_trust_store, public_trust_store_from, verify_server_chain, ComponentAnchor, TrustStore,
    VerifyError,
};
