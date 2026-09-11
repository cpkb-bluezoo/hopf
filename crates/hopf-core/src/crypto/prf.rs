// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.2 PRF (RFC 5246 §5) — HMAC-based; unrelated to TLS 1.3's HKDF
//! key schedule in [`super::hkdf`]. Used only by the TLS 1.2 handshake
//! engine (master secret, key block, `Finished` `verify_data`).

use aws_lc_rs::hmac::{self, Key, HMAC_SHA256, HMAC_SHA384};

/// Which hash a TLS 1.2 cipher suite's PRF (and `Finished` transcript hash)
/// uses — SHA-256 for every suite in this workspace except the `_SHA384`
/// GCM suites (RFC 5289 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfHash {
    /// HMAC-SHA-256 — the RFC 5246 default PRF, and every `_SHA256`/CBC suite.
    Sha256,
    /// HMAC-SHA-384 — RFC 5289's `*_GCM_SHA384` suites.
    Sha384,
}

impl PrfHash {
    fn algorithm(self) -> hmac::Algorithm {
        match self {
            PrfHash::Sha256 => HMAC_SHA256,
            PrfHash::Sha384 => HMAC_SHA384,
        }
    }

    /// Output size of the underlying hash — also the length of the
    /// handshake-transcript hash fed into `Finished`'s PRF seed.
    pub fn hash_len(self) -> usize {
        match self {
            PrfHash::Sha256 => 32,
            PrfHash::Sha384 => 48,
        }
    }
}

/// `P_hash(secret, seed)`, expanded to `len` bytes (RFC 5246 §5).
fn p_hash(hash: PrfHash, secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let key = Key::new(hash.algorithm(), secret);
    let mut out = Vec::with_capacity(len + hash.hash_len());
    let mut a = hmac::sign(&key, seed); // A(1) = HMAC_hash(secret, seed)
    while out.len() < len {
        let mut input = Vec::with_capacity(a.as_ref().len() + seed.len());
        input.extend_from_slice(a.as_ref());
        input.extend_from_slice(seed);
        out.extend_from_slice(hmac::sign(&key, &input).as_ref());
        a = hmac::sign(&key, a.as_ref()); // A(i+1) = HMAC_hash(secret, A(i))
    }
    out.truncate(len);
    out
}

/// `PRF(secret, label, seed)` (RFC 5246 §5), expanded to `len` bytes.
/// `label` is the ASCII label bytes (e.g. `b"master secret"`).
pub fn prf(hash: PrfHash, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut full_seed = Vec::with_capacity(label.len() + seed.len());
    full_seed.extend_from_slice(label);
    full_seed.extend_from_slice(seed);
    p_hash(hash, secret, &full_seed, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_output_has_requested_length() {
        let out = prf(PrfHash::Sha256, b"secret", b"label", b"seed", 100);
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn prf_is_deterministic() {
        let a = prf(PrfHash::Sha256, b"secret", b"label", b"seed", 48);
        let b = prf(PrfHash::Sha256, b"secret", b"label", b"seed", 48);
        assert_eq!(a, b);
    }

    #[test]
    fn different_labels_produce_different_output() {
        let a = prf(PrfHash::Sha256, b"secret", b"master secret", b"seed", 48);
        let b = prf(PrfHash::Sha256, b"secret", b"key expansion", b"seed", 48);
        assert_ne!(a, b);
    }

    #[test]
    fn longer_expansion_is_a_prefix_extension() {
        // P_hash iterates A(i) and only truncates at the very end, so a
        // longer request must reproduce the same leading bytes as a
        // shorter one — a cheap structural check independent of any
        // external test vector.
        let short = prf(PrfHash::Sha256, b"secret", b"label", b"seed", 32);
        let long = prf(PrfHash::Sha256, b"secret", b"label", b"seed", 96);
        assert_eq!(&long[..32], short.as_slice());
    }

    #[test]
    fn sha384_variant_differs_from_sha256() {
        let a = prf(PrfHash::Sha256, b"secret", b"label", b"seed", 48);
        let b = prf(PrfHash::Sha384, b"secret", b"label", b"seed", 48);
        assert_ne!(a, b);
    }
}
