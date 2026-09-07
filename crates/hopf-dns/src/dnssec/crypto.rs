// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Cryptographic signature verification via [`hopf_core::crypto`].

use hopf_core::crypto::{
    ecdsa_p256_sha256_verify, ecdsa_p384_sha384_verify, ed25519_verify, hash, rsa_verify_dnskey,
    HashAlgorithm,
};

use super::algorithm::DnssecAlgorithm;

/// Verify `signature` over `message` with DNSKEY public-key material.
pub fn verify_signature(
    algorithm: DnssecAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    match algorithm {
        DnssecAlgorithm::RsaSha256 => rsa_verify_dnskey(public_key, message, signature, false),
        DnssecAlgorithm::RsaSha512 => rsa_verify_dnskey(public_key, message, signature, true),
        DnssecAlgorithm::EcdsaP256Sha256 => ecdsa_p256_sha256_verify(public_key, message, signature),
        DnssecAlgorithm::EcdsaP384Sha384 => ecdsa_p384_sha384_verify(public_key, message, signature),
        DnssecAlgorithm::Ed25519 => ed25519_verify(public_key, message, signature),
        DnssecAlgorithm::Ed448 => verify_ed448(public_key, message, signature),
    }
}

/// DS digest over owner wire name + DNSKEY RDATA (RFC 4034 §5.1.4).
pub fn compute_ds_digest(owner_wire: &[u8], dnskey_rdata: &[u8], digest_type: u8) -> Option<Vec<u8>> {
    let alg = match digest_type {
        1 => HashAlgorithm::Sha1Legacy,
        2 => HashAlgorithm::Sha256,
        4 => HashAlgorithm::Sha384,
        _ => return None,
    };
    let mut data = Vec::with_capacity(owner_wire.len() + dnskey_rdata.len());
    data.extend_from_slice(owner_wire);
    data.extend_from_slice(dnskey_rdata);
    Some(hash(alg, &data).into_bytes().to_vec())
}

/// RFC 5155 §5 iterated NSEC3 hash: `H^(iterations+1)(owner || salt)`,
/// where `H` is SHA-1 — the only NSEC3 hash algorithm defined to date
/// (value 1) — and `owner` must already be the fully-canonical
/// (lowercased) wire-encoded name.
pub fn nsec3_hash(owner_wire: &[u8], iterations: u16, salt: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(owner_wire.len() + salt.len());
    buf.extend_from_slice(owner_wire);
    buf.extend_from_slice(salt);
    let mut h = hash(HashAlgorithm::Sha1Legacy, &buf).into_bytes().to_vec();
    for _ in 0..iterations {
        let mut buf = Vec::with_capacity(h.len() + salt.len());
        buf.extend_from_slice(&h);
        buf.extend_from_slice(salt);
        h = hash(HashAlgorithm::Sha1Legacy, &buf).into_bytes().to_vec();
    }
    h
}

#[cfg(feature = "dnssec")]
fn verify_ed448(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    hopf_core::crypto::ed448::verify(public_key, message, signature)
}

#[cfg(not(feature = "dnssec"))]
fn verify_ed448(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::crypto::{ed25519_sign, Ed25519PrivateKey};

    #[test]
    fn ed25519_roundtrip() {
        let doc = Ed25519PrivateKey::generate_pkcs8().unwrap();
        let pair = Ed25519PrivateKey::from_pkcs8(&doc).unwrap();
        let msg = b"dnssec-test-message";
        let sig = ed25519_sign(&pair, msg);
        assert!(verify_signature(
            DnssecAlgorithm::Ed25519,
            pair.public_key_bytes(),
            msg,
            &sig
        ));
        assert!(!verify_signature(
            DnssecAlgorithm::Ed25519,
            pair.public_key_bytes(),
            b"tampered",
            &sig
        ));
    }

    /// RFC 5155 Appendix A's worked example zone: `example.` with
    /// `NSEC3PARAM 1 0 12 aabbccdd` hashes the apex itself
    /// (`example.`) to owner name `0p9mhaveqvm6t7vbl5lop2u3t2rp3tom`.
    #[test]
    fn nsec3_hash_matches_rfc5155_appendix_a_vector() {
        let owner_wire = crate::wire::encode_name(&crate::wire::normalize_name("example.")).unwrap();
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        let hash = nsec3_hash(&owner_wire, 12, &salt);
        let expected = crate::wire::base32hex::decode("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom").unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn nsec3_hash_is_deterministic_and_iteration_sensitive() {
        let owner_wire = crate::wire::encode_name("www.example.com").unwrap();
        let salt = [1u8, 2, 3];
        let h0a = nsec3_hash(&owner_wire, 0, &salt);
        let h0b = nsec3_hash(&owner_wire, 0, &salt);
        assert_eq!(h0a, h0b, "must be deterministic");
        assert_eq!(h0a.len(), 20, "SHA-1 output is 20 bytes");
        let h1 = nsec3_hash(&owner_wire, 1, &salt);
        assert_ne!(h0a, h1, "different iteration counts must (overwhelmingly) differ");
        let mut buf = h0a.clone();
        buf.extend_from_slice(&salt);
        let expected = hash(HashAlgorithm::Sha1Legacy, &buf).into_bytes().to_vec();
        assert_eq!(h1, expected);
    }
}
