// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Cryptographic signature verification via `aws-lc-rs`.

use aws_lc_rs::digest;
use aws_lc_rs::signature::{self, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512};

use super::algorithm::DnssecAlgorithm;

/// Verify `signature` over `message` with DNSKEY public-key material.
pub fn verify_signature(
    algorithm: DnssecAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    match algorithm {
        DnssecAlgorithm::RsaSha256 => verify_rsa(public_key, message, signature, &RSA_PKCS1_2048_8192_SHA256),
        DnssecAlgorithm::RsaSha512 => verify_rsa(public_key, message, signature, &RSA_PKCS1_2048_8192_SHA512),
        DnssecAlgorithm::EcdsaP256Sha256 => verify_ecdsa_p256(public_key, message, signature),
        DnssecAlgorithm::EcdsaP384Sha384 => verify_ecdsa_p384(public_key, message, signature),
        DnssecAlgorithm::Ed25519 => verify_ed25519(public_key, message, signature),
        DnssecAlgorithm::Ed448 => verify_ed448(public_key, message, signature),
    }
}

/// DS digest over owner wire name + DNSKEY RDATA (RFC 4034 §5.1.4).
pub fn compute_ds_digest(owner_wire: &[u8], dnskey_rdata: &[u8], digest_type: u8) -> Option<Vec<u8>> {
    let alg = match digest_type {
        1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        2 => &digest::SHA256,
        4 => &digest::SHA384,
        _ => return None,
    };
    let mut ctx = digest::Context::new(alg);
    ctx.update(owner_wire);
    ctx.update(dnskey_rdata);
    Some(ctx.finish().as_ref().to_vec())
}

/// RFC 5155 §5 iterated NSEC3 hash: `H^(iterations+1)(owner || salt)`,
/// where `H` is SHA-1 — the only NSEC3 hash algorithm defined to date
/// (value 1) — and `owner` must already be the fully-canonical
/// (lowercased) wire-encoded name.
pub fn nsec3_hash(owner_wire: &[u8], iterations: u16, salt: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(owner_wire.len() + salt.len());
    buf.extend_from_slice(owner_wire);
    buf.extend_from_slice(salt);
    let mut h = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &buf).as_ref().to_vec();
    for _ in 0..iterations {
        let mut buf = Vec::with_capacity(h.len() + salt.len());
        buf.extend_from_slice(&h);
        buf.extend_from_slice(salt);
        h = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &buf).as_ref().to_vec();
    }
    h
}

fn verify_rsa(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    params: &'static dyn signature::VerificationAlgorithm,
) -> bool {
    let Some(der) = rsa_dnskey_to_der(public_key) else {
        return false;
    };
    UnparsedPublicKey::new(params, &der)
        .verify(message, signature)
        .is_ok()
}

fn verify_ecdsa_p256(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // RFC 6605: key is x||y (32+32); signature is r||s (32+32).
    if public_key.len() != 64 || signature.len() != 64 {
        return false;
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(public_key);
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &sec1)
        .verify(message, signature)
        .is_ok()
}

fn verify_ecdsa_p384(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 96 || signature.len() != 96 {
        return false;
    }
    let mut sec1 = Vec::with_capacity(97);
    sec1.push(0x04);
    sec1.extend_from_slice(public_key);
    UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &sec1)
        .verify(message, signature)
        .is_ok()
}

fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

/// `aws-lc-rs` has no Ed448 support, so this uses the pure-Rust
/// `ed448-goldilocks-plus` crate instead (its own RFC 8032 test vectors
/// pass). RFC 8080 §4 uses plain Ed448 (not Ed448ph, no context string),
/// matching `verify_raw` here.
fn verify_ed448(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key_bytes) = <[u8; 57]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 114]>::try_from(signature) else {
        return false;
    };
    let Ok(key) = ed448_goldilocks_plus::VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(sig) = ed448_goldilocks_plus::Signature::from_bytes(&sig_bytes) else {
        return false;
    };
    key.verify_raw(&sig, message).is_ok()
}

/// RFC 3110 RSA key → DER `RSAPublicKey` (PKCS#1).
fn rsa_dnskey_to_der(public_key: &[u8]) -> Option<Vec<u8>> {
    if public_key.is_empty() {
        return None;
    }
    let (exp_len, exp_start) = if public_key[0] == 0 {
        if public_key.len() < 3 {
            return None;
        }
        let len = u16::from_be_bytes([public_key[1], public_key[2]]) as usize;
        (len, 3usize)
    } else {
        (public_key[0] as usize, 1usize)
    };
    if public_key.len() < exp_start + exp_len {
        return None;
    }
    let exponent = &public_key[exp_start..exp_start + exp_len];
    let modulus = &public_key[exp_start + exp_len..];
    if modulus.is_empty() || exponent.is_empty() {
        return None;
    }
    let mod_der = asn1_integer(modulus);
    let exp_der = asn1_integer(exponent);
    let content_len = mod_der.len() + exp_der.len();
    let mut der = Vec::with_capacity(4 + content_len);
    der.push(0x30);
    der.extend(asn1_length(content_len));
    der.extend_from_slice(&mod_der);
    der.extend_from_slice(&exp_der);
    Some(der)
}

fn asn1_integer(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros but keep one if value would otherwise look negative.
    let mut i = 0;
    while i + 1 < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    let body = &bytes[i..];
    let needs_pad = !body.is_empty() && body[0] & 0x80 != 0;
    let mut out = Vec::with_capacity(2 + body.len() + usize::from(needs_pad));
    out.push(0x02);
    let len = body.len() + usize::from(needs_pad);
    out.extend(asn1_length(len));
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(body);
    out
}

fn asn1_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn ed25519_roundtrip() {
        let doc = Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let msg = b"dnssec-test-message";
        let sig = pair.sign(msg);
        assert!(verify_ed25519(pair.public_key().as_ref(), msg, sig.as_ref()));
        assert!(!verify_ed25519(pair.public_key().as_ref(), b"tampered", sig.as_ref()));
    }

    fn test_signing_key(seed_byte: u8) -> ed448_goldilocks_plus::SigningKey {
        let secret = ed448_goldilocks_plus::SecretKey::from([seed_byte; 57]);
        ed448_goldilocks_plus::SigningKey::from_bytes(&secret)
    }

    #[test]
    fn ed448_roundtrip() {
        use ed448_goldilocks_plus::crypto_signature::Signer;
        let private = test_signing_key(0x11);
        let public = private.verifying_key();
        let msg = b"dnssec-test-message";
        let sig: ed448_goldilocks_plus::Signature = private.sign(msg);
        assert!(verify_signature(DnssecAlgorithm::Ed448, public.as_bytes(), msg, &sig.to_bytes()));
        assert!(!verify_signature(DnssecAlgorithm::Ed448, public.as_bytes(), b"tampered", &sig.to_bytes()));
    }

    #[test]
    fn ed448_rejects_wrong_length_key_or_signature() {
        assert!(!verify_signature(DnssecAlgorithm::Ed448, &[0u8; 10], b"msg", &[0u8; 114]));
        let public = test_signing_key(0x22).verifying_key();
        assert!(!verify_signature(DnssecAlgorithm::Ed448, public.as_bytes(), b"msg", &[0u8; 10]));
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
        // One extra iteration is exactly SHA-1(h0 || salt).
        let mut buf = h0a.clone();
        buf.extend_from_slice(&salt);
        let expected = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &buf).as_ref().to_vec();
        assert_eq!(h1, expected);
    }
}
