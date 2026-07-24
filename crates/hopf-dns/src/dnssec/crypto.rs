// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Cryptographic signature verification via `ring`.

use ring::digest;
use ring::signature::{self, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512};

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
        DnssecAlgorithm::Ed448 => false, // ring has no Ed448
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
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn ed25519_roundtrip() {
        let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let msg = b"dnssec-test-message";
        let sig = pair.sign(msg);
        assert!(verify_ed25519(pair.public_key().as_ref(), msg, sig.as_ref()));
        assert!(!verify_ed25519(pair.public_key().as_ref(), b"tampered", sig.as_ref()));
    }
}
