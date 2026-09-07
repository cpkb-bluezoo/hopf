// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Digital signatures via AWS-LC.

use aws_lc_rs::signature::{
    self, KeyPair, RsaKeyPair, UnparsedPublicKey, ED25519, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_SHA256,
};

/// Key parsing or generation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyError;

/// Signing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignError;

/// RSA PKCS#8 private key for signing.
pub struct RsaPrivateKey(RsaKeyPair);

impl RsaPrivateKey {
    /// Load from PKCS#8 DER.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, KeyError> {
        RsaKeyPair::from_pkcs8(der).map(RsaPrivateKey).map_err(|_| KeyError)
    }
}

/// Ed25519 PKCS#8 private key for signing.
pub struct Ed25519PrivateKey(signature::Ed25519KeyPair);

impl Ed25519PrivateKey {
    /// Load from PKCS#8 DER (v1 seed-only or v2 seed+public).
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, KeyError> {
        signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map(Ed25519PrivateKey)
            .map_err(|_| KeyError)
    }

    /// Generate a new PKCS#8 document (tests and tooling).
    pub fn generate_pkcs8() -> Result<Vec<u8>, KeyError> {
        signature::Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new())
            .map(|doc| doc.as_ref().to_vec())
            .map_err(|_| KeyError)
    }

    /// Raw 32-byte public key.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    /// Re-load from a PKCS#8 document returned by [`Self::generate_pkcs8`].
    pub fn from_generated_pkcs8(doc: &[u8]) -> Result<Self, KeyError> {
        Self::from_pkcs8(doc)
    }
}

/// Ed25519 public key bytes (32 octets).
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// Parse a 32-byte public key.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes).ok().map(Ed25519PublicKey)
    }

    /// Raw public key octets.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// RSA `(n, e)` public-key components for verification (DKIM, DNSSEC).
pub struct RsaPublicKeyComponents<'a> {
    /// RSA modulus.
    pub n: &'a [u8],
    /// RSA public exponent.
    pub e: &'a [u8],
}

/// Sign `data` with RSA PKCS#1 v1.5 + SHA-256 (DKIM `rsa-sha256`).
pub fn rsa_sign_pkcs1_sha256(key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, SignError> {
    let mut sig = vec![0u8; key.0.public_modulus_len()];
    key.0
        .sign(
            &RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            data,
            &mut sig,
        )
        .map_err(|_| SignError)?;
    Ok(sig)
}

/// Sign `data` with Ed25519 (DKIM `ed25519-sha256`, DNSSEC).
pub fn ed25519_sign(key: &Ed25519PrivateKey, data: &[u8]) -> Vec<u8> {
    key.0.sign(data).as_ref().to_vec()
}

/// Verify RSA PKCS#1 v1.5 + SHA-256 over `message`.
pub fn rsa_verify_pkcs1_sha256(components: RsaPublicKeyComponents<'_>, message: &[u8], signature: &[u8]) -> bool {
    let key = signature::RsaPublicKeyComponents {
        n: components.n,
        e: components.e,
    };
    key.verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
        .is_ok()
}

/// Verify RSA PKCS#1 v1.5 + SHA-512 over `message` (DNSSEC RSASHA512).
pub fn rsa_verify_pkcs1_sha512(components: RsaPublicKeyComponents<'_>, message: &[u8], signature: &[u8]) -> bool {
    let key = signature::RsaPublicKeyComponents {
        n: components.n,
        e: components.e,
    };
    key.verify(&RSA_PKCS1_2048_8192_SHA512, message, signature)
        .is_ok()
}

/// Verify RSA over `message` using DNSKEY wire-format `public_key` (RFC 3110).
pub fn rsa_verify_dnskey(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    sha512: bool,
) -> bool {
    let Some(der) = rsa_dnskey_to_spki_der(public_key) else {
        return false;
    };
    let params: &dyn signature::VerificationAlgorithm = if sha512 {
        &RSA_PKCS1_2048_8192_SHA512
    } else {
        &RSA_PKCS1_2048_8192_SHA256
    };
    UnparsedPublicKey::new(params, &der)
        .verify(message, signature)
        .is_ok()
}

/// Verify Ed25519 over `message` (`public_key` is 32 bytes).
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

/// Verify ECDSA P-256 SHA-256 (RFC 6605: key is x||y, sig is r||s, 32+32 each).
pub fn ecdsa_p256_sha256_verify(public_key_xy: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key_xy.len() != 64 || signature.len() != 64 {
        return false;
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(public_key_xy);
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &sec1)
        .verify(message, signature)
        .is_ok()
}

/// Verify ECDSA P-384 SHA-384 (RFC 6605: key is x||y, sig is r||s, 48+48 each).
pub fn ecdsa_p384_sha384_verify(public_key_xy: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key_xy.len() != 96 || signature.len() != 96 {
        return false;
    }
    let mut sec1 = Vec::with_capacity(97);
    sec1.push(0x04);
    sec1.extend_from_slice(public_key_xy);
    UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &sec1)
        .verify(message, signature)
        .is_ok()
}

/// RFC 3110 RSA DNSKEY wire format → DER `RSAPublicKey` (PKCS#1) for verification.
pub fn rsa_dnskey_to_spki_der(public_key: &[u8]) -> Option<Vec<u8>> {
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

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let doc = Ed25519PrivateKey::generate_pkcs8().unwrap();
        let key = Ed25519PrivateKey::from_pkcs8(&doc).unwrap();
        let msg = b"hopf-crypto-test";
        let sig = ed25519_sign(&key, msg);
        assert!(ed25519_verify(key.public_key_bytes(), msg, &sig));
        assert!(!ed25519_verify(key.public_key_bytes(), b"tampered", &sig));
    }
}
