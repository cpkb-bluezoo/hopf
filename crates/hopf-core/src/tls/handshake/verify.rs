// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 CertificateVerify signing and verification (RFC 8446 §4.4.3).

use bytes::{Bytes, BytesMut};

use crate::crypto::cert::extract_spki;
use crate::crypto::signature::{
    ecdsa_p256_sha256_verify_spki, ecdsa_p256_sign, ecdsa_p384_sha384_verify_spki, ecdsa_p384_sign,
    ed25519_sign, ed25519_verify, rsa_pss_sha256_verify_spki, rsa_sign_pss_sha256,
    EcdsaP256PrivateKey, EcdsaP384PrivateKey, Ed25519PrivateKey, RsaPrivateKey,
};

/// IANA `SignatureScheme` for Ed25519 (RFC 8446 §4.2.3).
pub const SIG_ED25519: u16 = 0x0807;
/// IANA `SignatureScheme` for ECDSA P-256 + SHA-256 (RFC 8446 §4.2.3).
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// IANA `SignatureScheme` for ECDSA P-384 + SHA-384 (RFC 8446 §4.2.3).
pub const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
/// IANA `SignatureScheme` for RSA-PSS-RSAE + SHA-256 (RFC 8446 §4.2.3) — TLS 1.3
/// forbids PKCS#1 v1.5 (`rsa_pkcs1_*`) in `CertificateVerify`; RSA certs use this instead.
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;

/// Schemes advertised in ClientHello's `signature_algorithms` (RFC 8446 §4.2.3) and
/// accepted when verifying a peer's `CertificateVerify`, in preference order.
/// P-384 and RSA-PSS cover real-world WebPKI leaves; broader RSA hash widths and
/// client-certificate schemes are not implemented yet.
pub const SUPPORTED_SIGNATURE_SCHEMES: &[u16] = &[
    SIG_ED25519,
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_RSA_PSS_RSAE_SHA256,
];

/// Build the signed payload for CertificateVerify.
pub fn certificate_verify_message(is_client: bool, transcript_hash: &[u8; 32]) -> Bytes {
    let context = if is_client {
        b"TLS 1.3, client CertificateVerify"
    } else {
        b"TLS 1.3, server CertificateVerify"
    };
    let mut out = BytesMut::with_capacity(64 + context.len() + 1 + 32);
    out.extend(core::iter::repeat_n(0x20u8, 64));
    out.extend_from_slice(context);
    out.extend_from_slice(&[0]);
    out.extend_from_slice(transcript_hash);
    out.freeze()
}

/// Sign CertificateVerify with Ed25519.
pub fn sign_ed25519_certificate_verify(
    is_client: bool,
    key: &Ed25519PrivateKey,
    transcript_hash: &[u8; 32],
) -> (u16, Bytes) {
    let msg = certificate_verify_message(is_client, transcript_hash);
    (SIG_ED25519, ed25519_sign(key, &msg))
}

/// Sign CertificateVerify with whichever [`SUPPORTED_SIGNATURE_SCHEMES`] scheme
/// matches `signing_key_pkcs8`'s own key type (sniffed from the PKCS#8
/// `AlgorithmIdentifier` — server credentials carry a bare key, not a declared
/// scheme). Returns `None` for a key type or curve this crate doesn't sign with.
pub fn sign_certificate_verify(
    is_client: bool,
    signing_key_pkcs8: &[u8],
    transcript_hash: &[u8; 32],
) -> Option<(u16, Bytes)> {
    let msg = certificate_verify_message(is_client, transcript_hash);
    match pkcs8_key_kind(signing_key_pkcs8)? {
        KeyKind::Ed25519 => {
            let key = Ed25519PrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((SIG_ED25519, ed25519_sign(&key, &msg)))
        }
        KeyKind::EcdsaP256 => {
            let key = EcdsaP256PrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((SIG_ECDSA_SECP256R1_SHA256, ecdsa_p256_sign(&key, &msg).ok()?))
        }
        KeyKind::EcdsaP384 => {
            let key = EcdsaP384PrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((SIG_ECDSA_SECP384R1_SHA384, ecdsa_p384_sign(&key, &msg).ok()?))
        }
        KeyKind::Rsa => {
            let key = RsaPrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((SIG_RSA_PSS_RSAE_SHA256, rsa_sign_pss_sha256(&key, &msg).ok()?))
        }
    }
}

/// Verify a peer CertificateVerify signature against a leaf certificate DER.
pub fn verify_certificate_verify(
    peer_is_client: bool,
    leaf_cert_der: &[u8],
    scheme: u16,
    signature: &[u8],
    transcript_hash: &[u8; 32],
) -> bool {
    let Some(spki) = extract_spki(leaf_cert_der) else {
        return false;
    };
    let msg = certificate_verify_message(peer_is_client, transcript_hash);
    match scheme {
        SIG_ED25519 => {
            let Some(pk) = ed25519_public_key_from_spki(spki.as_ref()) else {
                return false;
            };
            ed25519_verify(&pk, &msg, signature)
        }
        SIG_ECDSA_SECP256R1_SHA256 => ecdsa_p256_sha256_verify_spki(spki.as_ref(), &msg, signature),
        SIG_ECDSA_SECP384R1_SHA384 => ecdsa_p384_sha384_verify_spki(spki.as_ref(), &msg, signature),
        SIG_RSA_PSS_RSAE_SHA256 => rsa_pss_sha256_verify_spki(spki.as_ref(), &msg, signature),
        _ => false,
    }
}

/// Key type sniffed from a PKCS#8 `AlgorithmIdentifier`, to pick a
/// `CertificateVerify` scheme without requiring the caller to declare one
/// alongside their PEM-loaded key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyKind {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa,
}

const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_SECP256R1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

/// `PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm AlgorithmIdentifier, ... }`
/// (RFC 5958) — reads just the algorithm OID (and, for EC keys, the curve OID) to
/// classify the key; never touches the private key material itself.
pub(crate) fn pkcs8_key_kind(pkcs8_der: &[u8]) -> Option<KeyKind> {
    let mut outer = parse_asn1_sequence(pkcs8_der)?;
    let _version = outer.next()?;
    let algorithm = outer.next()?;
    let mut algo_seq = parse_asn1_sequence(algorithm)?;
    let oid = read_oid(algo_seq.next()?)?;
    match oid {
        OID_ED25519 => Some(KeyKind::Ed25519),
        OID_RSA_ENCRYPTION => Some(KeyKind::Rsa),
        OID_EC_PUBLIC_KEY => match read_oid(algo_seq.next()?)? {
            OID_SECP256R1 => Some(KeyKind::EcdsaP256),
            OID_SECP384R1 => Some(KeyKind::EcdsaP384),
            _ => None,
        },
        _ => None,
    }
}

fn read_oid(tlv: &[u8]) -> Option<&[u8]> {
    if tlv.first() != Some(&0x06) {
        return None;
    }
    let (len, hdr) = read_length(&tlv[1..])?;
    tlv.get(1 + hdr..1 + hdr + len)
}

/// Extract a 32-byte Ed25519 public key from SPKI DER.
fn ed25519_public_key_from_spki(spki: &[u8]) -> Option<[u8; 32]> {
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let mut outer = parse_asn1_sequence(spki)?;
    let _alg = outer.next()?;
    let bit_string = outer.next()?;
    if bit_string.first() != Some(&0x03) {
        return None;
    }
    let (len, hdr) = read_length(&bit_string[1..])?;
    let content_start = 1 + hdr;
    let content_end = content_start + len;
    if bit_string.len() < content_end || len < 1 {
        return None;
    }
    // First byte of BIT STRING content is unused-bits count (0 for Ed25519).
    let key = &bit_string[content_start + 1..content_end];
    <[u8; 32]>::try_from(key).ok()
}

struct Asn1Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Asn1Reader<'a> {
    fn next(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        let _tag = *self.bytes.get(self.pos)?;
        self.pos += 1;
        let (len, hdr) = read_length(&self.bytes[self.pos..])?;
        self.pos += hdr;
        let end = self.pos.checked_add(len)?;
        self.pos = end;
        Some(&self.bytes[start..end])
    }
}

fn parse_asn1_sequence(bytes: &[u8]) -> Option<Asn1Reader<'_>> {
    if bytes.first() != Some(&0x30) {
        return None;
    }
    let (len, hdr) = read_length(&bytes[1..])?;
    let content_start = 1 + hdr;
    let content_end = content_start.checked_add(len)?;
    if content_end > bytes.len() {
        return None;
    }
    Some(Asn1Reader {
        bytes: &bytes[content_start..content_end],
        pos: 0,
    })
}

fn read_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 || bytes.len() < 1 + count {
        return None;
    }
    let mut len = 0usize;
    for i in 0..count {
        len = (len << 8) | bytes[1 + i] as usize;
    }
    Some((len, 1 + count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signature::Ed25519PrivateKey;

    #[test]
    fn ed25519_certificate_verify_roundtrip() {
        let doc = Ed25519PrivateKey::generate_pkcs8().unwrap();
        let key = Ed25519PrivateKey::from_pkcs8(&doc).unwrap();
        let th = [0xabu8; 32];
        let (scheme, sig) = sign_ed25519_certificate_verify(false, &key, &th);
        assert_eq!(scheme, SIG_ED25519);
        let msg = certificate_verify_message(false, &th);
        assert_eq!(msg.len(), 64 + 32 + 1 + "TLS 1.3, server CertificateVerify".len());
        assert!(ed25519_verify(key.public_key_bytes(), msg.as_ref(), sig.as_ref()));
    }
}
