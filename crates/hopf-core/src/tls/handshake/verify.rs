// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 CertificateVerify signing and verification (RFC 8446 §4.4.3).

use bytes::{Bytes, BytesMut};

use crate::crypto::cert::extract_spki;
use crate::crypto::signature::{ed25519_sign, ed25519_verify, Ed25519PrivateKey};

/// IANA `SignatureScheme` for Ed25519 (RFC 8446 §4.2.3).
pub const SIG_ED25519: u16 = 0x0807;

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

/// Verify a peer CertificateVerify signature against a leaf certificate DER.
pub fn verify_certificate_verify(
    peer_is_client: bool,
    leaf_cert_der: &[u8],
    scheme: u16,
    signature: &[u8],
    transcript_hash: &[u8; 32],
) -> bool {
    if scheme != SIG_ED25519 {
        return false;
    }
    let Some(spki) = extract_spki(leaf_cert_der) else {
        return false;
    };
    let Some(pk) = ed25519_public_key_from_spki(spki.as_ref()) else {
        return false;
    };
    let msg = certificate_verify_message(peer_is_client, transcript_hash);
    ed25519_verify(&pk, &msg, signature)
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
