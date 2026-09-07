// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Certificate digests and SPKI extraction.

use bytes::Bytes;

use super::digest::{hash, HashAlgorithm};

/// Lowercase hex SHA-256 digest of a DER certificate — used for mTLS
/// `SecurityInfo::peer_certificate_fingerprint` and SASL EXTERNAL `cert_key`.
pub fn sha256_fingerprint_hex(der: &[u8]) -> String {
    let digest = hash(HashAlgorithm::Sha256, der);
    let mut out = String::with_capacity(digest.as_bytes().len() * 2);
    for byte in digest.as_bytes() {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// SHA-256 digest of the SubjectPublicKeyInfo bytes inside a DER X.509
/// certificate (RFC 5280). Used for DANE TLSA SPKI matching (RFC 6698).
///
/// Returns `None` if `cert_der` is not a minimally well-formed certificate.
pub fn spki_sha256(cert_der: &[u8]) -> Option<Bytes> {
    let spki = extract_spki(cert_der)?;
    Some(hash(HashAlgorithm::Sha256, spki.as_ref()).into_bytes())
}

/// Extract the DER-encoded SubjectPublicKeyInfo from an X.509 certificate.
pub fn extract_spki(cert_der: &[u8]) -> Option<Bytes> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let mut outer = parse_asn1_sequence(cert_der)?;
    let tbs = parse_asn1_sequence(outer.next()?)?;
    // TBSCertificate fields: version [0], serial, sig alg, issuer, validity,
    // subject, subjectPublicKeyInfo, ...
    let mut fields = tbs;
    // Optional explicit version tag [0]
    if fields.peek_tag()? == 0xa0 {
        fields.skip_element()?;
    }
    fields.skip_element()?; // serialNumber
    fields.skip_element()?; // signature
    fields.skip_element()?; // issuer
    fields.skip_element()?; // validity
    fields.skip_element()?; // subject
    Some(Bytes::copy_from_slice(fields.next()?))
}

struct Asn1Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Asn1Reader<'a> {
    fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

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

    fn skip_element(&mut self) -> Option<()> {
        self.next()?;
        Some(())
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

    #[test]
    fn fingerprint_is_lowercase_hex() {
        let fp = sha256_fingerprint_hex(b"not-a-cert-but-hashable");
        assert_eq!(fp.len(), 64);
        assert!(fp.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }
}
