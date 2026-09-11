// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Certificate digests and SPKI extraction.

use bytes::Bytes;

use crate::asn1::parse_sequence;

use super::digest::{hash, HashAlgorithm};

/// A certificate's SubjectPublicKeyInfo, DER-encoded (RFC 5280) — distinct
/// from a raw certificate, a signature, or any other DER blob flowing
/// through the same call sites, so a caller can't pass the wrong one where
/// this is expected. Shared by every consumer of [`extract_spki`]:
/// `crypto::trust`'s component trust anchors, TLS `CertificateVerify`
/// (`tls::handshake::verify`), and DANE SPKI matching (`hopf-dns`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpkiDer(Bytes);

impl SpkiDer {
    /// Wrap already-encoded SubjectPublicKeyInfo DER bytes.
    pub fn from_bytes(der: Bytes) -> Self {
        Self(der)
    }

    /// Borrow the DER bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SpkiDer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

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
    Some(hash(HashAlgorithm::Sha256, spki.as_bytes()).into_bytes())
}

/// Extract the DER-encoded SubjectPublicKeyInfo from an X.509 certificate.
pub fn extract_spki(cert_der: &[u8]) -> Option<SpkiDer> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let mut outer = parse_sequence(cert_der)?;
    let tbs = parse_sequence(outer.next()?)?;
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
    Some(SpkiDer::from_bytes(Bytes::copy_from_slice(fields.next()?)))
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
