// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Minimal X.509 certificate parsing for chain verification (RFC 5280 subset).

use bytes::Bytes;

use crate::asn1::{parse_sequence, read_bit_string_content, read_length, read_oid, read_tlv_content};

use super::signature::ed25519_verify;
use aws_lc_rs::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ML_DSA_44, ML_DSA_65, ML_DSA_87,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};

/// Parsed certificate fields needed for chain and hostname verification.
#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    /// Full DER encoding.
    pub der: Bytes,
    /// Signed TBSCertificate element (tag + length + content).
    pub tbs_der: Bytes,
    /// Issuer Name DER.
    pub issuer_der: Bytes,
    /// Subject Name DER.
    pub subject_der: Bytes,
    /// SubjectPublicKeyInfo DER.
    pub spki_der: Bytes,
    /// Signature algorithm DER (AlgorithmIdentifier).
    pub sig_alg_der: Bytes,
    /// Signature bytes (BIT STRING content without unused-bits byte).
    pub signature: Bytes,
    /// NotBefore / NotAfter (UTC seconds since Unix epoch).
    pub not_before: u64,
    /// NotAfter (UTC seconds since Unix epoch).
    pub not_after: u64,
    /// DNS names from Subject Alternative Name.
    pub dns_names: Vec<String>,
    /// Common Name from subject (fallback).
    pub common_name: Option<String>,
}

/// Parse a DER X.509 certificate.
pub fn parse_certificate(der: &[u8]) -> Option<ParsedCertificate> {
    let mut outer = parse_sequence(der)?;
    let tbs_elem = Bytes::copy_from_slice(outer.next()?);
    let sig_alg_elem = Bytes::copy_from_slice(outer.next()?);
    let sig_bit_string = outer.next()?;

    let mut tbs = parse_sequence(&tbs_elem)?;
    if tbs.peek_tag()? == 0xa0 {
        tbs.skip_element()?;
    }
    tbs.skip_element()?; // serial
    tbs.skip_element()?; // signature alg inside tbs
    let issuer_der = Bytes::copy_from_slice(tbs.next()?);
    let validity = tbs.next()?;
    let subject_der = Bytes::copy_from_slice(tbs.next()?);
    let spki_der = Bytes::copy_from_slice(tbs.next()?);

    let (not_before, not_after) = parse_validity(validity)?;
    let mut dns_names = Vec::new();

    if tbs.peek_tag() == Some(0xa3) {
        let ext_wrapper = tbs.next()?;
        if let Some(ext_seq_bytes) = read_tlv_content(ext_wrapper, 0xa3) {
            if let Some(mut exts) = parse_sequence(ext_seq_bytes) {
                while exts.peek_tag().is_some() {
                    let ext_seq = exts.next()?;
                    if let Some(mut ext) = parse_sequence(ext_seq) {
                        let oid = read_oid(ext.next()?)?;
                        if ext.peek_tag() == Some(0x01) {
                            ext.skip_element()?;
                        }
                        let extn_value = ext.next()?;
                        if oid == OID_SUBJECT_ALT_NAME {
                            dns_names = parse_subject_alt_names(read_tlv_content(extn_value, 0x04)?);
                        }
                    }
                }
            }
        }
    }

    let common_name = parse_common_name(&subject_der);
    let signature = Bytes::copy_from_slice(read_bit_string_content(sig_bit_string)?);

    Some(ParsedCertificate {
        der: Bytes::copy_from_slice(der),
        tbs_der: tbs_elem,
        issuer_der,
        subject_der,
        spki_der,
        sig_alg_der: sig_alg_elem,
        signature,
        not_before,
        not_after,
        dns_names,
        common_name,
    })
}

/// TLS `SignatureScheme` codes (RFC 8446 §4.2.3) for every certificate
/// chain signature algorithm [`verify_cert_signature`] accepts — the
/// single source of truth behind the `signature_algorithms_cert`
/// extension both TLS engines send (RFC 8446 §4.2.3 / RFC 9846 §1.4).
/// Same order as, and **must stay in sync with**, the `if oid == ...`
/// chain below: Ed25519, ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384,
/// rsa_pkcs1_sha256/384/512, ML-DSA-44/65/87. No RSA-PSS certificate
/// signatures — that's `id-RSASSA-PSS`'s parameterized
/// `AlgorithmIdentifier`, which this module doesn't parse (a separate,
/// larger addition than what's here). The ML-DSA codepoints
/// (`SSL_SIGN_MLDSA44/65/87`, FIPS 204) are read from this repo's own
/// vendored `aws-lc-sys` build output
/// (`target/debug/build/aws-lc-sys-*/out/include/openssl/ssl.h`), not
/// guessed — verify-only (no ML-DSA signing support here; see
/// `crypto-migration-plan.md` for why).
pub const ACCEPTED_CERT_SIGNATURE_SCHEMES: &[u16] = &[
    0x0807, // ed25519
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0401, // rsa_pkcs1_sha256
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
    0x0904, // ML-DSA-44 (SSL_SIGN_MLDSA44)
    0x0905, // ML-DSA-65 (SSL_SIGN_MLDSA65)
    0x0906, // ML-DSA-87 (SSL_SIGN_MLDSA87)
];

/// Verify `cert` was signed by the public key in `issuer_spki`. Accepts
/// exactly the algorithms in [`ACCEPTED_CERT_SIGNATURE_SCHEMES`] — keep
/// the two in sync.
pub fn verify_cert_signature(cert: &ParsedCertificate, issuer_spki: &[u8]) -> bool {
    let Some(oid) = sig_alg_oid(&cert.sig_alg_der) else {
        return false;
    };
    if oid == OID_RAW_ED25519 {
        let Some(pubkey) = ed25519_pubkey_from_spki(issuer_spki) else {
            return false;
        };
        return ed25519_verify(pubkey, cert.tbs_der.as_ref(), cert.signature.as_ref());
    }
    if oid == OID_RAW_ECDSA_SHA256 {
        return UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, issuer_spki)
            .verify(cert.tbs_der.as_ref(), cert.signature.as_ref())
            .is_ok();
    }
    if oid == OID_RAW_ECDSA_SHA384 {
        return UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, issuer_spki)
            .verify(cert.tbs_der.as_ref(), cert.signature.as_ref())
            .is_ok();
    }
    if oid == OID_RAW_RSA_SHA256 {
        return UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, issuer_spki)
            .verify(cert.tbs_der.as_ref(), cert.signature.as_ref())
            .is_ok();
    }
    if oid == OID_RAW_RSA_SHA384 {
        return UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, issuer_spki)
            .verify(cert.tbs_der.as_ref(), cert.signature.as_ref())
            .is_ok();
    }
    if oid == OID_RAW_RSA_SHA512 {
        return UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, issuer_spki)
            .verify(cert.tbs_der.as_ref(), cert.signature.as_ref())
            .is_ok();
    }
    if oid == OID_RAW_ML_DSA_44 {
        return UnparsedPublicKey::new(&ML_DSA_44, issuer_spki)
            .verify(cert.tbs_der.as_ref(), cert.signature.as_ref())
            .is_ok();
    }
    if oid == OID_RAW_ML_DSA_65 {
        return UnparsedPublicKey::new(&ML_DSA_65, issuer_spki)
            .verify(cert.tbs_der.as_ref(), cert.signature.as_ref())
            .is_ok();
    }
    if oid == OID_RAW_ML_DSA_87 {
        return UnparsedPublicKey::new(&ML_DSA_87, issuer_spki)
            .verify(cert.tbs_der.as_ref(), cert.signature.as_ref())
            .is_ok();
    }
    false
}

/// Return true if `name` matches certificate identity (RFC 6125 DNS rules).
pub fn matches_hostname(cert: &ParsedCertificate, name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    for dns in &cert.dns_names {
        if dns_name_matches(dns, &name) {
            return true;
        }
    }
    if let Some(cn) = &cert.common_name {
        if dns_name_matches(cn, &name) {
            return true;
        }
    }
    false
}

fn dns_name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = pattern.strip_prefix("*.") {
        if let Some(pos) = host.find('.') {
            return &host[pos + 1..] == rest;
        }
        return false;
    }
    pattern == host
}

const OID_SUBJECT_ALT_NAME: [u8; 3] = [0x55, 0x1d, 0x11];
const OID_RAW_ED25519: [u8; 3] = [0x2b, 0x65, 0x70];
const OID_RAW_ECDSA_SHA256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_RAW_ECDSA_SHA384: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_RAW_RSA_SHA256: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_RAW_RSA_SHA384: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_RAW_RSA_SHA512: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
/// `id-ml-dsa-44` (FIPS 204, OBJ_MLDSA44 = 2.16.840.1.101.3.4.3.17) —
/// confirmed against this repo's own vendored `aws-lc-sys` `nid.h`.
const OID_RAW_ML_DSA_44: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
/// `id-ml-dsa-65` (2.16.840.1.101.3.4.3.18).
const OID_RAW_ML_DSA_65: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
/// `id-ml-dsa-87` (2.16.840.1.101.3.4.3.19).
const OID_RAW_ML_DSA_87: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

fn sig_alg_oid(sig_alg_der: &[u8]) -> Option<&[u8]> {
    let mut seq = parse_sequence(sig_alg_der)?;
    read_oid(seq.next()?)
}

fn parse_subject_alt_names(ext_value: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(mut seq) = parse_sequence(ext_value) else {
        return out;
    };
    while seq.peek_tag().is_some() {
        let tag = seq.peek_tag().unwrap();
        if tag == 0x82 {
            let elem = seq.next().unwrap();
            if let Some(name) = read_tlv_content(elem, 0x82) {
                if let Ok(s) = std::str::from_utf8(name) {
                    out.push(s.to_string());
                }
            }
        } else {
            seq.skip_element();
        }
    }
    out
}

fn parse_common_name(name_der: &[u8]) -> Option<String> {
    let mut rdns = parse_sequence(name_der)?;
    while rdns.peek_tag().is_some() {
        let rdn = rdns.next()?;
        let Some(mut set) = parse_sequence(rdn) else {
            continue;
        };
        while set.peek_tag().is_some() {
            let atv = set.next()?;
            let Some(mut seq) = parse_sequence(atv) else {
                continue;
            };
            let oid = read_oid(seq.next()?)?;
            let val = seq.next()?;
            if oid == [0x55, 0x04, 0x03] {
                return std::str::from_utf8(strip_asn1_string(val))
                    .ok()
                    .map(str::to_string);
            }
        }
    }
    None
}

fn strip_asn1_string(elem: &[u8]) -> &[u8] {
    if elem.len() >= 2 && matches!(elem[0], 0x0c | 0x13 | 0x16) {
        if let Some((len, hdr)) = read_length(&elem[1..]) {
            let start = 1 + hdr;
            let end = start + len;
            if end <= elem.len() {
                return &elem[start..end];
            }
        }
    }
    elem
}

fn parse_validity(validity: &[u8]) -> Option<(u64, u64)> {
    let mut seq = parse_sequence(validity)?;
    let nb = seq.next()?;
    let na = seq.next()?;
    Some((parse_asn1_time(nb)?, parse_asn1_time(na)?))
}

fn parse_asn1_time(elem: &[u8]) -> Option<u64> {
    let tag = *elem.first()?;
    let (len, hdr) = read_length(&elem[1..])?;
    let s = std::str::from_utf8(&elem[1 + hdr..1 + hdr + len]).ok()?;
    match tag {
        0x17 => parse_utc_time(s),
        0x18 => parse_generalized_time(s),
        _ => None,
    }
}

fn parse_utc_time(s: &str) -> Option<u64> {
    if s.len() != 13 || !s.ends_with('Z') {
        return None;
    }
    let year = i64::from(s[0..2].parse::<u32>().ok()?);
    let year = if year >= 50 { 1900 + year } else { 2000 + year };
    parse_ymdhms(year, &s[2..s.len() - 1])
}

fn parse_generalized_time(s: &str) -> Option<u64> {
    if s.len() < 15 || !s.ends_with('Z') {
        return None;
    }
    let year = s[0..4].parse::<i64>().ok()?;
    parse_ymdhms(year, &s[4..s.len() - 1])
}

fn parse_ymdhms(year: i64, rest: &str) -> Option<u64> {
    if rest.len() < 10 {
        return None;
    }
    let month = rest[0..2].parse::<i32>().ok()?;
    let day = rest[2..4].parse::<i32>().ok()?;
    let hour = rest[4..6].parse::<i32>().ok()?;
    let min = rest[6..8].parse::<i32>().ok()?;
    let sec = rest[8..10].parse::<i32>().ok()?;
    Some(utc_to_unix(year, month, day, hour, min, sec))
}

/// Civil UTC calendar date/time → Unix seconds (1970-01-01T00:00:00Z).
fn utc_to_unix(year: i64, month: i32, day: i32, hour: i32, min: i32, sec: i32) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + i64::from(doy);
    let days = era * 146097 + doe - 719468;
    (days * 86_400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec)) as u64
}

fn ed25519_pubkey_from_spki(spki: &[u8]) -> Option<&[u8]> {
    let mut seq = parse_sequence(spki)?;
    seq.skip_element()?;
    read_bit_string_content(seq.next()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rcgen_ed25519_cert() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let parsed = parse_certificate(cert.der()).expect("parse");
        assert!(
            parsed.dns_names.iter().any(|n| n == "localhost")
                || parsed.common_name.as_deref() == Some("localhost")
        );
        assert!(verify_cert_signature(&parsed, &parsed.spki_der));
        assert!(matches_hostname(&parsed, "localhost"));
    }

    /// Real WebPKI root/intermediate signatures are routinely ECDSA P-384 or
    /// RSA with SHA-384/512, not just the SHA-256 variants — this is what
    /// public-trust chain verification against a real CA hierarchy
    /// (`hopf-tls`'s `public_trust_connector_validates_a_real_public_certificate`
    /// integration test) needs but a same-algorithm-both-ends loopback like
    /// `parse_rcgen_ed25519_cert` above can't exercise.
    #[test]
    fn verify_cert_signature_covers_ecdsa_p384_sha384() {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        let ca_parsed = parse_certificate(ca_cert.der()).expect("parse CA");
        let leaf_parsed = parse_certificate(leaf_cert.der()).expect("parse leaf");
        assert!(verify_cert_signature(&leaf_parsed, &ca_parsed.spki_der));
    }

    // RSA-SHA384/512 CA signatures are covered by hopf-tls's
    // `public_trust_connector_validates_a_real_public_certificate`
    // integration test against a real WebPKI chain — rcgen can't generate
    // RSA keys, and constructing one by hand here just to sign a
    // synthetic cert would need a `rustls-pki-types` dev-dependency for
    // little extra coverage beyond what the ECDSA-P384 case above and the
    // real integration test already prove.

    // ML-DSA has no `rcgen` support in the pinned version (0.13.2) —
    // `SignatureAlgorithm`'s fields are all private, so unlike RSA above
    // there's no `RemoteKeyPair`-style way to plug in an algorithm rcgen
    // doesn't already know. These helpers hand-build just enough of a
    // minimal, non-CA-issuable X.509 DER certificate for
    // `parse_certificate`/`verify_cert_signature` to round-trip — not a
    // fully RFC 5280-compliant certificate.

    /// One DER TLV: tag + length (short or long form) + content.
    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 128 {
            out.push(len as u8);
        } else if len < 256 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
        out.extend_from_slice(content);
        out
    }

    fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
        let mut content = Vec::new();
        for p in parts {
            content.extend_from_slice(p);
        }
        der_tlv(0x30, &content)
    }

    /// `BIT STRING` with a zero-length unused-bits prefix (every value
    /// this module ever wraps is a whole number of bytes).
    fn der_bit_string(content: &[u8]) -> Vec<u8> {
        let mut inner = vec![0u8];
        inner.extend_from_slice(content);
        der_tlv(0x03, &inner)
    }

    /// Minimal `RDNSequence` — a single `commonName` RDN. Good enough for
    /// `parse_certificate`'s generic `Name` handling; not asserted on by
    /// the tests below (they only care about the signature).
    fn der_minimal_name() -> Vec<u8> {
        let cn_oid = der_tlv(0x06, &[0x55, 0x04, 0x03]); // id-at-commonName
        let cn_value = der_tlv(0x0c, b"ml-dsa-test"); // UTF8String
        let attr = der_seq(&[&cn_oid, &cn_value]);
        let rdn = der_tlv(0x31, &attr); // SET
        der_seq(&[&rdn])
    }

    fn der_validity() -> Vec<u8> {
        let not_before = der_tlv(0x17, b"260101000000Z"); // UTCTime
        let not_after = der_tlv(0x17, b"300101000000Z");
        der_seq(&[&not_before, &not_after])
    }

    /// `AlgorithmIdentifier ::= SEQUENCE { OID }` — no parameters, same
    /// minimal shape as Ed25519's (RFC 8410 §3), which ML-DSA follows too.
    fn der_alg_id(oid_raw: &[u8]) -> Vec<u8> {
        der_seq(&[&der_tlv(0x06, oid_raw)])
    }

    /// Hand-build a minimal self-signed ML-DSA-44 certificate. Returns
    /// `(cert_der, spki_der)`.
    fn build_ml_dsa_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, ML_DSA_44_SIGNING};

        let key_pair = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).unwrap();
        let spki_der: Vec<u8> = key_pair.public_key().as_der().unwrap().as_ref().to_vec();
        let alg_id = der_alg_id(&OID_RAW_ML_DSA_44);
        let name = der_minimal_name();
        // Empty (but present) extensions block, `[3] EXPLICIT SEQUENCE {}` —
        // every real-world v3 certificate carries this field even when it
        // has nothing in it (the no-extensions-field-at-all shape is
        // covered separately by
        // `parse_certificate_accepts_a_cert_with_no_extensions_field`).
        let extensions = der_tlv(0xa3, &der_seq(&[]));

        let tbs = der_seq(&[
            &der_tlv(0x02, &[0x01]), // serialNumber = 1
            &alg_id,                 // signature (inner, unread by parse_certificate)
            &name,                   // issuer
            &der_validity(),
            &name, // subject (self-signed: same as issuer)
            &spki_der,
            &extensions,
        ]);

        let mut signature = vec![0u8; ML_DSA_44_SIGNING.signature_len()];
        let sig_len = key_pair.sign(&tbs, &mut signature).unwrap();
        signature.truncate(sig_len);

        let cert = der_seq(&[&tbs, &alg_id, &der_bit_string(&signature)]);
        (cert, spki_der)
    }

    #[test]
    fn verify_cert_signature_covers_ml_dsa_44() {
        let (cert_der, spki_der) = build_ml_dsa_self_signed_cert();
        let parsed = parse_certificate(&cert_der).expect("parse ML-DSA-44 cert");
        assert!(verify_cert_signature(&parsed, &spki_der));
    }

    #[test]
    fn verify_cert_signature_rejects_tampered_ml_dsa_44_signature() {
        let (mut cert_der, spki_der) = build_ml_dsa_self_signed_cert();
        let last = cert_der.len() - 1;
        cert_der[last] ^= 0xff; // corrupt the last byte of the signature bit string
        let parsed = parse_certificate(&cert_der).expect("parse ML-DSA-44 cert");
        assert!(!verify_cert_signature(&parsed, &spki_der));
    }

    /// Hand-build a minimal self-signed Ed25519 certificate whose TBS has
    /// **no extensions field at all** — zero trailing bytes after
    /// `subjectPublicKeyInfo`. RFC 5280 marks extensions optional in the
    /// ASN.1 grammar, but every other fixture in this module happens to
    /// carry at least one (`rcgen`-generated certs always do, and
    /// `build_ml_dsa_self_signed_cert` above adds a deliberate empty one),
    /// so this shape had never been exercised before. Returns
    /// `(cert_der, spki_der)`.
    fn build_ed25519_cert_with_no_extensions_field() -> (Vec<u8>, Vec<u8>) {
        use super::super::signature::{ed25519_sign, Ed25519PrivateKey};

        let pkcs8 = Ed25519PrivateKey::generate_pkcs8().unwrap();
        let key_pair = Ed25519PrivateKey::from_generated_pkcs8(&pkcs8).unwrap();
        let alg_id = der_alg_id(&OID_RAW_ED25519);
        let spki_der = der_seq(&[&alg_id, &der_bit_string(key_pair.public_key_bytes())]);
        let name = der_minimal_name();

        let tbs = der_seq(&[
            &der_tlv(0x02, &[0x01]), // serialNumber = 1
            &alg_id,                 // signature (inner, unread by parse_certificate)
            &name,                   // issuer
            &der_validity(),
            &name, // subject (self-signed: same as issuer)
            &spki_der,
            // deliberately no extensions element — zero trailing TBS bytes
        ]);

        let signature = ed25519_sign(&key_pair, &tbs);
        let cert = der_seq(&[&tbs, &alg_id, &der_bit_string(&signature)]);
        (cert, spki_der)
    }

    #[test]
    fn parse_certificate_accepts_a_cert_with_no_extensions_field() {
        let (cert_der, spki_der) = build_ed25519_cert_with_no_extensions_field();
        let parsed =
            parse_certificate(&cert_der).expect("a cert with no extensions field at all should still parse");
        assert!(parsed.dns_names.is_empty());
        assert!(verify_cert_signature(&parsed, &spki_der));
    }
}
