// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Minimal X.509 certificate parsing for chain verification (RFC 5280 subset).

use bytes::Bytes;

use super::signature::ed25519_verify;
use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, RSA_PKCS1_2048_8192_SHA256};

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
    let mut outer = parse_asn1_sequence(der)?;
    let tbs_elem = Bytes::copy_from_slice(outer.next()?);
    let sig_alg_elem = Bytes::copy_from_slice(outer.next()?);
    let sig_bit_string = outer.next()?;

    let mut tbs = parse_asn1_sequence(&tbs_elem)?;
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

    if tbs.peek_tag()? == 0xa3 {
        let ext_wrapper = tbs.next()?;
        if let Some(ext_seq_bytes) = explicit_tag_contents(ext_wrapper, 0xa3) {
            if let Some(mut exts) = parse_asn1_sequence(ext_seq_bytes) {
                while exts.peek_tag().is_some() {
                    let ext_seq = exts.next()?;
                    if let Some(mut ext) = parse_asn1_sequence(ext_seq) {
                        let oid = parse_oid(ext.next()?)?;
                        if ext.peek_tag() == Some(0x01) {
                            ext.skip_element()?;
                        }
                        let extn_value = ext.next()?;
                        if oid == OID_SUBJECT_ALT_NAME {
                            dns_names = parse_subject_alt_names(octet_string_contents(extn_value)?);
                        }
                    }
                }
            }
        }
    }

    let common_name = parse_common_name(&subject_der);
    let signature = Bytes::from(bit_string_contents(sig_bit_string)?);

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

/// Verify `cert` was signed by the public key in `issuer_spki`.
pub fn verify_cert_signature(cert: &ParsedCertificate, issuer_spki: &[u8]) -> bool {
    let Some(oid) = sig_alg_oid(&cert.sig_alg_der) else {
        return false;
    };
    if oid.as_slice() == OID_RAW_ED25519 {
        let Some(pubkey) = ed25519_pubkey_from_spki(issuer_spki) else {
            return false;
        };
        return ed25519_verify(&pubkey, cert.tbs_der.as_ref(), cert.signature.as_ref());
    }
    if oid.as_slice() == OID_RAW_ECDSA_SHA256 {
        return UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, issuer_spki)
            .verify(cert.tbs_der.as_ref(), cert.signature.as_ref())
            .is_ok();
    }
    if oid.as_slice() == OID_RAW_RSA_SHA256 {
        return UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, issuer_spki)
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
const OID_RAW_RSA_SHA256: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

fn sig_alg_oid(sig_alg_der: &[u8]) -> Option<Vec<u8>> {
    let mut seq = parse_asn1_sequence(sig_alg_der)?;
    parse_oid(seq.next()?)
}

fn parse_subject_alt_names(ext_value: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(mut seq) = parse_asn1_sequence(ext_value) else {
        return out;
    };
    while seq.peek_tag().is_some() {
        let tag = seq.peek_tag().unwrap();
        if tag == 0x82 {
            let elem = seq.next().unwrap();
            if elem.len() >= 2 {
                if let Some((len, hdr)) = read_length(&elem[1..]) {
                    let start = 1 + hdr;
                    let end = start + len;
                    if end <= elem.len() {
                        if let Ok(s) = std::str::from_utf8(&elem[start..end]) {
                            out.push(s.to_string());
                        }
                    }
                }
            }
        } else {
            seq.skip_element();
        }
    }
    out
}

fn parse_common_name(name_der: &[u8]) -> Option<String> {
    let mut rdns = parse_asn1_sequence(name_der)?;
    while rdns.peek_tag().is_some() {
        let rdn = rdns.next()?;
        let Some(mut set) = parse_asn1_sequence(rdn) else {
            continue;
        };
        while set.peek_tag().is_some() {
            let atv = set.next()?;
            let Some(mut seq) = parse_asn1_sequence(atv) else {
                continue;
            };
            let oid = parse_oid(seq.next()?)?;
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
    let mut seq = parse_asn1_sequence(validity)?;
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

fn ed25519_pubkey_from_spki(spki: &[u8]) -> Option<Vec<u8>> {
    let mut seq = parse_asn1_sequence(spki)?;
    seq.skip_element()?;
    bit_string_contents(seq.next()?)
}

fn parse_oid(elem: &[u8]) -> Option<Vec<u8>> {
    if *elem.first()? != 0x06 {
        return None;
    }
    let (len, hdr) = read_length(&elem[1..])?;
    Some(elem[1 + hdr..1 + hdr + len].to_vec())
}

fn bit_string_contents(elem: &[u8]) -> Option<Vec<u8>> {
    if *elem.first()? != 0x03 {
        return None;
    }
    let (len, hdr) = read_length(&elem[1..])?;
    let start = 1 + hdr;
    let end = start + len;
    if elem.len() < end || len < 1 {
        return None;
    }
    Some(elem[start + 1..end].to_vec())
}

fn octet_string_contents(elem: &[u8]) -> Option<&[u8]> {
    if *elem.first()? != 0x04 {
        return None;
    }
    let (len, hdr) = read_length(&elem[1..])?;
    let start = 1 + hdr;
    let end = start + len;
    if end > elem.len() {
        return None;
    }
    Some(&elem[start..end])
}

fn explicit_tag_contents(elem: &[u8], expected_tag: u8) -> Option<&[u8]> {
    if *elem.first()? != expected_tag {
        return None;
    }
    let (len, hdr) = read_length(&elem[1..])?;
    let start = 1 + hdr;
    let end = start + len;
    if end > elem.len() {
        return None;
    }
    Some(&elem[start..end])
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
        if end > self.bytes.len() {
            return None;
        }
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
}
