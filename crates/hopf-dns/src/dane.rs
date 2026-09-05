// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DANE (RFC 6698/7672) certificate verification against TLSA records
//! (issue #352, feature `dane`).
//!
//! [`DaneServerCertVerifier`] implements rustls's
//! [`ServerCertVerifier`] extension point, so it plugs into any
//! `rustls::ClientConfig` via
//! `.dangerous().with_custom_certificate_verifier(...)` — no changes to
//! `hopf-tls` are needed; build a `ClientConfig` with this verifier and
//! hand it to `hopf_tls::connector()` as usual.
//!
//! This module only matches a certificate chain against TLSA records it's
//! given — it does not look up TLSA records itself, and does not perform
//! or check DNSSEC validation. The caller is responsible for only
//! constructing a verifier from TLSA records it has already confirmed are
//! DNSSEC-Secure (e.g. via [`crate::client::DnsResolver::validate_chain_of_trust`]);
//! a bogus or unvalidated TLSA answer must never reach here.
//!
//! ## Scope: only usage 2 (DANE-TA) and 3 (DANE-EE) are matched
//!
//! RFC 7672 §3.1.2 (the SMTP DANE profile that motivated this crate
//! feature) says certificate usages PKIX-TA(0) and PKIX-EE(1) — which
//! layer TLSA pinning on top of ordinary WebPKI/CA validation — are not
//! recommended: opportunistic MTA-to-MTA TLS is exactly the case DANE
//! exists to free from WebPKI's operational fragility, so re-requiring a
//! CA-validated chain defeats the point. TLSA records parse for all four
//! usages ([`crate::TlsaUsage`] round-trips every value, RFC 6698 §7.2's
//! private-use/unassigned range included), but this verifier only ever
//! matches DANE-TA(2) and DANE-EE(3) records — a usage-0/1 record is
//! never treated as a match, the same as an unassigned one.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::wire::{TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage};

/// Verifies a server's certificate chain against a set of TLSA records
/// (RFC 6698 §2.1), instead of (or as well as) ordinary WebPKI validation.
///
/// Construct with the TLSA records for the specific `_<port>._<protocol>.<hostname>`
/// name being dialed — one verifier per dial, since different hostnames
/// have different TLSA records.
pub struct DaneServerCertVerifier {
    records: Vec<TlsaRecord>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for DaneServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaneServerCertVerifier")
            .field("records", &self.records)
            .finish_non_exhaustive()
    }
}

impl DaneServerCertVerifier {
    /// Build a verifier for `records` using the default (aws-lc-rs)
    /// crypto provider.
    pub fn new(records: Vec<TlsaRecord>) -> Self {
        Self::with_provider(records, Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
    }

    /// Build a verifier for `records` using an explicit crypto provider —
    /// for a caller that already has one (e.g. to share with the rest of
    /// its `ClientConfig`) and wants to avoid building a second.
    pub fn with_provider(records: Vec<TlsaRecord>, provider: Arc<CryptoProvider>) -> Self {
        Self { records, provider }
    }
}

impl ServerCertVerifier for DaneServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let chain: Vec<&CertificateDer<'_>> =
            std::iter::once(end_entity).chain(intermediates.iter()).collect();

        for record in &self.records {
            match record.usage {
                TlsaUsage::DaneEe => {
                    if matches_record(record, end_entity) {
                        return Ok(ServerCertVerified::assertion());
                    }
                }
                TlsaUsage::DaneTa => {
                    let Some(anchor_idx) = chain.iter().position(|c| matches_record(record, c))
                    else {
                        continue;
                    };
                    if anchor_idx == 0 {
                        // The pinned certificate *is* the presented leaf —
                        // trivially its own anchor, nothing further to chain.
                        return Ok(ServerCertVerified::assertion());
                    }
                    let mut roots = RootCertStore::empty();
                    if roots.add(chain[anchor_idx].clone()).is_err() {
                        continue;
                    }
                    let Ok(webpki) =
                        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&self.provider))
                            .build()
                    else {
                        continue;
                    };
                    let sub_intermediates: Vec<CertificateDer<'_>> =
                        chain[1..anchor_idx].iter().map(|c| (*c).clone()).collect();
                    if webpki
                        .verify_server_cert(end_entity, &sub_intermediates, server_name, ocsp_response, now)
                        .is_ok()
                    {
                        return Ok(ServerCertVerified::assertion());
                    }
                }
                // PKIX-TA(0)/PKIX-EE(1) and any unassigned usage are never
                // matched — see the module doc comment.
                _ => {}
            }
        }

        Err(rustls::Error::General(
            "DANE: no TLSA record matched the presented certificate chain".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Whether `cert`'s selected data (per `record.selector`) matches
/// `record.association_data` (per `record.matching_type`).
fn matches_record(record: &TlsaRecord, cert: &CertificateDer<'_>) -> bool {
    let Some(selected) = selected_data(record.selector, cert.as_ref()) else {
        return false;
    };
    let Some(computed) = hash_selected_data(record.matching_type, &selected) else {
        return false;
    };
    computed == record.association_data
}

/// The bytes a TLSA record's association data is computed over, per its
/// selector (RFC 6698 §2.1.2).
fn selected_data(selector: TlsaSelector, cert_der: &[u8]) -> Option<Vec<u8>> {
    match selector {
        TlsaSelector::FullCertificate => Some(cert_der.to_vec()),
        TlsaSelector::SubjectPublicKeyInfo => extract_spki(cert_der),
        TlsaSelector::Unassigned(_) => None,
    }
}

/// Apply a TLSA matching type to already-selected data (RFC 6698 §2.1.3).
/// `Exact` is the identity function — the association data *is* the
/// selected data, unhashed.
fn hash_selected_data(matching_type: TlsaMatchingType, selected: &[u8]) -> Option<Vec<u8>> {
    match matching_type {
        TlsaMatchingType::Exact => Some(selected.to_vec()),
        TlsaMatchingType::Sha256 => {
            use sha2::{Digest, Sha256};
            Some(Sha256::digest(selected).to_vec())
        }
        TlsaMatchingType::Sha384 => {
            use sha2::{Digest, Sha384};
            Some(Sha384::digest(selected).to_vec())
        }
        TlsaMatchingType::Unassigned(_) => None,
    }
}

/// Compute a TLSA record's association data for `selector`/`matching_type`
/// from a DER-encoded certificate (RFC 6698 §2.1) — the same computation
/// [`DaneServerCertVerifier`] performs internally to check a *presented*
/// certificate against an existing record, exposed here for tooling that
/// needs to *generate* one instead (e.g. computing the record an operator
/// should publish for their own MX certificate). `None` for an
/// [`TlsaSelector::Unassigned`]/[`TlsaMatchingType::Unassigned`] value, or
/// if `cert_der` isn't parseable enough to extract its `SubjectPublicKeyInfo`
/// (only relevant for [`TlsaSelector::SubjectPublicKeyInfo`]).
pub fn compute_association_data(
    selector: TlsaSelector,
    matching_type: TlsaMatchingType,
    cert_der: &[u8],
) -> Option<Vec<u8>> {
    let selected = selected_data(selector, cert_der)?;
    hash_selected_data(matching_type, &selected)
}

/// Read one DER TLV (tag, value, and the offset just past it) at `buf[pos]`.
/// Definite-length form only (short or long) — X.509 certificates never use
/// indefinite length.
fn read_tlv(buf: &[u8], pos: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *buf.get(pos)?;
    let len_byte = *buf.get(pos + 1)?;
    let (len, header_len) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2)
    } else {
        let n = (len_byte & 0x7F) as usize;
        if n == 0 || n > 4 {
            return None; // indefinite length, or a length too large to fit usize sanely
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | (*buf.get(pos + 2 + i)? as usize);
        }
        (len, 2 + n)
    };
    let start = pos.checked_add(header_len)?;
    let end = start.checked_add(len)?;
    let value = buf.get(start..end)?;
    Some((tag, value, end))
}

/// Extract the DER-encoded `SubjectPublicKeyInfo` from an X.509
/// certificate (RFC 5280 §4.1): `Certificate ::= SEQUENCE { tbsCertificate,
/// signatureAlgorithm, signatureValue }`; within `TBSCertificate`, skip the
/// optional `[0] version`, then `serialNumber`, `signature`, `issuer`,
/// `validity`, `subject` to reach `subjectPublicKeyInfo`.
fn extract_spki(cert_der: &[u8]) -> Option<Vec<u8>> {
    const SEQUENCE: u8 = 0x30;
    const CONTEXT_CONSTRUCTED_0: u8 = 0xA0;

    let (tag, cert_body, _) = read_tlv(cert_der, 0)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, tbs, _) = read_tlv(cert_body, 0)?;
    if tag != SEQUENCE {
        return None;
    }

    let mut pos = 0;
    if tbs.first().copied() == Some(CONTEXT_CONSTRUCTED_0) {
        let (_, _, next) = read_tlv(tbs, pos)?;
        pos = next;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        let (_, _, next) = read_tlv(tbs, pos)?;
        pos = next;
    }
    let (tag, _, end) = read_tlv(tbs, pos)?;
    if tag != SEQUENCE {
        return None;
    }
    Some(tbs[pos..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cert() -> CertificateDer<'static> {
        let cert = rcgen::generate_simple_self_signed(vec!["dane.example".to_string()]).unwrap();
        cert.cert.der().clone()
    }

    #[test]
    fn extract_spki_finds_a_sequence_starting_at_a_plausible_offset() {
        let cert = test_cert();
        let spki = extract_spki(cert.as_ref()).expect("should extract an SPKI");
        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey (BIT STRING) }
        assert_eq!(spki[0], 0x30, "SPKI must be a SEQUENCE");
        let (tag, alg, next) = read_tlv(&spki, 2).unwrap();
        assert_eq!(tag, 0x30, "AlgorithmIdentifier must be a SEQUENCE");
        assert!(!alg.is_empty());
        let (tag, _, _) = read_tlv(&spki, next).unwrap();
        assert_eq!(tag, 0x03, "subjectPublicKey must be a BIT STRING");
    }

    #[test]
    fn extract_spki_is_a_strict_prefix_of_a_different_length_than_the_full_cert() {
        let cert = test_cert();
        let spki = extract_spki(cert.as_ref()).unwrap();
        // Sanity: the SPKI is a genuine substring of the certificate, and
        // strictly shorter than the whole thing (it's one field among
        // several in tbsCertificate).
        assert!(spki.len() < cert.as_ref().len());
        assert!(
            cert.as_ref().windows(spki.len()).any(|w| w == spki.as_slice()),
            "extracted SPKI bytes must appear verbatim in the certificate"
        );
    }

    #[test]
    fn extract_spki_rejects_garbage() {
        assert!(extract_spki(&[]).is_none());
        assert!(extract_spki(&[0x30, 0x00]).is_none()); // empty outer SEQUENCE, no tbsCertificate
        assert!(extract_spki(&[0x02, 0x01, 0x01]).is_none()); // not even a SEQUENCE
    }

    #[test]
    fn compute_association_data_full_cert_exact_is_the_raw_certificate_bytes() {
        let cert = test_cert();
        let computed = compute_association_data(
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Exact,
            cert.as_ref(),
        )
        .unwrap();
        assert_eq!(computed, cert.as_ref().to_vec());
    }

    #[test]
    fn compute_association_data_sha256_matches_an_independently_computed_digest() {
        use sha2::{Digest, Sha256};
        let cert = test_cert();
        let computed = compute_association_data(
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            cert.as_ref(),
        )
        .unwrap();
        let expected = Sha256::digest(cert.as_ref()).to_vec();
        assert_eq!(computed, expected);
    }

    #[test]
    fn compute_association_data_is_none_for_unassigned_selector_or_matching_type() {
        let cert = test_cert();
        assert!(compute_association_data(
            TlsaSelector::Unassigned(200),
            TlsaMatchingType::Sha256,
            cert.as_ref()
        )
        .is_none());
        assert!(compute_association_data(
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Unassigned(200),
            cert.as_ref()
        )
        .is_none());
    }

    /// The property that actually matters for a record-generation tool:
    /// what it computes must be exactly what [`DaneServerCertVerifier`]
    /// accepts for the same certificate — "generate" and "verify" must
    /// agree, not just each run without error.
    #[test]
    fn compute_association_data_round_trips_through_the_verifier() {
        let cert = test_cert();
        for (selector, matching_type) in [
            (TlsaSelector::FullCertificate, TlsaMatchingType::Exact),
            (TlsaSelector::FullCertificate, TlsaMatchingType::Sha256),
            (TlsaSelector::FullCertificate, TlsaMatchingType::Sha384),
            (TlsaSelector::SubjectPublicKeyInfo, TlsaMatchingType::Sha256),
            (TlsaSelector::SubjectPublicKeyInfo, TlsaMatchingType::Sha384),
        ] {
            let association_data =
                compute_association_data(selector, matching_type, cert.as_ref()).unwrap();
            let record = TlsaRecord {
                usage: TlsaUsage::DaneEe,
                selector,
                matching_type,
                association_data,
            };
            let verifier = DaneServerCertVerifier::new(vec![record]);
            let name = ServerName::try_from("dane.example").unwrap();
            assert!(
                verifier
                    .verify_server_cert(&cert, &[], &name, &[], unix_now())
                    .is_ok(),
                "selector={selector:?} matching_type={matching_type:?}"
            );
        }
    }

    fn dane_ee_record(matching_type: TlsaMatchingType, association_data: Vec<u8>) -> TlsaRecord {
        TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::FullCertificate,
            matching_type,
            association_data,
        }
    }

    fn unix_now() -> UnixTime {
        UnixTime::since_unix_epoch(std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap())
    }

    #[test]
    fn dane_ee_exact_match_accepts_the_pinned_leaf_certificate() {
        let cert = test_cert();
        let record = dane_ee_record(TlsaMatchingType::Exact, cert.as_ref().to_vec());
        let verifier = DaneServerCertVerifier::new(vec![record]);
        let name = ServerName::try_from("dane.example").unwrap();
        assert!(verifier
            .verify_server_cert(&cert, &[], &name, &[], unix_now())
            .is_ok());
    }

    #[test]
    fn dane_ee_sha256_match_accepts_the_pinned_leaf_certificate() {
        use sha2::{Digest, Sha256};
        let cert = test_cert();
        let digest = Sha256::digest(cert.as_ref()).to_vec();
        let record = dane_ee_record(TlsaMatchingType::Sha256, digest);
        let verifier = DaneServerCertVerifier::new(vec![record]);
        let name = ServerName::try_from("dane.example").unwrap();
        assert!(verifier
            .verify_server_cert(&cert, &[], &name, &[], unix_now())
            .is_ok());
    }

    #[test]
    fn dane_ee_spki_selector_accepts_a_renewed_certificate_with_the_same_key() {
        use sha2::{Digest, Sha256};
        // Two different self-signed certs sharing the *same* key pair —
        // simulates certificate renewal without a key rollover, exactly
        // the case RFC 7672 recommends selector=SPKI for.
        let key = rcgen::KeyPair::generate().unwrap();
        let params1 = rcgen::CertificateParams::new(vec!["dane.example".to_string()]).unwrap();
        let cert1 = params1.self_signed(&key).unwrap();
        let params2 = rcgen::CertificateParams::new(vec!["dane.example".to_string()]).unwrap();
        let cert2 = params2.self_signed(&key).unwrap();
        assert_ne!(cert1.der(), cert2.der(), "test needs two distinct certificates");

        let spki = extract_spki(cert1.der().as_ref()).unwrap();
        let digest = Sha256::digest(&spki).to_vec();
        let record = TlsaRecord {
            usage: TlsaUsage::DaneEe,
            selector: TlsaSelector::SubjectPublicKeyInfo,
            matching_type: TlsaMatchingType::Sha256,
            association_data: digest,
        };
        let verifier = DaneServerCertVerifier::new(vec![record]);
        let name = ServerName::try_from("dane.example").unwrap();
        // The *other* certificate (different serial/validity, same key)
        // must also verify, since the pin is on the key, not the cert.
        assert!(verifier
            .verify_server_cert(cert2.der(), &[], &name, &[], unix_now())
            .is_ok());
    }

    #[test]
    fn dane_ee_rejects_a_non_matching_certificate() {
        let cert = test_cert();
        let other = test_cert();
        let record = dane_ee_record(TlsaMatchingType::Exact, other.as_ref().to_vec());
        let verifier = DaneServerCertVerifier::new(vec![record]);
        let name = ServerName::try_from("dane.example").unwrap();
        assert!(verifier
            .verify_server_cert(&cert, &[], &name, &[], unix_now())
            .is_err());
    }

    #[test]
    fn pkix_ta_and_pkix_ee_records_are_never_matched() {
        // Even a byte-for-byte-correct usage-0/1 record must not
        // authenticate anything — RFC 7672 §3.1.2 scope boundary (see the
        // module doc comment).
        let cert = test_cert();
        for usage in [TlsaUsage::PkixTa, TlsaUsage::PkixEe, TlsaUsage::Unassigned(200)] {
            let record = TlsaRecord {
                usage,
                selector: TlsaSelector::FullCertificate,
                matching_type: TlsaMatchingType::Exact,
                association_data: cert.as_ref().to_vec(),
            };
            let verifier = DaneServerCertVerifier::new(vec![record]);
            let name = ServerName::try_from("dane.example").unwrap();
            assert!(
                verifier.verify_server_cert(&cert, &[], &name, &[], unix_now()).is_err(),
                "usage {usage:?} must never be matched"
            );
        }
    }

    #[test]
    fn dane_ta_matches_a_pinned_intermediate_and_validates_the_chain_up_to_it() {
        // A tiny CA hierarchy: root -> intermediate -> leaf. Pin the
        // intermediate via DANE-TA; the verifier must accept the leaf
        // *because* it chains validly to the pinned intermediate, not just
        // because the intermediate's bytes are present somewhere.
        let root_key = rcgen::KeyPair::generate().unwrap();
        let mut root_params = rcgen::CertificateParams::new(vec![]).unwrap();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let intermediate_key = rcgen::KeyPair::generate().unwrap();
        let mut intermediate_params = rcgen::CertificateParams::new(vec![]).unwrap();
        intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_key, &root_cert, &root_key)
            .unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["dane.example".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &intermediate_cert, &intermediate_key).unwrap();

        let record = TlsaRecord {
            usage: TlsaUsage::DaneTa,
            selector: TlsaSelector::FullCertificate,
            matching_type: TlsaMatchingType::Exact,
            association_data: intermediate_cert.der().as_ref().to_vec(),
        };
        let verifier = DaneServerCertVerifier::new(vec![record]);
        let name = ServerName::try_from("dane.example").unwrap();
        let leaf_der = leaf_cert.der().clone();
        let intermediate_der = intermediate_cert.der().clone();
        assert!(
            verifier
                .verify_server_cert(&leaf_der, &[intermediate_der], &name, &[], unix_now())
                .is_ok(),
            "leaf chaining validly to the pinned intermediate must be accepted"
        );
    }

    #[test]
    fn dane_ta_rejects_a_leaf_that_does_not_actually_chain_to_the_pinned_certificate() {
        // The pinned certificate's bytes are present in the chain, but the
        // leaf was NOT actually issued by it (unrelated key) — must be
        // rejected. This is the actual security property DANE-TA needs:
        // presence isn't enough, the signature chain must be real.
        let root_key = rcgen::KeyPair::generate().unwrap();
        let mut root_params = rcgen::CertificateParams::new(vec![]).unwrap();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();

        // "Intermediate" that will be pinned, but the leaf below is signed
        // by an unrelated, uninvolved key — not this intermediate.
        let intermediate_key = rcgen::KeyPair::generate().unwrap();
        let mut intermediate_params = rcgen::CertificateParams::new(vec![]).unwrap();
        intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_key, &root_cert, &root_key)
            .unwrap();

        let unrelated_leaf = test_cert(); // self-signed, unrelated to the intermediate above

        let record = TlsaRecord {
            usage: TlsaUsage::DaneTa,
            selector: TlsaSelector::FullCertificate,
            matching_type: TlsaMatchingType::Exact,
            association_data: intermediate_cert.der().as_ref().to_vec(),
        };
        let verifier = DaneServerCertVerifier::new(vec![record]);
        let name = ServerName::try_from("dane.example").unwrap();
        let intermediate_der = intermediate_cert.der().clone();
        assert!(
            verifier
                .verify_server_cert(&unrelated_leaf, &[intermediate_der], &name, &[], unix_now())
                .is_err(),
            "an unrelated leaf must not be accepted just because the pinned cert's bytes are somewhere in the chain"
        );
    }
}
