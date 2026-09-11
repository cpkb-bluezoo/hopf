// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DANE (RFC 6698/7672) certificate verification against TLSA records
//! (issue #352, feature `dane`).
//!
//! [`verify_dane_chain`] has no dependency on `rustls` — it takes a plain
//! DER certificate chain and plugs into
//! [`hopf_core::connector_with_verify_override`] as a verification
//! callback (see `hopf-smtp`'s relay handler for the real, in-production
//! use). An earlier `rustls`-based `ServerCertVerifier` implementation of
//! this same matching logic existed here before the crypto-migration
//! moved this crate's TLS engine off `rustls`; it was removed once
//! nothing constructed it any more — everything routes through
//! `hopf-core`'s own TLS stack now, so a second, `rustls`-specific
//! verifier had no real caller left.
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

use crate::wire::{TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage};

/// Whether `cert_der`'s selected data (per `record.selector`) matches
/// `record.association_data` (per `record.matching_type`) — what
/// [`verify_dane_chain`] uses.
fn matches_record_der(record: &TlsaRecord, cert_der: &[u8]) -> bool {
    let Some(selected) = selected_data(record.selector, cert_der) else {
        return false;
    };
    let Some(computed) = hash_selected_data(record.matching_type, &selected) else {
        return false;
    };
    computed == record.association_data
}

/// Verify a presented certificate chain (DER, leaf first) against `records`
/// (RFC 6698 §2.1) with no dependency on `rustls` — the shape
/// [`hopf_core::connector_with_verify_override`] needs. Same matching rules
/// as [`DaneServerCertVerifier`] (see that type's docs: only DANE-TA(2) and
/// DANE-EE(3) are matched; DANE-TA re-chains the rest of the presented chain
/// up to the pinned anchor using [`hopf_core::crypto::trust::TrustStore`]
/// instead of `rustls`'s `WebPkiServerVerifier`).
pub fn verify_dane_chain(records: &[TlsaRecord], chain: &[hopf_core::Bytes], server_name: Option<&str>) -> bool {
    let Some(leaf) = chain.first() else {
        return false;
    };
    for record in records {
        match record.usage {
            TlsaUsage::DaneEe => {
                if matches_record_der(record, leaf) {
                    return true;
                }
            }
            TlsaUsage::DaneTa => {
                let Some(anchor_idx) = chain.iter().position(|c| matches_record_der(record, c)) else {
                    continue;
                };
                if anchor_idx == 0 {
                    // The pinned certificate *is* the presented leaf —
                    // trivially its own anchor, nothing further to chain.
                    return true;
                }
                let mut trust = hopf_core::crypto::trust::TrustStore::new();
                trust.add_anchor(chain[anchor_idx].clone());
                if trust.verify_server_chain(&chain[..=anchor_idx], server_name).is_ok() {
                    return true;
                }
            }
            // PKIX-TA(0)/PKIX-EE(1) and any unassigned usage are never
            // matched — see the module doc comment.
            _ => {}
        }
    }
    false
}

/// The bytes a TLSA record's association data is computed over, per its
/// selector (RFC 6698 §2.1.2).
fn selected_data(selector: TlsaSelector, cert_der: &[u8]) -> Option<Vec<u8>> {
    match selector {
        TlsaSelector::FullCertificate => Some(cert_der.to_vec()),
        TlsaSelector::SubjectPublicKeyInfo => {
            hopf_core::crypto::cert::extract_spki(cert_der).map(|spki| spki.to_vec())
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::crypto::cert::extract_spki;
    use hopf_core::Bytes;

    fn test_cert() -> Bytes {
        let cert = rcgen::generate_simple_self_signed(vec!["dane.example".to_string()]).unwrap();
        Bytes::copy_from_slice(cert.cert.der())
    }

    #[test]
    fn extract_spki_finds_a_sequence_starting_at_a_plausible_offset() {
        let cert = test_cert();
        let spki = extract_spki(cert.as_ref()).expect("should extract an SPKI");
        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey (BIT STRING) }
        assert_eq!(spki[0], 0x30, "SPKI must be a SEQUENCE");
        let mut seq = hopf_core::asn1::parse_sequence(&spki).unwrap();
        let alg = seq.next().unwrap();
        assert_eq!(alg[0], 0x30, "AlgorithmIdentifier must be a SEQUENCE");
        assert!(alg.len() > 2);
        let subject_public_key = seq.next().unwrap();
        assert_eq!(subject_public_key[0], 0x03, "subjectPublicKey must be a BIT STRING");
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
            cert.as_ref().windows(spki.len()).any(|w| w == spki.as_ref()),
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
    /// what it computes must be exactly what [`verify_dane_chain`]
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
            assert!(
                verify_dane_chain(&[record], &[cert.clone()], Some("dane.example")),
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

    #[test]
    fn dane_ee_exact_match_accepts_the_pinned_leaf_certificate() {
        let cert = test_cert();
        let record = dane_ee_record(TlsaMatchingType::Exact, cert.as_ref().to_vec());
        assert!(verify_dane_chain(&[record], &[cert], Some("dane.example")));
    }

    #[test]
    fn dane_ee_sha256_match_accepts_the_pinned_leaf_certificate() {
        use sha2::{Digest, Sha256};
        let cert = test_cert();
        let digest = Sha256::digest(cert.as_ref()).to_vec();
        let record = dane_ee_record(TlsaMatchingType::Sha256, digest);
        assert!(verify_dane_chain(&[record], &[cert], Some("dane.example")));
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
        // The *other* certificate (different serial/validity, same key)
        // must also verify, since the pin is on the key, not the cert.
        let cert2_bytes = Bytes::copy_from_slice(cert2.der());
        assert!(verify_dane_chain(&[record], &[cert2_bytes], Some("dane.example")));
    }

    #[test]
    fn dane_ee_rejects_a_non_matching_certificate() {
        let cert = test_cert();
        let other = test_cert();
        let record = dane_ee_record(TlsaMatchingType::Exact, other.as_ref().to_vec());
        assert!(!verify_dane_chain(&[record], &[cert], Some("dane.example")));
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
            assert!(
                !verify_dane_chain(&[record], &[cert.clone()], Some("dane.example")),
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
        let leaf_bytes = Bytes::copy_from_slice(leaf_cert.der());
        let intermediate_bytes = Bytes::copy_from_slice(intermediate_cert.der());
        assert!(
            verify_dane_chain(&[record], &[leaf_bytes, intermediate_bytes], Some("dane.example")),
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
        let intermediate_bytes = Bytes::copy_from_slice(intermediate_cert.der());
        assert!(
            !verify_dane_chain(&[record], &[unrelated_leaf, intermediate_bytes], Some("dane.example")),
            "an unrelated leaf must not be accepted just because the pinned cert's bytes are somewhere in the chain"
        );
    }
}
