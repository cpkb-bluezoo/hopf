// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DANE (RFC 6698/7672) TLSA lookup and usability classification for
//! outbound relay delivery (issue #353).
//!
//! This decides *whether* DANE applies to a given MX host and, if so,
//! *which* TLSA records to authenticate against — the actual certificate
//! matching is [`hopf_dns::dane::DaneServerCertVerifier`] (issue #352);
//! DNSSEC validation is `hopf_dns`'s existing `dnssec` module. This is the
//! RFC 7672 §2.1-2.2 policy glue between the two, kept separate from
//! [`super::handler`] so the classification itself — the part a bug would
//! most dangerously hide in — is a small, pure, directly testable function.

use std::sync::Arc;

use hopf_dns::dnssec::DnssecStatus;
use hopf_dns::{DnsClass, DnsQuestion, DnsResolver, DnsType, TlsaRecord};

/// Whether DANE authentication applies to a dial, per RFC 7672 §2.1-2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DaneUsability {
    /// DNSSEC-Secure and TLSA records exist: STARTTLS and certificate
    /// matching against these records become mandatory for this host.
    Usable(Vec<TlsaRecord>),
    /// Not usable — either a DNSSEC-Secure authenticated denial (no TLSA
    /// records really exist), or the answer's DNSSEC status is Bogus or
    /// Indeterminate (no configured validator, or validation failed).
    /// Ordinary opportunistic TLS applies here; this must never be read
    /// as "DANE says no TLS is needed" — it's "DANE doesn't apply."
    NotUsable,
}

/// Pure RFC 7672 §2.1-2.2 classification — no I/O. `status` is whichever
/// DNSSEC validation applies to the TLSA answer actually received:
/// [`DnsResolver::validate_chain_of_trust`] if `records` came back
/// non-empty (authenticating the RRset itself), or
/// [`DnsResolver::validate_denial_of_existence`] if the answer had none
/// (authenticating the absence).
pub(crate) fn classify(status: DnssecStatus, records: Vec<TlsaRecord>) -> DaneUsability {
    if status == DnssecStatus::Secure && !records.is_empty() {
        DaneUsability::Usable(records)
    } else {
        DaneUsability::NotUsable
    }
}

/// Look up TLSA at `_<port>._tcp.<host>` and classify DANE usability for
/// it. Never fails outright — a lookup or validation problem just
/// resolves to [`DaneUsability::NotUsable`], the safe default (same as
/// "DANE doesn't apply here, use ordinary opportunistic TLS").
pub(crate) fn lookup_dane_usability(
    dns: &Arc<DnsResolver>,
    host: &str,
    port: u16,
    cb: Box<dyn FnOnce(DaneUsability) + Send>,
) {
    let name = format!("_{port}._tcp.{host}");
    let dns2 = Arc::clone(dns);
    let name2 = name.clone();
    dns.query(
        DnsQuestion::new(name, DnsType::Tlsa, DnsClass::In),
        Box::new(move |result| {
            let Ok(msg) = result else {
                cb(DaneUsability::NotUsable);
                return;
            };
            let records: Vec<TlsaRecord> =
                msg.answers.iter().filter_map(|rr| rr.as_tlsa()).collect();
            if records.is_empty() {
                dns2.validate_denial_of_existence(
                    &name2,
                    DnsType::Tlsa,
                    msg,
                    Box::new(move |_msg, status| cb(classify(status, Vec::new()))),
                );
            } else {
                dns2.validate_chain_of_trust(
                    &name2,
                    msg,
                    Box::new(move |_msg, status| cb(classify(status, records))),
                );
            }
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlsa(usage_byte: u8) -> TlsaRecord {
        use hopf_dns::{TlsaMatchingType, TlsaSelector, TlsaUsage};
        let usage = match usage_byte {
            2 => TlsaUsage::DaneTa,
            3 => TlsaUsage::DaneEe,
            other => TlsaUsage::Unassigned(other),
        };
        TlsaRecord {
            usage,
            selector: TlsaSelector::FullCertificate,
            matching_type: TlsaMatchingType::Exact,
            association_data: vec![1, 2, 3],
        }
    }

    #[test]
    fn secure_with_records_is_usable() {
        let usability = classify(DnssecStatus::Secure, vec![tlsa(3)]);
        assert_eq!(usability, DaneUsability::Usable(vec![tlsa(3)]));
    }

    #[test]
    fn secure_denial_with_no_records_is_not_usable() {
        assert_eq!(classify(DnssecStatus::Secure, Vec::new()), DaneUsability::NotUsable);
    }

    #[test]
    fn bogus_is_never_usable_even_with_records_present() {
        // The critical security property: a Bogus (failed) validation must
        // never be trusted just because *some* TLSA answer arrived — an
        // attacker able to inject/corrupt DNS responses could otherwise
        // supply forged TLSA records to whatever end they like, and Bogus
        // is exactly the signal that this answer can't be trusted at all.
        assert_eq!(classify(DnssecStatus::Bogus, vec![tlsa(3)]), DaneUsability::NotUsable);
    }

    #[test]
    fn insecure_unsigned_zone_is_never_usable() {
        // No DS record / unsigned zone — a legitimate, common case, not an
        // attack — but still can't prove the TLSA answer is authentic.
        assert_eq!(classify(DnssecStatus::Insecure, vec![tlsa(3)]), DaneUsability::NotUsable);
    }

    #[test]
    fn indeterminate_is_never_usable() {
        // No DNSSEC validator configured, or the zone isn't signed — must
        // fall back to ordinary opportunistic TLS, not be treated as
        // "confirmed no TLSA records."
        assert_eq!(
            classify(DnssecStatus::Indeterminate, Vec::new()),
            DaneUsability::NotUsable
        );
        assert_eq!(
            classify(DnssecStatus::Indeterminate, vec![tlsa(3)]),
            DaneUsability::NotUsable
        );
    }
}
