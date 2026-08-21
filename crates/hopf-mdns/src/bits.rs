// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 6762 high-bit conventions layered on `hopf-dns`'s wire types — the
//! QU "unicast response requested" bit (§5.4, top bit of a question's
//! QCLASS) and the cache-flush bit (§10.2, top bit of a resource record's
//! CLASS). Neither needs any change to `hopf-dns` itself: `DnsQuestion`/
//! `DnsResourceRecord` already carry the full raw wire value in
//! `raw_qclass`/`raw_class`, and `DnsMessage::serialize`/`parse` round-trip
//! it untouched — these are pure bitmasking helpers over those fields.
//!
//! mDNS code must always read `raw_qclass`/`raw_class` directly, never the
//! parsed `qclass`/`rclass` — a class value with either high bit set
//! (e.g. IN=1 with the top bit on is `0x8001`) matches no `DnsClass`
//! variant and parses to `None`, by design (RFC 3597 unknown-value
//! preservation), not a bug to work around here.

use hopf_dns::wire::{DnsQuestion, DnsResourceRecord};

/// RFC 6762 §5.4: top bit of QCLASS.
const QU_BIT: u16 = 0x8000;
/// RFC 6762 §10.2: top bit of a resource record's CLASS.
const CACHE_FLUSH_BIT: u16 = 0x8000;
/// Mask recovering the true class from a QU/cache-flush-bit-tagged value.
const CLASS_MASK: u16 = 0x7FFF;

/// Whether a question requests a unicast (rather than multicast) reply.
pub fn unicast_response_requested(q: &DnsQuestion) -> bool {
    q.raw_qclass & QU_BIT != 0
}

/// The question's class with the QU bit (if any) masked off.
pub fn question_class(q: &DnsQuestion) -> u16 {
    q.raw_qclass & CLASS_MASK
}

/// Set (or clear) the QU bit on a question's raw QCLASS.
pub fn with_unicast_response_requested(mut q: DnsQuestion, requested: bool) -> DnsQuestion {
    q.raw_qclass = if requested {
        q.raw_qclass | QU_BIT
    } else {
        q.raw_qclass & !QU_BIT
    };
    q
}

/// Whether a resource record asserts "this is the complete RRset" (RFC
/// 6762 §10.2) — a responder's cue to the querier to flush any cached
/// records for this name/type not present in the same message.
pub fn cache_flush(rr: &DnsResourceRecord) -> bool {
    rr.raw_class & CACHE_FLUSH_BIT != 0
}

/// The record's class with the cache-flush bit (if any) masked off.
pub fn record_class(rr: &DnsResourceRecord) -> u16 {
    rr.raw_class & CLASS_MASK
}

/// Set the cache-flush bit on a resource record's raw CLASS.
pub fn with_cache_flush(mut rr: DnsResourceRecord) -> DnsResourceRecord {
    rr.raw_class |= CACHE_FLUSH_BIT;
    rr
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_dns::wire::{DnsClass, DnsMessage, DnsResourceRecord, DnsType};
    use std::net::Ipv4Addr;

    #[test]
    fn qu_bit_round_trips_through_the_wire() {
        let q = DnsQuestion::in_class("example.local", DnsType::A);
        assert!(!unicast_response_requested(&q));
        assert_eq!(question_class(&q), DnsClass::In.value());

        let q = with_unicast_response_requested(q, true);
        assert!(unicast_response_requested(&q));
        // The true class must still recover correctly under the tag.
        assert_eq!(question_class(&q), DnsClass::In.value());

        let msg = DnsMessage::query(0, q, true);
        let bytes = msg.serialize().unwrap();
        let parsed = DnsMessage::parse(&bytes).unwrap();
        let parsed_q = &parsed.questions[0];
        assert!(unicast_response_requested(parsed_q));
        assert_eq!(question_class(parsed_q), DnsClass::In.value());
        // The parsed `qclass` enum, by contrast, does NOT recognize the
        // tagged value -- documented, not a bug (see module doc comment).
        assert_eq!(parsed_q.qclass, None);

        let cleared = with_unicast_response_requested(parsed.questions[0].clone(), false);
        assert!(!unicast_response_requested(&cleared));
    }

    #[test]
    fn cache_flush_bit_round_trips_through_the_wire() {
        let rr = DnsResourceRecord::a("example.local", 120, Ipv4Addr::new(192, 0, 2, 1));
        assert!(!cache_flush(&rr));
        assert_eq!(record_class(&rr), DnsClass::In.value());

        let rr = with_cache_flush(rr);
        assert!(cache_flush(&rr));
        assert_eq!(record_class(&rr), DnsClass::In.value());

        let mut msg = DnsMessage::query(0, DnsQuestion::in_class("example.local", DnsType::A), true);
        msg.answers.push(rr);
        let bytes = msg.serialize().unwrap();
        let parsed = DnsMessage::parse(&bytes).unwrap();
        let parsed_rr = &parsed.answers[0];
        assert!(cache_flush(parsed_rr));
        assert_eq!(record_class(parsed_rr), DnsClass::In.value());
        assert_eq!(parsed_rr.rclass, None);
    }
}
