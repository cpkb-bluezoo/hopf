// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-memory DNS response cache (TTL + negative NXDOMAIN).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::wire::{DnsClass, DnsQuestion, DnsResourceRecord, DnsType, RCODE_NXDOMAIN, DnsMessage};

#[cfg(feature = "dnssec")]
use crate::dnssec::DnssecStatus;

const DEFAULT_MAX_ENTRIES: usize = 10_000;
const DEFAULT_NEGATIVE_TTL: u32 = 300;

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: String,
    qtype: u16,
    qclass: u16,
    negative: bool,
}

impl CacheKey {
    fn from_question(q: &DnsQuestion) -> Self {
        Self {
            name: crate::wire::normalize_name(&q.name),
            qtype: q.raw_qtype,
            qclass: q.raw_qclass,
            negative: false,
        }
    }

    /// NXDOMAIN: the name itself doesn't exist, so no query type for it
    /// ever resolves — scoped by name only, ignoring qtype/qclass.
    fn negative(name: &str) -> Self {
        Self {
            name: crate::wire::normalize_name(name),
            qtype: DnsType::Any.value(),
            qclass: DnsClass::In.value(),
            negative: true,
        }
    }

    /// NODATA (RFC 2308 §2): the name exists but has no records of this
    /// specific qtype — unlike NXDOMAIN, this must stay scoped per
    /// qtype/qclass (NODATA for MX says nothing about A at the same name).
    fn nodata(q: &DnsQuestion) -> Self {
        Self {
            name: crate::wire::normalize_name(&q.name),
            qtype: q.raw_qtype,
            qclass: q.raw_qclass,
            negative: true,
        }
    }
}

struct CacheEntry {
    records: Vec<DnsResourceRecord>,
    cached_at: Instant,
    ttl: u32,
    #[cfg(feature = "dnssec")]
    #[allow(dead_code)]
    dnssec_status: Option<DnssecStatus>,
}

impl CacheEntry {
    fn expiry(&self) -> Instant {
        self.cached_at + Duration::from_secs(self.ttl as u64)
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expiry()
    }

    fn adjusted(&self) -> Vec<DnsResourceRecord> {
        let elapsed = Instant::now()
            .duration_since(self.cached_at)
            .as_secs()
            .min(u64::from(u32::MAX)) as u32;
        self.records
            .iter()
            .map(|rr| {
                let remain = rr.ttl.saturating_sub(elapsed);
                rr.with_ttl(remain)
            })
            .collect()
    }
}

/// Process-shared DNS cache.
pub struct DnsCache {
    inner: Mutex<HashMap<CacheKey, CacheEntry>>,
    max_entries: usize,
    negative_ttl: u32,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES, DEFAULT_NEGATIVE_TTL)
    }
}

impl DnsCache {
    /// Create a cache.
    pub fn new(max_entries: usize, negative_ttl: u32) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries,
            negative_ttl,
        }
    }

    /// Lookup positive answers.
    pub fn lookup(&self, question: &DnsQuestion) -> Option<Vec<DnsResourceRecord>> {
        let key = CacheKey::from_question(question);
        let mut g = self.inner.lock().unwrap();
        let entry = g.get(&key)?;
        if entry.is_expired() {
            g.remove(&key);
            return None;
        }
        Some(entry.adjusted())
    }

    /// NXDOMAIN cached?
    pub fn is_negatively_cached(&self, name: &str) -> bool {
        let key = CacheKey::negative(name);
        let mut g = self.inner.lock().unwrap();
        match g.get(&key) {
            Some(e) if !e.is_expired() => true,
            Some(_) => {
                g.remove(&key);
                false
            }
            None => false,
        }
    }

    /// NODATA cached for this exact question (RFC 2308 §2)?
    pub fn is_nodata_cached(&self, question: &DnsQuestion) -> bool {
        let key = CacheKey::nodata(question);
        let mut g = self.inner.lock().unwrap();
        match g.get(&key) {
            Some(e) if !e.is_expired() => true,
            Some(_) => {
                g.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Store records / negative from a response message.
    pub fn put_response(&self, response: &DnsMessage) {
        if response.questions.is_empty() {
            return;
        }
        let q = &response.questions[0];
        if response.rcode() == RCODE_NXDOMAIN {
            let ttl = self
                .authorities_soa_minimum(&response.authorities)
                .unwrap_or(self.negative_ttl);
            self.put_negative(&q.name, ttl);
            return;
        }
        if response.rcode() != 0 {
            return;
        }
        if response.answers.is_empty() {
            // RFC 2308 §2 NODATA: NOERROR with an empty answer set — the
            // name exists but has nothing of this qtype. Same SOA-MINIMUM
            // TTL derivation as NXDOMAIN, just scoped per-question instead
            // of per-name.
            let ttl = self
                .authorities_soa_minimum(&response.authorities)
                .unwrap_or(self.negative_ttl);
            self.put_nodata(q, ttl);
            return;
        }
        let ttl = response
            .answers
            .iter()
            .map(|rr| rr.ttl)
            .min()
            .unwrap_or(0);
        if ttl == 0 {
            return;
        }
        self.put(q, response.answers.clone(), ttl);
    }

    /// Store positive records.
    pub fn put(&self, question: &DnsQuestion, records: Vec<DnsResourceRecord>, ttl: u32) {
        let key = CacheKey::from_question(question);
        let mut g = self.inner.lock().unwrap();
        if g.len() >= self.max_entries && !g.contains_key(&key) {
            // Simple eviction: drop an arbitrary expired or first key.
            let victim = g
                .iter()
                .find(|(_, e)| e.is_expired())
                .map(|(k, _)| k.clone())
                .or_else(|| g.keys().next().cloned());
            if let Some(v) = victim {
                g.remove(&v);
            }
        }
        g.insert(
            key,
            CacheEntry {
                records,
                cached_at: Instant::now(),
                ttl,
                #[cfg(feature = "dnssec")]
                dnssec_status: None,
            },
        );
    }

    fn put_negative(&self, name: &str, ttl: u32) {
        let key = CacheKey::negative(name);
        let mut g = self.inner.lock().unwrap();
        g.insert(
            key,
            CacheEntry {
                records: Vec::new(),
                cached_at: Instant::now(),
                ttl,
                #[cfg(feature = "dnssec")]
                dnssec_status: None,
            },
        );
    }

    fn put_nodata(&self, question: &DnsQuestion, ttl: u32) {
        let key = CacheKey::nodata(question);
        let mut g = self.inner.lock().unwrap();
        g.insert(
            key,
            CacheEntry {
                records: Vec::new(),
                cached_at: Instant::now(),
                ttl,
                #[cfg(feature = "dnssec")]
                dnssec_status: None,
            },
        );
    }

    fn authorities_soa_minimum(&self, authorities: &[DnsResourceRecord]) -> Option<u32> {
        authorities.iter().find_map(|rr| rr.as_soa().map(|soa| soa.minimum.min(rr.ttl)))
    }

    /// Entry count (testing).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsMessage, DnsQuestion, DnsResourceRecord, DnsType, FLAG_QR, RCODE_NXDOMAIN};
    use std::net::Ipv4Addr;

    #[test]
    fn put_lookup_and_negative() {
        let cache = DnsCache::new(16, 30);
        let q = DnsQuestion::in_class("Ex.Test.", DnsType::A);
        let rr = DnsResourceRecord::a("ex.test.", 120, Ipv4Addr::new(9, 9, 9, 9));
        cache.put(&q, vec![rr], 120);
        let hit = cache.lookup(&q).unwrap();
        assert_eq!(hit[0].as_a().unwrap(), Ipv4Addr::new(9, 9, 9, 9));
        assert!(!cache.is_empty());

        let nx = DnsMessage::new(
            1,
            FLAG_QR | RCODE_NXDOMAIN,
            vec![DnsQuestion::in_class("missing.test.", DnsType::A)],
            vec![],
            vec![],
            vec![],
        );
        cache.put_response(&nx);
        assert!(cache.is_negatively_cached("Missing.Test."));
    }

    /// RFC 2308 §2 NODATA (NOERROR with an empty answer set) gets cached,
    /// distinct from NXDOMAIN and scoped per-qtype — a NODATA for A must
    /// not make an MX query at the same name look negatively cached too.
    #[test]
    fn nodata_response_is_cached_and_scoped_per_qtype() {
        let cache = DnsCache::new(16, 30);
        let a_question = DnsQuestion::in_class("nodata.test.", DnsType::A);
        let nodata = DnsMessage::new(1, FLAG_QR, vec![a_question.clone()], vec![], vec![], vec![]);
        cache.put_response(&nodata);

        assert!(cache.is_nodata_cached(&a_question), "NODATA for A must be cached");
        assert!(
            !cache.is_negatively_cached("nodata.test."),
            "NODATA must not be conflated with NXDOMAIN"
        );
        assert!(cache.lookup(&a_question).is_none(), "NODATA has no positive answers to return");

        let mx_question = DnsQuestion::in_class("nodata.test.", DnsType::Mx);
        assert!(
            !cache.is_nodata_cached(&mx_question),
            "NODATA for A must not apply to a different qtype at the same name"
        );
    }

    #[test]
    fn eviction_when_full() {
        let cache = DnsCache::new(1, 30);
        let q1 = DnsQuestion::in_class("a.test.", DnsType::A);
        let q2 = DnsQuestion::in_class("b.test.", DnsType::A);
        cache.put(
            &q1,
            vec![DnsResourceRecord::a("a.test.", 60, Ipv4Addr::LOCALHOST)],
            60,
        );
        cache.put(
            &q2,
            vec![DnsResourceRecord::a("b.test.", 60, Ipv4Addr::LOCALHOST)],
            60,
        );
        assert_eq!(cache.len(), 1);
    }
}

