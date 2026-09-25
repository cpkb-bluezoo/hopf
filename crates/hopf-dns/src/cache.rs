// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-memory DNS response cache (TTL, negative NXDOMAIN/NODATA, and a bounded
//! stale window for RFC 8767 Serve-Stale).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::wire::{DnsClass, DnsQuestion, DnsResourceRecord, DnsType, RCODE_NXDOMAIN, DnsMessage};

#[cfg(feature = "dnssec")]
use crate::dnssec::DnssecStatus;

const DEFAULT_MAX_ENTRIES: usize = 10_000;
const DEFAULT_NEGATIVE_TTL: u32 = 300;
/// How long past expiry a positive entry is kept for Serve-Stale: RFC 8767 §5
/// suggests 1 to 3 days for its "maximum stale timer".
const DEFAULT_MAX_STALE: Duration = Duration::from_secs(24 * 60 * 60);

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

    /// How long ago this entry expired; zero while it is still fresh.
    fn age_past_expiry(&self) -> Duration {
        Instant::now().saturating_duration_since(self.expiry())
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
    max_stale: Duration,
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
            max_stale: DEFAULT_MAX_STALE,
        }
    }

    /// How long an expired positive entry is retained for Serve-Stale
    /// (RFC 8767 §5's "maximum stale timer"; default 1 day, the low end of its
    /// suggested 1 to 3 days). [`Duration::ZERO`] keeps nothing past expiry,
    /// which turns retention off. Whether a retained entry is *served* is a
    /// separate policy, applied by the caller of [`Self::lookup_stale`].
    pub fn with_max_stale(mut self, window: Duration) -> Self {
        self.max_stale = window;
        self
    }

    /// Lookup positive answers. An expired entry is a miss; it stays in the
    /// cache for [`Self::lookup_stale`] until its stale window has passed.
    pub fn lookup(&self, question: &DnsQuestion) -> Option<Vec<DnsResourceRecord>> {
        let key = CacheKey::from_question(question);
        let mut g = self.inner.lock().unwrap();
        let entry = g.get(&key)?;
        if entry.is_expired() {
            if entry.age_past_expiry() > self.max_stale {
                g.remove(&key);
            }
            return None;
        }
        Some(entry.adjusted())
    }

    /// An *expired* positive answer still inside the stale window (RFC 8767),
    /// for use when a refresh has failed. `max_age` is the caller's own limit
    /// on how stale an answer it will serve; the effective limit is the
    /// smaller of that and the cache's window. Every record's TTL is set to
    /// `ttl` (RFC 8767 §4 requires a value greater than zero and recommends
    /// 30 seconds). Returns `None` for a fresh entry - use [`Self::lookup`].
    pub fn lookup_stale(&self, question: &DnsQuestion, max_age: Duration, ttl: u32) -> Option<Vec<DnsResourceRecord>> {
        let key = CacheKey::from_question(question);
        let mut g = self.inner.lock().unwrap();
        let entry = g.get(&key)?;
        if !entry.is_expired() {
            return None;
        }
        let age = entry.age_past_expiry();
        if age > self.max_stale {
            g.remove(&key);
            return None;
        }
        if age > max_age {
            return None;
        }
        Some(entry.records.iter().map(|rr| rr.with_ttl(ttl)).collect())
    }

    /// Is any *proper ancestor* of `name` a cached NXDOMAIN (RFC 8020: a name
    /// that does not exist has nothing beneath it)? The name itself is not
    /// considered; see [`Self::is_negatively_cached`].
    pub fn has_nxdomain_ancestor(&self, name: &str) -> bool {
        let normalised = crate::wire::normalize_name(name);
        let mut rest = normalised.as_str();
        while let Some((_, parent)) = rest.split_once('.') {
            if parent.is_empty() {
                break;
            }
            if self.is_negatively_cached(parent) {
                return true;
            }
            rest = parent;
        }
        false
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
            // Eviction: an expired entry first - the one furthest past expiry,
            // since it is the least useful to Serve-Stale - else an arbitrary
            // key.
            let victim = g
                .iter()
                .filter(|(_, e)| e.is_expired())
                .max_by_key(|(_, e)| e.age_past_expiry())
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

    /// Store records as though they had been cached `age` ago.
    #[cfg(test)]
    pub(crate) fn put_aged(&self, question: &DnsQuestion, records: Vec<DnsResourceRecord>, ttl: u32, age: Duration) {
        self.put(question, records, ttl);
        let key = CacheKey::from_question(question);
        let mut g = self.inner.lock().unwrap();
        if let Some(e) = g.get_mut(&key) {
            e.cached_at = Instant::now().checked_sub(age).expect("test clock");
        }
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

    fn a_record(name: &str) -> (DnsQuestion, Vec<DnsResourceRecord>) {
        (
            DnsQuestion::in_class(name, DnsType::A),
            vec![DnsResourceRecord::a(name, 60, Ipv4Addr::new(192, 0, 2, 1))],
        )
    }

    #[test]
    fn an_expired_entry_is_a_lookup_miss_but_is_kept_for_the_stale_window() {
        let cache = DnsCache::new(16, 30);
        let (q, rrs) = a_record("stale.test.");
        cache.put_aged(&q, rrs, 60, Duration::from_secs(3600)); // expired 3540 s ago
        assert!(cache.lookup(&q).is_none(), "expired data is never a normal hit");
        assert_eq!(cache.len(), 1, "but it stays for Serve-Stale");
        let stale = cache.lookup_stale(&q, Duration::from_secs(86_400), 30).expect("within the window");
        assert_eq!(stale[0].ttl, 30, "RFC 8767 section 4: a stale answer carries the capped TTL");
        assert_eq!(stale[0].as_a().unwrap(), Ipv4Addr::new(192, 0, 2, 1));
    }

    #[test]
    fn stale_answers_respect_both_the_cache_window_and_the_callers_limit() {
        let (q, rrs) = a_record("window.test.");
        let cache = DnsCache::new(16, 30).with_max_stale(Duration::from_secs(600));
        cache.put_aged(&q, rrs.clone(), 60, Duration::from_secs(60 + 300)); // 300 s stale
        // Caller limit shorter than the age: not served, but not discarded either.
        assert!(cache.lookup_stale(&q, Duration::from_secs(100), 30).is_none());
        assert!(cache.lookup_stale(&q, Duration::from_secs(400), 30).is_some());
        // Past the cache's own window the entry is dropped for good.
        cache.put_aged(&q, rrs, 60, Duration::from_secs(60 + 601));
        assert!(cache.lookup_stale(&q, Duration::from_secs(86_400), 30).is_none());
        assert!(cache.is_empty(), "entries past the window are evicted");
    }

    #[test]
    fn a_zero_window_keeps_nothing_past_expiry_and_fresh_entries_are_not_stale() {
        let (q, rrs) = a_record("zero.test.");
        let cache = DnsCache::new(16, 30).with_max_stale(Duration::ZERO);
        cache.put_aged(&q, rrs.clone(), 60, Duration::from_secs(61));
        assert!(cache.lookup(&q).is_none());
        assert!(cache.is_empty());

        let cache = DnsCache::new(16, 30);
        cache.put(&q, rrs, 60);
        assert!(cache.lookup(&q).is_some());
        assert!(cache.lookup_stale(&q, Duration::from_secs(60), 30).is_none(), "fresh data is a normal hit");
    }

    #[test]
    fn eviction_drops_the_entry_furthest_past_expiry_first() {
        let cache = DnsCache::new(2, 30);
        let (q_old, r_old) = a_record("old.test.");
        let (q_new, r_new) = a_record("recent.test.");
        cache.put_aged(&q_old, r_old, 60, Duration::from_secs(60 + 5000));
        cache.put_aged(&q_new, r_new, 60, Duration::from_secs(60 + 10));
        let (q3, r3) = a_record("third.test.");
        cache.put(&q3, r3, 60);
        assert!(cache.lookup_stale(&q_new, Duration::from_secs(86_400), 30).is_some(), "the recently expired one survives");
        assert!(cache.lookup_stale(&q_old, Duration::from_secs(86_400), 30).is_none(), "the stalest one is evicted");
    }

    fn nxdomain(cache: &DnsCache, name: &str) {
        let nx = DnsMessage::new(1, FLAG_QR | RCODE_NXDOMAIN, vec![DnsQuestion::in_class(name, DnsType::A)], vec![], vec![], vec![]);
        cache.put_response(&nx);
    }

    #[test]
    fn a_cached_nxdomain_covers_every_name_beneath_it() {
        let cache = DnsCache::new(16, 30);
        nxdomain(&cache, "gone.example.");
        assert!(cache.has_nxdomain_ancestor("www.gone.example."));
        assert!(cache.has_nxdomain_ancestor("a.b.c.GONE.example"));
        assert!(!cache.has_nxdomain_ancestor("gone.example."), "the name itself is is_negatively_cached's business");
        assert!(!cache.has_nxdomain_ancestor("other.example."), "siblings are unaffected");
        assert!(!cache.has_nxdomain_ancestor("example."), "parents are unaffected");
        assert!(!cache.has_nxdomain_ancestor("gone.example.evil.test."), "only true suffixes count");
        assert!(!cache.has_nxdomain_ancestor("notgone.example."), "a label boundary, not a string suffix");
    }

    #[test]
    fn nxdomain_cut_ignores_expired_and_nodata_entries() {
        let cache = DnsCache::new(16, 0); // NXDOMAIN with no SOA gets TTL 0: already expired
        nxdomain(&cache, "expired.example.");
        assert!(!cache.has_nxdomain_ancestor("www.expired.example."));

        // NODATA at a name says nothing about names beneath it (empty non-terminals).
        let cache = DnsCache::new(16, 300);
        cache.put_response(&DnsMessage::new(1, FLAG_QR, vec![DnsQuestion::in_class("nodata.example.", DnsType::A)], vec![], vec![], vec![]));
        assert!(!cache.has_nxdomain_ancestor("www.nodata.example."));
    }
}
