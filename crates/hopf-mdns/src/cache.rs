// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Querier-side mDNS cache (RFC 6762 §5, §10) — active TTL-based refresh
//! at 80/85/90/95/100% of each record's TTL (§5.2), and cache-flush/
//! goodbye handling with a short grace period rather than immediate
//! deletion (§10.1, §10.2), tolerating an answer arriving split across
//! more than one packet.
//!
//! A pure, timer-free data structure by design: it never calls into
//! `hopf_core` itself. [`crate::responder`] owns the real
//! [`hopf_core::ReactorHandle`] and schedules the actual timers, calling
//! back into [`MdnsCache::refresh_due`]/[`MdnsCache::expire_due`] when they
//! fire — decoupling this module's logic from the reactor entirely, so it
//! can be tested as plain data-in/data-out (see `tests` below) rather than
//! needing a mocked timer/socket. Each timer's callback captures the
//! `generation` current at schedule time; `refresh_due`/`expire_due`
//! compare it against the entry's *current* generation (bumped on every
//! upsert) and no-op if it's stale — the same guard Gumdrop's `MDNSCache`
//! uses, just without also needing to cancel the superseded timers for
//! correctness (only, at most, a few harmless extra no-op fires).

use std::collections::HashMap;

use hopf_dns::wire::{normalize_name, DnsResourceRecord, DnsType};

use crate::bits::cache_flush;

/// Fractions of a record's TTL at which it's actively refreshed (RFC 6762
/// §5.2) — the last entry (100%) is expiry, not a refresh attempt.
pub const REFRESH_FRACTIONS: [f64; 5] = [0.80, 0.85, 0.90, 0.95, 1.00];

type Key = (String, DnsType);

struct CachedRecord {
    record: DnsResourceRecord,
    generation: u64,
}

/// What the caller (the real reactor) needs to schedule after a cache
/// mutation — one entry per [`REFRESH_FRACTIONS`] stage.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScheduledStage {
    /// Which fraction of the TTL this stage represents.
    pub fraction: f64,
    /// Delay from *now* until this stage's timer should fire.
    pub delay: std::time::Duration,
    /// The generation to pass back into [`MdnsCache::refresh_due`]/
    /// [`MdnsCache::expire_due`] when it does.
    pub generation: u64,
    /// `true` for the terminal (100%) stage — call `expire_due`, not
    /// `refresh_due`, when this one fires.
    pub is_expiry: bool,
}

/// Result of feeding one incoming record into the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// New or updated; caller should (re-)arm all five stage timers.
    Scheduled,
    /// This exact record (same rdata) was already cached with the same
    /// generation's schedule still valid — nothing new to schedule.
    Unchanged,
}

/// Grace period before actually removing a record after a cache-flush
/// (§10.2) or goodbye (§10.1) — long enough to tolerate the flush/goodbye
/// answer arriving split across more than one packet.
pub const GRACE_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

/// Querier-side cache. See the module docs for the timer-ownership split.
#[derive(Default)]
pub struct MdnsCache {
    entries: HashMap<Key, Vec<CachedRecord>>,
    next_generation: u64,
}

impl MdnsCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    fn key_for(name: &str, qtype: DnsType) -> Key {
        (normalize_name(name), qtype)
    }

    /// Insert or refresh one record (e.g. from a received response).
    /// Returns the fresh generation and the five refresh/expiry stages to
    /// schedule against `record.ttl`, unless this is a byte-for-byte
    /// repeat of an already-current entry.
    pub fn upsert(&mut self, record: DnsResourceRecord) -> (u64, Option<[ScheduledStage; 5]>) {
        let Some(rtype) = record.rtype else {
            // Can't key an unrecognized type meaningfully; nothing to cache.
            return (0, None);
        };
        let key = Self::key_for(&record.name, rtype);
        let generation = self.next_generation;
        self.next_generation += 1;

        let list = self.entries.entry(key).or_default();
        if let Some(existing) = list.iter_mut().find(|e| e.record.rdata == record.rdata) {
            existing.record = record.clone();
            existing.generation = generation;
        } else {
            list.push(CachedRecord { record: record.clone(), generation });
        }

        let stages = std::array::from_fn(|i| {
            let fraction = REFRESH_FRACTIONS[i];
            ScheduledStage {
                fraction,
                delay: std::time::Duration::from_secs_f64(record.ttl as f64 * fraction),
                generation,
                is_expiry: i == REFRESH_FRACTIONS.len() - 1,
            }
        });
        (generation, Some(stages))
    }

    /// A refresh-stage timer (one of the first four of
    /// [`REFRESH_FRACTIONS`]) fired. Returns `Some((name, qtype))` — the
    /// caller should send a refresh query — if `generation` is still
    /// current for this record; `None` if a later update already
    /// superseded it (stale timer, no-op).
    pub fn refresh_due(&self, name: &str, qtype: DnsType, rdata: &[u8], generation: u64) -> Option<(String, DnsType)> {
        let key = Self::key_for(name, qtype);
        let current = self.entries.get(&key)?.iter().find(|e| e.record.rdata == rdata)?;
        if current.generation == generation {
            Some((name.to_string(), qtype))
        } else {
            None
        }
    }

    /// The terminal (100% of TTL) stage timer fired. Removes the record
    /// if `generation` is still current (i.e. it was never refreshed).
    pub fn expire_due(&mut self, name: &str, qtype: DnsType, rdata: &[u8], generation: u64) {
        let key = Self::key_for(name, qtype);
        if let Some(list) = self.entries.get_mut(&key) {
            list.retain(|e| !(e.record.rdata == rdata && e.generation == generation));
            if list.is_empty() {
                self.entries.remove(&key);
            }
        }
    }

    /// Feed one incoming mDNS message's answers into the cache (RFC 6762
    /// §10.2 cache-flush semantics): records are grouped by (name,type);
    /// if any record in a group carries the cache-flush bit, every
    /// *currently* cached record for that key whose rdata isn't in the
    /// incoming group is scheduled for grace removal rather than deleted
    /// immediately (tolerates the flush answer arriving split across more
    /// than one packet). Every incoming record is also `upsert`ed
    /// normally. Returns the upsert schedules (for the caller to arm)
    /// alongside the `(name, qtype, rdata, generation)` grace-removals to
    /// schedule after [`GRACE_PERIOD`].
    pub fn ingest(
        &mut self,
        answers: &[DnsResourceRecord],
    ) -> (Vec<(String, DnsType, [ScheduledStage; 5])>, Vec<(String, DnsType, Vec<u8>, u64)>) {
        let mut by_key: HashMap<Key, Vec<&DnsResourceRecord>> = HashMap::new();
        for rr in answers {
            if let Some(rtype) = rr.rtype {
                by_key.entry(Self::key_for(&rr.name, rtype)).or_default().push(rr);
            }
        }

        let mut scheduled = Vec::new();
        let mut grace_removals = Vec::new();

        for (key, group) in &by_key {
            let flush = group.iter().any(|rr| cache_flush(rr));
            if flush {
                if let Some(existing) = self.entries.get(key) {
                    for e in existing {
                        let still_present = group.iter().any(|rr| rr.rdata == e.record.rdata);
                        if !still_present {
                            grace_removals.push((key.0.clone(), key.1, e.record.rdata.clone(), e.generation));
                        }
                    }
                }
            }
            for rr in group {
                let (_, stages) = self.upsert((*rr).clone());
                if let Some(stages) = stages {
                    scheduled.push((key.0.clone(), key.1, stages));
                }
            }
        }

        (scheduled, grace_removals)
    }

    /// Handle a goodbye record (TTL 0, RFC 6762 §10.1): schedules the
    /// matching cached record (if any, and not already superseded) for
    /// [`GRACE_PERIOD`]-delayed removal, same as a cache-flush grace
    /// removal — returned as `Some` for the caller to schedule, `None` if
    /// nothing matching is cached.
    pub fn goodbye(&self, rr: &DnsResourceRecord) -> Option<(String, DnsType, Vec<u8>, u64)> {
        let rtype = rr.rtype?;
        let key = Self::key_for(&rr.name, rtype);
        let existing = self.entries.get(&key)?.iter().find(|e| e.record.rdata == rr.rdata)?;
        Some((key.0, key.1, existing.record.rdata.clone(), existing.generation))
    }

    /// Grace period elapsed for a cache-flush/goodbye removal — actually
    /// remove the record if `generation` is still current (a refresh in
    /// the meantime supersedes the removal).
    pub fn grace_remove_due(&mut self, name: &str, qtype: DnsType, rdata: &[u8], generation: u64) {
        self.expire_due(name, qtype, rdata, generation);
    }

    /// Synchronous cache peek — no network I/O, no timer involved. Empty
    /// if nothing is cached for `name`/`qtype`.
    pub fn lookup(&self, name: &str, qtype: DnsType) -> Vec<DnsResourceRecord> {
        self.entries
            .get(&Self::key_for(name, qtype))
            .map(|list| list.iter().map(|e| e.record.clone()).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_dns::wire::DnsType;
    use std::net::Ipv4Addr;

    fn a(name: &str, ttl: u32, addr: Ipv4Addr) -> DnsResourceRecord {
        DnsResourceRecord::a(name, ttl, addr)
    }

    #[test]
    fn upsert_schedules_five_stages_matching_ttl() {
        let mut cache = MdnsCache::new();
        let (_, stages) = cache.upsert(a("host.local", 120, Ipv4Addr::new(192, 0, 2, 1)));
        let stages = stages.unwrap();
        assert_eq!(stages.len(), 5);
        assert_eq!(stages[0].fraction, 0.80);
        assert_eq!(stages[4].fraction, 1.00);
        assert!(stages[4].is_expiry);
        assert!(!stages[0].is_expiry);
        // 80% of 120s = 96s.
        assert_eq!(stages[0].delay, std::time::Duration::from_secs(96));
        assert_eq!(cache.lookup("host.local", DnsType::A).len(), 1);
    }

    #[test]
    fn stale_generation_timer_is_a_no_op() {
        let mut cache = MdnsCache::new();
        let (gen1, _) = cache.upsert(a("host.local", 120, Ipv4Addr::new(192, 0, 2, 1)));
        let (gen2, _) = cache.upsert(a("host.local", 120, Ipv4Addr::new(192, 0, 2, 1)));
        assert_ne!(gen1, gen2, "re-upserting the same rdata still bumps the generation");

        let rdata = Ipv4Addr::new(192, 0, 2, 1).octets().to_vec();
        // A refresh timer captured at gen1 must not fire the refresh --
        // gen2 (the re-upsert) superseded it.
        assert_eq!(cache.refresh_due("host.local", DnsType::A, &rdata, gen1), None);
        assert_eq!(
            cache.refresh_due("host.local", DnsType::A, &rdata, gen2),
            Some(("host.local".to_string(), DnsType::A))
        );

        // Likewise an expiry timer at the stale generation must not remove
        // the (still valid) record.
        cache.expire_due("host.local", DnsType::A, &rdata, gen1);
        assert_eq!(cache.lookup("host.local", DnsType::A).len(), 1);
        cache.expire_due("host.local", DnsType::A, &rdata, gen2);
        assert!(cache.lookup("host.local", DnsType::A).is_empty());
    }

    #[test]
    fn cache_flush_schedules_grace_removal_only_for_records_not_reasserted() {
        let mut cache = MdnsCache::new();
        cache.upsert(a("host.local", 120, Ipv4Addr::new(192, 0, 2, 1)));
        cache.upsert(a("host.local", 120, Ipv4Addr::new(192, 0, 2, 2)));

        // Incoming message reasserts only .1, with the cache-flush bit --
        // .2 should be scheduled for grace removal, .1 should not.
        let reasserted = crate::bits::with_cache_flush(a("host.local", 120, Ipv4Addr::new(192, 0, 2, 1)));
        let (_, grace) = cache.ingest(&[reasserted]);
        assert_eq!(grace.len(), 1);
        assert_eq!(grace[0].2, Ipv4Addr::new(192, 0, 2, 2).octets().to_vec());

        // Both are still present until the grace period actually elapses.
        assert_eq!(cache.lookup("host.local", DnsType::A).len(), 2);
    }

    #[test]
    fn ingest_without_cache_flush_bit_never_schedules_grace_removal() {
        let mut cache = MdnsCache::new();
        cache.upsert(a("host.local", 120, Ipv4Addr::new(192, 0, 2, 1)));
        let (_, grace) = cache.ingest(&[a("host.local", 120, Ipv4Addr::new(192, 0, 2, 2))]);
        assert!(grace.is_empty());
        assert_eq!(cache.lookup("host.local", DnsType::A).len(), 2);
    }

    #[test]
    fn goodbye_schedules_grace_removal_for_the_matching_record_only() {
        let mut cache = MdnsCache::new();
        cache.upsert(a("host.local", 120, Ipv4Addr::new(192, 0, 2, 1)));
        cache.upsert(a("host.local", 120, Ipv4Addr::new(192, 0, 2, 2)));

        let goodbye_rr = a("host.local", 0, Ipv4Addr::new(192, 0, 2, 1));
        let removal = cache.goodbye(&goodbye_rr).expect("matching record cached");
        assert_eq!(removal.2, Ipv4Addr::new(192, 0, 2, 1).octets().to_vec());

        assert_eq!(cache.lookup("host.local", DnsType::A).len(), 2, "not removed until grace elapses");
        cache.grace_remove_due(&removal.0, removal.1, &removal.2, removal.3);
        assert_eq!(cache.lookup("host.local", DnsType::A).len(), 1);
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let mut cache = MdnsCache::new();
        cache.upsert(a("Host.LOCAL", 120, Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(cache.lookup("host.local", DnsType::A).len(), 1);
    }
}
