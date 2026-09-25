// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-memory authoritative zone and RFC 1034 §4.3.2 lookup.
//!
//! Names are held lower-cased without a trailing dot (hopf's convention);
//! the root zone's origin is the empty string.

use std::collections::{BTreeMap, HashMap, VecDeque};

use super::error::ZoneError;
use crate::wire::{decode_name, normalize_name, DnsClass, DnsResourceRecord, DnsType, SoaData};

const TYPE_CNAME: u16 = 5;
const TYPE_NS: u16 = 2;
const TYPE_SOA: u16 = 6;
const TYPE_MX: u16 = 15;
const TYPE_DS: u16 = 43;
const TYPE_ANY: u16 = 255;

/// Result of looking a name and type up in one zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// Records to answer with. When `wildcard`, they were synthesised from a
    /// wildcard owner and already carry the queried name.
    Answer {
        records: Vec<DnsResourceRecord>,
        wildcard: bool,
    },
    /// The name exists but has nothing of that type (RFC 2308 §2.2).
    NoData,
    /// The name does not exist.
    NxDomain,
    /// The name is at or below a delegation; answer with the NS RRset.
    Referral { ns: Vec<DnsResourceRecord> },
}

/// Entries kept for IXFR (RFC 1995); older clients get a full transfer.
const JOURNAL_LIMIT: usize = 512;

/// Records added and removed by one atomic change.
#[derive(Debug, Default, Clone)]
pub(crate) struct Change {
    pub(crate) deleted: Vec<DnsResourceRecord>,
    pub(crate) added: Vec<DnsResourceRecord>,
    /// The change replaced the SOA itself (an UPDATE adding a newer SOA), so
    /// the serial must not also be bumped.
    soa_replaced: bool,
}

impl Change {
    pub(crate) fn is_empty(&self) -> bool {
        self.deleted.is_empty() && self.added.is_empty()
    }
}

/// One step of zone history: the SOA serial before and after, and the
/// records removed and added (each side includes its SOA), as IXFR carries.
#[derive(Debug, Clone)]
pub(crate) struct JournalEntry {
    pub(crate) from: u32,
    pub(crate) to: u32,
    pub(crate) deleted: Vec<DnsResourceRecord>,
    pub(crate) added: Vec<DnsResourceRecord>,
}

/// One authoritative zone.
#[derive(Debug, Clone)]
pub struct Zone {
    origin: String,
    default_ttl: u32,
    names: BTreeMap<String, Vec<DnsResourceRecord>>,
    /// For each name, how many owner names lie strictly below it. A name
    /// with descendants exists even when it owns no records (an empty
    /// non-terminal, RFC 8020 §2), so it is NODATA rather than NXDOMAIN.
    below: HashMap<String, usize>,
    soa: SoaData,
    soa_ttl: u32,
    journal: VecDeque<JournalEntry>,
}

/// RFC 1982 serial-number "greater than".
pub(crate) fn serial_gt(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000_0000
}

fn parent(name: &str) -> Option<&str> {
    if name.is_empty() {
        None
    } else {
        Some(name.split_once('.').map_or("", |(_, rest)| rest))
    }
}

impl Zone {
    /// Build a zone from its records. `origin` and every owner name may use
    /// any case and an optional trailing dot. The records must contain
    /// exactly one SOA, at the origin, and nothing outside the zone.
    pub fn from_records(
        origin: &str,
        default_ttl: u32,
        records: Vec<DnsResourceRecord>,
    ) -> Result<Self, ZoneError> {
        let origin = normalize_name(origin);
        let mut soa: Option<(SoaData, u32)> = None;
        let mut zone = Self {
            origin,
            default_ttl,
            names: BTreeMap::new(),
            below: HashMap::new(),
            soa: SoaData {
                mname: String::new(),
                rname: String::new(),
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0,
            },
            soa_ttl: default_ttl,
            journal: VecDeque::new(),
        };
        for mut rr in records {
            rr.name = normalize_name(&rr.name);
            if !zone.is_within(&rr.name) {
                return Err(ZoneError::new(format!(
                    "{} is outside zone {}",
                    display(&rr.name),
                    display(&zone.origin)
                )));
            }
            if rr.raw_type == TYPE_SOA {
                if rr.name != zone.origin {
                    return Err(ZoneError::new("SOA record not at the zone origin"));
                }
                if soa.is_some() {
                    return Err(ZoneError::new("more than one SOA record"));
                }
                let data = rr
                    .as_soa()
                    .ok_or_else(|| ZoneError::new("malformed SOA record"))?;
                soa = Some((data, rr.ttl));
            }
            zone.insert(rr)?;
        }
        let (data, ttl) = soa.ok_or_else(|| ZoneError::new("zone has no SOA record"))?;
        zone.soa = data;
        zone.soa_ttl = ttl;
        zone.harmonise_ttls();
        Ok(zone)
    }

    /// Insert without touching the cached SOA (callers keep it in step).
    /// Enforces RFC 1034 §3.6.2: a CNAME owns its name alone. Silently drops
    /// an exact duplicate (RFC 2181 §5).
    fn insert(&mut self, rr: DnsResourceRecord) -> Result<(), ZoneError> {
        let existed = self.names.contains_key(&rr.name);
        let list = self.names.entry(rr.name.clone()).or_default();
        if list.iter().any(|r| same_rr(r, &rr)) {
            return Ok(());
        }
        let conflicts = if rr.raw_type == TYPE_CNAME {
            !list.is_empty()
        } else {
            list.iter().any(|r| r.raw_type == TYPE_CNAME)
        };
        if conflicts {
            if !existed {
                self.names.remove(&rr.name);
            }
            return Err(ZoneError::new(format!(
                "CNAME and other data at {}",
                display(&rr.name)
            )));
        }
        let name = rr.name.clone();
        list.push(rr);
        if !existed {
            self.count_below(&name, 1);
        }
        Ok(())
    }

    fn count_below(&mut self, name: &str, delta: isize) {
        let mut cur = parent(name);
        while let Some(anc) = cur {
            let e = self.below.entry(anc.to_string()).or_insert(0);
            *e = e.saturating_add_signed(delta);
            if *e == 0 {
                self.below.remove(anc);
            }
            if anc == self.origin {
                break;
            }
            cur = parent(anc);
        }
    }

    /// RFC 2181 §5.2: every RR of an RRset has the same TTL; use the lowest.
    fn harmonise_ttls(&mut self) {
        for list in self.names.values_mut() {
            let mut lowest: HashMap<u16, u32> = HashMap::new();
            for r in list.iter() {
                let e = lowest.entry(r.raw_type).or_insert(r.ttl);
                *e = (*e).min(r.ttl);
            }
            for r in list.iter_mut() {
                r.ttl = lowest[&r.raw_type];
            }
        }
        if let Some(soa) = self.names.get(&self.origin).and_then(|l| l.iter().find(|r| r.raw_type == TYPE_SOA)) {
            self.soa_ttl = soa.ttl;
        }
    }

    // ---- mutation (RFC 2136 updates, zone transfers) ----

    fn remove_exact(&mut self, rr: &DnsResourceRecord) -> bool {
        let Some(list) = self.names.get_mut(&rr.name) else {
            return false;
        };
        let Some(pos) = list.iter().position(|r| same_rr(r, rr)) else {
            return false;
        };
        list.remove(pos);
        if list.is_empty() {
            self.names.remove(&rr.name);
            let name = rr.name.clone();
            self.count_below(&name, -1);
        }
        true
    }

    /// RFC 2136 §3.4.2.2 "add to an RRset". A CNAME may not join other data
    /// and other data may not join a CNAME: such adds are ignored, not errors.
    /// The RRset's TTL becomes the added record's (RFC 2181 §5.2).
    pub(crate) fn add_rr(&mut self, mut rr: DnsResourceRecord, ch: &mut Change) {
        rr.name = normalize_name(&rr.name);
        if rr.raw_type == TYPE_SOA {
            if rr.name != self.origin {
                return;
            }
            let Some(new) = rr.as_soa() else { return };
            if !serial_gt(new.serial, self.soa.serial) {
                return;
            }
            ch.deleted.push(self.soa_record());
            ch.added.push(rr.clone());
            ch.soa_replaced = true;
            self.set_soa(rr, new);
            return;
        }
        let list = self.names.get(&rr.name);
        if let Some(list) = list {
            if list.iter().any(|r| same_rr(r, &rr)) {
                // Already present: only the TTL may change.
                if list.iter().any(|r| r.raw_type == rr.raw_type && r.ttl != rr.ttl) {
                    self.retime(&rr.name.clone(), rr.raw_type, rr.ttl, ch);
                }
                return;
            }
            let conflicts = if rr.raw_type == TYPE_CNAME {
                !list.is_empty()
            } else {
                list.iter().any(|r| r.raw_type == TYPE_CNAME)
            };
            if conflicts {
                return;
            }
            if list.iter().any(|r| r.raw_type == rr.raw_type && r.ttl != rr.ttl) {
                self.retime(&rr.name.clone(), rr.raw_type, rr.ttl, ch);
            }
        }
        ch.added.push(rr.clone());
        let _ = self.insert(rr); // conflicts were ruled out above
    }

    /// Give every record of an RRset `ttl`, journalling the replacement.
    fn retime(&mut self, name: &str, rtype: u16, ttl: u32, ch: &mut Change) {
        if let Some(list) = self.names.get_mut(name) {
            for r in list.iter_mut().filter(|r| r.raw_type == rtype) {
                ch.deleted.push(r.clone());
                r.ttl = ttl;
                ch.added.push(r.clone());
            }
        }
    }

    /// Delete one exact record (class NONE). The apex SOA and the last apex
    /// NS are never removed (RFC 2136 §3.4.2.4).
    pub(crate) fn delete_rr(&mut self, rr: &DnsResourceRecord, ch: &mut Change) {
        let mut rr = rr.clone();
        rr.name = normalize_name(&rr.name);
        if rr.name == self.origin {
            if rr.raw_type == TYPE_SOA {
                return;
            }
            if rr.raw_type == TYPE_NS && self.rrset(&self.origin, TYPE_NS).len() <= 1 {
                return;
            }
        }
        // Match ignoring TTL, which a class-NONE record does not carry.
        let found = self
            .names
            .get(&rr.name)
            .and_then(|l| l.iter().find(|r| r.raw_type == rr.raw_type && r.rdata == rr.rdata))
            .cloned();
        if let Some(found) = found {
            self.remove_exact(&found);
            ch.deleted.push(found);
        }
    }

    /// Delete an RRset (class ANY, one type).
    pub(crate) fn delete_rrset(&mut self, name: &str, rtype: u16, ch: &mut Change) {
        let name = normalize_name(name);
        if name == self.origin && (rtype == TYPE_SOA || rtype == TYPE_NS) {
            return;
        }
        for rr in self.rrset(&name, rtype) {
            self.remove_exact(&rr);
            ch.deleted.push(rr);
        }
    }

    /// Delete every RRset at a name (class ANY, type ANY). At the apex the
    /// SOA and NS RRsets stay.
    pub(crate) fn delete_name(&mut self, name: &str, ch: &mut Change) {
        let name = normalize_name(name);
        let at_apex = name == self.origin;
        let doomed: Vec<_> = self
            .names
            .get(&name)
            .into_iter()
            .flatten()
            .filter(|r| !(at_apex && (r.raw_type == TYPE_SOA || r.raw_type == TYPE_NS)))
            .cloned()
            .collect();
        for rr in doomed {
            self.remove_exact(&rr);
            ch.deleted.push(rr);
        }
    }

    fn set_soa(&mut self, rr: DnsResourceRecord, data: SoaData) {
        let old = self.soa_record();
        self.remove_exact(&old);
        self.soa_ttl = rr.ttl;
        self.soa = data;
        let _ = self.insert(rr);
    }

    /// Finish an update: bump the serial (unless the update set it), add the
    /// SOA change to the record of what changed, and journal it for IXFR.
    /// Returns whether anything changed.
    pub(crate) fn commit(&mut self, mut ch: Change) -> bool {
        if ch.is_empty() {
            return false;
        }
        let from = self.soa.serial;
        if !ch.soa_replaced {
            let old = self.soa_record();
            let mut data = self.soa.clone();
            data.serial = data.serial.wrapping_add(1);
            let new = soa_record_from(&self.origin, self.soa_ttl, &data);
            ch.deleted.push(old);
            ch.added.push(new.clone());
            self.set_soa(new, data);
        }
        self.journal.push_back(JournalEntry {
            from,
            to: self.soa.serial,
            deleted: ch.deleted,
            added: ch.added,
        });
        while self.journal.len() > JOURNAL_LIMIT {
            self.journal.pop_front();
        }
        true
    }

    /// Records changed since `serial`, oldest first, if the journal reaches
    /// back that far without a gap (RFC 1995 §4).
    pub(crate) fn changes_since(&self, serial: u32) -> Option<Vec<JournalEntry>> {
        let mut out: Vec<JournalEntry> = Vec::new();
        let mut at = serial;
        for e in &self.journal {
            if e.from == at {
                out.push(e.clone());
                at = e.to;
            }
        }
        (at == self.soa.serial && !out.is_empty()).then_some(out)
    }

    /// Apply one IXFR difference sequence (RFC 1995 §4): remove `deleted`,
    /// add `added`, each carrying the SOA of its side. Must start from the
    /// serial this zone is at.
    pub(crate) fn apply_diff(
        &mut self,
        deleted: Vec<DnsResourceRecord>,
        added: Vec<DnsResourceRecord>,
    ) -> Result<(), ZoneError> {
        let old_soa = deleted
            .iter()
            .find(|r| r.raw_type == TYPE_SOA)
            .and_then(|r| r.as_soa())
            .ok_or_else(|| ZoneError::new("IXFR difference without a deleted SOA"))?;
        let new_soa = added
            .iter()
            .find(|r| r.raw_type == TYPE_SOA)
            .cloned()
            .ok_or_else(|| ZoneError::new("IXFR difference without an added SOA"))?;
        if old_soa.serial != self.soa.serial {
            return Err(ZoneError::new("IXFR difference does not start at the current serial"));
        }
        let from = self.soa.serial;
        for rr in &deleted {
            let mut rr = rr.clone();
            rr.name = normalize_name(&rr.name);
            if rr.raw_type != TYPE_SOA {
                let found = self
                    .names
                    .get(&rr.name)
                    .and_then(|l| l.iter().find(|r| r.raw_type == rr.raw_type && r.rdata == rr.rdata))
                    .cloned();
                if let Some(f) = found {
                    self.remove_exact(&f);
                }
            }
        }
        let data = new_soa.as_soa().ok_or_else(|| ZoneError::new("malformed SOA"))?;
        for rr in &added {
            let mut rr = rr.clone();
            rr.name = normalize_name(&rr.name);
            if rr.raw_type != TYPE_SOA && self.is_within(&rr.name) {
                self.insert(rr)?;
            }
        }
        let mut new_soa = new_soa;
        new_soa.name = self.origin.clone();
        self.set_soa(new_soa, data);
        self.harmonise_ttls();
        self.journal.push_back(JournalEntry {
            from,
            to: self.soa.serial,
            deleted,
            added,
        });
        while self.journal.len() > JOURNAL_LIMIT {
            self.journal.pop_front();
        }
        Ok(())
    }

    /// The zone apex name (no trailing dot; empty for the root).
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// `$TTL` default the zone was loaded with.
    pub fn default_ttl(&self) -> u32 {
        self.default_ttl
    }

    /// Parsed SOA fields.
    pub fn soa(&self) -> &SoaData {
        &self.soa
    }

    /// SOA serial.
    pub fn serial(&self) -> u32 {
        self.soa.serial
    }

    /// The apex SOA record.
    pub fn soa_record(&self) -> DnsResourceRecord {
        self.names
            .get(&self.origin)
            .and_then(|l| l.iter().find(|r| r.raw_type == TYPE_SOA))
            .cloned()
            .expect("a Zone always holds its SOA")
    }

    /// SOA for the authority section of a negative answer: TTL is the lesser
    /// of the SOA's own and its MINIMUM (RFC 2308 §3).
    pub(crate) fn negative_soa(&self) -> DnsResourceRecord {
        let mut soa = self.soa_record();
        soa.ttl = soa.ttl.min(self.soa.minimum);
        soa
    }

    /// NS RRset at the apex.
    pub fn ns_records(&self) -> Vec<DnsResourceRecord> {
        self.rrset(&self.origin, TYPE_NS)
    }

    /// Whether `name` (normalised) is the origin or below it.
    pub fn is_within(&self, name: &str) -> bool {
        if self.origin.is_empty() || name == self.origin {
            return true;
        }
        name.len() > self.origin.len()
            && name.ends_with(&self.origin)
            && name.as_bytes()[name.len() - self.origin.len() - 1] == b'.'
    }

    /// Records of one type at one name.
    pub fn rrset(&self, name: &str, rtype: u16) -> Vec<DnsResourceRecord> {
        self.names
            .get(name)
            .map(|l| l.iter().filter(|r| r.raw_type == rtype).cloned().collect())
            .unwrap_or_default()
    }

    /// Every record, SOA first (the AXFR order, RFC 5936 §2.2).
    pub fn records(&self) -> Vec<DnsResourceRecord> {
        let mut out = vec![self.soa_record()];
        for list in self.names.values() {
            out.extend(list.iter().filter(|r| !(r.raw_type == TYPE_SOA && r.name == self.origin)).cloned());
        }
        out
    }

    /// Number of records, including the SOA.
    pub fn record_count(&self) -> usize {
        self.names.values().map(Vec::len).sum()
    }

    /// Whether `name` owns any record, or has owners below it.
    pub(crate) fn name_exists(&self, name: &str) -> bool {
        self.names.contains_key(name) || self.below.contains_key(name)
    }

    /// RFC 1034 §4.3.2 lookup. `qname` must be normalised and inside the zone.
    pub(crate) fn lookup(&self, qname: &str, qtype: u16) -> Lookup {
        // Step 2: a delegation at or above the name hides everything below it.
        if let Some(ns) = self.zone_cut(qname, qtype) {
            return Lookup::Referral { ns };
        }
        if let Some(list) = self.names.get(qname) {
            return match_at(list, qtype, None);
        }
        if self.below.contains_key(qname) {
            return Lookup::NoData; // empty non-terminal
        }
        // Wildcard synthesis at the closest encloser (RFC 4592 §3.3).
        let mut encloser = parent(qname).unwrap_or("");
        while !(self.name_exists(encloser) || encloser == self.origin) {
            encloser = parent(encloser).unwrap_or("");
        }
        let wildcard = if encloser.is_empty() {
            "*".to_string()
        } else {
            format!("*.{encloser}")
        };
        match self.names.get(&wildcard) {
            Some(list) => match_at(list, qtype, Some(qname)),
            None => Lookup::NxDomain,
        }
    }

    /// The NS RRset of the delegation that covers `qname`, if any.
    fn zone_cut(&self, qname: &str, qtype: u16) -> Option<Vec<DnsResourceRecord>> {
        if qname == self.origin {
            return None;
        }
        // Names from just below the origin down to the qname.
        let mut chain = Vec::new();
        let mut cur = qname;
        while cur != self.origin {
            chain.push(cur);
            cur = parent(cur)?;
        }
        for name in chain.into_iter().rev() {
            let ns = self.rrset(name, TYPE_NS);
            if ns.is_empty() {
                continue;
            }
            // DS lives on the parent side of the cut (RFC 4035 §2.4).
            if name == qname && qtype == TYPE_DS {
                return None;
            }
            return Some(ns);
        }
        None
    }

    /// A/AAAA records for the in-zone targets of NS and MX records: the
    /// additional-section glue that saves the client a round trip.
    pub(crate) fn glue_for(&self, records: &[DnsResourceRecord]) -> Vec<DnsResourceRecord> {
        let mut out: Vec<DnsResourceRecord> = Vec::new();
        for rr in records {
            let target = match rr.raw_type {
                TYPE_NS => rr.as_domain_name(),
                TYPE_MX => rr.as_mx().map(|(_, n)| n),
                _ => None,
            };
            let Some(target) = target.map(|t| normalize_name(&t)) else {
                continue;
            };
            if !self.is_within(&target) {
                continue;
            }
            for a in self.names.get(&target).into_iter().flatten() {
                if matches!(a.rtype, Some(DnsType::A) | Some(DnsType::Aaaa)) && !out.iter().any(|g| same_rr(g, a)) {
                    out.push(a.clone());
                }
            }
        }
        out
    }
}

fn display(name: &str) -> &str {
    if name.is_empty() {
        "."
    } else {
        name
    }
}

pub(crate) fn same_rr(a: &DnsResourceRecord, b: &DnsResourceRecord) -> bool {
    a.name == b.name && a.raw_type == b.raw_type && a.raw_class == b.raw_class && a.rdata == b.rdata
}

/// Match `qtype` against the records at one owner; `synth` rewrites the
/// owner (wildcard synthesis).
fn match_at(list: &[DnsResourceRecord], qtype: u16, synth: Option<&str>) -> Lookup {
    let take = |r: &DnsResourceRecord| {
        let mut r = r.clone();
        if let Some(name) = synth {
            r.name = name.to_string();
        }
        r
    };
    let matches: Vec<DnsResourceRecord> = list
        .iter()
        .filter(|r| qtype == TYPE_ANY || r.raw_type == qtype)
        .map(take)
        .collect();
    if !matches.is_empty() {
        return Lookup::Answer {
            records: matches,
            wildcard: synth.is_some(),
        };
    }
    // RFC 1034 §3.6.2: a CNAME answers any other type; the caller follows it.
    if let Some(c) = list.iter().find(|r| r.raw_type == TYPE_CNAME) {
        return Lookup::Answer {
            records: vec![take(c)],
            wildcard: synth.is_some(),
        };
    }
    Lookup::NoData
}

/// Decode the target of a CNAME record for chain following.
pub(crate) fn cname_target(rr: &DnsResourceRecord) -> Option<String> {
    let mut c = 0;
    decode_name(&rr.rdata, &mut c).ok().map(|n| normalize_name(&n))
}

/// SOA record for `origin` from parsed fields.
pub(crate) fn soa_record_from(origin: &str, ttl: u32, d: &SoaData) -> DnsResourceRecord {
    let mut rdata = crate::wire::encode_name(&d.mname).expect("SOA names came from a parsed record");
    rdata.extend_from_slice(&crate::wire::encode_name(&d.rname).expect("SOA names came from a parsed record"));
    for v in [d.serial, d.refresh, d.retry, d.expire, d.minimum] {
        rdata.extend_from_slice(&v.to_be_bytes());
    }
    in_record(origin, TYPE_SOA, ttl, rdata)
}

/// Build a record with class IN.
pub(crate) fn in_record(name: &str, rtype: u16, ttl: u32, rdata: Vec<u8>) -> DnsResourceRecord {
    DnsResourceRecord::opaque(name, rtype, DnsClass::In.value(), ttl, rdata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::zone::loader::parse_zone;

    fn zone() -> Zone {
        parse_zone(
            "example.com",
            "\
$TTL 300
@       IN SOA ns1 hostmaster 5 3600 900 604800 60
        IN NS  ns1
        IN NS  ns2.other.net.
        IN MX  10 mail
ns1     IN A   192.0.2.53
mail    IN A   192.0.2.25
www     IN CNAME web
web     IN A   192.0.2.80
        IN AAAA 2001:db8::80
*.wild  IN A   192.0.2.99
a.b.c   IN TXT \"deep\"
sub     IN NS  ns.sub
ns.sub  IN A   192.0.2.77
ext     IN CNAME elsewhere.org.
",
        )
        .unwrap()
    }

    fn ty(t: DnsType) -> u16 {
        t.value()
    }

    #[test]
    fn exact_match_nodata_and_nxdomain() {
        let z = zone();
        match z.lookup("web.example.com", ty(DnsType::A)) {
            Lookup::Answer { records, wildcard } => {
                assert_eq!(records.len(), 1);
                assert!(!wildcard);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(z.lookup("web.example.com", ty(DnsType::Mx)), Lookup::NoData);
        assert_eq!(z.lookup("nope.example.com", ty(DnsType::A)), Lookup::NxDomain);
    }

    #[test]
    fn empty_non_terminals_exist() {
        let z = zone();
        // a.b.c has data, so b.c and c exist with nothing on them.
        assert_eq!(z.lookup("b.c.example.com", ty(DnsType::A)), Lookup::NoData);
        assert_eq!(z.lookup("c.example.com", ty(DnsType::A)), Lookup::NoData);
        assert_eq!(z.lookup("x.c.example.com", ty(DnsType::A)), Lookup::NxDomain);
    }

    #[test]
    fn wildcards_synthesise_at_the_closest_encloser_with_the_queried_owner() {
        let z = zone();
        match z.lookup("x.y.wild.example.com", ty(DnsType::A)) {
            Lookup::Answer { records, wildcard } => {
                assert!(wildcard);
                assert_eq!(records[0].name, "x.y.wild.example.com");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(z.lookup("x.wild.example.com", ty(DnsType::Mx)), Lookup::NoData);
        // The wildcard does not reach names outside its parent.
        assert_eq!(z.lookup("x.example.com", ty(DnsType::A)), Lookup::NxDomain);
        // An existing name (the wildcard's own parent) is not synthesised.
        assert_eq!(z.lookup("wild.example.com", ty(DnsType::A)), Lookup::NoData);
    }

    #[test]
    fn cname_answers_other_types_but_not_itself() {
        let z = zone();
        match z.lookup("www.example.com", ty(DnsType::A)) {
            Lookup::Answer { records, .. } => assert_eq!(records[0].raw_type, 5),
            other => panic!("{other:?}"),
        }
        match z.lookup("www.example.com", ty(DnsType::Cname)) {
            Lookup::Answer { records, .. } => assert_eq!(records.len(), 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn delegations_produce_referrals_at_and_below_the_cut() {
        let z = zone();
        for q in ["sub.example.com", "host.sub.example.com", "ns.sub.example.com"] {
            match z.lookup(q, ty(DnsType::A)) {
                Lookup::Referral { ns } => assert_eq!(ns[0].name, "sub.example.com"),
                other => panic!("{q}: {other:?}"),
            }
        }
        // DS is answered by the parent, not referred.
        assert_eq!(z.lookup("sub.example.com", 43), Lookup::NoData);
        // The apex NS set is not a delegation.
        assert!(matches!(z.lookup("example.com", ty(DnsType::Ns)), Lookup::Answer { .. }));
    }

    #[test]
    fn glue_covers_in_zone_ns_and_mx_targets_only() {
        let z = zone();
        let mut rrs = z.ns_records();
        rrs.extend(z.rrset("example.com", 15));
        let glue = z.glue_for(&rrs);
        let names: Vec<_> = glue.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, ["ns1.example.com", "mail.example.com"], "ns2.other.net is out of zone");
        // Glue below a cut is still served as additional data.
        let sub = z.glue_for(&z.rrset("sub.example.com", 2));
        assert_eq!(sub[0].name, "ns.sub.example.com");
    }

    #[test]
    fn construction_rejects_bad_zones() {
        let a = |n: &str| DnsResourceRecord::a(n, 60, std::net::Ipv4Addr::LOCALHOST);
        let soa = DnsResourceRecord::soa("example.com", 60, "ns", "h", 1, 2, 3, 4, 5).unwrap();
        assert!(Zone::from_records("example.com", 60, vec![a("x.example.com")]).is_err(), "no SOA");
        assert!(Zone::from_records("example.com", 60, vec![soa.clone(), a("x.other.org")]).is_err(), "outside");
        assert!(Zone::from_records("example.com", 60, vec![soa.clone(), soa.clone()]).is_err(), "two SOAs");
        let cname = DnsResourceRecord::cname("x.example.com", 60, "y.example.com").unwrap();
        assert!(Zone::from_records("example.com", 60, vec![soa.clone(), cname, a("x.example.com")]).is_err(), "CNAME + data");
        // Exact duplicates collapse.
        let z = Zone::from_records("example.com", 60, vec![soa, a("x.example.com"), a("x.example.com")]).unwrap();
        assert_eq!(z.record_count(), 2);
    }

    #[test]
    fn rrset_ttls_are_harmonised_to_the_lowest() {
        let soa = DnsResourceRecord::soa("example.com", 60, "ns", "h", 1, 2, 3, 4, 5).unwrap();
        let z = Zone::from_records(
            "example.com",
            60,
            vec![
                soa,
                DnsResourceRecord::a("x.example.com", 300, std::net::Ipv4Addr::new(1, 1, 1, 1)),
                DnsResourceRecord::a("x.example.com", 100, std::net::Ipv4Addr::new(2, 2, 2, 2)),
            ],
        )
        .unwrap();
        assert!(z.rrset("x.example.com", 1).iter().all(|r| r.ttl == 100));
    }

    #[test]
    fn serial_arithmetic_wraps_per_rfc_1982() {
        assert!(serial_gt(2, 1));
        assert!(!serial_gt(1, 2));
        assert!(!serial_gt(5, 5));
        assert!(serial_gt(1, u32::MAX), "wrapped");
    }
}
