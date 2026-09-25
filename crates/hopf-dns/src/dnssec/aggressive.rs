// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Aggressive use of the DNSSEC-validated cache (RFC 8198): answering from a
//! cached NSEC/NSEC3 proof instead of asking the authoritative servers.
//!
//! Once a signed zone has told a validating resolver that nothing exists
//! between two names, the resolver already has the answer for *every* name in
//! that range. [`DenialCache`] keeps those proofs, per zone, and
//! [`DenialCache::synthesize`] turns them back into an NXDOMAIN or NODATA
//! answer - but only where the RFC 4035 §5.4 / RFC 5155 §8 rules say the
//! proof really covers the question.
//!
//! **Nothing in here validates.** [`DenialCache::store_validated`] must only
//! be given a response whose denial the caller has already verified as
//! `Secure` (for example with
//! [`DnsResolver::validate_denial_of_existence`](crate::DnsResolver::validate_denial_of_existence));
//! a proof that was never checked would let anyone who can spoof one reply
//! poison every name in its range.
//!
//! # What is and is not synthesised
//!
//! * NXDOMAIN and NODATA from NSEC, and from NSEC3 when its parameters are
//!   within [`MAX_NSEC3_ITERATIONS`].
//! * NXDOMAIN needs a proof that no wildcard could have matched, not only that
//!   the name is absent (RFC 8198 §5.1, RFC 4035 §5.4); a cache that lacks the
//!   wildcard's covering record falls back to the upstream.
//! * A covering NSEC3 with the Opt-Out flag proves nothing about an unsigned
//!   delegation's absence, so no answer is synthesised from it (§5.2).
//! * Records at or above a delegation (`NS` without `SOA`) or a `DNAME` do not
//!   prove anything about names beneath them.
//! * Not done: wildcard-*positive* synthesis (RFC 8198 §5.3, a `SHOULD`), and
//!   proofs from more than one NSEC3 parameter set per zone at a time.
//!
//! Lifetimes follow RFC 8198 §5.4: a proof lives for the smallest of its own
//! TTL, the SOA minimum of the response it came with, its signatures' remaining
//! validity, and three hours.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use super::crypto::nsec3_hash;
use super::denial::{hash_in_range, in_canonical_range};
use crate::wire::{
    base32hex, encode_name, normalize_name, DnsMessage, DnsQuestion, DnsResourceRecord, DnsType, RCODE_NXDOMAIN,
};

/// RFC 8198 §5.4: cap on how long negative information is kept (RFC 2308 §5).
const MAX_TTL: u32 = 10_800;
/// NSEC3 iteration counts above this are not worth hashing for (RFC 9276
/// §3.2 lets a resolver treat a higher count as insecure).
pub const MAX_NSEC3_ITERATIONS: u16 = 100;
/// Bound on cached proof records; over it, expired ones go first, then all.
const MAX_PROOF_RECORDS: usize = 20_000;

const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_DNAME: u16 = 39;
const TYPE_DS: u16 = 43;
const NSEC3_OPT_OUT: u8 = 0x01;
/// QTYPEs for which a negative answer is never synthesised.
const META_TYPES: [u16; 8] = [46, 47, 50, 41, 251, 252, 255, 250];

struct Proof {
    rr: DnsResourceRecord,
    sigs: Vec<DnsResourceRecord>,
    stored: Instant,
    ttl: u32,
    /// NSEC3: the owner's hash, decoded from the owner label.
    owner_hash: Vec<u8>,
}

impl Proof {
    fn remaining(&self) -> Option<u32> {
        let elapsed = self.stored.elapsed().as_secs().min(u64::from(u32::MAX)) as u32;
        self.ttl.checked_sub(elapsed).filter(|r| *r > 0)
    }

    fn live(&self) -> bool {
        self.remaining().is_some()
    }

    fn owner(&self) -> String {
        normalize_name(&self.rr.name)
    }

    fn types(&self) -> Option<Vec<u16>> {
        self.rr.nsec_types().or_else(|| self.rr.nsec3_types())
    }

    fn record(&self) -> SynthesizedRecord {
        let ttl = self.remaining().unwrap_or(1);
        SynthesizedRecord {
            rr: self.rr.with_ttl(ttl),
            sigs: self.sigs.iter().map(|s| s.with_ttl(ttl)).collect(),
        }
    }
}

#[derive(Default)]
struct ZoneProofs {
    soa: Option<Proof>,
    nsec: Vec<Proof>,
    nsec3: Vec<Proof>,
    /// (algorithm, iterations, salt) shared by every entry in `nsec3`.
    nsec3_params: Option<(u8, u16, Vec<u8>)>,
}

impl ZoneProofs {
    fn prune(&mut self) {
        self.nsec.retain(Proof::live);
        self.nsec3.retain(Proof::live);
        if self.soa.as_ref().is_some_and(|p| !p.live()) {
            self.soa = None;
        }
    }

    fn len(&self) -> usize {
        self.nsec.len() + self.nsec3.len()
    }
}

/// A record with the signatures that cover it.
#[derive(Debug, Clone)]
pub struct SynthesizedRecord {
    /// The record, its TTL already reduced to what remains.
    pub rr: DnsResourceRecord,
    /// Its RRSIGs, for a client that asked for DNSSEC data.
    pub sigs: Vec<DnsResourceRecord>,
}

/// A negative answer built from cached proofs.
#[derive(Debug, Clone)]
pub struct SynthesizedDenial {
    /// `RCODE_NXDOMAIN`, or `0` for NODATA.
    pub rcode: u16,
    /// The zone's SOA (RFC 2308 §3), present in every negative answer.
    pub soa: SynthesizedRecord,
    /// The NSEC or NSEC3 records that carry the proof.
    pub proofs: Vec<SynthesizedRecord>,
}

impl SynthesizedDenial {
    /// The authority section: the SOA alone, or with the proof records and
    /// every signature when the client asked for DNSSEC data (DO).
    pub fn authorities(&self, dnssec_ok: bool) -> Vec<DnsResourceRecord> {
        let mut out = vec![self.soa.rr.clone()];
        if dnssec_ok {
            out.extend(self.soa.sigs.iter().cloned());
            for p in &self.proofs {
                out.push(p.rr.clone());
                out.extend(p.sigs.iter().cloned());
            }
        }
        out
    }
}

/// Validated NSEC/NSEC3 proofs, per zone. Thread-safe.
#[derive(Default)]
pub struct DenialCache {
    zones: Mutex<HashMap<String, ZoneProofs>>,
}

fn now_unix() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs().min(u64::from(u32::MAX)) as u32)
}

/// Seconds the longest-lived of `sigs` is still valid for; `None` if all have
/// expired (or there are none).
fn signature_validity(sigs: &[DnsResourceRecord]) -> Option<u32> {
    let now = now_unix();
    sigs.iter()
        .filter_map(|s| s.rrsig_expiration())
        .filter_map(|exp| exp.checked_sub(now))
        .filter(|v| *v > 0)
        .max()
}

fn is_descendant(name: &str, ancestor: &str) -> bool {
    name != ancestor && (ancestor.is_empty() || name.ends_with(&format!(".{ancestor}")))
}

fn labels(name: &str) -> Vec<&str> {
    if name.is_empty() { Vec::new() } else { name.split('.').collect() }
}

/// The last `n` labels of `name`.
fn suffix(name: &str, n: usize) -> String {
    let l = labels(name);
    l[l.len().saturating_sub(n)..].join(".")
}

fn common_suffix_labels(a: &str, b: &str) -> usize {
    labels(a).iter().rev().zip(labels(b).iter().rev()).take_while(|(x, y)| x == y).count()
}

fn wildcard_of(ce: &str) -> String {
    if ce.is_empty() { "*".into() } else { format!("*.{ce}") }
}

/// A delegation point (NS without SOA) or a DNAME: nothing it proves extends
/// to names beneath it.
fn is_cut(types: &[u16]) -> bool {
    (types.contains(&TYPE_NS) && !types.contains(&TYPE_SOA)) || types.contains(&TYPE_DNAME)
}

/// Whether an existing name whose types are `types` has no data for `qtype`
/// that a resolver could answer authoritatively from this record alone.
fn proves_nodata(types: &[u16], qtype: u16) -> bool {
    if types.contains(&qtype) || (types.contains(&TYPE_CNAME) && qtype != TYPE_CNAME) {
        return false;
    }
    // At a delegation only the parent's view of the cut (DS) is answerable.
    let delegation = types.contains(&TYPE_NS) && !types.contains(&TYPE_SOA);
    !delegation || qtype == TYPE_DS
}

impl DenialCache {
    /// A new, empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of cached NSEC/NSEC3 records (testing and metrics).
    pub fn len(&self) -> usize {
        self.zones.lock().unwrap().values().map(ZoneProofs::len).sum()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Cache the NSEC/NSEC3 records (and the SOA) of a negative response.
    ///
    /// **The caller must have validated the denial** ([module docs](self)).
    /// Only signed records are kept, only under the zone that signed them, and
    /// only if the response carries the SOA that gives them their lifetime.
    pub fn store_validated(&self, msg: &DnsMessage) {
        let auth = &msg.authorities;
        let Some(soa_rr) = auth.iter().find(|r| r.rtype == Some(DnsType::Soa)) else {
            return;
        };
        let Some(soa) = soa_rr.as_soa() else {
            return;
        };
        let sigs_for = |rr: &DnsResourceRecord| -> Vec<DnsResourceRecord> {
            auth.iter()
                .filter(|s| {
                    s.rtype == Some(DnsType::Rrsig)
                        && s.rrsig_type_covered() == Some(rr.raw_type)
                        && normalize_name(&s.name) == normalize_name(&rr.name)
                })
                .cloned()
                .collect()
        };
        // RFC 8198 §5.4: no longer than the SOA minimum, nor three hours.
        let negative_ttl = soa.minimum.min(soa_rr.ttl).min(MAX_TTL);
        let mk = |rr: &DnsResourceRecord| -> Option<Proof> {
            let sigs = sigs_for(rr);
            let validity = signature_validity(&sigs)?;
            let ttl = rr.ttl.min(negative_ttl).min(validity);
            (ttl > 0).then(|| Proof {
                owner_hash: base32hex::decode_owner_label(&rr.name).unwrap_or_default(),
                rr: rr.clone(),
                sigs,
                stored: Instant::now(),
                ttl,
            })
        };
        let Some(soa_proof) = mk(soa_rr) else {
            return;
        };
        let proofs: Vec<Proof> = auth
            .iter()
            .filter(|r| matches!(r.rtype, Some(DnsType::Nsec | DnsType::Nsec3)))
            .filter_map(mk)
            .collect();
        // The zone is whoever signed the proofs; ignore any that disagree.
        let Some(zone) = proofs
            .first()
            .and_then(|p| p.sigs.first())
            .and_then(|s| s.rrsig_signer_name())
            .map(|z| normalize_name(&z))
        else {
            return;
        };
        let proofs: Vec<Proof> = proofs
            .into_iter()
            .filter(|p| p.sigs.iter().any(|s| s.rrsig_signer_name().map(|z| normalize_name(&z)).as_deref() == Some(zone.as_str())))
            .collect();

        let mut zones = self.zones.lock().unwrap();
        let total: usize = zones.values().map(ZoneProofs::len).sum();
        if total + proofs.len() > MAX_PROOF_RECORDS {
            for z in zones.values_mut() {
                z.prune();
            }
            zones.retain(|_, z| z.len() > 0);
            if zones.values().map(ZoneProofs::len).sum::<usize>() + proofs.len() > MAX_PROOF_RECORDS {
                zones.clear();
            }
        }
        let entry = zones.entry(zone).or_default();
        entry.soa = Some(soa_proof);
        for p in proofs {
            if p.rr.rtype == Some(DnsType::Nsec) {
                let owner = p.owner();
                entry.nsec.retain(|e| e.owner() != owner);
                entry.nsec.push(p);
            } else {
                let (Some(alg), Some(it), Some(salt)) =
                    (p.rr.nsec3_hash_algorithm(), p.rr.nsec3_iterations(), p.rr.nsec3_salt())
                else {
                    continue;
                };
                let params = (alg, it, salt.to_vec());
                if entry.nsec3_params.as_ref() != Some(&params) {
                    // The zone was re-signed with new parameters: the old
                    // chain no longer describes it.
                    entry.nsec3.clear();
                    entry.nsec3_params = Some(params);
                }
                let hash = p.owner_hash.clone();
                entry.nsec3.retain(|e| e.owner_hash != hash);
                entry.nsec3.push(p);
            }
        }
    }

    /// An NXDOMAIN or NODATA answer for `question` from cached proofs, or
    /// `None` when the cache does not hold enough to prove one (in which case
    /// the query must go upstream).
    pub fn synthesize(&self, question: &DnsQuestion) -> Option<SynthesizedDenial> {
        let qtype = question.raw_qtype;
        if META_TYPES.contains(&qtype) || question.raw_qclass != crate::wire::DnsClass::In.value() {
            return None;
        }
        let qname = normalize_name(&question.name);
        let mut zones = self.zones.lock().unwrap();
        let mut candidates: Vec<String> = zones
            .keys()
            .filter(|z| z.is_empty() || *z == &qname || is_descendant(&qname, z))
            .cloned()
            .collect();
        // Most specific zone first.
        candidates.sort_by_key(|z| std::cmp::Reverse(labels(z).len()));
        for z in candidates {
            let zp = zones.get_mut(&z)?;
            zp.prune();
            let Some(soa) = zp.soa.as_ref() else {
                continue;
            };
            let found = if !zp.nsec.is_empty() {
                synth_nsec(&zp.nsec, &z, &qname, qtype)
            } else if !zp.nsec3.is_empty() {
                synth_nsec3(zp, &z, &qname, qtype)
            } else {
                None
            };
            if let Some((rcode, chosen)) = found {
                return Some(SynthesizedDenial {
                    rcode,
                    soa: soa.record(),
                    proofs: chosen.into_iter().map(Proof::record).collect(),
                });
            }
        }
        None
    }
}

/// Deduplicate by pointer identity, keeping order.
fn distinct<'a>(items: Vec<&'a Proof>) -> Vec<&'a Proof> {
    let mut out: Vec<&Proof> = Vec::new();
    for p in items {
        if !out.iter().any(|q| std::ptr::eq(*q, p)) {
            out.push(p);
        }
    }
    out
}

fn nsec_covers(p: &Proof, name: &str) -> bool {
    p.rr.nsec_next_domain().is_some_and(|next| in_canonical_range(&p.rr.name, &next, name))
}

/// RFC 4035 §5.4 with RFC 8198 §5.1: NODATA from a matching NSEC, or NXDOMAIN
/// from a covering NSEC plus one covering the wildcard at the closest
/// encloser.
fn synth_nsec<'a>(nsecs: &'a [Proof], zone: &str, qname: &str, qtype: u16) -> Option<(u16, Vec<&'a Proof>)> {
    if let Some(m) = nsecs.iter().find(|p| p.owner() == qname) {
        let types = m.types()?;
        return proves_nodata(&types, qtype).then(|| (0, vec![m]));
    }
    let cover = nsecs.iter().find(|p| nsec_covers(p, qname))?;
    let (owner, next) = (cover.owner(), normalize_name(&cover.rr.nsec_next_domain()?));
    // Names beneath a delegation or DNAME are not the parent's to deny.
    if is_descendant(qname, &owner) && is_cut(&cover.types()?) {
        return None;
    }
    // The closest encloser is the deepest ancestor of qname that the covering
    // NSEC's own endpoints prove exists.
    let shared = common_suffix_labels(qname, &owner).max(common_suffix_labels(qname, &next));
    let ce = suffix(qname, shared);
    if ce != zone && !is_descendant(&ce, zone) && !zone.is_empty() {
        return None;
    }
    let wildcard = wildcard_of(&ce);
    if nsecs.iter().any(|p| p.owner() == wildcard) {
        return None; // the wildcard exists: not NXDOMAIN
    }
    let wc_cover = nsecs.iter().find(|p| nsec_covers(p, &wildcard))?;
    Some((RCODE_NXDOMAIN, distinct(vec![cover, wc_cover])))
}

/// RFC 5155 §8.4-8.6 with RFC 8198 §5.2: NODATA from a matching NSEC3, or
/// NXDOMAIN from a closest-encloser proof (match at the encloser, covers of the
/// next closer name and of the wildcard, none of them Opt-Out).
fn synth_nsec3<'a>(zp: &'a ZoneProofs, zone: &str, qname: &str, qtype: u16) -> Option<(u16, Vec<&'a Proof>)> {
    let (alg, iterations, salt) = zp.nsec3_params.as_ref()?;
    if *alg != 1 || *iterations > MAX_NSEC3_ITERATIONS {
        return None;
    }
    let hash = |name: &str| -> Option<Vec<u8>> { Some(nsec3_hash(&encode_name(name).ok()?, *iterations, salt)) };
    let matching = |h: &[u8]| zp.nsec3.iter().find(|p| p.owner_hash == h);
    let covering = |h: &[u8]| {
        zp.nsec3.iter().find(|p| {
            p.rr.nsec3_next_hashed_owner().is_some_and(|next| hash_in_range(&p.owner_hash, next, h))
        })
    };
    let opt_out = |p: &Proof| p.rr.nsec3_flags().is_none_or(|f| f & NSEC3_OPT_OUT != 0);

    let qhash = hash(qname)?;
    if let Some(m) = matching(&qhash) {
        let types = m.types()?;
        return proves_nodata(&types, qtype).then(|| (0, vec![m]));
    }

    // Walk up to the closest encloser: the deepest ancestor with a matching NSEC3.
    let depth = labels(qname).len();
    let zone_depth = labels(zone).len();
    for keep in (zone_depth..depth).rev() {
        let ce = suffix(qname, keep);
        let Some(ce_match) = matching(&hash(&ce)?) else {
            continue;
        };
        if is_cut(&ce_match.types()?) {
            return None;
        }
        let next_closer = suffix(qname, keep + 1);
        let nc_cover = covering(&hash(&next_closer)?)?;
        let wildcard = wildcard_of(&ce);
        let wh = hash(&wildcard)?;
        if matching(&wh).is_some() {
            return None; // the wildcard exists
        }
        let wc_cover = covering(&wh)?;
        if opt_out(nc_cover) || opt_out(wc_cover) {
            return None;
        }
        return Some((RCODE_NXDOMAIN, distinct(vec![ce_match, nc_cover, wc_cover])));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsClass, FLAG_QR};

    const ZONE: &str = "example.com";
    const A: u16 = 1;
    const TXT: u16 = 16;
    const RRSIG: u16 = 46;
    const NSEC_T: u16 = 47;
    const NSEC3_T: u16 = 50;

    /// An RRSIG that this cache treats as genuine: the caller has validated.
    fn rrsig(name: &str, covered: u16, signer: &str, valid_for: u32) -> DnsResourceRecord {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&covered.to_be_bytes());
        rdata.push(13);
        rdata.push(2);
        rdata.extend_from_slice(&3600u32.to_be_bytes());
        rdata.extend_from_slice(&(now_unix() + valid_for).to_be_bytes());
        rdata.extend_from_slice(&now_unix().saturating_sub(60).to_be_bytes());
        rdata.extend_from_slice(&1234u16.to_be_bytes());
        rdata.extend_from_slice(&encode_name(signer).unwrap());
        rdata.extend_from_slice(&[7u8; 64]);
        DnsResourceRecord::new(name, DnsType::Rrsig, DnsClass::In, 3600, rdata)
    }

    fn soa(minimum: u32) -> DnsResourceRecord {
        DnsResourceRecord::soa(ZONE, 3600, "ns.example.com", "h.example.com", 1, 1, 1, 1, minimum).unwrap()
    }

    /// A negative response carrying `proofs`, signed by `ZONE`.
    fn negative(soa_minimum: u32, proofs: Vec<DnsResourceRecord>) -> DnsMessage {
        let mut authorities = vec![soa(soa_minimum), rrsig(ZONE, TYPE_SOA, ZONE, 3600)];
        for p in proofs {
            authorities.push(rrsig(&p.name, p.raw_type, ZONE, 3600));
            authorities.push(p);
        }
        DnsMessage::new(1, FLAG_QR, vec![], vec![], authorities, vec![])
    }

    fn q(name: &str, qtype: DnsType) -> DnsQuestion {
        DnsQuestion::in_class(name, qtype)
    }

    // ---- NSEC ----

    /// example.com -> a -> c -> deleg -> w -> *.w -> (apex): the zone below.
    /// `deleg` is a delegation, `w` has a wildcard, `cname` has a CNAME.
    fn nsec_zone() -> Vec<DnsResourceRecord> {
        let ring: [(&str, &str, Vec<u16>); 7] = [
            ("example.com", "a.example.com", vec![2, TYPE_SOA, RRSIG, NSEC_T]),
            ("a.example.com", "c.example.com", vec![A, RRSIG, NSEC_T]),
            ("c.example.com", "cname.example.com", vec![A, RRSIG, NSEC_T]),
            ("cname.example.com", "deleg.example.com", vec![TYPE_CNAME, RRSIG, NSEC_T]),
            ("deleg.example.com", "w.example.com", vec![TYPE_NS, NSEC_T]),
            ("w.example.com", "*.w.example.com", vec![TXT, RRSIG, NSEC_T]),
            ("*.w.example.com", "example.com", vec![A, RRSIG, NSEC_T]),
        ];
        ring.into_iter()
            .map(|(owner, next, types)| DnsResourceRecord::nsec(owner, 3600, next, types).unwrap())
            .collect()
    }

    fn cached_nsec() -> DenialCache {
        let cache = DenialCache::new();
        cache.store_validated(&negative(3600, nsec_zone()));
        cache
    }

    #[test]
    fn nodata_comes_from_a_matching_nsec_whose_bitmap_lacks_the_type() {
        let cache = cached_nsec();
        let d = cache.synthesize(&q("a.example.com", DnsType::Txt)).expect("a has no TXT");
        assert_eq!(d.rcode, 0);
        assert_eq!(d.proofs.len(), 1);
        assert!(cache.synthesize(&q("a.example.com", DnsType::A)).is_none(), "A exists at a: go upstream");
    }

    #[test]
    fn nxdomain_needs_the_covering_nsec_and_one_covering_the_wildcard() {
        let cache = cached_nsec();
        let d = cache.synthesize(&q("b.example.com", DnsType::A)).expect("between a and c");
        assert_eq!(d.rcode, RCODE_NXDOMAIN);
        let owners: Vec<_> = d.proofs.iter().map(|p| normalize_name(&p.rr.name)).collect();
        assert_eq!(owners, ["a.example.com", "example.com"], "the covering NSEC and the wildcard's");

        // Without the record that covers *.example.com the cache cannot rule a
        // wildcard out, so it must ask.
        let partial = DenialCache::new();
        let only: Vec<_> = nsec_zone().into_iter().filter(|r| normalize_name(&r.name) != "example.com").collect();
        partial.store_validated(&negative(3600, only));
        assert!(partial.synthesize(&q("b.example.com", DnsType::A)).is_none());
    }

    #[test]
    fn an_existing_wildcard_blocks_nxdomain() {
        let cache = cached_nsec();
        assert!(cache.synthesize(&q("x.w.example.com", DnsType::A)).is_none(), "*.w.example.com would answer");
    }

    #[test]
    fn nothing_is_synthesised_at_or_below_a_delegation_except_ds() {
        let cache = cached_nsec();
        assert!(cache.synthesize(&q("host.deleg.example.com", DnsType::A)).is_none(), "the child zone's business");
        assert!(cache.synthesize(&q("deleg.example.com", DnsType::A)).is_none(), "needs a referral");
        let ds = cache.synthesize(&q("deleg.example.com", DnsType::Ds)).expect("no DS at an unsigned cut");
        assert_eq!(ds.rcode, 0);
    }

    #[test]
    fn a_cname_at_the_name_means_nodata_cannot_be_asserted() {
        let cache = cached_nsec();
        assert!(cache.synthesize(&q("cname.example.com", DnsType::A)).is_none());
    }

    #[test]
    fn other_zones_and_meta_queries_get_nothing() {
        let cache = cached_nsec();
        assert!(cache.synthesize(&q("b.example.org", DnsType::A)).is_none());
        assert!(cache.synthesize(&q("notexample.com", DnsType::A)).is_none(), "label boundary, not string suffix");
        assert!(cache.synthesize(&q("a.example.com", DnsType::Any)).is_none());
        assert!(cache.synthesize(&q("a.example.com", DnsType::Rrsig)).is_none());
        let chaos = DnsQuestion::new("b.example.com", DnsType::A, DnsClass::Ch);
        assert!(cache.synthesize(&chaos).is_none());
    }

    #[test]
    fn authorities_carry_the_soa_and_only_dnssec_clients_get_the_proof() {
        let cache = cached_nsec();
        let d = cache.synthesize(&q("b.example.com", DnsType::A)).unwrap();
        let plain = d.authorities(false);
        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].rtype, Some(DnsType::Soa));
        let signed = d.authorities(true);
        let count = |t: DnsType| signed.iter().filter(|r| r.rtype == Some(t)).count();
        assert_eq!((count(DnsType::Soa), count(DnsType::Nsec), count(DnsType::Rrsig)), (1, 2, 3));
    }

    #[test]
    fn lifetimes_follow_rfc_8198_section_5_4() {
        // SOA minimum below the NSEC TTL wins.
        let cache = DenialCache::new();
        cache.store_validated(&negative(20, nsec_zone()));
        let d = cache.synthesize(&q("b.example.com", DnsType::A)).unwrap();
        assert!(d.proofs.iter().all(|p| p.rr.ttl <= 20) && d.soa.rr.ttl <= 20);

        // Three hours is the ceiling whatever the records claim.
        let long: Vec<_> = nsec_zone()
            .into_iter()
            .map(|r| DnsResourceRecord::new(r.name.clone(), DnsType::Nsec, DnsClass::In, 864_000, r.rdata.clone()))
            .collect();
        let cache = DenialCache::new();
        cache.store_validated(&negative(864_000, long));
        let d = cache.synthesize(&q("b.example.com", DnsType::A)).unwrap();
        assert!(d.proofs.iter().all(|p| p.rr.ttl <= MAX_TTL));

        // A signature about to expire bounds the proof too.
        let cache = DenialCache::new();
        let mut msg = negative(3600, nsec_zone());
        for r in msg.authorities.iter_mut().filter(|r| r.rtype == Some(DnsType::Rrsig)) {
            *r = rrsig(&r.name, r.rrsig_type_covered().unwrap(), ZONE, 5);
        }
        cache.store_validated(&msg);
        assert!(cache.synthesize(&q("b.example.com", DnsType::A)).unwrap().proofs.iter().all(|p| p.rr.ttl <= 5));
    }

    #[test]
    fn unsigned_or_soa_less_responses_are_not_cached() {
        let cache = DenialCache::new();
        let mut unsigned = negative(3600, nsec_zone());
        unsigned.authorities.retain(|r| r.rtype != Some(DnsType::Rrsig));
        cache.store_validated(&unsigned);
        assert!(cache.is_empty(), "no signatures, no proof");

        let mut no_soa = negative(3600, nsec_zone());
        no_soa.authorities.retain(|r| r.rtype != Some(DnsType::Soa));
        cache.store_validated(&no_soa);
        assert!(cache.is_empty(), "the SOA gives the proof its lifetime");
    }

    #[test]
    fn proofs_from_a_signer_other_than_the_zone_are_ignored() {
        let cache = DenialCache::new();
        let mut msg = negative(3600, nsec_zone());
        for r in msg.authorities.iter_mut().filter(|r| r.rtype == Some(DnsType::Rrsig) && r.rrsig_type_covered() == Some(NSEC_T)) {
            *r = rrsig(&r.name, NSEC_T, "com", 3600);
        }
        cache.store_validated(&msg);
        // Filed under the signer, so they only ever answer names under it.
        assert!(cache.synthesize(&q("b.example.com", DnsType::A)).is_some());
        assert!(cache.synthesize(&q("b.example.org", DnsType::A)).is_none());
    }

    // ---- NSEC3 ----

    fn nsec3_ring(names: &[(&str, Vec<u16>)], flags: u8, iterations: u16, salt: &[u8]) -> Vec<DnsResourceRecord> {
        let mut hashed: Vec<(Vec<u8>, Vec<u16>)> = names
            .iter()
            .map(|(n, t)| (nsec3_hash(&encode_name(n).unwrap(), iterations, salt), t.clone()))
            .collect();
        hashed.sort();
        (0..hashed.len())
            .map(|i| {
                let (h, types) = &hashed[i];
                let next = &hashed[(i + 1) % hashed.len()].0;
                DnsResourceRecord::nsec3(
                    format!("{}.{ZONE}", base32hex::encode(h)),
                    3600,
                    1,
                    flags,
                    iterations,
                    salt,
                    next,
                    types.clone(),
                )
            })
            .collect()
    }

    fn zone_names() -> Vec<(&'static str, Vec<u16>)> {
        vec![
            ("example.com", vec![2, TYPE_SOA, RRSIG, 51, NSEC3_T]),
            ("a.example.com", vec![A, RRSIG, NSEC3_T]),
            ("deleg.example.com", vec![TYPE_NS, NSEC3_T]),
            ("w.example.com", vec![TXT, RRSIG, NSEC3_T]),
            ("*.w.example.com", vec![A, RRSIG, NSEC3_T]),
        ]
    }

    fn cached_nsec3(names: &[(&str, Vec<u16>)], flags: u8, iterations: u16) -> DenialCache {
        let cache = DenialCache::new();
        cache.store_validated(&negative(3600, nsec3_ring(names, flags, iterations, &[0xAB, 0xCD])));
        cache
    }

    #[test]
    fn nsec3_nodata_and_nxdomain_from_a_closest_encloser_proof() {
        let cache = cached_nsec3(&zone_names(), 0, 3);
        let nodata = cache.synthesize(&q("a.example.com", DnsType::Txt)).expect("a has no TXT");
        assert_eq!((nodata.rcode, nodata.proofs.len()), (0, 1));

        let nx = cache.synthesize(&q("b.example.com", DnsType::A)).expect("closest encloser proof");
        assert_eq!(nx.rcode, RCODE_NXDOMAIN);
        assert!(nx.proofs.iter().all(|p| p.rr.rtype == Some(DnsType::Nsec3)));
        assert!(nx.proofs.len() >= 2, "encloser match plus covers");

        // Deeper names walk up to the same encloser.
        assert_eq!(cache.synthesize(&q("x.y.example.com", DnsType::Aaaa)).unwrap().rcode, RCODE_NXDOMAIN);
    }

    #[test]
    fn nsec3_wildcards_delegations_and_missing_encloser_records_block_synthesis() {
        let cache = cached_nsec3(&zone_names(), 0, 3);
        assert!(cache.synthesize(&q("x.w.example.com", DnsType::A)).is_none(), "wildcard exists");
        assert!(cache.synthesize(&q("host.deleg.example.com", DnsType::A)).is_none(), "below a cut");

        // No NSEC3 for the apex: the closest encloser cannot be shown.
        let without_apex: Vec<_> = zone_names().into_iter().filter(|(n, _)| *n != "example.com").collect();
        let cache = cached_nsec3(&without_apex, 0, 3);
        assert!(cache.synthesize(&q("b.example.com", DnsType::A)).is_none());
    }

    #[test]
    fn opt_out_proves_nothing_and_excessive_iterations_are_refused() {
        // Opt-Out (flag 1) on the covering records: RFC 8198 section 5.2.
        let cache = cached_nsec3(&zone_names(), NSEC3_OPT_OUT, 3);
        assert!(cache.synthesize(&q("b.example.com", DnsType::A)).is_none());
        // ...but an exact match still proves NODATA.
        assert!(cache.synthesize(&q("a.example.com", DnsType::Txt)).is_some());

        let cache = cached_nsec3(&zone_names(), 0, MAX_NSEC3_ITERATIONS + 1);
        assert!(cache.synthesize(&q("b.example.com", DnsType::A)).is_none());
        let cache = cached_nsec3(&zone_names(), 0, MAX_NSEC3_ITERATIONS);
        assert!(cache.synthesize(&q("b.example.com", DnsType::A)).is_some());
    }

    #[test]
    fn new_nsec3_parameters_replace_the_old_chain() {
        let cache = DenialCache::new();
        cache.store_validated(&negative(3600, nsec3_ring(&zone_names(), 0, 3, &[1])));
        let before = cache.len();
        cache.store_validated(&negative(3600, nsec3_ring(&zone_names(), 0, 5, &[2])));
        assert_eq!(cache.len(), before, "the re-signed chain replaced, not joined, the old one");
    }
}
