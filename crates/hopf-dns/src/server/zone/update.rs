// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 2136 dynamic update processing against a [`Zone`].
//!
//! The sections of an UPDATE message reuse the ordinary four: the zone
//! (question), prerequisites (answer), updates (authority) and additional.

use std::collections::HashMap;

use super::model::{Change, Zone};
use crate::wire::{
    normalize_name, DnsMessage, DnsResourceRecord, RCODE_FORMERR, RCODE_NOERROR, RCODE_NOTZONE,
    RCODE_NXDOMAIN, RCODE_NXRRSET, RCODE_YXDOMAIN, RCODE_YXRRSET,
};

const CLASS_IN: u16 = 1;
const CLASS_NONE: u16 = 254;
const CLASS_ANY: u16 = 255;
const TYPE_OPT: u16 = 41;
const TYPE_ANY: u16 = 255;

/// Meta types (RFC 6895 §3.1) that may not appear as data in an update.
fn is_meta(t: u16) -> bool {
    t == TYPE_OPT || (249..=255).contains(&t)
}

/// Outcome of applying one UPDATE.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UpdateResult {
    pub(crate) rcode: u16,
    /// The zone changed (and its serial moved).
    pub(crate) changed: bool,
}

fn refuse(rcode: u16) -> UpdateResult {
    UpdateResult {
        rcode,
        changed: false,
    }
}

/// Check prerequisites and apply the update section atomically: either every
/// change lands (and the SOA serial moves once) or none does (RFC 2136 §3.4).
pub(crate) fn apply(zone: &mut Zone, req: &DnsMessage) -> UpdateResult {
    // §3.2: prerequisites.
    let mut value_sets: HashMap<(String, u16), Vec<&DnsResourceRecord>> = HashMap::new();
    for rr in &req.answers {
        let name = normalize_name(&rr.name);
        if !zone.is_within(&name) {
            return refuse(RCODE_NOTZONE);
        }
        let t = rr.raw_type;
        match rr.raw_class {
            CLASS_ANY | CLASS_NONE => {
                if rr.ttl != 0 || !rr.rdata.is_empty() {
                    return refuse(RCODE_FORMERR);
                }
                let exists = if t == TYPE_ANY {
                    zone.name_exists(&name)
                } else {
                    !zone.rrset(&name, t).is_empty()
                };
                let (want, fail) = match (rr.raw_class, t == TYPE_ANY) {
                    (CLASS_ANY, true) => (true, RCODE_NXDOMAIN),
                    (CLASS_ANY, false) => (true, RCODE_NXRRSET),
                    (_, true) => (false, RCODE_YXDOMAIN),
                    (_, false) => (false, RCODE_YXRRSET),
                };
                if exists != want {
                    return refuse(fail);
                }
            }
            CLASS_IN => {
                if is_meta(t) {
                    return refuse(RCODE_FORMERR);
                }
                value_sets.entry((name, t)).or_default().push(rr);
            }
            _ => return refuse(RCODE_FORMERR),
        }
    }
    // Value-dependent prerequisites compare whole RRsets, ignoring TTL.
    for ((name, t), want) in &value_sets {
        let have = zone.rrset(name, *t);
        let same = have.len() == want.len()
            && want.iter().all(|w| have.iter().any(|h| h.rdata == w.rdata))
            && have.iter().all(|h| want.iter().any(|w| w.rdata == h.rdata));
        if !same {
            return refuse(RCODE_NXRRSET);
        }
    }

    // §3.4.1: prescan, so a malformed record cannot leave a half-applied update.
    for rr in &req.authorities {
        if !zone.is_within(&normalize_name(&rr.name)) {
            return refuse(RCODE_NOTZONE);
        }
        let t = rr.raw_type;
        let ok = match rr.raw_class {
            CLASS_IN => !is_meta(t),
            CLASS_ANY => rr.ttl == 0 && rr.rdata.is_empty() && (t == TYPE_ANY || !is_meta(t)),
            CLASS_NONE => rr.ttl == 0 && !is_meta(t),
            _ => false,
        };
        if !ok {
            return refuse(RCODE_FORMERR);
        }
    }

    // §3.4.2: apply in order.
    let mut ch = Change::default();
    for rr in &req.authorities {
        match rr.raw_class {
            CLASS_IN => zone.add_rr(rr.clone(), &mut ch),
            CLASS_ANY if rr.raw_type == TYPE_ANY => zone.delete_name(&rr.name, &mut ch),
            CLASS_ANY => zone.delete_rrset(&rr.name, rr.raw_type, &mut ch),
            _ => zone.delete_rr(rr, &mut ch),
        }
    }
    let changed = zone.commit(ch);
    UpdateResult {
        rcode: RCODE_NOERROR,
        changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsQuestion, DnsType, OPCODE_UPDATE};
    use std::net::Ipv4Addr;

    fn zone() -> Zone {
        Zone::from_zone_text(
            "$TTL 60\n@ SOA ns1 h 10 3600 900 604800 60\n NS ns1\n NS ns2\nns1 A 192.0.2.1\nns2 A 192.0.2.2\nhost A 192.0.2.10\n A 192.0.2.11\nalias CNAME host\n",
            Some("example.com"),
        )
        .unwrap()
    }

    fn update(prereq: Vec<DnsResourceRecord>, updates: Vec<DnsResourceRecord>) -> DnsMessage {
        DnsMessage::new(
            1,
            OPCODE_UPDATE << 11,
            vec![DnsQuestion::in_class("example.com", DnsType::Soa)],
            prereq,
            updates,
            Vec::new(),
        )
    }

    fn a(name: &str, ip: [u8; 4]) -> DnsResourceRecord {
        DnsResourceRecord::a(name, 120, Ipv4Addr::from(ip))
    }

    fn special(name: &str, ty: u16, class: u16, rdata: Vec<u8>) -> DnsResourceRecord {
        DnsResourceRecord::opaque(name, ty, class, 0, rdata)
    }

    #[test]
    fn add_bumps_the_serial_once_and_is_journalled() {
        let mut z = zone();
        let r = apply(&mut z, &update(vec![], vec![a("new.example.com", [1, 1, 1, 1]), a("new.example.com", [2, 2, 2, 2])]));
        assert_eq!(r, UpdateResult { rcode: 0, changed: true });
        assert_eq!(z.serial(), 11);
        assert_eq!(z.rrset("new.example.com", 1).len(), 2);
        let j = z.changes_since(10).unwrap();
        assert_eq!(j.len(), 1);
        assert_eq!((j[0].from, j[0].to), (10, 11));
        assert!(j[0].deleted.iter().any(|r| r.raw_type == 6), "old SOA is in the deletions");
        assert!(j[0].added.iter().any(|r| r.raw_type == 6), "new SOA is in the additions");
    }

    #[test]
    fn a_no_op_update_changes_nothing() {
        let mut z = zone();
        let mut same = a("host.example.com", [192, 0, 2, 10]);
        same.ttl = 60; // identical to the zone's record
        let r = apply(&mut z, &update(vec![], vec![same]));
        assert_eq!((r.rcode, r.changed), (0, false));
        assert_eq!(z.serial(), 10);
        // Deleting what is not there is also a no-op.
        let r = apply(&mut z, &update(vec![], vec![special("ghost.example.com", 1, CLASS_ANY, vec![])]));
        assert!(!r.changed);
    }

    #[test]
    fn deletes_by_rrset_name_and_exact_record() {
        let mut z = zone();
        apply(&mut z, &update(vec![], vec![special("host.example.com", 1, CLASS_NONE, vec![192, 0, 2, 10])]));
        assert_eq!(z.rrset("host.example.com", 1).len(), 1, "one exact record removed");
        apply(&mut z, &update(vec![], vec![special("host.example.com", 1, CLASS_ANY, vec![])]));
        assert!(z.rrset("host.example.com", 1).is_empty(), "whole RRset removed");
        apply(&mut z, &update(vec![], vec![special("ns1.example.com", TYPE_ANY, CLASS_ANY, vec![])]));
        assert!(!z.name_exists("ns1.example.com"), "name removed");
    }

    #[test]
    fn the_apex_soa_and_last_ns_are_protected() {
        let mut z = zone();
        apply(&mut z, &update(vec![], vec![special("example.com", TYPE_ANY, CLASS_ANY, vec![])]));
        assert_eq!(z.ns_records().len(), 2, "apex NS survives delete-name");
        assert_eq!(z.rrset("example.com", 6).len(), 1);
        apply(&mut z, &update(vec![], vec![special("example.com", 2, CLASS_ANY, vec![])]));
        assert_eq!(z.ns_records().len(), 2, "apex NS RRset cannot be deleted");
        let ns1 = DnsResourceRecord::ns("example.com", 0, "ns1.example.com").unwrap();
        let ns2 = DnsResourceRecord::ns("example.com", 0, "ns2.example.com").unwrap();
        let none = |rr: &DnsResourceRecord| special("example.com", 2, CLASS_NONE, rr.rdata.clone());
        apply(&mut z, &update(vec![], vec![none(&ns1)]));
        assert_eq!(z.ns_records().len(), 1);
        apply(&mut z, &update(vec![], vec![none(&ns2)]));
        assert_eq!(z.ns_records().len(), 1, "the last NS stays");
    }

    #[test]
    fn cname_conflicts_are_ignored_not_errors() {
        let mut z = zone();
        let cn = DnsResourceRecord::cname("host.example.com", 60, "x.example.com").unwrap();
        let r = apply(&mut z, &update(vec![], vec![cn]));
        assert_eq!((r.rcode, r.changed), (0, false), "CNAME onto existing data ignored");
        let r = apply(&mut z, &update(vec![], vec![a("alias.example.com", [9, 9, 9, 9])]));
        assert_eq!((r.rcode, r.changed), (0, false), "data onto a CNAME ignored");
    }

    #[test]
    fn a_newer_soa_replaces_and_sets_the_serial() {
        let mut z = zone();
        let soa = DnsResourceRecord::soa("example.com", 60, "ns1.example.com", "h.example.com", 500, 1, 2, 3, 4).unwrap();
        let r = apply(&mut z, &update(vec![], vec![soa]));
        assert!(r.changed);
        assert_eq!(z.serial(), 500, "not 501");
        let old = DnsResourceRecord::soa("example.com", 60, "ns1.example.com", "h.example.com", 5, 1, 2, 3, 4).unwrap();
        assert!(!apply(&mut z, &update(vec![], vec![old])).changed, "an older SOA is ignored");
    }

    #[test]
    fn prerequisites_gate_the_update_and_map_to_the_right_rcodes() {
        let mut z = zone();
        let add = vec![a("p.example.com", [5, 5, 5, 5])];
        let cases: Vec<(Vec<DnsResourceRecord>, u16)> = vec![
            (vec![special("host.example.com", TYPE_ANY, CLASS_ANY, vec![])], 0),
            (vec![special("nope.example.com", TYPE_ANY, CLASS_ANY, vec![])], RCODE_NXDOMAIN),
            (vec![special("host.example.com", 1, CLASS_ANY, vec![])], 0),
            (vec![special("host.example.com", 28, CLASS_ANY, vec![])], RCODE_NXRRSET),
            (vec![special("host.example.com", TYPE_ANY, CLASS_NONE, vec![])], RCODE_YXDOMAIN),
            (vec![special("nope.example.com", TYPE_ANY, CLASS_NONE, vec![])], 0),
            (vec![special("host.example.com", 1, CLASS_NONE, vec![])], RCODE_YXRRSET),
            (vec![special("host.example.com", 28, CLASS_NONE, vec![])], 0),
            // Value dependent: the whole RRset must match, ignoring TTL.
            (vec![a("host.example.com", [192, 0, 2, 10]), a("host.example.com", [192, 0, 2, 11])], 0),
            (vec![a("host.example.com", [192, 0, 2, 10])], RCODE_NXRRSET),
            (vec![special("out.other.org", TYPE_ANY, CLASS_ANY, vec![])], RCODE_NOTZONE),
            (vec![DnsResourceRecord::opaque("host.example.com", 1, CLASS_ANY, 5, vec![])], RCODE_FORMERR),
        ];
        for (i, (prereq, want)) in cases.into_iter().enumerate() {
            let mut scratch = z.clone();
            let r = apply(&mut scratch, &update(prereq, add.clone()));
            assert_eq!(r.rcode, want, "case {i}");
            assert_eq!(r.changed, want == 0, "case {i}: update applies only if prerequisites hold");
        }
        let _ = &mut z;
    }

    #[test]
    fn a_bad_record_in_the_update_section_leaves_the_zone_untouched() {
        let mut z = zone();
        let before = z.records();
        let bad = DnsResourceRecord::opaque("x.example.com", TYPE_ANY, CLASS_IN, 60, vec![]);
        let r = apply(&mut z, &update(vec![], vec![a("ok.example.com", [1, 1, 1, 1]), bad]));
        assert_eq!(r.rcode, RCODE_FORMERR);
        assert_eq!(z.records(), before, "atomic: the good record was not applied either");
        let outside = a("elsewhere.other.org", [1, 1, 1, 1]);
        assert_eq!(apply(&mut z, &update(vec![], vec![outside])).rcode, RCODE_NOTZONE);
        assert_eq!(z.records(), before);
    }

    #[test]
    fn changing_an_rrset_ttl_retimes_the_whole_set() {
        let mut z = zone();
        let mut r = a("host.example.com", [192, 0, 2, 10]);
        r.ttl = 999;
        assert!(apply(&mut z, &update(vec![], vec![r])).changed);
        assert!(z.rrset("host.example.com", 1).iter().all(|x| x.ttl == 999));
    }

    #[test]
    fn journal_chains_multiple_updates_and_reports_gaps() {
        let mut z = zone();
        for i in 0..3u8 {
            apply(&mut z, &update(vec![], vec![a(&format!("h{i}.example.com"), [i, i, i, i])]));
        }
        assert_eq!(z.serial(), 13);
        assert_eq!(z.changes_since(10).unwrap().len(), 3);
        assert_eq!(z.changes_since(12).unwrap().len(), 1);
        assert!(z.changes_since(13).is_none(), "already current");
        assert!(z.changes_since(3).is_none(), "the journal does not reach back that far");
    }

    #[test]
    fn apply_diff_replays_a_journal_on_another_copy() {
        let mut primary = zone();
        let mut secondary = zone();
        apply(&mut primary, &update(vec![], vec![a("new.example.com", [1, 1, 1, 1])]));
        apply(&mut primary, &update(vec![], vec![special("host.example.com", 1, CLASS_ANY, vec![])]));
        for e in primary.changes_since(10).unwrap() {
            secondary.apply_diff(e.deleted, e.added).unwrap();
        }
        assert_eq!(secondary.records(), primary.records());
        assert_eq!(secondary.serial(), 12);
        // A diff that does not start at our serial is rejected.
        let stale = primary.changes_since(10).unwrap().remove(0);
        assert!(secondary.apply_diff(stale.deleted, stale.added).is_err());
    }
}
