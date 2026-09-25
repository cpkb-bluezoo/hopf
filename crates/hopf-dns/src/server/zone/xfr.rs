// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Server side of zone transfer: AXFR (RFC 5936) and IXFR (RFC 1995)
//! response messages.

use super::model::{serial_gt, Zone};
use crate::wire::{DnsMessage, DnsResourceRecord, FLAG_AA, FLAG_RA};

/// Payload budget per message. Well under the 64 KiB a TCP message may
/// carry, and estimated without name compression so it is never exceeded.
const MESSAGE_BUDGET: usize = 16 * 1024;
const TYPE_SOA: u16 = 6;

fn estimate(rr: &DnsResourceRecord) -> usize {
    rr.name.len() + 2 + 10 + rr.rdata.len()
}

/// Pack `rrs` into response messages for `query`. The question is echoed in
/// the first message only (RFC 5936 §2.2.1).
fn pack(query: &DnsMessage, rrs: Vec<DnsResourceRecord>) -> Vec<DnsMessage> {
    let shell = |first: bool| {
        let mut m = query.response_template(0);
        m.flags &= !FLAG_RA;
        m.flags |= FLAG_AA;
        if !first {
            m.questions.clear();
        }
        m
    };
    let mut out = Vec::new();
    let mut cur = shell(true);
    let mut size = 0;
    for rr in rrs {
        let n = estimate(&rr);
        if size > 0 && size + n > MESSAGE_BUDGET {
            out.push(std::mem::replace(&mut cur, shell(false)));
            size = 0;
        }
        size += n;
        cur.answers.push(rr);
    }
    out.push(cur);
    out
}

/// AXFR: SOA, every other record, SOA again.
pub(crate) fn axfr(query: &DnsMessage, zone: &Zone) -> Vec<DnsMessage> {
    let mut rrs = zone.records();
    rrs.push(zone.soa_record());
    pack(query, rrs)
}

/// IXFR for a client at `client_serial` (RFC 1995 §4): nothing to do, the
/// journalled differences, or (when the journal does not reach back) an
/// AXFR-style full transfer.
pub(crate) fn ixfr(query: &DnsMessage, zone: &Zone, client_serial: u32) -> Vec<DnsMessage> {
    let current = zone.soa_record();
    if !serial_gt(zone.serial(), client_serial) {
        return pack(query, vec![current]);
    }
    let Some(entries) = zone.changes_since(client_serial) else {
        return axfr(query, zone);
    };
    let mut rrs = vec![current.clone()];
    for e in entries {
        // Old SOA, then what went; new SOA, then what came.
        let (old_soa, deleted): (Vec<_>, Vec<_>) = e.deleted.into_iter().partition(|r| r.raw_type == TYPE_SOA);
        let (new_soa, added): (Vec<_>, Vec<_>) = e.added.into_iter().partition(|r| r.raw_type == TYPE_SOA);
        rrs.extend(old_soa);
        rrs.extend(deleted);
        rrs.extend(new_soa);
        rrs.extend(added);
    }
    rrs.push(current);
    pack(query, rrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsQuestion, DnsType};
    use std::net::Ipv4Addr;

    fn zone_with(n: usize) -> Zone {
        let mut text = String::from("$TTL 60\n@ SOA ns h 1 2 3 4 5\n NS ns\nns A 192.0.2.1\n");
        for i in 0..n {
            text.push_str(&format!("host{i:05}.some-longer-owner-name-to-take-space A 10.0.{}.{}\n", i / 250, i % 250));
        }
        Zone::from_zone_text(&text, Some("example.com")).unwrap()
    }

    fn query(ty: DnsType) -> DnsMessage {
        DnsMessage::query(7, DnsQuestion::in_class("example.com", ty), false)
    }

    #[test]
    fn axfr_is_soa_first_and_last_and_carries_every_record_once() {
        let z = zone_with(3);
        let msgs = axfr(&query(DnsType::Any), &z);
        assert_eq!(msgs.len(), 1);
        let a = &msgs[0].answers;
        assert_eq!(a.first().unwrap().raw_type, 6);
        assert_eq!(a.last().unwrap().raw_type, 6);
        assert_eq!(a.len(), z.record_count() + 1);
        assert!(msgs[0].flags & FLAG_AA != 0);
    }

    #[test]
    fn large_zones_split_into_messages_that_each_fit_a_tcp_frame() {
        let z = zone_with(2000);
        let msgs = axfr(&query(DnsType::Any), &z);
        assert!(msgs.len() > 2, "{} messages", msgs.len());
        assert_eq!(msgs[0].questions.len(), 1, "question only in the first");
        assert!(msgs[1..].iter().all(|m| m.questions.is_empty()));
        let total: usize = msgs.iter().map(|m| m.answers.len()).sum();
        assert_eq!(total, z.record_count() + 1);
        for m in &msgs {
            assert!(m.serialize().unwrap().len() < 65535);
            assert_eq!(m.id, 7);
        }
        assert_eq!(msgs.last().unwrap().answers.last().unwrap().raw_type, 6, "ends with SOA");
        // Reassembled and parsed back, it rebuilds the same zone.
        let mut records = Vec::new();
        for m in &msgs {
            records.extend(DnsMessage::parse(&m.serialize().unwrap()).unwrap().answers);
        }
        records.pop();
        let back = Zone::from_records("example.com", 60, records).unwrap();
        assert_eq!(back.records(), z.records());
    }

    #[test]
    fn ixfr_up_to_date_is_a_single_soa() {
        let z = zone_with(1);
        let m = ixfr(&query(DnsType::Soa), &z, z.serial());
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].answers.len(), 1);
        assert_eq!(m[0].answers[0].raw_type, 6);
    }

    #[test]
    fn ixfr_sends_differences_in_rfc_1995_order() {
        use crate::server::zone::update;
        let mut z = zone_with(1);
        let before = z.serial();
        let add = DnsResourceRecord::a("new.example.com", 60, Ipv4Addr::new(9, 9, 9, 9));
        let upd = DnsMessage::new(
            1,
            5 << 11,
            vec![DnsQuestion::in_class("example.com", DnsType::Soa)],
            vec![],
            vec![add.clone()],
            vec![],
        );
        assert!(update::apply(&mut z, &upd).changed);
        let m = ixfr(&query(DnsType::Soa), &z, before);
        assert_eq!(m.len(), 1);
        let types: Vec<u16> = m[0].answers.iter().map(|r| r.raw_type).collect();
        // SOA(new) SOA(old) [no deletions besides SOA] SOA(new) A SOA(new)
        assert_eq!(types, [6, 6, 6, 1, 6]);
        let serials: Vec<u32> = m[0].answers.iter().filter_map(|r| r.as_soa()).map(|s| s.serial).collect();
        assert_eq!(serials, [before + 1, before, before + 1, before + 1]);
    }

    #[test]
    fn ixfr_falls_back_to_a_full_transfer_when_the_journal_is_short() {
        let z = zone_with(2);
        let msgs = ixfr(&query(DnsType::Soa), &Zone::from_records("example.com", 60, {
            // A copy whose serial is ahead of anything journalled.
            let mut r = z.records();
            r[0] = DnsResourceRecord::soa("example.com", 60, "ns", "h", 50, 2, 3, 4, 5).unwrap();
            r
        }).unwrap(), 3);
        assert_eq!(msgs[0].answers.len() > 3, true, "AXFR-style: SOA, records, SOA");
        assert_eq!(msgs[0].answers.first().unwrap().raw_type, 6);
        assert_eq!(msgs[0].answers.last().unwrap().raw_type, 6);
    }
}
