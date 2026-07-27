// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Authenticated denial-of-existence (RFC 4035 §5.4): NSEC "qname falls
//! between owner and next" and NSEC3 closest-encloser proofs.
//!
//! Both proof families only tell you a name/type combination doesn't
//! exist *given that the NSEC(3) records themselves are genuine* — that
//! half is [`verify_denial`], which checks every NSEC/NSEC3 RRset in a
//! message's authority section is validly signed by an already
//! chain-of-trust-verified zone key (from [`super::DnssecChainWalk`],
//! mirroring how `client::validate_against_key` bridges the same gap for
//! ordinary answers) before trusting any of it.
//!
//! Scope: this covers direct NXDOMAIN/NODATA proofs only. Wildcard
//! non-existence (RFC 5155 §8.3's optional extra step) and Opt-Out
//! (§3/§6) are not implemented — an accepted, documented limitation.

use super::crypto::nsec3_hash;
use super::status::DnssecStatus;
use super::validator::{find_rrsigs, is_rrsig_current, verify_rrsig};
use crate::wire::{base32hex, canonical_compare, encode_name, normalize_name, DnsMessage, DnsResourceRecord, DnsType};

/// RFC 4034 §6.1 canonical-order range membership, with zone-apex
/// wraparound: the last NSEC(3) in a zone points back to the first, so
/// its range covers everything after `owner` *and* everything before
/// `next`.
fn in_canonical_range(owner: &str, next: &str, name: &str) -> bool {
    use std::cmp::Ordering::*;
    match canonical_compare(owner, next) {
        Less => canonical_compare(owner, name) == Less && canonical_compare(name, next) == Less,
        Equal => false, // single-owner zone: nothing is ever strictly "between"
        Greater => canonical_compare(owner, name) == Less || canonical_compare(name, next) == Less,
    }
}

/// True if `nsec`'s (owner, next) range covers `qname` — proves no name
/// exists there (RFC 4035 §5.4 NXDOMAIN case).
fn nsec_covers(nsec: &DnsResourceRecord, qname: &str) -> bool {
    let Some(next) = nsec.nsec_next_domain() else {
        return false;
    };
    in_canonical_range(&nsec.name, &next, qname)
}

/// True if `nsec` is owned by `qname` itself and its type bitmap omits
/// `qtype` — proves NODATA (RFC 4035 §5.4 NOERROR/no-answer case).
fn nsec_proves_nodata(nsec: &DnsResourceRecord, qname: &str, qtype: DnsType) -> bool {
    if normalize_name(&nsec.name) != normalize_name(qname) {
        return false;
    }
    nsec.nsec_types().is_some_and(|types| !types.contains(&qtype.value()))
}

fn nsec_proves_denial(records: &[&DnsResourceRecord], qname: &str, qtype: DnsType) -> bool {
    records.iter().any(|rr| nsec_proves_nodata(rr, qname, qtype))
        || records.iter().any(|rr| nsec_covers(rr, qname))
}

/// Raw-byte range membership for NSEC3 hashes: fixed-length digests, so
/// unsigned byte-wise comparison already matches RFC 5155's ordering,
/// with the same zone-apex wraparound as [`in_canonical_range`].
fn hash_in_range(owner_hash: &[u8], next_hash: &[u8], candidate: &[u8]) -> bool {
    match owner_hash.cmp(next_hash) {
        std::cmp::Ordering::Less => owner_hash < candidate && candidate < next_hash,
        std::cmp::Ordering::Equal => false,
        std::cmp::Ordering::Greater => candidate > owner_hash || candidate < next_hash,
    }
}

/// NSEC3 hash of `name` under the parameters carried by `nsec3` itself —
/// every NSEC3 in one response must share the same algorithm/iterations/
/// salt (RFC 5155 §7.1), so any record in the set can supply them.
fn hashed(nsec3: &DnsResourceRecord, name: &str) -> Option<Vec<u8>> {
    let iterations = nsec3.nsec3_iterations()?;
    let salt = nsec3.nsec3_salt()?.to_vec();
    let owner_wire = encode_name(&normalize_name(name)).ok()?;
    Some(nsec3_hash(&owner_wire, iterations, &salt))
}

/// True if `nsec3`'s hash range covers the NSEC3 hash of `name` — no
/// name hashing into that range exists.
fn nsec3_covers(nsec3: &DnsResourceRecord, name: &str) -> bool {
    let Some(candidate) = hashed(nsec3, name) else {
        return false;
    };
    let Some(next) = nsec3.nsec3_next_hashed_owner() else {
        return false;
    };
    let Some(owner_hash) = base32hex::decode_owner_label(&nsec3.name) else {
        return false;
    };
    hash_in_range(&owner_hash, next, &candidate)
}

/// True if `nsec3` is owned by the NSEC3 hash of `name` itself (the
/// direct match / closest-encloser hit, RFC 5155 §8.3 step 1).
fn nsec3_matches(nsec3: &DnsResourceRecord, name: &str) -> bool {
    let Some(candidate) = hashed(nsec3, name) else {
        return false;
    };
    let Some(owner_hash) = base32hex::decode_owner_label(&nsec3.name) else {
        return false;
    };
    owner_hash == candidate
}

/// `qname`, then its parent, grandparent, ... up to and including `zone`
/// (`""` once `zone` is the DNS root, since `normalize_name(".") == ""`).
fn ancestor_chain(qname: &str, zone: &str) -> Vec<String> {
    let z = normalize_name(zone);
    let mut out = vec![normalize_name(qname)];
    while out.last().unwrap() != &z {
        let cur = out.last().unwrap().clone();
        if cur.is_empty() {
            break; // reached the root without ever matching `zone` — malformed input
        }
        match cur.split_once('.') {
            Some((_, rest)) => out.push(rest.to_string()),
            None => out.push(String::new()), // single-label name's parent is the root
        }
    }
    out
}

/// RFC 5155 §8.3 closest-encloser proof: finds the longest ancestor of
/// `qname` that an NSEC3 in `records` is owned by (the closest encloser),
/// then checks another NSEC3 covers the very next label down from it
/// (the "next closer name") — proving nothing exists there, and so
/// `qname` doesn't either.
fn nsec3_denies_existence(records: &[&DnsResourceRecord], qname: &str, zone: &str) -> bool {
    let chain = ancestor_chain(qname, zone);
    for i in 1..chain.len() {
        if records.iter().any(|rr| nsec3_matches(rr, &chain[i])) {
            let next_closer = &chain[i - 1];
            return records.iter().any(|rr| nsec3_covers(rr, next_closer));
        }
    }
    false
}

fn nsec3_proves_denial(records: &[&DnsResourceRecord], qname: &str, qtype: DnsType, zone: &str) -> bool {
    if let Some(direct) = records.iter().find(|rr| nsec3_matches(rr, qname)) {
        return direct.nsec3_types().is_some_and(|types| !types.contains(&qtype.value()));
    }
    nsec3_denies_existence(records, qname, zone)
}

/// Verify `msg`'s authority-section NSEC/NSEC3 records are validly signed
/// by `key` (an already chain-of-trust-verified signing key for `zone`),
/// then check they prove `qname`/`qtype` doesn't exist (NXDOMAIN) or has
/// no data of that type (NODATA). `Insecure` if the zone simply isn't
/// signed at all (no NSEC/NSEC3 present); `Bogus` if present but either
/// the signature doesn't check out or the records don't actually prove
/// non-existence.
pub fn verify_denial(
    msg: &DnsMessage,
    zone: &str,
    key: &DnsResourceRecord,
    qname: &str,
    qtype: DnsType,
) -> DnssecStatus {
    let nsec3: Vec<&DnsResourceRecord> = msg.authorities.iter().filter(|rr| rr.rtype == Some(DnsType::Nsec3)).collect();
    let nsec: Vec<&DnsResourceRecord> = msg.authorities.iter().filter(|rr| rr.rtype == Some(DnsType::Nsec)).collect();
    let (records, rtype): (&[&DnsResourceRecord], DnsType) = if !nsec3.is_empty() {
        (&nsec3, DnsType::Nsec3)
    } else if !nsec.is_empty() {
        (&nsec, DnsType::Nsec)
    } else {
        return DnssecStatus::Insecure;
    };

    let rrsigs = find_rrsigs(&msg.authorities, rtype.value());
    for rr in records {
        let signed = rrsigs.iter().any(|sig| {
            normalize_name(&sig.name) == normalize_name(&rr.name)
                && is_rrsig_current(sig)
                && verify_rrsig(&[rr], sig, key)
        });
        if !signed {
            return DnssecStatus::Bogus;
        }
    }

    let proven = if rtype == DnsType::Nsec3 {
        nsec3_proves_denial(records, qname, qtype, zone)
    } else {
        nsec_proves_denial(records, qname, qtype)
    };
    if proven {
        DnssecStatus::Secure
    } else {
        DnssecStatus::Bogus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsClass, FLAG_QR};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn keypair() -> (Ed25519KeyPair, Vec<u8>) {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let public = pair.public_key().as_ref().to_vec();
        (pair, public)
    }

    /// RFC 4034 §3.1.8 canonical RRSIG signing, matching the pattern used
    /// elsewhere in this crate's DNSSEC tests.
    fn sign_rrset(rrset: &[&DnsResourceRecord], name: &str, rtype: DnsType, key_tag: u16, pair: &Ed25519KeyPair) -> DnsResourceRecord {
        // Canonical form (RFC 4034 §6.2) lowercases the owner name before
        // wire-encoding it for signing — the real verifier does the same
        // (`build_canonical_rrset`), so this must match or verification
        // fails for any owner name that isn't already all-lowercase (e.g.
        // NSEC3's base32hex hash labels, which `base32hex::encode` emits
        // as uppercase).
        let owner_wire = encode_name(&normalize_name(name)).unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&rtype.value().to_be_bytes());
        rdata.push(15); // Ed25519
        rdata.push(name.split('.').filter(|l| !l.is_empty()).count() as u8);
        rdata.extend_from_slice(&3600u32.to_be_bytes());
        rdata.extend_from_slice(&(now + 3600).to_be_bytes());
        rdata.extend_from_slice(&(now.saturating_sub(3600)).to_be_bytes());
        rdata.extend_from_slice(&key_tag.to_be_bytes());
        rdata.extend_from_slice(&encode_name(".").unwrap());
        let header_len = rdata.len();

        let mut signed_data = rdata.clone();
        let mut sorted: Vec<&DnsResourceRecord> = rrset.to_vec();
        sorted.sort_by(|a, b| a.rdata.cmp(&b.rdata));
        for rr in &sorted {
            signed_data.extend_from_slice(&owner_wire);
            signed_data.extend_from_slice(&rtype.value().to_be_bytes());
            signed_data.extend_from_slice(&DnsClass::In.value().to_be_bytes());
            signed_data.extend_from_slice(&3600u32.to_be_bytes());
            signed_data.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
            signed_data.extend_from_slice(&rr.rdata);
        }
        let sig = pair.sign(&signed_data);
        let mut full_rdata = rdata;
        full_rdata.truncate(header_len);
        full_rdata.extend_from_slice(sig.as_ref());
        DnsResourceRecord::new(name, DnsType::Rrsig, DnsClass::In, 3600, full_rdata)
    }

    fn msg_with_authorities(authorities: Vec<DnsResourceRecord>) -> DnsMessage {
        DnsMessage::new(1, FLAG_QR, vec![], vec![], authorities, vec![])
    }

    #[test]
    fn nsec_proves_nxdomain_for_a_covered_name() {
        let (pair, pub_key) = keypair();
        let key = DnsResourceRecord::dnskey("example.com", 3600, 257, 15, &pub_key);
        let key_tag = key.dnskey_key_tag().unwrap();

        let nsec = DnsResourceRecord::nsec("a.example.com", 3600, "c.example.com", vec![DnsType::A.value()]).unwrap();
        let rrsig = sign_rrset(&[&nsec], "a.example.com", DnsType::Nsec, key_tag, &pair);
        let msg = msg_with_authorities(vec![nsec, rrsig]);

        let status = verify_denial(&msg, "example.com", &key, "b.example.com", DnsType::A);
        assert_eq!(status, DnssecStatus::Secure);
    }

    #[test]
    fn nsec_proves_nodata_when_owner_matches_but_type_is_absent() {
        let (pair, pub_key) = keypair();
        let key = DnsResourceRecord::dnskey("example.com", 3600, 257, 15, &pub_key);
        let key_tag = key.dnskey_key_tag().unwrap();

        let nsec = DnsResourceRecord::nsec("b.example.com", 3600, "c.example.com", vec![DnsType::Mx.value()]).unwrap();
        let rrsig = sign_rrset(&[&nsec], "b.example.com", DnsType::Nsec, key_tag, &pair);
        let msg = msg_with_authorities(vec![nsec, rrsig]);

        let status = verify_denial(&msg, "example.com", &key, "b.example.com", DnsType::A);
        assert_eq!(status, DnssecStatus::Secure);
    }

    #[test]
    fn nsec_with_a_tampered_range_is_bogus() {
        let (pair, pub_key) = keypair();
        let key = DnsResourceRecord::dnskey("example.com", 3600, 257, 15, &pub_key);
        let key_tag = key.dnskey_key_tag().unwrap();

        let nsec = DnsResourceRecord::nsec("a.example.com", 3600, "c.example.com", vec![DnsType::A.value()]).unwrap();
        let rrsig = sign_rrset(&[&nsec], "a.example.com", DnsType::Nsec, key_tag, &pair);
        // Tamper the range after signing: attacker widens next-domain to
        // cover a name the zone owner never actually vouched for.
        let mut tampered = nsec;
        tampered.rdata = encode_name("zzz.example.com").unwrap();
        let msg = msg_with_authorities(vec![tampered, rrsig]);

        let status = verify_denial(&msg, "example.com", &key, "b.example.com", DnsType::A);
        assert_eq!(status, DnssecStatus::Bogus);
    }

    #[test]
    fn nsec3_closest_encloser_proves_nxdomain() {
        let (pair, pub_key) = keypair();
        let key = DnsResourceRecord::dnskey("example.com", 3600, 257, 15, &pub_key);
        let key_tag = key.dnskey_key_tag().unwrap();
        let salt = [0xAAu8, 0xBB];
        let iterations = 3u16;

        // Closest encloser: "example.com" itself exists.
        let encloser_hash = hashed_for_test("example.com", iterations, &salt);
        let encloser_owner = format!("{}.example.com", base32hex::encode(&encloser_hash));
        // Next closer name "nope.example.com" must be covered by some
        // NSEC3's hash range — pick an owner/next range that brackets it.
        let next_closer_hash = hashed_for_test("nope.example.com", iterations, &salt);
        let mut owner_hash = next_closer_hash.clone();
        owner_hash[0] = owner_hash[0].wrapping_sub(1);
        let mut next_hash = next_closer_hash.clone();
        next_hash[0] = next_hash[0].wrapping_add(1);
        let covering_owner = format!("{}.example.com", base32hex::encode(&owner_hash));

        let encloser_nsec3 = DnsResourceRecord::nsec3(&encloser_owner, 3600, 1, 0, iterations, &salt, &[9u8; 20], vec![DnsType::A.value()]);
        let covering_nsec3 = DnsResourceRecord::nsec3(&covering_owner, 3600, 1, 0, iterations, &salt, &next_hash, vec![DnsType::A.value()]);
        let sig1 = sign_rrset(&[&encloser_nsec3], &encloser_owner, DnsType::Nsec3, key_tag, &pair);
        let sig2 = sign_rrset(&[&covering_nsec3], &covering_owner, DnsType::Nsec3, key_tag, &pair);
        let msg = msg_with_authorities(vec![encloser_nsec3, sig1, covering_nsec3, sig2]);

        let status = verify_denial(&msg, "example.com", &key, "nope.example.com", DnsType::A);
        assert_eq!(status, DnssecStatus::Secure);
    }

    #[test]
    fn nsec3_direct_match_proves_nodata() {
        let (pair, pub_key) = keypair();
        let key = DnsResourceRecord::dnskey("example.com", 3600, 257, 15, &pub_key);
        let key_tag = key.dnskey_key_tag().unwrap();
        let salt = [0x11u8];
        let iterations = 1u16;

        let hash = hashed_for_test("host.example.com", iterations, &salt);
        let owner = format!("{}.example.com", base32hex::encode(&hash));
        let nsec3 = DnsResourceRecord::nsec3(&owner, 3600, 1, 0, iterations, &salt, &[7u8; 20], vec![DnsType::A.value()]);
        let sig = sign_rrset(&[&nsec3], &owner, DnsType::Nsec3, key_tag, &pair);
        let msg = msg_with_authorities(vec![nsec3, sig]);

        // The name exists (its own NSEC3 is present) but has no AAAA.
        let status = verify_denial(&msg, "example.com", &key, "host.example.com", DnsType::Aaaa);
        assert_eq!(status, DnssecStatus::Secure);
        // It does have an A record, so that must NOT be provable as absent.
        let status_a = verify_denial(&msg, "example.com", &key, "host.example.com", DnsType::A);
        assert_eq!(status_a, DnssecStatus::Bogus);
    }

    /// The closest encloser can be the DNS root itself (a single-label
    /// qname whose only ancestor is "."), which needs
    /// `normalize_name(".") == ""` to be reachable by walking up from a
    /// name with no further dots to split on.
    #[test]
    fn nsec3_closest_encloser_can_be_the_root_zone() {
        let (pair, pub_key) = keypair();
        let key = DnsResourceRecord::dnskey(".", 3600, 257, 15, &pub_key);
        let key_tag = key.dnskey_key_tag().unwrap();
        let salt = [0x42u8];
        let iterations = 0u16;

        let encloser_hash = hashed_for_test(".", iterations, &salt);
        let encloser_owner = base32hex::encode(&encloser_hash);
        let next_closer_hash = hashed_for_test("missing", iterations, &salt);
        let mut owner_hash = next_closer_hash.clone();
        owner_hash[0] = owner_hash[0].wrapping_sub(1);
        let mut next_hash = next_closer_hash.clone();
        next_hash[0] = next_hash[0].wrapping_add(1);
        let covering_owner = base32hex::encode(&owner_hash);

        let encloser_nsec3 = DnsResourceRecord::nsec3(&encloser_owner, 3600, 1, 0, iterations, &salt, &[9u8; 20], vec![DnsType::Ns.value()]);
        let covering_nsec3 = DnsResourceRecord::nsec3(&covering_owner, 3600, 1, 0, iterations, &salt, &next_hash, vec![DnsType::Ns.value()]);
        let sig1 = sign_rrset(&[&encloser_nsec3], &encloser_owner, DnsType::Nsec3, key_tag, &pair);
        let sig2 = sign_rrset(&[&covering_nsec3], &covering_owner, DnsType::Nsec3, key_tag, &pair);
        let msg = msg_with_authorities(vec![encloser_nsec3, sig1, covering_nsec3, sig2]);

        let status = verify_denial(&msg, ".", &key, "missing", DnsType::A);
        assert_eq!(status, DnssecStatus::Secure);
    }

    fn hashed_for_test(name: &str, iterations: u16, salt: &[u8]) -> Vec<u8> {
        let owner_wire = encode_name(&normalize_name(name)).unwrap();
        nsec3_hash(&owner_wire, iterations, salt)
    }
}
