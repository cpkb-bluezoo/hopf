// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 8198 against a live, scriptable, *signed* upstream: the forwarder learns
//! an NSEC proof only after the resolver has validated it up its chain of
//! trust, and then answers other names in the proven range itself. No external
//! network.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hopf_core::crypto::{ed25519_sign, Ed25519PrivateKey};
use hopf_core::Runtime;
use hopf_dns::dnssec::{compute_ds_digest, DnssecTrustAnchor, DnssecValidator};
use hopf_dns::server::{AggressiveNsecDisabled, DnsService, ForwarderHandler};
use hopf_dns::wire::{
    encode_name, DnsClass, DnsMessage, DnsQuestion, DnsResourceRecord, DnsType, FLAG_QR, FLAG_RA, RCODE_NXDOMAIN,
};
use hopf_dns::{DnsCache, DnsResolver};

const ZONE: &str = "example.com";
const KEY_TAG_ALG: u8 = 15; // Ed25519

/// RFC 4034 section 3.1.8 signing of one RRset.
fn sign(rrset: &[&DnsResourceRecord], key_tag: u16, pair: &Ed25519PrivateKey) -> DnsResourceRecord {
    let (name, rtype) = (rrset[0].name.clone(), rrset[0].rtype.unwrap());
    let owner_wire = encode_name(&name.to_ascii_lowercase()).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&rtype.value().to_be_bytes());
    rdata.push(KEY_TAG_ALG);
    rdata.push(name.split('.').filter(|l| !l.is_empty()).count() as u8);
    rdata.extend_from_slice(&3600u32.to_be_bytes());
    rdata.extend_from_slice(&(now + 3600).to_be_bytes());
    rdata.extend_from_slice(&now.saturating_sub(3600).to_be_bytes());
    rdata.extend_from_slice(&key_tag.to_be_bytes());
    rdata.extend_from_slice(&encode_name(ZONE).unwrap());
    let mut signed = rdata.clone();
    let mut sorted: Vec<&DnsResourceRecord> = rrset.to_vec();
    sorted.sort_by(|a, b| a.rdata.cmp(&b.rdata));
    for rr in sorted {
        signed.extend_from_slice(&owner_wire);
        signed.extend_from_slice(&rtype.value().to_be_bytes());
        signed.extend_from_slice(&DnsClass::In.value().to_be_bytes());
        signed.extend_from_slice(&3600u32.to_be_bytes());
        signed.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
        signed.extend_from_slice(&rr.rdata);
    }
    rdata.extend_from_slice(ed25519_sign(pair, &signed).as_bytes());
    DnsResourceRecord::new(name, DnsType::Rrsig, DnsClass::In, 3600, rdata)
}

/// A signed zone `example.com` whose names are `a` and `c` (NSEC ring
/// apex -> a -> c -> apex), plus a scriptable upstream serving it.
struct Zone {
    addr: SocketAddr,
    /// Non-DNSKEY/DS queries the upstream has answered.
    queries: Arc<AtomicUsize>,
    /// Corrupt the NSEC signatures in what the upstream sends.
    tamper: Arc<Mutex<bool>>,
    anchor: DnssecTrustAnchor,
}

fn spawn_zone() -> Zone {
    let doc = Ed25519PrivateKey::generate_pkcs8().unwrap();
    let pair = Ed25519PrivateKey::from_pkcs8(&doc).unwrap();
    let dnskey = DnsResourceRecord::dnskey(ZONE, 3600, 257, KEY_TAG_ALG, pair.public_key_bytes());
    let key_tag = dnskey.dnskey_key_tag().unwrap();
    let dnskey_sig = sign(&[&dnskey], key_tag, &pair);

    let mut anchor = DnssecTrustAnchor::empty();
    let digest = compute_ds_digest(&encode_name(ZONE).unwrap(), &dnskey.rdata, 2).unwrap();
    anchor.add_anchor(ZONE, key_tag, KEY_TAG_ALG, 2, &digest);

    let soa = DnsResourceRecord::soa(ZONE, 3600, "ns.example.com", "h.example.com", 1, 1, 1, 1, 3600).unwrap();
    let soa_sig = sign(&[&soa], key_tag, &pair);
    let ring = [
        ("example.com", "a.example.com", vec![2u16, 6, 46, 47, 48]),
        ("a.example.com", "c.example.com", vec![1, 46, 47]),
        ("c.example.com", "example.com", vec![1, 46, 47]),
    ];
    let nsecs: Vec<(DnsResourceRecord, DnsResourceRecord)> = ring
        .into_iter()
        .map(|(o, n, t)| {
            let rr = DnsResourceRecord::nsec(o, 3600, n, t).unwrap();
            let sig = sign(&[&rr], key_tag, &pair);
            (rr, sig)
        })
        .collect();

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let tamper = Arc::new(Mutex::new(false));
    let (n, t) = (Arc::clone(&queries), Arc::clone(&tamper));
    thread::spawn(move || loop {
        let mut buf = [0u8; 1500];
        let Ok((len, peer)) = sock.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..len]) else {
            continue;
        };
        let Some(question) = q.questions.first() else {
            continue;
        };
        let name = question.name.trim_end_matches('.').to_ascii_lowercase();
        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        match question.qtype {
            Some(DnsType::Svcb) => continue, // the resolver's own DDR probe
            Some(DnsType::Dnskey) if name == ZONE => {
                resp.answers = vec![dnskey.clone(), dnskey_sig.clone()];
            }
            Some(DnsType::Dnskey) | Some(DnsType::Ds) => {} // NODATA: not a separate zone
            _ => {
                n.fetch_add(1, Ordering::SeqCst);
                // Every name except a and c does not exist.
                if name != "a.example.com" && name != "c.example.com" {
                    resp = q.response_template(RCODE_NXDOMAIN);
                    resp.flags |= FLAG_QR | FLAG_RA;
                    resp.authorities.push(soa.clone());
                    resp.authorities.push(soa_sig.clone());
                    for (rr, sig) in &nsecs {
                        resp.authorities.push(rr.clone());
                        let mut sig = sig.clone();
                        if *t.lock().unwrap() {
                            let last = sig.rdata.len() - 1;
                            sig.rdata[last] ^= 0xff;
                        }
                        resp.authorities.push(sig);
                    }
                }
            }
        }
        let _ = sock.send_to(&resp.serialize().unwrap(), peer);
    });
    Zone { addr, queries, tamper, anchor }
}

fn validating_resolver(rt: &Runtime, zone: &Zone) -> DnsResolver {
    let r = DnsResolver::new(rt.pick_worker().clone());
    r.set_timeout(Duration::from_millis(2500));
    r.add_server(zone.addr);
    r.set_dnssec_validator(DnssecValidator::new(zone.anchor.clone()));
    r.open().unwrap();
    r
}

fn ask(service: &DnsService, name: &str, dnssec_ok: bool) -> DnsMessage {
    let mut q = DnsMessage::query(9, DnsQuestion::in_class(name, DnsType::A), true);
    if dnssec_ok {
        q.additionals.push(DnsResourceRecord::opt(1232, true, &[]));
    }
    service.process_query_sync(&q, "127.0.0.1:5353".parse().unwrap())
}

fn wait_for(cache: &DnsCache, want_learned: bool) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if cache.denials().is_empty() != want_learned {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn a_validated_proof_answers_other_names_in_its_range_without_the_upstream() {
    let zone = spawn_zone();
    let rt = Runtime::start(Default::default()).unwrap();
    let cache = Arc::new(DnsCache::default());
    let service = DnsService::with_handler(
        ForwarderHandler::new(Arc::clone(&cache)).with_upstream(validating_resolver(&rt, &zone)),
    );

    // The first miss goes upstream and is answered as ever...
    assert_eq!(ask(&service, "b.example.com", false).rcode(), RCODE_NXDOMAIN);
    assert_eq!(zone.queries.load(Ordering::SeqCst), 1);
    // ...while the proof is validated (DNSKEY chain walk) and learned.
    wait_for(&cache, true);
    assert!(!cache.denials().is_empty(), "a Secure denial is remembered");

    // A different name in a..c (and one in c..apex): no upstream query.
    let before = zone.queries.load(Ordering::SeqCst);
    for name in ["bb.example.com", "d.example.com", "zz.example.com"] {
        let resp = ask(&service, name, false);
        assert_eq!(resp.rcode(), RCODE_NXDOMAIN, "{name}");
        assert_eq!(resp.authorities.len(), 1, "a plain client gets just the SOA");
    }
    assert_eq!(zone.queries.load(Ordering::SeqCst), before, "answered from the proof");
    assert_eq!(service.metrics().aggressive_nsec_hits, 3);

    // A DNSSEC-aware client gets the proof and its signatures, and AD.
    let signed = ask(&service, "bbb.example.com", true);
    assert_eq!(signed.rcode(), RCODE_NXDOMAIN);
    assert!(signed.is_authenticated_data());
    let has = |t: DnsType| signed.authorities.iter().any(|r| r.rtype == Some(t));
    assert!(has(DnsType::Soa) && has(DnsType::Nsec) && has(DnsType::Rrsig));

    // Names that exist are never synthesised away.
    assert_eq!(ask(&service, "a.example.com", false).rcode(), 0);
    assert_eq!(zone.queries.load(Ordering::SeqCst), before + 1);
    rt.shutdown();
}

#[test]
fn a_proof_that_fails_validation_is_never_cached() {
    let zone = spawn_zone();
    *zone.tamper.lock().unwrap() = true;
    let rt = Runtime::start(Default::default()).unwrap();
    let cache = Arc::new(DnsCache::default());
    let service = DnsService::with_handler(
        ForwarderHandler::new(Arc::clone(&cache)).with_upstream(validating_resolver(&rt, &zone)),
    );
    // The resolver may refuse the bogus answer outright; either way nothing is learned.
    let _ = ask(&service, "b.example.com", false);
    thread::sleep(Duration::from_millis(800));
    assert!(cache.denials().is_empty(), "a forged proof must not be able to poison the range");
    let before = zone.queries.load(Ordering::SeqCst);
    let _ = ask(&service, "bb.example.com", false);
    assert_eq!(zone.queries.load(Ordering::SeqCst), before + 1, "so the next name still goes upstream");
    rt.shutdown();
}

#[test]
fn the_policy_can_switch_it_off_and_it_needs_validation_to_be_on() {
    let zone = spawn_zone();
    let rt = Runtime::start(Default::default()).unwrap();

    // Disabled by policy: nothing learned, every negative lookup reaches the upstream.
    let cache = Arc::new(DnsCache::default());
    let service = DnsService::with_handler(
        ForwarderHandler::new(Arc::clone(&cache))
            .with_upstream(validating_resolver(&rt, &zone))
            .with_aggressive_nsec_policy(AggressiveNsecDisabled),
    );
    let _ = ask(&service, "b.example.com", false);
    thread::sleep(Duration::from_millis(600));
    assert!(cache.denials().is_empty());
    let before = zone.queries.load(Ordering::SeqCst);
    let _ = ask(&service, "bb.example.com", false);
    assert_eq!(zone.queries.load(Ordering::SeqCst), before + 1);
    assert_eq!(service.metrics().aggressive_nsec_hits, 0);

    // A resolver that does not validate never learns a proof: there is
    // nothing to trust.
    let plain = DnsResolver::new(rt.pick_worker().clone());
    plain.add_server(zone.addr);
    plain.open().unwrap();
    let cache = Arc::new(DnsCache::default());
    let service = DnsService::with_handler(ForwarderHandler::new(Arc::clone(&cache)).with_upstream(plain));
    let _ = ask(&service, "b.example.com", false);
    thread::sleep(Duration::from_millis(600));
    assert!(cache.denials().is_empty(), "no validation, no proofs");
    rt.shutdown();
}
