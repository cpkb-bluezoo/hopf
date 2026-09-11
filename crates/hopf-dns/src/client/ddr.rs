// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9462 Discovery of Designated Resolvers (DDR).
//!
//! For an auto-mode server (see `capability_cache`'s own module docs) with
//! no capability-cache entry yet — neither seeded nor previously confirmed
//! — this issues one query over the server's existing plain UDP/TCP
//! channel for `_dns.resolver.arpa` IN SVCB (RFC 9460) to learn whether it
//! offers any encrypted transport.
//!
//! Three outcomes:
//! - No response at all (the base server is unreachable, or this one
//!   query happens to time out): not this module's concern — left alone,
//!   so a later query to the same server can simply try again. An
//!   unreachable *server* is the existing inter-server fallback's problem,
//!   not a capability question.
//! - A definitive negative (NXDOMAIN, NODATA, or a `FORMERR`/`NOTIMP`
//!   response showing the server doesn't understand the SVCB qtype at
//!   all): cached as confirmed-absent.
//! - A real SVCB answer: each candidate transport it advertises is
//!   *dialled and its certificate validated* against the public WebPKI
//!   (see `hopf_core::public_trust_connector`/
//!   `hopf_quic::client_config_public_trust`) before ever being promoted —
//!   the discovery query itself travelled over plain UDP, so an on-path
//!   attacker could otherwise forge a response redirecting to a malicious
//!   endpoint. Only a candidate that actually completes a validated
//!   handshake is recorded as confirmed-working.
//!
//! **DoH candidates are parsed but never validated or promoted**: unlike
//! DoT (a synchronous dial, no shared state needed) and DoQ (dials its own
//! dedicated connection via [`hopf_quic::connect_quic`]), this crate's
//! existing `DohClientTransport` needs a `hopf_core::Runtime` to dial
//! through, and nothing guarantees this resolver has one (only a caller
//! of `add_server_doh` supplies one, for its own server). A deployer who
//! wants DoH confirmed for a server can still pin it explicitly via
//! `add_server_doh`; auto-discovery just doesn't get there for DoH yet.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::wire::{DnsResourceRecord, RCODE_FORMERR, RCODE_NOERROR, RCODE_NOTIMP, RCODE_NXDOMAIN};

use super::capability_cache::{default_port, EncryptedTransport, EndpointDetails};
use super::{alloc_id, send_udp_query, DnsMessage, DnsQuestion, DnsType, PendingQuery, QueryCallback, ResolverInner};

#[cfg(feature = "dot")]
use super::TcpDnsConnectionPool;
#[cfg(feature = "doq")]
use super::{doq::DoqConnectionPool, DnsClientTransportHandler};

/// RFC 9462 §3: the well-known name a resolver's own DDR endpoints are
/// published under.
const DDR_QNAME: &str = "_dns.resolver.arpa";

/// Wall-clock budget for one candidate's validation dial — generous enough
/// for a real handshake over a slow path, short enough that a genuinely
/// dead candidate doesn't tie up a thread indefinitely.
///
/// Only [`validate_doq`] reads this today (DoT's validation is
/// synchronous and just uses its connection pool's own timeout).
#[cfg_attr(not(feature = "doq"), allow(dead_code))]
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(5);

/// If `server_idx` is an auto-mode server with no capability-cache entry
/// yet and no discovery already in flight for it, kick off one DDR query.
/// Safe to call on every real query dispatch — everything else here is a
/// cheap check that's a no-op once discovery is either done or running.
pub(super) fn maybe_trigger_discovery(inner: &Arc<std::sync::Mutex<ResolverInner>>, g: &mut ResolverInner, server_idx: usize) {
    let Some(server) = g.servers.get(server_idx) else {
        return;
    };
    if !server.auto || server.transport.encrypted_transport().is_some() {
        return;
    }
    let addr = server.addr;
    if !g.capability_cache.known_transports(addr).is_empty() || g.capability_cache.is_confirmed_absent(addr) {
        return;
    }
    if !g.discovery_in_flight.insert(addr) {
        return;
    }

    let question = DnsQuestion::in_class(DDR_QNAME, DnsType::Svcb);
    let id = alloc_id(g);
    let timeout = g.timeout;
    let inner_for_timeout = Arc::clone(inner);
    let cancel = g.reactor.schedule_timer(timeout, Box::new(move || on_timeout(&inner_for_timeout, id, addr)));
    let inner_for_callback = Arc::clone(inner);
    let callback: QueryCallback = Box::new(move |result| on_result(&inner_for_callback, addr, result));

    match send_udp_query(g, id, &question, addr, &[]) {
        Ok(()) => {
            g.pending.insert(
                id,
                PendingQuery {
                    callback,
                    question,
                    server_idx,
                    cname_depth: 0,
                    id,
                    server: addr,
                    cd: false,
                    cancel: Some(cancel),
                    extra_edns_options: Vec::new(),
                    active_transport: None,
                    actual_transport: None,
                },
            );
        }
        Err(_) => {
            // Dispatch itself failed (e.g. the resolver isn't open yet) —
            // nothing is outstanding, so don't leave the timer armed or
            // the in-flight marker set.
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
            g.discovery_in_flight.remove(&addr);
        }
    }
}

/// The discovery query's own timeout — deliberately *not*
/// [`super::retry_or_fail`]: that advances to a different configured
/// server, which makes no sense for a probe scoped to one specific
/// server. A timeout here just means "no answer this time"; clearing the
/// in-flight marker lets a later real query try discovery again.
fn on_timeout(inner: &Arc<std::sync::Mutex<ResolverInner>>, id: u16, addr: SocketAddr) {
    let mut g = inner.lock().unwrap();
    // Only clear in-flight if *this* attempt's pending entry is still
    // here — if the response already arrived (and `on_result` already
    // cleared it, possibly starting a newer attempt), a late-firing timer
    // for the old attempt must not stomp on that newer one's state.
    if g.pending.remove(&id).is_some() {
        g.discovery_in_flight.remove(&addr);
    }
}

/// Called once the discovery query's `PendingQuery` completes, exactly
/// like a normal query's callback — including having already run through
/// [`super::complete_response`] (cache insertion, DNSSEC validation if
/// enabled) for a real response, or truncation-over-TCP retry
/// transparently along the way. None of that machinery needs to know this
/// is a discovery query rather than an ordinary one.
fn on_result(inner: &Arc<std::sync::Mutex<ResolverInner>>, addr: SocketAddr, result: std::io::Result<DnsMessage>) {
    {
        let mut g = inner.lock().unwrap();
        g.discovery_in_flight.remove(&addr);
    }
    let Ok(msg) = result else {
        // No response / a transport-level error — not this module's
        // concern (see its own doc comment): leave the cache alone.
        return;
    };
    match classify(&msg) {
        Outcome::ConfirmedAbsent => {
            let g = inner.lock().unwrap();
            g.capability_cache.record_confirmed_absent(addr);
        }
        Outcome::Inconclusive => {}
        Outcome::Candidates(records) => {
            for candidate in extract_candidates(addr, &records) {
                spawn_validation(inner, addr, candidate);
            }
        }
    }
}

enum Outcome {
    /// A definitive "nothing beyond plain DNS" answer.
    ConfirmedAbsent,
    /// SERVFAIL/REFUSED/etc — could be a transient blip unrelated to DDR
    /// support, so unlike NXDOMAIN/NODATA/NOTIMP/FORMERR this doesn't
    /// justify caching a negative result.
    Inconclusive,
    /// At least one real, non-alias-form SVCB record.
    Candidates(Vec<DnsResourceRecord>),
}

fn classify(msg: &DnsMessage) -> Outcome {
    match msg.rcode() {
        RCODE_NOERROR => {
            let svcb: Vec<DnsResourceRecord> = msg
                .answers
                .iter()
                .filter(|rr| rr.rtype == Some(DnsType::Svcb) && !rr.is_svcb_alias_form())
                .cloned()
                .collect();
            if svcb.is_empty() {
                Outcome::ConfirmedAbsent // NOERROR with no SVCB answer: NODATA (RFC 2308 §2.2)
            } else {
                Outcome::Candidates(svcb)
            }
        }
        RCODE_NXDOMAIN | RCODE_NOTIMP | RCODE_FORMERR => Outcome::ConfirmedAbsent,
        _ => Outcome::Inconclusive,
    }
}

/// One encrypted-transport candidate extracted from a discovery response,
/// not yet validated.
struct Candidate {
    transport: EncryptedTransport,
    /// Where to dial and what to validate its certificate against — the
    /// record's own `ipv4hint`/`ipv6hint` (RFC 9460 §7.3) target when
    /// present, otherwise the *original* server's address (RFC 9462 §4.3
    /// allows falling back to it when no hint is given, on the basis that
    /// a designated resolver is commonly reachable at the same address as
    /// the plain one that referred to it) with the record's own target
    /// name as SNI. Already the exact shape `record_success` needs, so a
    /// validated candidate is recorded with no further translation.
    ///
    /// Read only by [`validate_dot`]/[`validate_doq`] — with neither
    /// feature enabled there's nothing to dial a candidate with at all.
    #[cfg_attr(not(any(feature = "dot", feature = "doq")), allow(dead_code))]
    details: EndpointDetails,
}

fn alpn_to_transport(alpn: &str) -> Option<EncryptedTransport> {
    match alpn {
        "dot" => Some(EncryptedTransport::Dot),
        "doq" => Some(EncryptedTransport::Doq),
        "h2" | "h3" => Some(EncryptedTransport::Doh),
        _ => None,
    }
}

fn extract_candidates(server: SocketAddr, records: &[DnsResourceRecord]) -> Vec<Candidate> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for rr in records {
        let Some(target) = rr.svcb_target_name() else {
            continue;
        };
        // An empty/root target name means "this record's owner name" —
        // `_dns.resolver.arpa` itself, which is useless as a TLS/QUIC SNI
        // to validate a real endpoint's certificate against.
        if target.is_empty() || target == "." {
            continue;
        }
        let port_hint = rr.svcb_port();
        let ip = rr
            .svcb_ipv4hint()
            .into_iter()
            .next()
            .map(IpAddr::V4)
            .or_else(|| rr.svcb_ipv6hint().into_iter().next().map(IpAddr::V6))
            .unwrap_or_else(|| server.ip());
        for alpn in rr.svcb_alpn_protocols() {
            let Some(transport) = alpn_to_transport(&alpn) else {
                continue;
            };
            // One validation attempt per transport is enough even if
            // multiple records/ALPN entries advertise it.
            if !seen.insert(transport) {
                continue;
            }
            out.push(Candidate {
                transport,
                details: EndpointDetails {
                    target: SocketAddr::new(ip, port_hint.unwrap_or_else(|| default_port(transport))),
                    sni: target.clone(),
                },
            });
        }
    }
    out
}

#[cfg_attr(not(any(feature = "dot", feature = "doq")), allow(unused_variables))]
fn spawn_validation(inner: &Arc<std::sync::Mutex<ResolverInner>>, server: SocketAddr, candidate: Candidate) {
    match candidate.transport {
        #[cfg(feature = "dot")]
        EncryptedTransport::Dot => {
            let inner = Arc::clone(inner);
            std::thread::Builder::new()
                .name("hopf-dns-ddr-dot".into())
                .spawn(move || {
                    if validate_dot(&candidate) {
                        let g = inner.lock().unwrap();
                        g.capability_cache.record_success(server, EncryptedTransport::Dot, candidate.details.clone());
                    }
                })
                .ok();
        }
        #[cfg(feature = "doq")]
        EncryptedTransport::Doq => {
            let inner = Arc::clone(inner);
            std::thread::Builder::new()
                .name("hopf-dns-ddr-doq".into())
                .spawn(move || {
                    if validate_doq(&candidate) {
                        let g = inner.lock().unwrap();
                        g.capability_cache.record_success(server, EncryptedTransport::Doq, candidate.details.clone());
                    }
                })
                .ok();
        }
        // DoH: see this module's own doc comment for why it's parsed but
        // never dialled here.
        #[allow(unreachable_patterns)]
        _ => {}
    }
}

/// Validate a DoT candidate by actually querying it — a real DNS response
/// over a TLS session that validated against the public WebPKI is exactly
/// the "successful, properly-authenticated connection" issue #378 asks
/// for, and reuses this crate's own [`TcpDnsConnectionPool`] rather than a
/// bespoke handshake-only check. Re-asks the same DDR question: already a
/// small, valid, harmless query, so there's no need to build another one.
#[cfg(feature = "dot")]
fn validate_dot(candidate: &Candidate) -> bool {
    let connector = hopf_core::public_trust_connector(&[b"dot"]);
    let mut pool = TcpDnsConnectionPool::new();
    let probe = DnsQuestion::in_class(DDR_QNAME, DnsType::Svcb);
    pool.query_dot(candidate.details.target, &candidate.details.sni, &connector, &probe, 1)
        .is_ok()
}

/// As [`validate_dot`], but over DoQ via a throwaway
/// [`DoqConnectionPool`] and [`hopf_quic::client_config_public_trust`].
/// [`hopf_quic::connect_quic`] dials on its own dedicated thread, so
/// (unlike DoH) this needs no shared `Runtime` — only a channel to wait
/// for its callback-based result.
#[cfg(feature = "doq")]
fn validate_doq(candidate: &Candidate) -> bool {
    let Ok(client_config) = hopf_quic::client_config_public_trust(&[super::doq::ALPN_DOQ]) else {
        return false;
    };
    let probe = DnsQuestion::in_class(DDR_QNAME, DnsType::Svcb);
    let msg = DnsMessage::query(1, probe, true);
    let Ok(bytes) = msg.serialize() else {
        return false;
    };

    struct ValidationHandler {
        tx: std::sync::mpsc::Sender<bool>,
    }
    impl DnsClientTransportHandler for ValidationHandler {
        fn on_response(&mut self, _server: SocketAddr, _data: &[u8]) {
            let _ = self.tx.send(true);
        }
        fn on_error(&mut self, _server: SocketAddr, _err: std::io::Error) {
            let _ = self.tx.send(false);
        }
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let mut pool = DoqConnectionPool::new();
    if pool
        .send_query(candidate.details.target, &client_config, &candidate.details.sni, &bytes, Box::new(ValidationHandler { tx }))
        .is_err()
    {
        return false;
    }
    rx.recv_timeout(VALIDATION_TIMEOUT).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svcb(target: &str, alpn: &[&str], port: Option<u16>) -> DnsResourceRecord {
        let mut params = vec![(1u16, crate::wire::encode_svcb_alpn(alpn))];
        if let Some(p) = port {
            params.push((3u16, p.to_be_bytes().to_vec()));
        }
        DnsResourceRecord::svcb(DDR_QNAME, 3600, 1, target, &params).unwrap()
    }

    fn message(rcode: u16, answers: Vec<DnsResourceRecord>) -> DnsMessage {
        let mut msg = DnsMessage::new(
            1,
            crate::wire::FLAG_QR,
            vec![DnsQuestion::in_class(DDR_QNAME, DnsType::Svcb)],
            answers,
            vec![],
            vec![],
        );
        msg.flags = (msg.flags & !0x0F) | rcode;
        msg
    }

    #[test]
    fn alpn_to_transport_maps_registered_ids() {
        assert_eq!(alpn_to_transport("dot"), Some(EncryptedTransport::Dot));
        assert_eq!(alpn_to_transport("doq"), Some(EncryptedTransport::Doq));
        assert_eq!(alpn_to_transport("h2"), Some(EncryptedTransport::Doh));
        assert_eq!(alpn_to_transport("h3"), Some(EncryptedTransport::Doh));
        assert_eq!(alpn_to_transport("imap"), None);
    }

    #[test]
    fn classify_noerror_with_svcb_answer_is_a_candidate() {
        let rr = svcb("dot.example", &["dot"], Some(853));
        match classify(&message(RCODE_NOERROR, vec![rr])) {
            Outcome::Candidates(records) => assert_eq!(records.len(), 1),
            _ => panic!("expected Candidates"),
        }
    }

    #[test]
    fn classify_noerror_with_no_svcb_answer_is_nodata_confirmed_absent() {
        assert!(matches!(classify(&message(RCODE_NOERROR, vec![])), Outcome::ConfirmedAbsent));
    }

    #[test]
    fn classify_nxdomain_is_confirmed_absent() {
        assert!(matches!(classify(&message(RCODE_NXDOMAIN, vec![])), Outcome::ConfirmedAbsent));
    }

    #[test]
    fn classify_notimp_and_formerr_are_confirmed_absent() {
        assert!(matches!(classify(&message(RCODE_NOTIMP, vec![])), Outcome::ConfirmedAbsent));
        assert!(matches!(classify(&message(RCODE_FORMERR, vec![])), Outcome::ConfirmedAbsent));
    }

    #[test]
    fn classify_servfail_is_inconclusive_not_confirmed_absent() {
        // A transient upstream problem must never be cached as a
        // definitive "no DDR support" answer.
        assert!(matches!(classify(&message(crate::wire::RCODE_SERVFAIL, vec![])), Outcome::Inconclusive));
    }

    #[test]
    fn classify_ignores_alias_form_records() {
        // Priority 0 is SVCB's alias form (RFC 9460 §2.4.2) — a pure CNAME-
        // style redirect, not itself an encrypted-transport advertisement.
        let alias = DnsResourceRecord::svcb(DDR_QNAME, 3600, 0, "somewhere.example", &[]).unwrap();
        assert!(matches!(classify(&message(RCODE_NOERROR, vec![alias])), Outcome::ConfirmedAbsent));
    }

    #[test]
    fn extract_candidates_uses_ipv4hint_when_present() {
        let mut params = vec![(1u16, crate::wire::encode_svcb_alpn(&["dot"]))];
        params.push((4u16, vec![203, 0, 113, 9]));
        let rr = DnsResourceRecord::svcb(DDR_QNAME, 3600, 1, "dot.example", &params).unwrap();
        let server: SocketAddr = "198.51.100.1:53".parse().unwrap();
        let candidates = extract_candidates(server, &[rr]);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].details.target, "203.0.113.9:853".parse().unwrap());
        assert_eq!(candidates[0].details.sni, "dot.example");
    }

    #[test]
    fn extract_candidates_falls_back_to_the_original_server_address_without_hints() {
        let rr = svcb("dot.example", &["dot"], None);
        let server: SocketAddr = "198.51.100.1:53".parse().unwrap();
        let candidates = extract_candidates(server, &[rr]);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].details.target, "198.51.100.1:853".parse().unwrap());
    }

    #[test]
    fn extract_candidates_uses_the_explicit_port_hint_when_given() {
        let rr = svcb("dot.example", &["dot"], Some(8853));
        let server: SocketAddr = "198.51.100.1:53".parse().unwrap();
        assert_eq!(extract_candidates(server, &[rr])[0].details.target.port(), 8853);
    }

    #[test]
    fn extract_candidates_defaults_doh_to_port_443() {
        let rr = svcb("doh.example", &["h2"], None);
        let server: SocketAddr = "198.51.100.1:53".parse().unwrap();
        assert_eq!(extract_candidates(server, &[rr])[0].details.target.port(), 443);
    }

    #[test]
    fn extract_candidates_skips_a_record_whose_target_is_the_root() {
        let rr = svcb(".", &["dot"], None);
        let server: SocketAddr = "198.51.100.1:53".parse().unwrap();
        assert!(extract_candidates(server, &[rr]).is_empty());
    }

    #[test]
    fn extract_candidates_deduplicates_the_same_transport_across_records() {
        let a = svcb("dot-a.example", &["dot"], None);
        let b = svcb("dot-b.example", &["dot"], None);
        let server: SocketAddr = "198.51.100.1:53".parse().unwrap();
        assert_eq!(extract_candidates(server, &[a, b]).len(), 1);
    }

    #[test]
    fn extract_candidates_yields_one_entry_per_alpn_in_a_multi_alpn_record() {
        let rr = svcb("doh.example", &["h2", "h3"], None);
        let server: SocketAddr = "198.51.100.1:53".parse().unwrap();
        // Both "h2" and "h3" map to the same EncryptedTransport::Doh, so
        // this must still collapse to exactly one candidate, not two.
        assert_eq!(extract_candidates(server, &[rr]).len(), 1);
    }

    #[test]
    fn extract_candidates_skips_unrecognized_alpn_ids() {
        let rr = svcb("mystery.example", &["carrier-pigeon"], None);
        let server: SocketAddr = "198.51.100.1:53".parse().unwrap();
        assert!(extract_candidates(server, &[rr]).is_empty());
    }
}
