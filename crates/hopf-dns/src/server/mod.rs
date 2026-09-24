// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Caching DNS forwarder service + listeners.

#[cfg(feature = "server")]
mod udp;

#[cfg(all(feature = "server", feature = "dot"))]
mod dot;

#[cfg(all(feature = "server", feature = "doq"))]
mod doq;

#[cfg(feature = "server")]
pub use udp::{listen_dns_udp, DnsUdpListenConfig};

#[cfg(all(feature = "server", feature = "dot"))]
pub use dot::listen_dns_dot;

#[cfg(all(feature = "server", feature = "doq"))]
pub use doq::listen_dns_doq;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::cache::DnsCache;
use crate::client::DnsResolver;
use crate::cookie::{ClientCookieOption, DnsCookie};
use crate::wire::{DnsMessage, OPCODE_QUERY, RCODE_FORMERR, RCODE_NOTIMP, RCODE_SERVFAIL};

/// Simple server metrics counters.
#[derive(Debug, Default, Clone)]
pub struct DnsServerMetrics {
    /// Queries received.
    pub queries: u64,
    /// Cache hits.
    pub cache_hits: u64,
    /// Upstream forwards.
    pub upstreams: u64,
    /// Errors.
    pub errors: u64,
    /// Queries that presented a DNS Cookie (RFC 7873) option.
    pub cookies_presented: u64,
    /// Of those, queries whose presented server cookie was verified
    /// against a freshly (re)computed one for the client's address.
    pub cookies_verified: u64,
}

/// Caching forwarder (Gumdrop `DNSService`).
pub struct DnsService {
    cache: Arc<DnsCache>,
    upstream: Option<DnsResolver>,
    cookies: DnsCookie,
    metrics: std::sync::Mutex<DnsServerMetrics>,
    /// Optional local resolve hook: return `Some` to answer, `None` to forward.
    local: Option<Box<dyn Fn(&DnsMessage) -> Option<DnsMessage> + Send + Sync>>,
    /// Optional hook for messages whose opcode is not QUERY.
    opcode: Option<Box<OpcodeHandler>>,
}

/// See [`DnsService::set_opcode_handler`].
type OpcodeHandler = dyn Fn(&DnsMessage, SocketAddr) -> Option<DnsMessage> + Send + Sync;

impl DnsService {
    /// New service with shared cache.
    pub fn new(cache: Arc<DnsCache>) -> Self {
        Self {
            cache,
            upstream: None,
            cookies: DnsCookie::new(),
            metrics: std::sync::Mutex::new(DnsServerMetrics::default()),
            local: None,
            opcode: None,
        }
    }

    /// Attach upstream stub resolver for forwarding.
    pub fn set_upstream(&mut self, resolver: DnsResolver) {
        self.upstream = Some(resolver);
    }

    /// Custom local answers (override `resolve`).
    ///
    /// Only reached for standard queries (opcode QUERY). For other opcodes
    /// see [`Self::set_opcode_handler`].
    pub fn set_local_resolver<F>(&mut self, f: F)
    where
        F: Fn(&DnsMessage) -> Option<DnsMessage> + Send + Sync + 'static,
    {
        self.local = Some(Box::new(f));
    }

    /// Handle messages with an opcode other than QUERY, such as NOTIFY
    /// (RFC 1996) and dynamic UPDATE (RFC 2136).
    ///
    /// This is the counterpart of [`Self::set_local_resolver`] for the rest
    /// of the opcode space. `hopf-dns` is a caching forwarder and implements
    /// none of these itself: it has no zone store to notify about or mutate.
    /// A caller that serves a zone through `set_local_resolver` can plug in
    /// its own handling here instead of having the message refused before its
    /// code ever sees it.
    ///
    /// `f` receives the parsed message and the peer's address (an UPDATE
    /// handler needs the source to authorise the change) and returns
    /// `Some(response)` to answer, or `None` to decline, in which case the
    /// reply is `NOTIMP` exactly as if no handler were set. Build responses
    /// with [`DnsMessage::response_template`], which echoes the request's
    /// opcode as RFC 1996 §4.7 and RFC 2136 §3.8 require. The opcode
    /// constants are [`OPCODE_NOTIFY`](crate::wire::OPCODE_NOTIFY) and
    /// [`OPCODE_UPDATE`](crate::wire::OPCODE_UPDATE); the sections of an
    /// UPDATE message (zone, prerequisite, update, additional) arrive in the
    /// question, answer, authority and additional fields, with the RFC 2136
    /// `NONE` class (254) preserved in each record's `raw_class`.
    ///
    /// Notes:
    ///
    /// - The handler sees only requests: a message with the QR bit set is a
    ///   response, never a query, and is refused with `NOTIMP` without
    ///   reaching it.
    /// - It is subject to the same DNS Cookie anti-amplification rule as
    ///   resolution (RFC 7873 §5.2.3): a client that presents a cookie
    ///   without a verifiable server cookie gets a cookie-only reply and the
    ///   handler is not called. A client presenting *no* cookie is not
    ///   filtered, so an UPDATE handler must authenticate and authorise the
    ///   sender itself; `hopf-dns` provides no TSIG or SIG(0).
    /// - It runs on the listener's thread, so it should not block.
    pub fn set_opcode_handler<F>(&mut self, f: F)
    where
        F: Fn(&DnsMessage, SocketAddr) -> Option<DnsMessage> + Send + Sync + 'static,
    {
        self.opcode = Some(Box::new(f));
    }

    /// Shared cache.
    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }

    /// Snapshot metrics.
    pub fn metrics(&self) -> DnsServerMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Process one query message from `peer`; returns response (may be
    /// async via callback for upstream). Handles the server-side DNS
    /// Cookie exchange (RFC 7873 §5.2) around [`Self::compute_response`]:
    /// an inbound COOKIE option gets a response COOKIE option back, echoing
    /// the client's cookie plus a freshly (re)issued server cookie.
    ///
    /// A malformed COOKIE option (shorter than the 8-byte client cookie) is
    /// FORMERR with no cookie exchange (RFC 7873 §5.2.2). A client cookie
    /// presented without a server cookie we can verify gets a minimal
    /// cookie-only response instead of full resolution — RFC 7873 §5.2.3's
    /// anti-amplification guard: don't do real resolution work (including
    /// upstream forwarding) for a source that hasn't yet proven it can see
    /// our responses, since that work could otherwise be triggered at scale
    /// against a spoofed victim address.
    pub fn process_query_sync(&self, query: &DnsMessage, peer: SocketAddr) -> DnsMessage {
        match crate::cookie::parse_client_cookie(&query.additionals) {
            ClientCookieOption::Absent => self.compute_response(query, peer),
            ClientCookieOption::Malformed => query.response_template(RCODE_FORMERR),
            ClientCookieOption::Present { client, server } => {
                let ip_bytes = ip_octets(peer.ip());
                let mut m = self.metrics.lock().unwrap();
                m.cookies_presented += 1;
                let verified = server
                    .as_deref()
                    .is_some_and(|sc| self.cookies.validate_server_cookie(&client, &ip_bytes, sc));
                if verified {
                    m.cookies_verified += 1;
                }
                drop(m);
                let option = self.cookies.encode_response_edns_option(&client, &ip_bytes);
                let mut resp = if verified {
                    self.compute_response(query, peer)
                } else {
                    query.response_template(0)
                };
                resp.additionals
                    .push(crate::wire::DnsResourceRecord::opt(crate::wire::OPT_UDP_PAYLOAD, false, &option));
                resp
            }
        }
    }

    /// Core query handling, without the cookie exchange (factored out so
    /// [`Self::process_query_sync`] can wrap every return path uniformly).
    fn compute_response(&self, query: &DnsMessage, peer: SocketAddr) -> DnsMessage {
        {
            let mut m = self.metrics.lock().unwrap();
            m.queries += 1;
        }
        // RFC 1035 §4.1.1: a message with QR set is a response, not a query.
        if !query.is_query() {
            return query.response_template(RCODE_NOTIMP);
        }
        // Only the standard QUERY opcode is implemented here. Anything else
        // (NOTIFY, UPDATE, ...) is offered to the caller's own handler, and
        // is NOTIMP if there is none or it declines.
        if query.opcode() != OPCODE_QUERY {
            if let Some(ref handler) = self.opcode {
                if let Some(resp) = handler(query, peer) {
                    return resp;
                }
            }
            return query.response_template(RCODE_NOTIMP);
        }
        // RFC 1035 §4.1.2: the question section must not be empty.
        if query.questions.is_empty() {
            return query.response_template(RCODE_FORMERR);
        }
        let q = &query.questions[0];

        if let Some(ref local) = self.local {
            if let Some(resp) = local(query) {
                return resp;
            }
        }

        if self.cache.is_negatively_cached(&q.name) {
            let mut m = self.metrics.lock().unwrap();
            m.cache_hits += 1;
            return query.response_template(crate::wire::RCODE_NXDOMAIN);
        }
        if self.cache.is_nodata_cached(q) {
            // RFC 2308 §2 NODATA: NOERROR with an empty answer set, not NXDOMAIN.
            let mut m = self.metrics.lock().unwrap();
            m.cache_hits += 1;
            return query.response_template(0);
        }
        if let Some(answers) = self.cache.lookup(q) {
            let mut m = self.metrics.lock().unwrap();
            m.cache_hits += 1;
            let mut resp = query.response_template(0);
            resp.answers = answers;
            return resp;
        }

        // Sync upstream via TCP fallback path when resolver available — for UDP
        // server we use blocking TCP to upstream as a pragmatic Stage-D forward.
        if let Some(ref upstream) = self.upstream {
            let mut m = self.metrics.lock().unwrap();
            m.upstreams += 1;
            drop(m);
            let (tx, rx) = std::sync::mpsc::channel();
            upstream.query_with_cd(q.clone(), query.is_checking_disabled(), Box::new(move |r| {
                let _ = tx.send(r);
            }));
            match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(Ok(mut resp)) => {
                    resp.id = query.id;
                    if !query.has_do() {
                        // Strip DNSSEC RRs when client lacks DO (Gumdrop behaviour).
                        resp.answers
                            .retain(|rr| !matches!(rr.rtype, Some(crate::wire::DnsType::Rrsig)
                                | Some(crate::wire::DnsType::Nsec)
                                | Some(crate::wire::DnsType::Nsec3)
                                | Some(crate::wire::DnsType::Dnskey)
                                | Some(crate::wire::DnsType::Ds)));
                    }
                    self.cache.put_response(&resp);
                    resp
                }
                _ => {
                    let mut m = self.metrics.lock().unwrap();
                    m.errors += 1;
                    query.response_template(RCODE_SERVFAIL)
                }
            }
        } else {
            query.response_template(RCODE_SERVFAIL)
        }
    }

    /// Server cookie helper.
    pub fn cookies(&self) -> &DnsCookie {
        &self.cookies
    }
}

/// Config shared by listeners.
#[derive(Clone)]
pub struct DnsServiceHandle {
    inner: Arc<DnsService>,
}

impl DnsServiceHandle {
    /// Wrap service.
    pub fn new(service: DnsService) -> Self {
        Self {
            inner: Arc::new(service),
        }
    }

    /// Process query from `peer`.
    pub fn process(&self, query: &DnsMessage, peer: SocketAddr) -> DnsMessage {
        self.inner.process_query_sync(query, peer)
    }

    /// Arc access.
    pub fn service(&self) -> &Arc<DnsService> {
        &self.inner
    }
}

/// Raw address octets for [`DnsCookie::generate_server_cookie`]'s
/// client-IP input (4 for IPv4, 16 for IPv6).
fn ip_octets(ip: std::net::IpAddr) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// Upstream server list helper.
pub fn parse_upstream_list(s: &str) -> io::Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    for part in s.split_whitespace() {
        if let Ok(addr) = part.parse::<SocketAddr>() {
            out.push(addr);
        } else if let Ok(ip) = part.parse::<std::net::IpAddr>() {
            out.push(SocketAddr::new(ip, crate::client::DEFAULT_DNS_PORT));
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad upstream {part}"),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{DnsQuestion, DnsResourceRecord, DnsType};
    use std::net::Ipv4Addr;

    fn cookie_option(client: &[u8], server: Option<&[u8]>) -> DnsResourceRecord {
        let mut data = client.to_vec();
        if let Some(s) = server {
            data.extend_from_slice(s);
        }
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&crate::cookie::EDNS_OPTION_COOKIE.to_be_bytes());
        rdata.extend_from_slice(&(data.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&data);
        DnsResourceRecord::opt(1232, false, &rdata)
    }

    fn service_answering(ip: Ipv4Addr) -> DnsService {
        let mut service = DnsService::new(Arc::new(DnsCache::default()));
        service.set_local_resolver(move |q| {
            let mut resp = q.response_template(0);
            resp.answers.push(DnsResourceRecord::a(&q.questions[0].name, 60, ip));
            Some(resp)
        });
        service
    }

    #[test]
    fn server_echoes_client_cookie_and_issues_a_verifiable_server_cookie() {
        let service = service_answering(Ipv4Addr::new(203, 0, 113, 9));
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let client_cookie = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let mut query = DnsMessage::query(1, DnsQuestion::in_class("example.com", DnsType::A), true);
        query.additionals.push(cookie_option(&client_cookie, None));
        let resp = service.process_query_sync(&query, peer);

        let opt = resp
            .additionals
            .iter()
            .find(|rr| rr.rtype == Some(DnsType::Opt))
            .expect("response must carry an OPT record with the COOKIE option");
        let (got_client, got_server) = match crate::cookie::parse_client_cookie(std::slice::from_ref(opt)) {
            ClientCookieOption::Present { client, server } => (client, server),
            other => panic!("COOKIE option must round-trip, got {other:?}"),
        };
        assert_eq!(got_client, client_cookie);
        let server_cookie = got_server.expect("server must always issue a server cookie");
        assert!(service.cookies().validate_server_cookie(&client_cookie, &ip_octets(peer.ip()), &server_cookie));

        assert_eq!(service.metrics().cookies_presented, 1);
        assert_eq!(service.metrics().cookies_verified, 0, "no prior server cookie was presented, so nothing to verify yet");
    }

    #[test]
    fn server_verifies_a_previously_issued_cookie_on_the_next_query() {
        let service = service_answering(Ipv4Addr::new(203, 0, 113, 9));
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let client_cookie = [9u8; 8];
        let server_cookie = service.cookies().generate_server_cookie(&client_cookie, &ip_octets(peer.ip()));

        let mut query = DnsMessage::query(2, DnsQuestion::in_class("example.com", DnsType::A), true);
        query.additionals.push(cookie_option(&client_cookie, Some(&server_cookie)));
        let _ = service.process_query_sync(&query, peer);

        assert_eq!(service.metrics().cookies_presented, 1);
        assert_eq!(service.metrics().cookies_verified, 1, "the echoed, still-valid server cookie must verify");
    }

    #[test]
    fn server_rejects_a_forged_server_cookie_from_a_different_client() {
        let service = service_answering(Ipv4Addr::new(203, 0, 113, 9));
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let attacker: SocketAddr = "192.0.2.66:5353".parse().unwrap();
        let client_cookie = [3u8; 8];
        // A cookie genuinely issued to a *different* source address.
        let cookie_for_someone_else = service.cookies().generate_server_cookie(&client_cookie, &ip_octets(attacker.ip()));

        let mut query = DnsMessage::query(3, DnsQuestion::in_class("example.com", DnsType::A), true);
        query.additionals.push(cookie_option(&client_cookie, Some(&cookie_for_someone_else)));
        let _ = service.process_query_sync(&query, peer);

        assert_eq!(service.metrics().cookies_presented, 1);
        assert_eq!(service.metrics().cookies_verified, 0, "a cookie issued for a different address must not verify");
    }

    #[test]
    fn no_cookie_option_in_query_means_none_in_response() {
        let service = service_answering(Ipv4Addr::new(203, 0, 113, 9));
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let query = DnsMessage::query(4, DnsQuestion::in_class("example.com", DnsType::A), true);
        let resp = service.process_query_sync(&query, peer);
        assert!(resp.additionals.iter().all(|rr| rr.rtype != Some(DnsType::Opt)));
        assert_eq!(service.metrics().cookies_presented, 0);
    }

    #[test]
    fn empty_question_section_is_formerr() {
        // RFC 1035 §4.1.2: the question section must not be empty.
        let service = service_answering(Ipv4Addr::new(203, 0, 113, 9));
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let query = DnsMessage::new(5, 0, Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let resp = service.process_query_sync(&query, peer);
        assert_eq!(resp.rcode(), RCODE_FORMERR);
    }

    #[test]
    fn response_message_sent_as_a_query_is_notimp() {
        // RFC 1035 §4.1.1: a message with QR already set is a response, not
        // a query — reject it rather than trying to resolve it.
        let service = service_answering(Ipv4Addr::new(203, 0, 113, 9));
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let mut query = DnsMessage::query(6, DnsQuestion::in_class("example.com", DnsType::A), true);
        query.flags |= crate::wire::FLAG_QR;
        let resp = service.process_query_sync(&query, peer);
        assert_eq!(resp.rcode(), RCODE_NOTIMP);
    }

    /// A NOTIFY (opcode 4) query for `zone`.
    fn notify(id: u16, zone: &str) -> DnsMessage {
        let mut m = DnsMessage::query(id, DnsQuestion::in_class(zone, DnsType::Soa), false);
        m.flags |= 4 << 11;
        m
    }

    #[test]
    fn unhandled_opcode_is_notimp_and_the_reply_carries_that_opcode() {
        let service = service_answering(Ipv4Addr::new(203, 0, 113, 9));
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let resp = service.process_query_sync(&notify(11, "example.com"), peer);
        assert_eq!(resp.rcode(), RCODE_NOTIMP);
        assert_eq!(resp.opcode(), 4, "the reply must echo the NOTIFY opcode");
    }

    /// What an opcode handler was asked, recorded for assertions.
    type Seen = Arc<std::sync::Mutex<Vec<(u16, u16, String, SocketAddr)>>>;

    fn service_with_recording_handler(reply: bool) -> (DnsService, Seen) {
        let mut service = service_answering(Ipv4Addr::new(203, 0, 113, 9));
        let seen: Seen = Arc::default();
        let seen2 = Arc::clone(&seen);
        service.set_opcode_handler(move |m, peer| {
            let zone = m.questions.first().map(|q| q.name.clone()).unwrap_or_default();
            seen2.lock().unwrap().push((m.opcode(), m.id, zone, peer));
            reply.then(|| m.response_template(crate::wire::RCODE_NOERROR))
        });
        (service, seen)
    }

    #[test]
    fn opcode_handler_answers_notify_and_sees_the_message_and_peer() {
        let (service, seen) = service_with_recording_handler(true);
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let resp = service.process_query_sync(&notify(21, "example.com"), peer);

        assert_eq!(resp.rcode(), crate::wire::RCODE_NOERROR);
        assert_eq!(resp.opcode(), crate::wire::OPCODE_NOTIFY, "a reply built from the template echoes NOTIFY");
        assert!(resp.is_response());
        assert_eq!(resp.id, 21);
        assert_eq!(
            *seen.lock().unwrap(),
            [(crate::wire::OPCODE_NOTIFY, 21, "example.com".to_string(), peer)]
        );
    }

    #[test]
    fn a_declining_opcode_handler_leaves_the_default_notimp() {
        let (service, seen) = service_with_recording_handler(false);
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let resp = service.process_query_sync(&notify(22, "example.com"), peer);
        assert_eq!(resp.rcode(), RCODE_NOTIMP);
        assert_eq!(resp.opcode(), 4);
        assert_eq!(seen.lock().unwrap().len(), 1, "it was consulted, and declined");
    }

    #[test]
    fn opcode_handler_is_not_consulted_for_queries_or_for_responses() {
        let (service, seen) = service_with_recording_handler(true);
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();

        // An ordinary query still goes to the local resolver / forwarder.
        let q = DnsMessage::query(23, DnsQuestion::in_class("example.com", DnsType::A), true);
        let resp = service.process_query_sync(&q, peer);
        assert_eq!(resp.answers.len(), 1);

        // A message with QR set is a response even when its opcode is not
        // QUERY: refused, never handed to the handler.
        let mut echo = notify(24, "example.com");
        echo.flags |= crate::wire::FLAG_QR;
        let resp = service.process_query_sync(&echo, peer);
        assert_eq!(resp.rcode(), RCODE_NOTIMP);
        assert!(seen.lock().unwrap().is_empty(), "the handler must only ever see requests");
    }

    #[test]
    fn opcode_handler_is_skipped_for_a_cookie_that_has_not_been_verified() {
        // RFC 7873 §5.2.3 anti-amplification applies to it as to resolution.
        let (service, seen) = service_with_recording_handler(true);
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let client_cookie = [6u8; 8];

        let mut unverified = notify(25, "example.com");
        unverified.additionals.push(cookie_option(&client_cookie, None));
        let resp = service.process_query_sync(&unverified, peer);
        assert!(seen.lock().unwrap().is_empty(), "no verified server cookie: no handler call");
        assert!(resp.additionals.iter().any(|rr| rr.rtype == Some(DnsType::Opt)), "cookie-only reply");

        let server_cookie = service.cookies().generate_server_cookie(&client_cookie, &ip_octets(peer.ip()));
        let mut verified = notify(26, "example.com");
        verified.additionals.push(cookie_option(&client_cookie, Some(&server_cookie)));
        service.process_query_sync(&verified, peer);
        assert_eq!(seen.lock().unwrap().len(), 1, "a verified cookie reaches the handler");
    }

    /// An RFC 2136 UPDATE carries records the query path never sees: the
    /// `NONE` class (254) and `ANY` type/class prerequisites and deletions.
    /// They must survive parsing intact for a handler to act on them.
    #[test]
    fn an_rfc_2136_update_reaches_the_handler_with_its_sections_intact() {
        use crate::wire::{DnsResourceRecord as Rr, OPCODE_UPDATE};
        const NONE: u16 = 254;
        const ANY: u16 = 255;
        let a = DnsType::A as u16;

        let mut update = DnsMessage::new(
            30,
            OPCODE_UPDATE << 11,
            // Zone section: the zone being updated (type SOA).
            vec![DnsQuestion::in_class("example.com", DnsType::Soa)],
            // Prerequisite: "name is in use" (class ANY, type ANY, no data).
            vec![Rr::opaque("host.example.com", ANY, ANY, 0, vec![])],
            // Update section: add one A record, delete another (class NONE, with its rdata).
            vec![
                Rr::opaque("host.example.com", a, 1, 300, vec![192, 0, 2, 1]),
                Rr::opaque("host.example.com", a, NONE, 0, vec![192, 0, 2, 2]),
            ],
            Vec::new(),
        );
        update.flags &= !crate::wire::FLAG_RD;
        let wire = update.serialize().unwrap();
        let parsed = DnsMessage::parse(&wire).unwrap();

        let observed: Arc<std::sync::Mutex<Option<DnsMessage>>> = Arc::default();
        let observed2 = Arc::clone(&observed);
        let mut service = DnsService::new(Arc::new(DnsCache::default()));
        service.set_opcode_handler(move |m, _| {
            *observed2.lock().unwrap() = Some(m.clone());
            Some(m.response_template(crate::wire::RCODE_NOERROR))
        });
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let resp = service.process_query_sync(&parsed, peer);

        assert_eq!(resp.opcode(), OPCODE_UPDATE);
        assert_eq!(resp.rcode(), crate::wire::RCODE_NOERROR);
        // The reply survives the wire too.
        let back = DnsMessage::parse(&resp.serialize().unwrap()).unwrap();
        assert_eq!(back.opcode(), OPCODE_UPDATE);

        let m = observed.lock().unwrap().clone().expect("handler must have run");
        assert_eq!(m.opcode(), OPCODE_UPDATE);
        assert_eq!(m.questions[0].name, "example.com");
        assert_eq!((m.answers[0].raw_type, m.answers[0].raw_class), (ANY, ANY), "prerequisite");
        assert_eq!((m.authorities[0].raw_type, m.authorities[0].raw_class, m.authorities[0].ttl), (a, 1, 300));
        assert_eq!(m.authorities[0].rdata, [192, 0, 2, 1]);
        assert_eq!((m.authorities[1].raw_class, m.authorities[1].rdata.as_slice()), (NONE, &[192u8, 0, 2, 2][..]), "class NONE deletion");
    }

    #[test]
    fn malformed_cookie_option_is_formerr_with_no_cookie_exchange() {
        // RFC 7873 §5.2.2: a COOKIE option shorter than the mandatory
        // 8-byte client cookie is malformed.
        let service = service_answering(Ipv4Addr::new(203, 0, 113, 9));
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let mut query = DnsMessage::query(7, DnsQuestion::in_class("example.com", DnsType::A), true);
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&crate::cookie::EDNS_OPTION_COOKIE.to_be_bytes());
        let short = [1u8, 2, 3];
        rdata.extend_from_slice(&(short.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&short);
        query.additionals.push(DnsResourceRecord::opt(1232, false, &rdata));

        let resp = service.process_query_sync(&query, peer);
        assert_eq!(resp.rcode(), RCODE_FORMERR);
        assert!(resp.additionals.iter().all(|rr| rr.rtype != Some(DnsType::Opt)));
        assert_eq!(service.metrics().cookies_presented, 0, "a malformed option was never actually parsed as a cookie");
    }

    #[test]
    fn cookie_without_a_verifiable_server_cookie_skips_resolution() {
        // RFC 7873 §5.2.3 anti-amplification: don't do real resolution work
        // (including upstream forwarding) for a client that hasn't yet
        // proven it can see our responses.
        let service = service_answering(Ipv4Addr::new(203, 0, 113, 9));
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let client_cookie = [4u8; 8];

        // No server cookie presented at all.
        let mut query = DnsMessage::query(8, DnsQuestion::in_class("example.com", DnsType::A), true);
        query.additionals.push(cookie_option(&client_cookie, None));
        let resp = service.process_query_sync(&query, peer);
        assert!(resp.answers.is_empty(), "must not resolve without a verified server cookie");
        assert_eq!(resp.rcode(), 0);

        // A server cookie is presented, but it's invalid (forged/stale).
        let mut query2 = DnsMessage::query(9, DnsQuestion::in_class("example.com", DnsType::A), true);
        query2.additionals.push(cookie_option(&client_cookie, Some(&[0u8; 8])));
        let resp2 = service.process_query_sync(&query2, peer);
        assert!(resp2.answers.is_empty(), "must not resolve with an invalid server cookie");

        // Once the client echoes back the valid, freshly-issued server
        // cookie, resolution proceeds normally.
        let server_cookie = service.cookies().generate_server_cookie(&client_cookie, &ip_octets(peer.ip()));
        let mut query3 = DnsMessage::query(10, DnsQuestion::in_class("example.com", DnsType::A), true);
        query3.additionals.push(cookie_option(&client_cookie, Some(&server_cookie)));
        let resp3 = service.process_query_sync(&query3, peer);
        assert!(!resp3.answers.is_empty(), "a verified server cookie must proceed to full resolution");
    }
}
