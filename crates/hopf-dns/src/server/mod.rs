// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS server shell + listeners.
//!
//! [`DnsService`] is the protocol shell: cookies (RFC 7873), header
//! validation and transport framing. It does no resolution of its own. With
//! no handler it answers every query with an empty `NOERROR`; behaviour comes
//! from a composed [`DnsQueryHandler`]:
//!
//! ```ignore
//! // Caching forwarder.
//! let service = DnsService::with_handler(
//!     ForwarderHandler::new(cache).with_upstream(resolver),
//! );
//! // Authoritative zones first, everything else forwarded.
//! let service = DnsService::with_handler(
//!     ChainHandler::new().then(zones).then(ForwarderHandler::new(cache)),
//! );
//! ```

mod forwarder;
mod framed;
mod handler;
mod minimal_any;
mod udp;
pub mod zone;

#[cfg(feature = "dot")]
mod dot;

#[cfg(feature = "doq")]
mod doq;

pub use forwarder::ForwarderHandler;
pub use framed::listen_dns_tcp;
pub use handler::{
    ChainHandler, DnsQueryHandler, DnsTransport, EmptyHandler, FnHandler, HandlerOutcome,
    MetricsSink, QueryContext,
};
pub use minimal_any::{MinimalAnyDisabled, MinimalAnyEnabled, MinimalAnyPolicy};
pub use udp::{listen_dns_udp, DnsUdpListenConfig};

#[cfg(feature = "dot")]
pub use dot::listen_dns_dot;

#[cfg(feature = "doq")]
pub use doq::listen_dns_doq;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::Runtime;

use crate::cookie::{ClientCookieOption, DnsCookie};
use crate::tsig::{self, Chain, TsigKeyring};
use crate::wire::{
    DnsMessage, FLAG_TC, OPCODE_QUERY, RCODE_FORMERR, RCODE_NOTAUTH, RCODE_NOTIMP,
};

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

/// DNS protocol shell. See the [module docs](self).
pub struct DnsService {
    handler: Arc<dyn DnsQueryHandler>,
    cookies: DnsCookie,
    metrics: std::sync::Mutex<DnsServerMetrics>,
    keyring: TsigKeyring,
}

impl Default for DnsService {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsService {
    /// A no-op service: every query gets an empty `NOERROR`, every other
    /// opcode `NOTIMP`. Attach behaviour with [`Self::with_handler`].
    pub fn new() -> Self {
        Self::with_handler(EmptyHandler)
    }

    /// Service backed by `handler`.
    pub fn with_handler<H: DnsQueryHandler + 'static>(handler: H) -> Self {
        Self::with_shared_handler(Arc::new(handler))
    }

    /// Service backed by a handler that is also held elsewhere (for example
    /// to reach an authoritative handler's zones from application code).
    pub fn with_shared_handler(handler: Arc<dyn DnsQueryHandler>) -> Self {
        Self {
            handler,
            cookies: DnsCookie::new(),
            metrics: std::sync::Mutex::new(DnsServerMetrics::default()),
            keyring: TsigKeyring::new(),
        }
    }

    /// Accept TSIG-signed requests (RFC 8945) made with these keys. A
    /// request whose signature verifies is authenticated as that key
    /// ([`QueryContext::tsig_key`]) and its responses are signed; one that
    /// does not is answered `NOTAUTH` with the TSIG error and never reaches
    /// the handler. Unsigned requests are unaffected: what they may do is
    /// the handler's decision. Not applied over DoQ, which has no use for
    /// it (RFC 9250 §4.2.1 requires message ID 0).
    pub fn set_tsig_keyring(&mut self, keyring: TsigKeyring) {
        self.keyring = keyring;
    }

    /// Replace the handler.
    pub fn set_handler<H: DnsQueryHandler + 'static>(&mut self, handler: H) {
        self.handler = Arc::new(handler);
    }

    /// Start the handler's background work (see [`DnsQueryHandler::start`]).
    /// Call before binding listeners.
    pub fn start(&self, rt: &Runtime) -> io::Result<()> {
        self.handler.start(rt)
    }

    /// Stop the handler's background work.
    pub fn stop(&self) {
        self.handler.stop();
    }

    /// Snapshot metrics.
    pub fn metrics(&self) -> DnsServerMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Process one message from `peer` as if it arrived over UDP, returning
    /// the first response message. Convenience for single-message
    /// transports; see [`Self::process_on`].
    pub fn process_query_sync(&self, query: &DnsMessage, peer: SocketAddr) -> DnsMessage {
        self.process_on(query, peer, DnsTransport::Udp)
            .into_iter()
            .next()
            .expect("process_on always returns at least one message")
    }

    /// Process one message from `peer` over `transport`. Returns one
    /// response, or several for a zone transfer on a stream transport;
    /// never empty.
    ///
    /// Handles the server-side DNS Cookie exchange (RFC 7873 §5.2) around
    /// the handler dispatch: an inbound COOKIE option gets a response
    /// COOKIE option back, echoing the client's cookie plus a freshly
    /// (re)issued server cookie (on the first message of a sequence).
    ///
    /// A malformed COOKIE option (shorter than the 8-byte client cookie) is
    /// FORMERR with no cookie exchange (RFC 7873 §5.2.2). A client cookie
    /// presented without a server cookie we can verify gets a minimal
    /// cookie-only response instead of the handler's answer - RFC 7873
    /// §5.2.3's anti-amplification guard: don't do real work (including
    /// upstream forwarding or a zone transfer) for a source that hasn't yet
    /// proven it can see our responses. A client presenting *no* cookie is
    /// not filtered, so an UPDATE or transfer handler must authenticate and
    /// authorise the sender itself.
    pub fn process_on(
        &self,
        query: &DnsMessage,
        peer: SocketAddr,
        transport: DnsTransport,
    ) -> Vec<DnsMessage> {
        self.process_authenticated(query, peer, transport, None)
    }

    fn process_authenticated(
        &self,
        query: &DnsMessage,
        peer: SocketAddr,
        transport: DnsTransport,
        tsig_key: Option<&str>,
    ) -> Vec<DnsMessage> {
        match crate::cookie::parse_client_cookie(&query.additionals) {
            ClientCookieOption::Absent => self.compute_response(query, peer, transport, tsig_key),
            ClientCookieOption::Malformed => vec![query.response_template(RCODE_FORMERR)],
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
                let mut out = if verified {
                    self.compute_response(query, peer, transport, tsig_key)
                } else {
                    vec![query.response_template(0)]
                };
                out[0].additionals.push(crate::wire::DnsResourceRecord::opt(
                    crate::wire::OPT_UDP_PAYLOAD,
                    false,
                    &option,
                ));
                out
            }
        }
    }

    /// Core message handling, without the cookie exchange (factored out so
    /// `process_on` can wrap every return path uniformly).
    fn compute_response(
        &self,
        query: &DnsMessage,
        peer: SocketAddr,
        transport: DnsTransport,
        tsig_key: Option<&str>,
    ) -> Vec<DnsMessage> {
        self.metrics.lock().unwrap().queries += 1;
        // RFC 1035 §4.1.1: a message with QR set is a response, not a query.
        if !query.is_query() {
            return vec![query.response_template(RCODE_NOTIMP)];
        }
        let ctx = QueryContext {
            peer,
            transport,
            tsig_key,
            metrics: MetricsSink(&self.metrics),
        };
        // Only the standard QUERY opcode reaches `handle_query`. Anything
        // else (NOTIFY, UPDATE, ...) is offered to `handle_non_query_opcode`
        // and is NOTIMP if nothing claims it.
        let (outcome, fallback) = if query.opcode() != OPCODE_QUERY {
            (
                self.handler.handle_non_query_opcode(query, &ctx),
                RCODE_NOTIMP,
            )
        } else if query.questions.is_empty() {
            // RFC 1035 §4.1.2: the question section must not be empty.
            return vec![query.response_template(RCODE_FORMERR)];
        } else {
            (self.handler.handle_query(query, &ctx), 0)
        };
        match outcome {
            HandlerOutcome::Respond(resp) => vec![resp],
            HandlerOutcome::Sequence(seq) if !seq.is_empty() => seq,
            HandlerOutcome::Sequence(_) | HandlerOutcome::Decline => {
                vec![query.response_template(fallback)]
            }
        }
    }

    /// Handle one request as received on the wire and return the encoded
    /// responses to send (one, or several for a zone transfer on a stream
    /// transport). `None` means the bytes are not a DNS message and nothing
    /// should be sent.
    ///
    /// This is what the listeners call. It owns everything below the
    /// handler: TSIG verification and signing, UDP truncation to the size
    /// the client advertised (RFC 1035 §4.1.1, RFC 6891 §6.2.3: records are
    /// dropped and TC set, and the client retries over TCP), and the zero
    /// message ID required over DoQ (RFC 9250 §4.2.1).
    pub fn process_wire(
        &self,
        raw: &[u8],
        peer: SocketAddr,
        transport: DnsTransport,
    ) -> Option<Vec<Vec<u8>>> {
        let now = tsig::now();
        let use_tsig = !self.keyring.is_empty() && transport != DnsTransport::Doq;
        let mut signer: Option<(&tsig::TsigKey, Vec<u8>)> = None;
        let query = match use_tsig.then(|| tsig::locate(raw)).flatten() {
            None => DnsMessage::parse(raw).ok()?,
            Some(rec) => match tsig::verify(raw, &self.keyring, Chain::default(), false, now) {
                Ok(v) => {
                    signer = self.keyring.get(&v.key_name).map(|k| (k, v.mac));
                    DnsMessage::parse(&v.unsigned).ok()?
                }
                Err(e) => {
                    let q = DnsMessage::parse(raw).ok()?;
                    let reply = q.response_template(RCODE_NOTAUTH).serialize().ok()?;
                    return Some(vec![tsig::error_reply(&reply, &rec, e.code(), now)]);
                }
            },
        };
        let key_name = signer.as_ref().map(|(k, _)| k.name().to_string());
        let mut responses = self.process_authenticated(&query, peer, transport, key_name.as_deref());
        if transport == DnsTransport::Udp {
            responses.truncate(1);
        }
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(responses.len());
        for mut resp in responses {
            if transport == DnsTransport::Doq {
                resp.id = 0;
            }
            let mut bytes = resp.serialize().ok()?;
            if transport == DnsTransport::Udp && bytes.len() > query.requested_udp_payload_size() as usize {
                resp.answers.clear();
                resp.authorities.clear();
                resp.additionals.clear();
                resp.flags |= FLAG_TC;
                bytes = resp.serialize().ok()?;
            }
            out.push(bytes);
        }
        if let Some((key, request_mac)) = signer {
            let mut prior = request_mac;
            for (i, bytes) in out.iter_mut().enumerate() {
                let chain = Chain {
                    prior_mac: Some(&prior),
                    unsigned_since: &[],
                };
                let (signed, mac) = tsig::sign(bytes, key, chain, i > 0, now);
                *bytes = signed;
                prior = mac;
            }
        }
        Some(out)
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

    /// Process a UDP message from `peer`; see [`DnsService::process_query_sync`].
    pub fn process(&self, query: &DnsMessage, peer: SocketAddr) -> DnsMessage {
        self.inner.process_query_sync(query, peer)
    }

    /// Process a message over `transport`; see [`DnsService::process_on`].
    pub fn process_on(
        &self,
        query: &DnsMessage,
        peer: SocketAddr,
        transport: DnsTransport,
    ) -> Vec<DnsMessage> {
        self.inner.process_on(query, peer, transport)
    }

    /// Handle wire bytes; see [`DnsService::process_wire`].
    pub fn process_wire(
        &self,
        raw: &[u8],
        peer: SocketAddr,
        transport: DnsTransport,
    ) -> Option<Vec<Vec<u8>>> {
        self.inner.process_wire(raw, peer, transport)
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

    fn answering(ip: Ipv4Addr) -> FnHandler {
        FnHandler::new().on_query(move |q| {
            let mut resp = q.response_template(0);
            resp.answers.push(DnsResourceRecord::a(&q.questions[0].name, 60, ip));
            Some(resp)
        })
    }

    fn service_answering(ip: Ipv4Addr) -> DnsService {
        DnsService::with_handler(answering(ip))
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
        let seen: Seen = Arc::default();
        let seen2 = Arc::clone(&seen);
        let handler = answering(Ipv4Addr::new(203, 0, 113, 9)).on_opcode(move |m, peer| {
            let zone = m.questions.first().map(|q| q.name.clone()).unwrap_or_default();
            seen2.lock().unwrap().push((m.opcode(), m.id, zone, peer));
            reply.then(|| m.response_template(crate::wire::RCODE_NOERROR))
        });
        (DnsService::with_handler(handler), seen)
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
        let service = DnsService::with_handler(FnHandler::new().on_opcode(move |m, _| {
            *observed2.lock().unwrap() = Some(m.clone());
            Some(m.response_template(crate::wire::RCODE_NOERROR))
        }));
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

    #[test]
    fn a_service_with_no_handler_is_a_noop_noerror_empty_answer() {
        let service = DnsService::new();
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let q = DnsMessage::query(40, DnsQuestion::in_class("example.com", DnsType::A), true);
        let resp = service.process_query_sync(&q, peer);
        assert_eq!(resp.rcode(), crate::wire::RCODE_NOERROR);
        assert!(resp.answers.is_empty());
        assert!(resp.is_response());
        // Other opcodes remain NOTIMP.
        let resp = service.process_query_sync(&notify(41, "example.com"), peer);
        assert_eq!(resp.rcode(), RCODE_NOTIMP);
    }

    #[test]
    fn chain_uses_the_first_handler_that_does_not_decline() {
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let only_example = FnHandler::new().on_query(|q| {
            (q.questions[0].name == "example.com").then(|| {
                let mut r = q.response_template(0);
                r.answers.push(DnsResourceRecord::a("example.com", 60, Ipv4Addr::new(192, 0, 2, 1)));
                r
            })
        });
        let service = DnsService::with_handler(
            ChainHandler::new().then(only_example).then(answering(Ipv4Addr::new(203, 0, 113, 9))),
        );
        let a = |name: &str| {
            let q = DnsMessage::query(42, DnsQuestion::in_class(name, DnsType::A), true);
            service.process_query_sync(&q, peer).answers[0].as_a().unwrap()
        };
        assert_eq!(a("example.com"), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(a("other.test"), Ipv4Addr::new(203, 0, 113, 9), "declined names fall through");
    }

    #[test]
    fn a_stream_transport_receives_every_message_of_a_sequence_but_udp_only_the_first() {
        struct Seq;
        impl DnsQueryHandler for Seq {
            fn handle_query(&self, q: &DnsMessage, ctx: &QueryContext<'_>) -> HandlerOutcome {
                let mut a = q.response_template(0);
                a.id = q.id;
                let mut b = a.clone();
                b.answers.push(DnsResourceRecord::a("x.test", 1, Ipv4Addr::LOCALHOST));
                if ctx.transport.supports_multi_message() {
                    HandlerOutcome::Sequence(vec![a, b])
                } else {
                    HandlerOutcome::Respond(a)
                }
            }
        }
        let service = DnsService::with_handler(Seq);
        let peer: SocketAddr = "198.51.100.7:5353".parse().unwrap();
        let q = DnsMessage::query(43, DnsQuestion::in_class("x.test", DnsType::A), true);
        assert_eq!(service.process_on(&q, peer, DnsTransport::Tcp).len(), 2);
        assert_eq!(service.process_on(&q, peer, DnsTransport::Udp).len(), 1);
    }
}
