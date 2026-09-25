// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`AuthoritativeZoneHandler`]: serves in-memory zones, and takes part in
//! NOTIFY, dynamic update and zone transfer.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use hopf_core::Runtime;

use super::error::ZoneError;
use super::maintain::{Cmd, Maintainer};
use super::model::{cname_target, in_record, Lookup, Zone};
use super::options::{ZoneFileMode, ZoneOptions};
use super::rdata::TYPE_HINFO;
use super::{update, xfr};
use crate::server::handler::{DnsQueryHandler, HandlerOutcome, QueryContext};
use crate::server::minimal_any::{MinimalAnyDisabled, MinimalAnyEnabled, MinimalAnyPolicy};
use crate::wire::{
    normalize_name, DnsClass, DnsMessage, DnsResourceRecord, DnsType, FLAG_AA, FLAG_RA, FLAG_TC,
    OPCODE_NOTIFY, OPCODE_UPDATE, OPT_UDP_PAYLOAD, RCODE_BADVERS, RCODE_FORMERR, RCODE_NOERROR,
    RCODE_NOTAUTH, RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL,
};

/// RFC 1034 §3.6.2 / RFC 6604 give no bound; this matches common servers.
const MAX_CNAME_CHAIN: usize = 16;
const TYPE_CNAME: u16 = 5;
const TYPE_ANY: u16 = 255;
const TYPE_SOA: u16 = 6;
const TYPE_IXFR: u16 = 251;
const TYPE_AXFR: u16 = 252;

/// One served zone.
pub(super) struct ZoneSlot {
    pub(super) origin: String,
    /// `None` on a secondary until its first transfer (or persisted copy).
    pub(super) zone: RwLock<Option<Zone>>,
    /// A secondary that could not reach its primary for the SOA EXPIRE
    /// interval stops answering (RFC 1035 §3.3.13).
    pub(super) expired: AtomicBool,
    pub(super) options: ZoneOptions,
    /// Set for a secondary: where to transfer from.
    pub(super) primary: Option<SocketAddr>,
}

pub(super) struct Inner {
    /// Longest origin first, so the first `is_within` match is the most
    /// specific zone.
    pub(super) slots: Vec<Arc<ZoneSlot>>,
    pub(super) refuse_outside_zones: bool,
    pub(super) minimal_any: Arc<dyn MinimalAnyPolicy>,
    pub(super) maintainer: Mutex<Option<Maintainer>>,
}

impl Inner {
    /// Hand background work to the maintenance thread, if it is running.
    pub(super) fn signal(&self, cmd: Cmd) {
        if let Some(m) = self.maintainer.lock().unwrap().as_ref() {
            m.send(cmd);
        }
    }
}

/// Authoritative DNS backed by one or more [`Zone`]s.
///
/// Answers carry the AA bit; names outside every zone are `REFUSED` (or, with
/// [`AuthoritativeZoneHandlerBuilder::decline_outside_zones`], declined so a
/// [`ChainHandler`](crate::server::ChainHandler) can pass them to a
/// forwarder). Implements RFC 1034 §4.3.2 lookup with CNAME chains,
/// wildcards (RFC 4592), empty non-terminals (RFC 8020), delegation
/// referrals, in-zone glue, RFC 2308 negative answers with the SOA, and
/// RFC 8482 minimal `ANY`.
///
/// Zone maintenance:
///
/// - RFC 2136 dynamic update on primaries, gated by
///   [`ZoneOptions::allow_update`]. Secondaries refuse updates.
/// - RFC 1996 NOTIFY: primaries send it after each change; a secondary
///   refreshes when its primary sends it.
/// - AXFR and IXFR (over stream transports) gated by
///   [`ZoneOptions::allow_transfer`].
/// - Secondaries also refresh on the SOA REFRESH/RETRY timers and stop
///   answering after EXPIRE, so they converge without NOTIFY.
///
/// The timer, NOTIFY and persistence work runs on a background thread that
/// exists between [`DnsService::start`](crate::server::DnsService::start) and
/// `stop`; without `start` the handler still answers, but does none of it.
#[derive(Clone)]
pub struct AuthoritativeZoneHandler {
    pub(super) inner: Arc<Inner>,
}

struct Pending {
    origin: String,
    zone: Option<Zone>,
    options: ZoneOptions,
    primary: Option<SocketAddr>,
}

/// Fluent configuration for [`AuthoritativeZoneHandler`].
pub struct AuthoritativeZoneHandlerBuilder {
    zones: Vec<Pending>,
    refuse_outside_zones: bool,
    minimal_any: Arc<dyn MinimalAnyPolicy>,
}

impl AuthoritativeZoneHandler {
    /// Start configuring a handler.
    pub fn builder() -> AuthoritativeZoneHandlerBuilder {
        AuthoritativeZoneHandlerBuilder {
            zones: Vec::new(),
            refuse_outside_zones: true,
            minimal_any: Arc::new(MinimalAnyEnabled),
        }
    }

    /// Origins served, most specific first.
    pub fn origins(&self) -> Vec<String> {
        self.inner.slots.iter().map(|s| s.origin.clone()).collect()
    }

    /// A copy of the named zone as it is now (`None` if it is not served, or
    /// a secondary that has not loaded it yet).
    pub fn zone_snapshot(&self, origin: &str) -> Option<Zone> {
        let origin = normalize_name(origin);
        self.slot_for_origin(&origin)?.zone.read().unwrap().clone()
    }

    fn slot_for(&self, name: &str) -> Option<&Arc<ZoneSlot>> {
        self.inner.slots.iter().find(|s| is_within(&s.origin, name))
    }

    fn slot_for_origin(&self, origin: &str) -> Option<&Arc<ZoneSlot>> {
        self.inner.slots.iter().find(|s| s.origin == origin)
    }
}

fn is_within(origin: &str, name: &str) -> bool {
    origin.is_empty()
        || name == origin
        || (name.len() > origin.len()
            && name.ends_with(origin)
            && name.as_bytes()[name.len() - origin.len() - 1] == b'.')
}

impl AuthoritativeZoneHandlerBuilder {
    /// Serve `zone` as a primary with closed default options.
    pub fn zone(self, zone: Zone) -> Self {
        self.zone_with(zone, ZoneOptions::default())
    }

    /// Serve `zone` as a primary with `options`.
    pub fn zone_with(mut self, zone: Zone, options: ZoneOptions) -> Self {
        self.zones.push(Pending {
            origin: zone.origin().to_string(),
            zone: Some(zone),
            options,
            primary: None,
        });
        self
    }

    /// Load a zone file and serve it as a primary (blocking read; do this
    /// before the runtime is busy). `origin` seeds `$ORIGIN` for files that
    /// use relative names before declaring one. `mode` decides whether
    /// updates are written back to `path`.
    pub fn zone_file(
        self,
        path: &std::path::Path,
        origin: Option<&str>,
        mode: ZoneFileMode,
        options: ZoneOptions,
    ) -> Result<Self, ZoneError> {
        let zone = Zone::from_zone_file(path, origin)?;
        Ok(self.zone_with(zone, options.persist(path, mode)))
    }

    /// Serve `origin` as a secondary of `primary`. The zone is empty (and
    /// answers `SERVFAIL`) until the first transfer completes, unless
    /// `options` names a persisted zone file that already exists, which is
    /// loaded and served while the primary is checked.
    pub fn secondary(mut self, origin: &str, primary: SocketAddr, options: ZoneOptions) -> Self {
        self.zones.push(Pending {
            origin: normalize_name(origin),
            zone: None,
            options,
            primary: Some(primary),
        });
        self
    }

    /// Whether a name outside every zone is answered `REFUSED` (the default,
    /// right for a standalone authoritative server) or declined so a chained
    /// handler can take it.
    pub fn decline_outside_zones(mut self, decline: bool) -> Self {
        self.refuse_outside_zones = !decline;
        self
    }

    /// RFC 8482: answer `ANY` with a single synthesised `HINFO` instead of
    /// the whole node (default on). Shorthand for
    /// [`minimal_any_policy`](Self::minimal_any_policy) with an always-on or
    /// always-off policy.
    pub fn minimal_any(self, enabled: bool) -> Self {
        if enabled {
            self.minimal_any_policy(MinimalAnyEnabled)
        } else {
            self.minimal_any_policy(MinimalAnyDisabled)
        }
    }

    /// Decide per question whether `ANY` is answered minimally.
    pub fn minimal_any_policy<P: MinimalAnyPolicy + 'static>(mut self, policy: P) -> Self {
        self.minimal_any = Arc::new(policy);
        self
    }

    /// Finish. Fails if no zone was added, an origin is served twice, or a
    /// secondary's persisted zone file exists but cannot be read.
    pub fn build(self) -> Result<AuthoritativeZoneHandler, ZoneError> {
        if self.zones.is_empty() {
            return Err(ZoneError::new("at least one zone is required"));
        }
        let mut slots: Vec<Arc<ZoneSlot>> = Vec::new();
        for mut p in self.zones {
            if slots.iter().any(|s| s.origin == p.origin) {
                return Err(ZoneError::new(format!("zone {:?} configured twice", p.origin)));
            }
            if p.zone.is_none() {
                if let Some((path, _)) = &p.options.persist {
                    if path.exists() {
                        p.zone = Some(Zone::from_zone_file(path, Some(&p.origin))?);
                    }
                }
            }
            slots.push(Arc::new(ZoneSlot {
                origin: p.origin,
                zone: RwLock::new(p.zone),
                expired: AtomicBool::new(false),
                options: p.options,
                primary: p.primary,
            }));
        }
        let labels = |s: &Arc<ZoneSlot>| {
            if s.origin.is_empty() {
                0
            } else {
                s.origin.matches('.').count() + 1
            }
        };
        slots.sort_by_key(|s| std::cmp::Reverse(labels(s)));
        Ok(AuthoritativeZoneHandler {
            inner: Arc::new(Inner {
                slots,
                refuse_outside_zones: self.refuse_outside_zones,
                minimal_any: self.minimal_any,
                maintainer: Mutex::new(None),
            }),
        })
    }
}

/// Response shell: QR, AA, echoed RD/opcode, no RA (not a recursive server).
fn authoritative(query: &DnsMessage, rcode: u16) -> DnsMessage {
    let mut r = query.response_template(rcode);
    r.flags &= !FLAG_RA;
    r.flags |= FLAG_AA;
    r
}

/// A response without the AA bit (errors, refusals).
fn plain(query: &DnsMessage, rcode: u16) -> DnsMessage {
    let mut r = query.response_template(rcode);
    r.flags &= !FLAG_RA;
    r
}

/// RFC 6891 §6.1.1: a response to a query with OPT carries an OPT.
fn add_edns(query: &DnsMessage, resp: &mut DnsMessage) {
    if query.additionals.iter().any(|r| r.rtype == Some(DnsType::Opt)) {
        resp.additionals
            .push(DnsResourceRecord::opt(OPT_UDP_PAYLOAD, query.has_do(), &[]));
    }
}

impl DnsQueryHandler for AuthoritativeZoneHandler {
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext<'_>) -> HandlerOutcome {
        let q = &query.questions[0];

        // RFC 6891 §6.1.3: an EDNS version we do not implement is BADVERS.
        if let Some(opt) = query.additionals.iter().find(|r| r.rtype == Some(DnsType::Opt)) {
            if opt.edns_version().unwrap_or(0) > 0 {
                let mut r = plain(query, RCODE_NOERROR);
                r.additionals
                    .push(DnsResourceRecord::opt(OPT_UDP_PAYLOAD, false, &[]).with_edns_rcode_version(
                        (RCODE_BADVERS >> 4) as u8,
                        0,
                    ));
                return HandlerOutcome::Respond(r);
            }
        }

        let qname = normalize_name(&q.name);
        let Some(slot) = self.slot_for(&qname) else {
            return if self.inner.refuse_outside_zones {
                let mut r = plain(query, RCODE_REFUSED);
                add_edns(query, &mut r);
                HandlerOutcome::Respond(r)
            } else {
                HandlerOutcome::Decline
            };
        };
        // Only class IN is served (or ANY, which matches it).
        if q.raw_qclass != DnsClass::In.value() && q.raw_qclass != DnsClass::Any.value() {
            let mut r = plain(query, RCODE_REFUSED);
            add_edns(query, &mut r);
            return HandlerOutcome::Respond(r);
        }

        let guard = slot.zone.read().unwrap();
        let zone = match guard.as_ref() {
            Some(z) if !slot.expired.load(Ordering::Relaxed) => z,
            // A secondary with no (or expired) data cannot answer.
            _ => {
                let mut r = plain(query, RCODE_SERVFAIL);
                add_edns(query, &mut r);
                return HandlerOutcome::Respond(r);
            }
        };

        if q.raw_qtype == TYPE_AXFR || q.raw_qtype == TYPE_IXFR {
            return transfer(slot, zone, query, ctx, &qname);
        }
        let minimal = q.raw_qtype == TYPE_ANY && self.inner.minimal_any.should_return_minimal_any(q);
        HandlerOutcome::Respond(answer(zone, query, &qname, q.raw_qtype, minimal))
    }

    fn handle_non_query_opcode(&self, query: &DnsMessage, ctx: &QueryContext<'_>) -> HandlerOutcome {
        match query.opcode() {
            OPCODE_NOTIFY => self.notify(query, ctx),
            OPCODE_UPDATE => self.update(query, ctx),
            _ => HandlerOutcome::Decline,
        }
    }

    fn start(&self, _rt: &Runtime) -> io::Result<()> {
        let mut m = self.inner.maintainer.lock().unwrap();
        if m.is_none() {
            *m = Some(Maintainer::spawn(Arc::clone(&self.inner))?);
        }
        Ok(())
    }

    fn stop(&self) {
        // Take it out first: joining while holding the lock would deadlock
        // a `signal` from the very thread being joined.
        let m = self.inner.maintainer.lock().unwrap().take();
        if let Some(m) = m {
            m.stop();
        }
    }
}

impl AuthoritativeZoneHandler {
    /// RFC 1996 NOTIFY: only meaningful to a secondary, from its primary.
    fn notify(&self, query: &DnsMessage, ctx: &QueryContext<'_>) -> HandlerOutcome {
        let Some(q) = query.questions.first() else {
            return HandlerOutcome::Respond(plain(query, RCODE_FORMERR));
        };
        let Some(slot) = self.slot_for_origin(&normalize_name(&q.name)) else {
            return HandlerOutcome::Respond(plain(query, RCODE_NOTAUTH));
        };
        match slot.primary {
            // Only the configured primary may trigger a transfer.
            Some(primary) if primary.ip() == ctx.peer.ip() => {
                self.inner.signal(Cmd::Notified(slot.origin.clone()));
                HandlerOutcome::Respond(authoritative(query, RCODE_NOERROR))
            }
            _ => HandlerOutcome::Respond(plain(query, RCODE_REFUSED)),
        }
    }

    /// RFC 2136 UPDATE.
    fn update(&self, query: &DnsMessage, ctx: &QueryContext<'_>) -> HandlerOutcome {
        let reply = |rcode| HandlerOutcome::Respond(plain(query, rcode));
        // §3.1: exactly one zone-section entry, of type SOA.
        let [zone_q] = query.questions.as_slice() else {
            return reply(RCODE_FORMERR);
        };
        if zone_q.raw_qtype != TYPE_SOA {
            return reply(RCODE_FORMERR);
        }
        let Some(slot) = self.slot_for_origin(&normalize_name(&zone_q.name)) else {
            return reply(RCODE_NOTAUTH);
        };
        // A secondary's data comes from its primary; a local change would be
        // overwritten (or worse, diverge), so it refuses (§3.1).
        if slot.primary.is_some() || !slot.options.allow_update.allows(ctx.peer.ip(), ctx.tsig_key) {
            return reply(RCODE_REFUSED);
        }
        let mut guard = slot.zone.write().unwrap();
        let Some(zone) = guard.as_mut() else {
            return reply(RCODE_SERVFAIL);
        };
        let result = update::apply(zone, query);
        drop(guard);
        if result.changed {
            self.inner.signal(Cmd::Changed(slot.origin.clone()));
        }
        reply(result.rcode)
    }
}

/// AXFR/IXFR (RFC 5936, RFC 1995).
fn transfer(
    slot: &ZoneSlot,
    zone: &Zone,
    query: &DnsMessage,
    ctx: &QueryContext<'_>,
    qname: &str,
) -> HandlerOutcome {
    let q = &query.questions[0];
    if qname != zone.origin() {
        return HandlerOutcome::Respond(plain(query, RCODE_REFUSED));
    }
    if !slot.options.allow_transfer.allows(ctx.peer.ip(), ctx.tsig_key) {
        return HandlerOutcome::Respond(plain(query, RCODE_REFUSED));
    }
    let messages = if q.raw_qtype == TYPE_IXFR {
        // RFC 1995 §3: the client's SOA is in the authority section.
        let have = query
            .authorities
            .iter()
            .find(|r| r.raw_type == TYPE_SOA)
            .and_then(|r| r.as_soa())
            .map(|s| s.serial);
        match have {
            Some(serial) => xfr::ixfr(query, zone, serial),
            None => xfr::axfr(query, zone),
        }
    } else {
        xfr::axfr(query, zone)
    };
    if !ctx.transport.supports_multi_message() {
        // RFC 5936 §4.2 wants AXFR on TCP. A one-message IXFR may go over
        // UDP (RFC 1995 §2); anything else is truncated so the client
        // retries over TCP.
        if q.raw_qtype == TYPE_IXFR && messages.len() == 1 {
            return HandlerOutcome::Respond(messages.into_iter().next().unwrap());
        }
        let mut r = authoritative(query, RCODE_NOERROR);
        r.flags |= FLAG_TC;
        return HandlerOutcome::Respond(r);
    }
    HandlerOutcome::Sequence(messages)
}

/// Build the response to an ordinary query against one zone.
pub(super) fn answer(zone: &Zone, query: &DnsMessage, qname: &str, qtype: u16, minimal_any: bool) -> DnsMessage {
    let mut answers: Vec<DnsResourceRecord> = Vec::new();
    let mut current = qname.to_string();
    let mut outcome = None;

    for _ in 0..=MAX_CNAME_CHAIN {
        match zone.lookup(&current, qtype) {
            Lookup::Answer { records, .. } => {
                let follow = records.len() == 1
                    && records[0].raw_type == TYPE_CNAME
                    && qtype != TYPE_CNAME
                    && qtype != TYPE_ANY;
                if !follow {
                    answers.extend(records);
                    outcome = Some(Lookup::NoData); // "done": positive unless answers is empty
                    break;
                }
                let target = cname_target(&records[0]);
                answers.extend(records);
                match target {
                    Some(t) if zone.is_within(&t) => current = t,
                    _ => {
                        outcome = Some(Lookup::NoData);
                        break;
                    }
                }
            }
            other => {
                outcome = Some(other);
                break;
            }
        }
    }
    let Some(outcome) = outcome else {
        // A CNAME loop or an over-long chain.
        let mut r = authoritative(query, RCODE_SERVFAIL);
        r.flags &= !FLAG_AA;
        add_edns(query, &mut r);
        return r;
    };

    let mut resp = match outcome {
        Lookup::Referral { ns } if answers.is_empty() => {
            let mut r = authoritative(query, RCODE_NOERROR);
            r.flags &= !FLAG_AA; // a referral is not authoritative data (RFC 1034 §4.3.2 step 3b)
            r.additionals = zone.glue_for(&ns);
            r.authorities = ns;
            r
        }
        Lookup::NxDomain => {
            let mut r = authoritative(query, RCODE_NXDOMAIN);
            r.answers = answers;
            r.authorities = vec![zone.negative_soa()];
            r
        }
        Lookup::NoData if answers.is_empty() => {
            let mut r = authoritative(query, RCODE_NOERROR);
            r.authorities = vec![zone.negative_soa()];
            r
        }
        // Positive (including a CNAME chain that ends outside the zone or
        // at a delegation: the client continues from the last target).
        _ => {
            let mut r = authoritative(query, RCODE_NOERROR);
            if minimal_any {
                answers = vec![minimal_any_hinfo(qname)];
            }
            let apex_ns_is_answer = answers.iter().any(|a| a.raw_type == 2 && a.name == zone.origin());
            if !apex_ns_is_answer {
                r.authorities = zone.ns_records();
            }
            let mut glue = zone.glue_for(&answers);
            for g in zone.glue_for(&r.authorities) {
                if !glue.iter().any(|x| super::model::same_rr(x, &g)) {
                    glue.push(g);
                }
            }
            r.additionals = glue;
            r.answers = answers;
            r
        }
    };
    add_edns(query, &mut resp);
    resp
}

/// RFC 8482 §4.2: `HINFO "RFC8482" ""`.
fn minimal_any_hinfo(name: &str) -> DnsResourceRecord {
    let mut rdata = vec![7];
    rdata.extend_from_slice(b"RFC8482");
    rdata.push(0);
    in_record(name, TYPE_HINFO, 3600, rdata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{ChainHandler, DnsService, FnHandler};
    use crate::wire::{DnsQuestion, DnsType};
    use std::net::{Ipv4Addr, SocketAddr};

    const ZONE: &str = "\
$TTL 300
@       IN SOA ns1 hostmaster 5 3600 900 604800 120
        IN NS  ns1
        IN MX  10 mail
ns1     IN A   192.0.2.53
mail    IN A   192.0.2.25
www     IN CNAME web
web     IN A   192.0.2.80
out     IN CNAME elsewhere.org.
loop1   IN CNAME loop2
loop2   IN CNAME loop1
*.wild  IN A   192.0.2.99
a.b     IN TXT \"deep\"
sub     IN NS  ns.sub
ns.sub  IN A   192.0.2.77
";

    fn peer() -> SocketAddr {
        "198.51.100.7:5353".parse().unwrap()
    }

    fn service() -> DnsService {
        let zone = Zone::from_zone_text(ZONE, Some("example.com")).unwrap();
        DnsService::with_handler(AuthoritativeZoneHandler::builder().zone(zone).build().unwrap())
    }

    fn ask(svc: &DnsService, name: &str, ty: DnsType) -> DnsMessage {
        let q = DnsMessage::query(9, DnsQuestion::in_class(name, ty), false);
        let resp = svc.process_query_sync(&q, peer());
        // Everything must survive the wire.
        DnsMessage::parse(&resp.serialize().unwrap()).unwrap()
    }

    #[test]
    fn positive_answer_is_authoritative_with_ns_and_glue() {
        let r = ask(&service(), "web.example.com", DnsType::A);
        assert!(r.flags & FLAG_AA != 0);
        assert_eq!(r.flags & FLAG_RA, 0, "not recursive");
        assert_eq!(r.rcode(), 0);
        assert_eq!(r.answers[0].as_a(), Some(Ipv4Addr::new(192, 0, 2, 80)));
        assert_eq!(r.authorities.len(), 1);
        assert_eq!(r.authorities[0].raw_type, 2);
        assert_eq!(r.additionals[0].name, "ns1.example.com", "glue for the NS in authority");
    }

    #[test]
    fn apex_soa_ns_and_mx_with_glue() {
        let svc = service();
        let soa = ask(&svc, "example.com", DnsType::Soa);
        assert_eq!(soa.answers[0].as_soa().unwrap().serial, 5);
        let ns = ask(&svc, "example.com", DnsType::Ns);
        assert_eq!(ns.answers.len(), 1);
        assert!(ns.authorities.is_empty(), "the NS set is already the answer");
        let mx = ask(&svc, "example.com", DnsType::Mx);
        assert!(mx.additionals.iter().any(|a| a.name == "mail.example.com"));
    }

    #[test]
    fn nxdomain_and_nodata_carry_the_soa_with_the_minimum_ttl() {
        let svc = service();
        let nx = ask(&svc, "nope.example.com", DnsType::A);
        assert_eq!(nx.rcode(), RCODE_NXDOMAIN);
        assert!(nx.flags & FLAG_AA != 0);
        assert!(nx.answers.is_empty());
        assert_eq!(nx.authorities[0].raw_type, 6);
        assert_eq!(nx.authorities[0].ttl, 120, "min(SOA TTL 300, MINIMUM 120), RFC 2308 §3");

        let nd = ask(&svc, "web.example.com", DnsType::Mx);
        assert_eq!(nd.rcode(), 0);
        assert!(nd.answers.is_empty());
        assert_eq!(nd.authorities[0].raw_type, 6);

        // Empty non-terminal: b.example.com has only a child.
        let ent = ask(&svc, "b.example.com", DnsType::A);
        assert_eq!(ent.rcode(), 0, "exists, so NODATA not NXDOMAIN");
    }

    #[test]
    fn cname_chains_are_followed_in_zone_and_stop_at_the_zone_edge() {
        let svc = service();
        let r = ask(&svc, "www.example.com", DnsType::A);
        assert_eq!(r.answers.len(), 2);
        assert_eq!(r.answers[0].raw_type, 5);
        assert_eq!(r.answers[1].as_a(), Some(Ipv4Addr::new(192, 0, 2, 80)));

        let out = ask(&svc, "out.example.com", DnsType::A);
        assert_eq!(out.answers.len(), 1, "target is out of zone; the client continues");
        assert_eq!(out.rcode(), 0);

        // Asking for the CNAME itself does not chase it.
        assert_eq!(ask(&svc, "www.example.com", DnsType::Cname).answers.len(), 1);
        // A loop is a server failure, not an endless answer.
        assert_eq!(ask(&svc, "loop1.example.com", DnsType::A).rcode(), RCODE_SERVFAIL);
    }

    #[test]
    fn wildcard_answers_carry_the_queried_name() {
        let r = ask(&service(), "anything.wild.example.com", DnsType::A);
        assert_eq!(r.answers[0].name, "anything.wild.example.com");
        assert!(r.flags & FLAG_AA != 0);
    }

    #[test]
    fn delegations_are_referrals_without_aa() {
        let r = ask(&service(), "host.sub.example.com", DnsType::A);
        assert_eq!(r.flags & FLAG_AA, 0);
        assert_eq!(r.rcode(), 0);
        assert!(r.answers.is_empty());
        assert_eq!(r.authorities[0].name, "sub.example.com");
        assert_eq!(r.additionals[0].name, "ns.sub.example.com");
    }

    #[test]
    fn any_gets_the_minimal_hinfo_answer() {
        let r = ask(&service(), "web.example.com", DnsType::Any);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].raw_type, TYPE_HINFO);
        // Off: the whole node.
        let zone = Zone::from_zone_text(ZONE, Some("example.com")).unwrap();
        let full = DnsService::with_handler(
            AuthoritativeZoneHandler::builder().zone(zone).minimal_any(false).build().unwrap(),
        );
        assert_eq!(ask(&full, "web.example.com", DnsType::Any).answers[0].raw_type, 1);
        // A per-question policy: minimal only outside `.internal.`.
        let zone = Zone::from_zone_text(ZONE, Some("example.com")).unwrap();
        let picky = DnsService::with_handler(
            AuthoritativeZoneHandler::builder()
                .zone(zone)
                .minimal_any_policy(|q: &DnsQuestion| q.name != "web.example.com")
                .build()
                .unwrap(),
        );
        assert_eq!(ask(&picky, "web.example.com", DnsType::Any).answers[0].raw_type, 1, "policy said no");
        assert_eq!(ask(&picky, "ns1.example.com", DnsType::Any).answers[0].raw_type, TYPE_HINFO, "policy said yes");
        // A name that does not exist is still NXDOMAIN.
        assert_eq!(ask(&service(), "no.example.com", DnsType::Any).rcode(), RCODE_NXDOMAIN);
    }

    #[test]
    fn outside_zones_are_refused_or_declined_for_chaining() {
        let svc = service();
        let r = ask(&svc, "example.org", DnsType::A);
        assert_eq!(r.rcode(), RCODE_REFUSED);
        assert_eq!(r.flags & FLAG_AA, 0);

        let zone = Zone::from_zone_text(ZONE, Some("example.com")).unwrap();
        let auth = AuthoritativeZoneHandler::builder().zone(zone).decline_outside_zones(true).build().unwrap();
        let fallback = FnHandler::new().on_query(|q| {
            let mut r = q.response_template(0);
            r.answers.push(DnsResourceRecord::a(&q.questions[0].name, 60, Ipv4Addr::new(203, 0, 113, 1)));
            Some(r)
        });
        let chained = DnsService::with_handler(ChainHandler::new().then(auth).then(fallback));
        assert_eq!(ask(&chained, "example.org", DnsType::A).answers.len(), 1, "forwarded");
        assert!(ask(&chained, "www.example.com", DnsType::A).flags & FLAG_AA != 0, "served locally");
    }

    #[test]
    fn non_in_classes_are_refused() {
        let svc = service();
        let mut q = DnsMessage::query(1, DnsQuestion::opaque("web.example.com", 1, 3), false);
        q.flags = 0;
        assert_eq!(svc.process_query_sync(&q, peer()).rcode(), RCODE_REFUSED);
    }

    #[test]
    fn the_most_specific_zone_wins() {
        let parent = Zone::from_zone_text("$TTL 60\n@ SOA n h 1 2 3 4 5\nx A 1.1.1.1\nsub A 2.2.2.2\n", Some("example.com")).unwrap();
        let child = Zone::from_zone_text("$TTL 60\n@ SOA n h 1 2 3 4 5\nx A 3.3.3.3\n", Some("sub.example.com")).unwrap();
        let svc = DnsService::with_handler(
            AuthoritativeZoneHandler::builder().zone(parent).zone(child).build().unwrap(),
        );
        assert_eq!(ask(&svc, "x.sub.example.com", DnsType::A).answers[0].as_a(), Some(Ipv4Addr::new(3, 3, 3, 3)));
        assert_eq!(ask(&svc, "x.example.com", DnsType::A).answers[0].as_a(), Some(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn edns_is_echoed_and_unknown_versions_are_badvers() {
        let svc = service();
        let mut q = DnsMessage::query(1, DnsQuestion::in_class("web.example.com", DnsType::A), false);
        q.additionals.push(DnsResourceRecord::opt(1232, true, &[]));
        let r = svc.process_query_sync(&q, peer());
        let opt = r.additionals.iter().find(|a| a.rtype == Some(DnsType::Opt)).expect("OPT echoed");
        assert!(opt.edns_do());

        let mut q = DnsMessage::query(2, DnsQuestion::in_class("web.example.com", DnsType::A), false);
        q.additionals.push(DnsResourceRecord::opt(1232, false, &[]).with_edns_rcode_version(0, 1));
        let r = svc.process_query_sync(&q, peer());
        let opt = r.additionals.iter().find(|a| a.rtype == Some(DnsType::Opt)).unwrap();
        assert_eq!(opt.edns_full_rcode(r.rcode() as u8), Some(RCODE_BADVERS));
        assert!(r.answers.is_empty());
    }

    #[test]
    fn builder_rejects_empty_and_duplicate_configuration() {
        assert!(AuthoritativeZoneHandler::builder().build().is_err());
        let z = || Zone::from_zone_text("@ SOA n h 1 2 3 4 5\n", Some("e.org")).unwrap();
        assert!(AuthoritativeZoneHandler::builder().zone(z()).zone(z()).build().is_err());
    }
}
