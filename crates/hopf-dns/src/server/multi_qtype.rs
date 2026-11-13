// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Server side of RFC 10029 (DNS Multiple QTYPEs).
//!
//! A query may carry an `MQTYPE-Query` EDNS option naming extra RRTYPEs for
//! its one question. When the service allows it ([`DnsService::set_max_multi_qtypes`]),
//! the shell asks the handler about each extra type as if it were a separate
//! query for the same name, with the same [`QueryContext`] (the same peer,
//! local address and TLS identity), merges what comes back into the single
//! response, and lists the types it answered in an `MQTYPE-Response` option.
//! A type the response does not list was not answered, and the client asks for
//! it on its own.
//!
//! The handler never sees the mechanism: each sub-query is an ordinary
//! single-question query without the option, so every handler (a table, a
//! forwarder, a chain) works unchanged, and one that answers later does so
//! for each sub-query on its own. The sub-queries are issued together and the
//! merged answer is delivered when the last has completed.
//!
//! [`DnsService::set_max_multi_qtypes`]: super::DnsService::set_max_multi_qtypes

use std::sync::{Arc, Mutex};

use super::handler::{DnsQueryCallback, DnsQueryHandler, HandlerOutcome, QueryContext};
use super::{DnsServerMetrics, MessageSink};
use crate::multi_qtype::{
    add_edns_option, encode_mqtype_response_option, find_mqtype_option, without_option, EDNS_OPTION_MQTYPE_QUERY,
};
use crate::wire::{DnsMessage, DnsQuestion, DnsType, RCODE_NOERROR, RCODE_NXDOMAIN};

/// The extra types `query` asks for, when the shell should merge them:
/// `Some` for a plain QUERY with one question that carries an MQTYPE-Query
/// option and a service that allows more than zero extra types, `None`
/// otherwise. The list leaves out the question's own type and the types that
/// cannot be answered as a question (`ANY`, `OPT`), repeats once, and stops at
/// `cap`; the client asks for whatever is missing on its own.
pub(super) fn requested_types(query: &DnsMessage, cap: usize) -> Option<Vec<DnsType>> {
    if cap == 0 || query.questions.len() != 1 {
        return None;
    }
    let primary = query.questions[0].qtype;
    let opt = query.additionals.iter().find(|rr| rr.rtype == Some(DnsType::Opt))?;
    let asked = find_mqtype_option(&opt.rdata, EDNS_OPTION_MQTYPE_QUERY)?;
    let mut out: Vec<DnsType> = Vec::new();
    for t in asked {
        if Some(t) != primary && !matches!(t, DnsType::Any | DnsType::Opt) && !out.contains(&t) {
            out.push(t);
        }
    }
    out.truncate(cap);
    Some(out)
}

/// What one sub-query came to.
type Slot = Option<HandlerOutcome>;

/// The sub-queries of one request, collected as they complete.
struct Gather {
    slots: Vec<Slot>,
    remaining: usize,
    finish: Option<Box<dyn FnOnce(Vec<Slot>) + Send>>,
}

/// Merge the answers for `extra` into `primary`, the messages that answer
/// `query`, and deliver the result to `done` with the MQTYPE-Response option.
///
/// Anything other than a single `NOERROR` or `NXDOMAIN` answer is delivered
/// as it is, with an empty MQTYPE-Response: the server supports the
/// mechanism, and covers nothing here.
pub(super) fn merge(
    handler: Arc<dyn DnsQueryHandler>,
    metrics: Arc<Mutex<DnsServerMetrics>>,
    query: Arc<DnsMessage>,
    ctx: QueryContext,
    extra: Vec<DnsType>,
    mut primary: Vec<DnsMessage>,
    done: MessageSink,
) {
    metrics.lock().unwrap().mqtype_queries += 1;
    let rcode = (primary.len() == 1).then(|| primary[0].rcode());
    match rcode {
        Some(RCODE_NXDOMAIN) => {
            // The name does not exist, so no type of it does: every extra
            // type is answered, with nothing.
            add_edns_option(&mut primary[0], &encode_mqtype_response_option(&extra));
            done(primary);
        }
        Some(RCODE_NOERROR) if !extra.is_empty() => {
            let mut sub_queries = Vec::with_capacity(extra.len());
            for t in &extra {
                let mut sub = (*query).clone();
                sub.questions = vec![DnsQuestion::new(
                    query.questions[0].name.clone(),
                    *t,
                    query.questions[0]
                        .qclass
                        .unwrap_or(crate::wire::DnsClass::In),
                )];
                if let Some(opt) = sub.additionals.iter_mut().find(|rr| rr.rtype == Some(DnsType::Opt)) {
                    opt.rdata = without_option(&opt.rdata, EDNS_OPTION_MQTYPE_QUERY);
                }
                sub_queries.push(sub);
            }
            metrics.lock().unwrap().mqtype_subqueries += sub_queries.len() as u64;
            let gather = Arc::new(Mutex::new(Gather {
                slots: vec![None; sub_queries.len()],
                remaining: sub_queries.len(),
                finish: Some(Box::new(move |slots| {
                    let mut response = primary.remove(0);
                    let mut covered = Vec::new();
                    for (t, slot) in extra.iter().zip(slots) {
                        // A decline, an error or a sequence leaves the type
                        // to the client's own query.
                        if let Some(HandlerOutcome::Respond(sub)) = slot {
                            if sub.rcode() == RCODE_NOERROR {
                                absorb(&mut response, sub);
                                covered.push(*t);
                            }
                        }
                    }
                    add_edns_option(&mut response, &encode_mqtype_response_option(&covered));
                    done(vec![response]);
                })),
            }));
            for (index, sub) in sub_queries.iter().enumerate() {
                let gather = Arc::clone(&gather);
                let callback = DnsQueryCallback::new(move |outcome| {
                    let finished = {
                        let mut g = gather.lock().unwrap();
                        g.slots[index] = Some(outcome);
                        g.remaining -= 1;
                        if g.remaining == 0 {
                            g.finish.take().map(|f| (f, std::mem::take(&mut g.slots)))
                        } else {
                            None
                        }
                    };
                    if let Some((finish, slots)) = finished {
                        finish(slots);
                    }
                });
                handler.handle_query(sub, &ctx, callback);
            }
        }
        _ => {
            if let Some(first) = primary.first_mut() {
                add_edns_option(first, &encode_mqtype_response_option(&[]));
            }
            done(primary);
        }
    }
}

/// Add `sub`'s records to `response`, leaving out any it already has and the
/// OPT record, which is the response's own.
fn absorb(response: &mut DnsMessage, sub: DnsMessage) {
    fn append(into: &mut Vec<crate::wire::DnsResourceRecord>, from: Vec<crate::wire::DnsResourceRecord>) {
        for rr in from {
            if rr.rtype != Some(DnsType::Opt) && !into.contains(&rr) {
                into.push(rr);
            }
        }
    }
    append(&mut response.answers, sub.answers);
    append(&mut response.authorities, sub.authorities);
    append(&mut response.additionals, sub.additionals);
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::{
        ChainHandler, ConnectionInfo, DnsService, DnsTransport, FnHandler,
    };
    use super::*;
    use crate::multi_qtype::{encode_mqtype_query_option, find_mqtype_option, EDNS_OPTION_MQTYPE_RESPONSE};
    use crate::wire::{DnsResourceRecord, RCODE_SERVFAIL};

    const PEER: &str = "198.51.100.7:5353";

    /// A query for `name`/`primary` asking for `extra` as well.
    fn mq_query(name: &str, primary: DnsType, extra: &[DnsType]) -> DnsMessage {
        let mut q = DnsMessage::query(7, DnsQuestion::in_class(name, primary), true);
        q.additionals.push(DnsResourceRecord::opt(1232, false, &encode_mqtype_query_option(extra)));
        q
    }

    /// Answers A, AAAA and TXT; declines everything else.
    fn zone() -> FnHandler {
        FnHandler::new().on_query(|q| {
            let name = &q.questions[0].name;
            let mut r = q.response_template(0);
            match q.questions[0].qtype? {
                DnsType::A => r.answers.push(DnsResourceRecord::a(name, 60, Ipv4Addr::new(192, 0, 2, 1))),
                DnsType::Aaaa => r.answers.push(DnsResourceRecord::aaaa(name, 60, Ipv6Addr::LOCALHOST)),
                DnsType::Txt => r.answers.push(DnsResourceRecord::txt(name, 60, "hello").unwrap()),
                _ => return None,
            }
            Some(r)
        })
    }

    fn enabled(handler: impl DnsQueryHandler + 'static, cap: usize) -> DnsService {
        let mut s = DnsService::with_handler(handler);
        s.set_max_multi_qtypes(cap);
        s
    }

    fn ask(service: &DnsService, q: &DnsMessage) -> DnsMessage {
        service.process_on(q, PEER.parse().unwrap(), DnsTransport::Udp).remove(0)
    }

    fn types_of(r: &DnsMessage) -> Vec<DnsType> {
        r.answers.iter().filter_map(|rr| rr.rtype).collect()
    }

    /// The types the response says it covers, or `None` with no option.
    fn covered(r: &DnsMessage) -> Option<Vec<DnsType>> {
        let opts: Vec<_> = r.additionals.iter().filter(|rr| rr.rtype == Some(DnsType::Opt)).collect();
        assert!(opts.len() <= 1, "one OPT record at most");
        opts.first().and_then(|o| find_mqtype_option(&o.rdata, EDNS_OPTION_MQTYPE_RESPONSE))
    }

    #[test]
    fn the_option_is_ignored_unless_the_service_allows_it() {
        let service = DnsService::with_handler(zone());
        let r = ask(&service, &mq_query("a.test", DnsType::A, &[DnsType::Aaaa]));
        assert_eq!(types_of(&r), vec![DnsType::A], "only the primary question is answered");
        assert_eq!(covered(&r), None, "no MQTYPE-Response, so the client learns it is unsupported");
        assert_eq!(service.metrics().mqtype_queries, 0);
    }

    #[test]
    fn extra_types_are_merged_and_listed_in_the_response() {
        let service = enabled(zone(), 4);
        let r = ask(&service, &mq_query("a.test", DnsType::A, &[DnsType::Aaaa, DnsType::Txt]));
        assert_eq!(r.rcode(), 0);
        assert_eq!(types_of(&r), vec![DnsType::A, DnsType::Aaaa, DnsType::Txt]);
        assert_eq!(covered(&r), Some(vec![DnsType::Aaaa, DnsType::Txt]));
        let m = service.metrics();
        assert_eq!((m.mqtype_queries, m.mqtype_subqueries), (1, 2));
    }

    #[test]
    fn a_query_without_the_option_is_untouched() {
        let service = enabled(zone(), 4);
        let q = DnsMessage::query(8, DnsQuestion::in_class("a.test", DnsType::A), true);
        let r = ask(&service, &q);
        assert_eq!(types_of(&r), vec![DnsType::A]);
        assert_eq!(covered(&r), None);
    }

    #[test]
    fn a_type_the_handler_declines_is_not_covered() {
        let service = enabled(zone(), 4);
        // The zone has no MX: declined, so the client must ask for it itself.
        let r = ask(&service, &mq_query("a.test", DnsType::A, &[DnsType::Mx, DnsType::Aaaa]));
        assert_eq!(types_of(&r), vec![DnsType::A, DnsType::Aaaa]);
        assert_eq!(covered(&r), Some(vec![DnsType::Aaaa]));
    }

    #[test]
    fn the_cap_bounds_the_work_and_the_client_asks_for_the_rest() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let inner = zone();
        let counted = FnHandler::new().on_query_ctx(move |q, ctx| {
            counter.fetch_add(1, Ordering::SeqCst);
            crate::server::SyncDnsQueryHandler::resolve(&inner, q, ctx)
        });
        let service = enabled(counted, 2);
        let r = ask(&service, &mq_query("a.test", DnsType::A, &[DnsType::Aaaa, DnsType::Txt, DnsType::Mx]));
        assert_eq!(calls.load(Ordering::SeqCst), 3, "the primary and two extras");
        assert_eq!(covered(&r), Some(vec![DnsType::Aaaa, DnsType::Txt]));
    }

    #[test]
    fn the_primary_type_any_and_repeats_are_not_asked_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let inner = zone();
        let counted = FnHandler::new().on_query_ctx(move |q, ctx| {
            counter.fetch_add(1, Ordering::SeqCst);
            crate::server::SyncDnsQueryHandler::resolve(&inner, q, ctx)
        });
        let service = enabled(counted, 8);
        let extra = [DnsType::A, DnsType::Any, DnsType::Aaaa, DnsType::Aaaa];
        let r = ask(&service, &mq_query("a.test", DnsType::A, &extra));
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the primary, and AAAA once");
        assert_eq!(covered(&r), Some(vec![DnsType::Aaaa]));
    }

    #[test]
    fn each_sub_query_is_a_plain_single_question_with_the_same_context() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let handler = FnHandler::new().on_query_ctx(move |q, ctx| {
            sink.lock().unwrap().push((
                q.questions.len(),
                q.questions[0].qtype,
                ctx.local(),
                ctx.sni().map(str::to_owned),
                q.additionals
                    .iter()
                    .find(|rr| rr.rtype == Some(DnsType::Opt))
                    .and_then(|o| find_mqtype_option(&o.rdata, EDNS_OPTION_MQTYPE_QUERY)),
            ));
            Some(q.response_template(0))
        });
        let service = enabled(handler, 4);
        let security = hopf_core::SecurityInfo::secure(None, None, None).with_sni(Some("dns.example".into()));
        let conn = ConnectionInfo::new(PEER.parse().unwrap())
            .with_local(Some("192.0.2.53:853".parse().unwrap()))
            .with_security(Some(Arc::new(security)));
        service.process_on_with(&mq_query("a.test", DnsType::A, &[DnsType::Aaaa, DnsType::Txt]), &conn, DnsTransport::Dot);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        for (questions, _, local, sni, _) in seen.iter() {
            assert_eq!(*questions, 1);
            assert_eq!(*local, Some("192.0.2.53:853".parse::<SocketAddr>().unwrap()));
            assert_eq!(sni.as_deref(), Some("dns.example"));
        }
        // Only the primary (first) sees the option; the sub-queries do not.
        assert!(seen[0].4.is_some());
        assert!(seen[1..].iter().all(|s| s.4.is_none()));
        let qtypes: Vec<_> = seen.iter().map(|s| s.1).collect();
        assert_eq!(qtypes, vec![Some(DnsType::A), Some(DnsType::Aaaa), Some(DnsType::Txt)]);
    }

    #[test]
    fn a_nonexistent_name_covers_every_extra_type_without_asking_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let handler = FnHandler::new().on_query(move |q| {
            counter.fetch_add(1, Ordering::SeqCst);
            Some(q.response_template(crate::wire::RCODE_NXDOMAIN))
        });
        let service = enabled(handler, 4);
        let r = ask(&service, &mq_query("gone.test", DnsType::A, &[DnsType::Aaaa, DnsType::Txt]));
        assert_eq!(r.rcode(), crate::wire::RCODE_NXDOMAIN);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(covered(&r), Some(vec![DnsType::Aaaa, DnsType::Txt]));
    }

    #[test]
    fn a_failed_primary_is_delivered_as_it_is_and_covers_nothing() {
        let handler = FnHandler::new().on_query(|q| Some(q.response_template(RCODE_SERVFAIL)));
        let service = enabled(handler, 4);
        let r = ask(&service, &mq_query("a.test", DnsType::A, &[DnsType::Aaaa]));
        assert_eq!(r.rcode(), RCODE_SERVFAIL);
        assert_eq!(covered(&r), Some(vec![]));
    }

    #[test]
    fn handlers_that_answer_late_are_merged_when_the_last_one_completes() {
        struct Late;
        impl DnsQueryHandler for Late {
            fn handle_query(&self, q: &DnsMessage, _ctx: &QueryContext, callback: DnsQueryCallback) {
                let mut r = q.response_template(0);
                let name = q.questions[0].name.clone();
                let qtype = q.questions[0].qtype;
                // Later types answer sooner, so completion order differs
                // from the order the types were asked in.
                let delay = if qtype == Some(DnsType::Aaaa) { 60 } else { 10 };
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(delay));
                    match qtype {
                        Some(DnsType::Aaaa) => r.answers.push(DnsResourceRecord::aaaa(&name, 60, Ipv6Addr::LOCALHOST)),
                        _ => r.answers.push(DnsResourceRecord::a(&name, 60, Ipv4Addr::new(192, 0, 2, 1))),
                    }
                    callback.respond(r);
                });
            }
        }
        let service = enabled(Late, 4);
        let r = ask(&service, &mq_query("a.test", DnsType::A, &[DnsType::Aaaa, DnsType::Txt]));
        assert_eq!(covered(&r), Some(vec![DnsType::Aaaa, DnsType::Txt]));
        assert!(types_of(&r).contains(&DnsType::Aaaa), "the slowest answer is in the merged response");
    }

    #[test]
    fn a_chain_declining_a_sub_query_leaves_it_to_the_client() {
        let service = enabled(ChainHandler::new().then(zone()), 4);
        let r = ask(&service, &mq_query("a.test", DnsType::A, &[DnsType::Mx]));
        assert_eq!(covered(&r), Some(vec![]));
    }

    #[test]
    fn the_response_option_and_the_cookie_share_one_opt_record() {
        let service = enabled(zone(), 4);
        let peer: SocketAddr = PEER.parse().unwrap();
        let client_cookie = [3u8; 8];
        let server_cookie = service.cookies().generate_server_cookie(&client_cookie, &super::super::ip_octets(peer.ip()));
        let mut q = mq_query("a.test", DnsType::A, &[DnsType::Aaaa]);
        let mut cookie = Vec::new();
        cookie.extend_from_slice(&crate::cookie::EDNS_OPTION_COOKIE.to_be_bytes());
        cookie.extend_from_slice(&((client_cookie.len() + server_cookie.len()) as u16).to_be_bytes());
        cookie.extend_from_slice(&client_cookie);
        cookie.extend_from_slice(&server_cookie);
        q.additionals[0].rdata.extend_from_slice(&cookie);
        let r = ask(&service, &q);
        assert_eq!(covered(&r), Some(vec![DnsType::Aaaa]));
        let opt = r.additionals.iter().find(|rr| rr.rtype == Some(DnsType::Opt)).unwrap();
        assert!(
            opt.rdata.windows(2).any(|w| w == crate::cookie::EDNS_OPTION_COOKIE.to_be_bytes()),
            "the cookie option is in the same OPT record"
        );
    }
}
