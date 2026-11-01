// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! End-to-end tests of the LDAP client endpoint: the test plays the server
//! over an in-process [`Peer`], writing BER-encoded LDAP messages and
//! decoding the requests the client sends back.

use std::io;
use std::sync::{Arc, Mutex};

use hopf_core::testing::Peer;
use hopf_core::SecurityInfo;

use crate::{Asn1Element, Asn1Type, BerDecoder, BerEncoder};

use super::endpoint::LdapEndpoint;
use super::session::{LdapSession, LdapShared, ReadyCallback};
use super::types::{
    APP_ABANDON_REQUEST, APP_BIND_REQUEST, APP_BIND_RESPONSE, APP_EXTENDED_RESPONSE,
    APP_SEARCH_REQUEST, APP_SEARCH_RESULT_DONE, APP_SEARCH_RESULT_ENTRY,
    APP_SEARCH_RESULT_REFERENCE, APP_UNBIND_REQUEST,
};
use super::{
    BindResult, LdapError, LdapResultCode, SearchDone, SearchEntry, SearchRequest, SearchScope,
    SyncMode, SyncRequest,
};

type Ready = Arc<Mutex<Option<Result<LdapSession, LdapError>>>>;

fn endpoint(implicit_tls: bool) -> (Peer<LdapEndpoint>, Ready, Arc<LdapShared>) {
    let shared = Arc::new(LdapShared::new(None));
    let ready = Ready::default();
    let r = Arc::clone(&ready);
    let on_ready: Arc<Mutex<Option<ReadyCallback>>> =
        Arc::new(Mutex::new(Some(Box::new(move |s| *r.lock().unwrap() = Some(s)))));
    let ep = LdapEndpoint::new(Arc::clone(&shared), on_ready, implicit_tls);
    (Peer::connect(ep, |_| false), ready, shared)
}

/// A connected client and its session.
fn connected() -> (Peer<LdapEndpoint>, LdapSession) {
    let (peer, ready, _shared) = endpoint(false);
    let session = ready.lock().unwrap().take().expect("ready").expect("a session");
    (peer, session)
}

// Server side -------------------------------------------------------------

pub(crate) fn message(id: i32, op: impl FnOnce(&mut BerEncoder)) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_integer_i32(id);
    op(&mut enc);
    enc.end_sequence();
    enc.into_bytes()
}

pub(crate) fn result_body(enc: &mut BerEncoder, code: i32, matched: &str, diagnostic: &str, referrals: &[&str]) {
    enc.write_enumerated(code);
    enc.write_octet_string_str(matched);
    enc.write_octet_string_str(diagnostic);
    if !referrals.is_empty() {
        enc.begin_context(3, true);
        for url in referrals {
            enc.write_octet_string_str(url);
        }
        enc.end_context();
    }
}

pub(crate) fn bind_response(id: i32, code: i32, matched: &str, diagnostic: &str, referrals: &[&str]) -> Vec<u8> {
    message(id, |enc| {
        enc.begin_application(APP_BIND_RESPONSE, true);
        result_body(enc, code, matched, diagnostic, referrals);
        enc.end_application();
    })
}

pub(crate) fn entry(id: i32, dn: &str, attrs: &[(&str, &[&str])]) -> Vec<u8> {
    message(id, |enc| {
        enc.begin_application(APP_SEARCH_RESULT_ENTRY, true);
        enc.write_octet_string_str(dn);
        enc.begin_sequence();
        for (name, values) in attrs {
            enc.begin_sequence();
            enc.write_octet_string_str(name);
            enc.begin_set();
            for v in *values {
                enc.write_octet_string_str(v);
            }
            enc.end_set();
            enc.end_sequence();
        }
        enc.end_sequence();
        enc.end_application();
    })
}

pub(crate) fn done(id: i32, code: i32, referrals: &[&str]) -> Vec<u8> {
    message(id, |enc| {
        enc.begin_application(APP_SEARCH_RESULT_DONE, true);
        result_body(enc, code, "", "", referrals);
        enc.end_application();
    })
}

pub(crate) fn reference(id: i32, urls: &[&str]) -> Vec<u8> {
    message(id, |enc| {
        enc.begin_application(APP_SEARCH_RESULT_REFERENCE, true);
        for u in urls {
            enc.write_octet_string_str(u);
        }
        enc.end_application();
    })
}

pub(crate) fn extended_response(id: i32, code: i32) -> Vec<u8> {
    message(id, |enc| {
        enc.begin_application(APP_EXTENDED_RESPONSE, true);
        result_body(enc, code, "", "", &[]);
        enc.end_application();
    })
}

// Client side -------------------------------------------------------------

/// What the client has sent: a session writes through its connection handle,
/// so the peer is run first to deliver it.
fn sent(peer: &mut Peer<LdapEndpoint>) -> Vec<u8> {
    peer.pump();
    peer.take_bytes()
}

fn requests(bytes: &[u8]) -> Vec<Asn1Element> {
    let mut dec = BerDecoder::new();
    dec.receive(bytes).unwrap();
    let mut out = Vec::new();
    while let Some(e) = dec.next() {
        out.push(e);
    }
    out
}

fn only(bytes: &[u8]) -> Asn1Element {
    let mut all = requests(bytes);
    assert_eq!(all.len(), 1, "expected exactly one request");
    all.remove(0)
}

fn id_of(m: &Asn1Element) -> i32 {
    m.child(0).as_i32().unwrap()
}

fn op_tag(m: &Asn1Element) -> u8 {
    Asn1Type::tag_number(m.child(1).tag())
}

// Collectors --------------------------------------------------------------

type Bound = Arc<Mutex<Option<Result<BindResult, LdapError>>>>;

fn bind(session: &LdapSession, dn: &str, password: &str) -> Bound {
    let out = Bound::default();
    let o = Arc::clone(&out);
    session.bind(dn, password, move |r| *o.lock().unwrap() = Some(r));
    out
}

#[derive(Default)]
struct Found {
    entries: Vec<SearchEntry>,
    done: Option<Result<SearchDone, LdapError>>,
}

type Search = Arc<Mutex<Found>>;

fn search(session: &LdapSession, request: SearchRequest) -> Search {
    let out = Search::default();
    let (e, d) = (Arc::clone(&out), Arc::clone(&out));
    session.search(
        request,
        move |entry| e.lock().unwrap().entries.push(entry),
        move |r| d.lock().unwrap().done = Some(r),
    );
    out
}

fn req(base: &str, filter: &str) -> SearchRequest {
    SearchRequest::new(base, filter)
}

// Tests -------------------------------------------------------------------

#[test]
fn the_session_is_ready_as_soon_as_the_connection_is() {
    let (_peer, ready, _shared) = endpoint(false);
    assert!(ready.lock().unwrap().as_ref().unwrap().is_ok());
}

#[test]
fn an_ldaps_session_is_ready_when_the_handshake_is_done() {
    let (mut peer, ready, _shared) = endpoint(true);
    assert!(ready.lock().unwrap().is_none());
    peer.secure(&SecurityInfo::plaintext());
    assert!(ready.lock().unwrap().as_ref().unwrap().is_ok());
}

#[test]
fn a_bind_sends_version_dn_and_simple_password() {
    let (mut peer, session) = connected();
    bind(&session, "cn=admin,dc=example", "secret");
    let m = only(&sent(&mut peer));
    assert_eq!((id_of(&m), op_tag(&m)), (1, APP_BIND_REQUEST));
    let op = m.child(1);
    assert_eq!(op.child(0).as_i32().unwrap(), 3);
    assert_eq!(op.child(1).as_string().as_deref(), Some("cn=admin,dc=example"));
    assert_eq!(op.child(2).as_string().as_deref(), Some("secret"));
}

#[test]
fn an_anonymous_bind_has_an_empty_name_and_password() {
    let (mut peer, session) = connected();
    session.bind_anonymous(|_| {});
    let m = only(&sent(&mut peer));
    let op = m.child(1);
    assert_eq!(op.child(1).as_string().unwrap_or_default(), "");
    assert_eq!(op.child(2).as_string().unwrap_or_default(), "");
}

#[test]
fn a_successful_bind_is_reported() {
    let (mut peer, session) = connected();
    let result = bind(&session, "cn=a", "pw");
    peer.run_bytes(&bind_response(1, 0, "", "", &[]));
    let r = result.lock().unwrap().take().unwrap().unwrap();
    assert!(r.success);
    assert_eq!(r.result_code, LdapResultCode::Success);
    assert!(r.matched_dn.is_none() && r.diagnostic.is_none() && r.referrals.is_empty());
}

#[test]
fn a_refused_bind_carries_the_servers_reasons() {
    let (mut peer, session) = connected();
    let result = bind(&session, "cn=a", "wrong");
    peer.run_bytes(&bind_response(1, 49, "dc=example", "bad password", &["ldap://other/"]));
    let r = result.lock().unwrap().take().unwrap().unwrap();
    assert!(!r.success);
    assert_eq!(r.result_code, LdapResultCode::InvalidCredentials);
    assert_eq!(r.matched_dn.as_deref(), Some("dc=example"));
    assert_eq!(r.diagnostic.as_deref(), Some("bad password"));
    assert_eq!(r.referrals, ["ldap://other/"]);
}

#[test]
fn message_ids_count_up_and_answers_find_their_request() {
    let (mut peer, session) = connected();
    let first = bind(&session, "cn=a", "1");
    let second = bind(&session, "cn=b", "2");
    let ids: Vec<i32> = requests(&sent(&mut peer)).iter().map(id_of).collect();
    assert_eq!(ids, [1, 2]);
    // Answered out of order.
    peer.run_bytes(&bind_response(2, 49, "", "", &[]));
    assert!(first.lock().unwrap().is_none());
    assert!(!second.lock().unwrap().take().unwrap().unwrap().success);
    peer.run_bytes(&bind_response(1, 0, "", "", &[]));
    assert!(first.lock().unwrap().take().unwrap().unwrap().success);
}

#[test]
fn a_search_request_names_base_scope_filter_and_attributes() {
    let (mut peer, session) = connected();
    let mut request = req("dc=example,dc=com", "(&(objectClass=person)(uid=alice))");
    request.scope = SearchScope::SingleLevel;
    request.attributes = vec!["cn".into(), "mail".into()];
    request.size_limit = 50;
    request.time_limit = 9;
    request.types_only = true;
    search(&session, request);
    let m = only(&sent(&mut peer));
    assert_eq!(op_tag(&m), APP_SEARCH_REQUEST);
    let op = m.child(1);
    assert_eq!(op.child(0).as_string().as_deref(), Some("dc=example,dc=com"));
    assert_eq!(op.child(1).as_i32().unwrap(), SearchScope::SingleLevel.value());
    assert_eq!(op.child(3).as_i32().unwrap(), 50);
    assert_eq!(op.child(4).as_i32().unwrap(), 9);
    assert!(op.child(5).as_bool().unwrap());
    assert_eq!(op.child(6).tag(), Asn1Type::context_tag(0, true), "an AND filter");
    let attrs = op.child(7);
    assert_eq!(attrs.child_count(), 2);
    assert_eq!(attrs.child(1).as_string().as_deref(), Some("mail"));
}

#[test]
fn search_entries_arrive_one_at_a_time_then_the_end() {
    let (mut peer, session) = connected();
    let found = search(&session, req("dc=example", "(uid=*)"));
    peer.run_bytes(&entry(1, "uid=a,dc=example", &[("cn", &["Alice"]), ("mail", &["a@x", "a@y"])]));
    assert_eq!(found.lock().unwrap().entries.len(), 1);
    assert!(found.lock().unwrap().done.is_none());
    peer.run_bytes(&entry(1, "uid=b,dc=example", &[("cn", &["Bob"])]));
    peer.run_bytes(&done(1, 0, &[]));
    let f = found.lock().unwrap();
    assert_eq!(f.entries[0].dn, "uid=a,dc=example");
    assert_eq!(f.entries[0].attributes["mail"], [b"a@x".to_vec(), b"a@y".to_vec()]);
    assert_eq!(f.entries[1].attributes["cn"], [b"Bob".to_vec()]);
    assert_eq!(f.done.as_ref().unwrap().as_ref().unwrap().result_code, LdapResultCode::Success);
}

#[test]
fn an_entry_with_no_attributes_or_values_is_kept() {
    let (mut peer, session) = connected();
    let found = search(&session, req("", "(x=y)"));
    peer.run_bytes(&entry(1, "cn=bare", &[]));
    peer.run_bytes(&entry(1, "cn=empty", &[("description", &[])]));
    let f = found.lock().unwrap();
    assert!(f.entries[0].attributes.is_empty());
    assert!(f.entries[1].attributes["description"].is_empty());
}

#[test]
fn soft_result_codes_are_delivered_as_a_normal_end() {
    for code in [4, 10, 32] {
        let (mut peer, session) = connected();
        let found = search(&session, req("dc=example", "(x=y)"));
        peer.run_bytes(&done(1, code, &[]));
        let d = found.lock().unwrap().done.take().unwrap();
        assert_eq!(d.unwrap().result_code.code(), code);
    }
}

#[test]
fn a_failed_search_is_an_error() {
    let (mut peer, session) = connected();
    let found = search(&session, req("dc=example", "(x=y)"));
    peer.run_bytes(&done(1, 50, &[]));
    let result = found.lock().unwrap().done.take().unwrap();
    match result {
        Err(LdapError::SearchFailed(c)) => assert_eq!(c.code(), 50),
        other => panic!("{other:?}"),
    }
}

#[test]
fn referrals_from_references_and_the_result_are_collected() {
    let (mut peer, session) = connected();
    let found = search(&session, req("dc=example", "(x=y)"));
    peer.run_bytes(&reference(1, &["ldap://a/dc=x", "ldap://b/dc=y"]));
    peer.run_bytes(&reference(1, &["ldap://c/dc=z"]));
    peer.run_bytes(&done(1, 10, &["ldap://d/"]));
    let d = found.lock().unwrap().done.take().unwrap().unwrap();
    assert_eq!(d.referrals, ["ldap://a/dc=x", "ldap://b/dc=y", "ldap://c/dc=z", "ldap://d/"]);
}

#[test]
fn concurrent_searches_keep_their_entries_apart() {
    let (mut peer, session) = connected();
    let one = search(&session, req("dc=one", "(x=y)"));
    let two = search(&session, req("dc=two", "(x=y)"));
    let mut wire = entry(2, "cn=two-a", &[]);
    wire.extend(entry(1, "cn=one-a", &[]));
    wire.extend(entry(2, "cn=two-b", &[]));
    wire.extend(done(1, 0, &[]));
    wire.extend(done(2, 0, &[]));
    peer.run_bytes(&wire);
    let dns = |s: &Search| -> Vec<String> {
        s.lock().unwrap().entries.iter().map(|e| e.dn.clone()).collect()
    };
    assert_eq!(dns(&one), ["cn=one-a"]);
    assert_eq!(dns(&two), ["cn=two-a", "cn=two-b"]);
    assert!(one.lock().unwrap().done.is_some() && two.lock().unwrap().done.is_some());
}

#[test]
fn answers_to_unknown_message_ids_are_ignored() {
    let (mut peer, session) = connected();
    let found = search(&session, req("dc=example", "(x=y)"));
    let mut wire = entry(9, "cn=stray", &[]);
    wire.extend(done(9, 0, &[]));
    wire.extend(bind_response(9, 0, "", "", &[]));
    wire.extend(extended_response(9, 0));
    peer.run_bytes(&wire);
    assert!(found.lock().unwrap().entries.is_empty());
    assert!(found.lock().unwrap().done.is_none());
    assert!(!peer.is_closed());
}

#[test]
fn a_whole_exchange_is_the_same_at_every_chunking() {
    let mut wire = bind_response(1, 0, "", "", &[]);
    wire.extend(entry(2, "uid=a", &[("cn", &["Alice"])]));
    wire.extend(reference(2, &["ldap://r/"]));
    wire.extend(done(2, 0, &["ldap://s/"]));
    let run = |chunk: usize| {
        let (mut peer, session) = connected();
        let bound = bind(&session, "cn=a", "pw");
        let found = search(&session, req("dc=example", "(uid=a)"));
        peer.run_chunked_bytes(&wire, chunk);
        let success = bound.lock().unwrap().as_ref().unwrap().as_ref().unwrap().success;
        let f = found.lock().unwrap();
        (
            success,
            f.entries.iter().map(|e| e.dn.clone()).collect::<Vec<_>>(),
            f.done.as_ref().unwrap().as_ref().unwrap().referrals.clone(),
        )
    };
    let whole = run(wire.len());
    assert_eq!(
        whole,
        (true, vec!["uid=a".to_string()], vec!["ldap://r/".to_string(), "ldap://s/".to_string()])
    );
    for chunk in [1, 2, 3, 7] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

#[test]
fn unbind_sends_the_request_closes_and_fails_what_is_pending() {
    let (mut peer, session) = connected();
    let bound = bind(&session, "cn=a", "pw");
    sent(&mut peer);
    session.unbind();
    let m = only(&sent(&mut peer));
    assert_eq!(op_tag(&m), APP_UNBIND_REQUEST);
    assert!(peer.is_closed());
    assert!(session.is_closed());
    assert!(matches!(bound.lock().unwrap().take().unwrap(), Err(LdapError::Closed)));
    // A second unbind does nothing.
    session.unbind();
    assert!(sent(&mut peer).is_empty());
}

#[test]
fn operations_on_a_closed_session_fail_at_once() {
    let (_peer, session) = connected();
    session.unbind();
    let bound = bind(&session, "cn=a", "pw");
    assert!(matches!(bound.lock().unwrap().take().unwrap(), Err(LdapError::Closed)));
    let found = search(&session, req("", "(x=y)"));
    assert!(matches!(found.lock().unwrap().done.take().unwrap(), Err(LdapError::Closed)));
}

#[test]
fn starttls_without_a_connector_is_a_configuration_error() {
    let (_peer, session) = connected();
    assert!(!session.starttls_configured());
    let out = Arc::new(Mutex::new(None));
    let o = Arc::clone(&out);
    session.start_tls(move |r| *o.lock().unwrap() = Some(r));
    assert!(matches!(out.lock().unwrap().take().unwrap(), Err(LdapError::Config(_))));
}

#[test]
fn losing_the_connection_fails_what_is_pending() {
    let (mut peer, session) = connected();
    let bound = bind(&session, "cn=a", "pw");
    let found = search(&session, req("", "(x=y)"));
    peer.disconnect();
    assert!(matches!(bound.lock().unwrap().take().unwrap(), Err(LdapError::Closed)));
    assert!(matches!(found.lock().unwrap().done.take().unwrap(), Err(LdapError::Closed)));
    assert!(session.is_closed());
}

#[test]
fn a_timeout_is_reported_as_one() {
    let (mut peer, session) = connected();
    let bound = bind(&session, "cn=a", "pw");
    peer.fail(&io::Error::new(io::ErrorKind::TimedOut, "slow"));
    assert!(matches!(bound.lock().unwrap().take().unwrap(), Err(LdapError::Timeout)));
    assert!(peer.is_closed());
}

#[test]
fn an_io_error_keeps_its_kind() {
    let (mut peer, session) = connected();
    let bound = bind(&session, "cn=a", "pw");
    peer.fail(&io::Error::new(io::ErrorKind::ConnectionReset, "reset"));
    let result = bound.lock().unwrap().take().unwrap();
    match result {
        Err(LdapError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_notice_of_disconnection_ends_the_session() {
    let (mut peer, session) = connected();
    let bound = bind(&session, "cn=a", "pw");
    peer.run_bytes(&extended_response(0, 52));
    assert!(matches!(bound.lock().unwrap().take().unwrap(), Err(LdapError::Protocol(_))));
    assert!(session.is_closed());
}

#[test]
fn a_message_that_is_not_a_sequence_closes_the_connection() {
    let (mut peer, session) = connected();
    let bound = bind(&session, "cn=a", "pw");
    let mut enc = BerEncoder::new();
    enc.write_integer_i32(5);
    peer.run_bytes(&enc.into_bytes());
    assert!(peer.is_closed());
    assert!(matches!(bound.lock().unwrap().take().unwrap(), Err(LdapError::Asn1(_))));
}

#[test]
fn a_message_with_no_operation_closes_the_connection() {
    let (mut peer, _session) = connected();
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_integer_i32(1);
    enc.end_sequence();
    peer.run_bytes(&enc.into_bytes());
    assert!(peer.is_closed());
}

#[test]
fn a_truncated_result_closes_the_connection() {
    let (mut peer, session) = connected();
    bind(&session, "cn=a", "pw");
    let wire = message(1, |enc| {
        enc.begin_application(APP_BIND_RESPONSE, true);
        enc.write_enumerated(0);
        enc.end_application();
    });
    peer.run_bytes(&wire);
    assert!(peer.is_closed());
}

#[test]
fn a_search_entry_with_too_few_parts_closes_the_connection() {
    let (mut peer, session) = connected();
    search(&session, req("", "(x=y)"));
    let wire = message(1, |enc| {
        enc.begin_application(APP_SEARCH_RESULT_ENTRY, true);
        enc.write_octet_string_str("cn=x");
        enc.end_application();
    });
    peer.run_bytes(&wire);
    assert!(peer.is_closed());
}

#[test]
fn messages_after_a_failure_are_not_processed() {
    let (mut peer, session) = connected();
    let bound = bind(&session, "cn=a", "pw");
    let mut wire = message(1, |enc| {
        enc.begin_application(APP_BIND_RESPONSE, true);
        enc.write_enumerated(0);
        enc.end_application();
    });
    wire.extend(bind_response(1, 0, "", "", &[]));
    peer.run_bytes(&wire);
    assert!(matches!(bound.lock().unwrap().take().unwrap(), Err(LdapError::Asn1(_))));
}

#[test]
fn sync_cancel_abandons_the_operation() {
    let (mut peer, session) = connected();
    let out = Arc::new(Mutex::new(None));
    let o = Arc::clone(&out);
    let handle = session.sync(
        req("dc=example", "(objectClass=*)"),
        SyncRequest::new(SyncMode::RefreshOnly),
        |_| {},
        move |r| *o.lock().unwrap() = Some(r),
    );
    sent(&mut peer);
    handle.cancel();
    let m = only(&sent(&mut peer));
    assert_eq!(op_tag(&m), APP_ABANDON_REQUEST);
    assert!(matches!(out.lock().unwrap().take().unwrap(), Err(LdapError::Cancelled)));
    // Cancelling again is harmless.
    handle.cancel();
    assert!(sent(&mut peer).is_empty());
}
