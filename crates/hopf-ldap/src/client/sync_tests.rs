// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! End-to-end tests of RFC 4533 content synchronisation: the real client, on
//! the real reactor, against a scripted in-tree LDAP peer that implements the
//! server side of the protocol over a small in-memory directory.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hopf_core::Runtime;

use crate::{Asn1Element, Asn1Type, BerDecoder, BerEncoder};

use super::control::{decode_controls, encode_controls, Control};
use super::sync::{
    OID_SYNC_DONE_CONTROL, OID_SYNC_INFO_MESSAGE, OID_SYNC_REQUEST_CONTROL, OID_SYNC_STATE_CONTROL,
};
use super::{
    LdapClient, LdapClientConfig, LdapError, LdapResultCode, LdapSession, SearchRequest, SyncDone,
    SyncEvent, SyncMode, SyncReplica, SyncRequest,
};

const WAIT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// The in-memory directory the peer serves.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Item {
    uuid: [u8; 16],
    dn: String,
    mail: String,
    version: u64,
}

#[derive(Default)]
struct Directory {
    items: Vec<Item>,
    /// (uuid, version at which it was deleted)
    tombstones: Vec<([u8; 16], u64)>,
    version: u64,
    /// Cookies older than this cannot be served incrementally.
    compacted_before: u64,
}

impl Directory {
    fn add(&mut self, n: u8, dn: &str, mail: &str) {
        self.version += 1;
        self.items.push(Item { uuid: [n; 16], dn: dn.into(), mail: mail.into(), version: self.version });
    }

    fn modify(&mut self, n: u8, mail: &str) {
        self.version += 1;
        let v = self.version;
        let it = self.items.iter_mut().find(|i| i.uuid == [n; 16]).unwrap();
        it.mail = mail.into();
        it.version = v;
    }

    fn rename(&mut self, n: u8, dn: &str) {
        self.version += 1;
        let v = self.version;
        let it = self.items.iter_mut().find(|i| i.uuid == [n; 16]).unwrap();
        it.dn = dn.into();
        it.version = v;
    }

    fn delete(&mut self, n: u8) {
        self.version += 1;
        self.items.retain(|i| i.uuid != [n; 16]);
        self.tombstones.push(([n; 16], self.version));
    }

    fn cookie(&self) -> Vec<u8> {
        format!("csn={}", self.version).into_bytes()
    }

    /// What the directory holds, as a client would compare it: DN -> mail.
    fn snapshot(&self) -> Vec<(String, String)> {
        let mut v: Vec<_> = self.items.iter().map(|i| (i.dn.clone(), i.mail.clone())).collect();
        v.sort();
        v
    }
}

fn parse_cookie(c: &[u8]) -> Option<u64> {
    std::str::from_utf8(c).ok()?.strip_prefix("csn=")?.parse().ok()
}

/// How the peer reports a refresh (RFC 4533 section 3.3.2 allows all three).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Style {
    /// Changed entries, then explicit deletes; done with refreshDeletes TRUE.
    DeletePhase,
    /// Changed entries, then the unchanged ones as present; done with
    /// refreshDeletes FALSE (absent entries are implicitly gone).
    PresentPhase,
    /// A present phase, refreshPresent(refreshDone FALSE), then a delete
    /// phase; done with refreshDeletes TRUE.
    PresentThenDelete,
}

/// A change the test pushes to the peer during the persist stage.
enum Push {
    Add(u8, &'static str, &'static str),
    Modify(u8, &'static str),
    Delete(u8),
    /// Delete several via one syncIdSet.
    DeleteMany(Vec<u8>),
    NewCookie,
    /// Send a syncInfo the client cannot parse.
    GarbageInfo,
}

struct Peer {
    addr: SocketAddr,
    dir: Arc<Mutex<Directory>>,
    /// Sync requests the peer received: (mode, cookie, critical).
    requests: Receiver<(i32, Option<Vec<u8>>, bool)>,
    push: Sender<Push>,
    /// Message IDs the client abandoned.
    abandoned: Receiver<i32>,
}

// ---------------------------------------------------------------------------
// Wire helpers (server side).
// ---------------------------------------------------------------------------

fn state_control(state: i32, uuid: &[u8; 16], cookie: Option<&[u8]>) -> Control {
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_enumerated(state);
    enc.write_octet_string(uuid);
    if let Some(c) = cookie {
        enc.write_octet_string(c);
    }
    enc.end_sequence();
    Control { oid: OID_SYNC_STATE_CONTROL.into(), critical: false, value: Some(enc.into_bytes()) }
}

fn done_control(cookie: Option<&[u8]>, refresh_deletes: bool) -> Control {
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    if let Some(c) = cookie {
        enc.write_octet_string(c);
    }
    if refresh_deletes {
        enc.write_boolean(true);
    }
    enc.end_sequence();
    Control { oid: OID_SYNC_DONE_CONTROL.into(), critical: false, value: Some(enc.into_bytes()) }
}

fn entry_msg(id: i32, dn: &str, mail: Option<&str>, control: Control) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_integer_i32(id);
    enc.begin_application(4, true);
    enc.write_octet_string_str(dn);
    enc.begin_sequence();
    if let Some(m) = mail {
        enc.begin_sequence();
        enc.write_octet_string_str("mail");
        enc.begin_set();
        enc.write_octet_string_str(m);
        enc.end_set();
        enc.end_sequence();
    }
    enc.end_sequence();
    enc.end_application();
    encode_controls(&mut enc, &[control]);
    enc.end_sequence();
    enc.into_bytes()
}

fn result_msg(app: u8, id: i32, code: i32, controls: &[Control]) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_integer_i32(id);
    enc.begin_application(app, true);
    enc.write_enumerated(code);
    enc.write_octet_string_str("");
    enc.write_octet_string_str("");
    enc.end_application();
    encode_controls(&mut enc, controls);
    enc.end_sequence();
    enc.into_bytes()
}

fn info_msg(id: i32, value: &[u8]) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_integer_i32(id);
    enc.begin_application(25, true);
    enc.write_context(0, OID_SYNC_INFO_MESSAGE.as_bytes());
    enc.write_context(1, value);
    enc.end_application();
    enc.end_sequence();
    enc.into_bytes()
}

fn info_new_cookie(cookie: &[u8]) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.write_context(0, cookie);
    enc.into_bytes()
}

fn info_refresh(choice: u8, cookie: Option<&[u8]>, done: bool) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.begin_context(choice, true);
    if let Some(c) = cookie {
        enc.write_octet_string(c);
    }
    if !done {
        enc.write_boolean(false); // refreshDone DEFAULT TRUE
    }
    enc.end_context();
    enc.into_bytes()
}

fn info_id_set(cookie: Option<&[u8]>, refresh_deletes: bool, uuids: &[[u8; 16]]) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.begin_context(3, true);
    if let Some(c) = cookie {
        enc.write_octet_string(c);
    }
    if refresh_deletes {
        enc.write_boolean(true);
    }
    enc.begin_set();
    for u in uuids {
        enc.write_octet_string(u);
    }
    enc.end_set();
    enc.end_context();
    enc.into_bytes()
}

/// Read one complete LDAPMessage off `stream` (blocking up to `timeout`).
fn read_message(stream: &mut TcpStream, dec: &mut BerDecoder, timeout: Duration) -> Option<Asn1Element> {
    stream.set_read_timeout(Some(timeout)).ok()?;
    loop {
        if let Some(m) = dec.next() {
            return Some(m);
        }
        let mut buf = [0u8; 4096];
        match stream.read(&mut buf) {
            Ok(0) => return None,
            Ok(n) => dec.receive(&buf[..n]).ok()?,
            Err(_) => return None,
        }
    }
}

/// `(mode, cookie, critical)` from a Sync Request Control.
fn parse_sync_request(controls: &[Control]) -> Option<(i32, Option<Vec<u8>>, bool)> {
    let c = controls.iter().find(|c| c.oid == OID_SYNC_REQUEST_CONTROL)?;
    let mut dec = BerDecoder::new();
    dec.receive(c.value.as_ref()?).ok()?;
    let seq = dec.next()?;
    let mode = seq.child(0).as_i32().ok()?;
    let mut cookie = None;
    for i in 1..seq.child_count() {
        if seq.child(i).tag() == Asn1Type::OCTET_STRING {
            cookie = seq.child(i).as_octet_string().map(<[u8]>::to_vec);
        }
    }
    Some((mode, cookie, c.critical))
}

// ---------------------------------------------------------------------------
// The peer.
// ---------------------------------------------------------------------------

fn start_peer(dir: Directory, style: Style) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = Arc::new(Mutex::new(dir));
    let style = Arc::new(Mutex::new(style));
    let (req_tx, requests) = channel();
    let (push, push_rx) = channel::<Push>();
    let (ab_tx, abandoned) = channel();
    let dir2 = Arc::clone(&dir);
    let style2 = Arc::clone(&style);
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let mut dec = BerDecoder::new();
        let mut persist: Option<i32> = None; // message id of the persistent search
        loop {
            // While persisting, poll the push channel between short reads so a
            // change reaches the client promptly and an Abandon is noticed.
            let timeout = if persist.is_some() { Duration::from_millis(20) } else { Duration::from_secs(10) };
            let msg = read_message(&mut stream, &mut dec, timeout);
            if let Some(id) = persist {
                while let Ok(p) = push_rx.try_recv() {
                    push_change(&mut stream, &dir2, id, p);
                }
            }
            let Some(msg) = msg else {
                if persist.is_none() {
                    return; // closed, or idle too long
                }
                continue;
            };
            let id = msg.child(0).as_i32().unwrap();
            let op = msg.child(1);
            match Asn1Type::tag_number(op.tag()) {
                0 => {
                    stream.write_all(&result_msg(1, id, 0, &[])).unwrap();
                }
                2 => return, // unbind
                16 => {
                    let target = op.as_i32().unwrap();
                    let _ = ab_tx.send(target);
                    if persist == Some(target) {
                        persist = None;
                    }
                }
                3 => {
                    let controls = decode_controls(&msg).unwrap();
                    match parse_sync_request(&controls) {
                        Some((mode, cookie, critical)) => {
                            let _ = req_tx.send((mode, cookie.clone(), critical));
                            let style = *style2.lock().unwrap();
                            let ended = serve_sync(&mut stream, &dir2, id, mode, cookie, style);
                            if !ended {
                                persist = Some(id);
                            }
                        }
                        None => {
                            // An ordinary search: one entry, then done.
                            stream.write_all(&entry_msg(id, "cn=plain", Some("p@example.test"), Control::new("9.9.9"))).unwrap();
                            stream.write_all(&result_msg(5, id, 0, &[])).unwrap();
                        }
                    }
                }
                _ => {}
            }
        }
    });
    Peer { addr, dir, requests, push, abandoned }
}

/// Answer a sync search. Returns `true` if the search ended (refreshOnly or
/// an error), `false` if it stays open (refreshAndPersist).
fn serve_sync(
    stream: &mut TcpStream,
    dir: &Arc<Mutex<Directory>>,
    id: i32,
    mode: i32,
    cookie: Option<Vec<u8>>,
    style: Style,
) -> bool {
    let d = dir.lock().unwrap();
    let since = cookie.as_deref().and_then(parse_cookie);
    let persist = mode == 3;

    // A cookie the server has compacted past, or does not recognise:
    // e-syncRefreshRequired (4096), no incremental path.
    if cookie.is_some() && since.is_none_or(|v| v < d.compacted_before) {
        stream.write_all(&result_msg(5, id, 4096, &[])).unwrap();
        return true;
    }
    let now = d.cookie();
    let mut out: Vec<Vec<u8>> = Vec::new();

    match since {
        // Initial content: everything as add, no cookies on the entries.
        None => {
            for it in &d.items {
                out.push(entry_msg(id, &it.dn, Some(&it.mail), state_control(1, &it.uuid, None)));
            }
            if persist {
                out.push(info_msg(id, &info_refresh(1, Some(&now), true)));
            } else {
                out.push(result_msg(5, id, 0, &[done_control(Some(&now), false)]));
            }
        }
        Some(since) => {
            let changed: Vec<&Item> = d.items.iter().filter(|i| i.version > since).collect();
            let unchanged: Vec<&Item> = d.items.iter().filter(|i| i.version <= since).collect();
            let deleted: Vec<[u8; 16]> = d.tombstones.iter().filter(|(_, v)| *v > since).map(|(u, _)| *u).collect();
            for it in &changed {
                out.push(entry_msg(id, &it.dn, Some(&it.mail), state_control(1, &it.uuid, None)));
            }
            let present_phase = |out: &mut Vec<Vec<u8>>| {
                // Unchanged entries: empty entries with state present (their
                // current DN), coalesced into a syncIdSet when there are many.
                let (few, many) = unchanged.split_at(unchanged.len().min(1));
                for it in few {
                    out.push(entry_msg(id, &it.dn, None, state_control(0, &it.uuid, None)));
                }
                if !many.is_empty() {
                    let uuids: Vec<[u8; 16]> = many.iter().map(|i| i.uuid).collect();
                    out.push(info_msg(id, &info_id_set(None, false, &uuids)));
                }
            };
            let delete_phase = |out: &mut Vec<Vec<u8>>| {
                for u in &deleted {
                    out.push(entry_msg(id, "", None, state_control(3, u, None)));
                }
            };
            match style {
                Style::DeletePhase => {
                    delete_phase(&mut out);
                    if persist {
                        out.push(info_msg(id, &info_refresh(1, Some(&now), true)));
                    } else {
                        out.push(result_msg(5, id, 0, &[done_control(Some(&now), true)]));
                    }
                }
                Style::PresentPhase => {
                    present_phase(&mut out);
                    if persist {
                        out.push(info_msg(id, &info_refresh(2, Some(&now), true)));
                    } else {
                        out.push(result_msg(5, id, 0, &[done_control(Some(&now), false)]));
                    }
                }
                Style::PresentThenDelete => {
                    present_phase(&mut out);
                    out.push(info_msg(id, &info_refresh(2, None, false)));
                    delete_phase(&mut out);
                    if persist {
                        out.push(info_msg(id, &info_refresh(1, Some(&now), true)));
                    } else {
                        out.push(result_msg(5, id, 0, &[done_control(Some(&now), true)]));
                    }
                }
            }
        }
    }
    for m in out {
        stream.write_all(&m).unwrap();
    }
    !persist
}

fn push_change(stream: &mut TcpStream, dir: &Arc<Mutex<Directory>>, id: i32, p: Push) {
    let mut d = dir.lock().unwrap();
    match p {
        Push::Add(n, dn, mail) => {
            d.add(n, dn, mail);
            let cookie = d.cookie();
            stream.write_all(&entry_msg(id, dn, Some(mail), state_control(1, &[n; 16], Some(&cookie)))).unwrap();
        }
        Push::Modify(n, mail) => {
            d.modify(n, mail);
            let it = d.items.iter().find(|i| i.uuid == [n; 16]).unwrap().clone();
            let cookie = d.cookie();
            stream.write_all(&entry_msg(id, &it.dn, Some(mail), state_control(2, &it.uuid, Some(&cookie)))).unwrap();
        }
        Push::Delete(n) => {
            d.delete(n);
            let cookie = d.cookie();
            stream.write_all(&entry_msg(id, "", None, state_control(3, &[n; 16], Some(&cookie)))).unwrap();
        }
        Push::DeleteMany(ns) => {
            for n in &ns {
                d.delete(*n);
            }
            let cookie = d.cookie();
            let uuids: Vec<[u8; 16]> = ns.iter().map(|n| [*n; 16]).collect();
            stream.write_all(&info_msg(id, &info_id_set(Some(&cookie), true, &uuids))).unwrap();
        }
        Push::NewCookie => {
            let cookie = d.cookie();
            stream.write_all(&info_msg(id, &info_new_cookie(&cookie))).unwrap();
        }
        Push::GarbageInfo => {
            stream.write_all(&info_msg(id, &[0xa9, 0x00])).unwrap(); // [9]: not a syncInfoValue choice
        }
    }
}

// ---------------------------------------------------------------------------
// The client side of the tests.
// ---------------------------------------------------------------------------

fn connect(rt: &Runtime, addr: SocketAddr) -> LdapSession {
    let (tx, rx) = channel();
    LdapClient::connect(rt, LdapClientConfig::from_addr(addr), move |r| {
        let _ = tx.send(r);
    })
    .unwrap();
    rx.recv_timeout(WAIT).expect("connected").expect("session")
}

enum Msg {
    Event(SyncEvent),
    Done(Result<SyncDone, LdapError>),
}

struct Sync {
    rx: Receiver<Msg>,
    handle: super::SyncHandle,
}

fn start_sync(session: &LdapSession, mode: SyncMode, replica: &mut SyncReplica) -> Sync {
    replica.begin_refresh();
    let mut req = SyncRequest::new(mode);
    if let Some(c) = replica.cookie() {
        req = req.with_cookie(c.to_vec());
    }
    let (tx, rx) = channel();
    let tx2 = tx.clone();
    let handle = session.sync(
        SearchRequest::new("dc=example,dc=test", "(objectClass=*)"),
        req,
        move |e| {
            let _ = tx.send(Msg::Event(e));
        },
        move |d| {
            let _ = tx2.send(Msg::Done(d));
        },
    );
    Sync { rx, handle }
}

/// Apply events to `replica` until the operation ends; returns the result.
fn run_to_done(sync: &Sync, replica: &mut SyncReplica) -> Result<SyncDone, LdapError> {
    loop {
        match sync.rx.recv_timeout(WAIT).expect("sync stalled") {
            Msg::Event(e) => replica.apply(&e).expect("event applies"),
            Msg::Done(Ok(done)) => {
                replica.finish(&done);
                return Ok(done);
            }
            Msg::Done(Err(e)) => return Err(e),
        }
    }
}

/// Apply events until `pred` says the persist stage has reached the state we
/// are waiting for.
fn run_until(sync: &Sync, replica: &mut SyncReplica, mut pred: impl FnMut(&SyncReplica) -> bool) {
    while !pred(replica) {
        match sync.rx.recv_timeout(WAIT).expect("persist stalled") {
            Msg::Event(e) => replica.apply(&e).expect("event applies"),
            Msg::Done(d) => panic!("sync ended unexpectedly: {d:?}"),
        }
    }
}

fn replica_snapshot(r: &SyncReplica) -> Vec<(String, String)> {
    let mut v: Vec<_> = r
        .entries()
        .values()
        .map(|e| (e.dn.clone(), String::from_utf8_lossy(&e.attributes.get("mail").map(|v| v[0].clone()).unwrap_or_default()).into_owned()))
        .collect();
    v.sort();
    v
}

fn seed() -> Directory {
    let mut d = Directory::default();
    d.add(1, "cn=alice,dc=example,dc=test", "alice@example.test");
    d.add(2, "cn=bob,dc=example,dc=test", "bob@example.test");
    d.add(3, "cn=carol,dc=example,dc=test", "carol@example.test");
    d
}

fn expect_request(peer: &Peer) -> (i32, Option<Vec<u8>>, bool) {
    peer.requests.recv_timeout(WAIT).expect("the peer saw a sync request")
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Acceptance: a refresh-only sync completes and the client can resume with
/// the stored cookie; the peer sees the cookie in the second request.
#[test]
fn refresh_only_completes_and_resumes_from_the_stored_cookie() {
    let rt = Runtime::start(Default::default()).unwrap();
    let peer = start_peer(seed(), Style::DeletePhase);
    let session = connect(&rt, peer.addr);
    let mut replica = SyncReplica::new();

    // Initial poll: no cookie, refreshOnly, critical.
    let s = start_sync(&session, SyncMode::RefreshOnly, &mut replica);
    let done = run_to_done(&s, &mut replica).unwrap();
    assert_eq!(done.result_code, LdapResultCode::Success);
    assert_eq!(expect_request(&peer), (1, None, true));
    assert_eq!(replica_snapshot(&replica), peer.dir.lock().unwrap().snapshot());
    assert_eq!(replica.cookie(), Some(&b"csn=3"[..]));

    // The directory changes while the client is away.
    {
        let mut d = peer.dir.lock().unwrap();
        d.modify(2, "bob.new@example.test");
        d.delete(3);
        d.add(4, "cn=dave,dc=example,dc=test", "dave@example.test");
    }
    let s = start_sync(&session, SyncMode::RefreshOnly, &mut replica);
    let done = run_to_done(&s, &mut replica).unwrap();
    assert_eq!(done.cookie.as_deref(), Some(&b"csn=6"[..]));
    // The second request resumed from the first poll's cookie.
    assert_eq!(expect_request(&peer), (1, Some(b"csn=3".to_vec()), true));
    assert_eq!(replica_snapshot(&replica), peer.dir.lock().unwrap().snapshot());
    assert_eq!(replica.cookie(), Some(&b"csn=6"[..]));
    rt.shutdown();
}

/// Present/delete updates are applied correctly whichever way the server
/// reports a refresh (RFC 4533 section 3.3.2): the replica converges on the
/// directory - modifications, a rename, a deletion and an addition - in every
/// style, and entries the update did not mention survive.
#[test]
fn every_refresh_style_converges_the_replica() {
    for style in [Style::DeletePhase, Style::PresentPhase, Style::PresentThenDelete] {
        let rt = Runtime::start(Default::default()).unwrap();
        let peer = start_peer(seed(), style);
        let session = connect(&rt, peer.addr);
        let mut replica = SyncReplica::new();
        let s = start_sync(&session, SyncMode::RefreshOnly, &mut replica);
        run_to_done(&s, &mut replica).unwrap();

        {
            let mut d = peer.dir.lock().unwrap();
            d.modify(1, "alice.new@example.test");
            d.rename(2, "cn=robert,dc=example,dc=test");
            d.delete(3);
            d.add(4, "cn=dave,dc=example,dc=test", "dave@example.test");
        }
        let s = start_sync(&session, SyncMode::RefreshOnly, &mut replica);
        run_to_done(&s, &mut replica).unwrap();
        assert_eq!(replica_snapshot(&replica), peer.dir.lock().unwrap().snapshot(), "{style:?}");

        // A further update with nothing changed leaves it as it was.
        let before = replica_snapshot(&replica);
        let s = start_sync(&session, SyncMode::RefreshOnly, &mut replica);
        run_to_done(&s, &mut replica).unwrap();
        assert_eq!(replica_snapshot(&replica), before, "{style:?} no-op poll");
        rt.shutdown();
    }
}

/// e-syncRefreshRequired: the peer cannot serve the cookie incrementally. The
/// result is delivered (not an error), the replica resets, and an initial
/// reload converges.
#[test]
fn refresh_required_makes_the_replica_reload() {
    let rt = Runtime::start(Default::default()).unwrap();
    let peer = start_peer(seed(), Style::DeletePhase);
    let session = connect(&rt, peer.addr);
    let mut replica = SyncReplica::new();
    let s = start_sync(&session, SyncMode::RefreshOnly, &mut replica);
    run_to_done(&s, &mut replica).unwrap();

    {
        let mut d = peer.dir.lock().unwrap();
        d.delete(2);
        d.compacted_before = d.version + 1; // history gone
    }
    let s = start_sync(&session, SyncMode::RefreshOnly, &mut replica);
    let done = run_to_done(&s, &mut replica).unwrap();
    assert_eq!(done.result_code, LdapResultCode::SyncRefreshRequired);
    assert!(replica.is_empty() && replica.cookie().is_none(), "reset");

    // Reload from scratch.
    let s = start_sync(&session, SyncMode::RefreshOnly, &mut replica);
    let done = run_to_done(&s, &mut replica).unwrap();
    assert_eq!(done.result_code, LdapResultCode::Success);
    assert_eq!(replica_snapshot(&replica), peer.dir.lock().unwrap().snapshot());
    rt.shutdown();
}

/// refreshAndPersist: the refresh stage ends with a Sync Info marker rather
/// than a SearchResultDone, then changes stream in as they happen, and the
/// client ends the operation with an Abandon.
#[test]
fn refresh_and_persist_streams_changes_until_cancelled() {
    let rt = Runtime::start(Default::default()).unwrap();
    let peer = start_peer(seed(), Style::DeletePhase);
    let session = connect(&rt, peer.addr);
    let mut replica = SyncReplica::new();

    let s = start_sync(&session, SyncMode::RefreshAndPersist, &mut replica);
    assert_eq!(expect_request(&peer).0, 3, "refreshAndPersist");
    // Refresh stage: three adds then the refreshDelete(done) marker, which
    // carries the cookie.
    run_until(&s, &mut replica, |r| r.len() == 3 && r.cookie().is_some());
    assert_eq!(replica.cookie(), Some(&b"csn=3"[..]));

    // Persist stage.
    peer.push.send(Push::Add(4, "cn=dave,dc=example,dc=test", "dave@example.test")).unwrap();
    peer.push.send(Push::Modify(1, "alice.new@example.test")).unwrap();
    peer.push.send(Push::Delete(2)).unwrap();
    run_until(&s, &mut replica, |r| replica_snapshot(r) == peer.dir.lock().unwrap().snapshot() && r.cookie() == Some(&b"csn=6"[..]));

    // A bulk delete via syncIdSet, and a bare new cookie.
    peer.push.send(Push::DeleteMany(vec![3, 4])).unwrap();
    run_until(&s, &mut replica, |r| r.is_empty() || r.len() == 1);
    peer.push.send(Push::NewCookie).unwrap();
    run_until(&s, &mut replica, |r| r.cookie() == Some(&b"csn=8"[..]));
    assert_eq!(replica_snapshot(&replica), peer.dir.lock().unwrap().snapshot());

    // Cancel: an Abandon for the sync search goes out, on_done reports it.
    s.handle.cancel();
    assert_eq!(peer.abandoned.recv_timeout(WAIT).expect("abandon"), s.handle.message_id());
    loop {
        match s.rx.recv_timeout(WAIT).expect("on_done") {
            Msg::Event(_) => {}
            Msg::Done(d) => {
                assert!(matches!(d, Err(LdapError::Cancelled)), "{d:?}");
                break;
            }
        }
    }
    // Cancelling again is a no-op.
    s.handle.cancel();
    rt.shutdown();
}

/// No blocking: a persistent sync is just an outstanding search. Ordinary
/// operations on the same connection - and pushed changes - proceed while it
/// is open, on the same reactor.
#[test]
fn a_persistent_sync_does_not_block_other_operations() {
    let rt = Runtime::start(Default::default()).unwrap();
    let peer = start_peer(seed(), Style::DeletePhase);
    let session = connect(&rt, peer.addr);
    let mut replica = SyncReplica::new();
    let s = start_sync(&session, SyncMode::RefreshAndPersist, &mut replica);
    run_until(&s, &mut replica, |r| r.len() == 3 && r.cookie().is_some());

    // An ordinary search while the sync is open.
    let (tx, rx) = channel();
    let tx2 = tx.clone();
    session.search(
        SearchRequest::new("dc=example,dc=test", "(cn=plain)"),
        move |e| {
            let _ = tx.send(Some(e.dn));
        },
        move |d| {
            let _ = tx2.send(d.ok().map(|_| String::new()).filter(|_| false));
        },
    );
    assert_eq!(rx.recv_timeout(WAIT).unwrap().as_deref(), Some("cn=plain"));

    // And the sync is still live.
    peer.push.send(Push::Add(9, "cn=late,dc=example,dc=test", "late@example.test")).unwrap();
    run_until(&s, &mut replica, |r| r.len() == 4);
    s.handle.cancel();
    rt.shutdown();
}

/// A server error ends the operation with the failing code; e-syncRefreshRequired
/// is the only non-success code delivered as `Ok`.
#[test]
fn a_failed_sync_reports_the_result_code() {
    // Ask a peer for sync with a cookie it rejects as unparseable garbage: it
    // answers refresh-required; a control the peer does not understand would
    // be unavailableCriticalExtension (12), which we script directly.
    let rt = Runtime::start(Default::default()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut dec = BerDecoder::new();
        let msg = read_message(&mut stream, &mut dec, Duration::from_secs(10)).unwrap();
        let id = msg.child(0).as_i32().unwrap();
        stream.write_all(&result_msg(5, id, 12, &[])).unwrap();
        thread::sleep(Duration::from_millis(200));
    });
    let session = connect(&rt, addr);
    let mut replica = SyncReplica::new();
    let s = start_sync(&session, SyncMode::RefreshOnly, &mut replica);
    let r = run_to_done(&s, &mut replica);
    assert!(matches!(r, Err(LdapError::SearchFailed(c)) if c.code() == 12), "{r:?}");
    rt.shutdown();
}

/// A Sync Info Message the client cannot parse ends the operation (a replica
/// must not silently miss a cookie or phase boundary) and abandons the search.
#[test]
fn an_unreadable_sync_info_message_ends_the_operation() {
    let rt = Runtime::start(Default::default()).unwrap();
    let peer = start_peer(seed(), Style::DeletePhase);
    let session = connect(&rt, peer.addr);
    let mut replica = SyncReplica::new();
    let s = start_sync(&session, SyncMode::RefreshAndPersist, &mut replica);
    run_until(&s, &mut replica, |r| r.len() == 3 && r.cookie().is_some());
    peer.push.send(Push::GarbageInfo).unwrap();
    let result = loop {
        match s.rx.recv_timeout(WAIT).expect("ended") {
            Msg::Event(e) => replica.apply(&e).unwrap(),
            Msg::Done(d) => break d,
        }
    };
    assert!(matches!(result, Err(LdapError::Protocol(_))), "{result:?}");
    assert_eq!(peer.abandoned.recv_timeout(WAIT).unwrap(), s.handle.message_id());
    rt.shutdown();
}

/// Dropping the connection mid-sync fails the operation rather than hanging it.
#[test]
fn a_dropped_connection_ends_a_persistent_sync() {
    let rt = Runtime::start(Default::default()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut dec = BerDecoder::new();
        let _ = read_message(&mut stream, &mut dec, Duration::from_secs(10));
        // Say nothing and hang up.
    });
    let session = connect(&rt, addr);
    let mut replica = SyncReplica::new();
    let s = start_sync(&session, SyncMode::RefreshAndPersist, &mut replica);
    let r = run_to_done(&s, &mut replica);
    assert!(matches!(r, Err(LdapError::Closed) | Err(LdapError::Io(_))), "{r:?}");
    rt.shutdown();
}

