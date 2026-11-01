// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! End-to-end tests of the POP3 client: a [`Pop3ClientEndpoint`] on an
//! in-process connection, the test playing the server. Each test writes
//! the server's replies and checks the commands the client sends back, and
//! what the auto-pilots ([`Pop3Script`], [`Pop3Fetch`]) report at the end.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::testing::Peer;

use super::endpoint::Pop3ClientEndpoint;
use super::handlers::Pop3ClientHandlerFactory;
use super::pipeline::{MessageReceiveCallback, Pop3Fetch};
use super::script::{Pop3Op, Pop3OpResult, Pop3Script, Pop3ScriptOutcome};

type Outcome = Arc<Mutex<Option<Pop3ScriptOutcome>>>;

fn connect(factory: &dyn Pop3ClientHandlerFactory) -> Peer<Pop3ClientEndpoint> {
    let ep = Pop3ClientEndpoint::new(factory, Duration::from_secs(60), Duration::from_secs(600), None, None, false);
    Peer::connect(ep, |_| false)
}

/// A script that records its outcome.
fn script(user_pass: Option<(&str, &str)>, ops: Vec<Pop3Op>) -> (Pop3Script, Outcome) {
    let outcome: Outcome = Arc::default();
    let sink = Arc::clone(&outcome);
    let mut s = Pop3Script::new().ops(ops).on_result(Box::new(move |o| *sink.lock().unwrap() = Some(o)));
    if let Some((u, p)) = user_pass {
        s = s.credentials(u, p);
    }
    (s, outcome)
}

fn outcome(o: &Outcome) -> Pop3ScriptOutcome {
    o.lock().unwrap().clone().expect("the script has not reported")
}

const CAPA_USER: &str = "+OK\r\nUSER\r\nUIDL\r\nTOP\r\n.\r\n";

/// Greeting, CAPA and USER/PASS up to the first transaction command.
fn login(peer: &mut Peer<Pop3ClientEndpoint>) -> String {
    let mut out = peer.run("+OK ready\r\n");
    out += &peer.run(CAPA_USER);
    out += &peer.run("+OK\r\n");
    out += &peer.run("+OK logged in\r\n");
    out
}

#[test]
fn script_reports_stat_list_and_uidl() {
    let (s, result) = script(Some(("alice", "secret")), vec![Pop3Op::Stat, Pop3Op::List, Pop3Op::Uidl]);
    let mut peer = connect(&s);
    assert_eq!(login(&mut peer), "CAPA\r\nUSER alice\r\nPASS secret\r\nSTAT\r\n");
    assert_eq!(peer.run("+OK 2 300\r\n"), "LIST\r\n");
    assert_eq!(peer.run("+OK\r\n1 100\r\n2 200\r\n.\r\n"), "UIDL\r\n");
    assert_eq!(peer.run("+OK\r\n1 aaa\r\n2 bbb\r\n.\r\n"), "QUIT\r\n");
    assert_eq!(
        outcome(&result),
        Pop3ScriptOutcome::Done(vec![
            Pop3OpResult::Stat { count: 2, octets: 300 },
            Pop3OpResult::List(vec![(1, 100), (2, 200)]),
            Pop3OpResult::Uidl(vec![(1, "aaa".into()), (2, "bbb".into())]),
        ])
    );
    peer.run("+OK bye\r\n");
    peer.disconnect();
}

#[test]
fn script_unstuffs_retr_and_top_bodies() {
    let (s, result) = script(Some(("a", "b")), vec![Pop3Op::Retr(1), Pop3Op::Top { message: 2, lines: 1 }]);
    let mut peer = connect(&s);
    login(&mut peer);
    assert_eq!(peer.run("+OK 20 octets\r\nSubject: x\r\n\r\n..dot\r\n...\r\n.\r\n"), "TOP 2 1\r\n");
    assert_eq!(peer.run("+OK\r\nSubject: y\r\n\r\nfirst\r\n.\r\n"), "QUIT\r\n");
    assert_eq!(
        outcome(&result),
        Pop3ScriptOutcome::Done(vec![
            Pop3OpResult::Message { message: 1, is_top: false, body: b"Subject: x\r\n\r\n.dot\r\n..\r\n".to_vec() },
            Pop3OpResult::Message { message: 2, is_top: true, body: b"Subject: y\r\n\r\nfirst\r\n".to_vec() },
        ])
    );
}

#[test]
fn script_is_chunking_independent() {
    let server = "+OK ready\r\n+OK\r\nUSER\r\n.\r\n+OK\r\n+OK\r\n+OK 1 20\r\n+OK\r\n1 20\r\n.\r\n\
                  +OK\r\nA\r\n..B\r\n.\r\n+OK\r\n";
    let ops = || vec![Pop3Op::Stat, Pop3Op::List, Pop3Op::Retr(1)];
    let (s, whole) = script(Some(("u", "p")), ops());
    let mut peer = connect(&s);
    // Replies are only valid after the command they answer, so the whole
    // exchange is fed reply by reply, and each reply is split.
    let replies = ["+OK ready\r\n", "+OK\r\nUSER\r\n.\r\n", "+OK\r\n", "+OK\r\n", "+OK 1 20\r\n", "+OK\r\n1 20\r\n.\r\n", "+OK\r\nA\r\n..B\r\n.\r\n", "+OK\r\n"];
    assert_eq!(replies.concat(), server);
    let mut sent = String::new();
    for r in replies {
        sent += &peer.run(r);
    }
    for chunk in [1, 2, 3, 7] {
        let (s, split) = script(Some(("u", "p")), ops());
        let mut peer = connect(&s);
        let mut sent2 = String::new();
        for r in replies {
            sent2 += &peer.run_chunked(r, chunk);
        }
        assert_eq!(sent2, sent, "chunk {chunk}");
        assert_eq!(outcome(&split), outcome(&whole), "chunk {chunk}");
    }
    assert_eq!(sent, "CAPA\r\nUSER u\r\nPASS p\r\nSTAT\r\nLIST\r\nRETR 1\r\nQUIT\r\n");
}

#[test]
fn script_deletes_and_reports_the_message_number() {
    let (s, result) = script(Some(("a", "b")), vec![Pop3Op::Dele(3)]);
    let mut peer = connect(&s);
    login(&mut peer);
    assert_eq!(peer.run("+OK deleted\r\n"), "QUIT\r\n");
    assert_eq!(outcome(&result), Pop3ScriptOutcome::Done(vec![Pop3OpResult::Deleted(3)]));
}

#[test]
fn script_with_no_credentials_probes_and_quits() {
    let (s, result) = script(None, vec![]);
    let mut peer = connect(&s);
    assert_eq!(peer.run("+OK ready\r\n"), "CAPA\r\n");
    assert_eq!(peer.run(CAPA_USER), "QUIT\r\n");
    assert_eq!(outcome(&result), Pop3ScriptOutcome::Done(vec![]));
}

#[test]
fn script_with_ops_and_no_credentials_fails_before_any_command() {
    let (s, result) = script(None, vec![Pop3Op::Stat]);
    let mut peer = connect(&s);
    peer.run("+OK ready\r\n");
    assert_eq!(peer.run(CAPA_USER), "QUIT\r\n");
    match outcome(&result) {
        Pop3ScriptOutcome::Failed { completed, error } => {
            assert!(completed.is_empty());
            assert!(error.contains("credentials"), "{error}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn script_reports_refused_credentials() {
    let (s, result) = script(Some(("a", "wrong")), vec![Pop3Op::Stat]);
    let mut peer = connect(&s);
    peer.run("+OK ready\r\n");
    peer.run(CAPA_USER);
    peer.run("+OK\r\n");
    assert_eq!(peer.run("-ERR [AUTH] bad password\r\n"), "QUIT\r\n");
    assert_eq!(outcome(&result), Pop3ScriptOutcome::AuthFailed("[AUTH] bad password".into()));
}

#[test]
fn script_falls_back_to_user_pass_when_capa_is_refused() {
    let (s, result) = script(Some(("a", "b")), vec![Pop3Op::Stat]);
    let mut peer = connect(&s);
    assert_eq!(peer.run("+OK ready\r\n"), "CAPA\r\n");
    assert_eq!(peer.run("-ERR unknown command\r\n"), "USER a\r\n");
    assert_eq!(peer.run("+OK\r\n"), "PASS b\r\n");
    assert_eq!(peer.run("+OK\r\n"), "STAT\r\n");
    assert_eq!(peer.run("+OK 0 0\r\n"), "QUIT\r\n");
    assert_eq!(outcome(&result), Pop3ScriptOutcome::Done(vec![Pop3OpResult::Stat { count: 0, octets: 0 }]));
}

#[test]
fn script_authenticates_with_sasl_plain() {
    let (s, result) = script(Some(("alice", "secret")), vec![Pop3Op::Stat]);
    let mut peer = connect(&s);
    peer.run("+OK ready\r\n");
    // "\0alice\0secret"
    assert_eq!(peer.run("+OK\r\nSASL PLAIN\r\n.\r\n"), "AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n");
    assert_eq!(peer.run("+OK welcome\r\n"), "STAT\r\n");
    assert_eq!(peer.run("+OK 1 5\r\n"), "QUIT\r\n");
    assert_eq!(outcome(&result), Pop3ScriptOutcome::Done(vec![Pop3OpResult::Stat { count: 1, octets: 5 }]));
}

/// One step of a real server-side SASL mechanism, for the test to play the server.
fn server_step(
    server: &mut Box<dyn hopf_auth::SaslServer>,
    input: Option<&[u8]>,
) -> hopf_auth::SaslServerStep {
    let (tx, rx) = std::sync::mpsc::channel();
    server.step(input, Box::new(move |step| {
        let _ = tx.send(step);
    }));
    rx.recv().expect("the mechanism answers")
}

#[test]
fn script_acknowledges_the_servers_final_scram_data_with_an_empty_line() {
    // RFC 5034 section 4: data the server sends with the success of the
    // exchange comes as one more `+` continuation, and the client must
    // answer it with an empty line before the server says +OK.
    use hopf_auth::{create_server, PasswordStore, SaslMechanism, SaslServerOptions, SaslServerStep};
    let store = PasswordStore::new().with_user("alice", "secret").shared();
    let mut server = create_server(
        SaslMechanism::ScramSha256,
        store,
        SaslServerOptions { hostname: "pop".into(), realm: "pop".into(), peer_certificate: None, channel_binding: None },
    );
    let b64 = |b: &[u8]| rmimeparser::charset::base64::encode(b);
    let unb64 = |s: &str| rmimeparser::charset::base64::decode(s.trim()).unwrap();

    let (s, result) = script(Some(("alice", "secret")), vec![Pop3Op::Stat]);
    let mut peer = connect(&s);
    peer.run("+OK ready\r\n");
    let sent = peer.run("+OK\r\nSASL SCRAM-SHA-256\r\n.\r\n");
    let initial = sent.strip_prefix("AUTH SCRAM-SHA-256 ").expect("an AUTH with an initial response");
    let SaslServerStep::Challenge(first) = server_step(&mut server, Some(&unb64(initial))) else {
        panic!("the server challenges");
    };
    let sent = peer.run(&format!("+ {}\r\n", b64(&first)));
    let SaslServerStep::Complete { username, final_message } = server_step(&mut server, Some(&unb64(&sent))) else {
        panic!("the exchange completes");
    };
    assert_eq!(username, "alice");
    let final_message = final_message.expect("SCRAM ends with the server's signature");
    assert_eq!(peer.run(&format!("+ {}\r\n", b64(&final_message))), "\r\n", "the empty acknowledgement");
    assert_eq!(peer.run("+OK welcome\r\n"), "STAT\r\n");
    assert!(result.lock().unwrap().is_none());
}

#[test]
fn script_answers_a_login_challenge() {
    let (s, result) = script(Some(("alice", "secret")), vec![Pop3Op::Stat]);
    let mut peer = connect(&s);
    peer.run("+OK ready\r\n");
    assert_eq!(peer.run("+OK\r\nSASL LOGIN\r\n.\r\n"), "AUTH LOGIN\r\n");
    // "Username:" and "Password:"
    assert_eq!(peer.run("+ VXNlcm5hbWU6\r\n"), "YWxpY2U=\r\n");
    assert_eq!(peer.run("+ UGFzc3dvcmQ6\r\n"), "c2VjcmV0\r\n");
    assert_eq!(peer.run("+OK\r\n"), "STAT\r\n");
    assert!(result.lock().unwrap().is_none());
}

#[test]
fn script_gives_up_on_a_challenge_that_is_not_base64() {
    let (s, result) = script(Some(("alice", "secret")), vec![Pop3Op::Stat]);
    let mut peer = connect(&s);
    peer.run("+OK ready\r\n");
    peer.run("+OK\r\nSASL LOGIN\r\n.\r\n");
    assert_eq!(peer.run("+ !!!\r\n"), "");
    match outcome(&result) {
        Pop3ScriptOutcome::Failed { error, .. } => assert!(error.contains("base64"), "{error}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn script_uses_apop_when_preferred() {
    let (s, result) = script(Some(("alice", "secret")), vec![Pop3Op::Stat]);
    let s = s.prefer_apop(true);
    let mut peer = connect(&s);
    assert_eq!(peer.run("+OK ready <1896.697170952@dbc.mtview.ca.us>\r\n"), "CAPA\r\n");
    let digest = hopf_auth::crypto::md5_hex(b"<1896.697170952@dbc.mtview.ca.us>secret");
    assert_eq!(peer.run(CAPA_USER), format!("APOP alice {digest}\r\n"));
    assert_eq!(peer.run("+OK\r\n"), "STAT\r\n");
    assert!(result.lock().unwrap().is_none());
}

#[test]
fn script_fails_when_stls_is_required_and_not_offered() {
    let (s, result) = script(Some(("a", "b")), vec![Pop3Op::Stat]);
    let s = s.require_stls(true);
    let mut peer = connect(&s);
    peer.run("+OK ready\r\n");
    assert_eq!(peer.run(CAPA_USER), "QUIT\r\n");
    match outcome(&result) {
        Pop3ScriptOutcome::Failed { error, .. } => assert!(error.contains("STLS"), "{error}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn script_fails_when_stls_is_refused() {
    let (s, result) = script(Some(("a", "b")), vec![Pop3Op::Stat]);
    let s = s.require_stls(true);
    let mut peer = connect(&s);
    peer.run("+OK ready\r\n");
    assert_eq!(peer.run("+OK\r\nSTLS\r\nUSER\r\n.\r\n"), "STLS\r\n");
    assert_eq!(peer.run("-ERR not now\r\n"), "QUIT\r\n");
    match outcome(&result) {
        Pop3ScriptOutcome::Failed { error, .. } => assert!(error.contains("STLS"), "{error}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn script_stops_at_the_first_failing_op_and_keeps_what_completed() {
    let (s, result) = script(Some(("a", "b")), vec![Pop3Op::Stat, Pop3Op::Retr(9), Pop3Op::Stat]);
    let mut peer = connect(&s);
    login(&mut peer);
    assert_eq!(peer.run("+OK 1 5\r\n"), "RETR 9\r\n");
    assert_eq!(peer.run("-ERR no such message\r\n"), "QUIT\r\n");
    match outcome(&result) {
        Pop3ScriptOutcome::Failed { completed, error } => {
            assert_eq!(completed, vec![Pop3OpResult::Stat { count: 1, octets: 5 }]);
            assert!(error.contains("no such message"), "{error}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn script_reports_a_message_that_is_already_deleted() {
    let (s, result) = script(Some(("a", "b")), vec![Pop3Op::Retr(1)]);
    let mut peer = connect(&s);
    login(&mut peer);
    peer.run("-ERR message 1 deleted\r\n");
    match outcome(&result) {
        Pop3ScriptOutcome::Failed { error, .. } => assert!(error.contains("deleted"), "{error}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn script_reports_list_and_stat_errors() {
    for (op, reply) in [(Pop3Op::Stat, "STAT"), (Pop3Op::List, "LIST"), (Pop3Op::Uidl, "UIDL")] {
        let (s, result) = script(Some(("a", "b")), vec![op]);
        let mut peer = connect(&s);
        login(&mut peer);
        assert_eq!(peer.run("-ERR busy\r\n"), "QUIT\r\n", "{reply}");
        match outcome(&result) {
            Pop3ScriptOutcome::Failed { error, .. } => assert!(error.contains("busy"), "{reply}: {error}"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn script_reports_a_connection_that_drops_mid_session() {
    let (s, result) = script(Some(("a", "b")), vec![Pop3Op::Stat]);
    let mut peer = connect(&s);
    login(&mut peer);
    peer.run("-ERR");
    peer.disconnect();
    match outcome(&result) {
        Pop3ScriptOutcome::Failed { error, .. } => assert!(error.contains("closed"), "{error}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn script_reports_a_protocol_error() {
    let (s, result) = script(Some(("a", "b")), vec![Pop3Op::Stat]);
    let mut peer = connect(&s);
    peer.run("this is not a reply\r\n");
    match outcome(&result) {
        Pop3ScriptOutcome::Failed { .. } => {}
        other => panic!("{other:?}"),
    }
}

// ── Pop3Fetch ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Collected {
    events: Vec<String>,
    stop_after: Option<usize>,
}

struct Collector(Arc<Mutex<Collected>>);

impl MessageReceiveCallback for Collector {
    fn start_message(&mut self, id: u32, uid: Option<&str>) {
        assert!(uid.is_none());
        self.0.lock().unwrap().events.push(format!("start {id}"));
    }
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        let mut c = self.0.lock().unwrap();
        c.events.push(format!("data {}", String::from_utf8_lossy(chunk)));
        match c.stop_after {
            Some(n) => c.events.iter().filter(|e| e.starts_with("data")).count() < n,
            None => true,
        }
    }
    fn end_message(&mut self) {
        self.0.lock().unwrap().events.push("end".into());
    }
}

fn fetch(delete: bool, stop_after: Option<usize>) -> (Pop3Fetch, Arc<Mutex<Collected>>, Arc<Mutex<Vec<bool>>>) {
    let collected = Arc::new(Mutex::new(Collected { events: Vec::new(), stop_after }));
    let done: Arc<Mutex<Vec<bool>>> = Arc::default();
    let sink = Arc::clone(&done);
    let f = Pop3Fetch::new()
        .credentials("a", "b")
        .prefer_apop(false)
        .delete_after_fetch(delete)
        .on_message(Box::new(Collector(Arc::clone(&collected))))
        .on_complete(Box::new(move |ok| sink.lock().unwrap().push(ok)));
    (f, collected, done)
}

/// The data events joined: content may arrive in however many chunks.
fn joined(c: &Collected) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in &c.events {
        match (e.strip_prefix("data "), out.last_mut()) {
            (Some(d), Some(last)) if last.starts_with("data ") => last.push_str(d),
            _ => out.push(e.clone()),
        }
    }
    out
}

#[test]
fn fetch_retrieves_every_message_in_order() {
    let (f, collected, done) = fetch(false, None);
    let mut peer = connect(&f);
    assert_eq!(login(&mut peer), "CAPA\r\nUSER a\r\nPASS b\r\nSTAT\r\n");
    assert_eq!(peer.run("+OK 2 30\r\n"), "LIST\r\n");
    assert_eq!(peer.run("+OK\r\n1 10\r\n2 20\r\n.\r\n"), "RETR 1\r\n");
    assert_eq!(peer.run("+OK\r\none\r\n.\r\n"), "RETR 2\r\n");
    assert!(done.lock().unwrap().is_empty());
    assert_eq!(peer.run("+OK\r\n..two\r\n.\r\n"), "QUIT\r\n");
    assert_eq!(*done.lock().unwrap(), vec![true]);
    assert_eq!(
        joined(&collected.lock().unwrap()),
        vec!["start 1", "data one\r\n", "end", "start 2", "data .two\r\n", "end"]
    );
    peer.run("+OK bye\r\n");
    peer.disconnect();
    assert_eq!(*done.lock().unwrap(), vec![true]);
}

#[test]
fn fetch_deletes_each_message_after_retrieving_it() {
    let (f, _collected, done) = fetch(true, None);
    let mut peer = connect(&f);
    login(&mut peer);
    peer.run("+OK 2 30\r\n");
    assert_eq!(peer.run("+OK\r\n1 10\r\n2 20\r\n.\r\n"), "RETR 1\r\n");
    assert_eq!(peer.run("+OK\r\none\r\n.\r\n"), "DELE 1\r\n");
    assert_eq!(peer.run("+OK\r\n"), "RETR 2\r\n");
    assert_eq!(peer.run("+OK\r\ntwo\r\n.\r\n"), "DELE 2\r\n");
    assert_eq!(peer.run("+OK\r\n"), "QUIT\r\n");
    assert_eq!(*done.lock().unwrap(), vec![true]);
}

#[test]
fn fetch_of_an_empty_maildrop_just_quits() {
    let (f, collected, done) = fetch(false, None);
    let mut peer = connect(&f);
    login(&mut peer);
    assert_eq!(peer.run("+OK 0 0\r\n"), "QUIT\r\n");
    assert_eq!(*done.lock().unwrap(), vec![true]);
    assert!(collected.lock().unwrap().events.is_empty());
}

#[test]
fn fetch_keeps_consuming_a_message_the_callback_stopped_on() {
    let (f, collected, done) = fetch(false, Some(1));
    let mut peer = connect(&f);
    login(&mut peer);
    peer.run("+OK 2 30\r\n");
    peer.run("+OK\r\n1 10\r\n2 20\r\n.\r\n");
    // One chunk per line so the callback is offered more after it declined.
    assert_eq!(peer.run_chunked("+OK\r\nline1\r\nline2\r\nline3\r\n.\r\n", 8), "RETR 2\r\n");
    let events = collected.lock().unwrap().events.clone();
    assert_eq!(events.iter().filter(|e| e.starts_with("data")).count(), 1, "{events:?}");
    assert_eq!(peer.run("+OK\r\nx\r\n.\r\n"), "QUIT\r\n");
    assert_eq!(*done.lock().unwrap(), vec![true]);
}

#[test]
fn fetch_skips_a_message_that_has_vanished() {
    let (f, collected, done) = fetch(false, None);
    let mut peer = connect(&f);
    login(&mut peer);
    peer.run("+OK 2 30\r\n");
    peer.run("+OK\r\n1 10\r\n2 20\r\n.\r\n");
    assert_eq!(peer.run("-ERR no such message\r\n"), "RETR 2\r\n");
    assert_eq!(peer.run("+OK\r\ntwo\r\n.\r\n"), "QUIT\r\n");
    assert_eq!(*done.lock().unwrap(), vec![true]);
    let events = joined(&collected.lock().unwrap());
    assert!(events.contains(&"data two\r\n".to_string()), "{events:?}");
}

#[test]
fn fetch_reports_failure_when_the_login_is_refused() {
    let (f, _collected, done) = fetch(false, None);
    let mut peer = connect(&f);
    peer.run("+OK ready\r\n");
    peer.run(CAPA_USER);
    peer.run("+OK\r\n");
    assert_eq!(peer.run("-ERR no\r\n"), "QUIT\r\n");
    assert_eq!(*done.lock().unwrap(), vec![false]);
}

#[test]
fn fetch_reports_failure_when_the_stat_fails() {
    let (f, _collected, done) = fetch(false, None);
    let mut peer = connect(&f);
    login(&mut peer);
    assert_eq!(peer.run("-ERR locked\r\n"), "QUIT\r\n");
    assert_eq!(*done.lock().unwrap(), vec![false]);
}

#[test]
fn fetch_reports_failure_when_the_connection_drops() {
    let (f, _collected, done) = fetch(false, None);
    let mut peer = connect(&f);
    login(&mut peer);
    peer.run("+OK 1 5\r\n");
    peer.disconnect();
    assert_eq!(*done.lock().unwrap(), vec![false]);
}

#[test]
fn fetch_prefers_apop_by_default() {
    let done: Arc<Mutex<Vec<bool>>> = Arc::default();
    let sink = Arc::clone(&done);
    let f = Pop3Fetch::new().credentials("alice", "secret").on_complete(Box::new(move |ok| sink.lock().unwrap().push(ok)));
    let mut peer = connect(&f);
    peer.run("+OK ready <t@h>\r\n");
    let digest = hopf_auth::crypto::md5_hex(b"<t@h>secret");
    assert_eq!(peer.run(CAPA_USER), format!("APOP alice {digest}\r\n"));
}

#[test]
fn fetch_requires_stls_when_asked() {
    let done: Arc<Mutex<Vec<bool>>> = Arc::default();
    let sink = Arc::clone(&done);
    let f = Pop3Fetch::new()
        .credentials("a", "b")
        .require_stls(true)
        .on_complete(Box::new(move |ok| sink.lock().unwrap().push(ok)));
    let mut peer = connect(&f);
    peer.run("+OK ready\r\n");
    assert_eq!(peer.run(CAPA_USER), "QUIT\r\n");
    assert_eq!(*done.lock().unwrap(), vec![false]);
}
