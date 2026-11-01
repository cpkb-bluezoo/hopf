// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! End-to-end tests of the NNTP client: a [`NntpClientEndpoint`] on an
//! in-process connection, the test playing the server. Each test writes the
//! server's replies and checks the commands the client sends back and what
//! the application is told.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::testing::Peer;

use super::endpoint::{NntpClientEndpoint, TlsMode};
use super::error::NntpClientError;
use super::handlers::{NntpClientHandler, NntpGreeting};
use super::reply::{ArticleRef, GroupResult, NewsgroupEntry, OverviewEntry};
use super::session::NntpSession;

#[derive(Default)]
struct Log {
    greeting: Option<NntpGreeting>,
    session: Option<NntpSession>,
    errors: Vec<String>,
    disconnected: bool,
}

struct Handler(Arc<Mutex<Log>>);

impl NntpClientHandler for Handler {
    fn on_connected(&mut self, session: &NntpSession, greeting: &NntpGreeting) {
        let mut log = self.0.lock().unwrap();
        log.session = Some(session.clone());
        log.greeting = Some(greeting.clone());
    }
    fn on_error(&mut self, error: &io::Error) {
        self.0.lock().unwrap().errors.push(error.to_string());
    }
    fn on_disconnected(&mut self) {
        self.0.lock().unwrap().disconnected = true;
    }
}

type Client = (Peer<NntpClientEndpoint>, Arc<Mutex<Log>>);

fn connect(credentials: Option<(&str, &str)>, tls_mode: TlsMode) -> Client {
    let log: Arc<Mutex<Log>> = Arc::default();
    let ep = NntpClientEndpoint::new(
        Box::new(Handler(Arc::clone(&log))),
        credentials.map(|(u, p)| (u.to_string(), p.to_string())),
        None,
        tls_mode,
        Duration::from_secs(60),
    );
    (Peer::connect(ep, |_| false), log)
}

const CAPS: &str = "101 Capability list:\r\nVERSION 2\r\nREADER\r\nOVER\r\n.\r\n";

/// A client with no credentials, up to the moment its session is usable.
fn ready() -> Client {
    let (mut peer, log) = connect(None, TlsMode::None);
    assert_eq!(peer.run("200 Service available, posting allowed\r\n"), "CAPABILITIES\r\n");
    assert_eq!(peer.run(CAPS), "");
    assert!(log.lock().unwrap().session.is_some());
    (peer, log)
}

fn session(log: &Arc<Mutex<Log>>) -> NntpSession {
    log.lock().unwrap().session.clone().expect("the session is not ready")
}

/// What the client has written, once it has seen to what it was asked.
fn sent(peer: &mut Peer<NntpClientEndpoint>) -> String {
    peer.pump();
    peer.take()
}

type Slot<T> = Arc<Mutex<Option<Result<T, NntpClientError>>>>;

fn slot<T>() -> Slot<T> {
    Arc::new(Mutex::new(None))
}

fn put<T: Send + 'static>(s: &Slot<T>) -> impl FnOnce(Result<T, NntpClientError>) + Send + 'static {
    let s = Arc::clone(s);
    move |r| *s.lock().unwrap() = Some(r)
}

fn got<T>(s: &Slot<T>) -> Result<T, NntpClientError> {
    s.lock().unwrap().take().expect("the command has not completed")
}

#[test]
fn the_session_is_ready_after_the_greeting_and_capabilities() {
    let (mut peer, log) = connect(None, TlsMode::None);
    assert_eq!(peer.run("201 Service available, posting prohibited\r\n"), "CAPABILITIES\r\n");
    assert!(log.lock().unwrap().greeting.is_none());
    peer.run(CAPS);
    let log = log.lock().unwrap();
    let greeting = log.greeting.as_ref().unwrap();
    assert_eq!(greeting.code, 201);
    assert!(!greeting.posting_allowed);
    assert_eq!(greeting.capabilities, vec!["VERSION 2", "READER", "OVER"]);
    assert!(!greeting.secure && !greeting.authenticated);
}

#[test]
fn a_server_without_capabilities_is_carried_on_with() {
    let (mut peer, log) = connect(None, TlsMode::None);
    peer.run("200 hi\r\n");
    peer.run("500 What?\r\n");
    assert!(log.lock().unwrap().greeting.as_ref().unwrap().capabilities.is_empty());
}

#[test]
fn a_greeting_that_refuses_ends_the_session() {
    let (mut peer, log) = connect(None, TlsMode::None);
    peer.run("400 Service temporarily unavailable\r\n");
    assert!(peer.is_closed());
    assert!(log.lock().unwrap().errors[0].contains("400"));
}

#[test]
fn a_greeting_that_is_no_status_ends_the_session() {
    let (mut peer, log) = connect(None, TlsMode::None);
    peer.run("hello there\r\n");
    assert!(peer.is_closed());
    assert!(log.lock().unwrap().errors[0].contains("greeting"), "{:?}", log.lock().unwrap().errors);
}

#[test]
fn group_is_read_into_its_fields() {
    let (mut peer, log) = ready();
    let r: Slot<GroupResult> = slot();
    session(&log).group("misc.test", put(&r));
    assert_eq!(sent(&mut peer), "GROUP misc.test\r\n");
    peer.run("211 1234 3000234 3002322 misc.test\r\n");
    assert_eq!(got(&r).unwrap(), GroupResult { count: 1234, first: 3000234, last: 3002322, name: "misc.test".into() });
}

#[test]
fn a_group_that_does_not_exist_is_a_rejection() {
    let (mut peer, log) = ready();
    let r: Slot<GroupResult> = slot();
    session(&log).group("no.such", put(&r));
    sent(&mut peer);
    peer.run("411 No such newsgroup\r\n");
    let err = got(&r).unwrap_err();
    assert!(err.to_string().contains("411"), "{err}");
}

#[test]
fn stat_names_the_article() {
    let (mut peer, log) = ready();
    let r: Slot<ArticleRef> = slot();
    session(&log).stat(3000234, put(&r));
    assert_eq!(sent(&mut peer), "STAT 3000234\r\n");
    peer.run("223 3000234 <45223423@example.com>\r\n");
    assert_eq!(got(&r).unwrap(), ArticleRef { number: 3000234, message_id: "<45223423@example.com>".into() });

    session(&log).stat(1, put(&r));
    sent(&mut peer);
    peer.run("423 No article with that number\r\n");
    assert!(got(&r).unwrap_err().to_string().contains("423"));
}

#[test]
fn list_active_gives_an_entry_per_line_and_completes_at_the_dot() {
    let (mut peer, log) = ready();
    let entries: Arc<Mutex<Vec<NewsgroupEntry>>> = Arc::default();
    let r: Slot<()> = slot();
    let e = Arc::clone(&entries);
    session(&log).list_active("comp.*", move |g| e.lock().unwrap().push(g), put(&r));
    assert_eq!(sent(&mut peer), "LIST ACTIVE comp.*\r\n");
    peer.run("215 list follows\r\ncomp.lang.rust 1234 12 y\r\ncomp.test 5 1 m\r\n");
    assert_eq!(entries.lock().unwrap().len(), 2);
    assert!(r.lock().unwrap().is_none());
    peer.run(".\r\n");
    got(&r).unwrap();
    let entries = entries.lock().unwrap();
    assert_eq!(entries[0], NewsgroupEntry { name: "comp.lang.rust".into(), high: 1234, low: 12, status: 'y' });
    assert_eq!(entries[1].status, 'm');
}

#[test]
fn over_gives_an_entry_per_line() {
    let (mut peer, log) = ready();
    let entries: Arc<Mutex<Vec<OverviewEntry>>> = Arc::default();
    let r: Slot<()> = slot();
    let e = Arc::clone(&entries);
    session(&log).over(10, 11, move |o| e.lock().unwrap().push(o), put(&r));
    assert_eq!(sent(&mut peer), "OVER 10-11\r\n");
    peer.run("224 Overview information follows\r\n10\tA subject\tme <me@x>\tMon, 1 Jan 2024\t<a@x>\t\t120\t3\r\n");
    peer.run("11\t.dot\tyou\tTue\t<b@x>\t<a@x>\t80\t2\tXref: x\r\nnot an overview line\r\n.\r\n");
    got(&r).unwrap();
    let entries = entries.lock().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].article_number, 10);
    assert_eq!(entries[0].references, "");
    assert_eq!(entries[1].subject, ".dot");
    assert_eq!(entries[1].lines, 2);
}

#[test]
fn an_article_arrives_as_content_dot_unstuffed() {
    let (mut peer, log) = ready();
    let text: Arc<Mutex<Vec<u8>>> = Arc::default();
    let r: Slot<()> = slot();
    let t = Arc::clone(&text);
    session(&log).article(12, move |c| t.lock().unwrap().extend_from_slice(c), put(&r));
    assert_eq!(sent(&mut peer), "ARTICLE 12\r\n");
    peer.run("220 12 <c1@x> article follows\r\nSubject: s\r\n\r\n..leading dot\r\nsecond");
    assert!(r.lock().unwrap().is_none());
    peer.run(" line\r\n.\r\n");
    got(&r).unwrap();
    assert_eq!(&*text.lock().unwrap(), b"Subject: s\r\n\r\n.leading dot\r\nsecond line\r\n");
}

#[test]
fn head_and_body_are_the_same_kind_of_block() {
    let (mut peer, log) = ready();
    for (verb, code) in [("head", 221), ("body", 222)] {
        let text: Arc<Mutex<Vec<u8>>> = Arc::default();
        let r: Slot<()> = slot();
        let t = Arc::clone(&text);
        let s = session(&log);
        if verb == "head" {
            s.head(1, move |c| t.lock().unwrap().extend_from_slice(c), put(&r));
        } else {
            s.body(1, move |c| t.lock().unwrap().extend_from_slice(c), put(&r));
        }
        assert_eq!(sent(&mut peer), format!("{} 1\r\n", verb.to_uppercase()));
        peer.run(&format!("{code} 1 <i@x>\r\nline\r\n.\r\n"));
        got(&r).unwrap();
        assert_eq!(&*text.lock().unwrap(), b"line\r\n");
    }
}

#[test]
fn an_article_that_is_not_there_completes_with_the_rejection_and_no_content() {
    let (mut peer, log) = ready();
    let r: Slot<()> = slot();
    session(&log).article(99, |_| panic!("content for a missing article"), put(&r));
    sent(&mut peer);
    peer.run("423 No article with that number\r\n");
    assert!(got(&r).unwrap_err().to_string().contains("423"));
    // And the next command goes out as usual.
    let g: Slot<GroupResult> = slot();
    session(&log).group("a.b", put(&g));
    assert_eq!(sent(&mut peer), "GROUP a.b\r\n");
}

#[test]
fn commands_go_out_one_at_a_time_in_order() {
    let (mut peer, log) = ready();
    let a: Slot<GroupResult> = slot();
    let b: Slot<ArticleRef> = slot();
    let s = session(&log);
    s.group("a.b", put(&a));
    s.stat(5, put(&b));
    assert_eq!(sent(&mut peer), "GROUP a.b\r\n");
    assert_eq!(peer.run("211 1 5 5 a.b\r\n"), "STAT 5\r\n");
    peer.run("223 5 <m@x>\r\n");
    assert!(got(&a).is_ok() && got(&b).is_ok());
}

#[test]
fn post_sends_the_article_stuffed_after_the_340() {
    let (mut peer, log) = ready();
    let r: Slot<()> = slot();
    session(&log).post(b"Subject: s\n\n.dot\nbody", put(&r));
    assert_eq!(sent(&mut peer), "POST\r\n");
    assert_eq!(peer.run("340 Input article; end with <CR-LF>.<CR-LF>\r\n"), "Subject: s\r\n\r\n..dot\r\nbody\r\n.\r\n");
    peer.run("240 Article received OK\r\n");
    got(&r).unwrap();
}

#[test]
fn a_post_that_is_refused_completes_with_the_rejection() {
    let (mut peer, log) = ready();
    let r: Slot<()> = slot();
    session(&log).post(b"x", put(&r));
    sent(&mut peer);
    assert_eq!(peer.run("440 Posting not permitted\r\n"), "");
    assert!(got(&r).unwrap_err().to_string().contains("440"));
}

#[test]
fn quit_closes_the_connection() {
    let (mut peer, log) = ready();
    session(&log).quit();
    assert_eq!(sent(&mut peer), "QUIT\r\n");
    assert!(!session(&log).is_alive());
    peer.run("205 Connection closing\r\n");
    assert!(peer.is_closed());
}

#[test]
fn a_connection_lost_mid_command_fails_it_and_the_ones_behind() {
    let (mut peer, log) = ready();
    let a: Slot<GroupResult> = slot();
    let b: Slot<GroupResult> = slot();
    let s = session(&log);
    s.group("a.b", put(&a));
    s.group("c.d", put(&b));
    sent(&mut peer);
    peer.disconnect();
    assert!(got(&a).is_err());
    assert!(got(&b).is_err());
    assert!(log.lock().unwrap().disconnected);
}

#[test]
fn the_session_is_the_same_under_every_chunking() {
    let replies = [
        "211 3 1 3 misc.test\r\n",
        "215 list\r\nmisc.test 3 1 y\r\n.\r\n",
        "224 o\r\n1\ts\tf\td\t<i@x>\t\t10\t2\r\n.\r\n",
        "220 1 <i@x>\r\nH: v\r\n\r\n..x\r\n.\r\n",
        "223 2 <j@x>\r\n",
    ];
    let mut outcomes = Vec::new();
    for chunk in [usize::MAX, 1, 2, 3, 7] {
        let (mut peer, log) = ready();
        let s = session(&log);
        let events: Arc<Mutex<Vec<String>>> = Arc::default();
        let e = Arc::clone(&events);
        s.group("misc.test", move |r| e.lock().unwrap().push(format!("{:?}", r.map(|g| (g.count, g.first, g.last, g.name)))));
        let e = Arc::clone(&events);
        let e2 = Arc::clone(&events);
        s.list_active("", move |g| e.lock().unwrap().push(format!("{g:?}")), move |r| e2.lock().unwrap().push(format!("{:?}", r.map(|_| ()))));
        let e = Arc::clone(&events);
        let e2 = Arc::clone(&events);
        s.over(1, 1, move |o| e.lock().unwrap().push(format!("{o:?}")), move |r| e2.lock().unwrap().push(format!("{:?}", r.map(|_| ()))));
        let body: Arc<Mutex<Vec<u8>>> = Arc::default();
        let b = Arc::clone(&body);
        let e = Arc::clone(&events);
        s.article(1, move |c| b.lock().unwrap().extend_from_slice(c), move |r| e.lock().unwrap().push(format!("{:?}", r.map(|_| ()))));
        let e = Arc::clone(&events);
        s.stat(2, move |r| e.lock().unwrap().push(format!("{r:?}")));
        let mut sent = sent(&mut peer);
        for r in replies {
            let piece = if chunk == usize::MAX { peer.run(r) } else { peer.run_chunked(r, chunk) };
            sent.push_str(&piece);
        }
        events.lock().unwrap().push(String::from_utf8_lossy(&body.lock().unwrap()).into_owned());
        outcomes.push((sent, events.lock().unwrap().clone()));
    }
    assert_eq!(outcomes[0].0, "GROUP misc.test\r\nLIST ACTIVE\r\nOVER 1-1\r\nARTICLE 1\r\nSTAT 2\r\n");
    assert!(outcomes[0].1.last().unwrap().contains("H: v"), "{:?}", outcomes[0].1);
    for (i, o) in outcomes.iter().enumerate() {
        assert_eq!(o, &outcomes[0], "chunking {i}");
    }
}

// ── authentication ────────────────────────────────────────────────────────

#[test]
fn authinfo_user_and_pass() {
    let (mut peer, log) = connect(Some(("alice", "secret")), TlsMode::None);
    peer.run("200 hi\r\n");
    assert_eq!(peer.run(CAPS), "AUTHINFO USER alice\r\n");
    assert_eq!(peer.run("381 Password required\r\n"), "AUTHINFO PASS secret\r\n");
    peer.run("281 Authentication accepted\r\n");
    assert!(log.lock().unwrap().greeting.as_ref().unwrap().authenticated);
}

#[test]
fn authinfo_rejected_credentials_end_the_session() {
    let (mut peer, log) = connect(Some(("alice", "wrong")), TlsMode::None);
    peer.run("200 hi\r\n");
    peer.run(CAPS);
    peer.run("381 Password required\r\n");
    peer.run("481 Authentication failed\r\n");
    assert!(peer.is_closed());
    assert!(log.lock().unwrap().errors[0].contains("481"));
}

#[test]
fn sasl_plain_sends_its_initial_response_with_the_command() {
    let (mut peer, log) = connect(Some(("alice", "secret")), TlsMode::None);
    peer.run("200 hi\r\n");
    // "\0alice\0secret"
    assert_eq!(peer.run("101 caps\r\nVERSION 2\r\nSASL PLAIN\r\n.\r\n"), "AUTHINFO SASL PLAIN AGFsaWNlAHNlY3JldA==\r\n");
    peer.run("281 Authentication accepted\r\n");
    assert!(log.lock().unwrap().greeting.as_ref().unwrap().authenticated);
}

#[test]
fn sasl_login_answers_its_prompts_with_the_credentials() {
    let (mut peer, log) = connect(Some(("alice", "secret")), TlsMode::None);
    peer.run("200 hi\r\n");
    assert_eq!(peer.run("101 caps\r\nSASL LOGIN\r\n.\r\n"), "AUTHINFO SASL LOGIN\r\n");
    // "Username:", "Password:" in; "alice", "secret" out.
    assert_eq!(peer.run("383 VXNlcm5hbWU6\r\n"), "YWxpY2U=\r\n");
    assert_eq!(peer.run("383 UGFzc3dvcmQ6\r\n"), "c2VjcmV0\r\n");
    peer.run("281 ok\r\n");
    assert!(log.lock().unwrap().greeting.as_ref().unwrap().authenticated);
}

#[test]
fn starttls_is_required_or_the_session_fails() {
    let (mut peer, log) = connect(None, TlsMode::StartTlsRequired);
    peer.run("200 hi\r\n");
    peer.run(CAPS);
    assert!(peer.is_closed());
    assert!(log.lock().unwrap().errors[0].contains("STARTTLS"));
}

#[test]
fn starttls_is_asked_for_when_offered() {
    let (mut peer, _log) = connect(None, TlsMode::StartTlsOpportunistic);
    peer.run("200 hi\r\n");
    assert_eq!(peer.run("101 caps\r\nSTARTTLS\r\n.\r\n"), "STARTTLS\r\n");
}

#[test]
fn opportunistic_starttls_carries_on_in_the_clear_when_refused() {
    let (mut peer, log) = connect(None, TlsMode::StartTlsOpportunistic);
    peer.run("200 hi\r\n");
    peer.run("101 caps\r\nSTARTTLS\r\n.\r\n");
    peer.run("502 Command unavailable\r\n");
    assert!(log.lock().unwrap().session.is_some());
}
