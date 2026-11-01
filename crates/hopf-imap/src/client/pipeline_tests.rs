// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-process tests of the [`ImapFetch`] and [`ImapIdle`] pipelines: the
//! test plays the IMAP server over a [`Peer`], answering each command the
//! pipeline sends and checking what it sends next.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::testing::Peer;

use super::*;
use crate::client::endpoint::ImapClientEndpoint;
use crate::client::pending::DEFAULT_MAX_PIPELINE;

type Client = Peer<ImapClientEndpoint>;

fn start(factory: &dyn ImapClientHandlerFactory) -> Client {
    let ep = ImapClientEndpoint::new(
        factory,
        Duration::from_secs(30),
        Duration::from_secs(30),
        Duration::from_secs(30),
        None,
        None,
        false,
        DEFAULT_MAX_PIPELINE,
    );
    Peer::connect(ep, |_| false)
}

/// The tag and the rest of the one command line the client just sent.
fn command(sent: &str) -> (String, String) {
    let line = sent.trim_end_matches("\r\n");
    assert!(!line.contains('\n'), "exactly one command expected, got {sent:?}");
    let (tag, rest) = line.split_once(' ').unwrap_or((line, ""));
    (tag.to_string(), rest.to_string())
}

/// Answer the command in `sent` with `untagged` lines and a tagged `status`.
fn answer(c: &mut Client, sent: &str, untagged: &str, status: &str) -> String {
    let (tag, _) = command(sent);
    c.run(&format!("{untagged}{tag} {status}\r\n"))
}

/// What a message callback saw.
#[derive(Default)]
struct Messages {
    log: Vec<String>,
}

struct Receiver(Arc<Mutex<Messages>>);

impl MessageReceiveCallback for Receiver {
    fn start_message(&mut self, seq: u32) {
        self.0.lock().unwrap().log.push(format!("start {seq}"));
    }
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        self.0.lock().unwrap().log.push(format!("content {}", String::from_utf8_lossy(chunk)));
        true
    }
    fn end_message(&mut self, uid: Option<u32>) {
        self.0.lock().unwrap().log.push(format!("end {uid:?}"));
    }
}

struct Events(Arc<Mutex<Vec<String>>>);

impl MailboxEventListener for Events {
    fn on_exists(&mut self, count: u32) {
        self.0.lock().unwrap().push(format!("exists {count}"));
    }
    fn on_recent(&mut self, count: u32) {
        self.0.lock().unwrap().push(format!("recent {count}"));
    }
    fn on_expunge(&mut self, seq: u32) {
        self.0.lock().unwrap().push(format!("expunge {seq}"));
    }
    fn on_flags(&mut self, seq: u32, flags: &[String]) {
        self.0.lock().unwrap().push(format!("flags {seq} {}", flags.join(",")));
    }
}

type Outcome = Arc<Mutex<Vec<bool>>>;

fn fetch(outcome: &Outcome) -> (ImapFetch, Arc<Mutex<Messages>>) {
    let log = Arc::new(Mutex::new(Messages::default()));
    let outcome = Arc::clone(outcome);
    let f = ImapFetch::new()
        .credentials("alice", "s3cret")
        .on_message(Box::new(Receiver(Arc::clone(&log))))
        .on_complete(Box::new(move |ok| outcome.lock().unwrap().push(ok)));
    (f, log)
}

/// Greeting and CAPABILITY done with `caps`; returns what the client sent next.
fn through_capability(c: &mut Client, caps: &str) -> String {
    let sent = c.take();
    assert_eq!(sent, "", "the client waits for the greeting");
    let sent = c.run("* OK IMAP ready\r\n");
    assert!(command(&sent).1.eq_ignore_ascii_case("CAPABILITY"), "{sent:?}");
    answer(c, &sent, &format!("* CAPABILITY IMAP4rev1 {caps}\r\n"), "OK done")
}

fn b64(user: &str, pass: &str) -> String {
    hopf_auth::crypto::encode_base64(format!("\0{user}\0{pass}").as_bytes())
}

// -- ImapFetch ---------------------------------------------------------------

/// Drive an `ImapFetch` to the point where FETCH has been sent.
fn to_fetch(f: &ImapFetch, caps: &str) -> (Client, String) {
    let mut c = start(f);
    let sent = through_capability(&mut c, caps);
    assert_eq!(unquote(&command(&sent).1), "LOGIN alice s3cret");
    let sent = answer(&mut c, &sent, "", "OK logged in");
    assert_eq!(unquote(&command(&sent).1), "SELECT INBOX");
    let sent = answer(&mut c, &sent, "* 2 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 7] ok\r\n", "OK [READ-WRITE] done");
    (c, sent)
}

fn unquote(s: &str) -> String {
    s.replace('"', "")
}

#[test]
fn fetch_logs_in_selects_fetches_and_logs_out() {
    let outcome = Outcome::default();
    let (f, log) = fetch(&outcome);
    let (mut c, sent) = to_fetch(&f, "LOGIN");
    assert_eq!(command(&sent).1, "FETCH 1:* (RFC822)");
    let (tag, _) = command(&sent);
    assert_eq!(c.run("* 1 FETCH (UID 11 RFC822 {5}\r\nhello)\r\n* 2 FETCH (UID 12 RFC822 {3}\r\nabc)\r\n"), "");
    assert!(outcome.lock().unwrap().is_empty(), "not done before the tagged reply");
    let sent = c.run(&format!("{tag} OK fetched\r\n"));
    assert_eq!(command(&sent).1, "LOGOUT");
    assert_eq!(*outcome.lock().unwrap(), [true]);
    assert_eq!(
        log.lock().unwrap().log,
        ["start 1", "content hello", "end Some(11)", "start 2", "content abc", "end Some(12)"]
    );
}

#[test]
fn fetch_with_non_default_mailbox_set_and_items() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let f = f.mailbox("Archive/2026").sequence_set("5:7").fetch_items("(UID FLAGS)");
    let mut c = start(&f);
    let sent = through_capability(&mut c, "");
    let sent = answer(&mut c, &sent, "", "OK");
    assert_eq!(unquote(&command(&sent).1), "SELECT Archive/2026");
    let sent = answer(&mut c, &sent, "", "OK [READ-ONLY] done");
    assert_eq!(command(&sent).1, "FETCH 5:7 (UID FLAGS)");
}

#[test]
fn fetch_flags_only_responses_end_the_message_with_the_uid() {
    let outcome = Outcome::default();
    let (f, log) = fetch(&outcome);
    let f = f.fetch_items("(UID FLAGS)");
    let (mut c, sent) = to_fetch(&f, "");
    let (tag, _) = command(&sent);
    c.run("* 1 FETCH (UID 40 FLAGS (\\Seen))\r\n");
    c.run(&format!("{tag} OK done\r\n"));
    assert_eq!(log.lock().unwrap().log, ["end Some(40)"]);
}

#[test]
fn fetch_delivers_a_message_split_across_reads_whole() {
    let outcome = Outcome::default();
    let (f, log) = fetch(&outcome);
    let (mut c, sent) = to_fetch(&f, "");
    let (tag, _) = command(&sent);
    c.run_chunked("* 1 FETCH (UID 3 RFC822 {11}\r\nhello world)\r\n", 3);
    c.run(&format!("{tag} OK done\r\n"));
    let l = log.lock().unwrap();
    assert_eq!(l.log.first().map(String::as_str), Some("start 1"));
    assert_eq!(l.log.last().map(String::as_str), Some("end Some(3)"));
    let body: String = l.log.iter().filter_map(|e| e.strip_prefix("content ")).collect();
    assert_eq!(body, "hello world");
    assert_eq!(l.log.iter().filter(|e| e.starts_with("start")).count(), 1);
}

#[test]
fn fetch_uses_authenticate_plain_when_offered() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "AUTH=PLAIN SASL-IR");
    assert_eq!(command(&sent).1, format!("AUTHENTICATE PLAIN {}", b64("alice", "s3cret")));
}

#[test]
fn fetch_waits_for_the_continuation_when_the_server_has_no_sasl_ir() {
    // RFC 4959: an initial response may only be sent with the command when
    // the server advertises SASL-IR; otherwise it answers the "+" prompt.
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "AUTH=PLAIN");
    assert_eq!(command(&sent).1, "AUTHENTICATE PLAIN");
    let reply = c.run("+ \r\n");
    assert_eq!(reply.trim_end(), b64("alice", "s3cret"));
}

#[test]
fn fetch_prefers_login_when_asked_to() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let f = f.prefer_auth_plain(false);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "AUTH=PLAIN SASL-IR");
    assert_eq!(unquote(&command(&sent).1), "LOGIN alice s3cret");
}

#[test]
fn fetch_does_not_send_login_when_the_server_disables_it() {
    // RFC 3501 section 7.2.1: a client must not LOGIN while LOGINDISABLED.
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "LOGINDISABLED");
    assert!(!sent.to_ascii_uppercase().contains("LOGIN"), "{sent:?}");
    assert_eq!(*outcome.lock().unwrap(), [false]);
    assert!(c.is_closed());
}

#[test]
fn fetch_falls_back_to_authenticate_plain_when_login_is_disabled() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let f = f.prefer_auth_plain(false);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "LOGINDISABLED AUTH=PLAIN SASL-IR");
    assert!(command(&sent).1.starts_with("AUTHENTICATE PLAIN"), "{sent:?}");
}

#[test]
fn fetch_fails_when_authentication_is_refused() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "");
    answer(&mut c, &sent, "", "NO [AUTHENTICATIONFAILED] bad");
    assert_eq!(*outcome.lock().unwrap(), [false]);
    assert!(c.is_closed());
}

#[test]
fn fetch_fails_when_select_is_refused() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "");
    let sent = answer(&mut c, &sent, "", "OK");
    answer(&mut c, &sent, "", "NO no such mailbox");
    assert_eq!(*outcome.lock().unwrap(), [false]);
    assert!(c.is_closed());
}

#[test]
fn fetch_reports_failure_but_still_logs_out_when_the_fetch_is_refused() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let (mut c, sent) = to_fetch(&f, "");
    let reply = answer(&mut c, &sent, "", "NO fetch failed");
    assert_eq!(command(&reply).1, "LOGOUT");
    assert_eq!(*outcome.lock().unwrap(), [false]);
}

#[test]
fn fetch_requiring_starttls_fails_when_the_server_lacks_it() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let f = f.require_starttls(true);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "AUTH=PLAIN");
    assert_eq!(sent, "", "no credentials sent in the clear");
    assert_eq!(*outcome.lock().unwrap(), [false]);
    assert!(c.is_closed());
}

#[test]
fn fetch_requiring_starttls_asks_for_it() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let f = f.require_starttls(true);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "STARTTLS AUTH=PLAIN");
    assert_eq!(command(&sent).1, "STARTTLS");
    // the in-process peer cannot upgrade: that is a failure, with nothing sent after it
    let after = answer(&mut c, &sent, "", "OK begin TLS");
    assert!(!after.to_ascii_uppercase().contains("AUTHENTICATE") && !after.to_ascii_uppercase().contains("LOGIN"), "{after:?}");
    assert_eq!(*outcome.lock().unwrap(), [false]);
}

#[test]
fn fetch_refused_starttls_is_a_failure() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let f = f.require_starttls(true);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "STARTTLS");
    let after = answer(&mut c, &sent, "", "NO not now");
    assert!(!after.to_ascii_uppercase().contains("LOGIN"), "{after:?}");
    assert_eq!(*outcome.lock().unwrap(), [false]);
}

#[test]
fn fetch_without_starttls_required_does_not_use_it() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "STARTTLS");
    assert!(command(&sent).1.to_ascii_uppercase().starts_with("LOGIN"));
}

#[test]
fn fetch_reports_failure_once_when_the_connection_drops() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let (mut c, _) = to_fetch(&f, "");
    c.disconnect();
    assert_eq!(*outcome.lock().unwrap(), [false]);
}

#[test]
fn fetch_reports_failure_when_the_connection_errors() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let (mut c, _) = to_fetch(&f, "");
    c.fail(&std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset"));
    assert_eq!(*outcome.lock().unwrap(), [false]);
}

#[test]
fn fetch_reports_failure_when_the_connection_cannot_be_made() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    f.connect_failed("imap.example", &std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "no"));
    f.connect_failed("imap.example", &std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "no"));
    assert_eq!(*outcome.lock().unwrap(), [false], "reported once");
}

#[test]
fn fetch_passes_mailbox_events_to_the_listener() {
    let outcome = Outcome::default();
    let (f, _) = fetch(&outcome);
    let events = Arc::new(Mutex::new(Vec::new()));
    let f = f.mailbox_events(Box::new(Events(Arc::clone(&events))));
    let (mut c, sent) = to_fetch(&f, "");
    let (tag, _) = command(&sent);
    c.run("* 3 EXISTS\r\n* 1 EXPUNGE\r\n");
    c.run(&format!("{tag} OK done\r\n"));
    assert_eq!(*events.lock().unwrap(), ["exists 3", "expunge 1"]);
}

// -- ImapIdle ----------------------------------------------------------------

fn idle(outcome: &Outcome, events: &Arc<Mutex<Vec<String>>>) -> ImapIdle {
    let outcome = Arc::clone(outcome);
    ImapIdle::new()
        .credentials("alice", "s3cret")
        .mailbox_events(Box::new(Events(Arc::clone(events))))
        .on_complete(Box::new(move |ok| outcome.lock().unwrap().push(ok)))
}

/// An `ImapIdle` to the point where IDLE has been sent; returns the IDLE tag.
fn to_idle(f: &ImapIdle, caps: &str) -> (Client, String) {
    let mut c = start(f);
    let sent = through_capability(&mut c, caps);
    let sent = answer(&mut c, &sent, "", "OK logged in");
    assert_eq!(unquote(&command(&sent).1), "SELECT INBOX");
    let sent = answer(&mut c, &sent, "* 4 EXISTS\r\n", "OK [READ-WRITE] done");
    assert_eq!(command(&sent).1, "IDLE");
    let (tag, _) = command(&sent);
    (c, tag)
}

#[test]
fn idle_reports_events_and_finishes_when_told_to_stop() {
    let outcome = Outcome::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let f = idle(&outcome, &events).done_on_event(true);
    let (mut c, tag) = to_idle(&f, "IDLE");
    assert_eq!(c.run("+ idling\r\n"), "");
    let sent = c.run("* 5 EXISTS\r\n");
    assert_eq!(sent, "DONE\r\n", "DONE after the first event");
    assert_eq!(*events.lock().unwrap(), ["exists 5"]);
    let sent = c.run(&format!("{tag} OK idle terminated\r\n"));
    assert_eq!(command(&sent).1, "LOGOUT");
    assert_eq!(*outcome.lock().unwrap(), [true]);
}

#[test]
fn idle_sends_done_only_once() {
    let outcome = Outcome::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let f = idle(&outcome, &events).done_on_event(true);
    let (mut c, _) = to_idle(&f, "IDLE");
    c.run("+ idling\r\n");
    assert_eq!(c.run("* 5 EXISTS\r\n"), "DONE\r\n");
    assert_eq!(c.run("* 6 EXISTS\r\n"), "");
    assert_eq!(*events.lock().unwrap(), ["exists 5", "exists 6"]);
}

#[test]
fn idle_without_done_on_event_keeps_listening() {
    let outcome = Outcome::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let f = idle(&outcome, &events);
    let (mut c, _) = to_idle(&f, "IDLE");
    c.run("+ idling\r\n");
    assert_eq!(c.run("* 5 EXISTS\r\n* 2 EXPUNGE\r\n* 1 FETCH (FLAGS (\\Seen))\r\n"), "");
    assert_eq!(*events.lock().unwrap(), ["exists 5", "expunge 2", "flags 1 \\Seen"]);
    assert!(outcome.lock().unwrap().is_empty());
}

#[test]
fn idle_fails_when_the_server_cannot_idle() {
    let outcome = Outcome::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let f = idle(&outcome, &events);
    let mut c = start(&f);
    let sent = through_capability(&mut c, "");
    let sent = answer(&mut c, &sent, "", "OK");
    let after = answer(&mut c, &sent, "", "OK [READ-WRITE] done");
    assert!(!after.to_ascii_uppercase().contains("IDLE"), "{after:?}");
    assert_eq!(*outcome.lock().unwrap(), [false]);
    assert!(c.is_closed());
}

#[test]
fn idle_fails_when_authentication_or_select_is_refused() {
    let outcome = Outcome::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut c = start(&idle(&outcome, &events));
    let sent = through_capability(&mut c, "IDLE");
    answer(&mut c, &sent, "", "NO bad credentials");
    assert_eq!(*outcome.lock().unwrap(), [false]);

    let outcome = Outcome::default();
    let mut c = start(&idle(&outcome, &events));
    let sent = through_capability(&mut c, "IDLE");
    let sent = answer(&mut c, &sent, "", "OK");
    answer(&mut c, &sent, "", "NO no such mailbox");
    assert_eq!(*outcome.lock().unwrap(), [false]);
}

#[test]
fn idle_authenticates_the_same_ways_fetch_does() {
    let outcome = Outcome::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut c = start(&idle(&outcome, &events));
    let sent = through_capability(&mut c, "AUTH=PLAIN");
    assert_eq!(command(&sent).1, "AUTHENTICATE PLAIN", "no initial response without SASL-IR");
    assert_eq!(c.run("+ \r\n").trim_end(), b64("alice", "s3cret"));

    let mut c = start(&idle(&outcome, &events));
    let sent = through_capability(&mut c, "AUTH=PLAIN SASL-IR");
    assert_eq!(command(&sent).1, format!("AUTHENTICATE PLAIN {}", b64("alice", "s3cret")));

    let mut c = start(&idle(&outcome, &events).prefer_auth_plain(false));
    let sent = through_capability(&mut c, "AUTH=PLAIN SASL-IR");
    assert_eq!(unquote(&command(&sent).1), "LOGIN alice s3cret");
}

#[test]
fn idle_does_not_send_login_when_the_server_disables_it() {
    let outcome = Outcome::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut c = start(&idle(&outcome, &events));
    let sent = through_capability(&mut c, "LOGINDISABLED");
    assert!(!sent.to_ascii_uppercase().contains("LOGIN"), "{sent:?}");
    assert_eq!(*outcome.lock().unwrap(), [false]);
}

#[test]
fn idle_requiring_starttls_fails_without_it_and_asks_with_it() {
    let outcome = Outcome::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut c = start(&idle(&outcome, &events).require_starttls(true));
    let sent = through_capability(&mut c, "AUTH=PLAIN");
    assert_eq!(sent, "");
    assert_eq!(*outcome.lock().unwrap(), [false]);

    let outcome = Outcome::default();
    let mut c = start(&idle(&outcome, &events).require_starttls(true));
    let sent = through_capability(&mut c, "STARTTLS");
    assert_eq!(command(&sent).1, "STARTTLS");
}

#[test]
fn idle_reports_failure_when_the_connection_drops_or_fails() {
    let outcome = Outcome::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let (mut c, _) = to_idle(&idle(&outcome, &events), "IDLE");
    c.disconnect();
    assert_eq!(*outcome.lock().unwrap(), [false]);

    let outcome = Outcome::default();
    let (mut c, _) = to_idle(&idle(&outcome, &events), "IDLE");
    c.fail(&std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset"));
    assert_eq!(*outcome.lock().unwrap(), [false]);
}

#[test]
fn idle_reports_failure_when_the_connection_cannot_be_made() {
    let outcome = Outcome::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let f = idle(&outcome, &events);
    f.connect_failed("imap.example", &std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "no"));
    assert_eq!(*outcome.lock().unwrap(), [false]);
}
