// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The control handler driven end to end, with no sockets: a [`Peer`]
//! stands in for the connection and plays the reactor for the storage pool's
//! callbacks, over a Maildir under a temporary directory.

use std::collections::BTreeSet;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::Ordering;

use hopf_core::testing::Peer;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_mailbox::{AppendGuard, MailboxFactory};

use super::*;
use crate::server::handler::{DefaultPop3HandlerFactory, Pop3HandlerFactory};

/// A message in canonical form (CRLF line ends).
pub(super) fn message(subject: &str, body: &str) -> String {
    format!("From: a@x.org\r\nTo: u@x.org\r\nSubject: {subject}\r\nMessage-ID: <{subject}@x.org>\r\n\r\n{body}")
}

/// One client connected to a handler over a Maildir under a temporary directory.
pub(super) struct Session {
    peer: Peer<Pop3ControlHandler>,
    /// What the server said on connecting.
    pub(super) greeting: String,
    factory: Arc<hopf_mailbox::MaildirFactory>,
    _root: tempfile::TempDir,
}

impl Deref for Session {
    type Target = Peer<Pop3ControlHandler>;
    fn deref(&self) -> &Self::Target {
        &self.peer
    }
}

impl DerefMut for Session {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.peer
    }
}

impl Session {
    /// A session over a mailbox holding `messages`, greeted and waiting.
    pub(super) fn with_messages(messages: &[String]) -> Self {
        Self::with(messages, |config| config)
    }

    pub(super) fn with(messages: &[String], configure: impl FnOnce(Pop3Config) -> Pop3Config) -> Self {
        let root = tempfile::tempdir().unwrap();
        let factory = Arc::new(hopf_mailbox::MaildirFactory::new(root.path()));
        let factory_for_reconnect = Arc::clone(&factory);
        {
            let mut store = factory.create_store();
            store.open("u").unwrap();
            let mut inbox = store.open_mailbox("INBOX", false).unwrap();
            for body in messages {
                let mut guard = AppendGuard::start(inbox.as_mut(), &BTreeSet::new(), None).unwrap();
                guard.append_content(body.as_bytes()).unwrap();
                guard.commit().unwrap();
            }
            inbox.close(false).unwrap();
        }
        let store = Arc::new(hopf_auth::PasswordStore::new().with_user("u", "p"));
        let listen: SocketAddr = "127.0.0.1:1110".parse().unwrap();
        let config = configure(Pop3Config::new(listen, "localhost", store, factory));
        let (peer, greeting) = Self::connect(config);
        Self { peer, greeting, factory: Arc::clone(&factory_for_reconnect), _root: root }
    }

    fn connect(config: Pop3Config) -> (Peer<Pop3ControlHandler>, String) {
        let client = DefaultPop3HandlerFactory::new("ready").create();
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let handler = Pop3ControlHandler::new(client, Pop3ServerMetrics::shared(), config, rt);
        let mut peer = Peer::connect(handler, |h| h.busy.load(Ordering::Relaxed) || !h.cmd_queue.is_empty());
        let greeting = peer.take();
        (peer, greeting)
    }

    /// Drops the connection without a QUIT and connects again to the same mailbox.
    pub(super) fn reconnect(&mut self) {
        self.peer.disconnect();
        let store = Arc::new(hopf_auth::PasswordStore::new().with_user("u", "p"));
        let listen: SocketAddr = "127.0.0.1:1110".parse().unwrap();
        let (peer, greeting) = Self::connect(Pop3Config::new(listen, "localhost", store, self.factory.clone()));
        self.peer = peer;
        self.greeting = greeting;
    }

    /// Logs in as the test user.
    pub(super) fn login(&mut self) {
        let out = self.run("USER u\r\nPASS p\r\n");
        assert!(out.ends_with("+OK Logged in\r\n") || out.lines().last().is_some_and(|l| l.starts_with("+OK")), "{out}");
    }
}

fn b64(bytes: &[u8]) -> String {
    rmimeparser::charset::base64::encode(bytes)
}

/// Replies come back in the order the commands were sent, however they are
/// produced: a listing that goes out after the next command's reply would
/// corrupt it for a client that pipelines.
#[test]
fn pipelined_commands_are_answered_in_order_whatever_they_produce() {
    let msgs = [message("one", "hello\r\n"), message("two", "again\r\n")];
    let mut s = Session::with_messages(&msgs);
    s.login();
    let out = s.run("LIST\r\nNOOP\r\nUIDL\r\nNOOP\r\nSTAT\r\nTOP 1 0\r\nNOOP\r\nRETR 2\r\nNOOP\r\n");
    let lines: Vec<&str> = out.split("\r\n").collect();
    // LIST: header, two rows, terminator; then the NOOP.
    assert_eq!(lines[0], "+OK 2 messages", "{out}");
    assert!(lines[1].starts_with("1 ") && lines[2].starts_with("2 ") && lines[3] == ".", "{out}");
    assert_eq!(lines[4], "+OK", "NOOP after LIST: {out}");
    assert_eq!(lines[5], "+OK Unique-ID listing follows", "{out}");
    assert!(lines[6].starts_with("1 ") && lines[7].starts_with("2 ") && lines[8] == ".", "{out}");
    assert_eq!(lines[9], "+OK", "NOOP after UIDL: {out}");
    assert!(lines[10].starts_with("+OK 2 "), "STAT: {out}");
    assert_eq!(lines[11], "+OK Top of message follows", "{out}");
    let end_top = lines.iter().position(|l| *l == ".").and_then(|_| lines.iter().skip(11).position(|l| *l == ".")).unwrap() + 11;
    assert_eq!(lines[end_top + 1], "+OK", "NOOP after TOP: {out}");
    assert!(lines[end_top + 2].starts_with("+OK ") && lines[end_top + 2].ends_with("octets"), "RETR: {out}");
    assert_eq!(&lines[lines.len() - 2..], ["+OK", ""], "NOOP after RETR is last: {out}");
}

/// RFC 5034: AUTH without an initial response is answered with an empty `+`,
/// and the client's first message is its reply.
#[test]
fn auth_without_an_initial_response_prompts_for_one() {
    let plain = |user: &str, pass: &str| b64(format!("\0{user}\0{pass}").as_bytes());
    let secure = || {
        let mut s = Session::with_messages(&[]);
        s.handler.tls = true;
        s
    };
    let mut s = secure();
    assert_eq!(s.run("AUTH PLAIN\r\n"), "+ \r\n");
    assert_eq!(s.run(&format!("{}\r\n", plain("u", "p"))), "+OK Mailbox opened\r\n");
    assert!(s.run("STAT\r\n").starts_with("+OK 0 0"));

    let mut s = secure();
    assert_eq!(s.run("AUTH PLAIN\r\n"), "+ \r\n");
    assert!(s.run(&format!("{}\r\n", plain("u", "wrong"))).starts_with("-ERR [AUTH]"));
    let delayed = Session::with(&[], |mut c| {
        c.login_delay = std::time::Duration::from_secs(60);
        c
    });
    drop(delayed);

    // Cancelling.
    let mut s = secure();
    assert_eq!(s.run("AUTH PLAIN\r\n"), "+ \r\n");
    assert!(s.run("*\r\n").starts_with("-ERR [AUTH] Authentication cancelled"));
    assert_eq!(s.run("NOOP\r\n"), "+OK\r\n");

    // With the response on the command line, nothing is prompted for.
    let mut s = secure();
    assert_eq!(s.run(&format!("AUTH PLAIN {}\r\n", plain("u", "p"))), "+OK Mailbox opened\r\n");
    let mut s = secure();
    assert!(s.run("AUTH PLAIN =\r\n").starts_with("-ERR [AUTH]"));

    // A mechanism where the server speaks first is unaffected.
    let mut s = secure();
    assert_eq!(s.run("AUTH LOGIN\r\n"), format!("+ {}\r\n", b64(b"Username:")));
    assert_eq!(s.run(&format!("{}\r\n", b64(b"u"))), format!("+ {}\r\n", b64(b"Password:")));
    assert_eq!(s.run(&format!("{}\r\n", b64(b"p"))), "+OK Mailbox opened\r\n");
}

/// A full SCRAM-SHA-256 exchange against the server, with hopf's own client:
/// its final data goes out as a `+`, the client acknowledges it with an empty
/// line, and only then does the command complete (RFC 4422 §3.5).
#[test]
fn scram_sha_256_authenticates_end_to_end() {
    use hopf_auth::{create_client, SaslClientStep, SaslMechanism};
    let decode = |line: &str| rmimeparser::charset::base64::decode(line.trim().trim_start_matches("+ ")).unwrap();
    for initial_response in [true, false] {
        for (password, ok) in [("p", true), ("wrong", false)] {
            let mut client = create_client(SaslMechanism::ScramSha256, "u", password, "localhost", "pop", None);
            let SaslClientStep::Response(first) = client.evaluate(None) else { panic!("client-first") };
            let mut s = Session::with_messages(&[]);
            let out = if initial_response {
                s.run(&format!("AUTH SCRAM-SHA-256 {}\r\n", b64(&first)))
            } else {
                assert_eq!(s.run("AUTH SCRAM-SHA-256\r\n"), "+ \r\n");
                s.run(&format!("{}\r\n", b64(&first)))
            };
            assert!(out.starts_with("+ "), "server-first: {out}");
            let (SaslClientStep::Response(last) | SaslClientStep::Complete(last)) = client.evaluate(Some(&decode(&out))) else {
                panic!("client-final")
            };
            let out = s.run(&format!("{}\r\n", b64(&last)));
            if !ok {
                assert!(out.starts_with("-ERR [AUTH]"), "wrong password: {out}");
                continue;
            }
            assert!(out.starts_with("+ ") && !out.contains("+OK"), "completed before the client acknowledged: {out}");
            assert!(matches!(client.evaluate(Some(&decode(&out))), SaslClientStep::Complete(ref m) if m.is_empty()));
            assert_eq!(s.run("\r\n"), "+OK Mailbox opened\r\n");
            assert!(s.run("STAT\r\n").starts_with("+OK 0 0"), "logged in");
        }
    }
}

/// RFC 3206: an attempt too soon after a failed one is refused with LOGIN-DELAY.
#[test]
fn a_login_too_soon_after_a_failure_is_refused_with_the_login_delay_code() {
    let mut s = Session::with(&[], |mut c| {
        c.login_delay = std::time::Duration::from_secs(60);
        c
    });
    assert_eq!(s.run("USER u\r\nPASS no\r\n"), "+OK User accepted\r\n-ERR [AUTH] Authentication failed\r\n");
    let out = s.run("USER u\r\nPASS p\r\n");
    assert_eq!(out, "+OK User accepted\r\n-ERR [LOGIN-DELAY] Login delay active\r\n");
    assert!(s.run("STAT\r\n").starts_with("-ERR"), "still not logged in");
}

#[test]
fn the_greeting_and_the_commands_that_work_before_login() {
    let mut s = Session::with(&[], |mut c| {
        c.enable_apop = true;
        c
    });
    assert!(s.greeting.starts_with("+OK ready <") && s.greeting.ends_with("@localhost>\r\n"), "{:?}", s.greeting);
    let out = s.run("CAPA\r\n");
    for capability in ["USER", "UIDL", "TOP", "RESP-CODES", "AUTH-RESP-CODE", "IMPLEMENTATION hopf", "UTF8 USER", "APOP", "SASL "] {
        assert!(out.contains(&format!("\r\n{capability}")), "{capability} in {out}");
    }
    assert!(out.starts_with("+OK Capability list follows\r\n") && out.ends_with("\r\n.\r\n"), "{out}");
    assert_eq!(s.run("NOOP\r\n"), "+OK\r\n");
    // What needs a mailbox, or a user, is refused with a reason.
    for command in ["STAT", "LIST", "UIDL", "RETR 1", "TOP 1 1", "DELE 1", "RSET"] {
        assert_eq!(s.run(&format!("{command}\r\n")), "-ERR Command not valid in AUTHORIZATION state\r\n", "{command}");
    }
    assert_eq!(s.run("PASS p\r\n"), "-ERR USER required first\r\n");
    assert_eq!(s.run("USER\r\n"), "-ERR Missing username\r\n");
    assert!(s.run("FROB\r\n").starts_with("-ERR "));
    assert_eq!(s.run("STLS\r\n"), "-ERR TLS not available\r\n");
    assert_eq!(s.run(&format!("USER {}\r\n", "x".repeat(3000))), "-ERR Line too long\r\n");
    assert_eq!(s.run("NOOP\r\n"), "+OK\r\n", "the long line did not disturb the next command");
    // An unknown user is not told apart from a wrong password.
    assert_eq!(s.run("USER nobody\r\n"), "+OK User accepted\r\n");
    assert_eq!(s.run("PASS x\r\n"), "-ERR [AUTH] Authentication failed\r\n");
    // QUIT before logging in just closes.
    assert!(s.run("QUIT\r\n").starts_with("+OK"));
    assert!(s.is_closed());
}

fn numbers(out: &str) -> Vec<String> {
    out.lines().filter(|l| l.chars().next().is_some_and(|c| c.is_ascii_digit())).map(|l| l.split(' ').next().unwrap().to_string()).collect()
}

#[test]
fn stat_list_and_uidl_describe_the_mailbox() {
    let msgs = [message("one", "hello\r\n"), message("two", "second message\r\n"), message("three", "x\r\n")];
    let mut s = Session::with_messages(&msgs);
    s.login();
    let total: usize = msgs.iter().map(String::len).sum();
    assert_eq!(s.run("STAT\r\n"), format!("+OK 3 {total}\r\n"));
    let out = s.run("LIST\r\n");
    assert!(out.starts_with("+OK 3 messages\r\n") && out.ends_with("\r\n.\r\n"), "{out}");
    assert_eq!(numbers(&out), ["1", "2", "3"]);
    for (i, m) in msgs.iter().enumerate() {
        assert!(out.contains(&format!("\r\n{} {}\r\n", i + 1, m.len())), "{out}");
        assert_eq!(s.run(&format!("LIST {}\r\n", i + 1)), format!("+OK {} {}\r\n", i + 1, m.len()));
    }
    let out = s.run("UIDL\r\n");
    assert!(out.starts_with("+OK Unique-ID listing follows\r\n") && out.ends_with("\r\n.\r\n"), "{out}");
    let uids: Vec<&str> = out.lines().filter(|l| l.starts_with(|c: char| c.is_ascii_digit())).map(|l| l.split(' ').nth(1).unwrap()).collect();
    assert_eq!(uids.len(), 3);
    assert!(uids.iter().all(|u| !u.is_empty() && u.len() <= 70 && u.bytes().all(|b| (0x21..=0x7e).contains(&b))), "RFC 1939 unique-ids: {uids:?}");
    assert_eq!(uids.iter().collect::<std::collections::BTreeSet<_>>().len(), 3, "distinct");
    assert_eq!(s.run("UIDL 2\r\n"), format!("+OK 2 {}\r\n", uids[1]));
    // The unique-id is the same on the next connection.
    s.reconnect();
    s.login();
    assert!(s.run("UIDL\r\n").contains(uids[0]));
    // Wrong numbers.
    for command in ["LIST 9", "UIDL 9", "RETR 9", "TOP 9 1", "DELE 9"] {
        assert_eq!(s.run(&format!("{command}\r\n")), "-ERR No such message\r\n", "{command}");
    }
    for command in ["RETR", "RETR x", "RETR 0", "TOP 1", "TOP 1 x", "TOP x 1", "DELE", "DELE x"] {
        let out = s.run(&format!("{command}\r\n"));
        assert!(out.starts_with("-ERR "), "{command}: {out}");
    }
    // (An argument to LIST or UIDL that is not a message number is taken as none: a
    // deliberate leniency of the lexer, tested there.)
}

#[test]
fn retr_sends_the_message_dot_stuffed_with_crlf_line_ends() {
    let crlf = message("crlf", "first\r\n.starts with a dot\r\n.\r\n..two dots\r\nlast\r\n");
    let lf = "Subject: lf\n\nbody\n.dot\n.\nafter\n".to_string();
    let bare = message("bare", "no newline at the end");
    let mut s = Session::with_messages(&[crlf.clone(), lf, bare]);
    s.login();
    let out = s.run("RETR 1\r\n");
    let (head, body) = out.split_once("\r\n").unwrap();
    assert_eq!(head, format!("+OK {} octets", crlf.len()));
    let want = crlf.replace("\r\n.", "\r\n..");
    assert_eq!(body, format!("{want}.\r\n"), "dot-stuffed, and the lone dot is doubled too");
    // A message stored with bare LF is sent with CRLF; one with no final newline gets one.
    let out = s.run("RETR 2\r\n");
    assert!(out.ends_with("Subject: lf\r\n\r\nbody\r\n..dot\r\n..\r\nafter\r\n.\r\n"), "{out:?}");
    assert!(!out.replace("\r\n", "").contains('\n'), "no bare LF is sent: {out:?}");
    let out = s.run("RETR 3\r\n");
    assert!(out.ends_with("no newline at the end\r\n.\r\n"), "{out:?}");
}

#[test]
fn retr_streams_a_message_larger_than_any_buffer_in_one_piece() {
    let mut body = String::new();
    for i in 0..30_000 {
        body.push_str(&format!("line {i} of a long message\r\n"));
        if i % 1000 == 0 {
            body.push_str(".a line that starts with a dot\r\n");
        }
    }
    let m = message("big", &body);
    let mut s = Session::with_messages(&[m.clone()]);
    s.login();
    let out = s.run("RETR 1\r\n");
    assert!(out.starts_with(&format!("+OK {} octets\r\n", m.len())), "{}", &out[..60]);
    assert!(out.ends_with("\r\n.\r\n") && !out.ends_with("\r\n\r\n.\r\n"));
    assert_eq!(out.matches("\r\n..a line").count(), 30, "every dot-line doubled once");
    assert!(out.contains("line 29999 of a long message\r\n"), "the end arrived");
    assert_eq!(s.run("NOOP\r\n"), "+OK\r\n", "and the connection goes on");
}

#[test]
fn top_returns_the_headers_and_the_first_lines_of_the_body() {
    let m = message("t", "l1\r\nl2\r\nl3\r\n");
    let mut s = Session::with_messages(&[m.clone()]);
    s.login();
    let headers = &m[..m.find("\r\n\r\n").unwrap() + 4];
    assert_eq!(s.run("TOP 1 0\r\n"), format!("+OK Top of message follows\r\n{headers}.\r\n"));
    assert_eq!(s.run("TOP 1 2\r\n"), format!("+OK Top of message follows\r\n{headers}l1\r\nl2\r\n.\r\n"));
    assert_eq!(s.run("TOP 1 99\r\n"), format!("+OK Top of message follows\r\n{headers}l1\r\nl2\r\nl3\r\n.\r\n"));
    s.run("DELE 1\r\n");
    assert_eq!(s.run("TOP 1 1\r\n"), "-ERR Message deleted\r\n");
}

#[test]
fn dele_hides_a_message_rset_brings_it_back_and_only_quit_removes_it() {
    let msgs = [message("a", "1\r\n"), message("b", "2\r\n"), message("c", "3\r\n")];
    let mut s = Session::with_messages(&msgs);
    s.login();
    assert_eq!(s.run("DELE 2\r\n"), "+OK Message marked for deletion\r\n");
    assert_eq!(s.run("DELE 2\r\n"), "-ERR Message already deleted\r\n");
    for command in ["RETR 2", "TOP 2 1", "LIST 2", "UIDL 2"] {
        assert_eq!(s.run(&format!("{command}\r\n")), "-ERR Message deleted\r\n", "{command}");
    }
    let out = s.run("LIST\r\n");
    assert!(out.starts_with("+OK 2 messages\r\n") && numbers(&out) == ["1", "3"], "numbers do not shift: {out}");
    assert_eq!(numbers(&s.run("UIDL\r\n")), ["1", "3"]);
    assert_eq!(s.run("STAT\r\n"), format!("+OK 2 {}\r\n", msgs[0].len() + msgs[2].len()));
    assert!(s.run("RSET\r\n").starts_with("+OK "));
    assert_eq!(s.run("STAT\r\n"), format!("+OK 3 {}\r\n", msgs.iter().map(String::len).sum::<usize>()));
    assert!(s.run("RETR 2\r\n").starts_with("+OK "));

    // Dropping the connection without QUIT removes nothing.
    s.run("DELE 1\r\nDELE 3\r\n");
    s.reconnect();
    s.login();
    assert!(s.run("STAT\r\n").starts_with("+OK 3 "), "nothing was removed without QUIT");

    // QUIT enters the UPDATE state and removes what was marked.
    s.run("DELE 1\r\nDELE 3\r\n");
    assert!(s.run("QUIT\r\n").starts_with("+OK "));
    assert!(s.is_closed());
    s.reconnect();
    s.login();
    assert_eq!(numbers(&s.run("LIST\r\n")), ["1"], "only the middle message is left");
    assert!(s.run("RETR 1\r\n").contains("Subject: b"));
    // A QUIT with nothing marked changes nothing.
    assert!(s.run("QUIT\r\n").starts_with("+OK "));
    s.reconnect();
    s.login();
    assert!(s.run("STAT\r\n").starts_with("+OK 1 "));
}

#[test]
fn commands_that_are_for_the_authorization_state_are_refused_once_logged_in() {
    let mut s = Session::with_messages(&[]);
    s.login();
    for command in ["USER u", "PASS p", "APOP u 00000000000000000000000000000000", "AUTH", "AUTH PLAIN x"] {
        assert_eq!(s.run(&format!("{command}\r\n")), "-ERR Already authenticated\r\n", "{command}");
    }
    assert_eq!(s.run("STLS\r\n"), "-ERR STLS only valid in AUTHORIZATION state\r\n");
    assert_eq!(s.run("UTF8\r\n"), "-ERR UTF8 only valid in AUTHORIZATION state\r\n");
    assert_eq!(s.run("NOOP\r\n"), "+OK\r\n");
    assert!(s.run("CAPA\r\n").starts_with("+OK "));
}

#[test]
fn a_message_with_non_ascii_headers_needs_utf8_mode() {
    let cafe = "Subject: caf\u{e9}\r\nFrom: a@x.org\r\n\r\nbody\r\n".to_string();
    let plain = message("plain", "x\r\n");
    let mut s = Session::with_messages(&[plain.clone(), cafe.clone()]);
    s.login();
    assert!(s.run("RETR 1\r\n").starts_with("+OK "));
    for command in ["RETR 2", "TOP 2 0", "LIST 2"] {
        let out = s.run(&format!("{command}\r\n"));
        assert!(out.starts_with("-ERR [UTF8] UTF8 mode required"), "{command}: {out}");
    }
    // Enabled before the login (RFC 6856 §2), the same message is available.
    let mut s = Session::with_messages(&[plain, cafe.clone()]);
    assert_eq!(s.run("UTF8\r\n"), "+OK UTF8 mode enabled\r\n");
    s.login();
    let out = s.run("RETR 2\r\n");
    assert!(out.contains("Subject: caf\u{e9}\r\n") && out.starts_with(&format!("+OK {} octets", cafe.len())), "{out}");
    assert!(s.run("LIST 2\r\n").starts_with("+OK 2 "));
}

/// APOP needs a store that can recover the password; `PasswordStore` keeps none.
struct RecoverableStore(hopf_auth::PasswordStore);

impl hopf_auth::CredentialStore for RecoverableStore {
    fn password_match(&self, username: &str, password: &str) -> bool {
        self.0.password_match(username, password)
    }
    fn plaintext_password(&self, username: &str) -> Option<String> {
        (username == "u").then(|| "p".to_string())
    }
    fn digest_ha1(&self, username: &str, realm: &str) -> Option<String> {
        self.0.digest_ha1(username, realm)
    }
    fn scram_credentials(&self, username: &str) -> Option<hopf_auth::store::ScramCredentials> {
        self.0.scram_credentials(username)
    }
}

fn apop_session() -> Session {
    Session::with(&[], |mut c| {
        c.enable_apop = true;
        c.store = Arc::new(RecoverableStore(hopf_auth::PasswordStore::new().with_user("u", "p")));
        c
    })
}

#[test]
fn apop_authenticates_with_the_greeting_s_timestamp() {
    let mut s = apop_session();
    let timestamp = s.greeting.trim().rsplit(' ').next().unwrap().to_string();
    assert!(timestamp.starts_with('<') && timestamp.ends_with('>'), "{timestamp}");
    let digest = hopf_auth::crypto::md5_hex(format!("{timestamp}p").as_bytes());
    assert_eq!(s.run(&format!("APOP u {digest}\r\n")), "+OK Mailbox opened\r\n");
    assert!(s.run("STAT\r\n").starts_with("+OK 0 0"));

    let mut s = apop_session();
    let timestamp = s.greeting.trim().rsplit(' ').next().unwrap().to_string();
    let wrong = hopf_auth::crypto::md5_hex(format!("{timestamp}nope").as_bytes());
    assert_eq!(s.run(&format!("APOP u {wrong}\r\n")), "-ERR [AUTH] Authentication failed\r\n");
    // A digest for another timestamp (a replay) is no good.
    let replay = hopf_auth::crypto::md5_hex(b"<other@localhost>p");
    assert_eq!(s.run(&format!("APOP u {replay}\r\n")), "-ERR [AUTH] Authentication failed\r\n");
    // A store that cannot recover the password cannot do APOP, and says it failed.
    let mut s = Session::with(&[], |mut c| {
        c.enable_apop = true;
        c
    });
    let timestamp = s.greeting.trim().rsplit(' ').next().unwrap().to_string();
    let digest = hopf_auth::crypto::md5_hex(format!("{timestamp}p").as_bytes());
    assert_eq!(s.run(&format!("APOP u {digest}\r\n")), "-ERR [AUTH] Authentication failed\r\n");
    // Without APOP enabled the greeting has no timestamp and the command is refused.
    let mut off = Session::with(&[], |mut c| {
        c.enable_apop = false;
        c
    });
    assert!(!off.greeting.contains('<'), "{:?}", off.greeting);
    assert_eq!(off.run("APOP u 00000000000000000000000000000000\r\n"), "-ERR APOP not available\r\n");
    assert!(!off.run("CAPA\r\n").contains("\r\nAPOP\r\n"));
}

#[test]
fn input_split_anywhere_makes_the_same_replies() {
    let msgs = [message("a", "one\r\n.two\r\n"), message("b", "three\r\n")];
    let script = "CAPA\r\nUSER u\r\nPASS p\r\nSTAT\r\nLIST\r\nUIDL\r\nTOP 1 1\r\nRETR 2\r\nDELE 1\r\nRSET\r\nNOOP\r\nQUIT\r\n";
    let normalise = |out: String| -> Vec<String> {
        // (The unique-ids carry a time; the greeting timestamp is not part of it.)
        out.lines().map(|l| if l.len() > 20 && l.contains(".local,S=") || l.contains("groenendael") { "UID".to_string() } else { l.to_string() }).collect()
    };
    let mut whole = Session::with_messages(&msgs);
    let want = normalise(whole.run(script));
    assert!(want.iter().any(|l| l.starts_with("+OK Goodbye")), "{want:?}");
    for chunk in [1, 2, 3, 7] {
        let mut s = Session::with_messages(&msgs);
        let got = normalise(s.run_chunked(script, chunk));
        assert_eq!(got.len(), want.len(), "chunk={chunk}: {got:?}");
        for (g, w) in got.iter().zip(&want) {
            // Sizes and timestamps differ between mailboxes; shapes do not.
            assert_eq!(g.split(' ').next(), w.split(' ').next(), "chunk={chunk}: {g:?} vs {w:?}");
        }
    }
}
