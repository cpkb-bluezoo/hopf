// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The control handler driven end to end, with no sockets: a recording
//! endpoint stands in for the connection, and a backend for its `ConnHandle`
//! queues the callbacks that storage workers post, so the test can run them
//! against the endpoint the way the reactor does.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{
    ConnHandle, ConnHandleBackend, Endpoint, LoopBuf, PeerAddr, ProtocolHandler, Runtime, RuntimeConfig,
    SecurityInfo, StartTlsError, TimerHandle, WriteReadyCallback,
};

use super::*;
use crate::server::handler::{DefaultImapHandlerFactory, ImapHandlerFactory};

type Job = Box<dyn FnOnce(&mut dyn Endpoint) + Send>;

/// What the connection saw, shared between the endpoint and its handle.
#[derive(Default)]
struct Wire {
    out: Mutex<Vec<u8>>,
    jobs: Mutex<VecDeque<Job>>,
    poked: AtomicBool,
    paused: AtomicBool,
    closed: AtomicBool,
}

struct Backend(Arc<Wire>);

impl ConnHandleBackend for Backend {
    fn with_endpoint(&self, task: Job) {
        self.0.jobs.lock().unwrap().push_back(task);
    }

    fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        task();
    }

    fn is_probably_open(&self) -> bool {
        !self.0.closed.load(Ordering::Relaxed)
    }

    fn schedule_timer(&self, _delay: Duration, _callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        TimerHandle::from_cancel(|| {})
    }
}

struct TestEndpoint(Arc<Wire>);

impl Endpoint for TestEndpoint {
    fn send(&mut self, data: &[u8]) {
        self.0.out.lock().unwrap().extend_from_slice(data);
    }
    fn is_open(&self) -> bool {
        !self.0.closed.load(Ordering::Relaxed)
    }
    fn is_closing(&self) -> bool {
        self.0.closed.load(Ordering::Relaxed)
    }
    fn close(&mut self) {
        self.0.closed.store(true, Ordering::Relaxed);
    }
    fn local_addr(&self) -> io::Result<PeerAddr> {
        Ok(PeerAddr::Inet("127.0.0.1:143".parse().unwrap()))
    }
    fn remote_addr(&self) -> io::Result<PeerAddr> {
        Ok(PeerAddr::Inet("127.0.0.1:9999".parse().unwrap()))
    }
    fn security_info(&self) -> &SecurityInfo {
        static PLAINTEXT: std::sync::OnceLock<SecurityInfo> = std::sync::OnceLock::new();
        PLAINTEXT.get_or_init(SecurityInfo::plaintext)
    }
    fn start_tls(&mut self) -> Result<(), StartTlsError> {
        Err(StartTlsError::Unsupported)
    }
    fn pause_read(&mut self) {
        self.0.paused.store(true, Ordering::Relaxed);
    }
    fn resume_read(&mut self) {
        self.0.paused.store(false, Ordering::Relaxed);
    }
    fn on_write_ready(&mut self, _callback: Option<WriteReadyCallback>) {}
    fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        task();
    }
    fn schedule_timer(&self, _delay: Duration, _callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        TimerHandle::from_cancel(|| {})
    }
    fn handle(&self) -> ConnHandle {
        ConnHandle::from_backend(Arc::new(Backend(Arc::clone(&self.0))))
    }
    fn poke_handler(&mut self) {
        self.0.poked.store(true, Ordering::Relaxed);
    }
}

/// One client connected to a handler over a Maildir under a temporary directory.
pub(super) struct Session {
    h: ImapControlHandler,
    ep: TestEndpoint,
    wire: Arc<Wire>,
    input: LoopBuf,
    /// What the server said on connecting.
    pub(super) greeting: String,
    /// The Maildir root, kept for the session's life.
    _root: tempfile::TempDir,
}

impl Session {
    /// A session with every optional extension on, greeted and waiting.
    pub(super) fn new() -> Self {
        Self::with(|config| config)
    }

    pub(super) fn with(configure: impl FnOnce(ImapConfig) -> ImapConfig) -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(hopf_auth::PasswordStore::new().with_user("u", "p"));
        let factory = Arc::new(hopf_mailbox::MaildirFactory::new(root.path()));
        let listen: SocketAddr = "127.0.0.1:1143".parse().unwrap();
        let mut config = ImapConfig::new(listen, "localhost", store, factory);
        config.enable_sort = true;
        config.enable_thread_ordered_subject = true;
        config.enable_thread_references = true;
        config.enable_quota = true;
        config.enable_move = true;
        config.enable_metadata = true;
        config.enable_notify = true;
        config.enable_condstore = true;
        let config = configure(config);
        let client = DefaultImapHandlerFactory::new("ready").create();
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let h = ImapControlHandler::new(client, config, rt, ImapServerMetrics::shared());
        let wire = Arc::new(Wire::default());
        let mut session = Self { h, ep: TestEndpoint(Arc::clone(&wire)), wire, input: LoopBuf::with_capacity(1 << 20), greeting: String::new(), _root: root };
        session.h.connected(&mut session.ep);
        session.pump();
        session.greeting = session.take();
        session
    }

    /// Everything the server has written since the last call.
    pub(super) fn take(&mut self) -> String {
        String::from_utf8_lossy(&std::mem::take(&mut *self.wire.out.lock().unwrap())).into_owned()
    }

    /// Sends `wire` and returns what the server answered by the time it is idle.
    pub(super) fn run(&mut self, wire: &str) -> String {
        self.input.extend_from_slice(wire.as_bytes());
        self.pump();
        self.take()
    }

    /// Sends `wire` in chunks of `chunk` bytes, waiting for idle after each.
    pub(super) fn run_chunked(&mut self, wire: &str, chunk: usize) -> String {
        for piece in wire.as_bytes().chunks(chunk) {
            self.input.extend_from_slice(piece);
            self.pump();
        }
        self.take()
    }

    pub(super) fn is_closed(&self) -> bool {
        self.wire.closed.load(Ordering::Relaxed)
    }

    /// Plays the reactor until the handler has nothing left to do.
    fn pump(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            loop {
                let job = self.wire.jobs.lock().unwrap().pop_front();
                match job {
                    Some(job) => job(&mut self.ep),
                    None => break,
                }
            }
            let poked = self.wire.poked.swap(false, Ordering::Relaxed);
            let paused = self.wire.paused.load(Ordering::Relaxed);
            if poked || (!paused && !self.input.is_empty()) {
                self.h.receive(&mut self.ep, &mut self.input);
                continue;
            }
            let working = self.h.busy.load(Ordering::Relaxed)
                || !self.h.cmd_queue.is_empty()
                || !self.wire.jobs.lock().unwrap().is_empty();
            if !working {
                return;
            }
            assert!(Instant::now() < deadline, "the handler never went idle; output so far: {:?}", self.take());
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Logs in as the test user.
    pub(super) fn login(&mut self) {
        let out = self.run("l LOGIN u p\r\n");
        assert!(out.contains("l OK"), "{out}");
    }

    /// Appends `body` to `mailbox` with `flags` (`"\\Seen"`, or `""`), and
    /// returns the server's answer.
    pub(super) fn append(&mut self, mailbox: &str, flags: &str, body: &str) -> String {
        let flags = if flags.is_empty() { String::new() } else { format!(" ({flags})") };
        self.run(&format!("ap APPEND {mailbox}{flags} {{{}}}\r\n{body}\r\n", body.len()))
    }

    /// Logs in and puts `messages` in the INBOX, then selects it.
    pub(super) fn with_inbox(messages: &[(&str, &str)]) -> Self {
        let mut s = Self::new();
        s.login();
        for (flags, body) in messages {
            let out = s.append("INBOX", flags, body);
            assert!(out.contains("ap OK [APPENDUID"), "{out}");
        }
        let out = s.run("sel SELECT INBOX\r\n");
        assert!(out.contains("sel OK [READ-WRITE]"), "{out}");
        s
    }
}

/// A message in canonical form (CRLF line ends).
pub(super) fn message(subject: &str, from: &str, to: &str, date: &str, body: &str) -> String {
    format!("Date: {date}\r\nSubject: {subject}\r\nFrom: {from}\r\nTo: {to}\r\nMessage-ID: <{subject}@x.org>\r\n\r\n{body}")
}

/// The lines of `out` that begin with `prefix`.
fn lines<'a>(out: &'a str, prefix: &str) -> Vec<&'a str> {
    out.lines().filter(|l| l.starts_with(prefix)).collect()
}

/// The tagged status line of `tag` in `out`.
fn status<'a>(out: &'a str, tag: &str) -> &'a str {
    out.lines().find(|l| l.starts_with(&format!("{tag} "))).unwrap_or_else(|| panic!("no {tag} line in {out:?}"))
}

const ALICE: &str = "Mon, 1 Jan 2024 10:00:00 +0000";
const BOB: &str = "Tue, 2 Jan 2024 10:00:00 +0000";


#[test]
fn before_login_only_the_open_commands_work() {
    let mut s = Session::new();
    assert_eq!(
        s.greeting,
        "* OK [CAPABILITY IMAP4rev2 AUTH=SCRAM-SHA-256 UNSELECT UIDPLUS CHILDREN LIST-EXTENDED LIST-STATUS LITERAL- ID ENABLE] ready\r\n"
    );
    let out = s.run("a1 CAPABILITY\r\na2 NOOP\r\n");
    assert!(out.starts_with("* CAPABILITY IMAP4rev2 "), "{out}");
    assert!(out.contains("a1 OK CAPABILITY completed\r\n") && out.contains("a2 OK NOOP completed\r\n"), "{out}");
    for command in ["LIST \"\" *", "SELECT INBOX", "FETCH 1 FLAGS", "STATUS INBOX (MESSAGES)", "CREATE x", "NAMESPACE"] {
        let out = s.run(&format!("x {command}\r\n"));
        let line = status(&out, "x");
        assert!(line.starts_with("x NO ") || line.starts_with("x BAD "), "{command}: {out}");
    }
    assert!(status(&s.run("b LOGIN u wrong\r\n"), "b").starts_with("b NO "));
    assert!(status(&s.run("c LOGIN nobody p\r\n"), "c").starts_with("c NO "));
    assert!(status(&s.run("d FROB\r\n"), "d").starts_with("d BAD Unknown command FROB"));
    assert!(status(&s.run("e LOGIN u\r\n"), "e").starts_with("e BAD "));
    let out = s.run("f LOGIN u p\r\n");
    assert!(status(&out, "f").starts_with("f OK [CAPABILITY IMAP4rev2 IDLE NAMESPACE QUOTA MOVE "), "{out}");
    assert!(!s.is_closed());
}

#[test]
fn logout_says_goodbye_and_closes() {
    let mut s = Session::new();
    s.login();
    let out = s.run("z LOGOUT\r\n");
    assert_eq!(out, "* BYE Logging out\r\nz OK LOGOUT completed\r\n");
    assert!(s.is_closed());
}

#[test]
fn arguments_that_are_wrong_are_refused_and_the_session_goes_on() {
    let mut s = Session::new();
    s.login();
    let out = s.run("a COPY x\r\nb FETCH\r\nc STORE 1 FLAGS\r\nd LIST\r\ne SEARCH (\r\nf UID FROB\r\ng NOOP\r\n");
    for tag in ["a", "b", "c", "d", "e", "f"] {
        assert!(status(&out, tag).starts_with(&format!("{tag} BAD ")), "{tag}: {out}");
    }
    assert!(status(&out, "g").starts_with("g OK "), "{out}");
}

#[test]
fn mailbox_management() {
    let mut s = Session::new();
    s.login();
    assert!(status(&s.run("a CREATE Work\r\n"), "a").starts_with("a OK "));
    assert!(status(&s.run("b CREATE Work\r\n"), "b").starts_with("b NO "), "creating twice is refused");
    assert!(status(&s.run("c CREATE Work/Reports\r\n"), "c").starts_with("c OK "));

    let out = s.run("d LIST \"\" *\r\n");
    let listed = lines(&out, "* LIST");
    assert!(listed.iter().any(|l| l.ends_with(" INBOX")), "{out}");
    assert!(listed.iter().any(|l| l.ends_with(" Work")), "{out}");
    assert!(listed.iter().any(|l| l.ends_with(" Work/Reports")), "{out}");
    assert!(status(&out, "d").starts_with("d OK "));

    let out = s.run("e LIST \"\" \"Work/%\"\r\n");
    assert_eq!(lines(&out, "* LIST").len(), 1, "{out}");
    let out = s.run("e2 LIST \"\" Work\r\n");
    assert_eq!(lines(&out, "* LIST").len(), 1, "an exact name matches itself only: {out}");

    // Extended LIST: selection and return options.
    let out = s.run("f LIST (SUBSCRIBED) \"\" * RETURN (CHILDREN)\r\n");
    assert!(status(&out, "f").starts_with("f OK "), "{out}");

    assert!(status(&s.run("g SUBSCRIBE Work\r\n"), "g").starts_with("g OK "));
    let out = s.run("h LSUB \"\" *\r\n");
    assert!(lines(&out, "* LSUB").iter().any(|l| l.ends_with(" Work")), "{out}");
    assert!(status(&s.run("i UNSUBSCRIBE Work\r\n"), "i").starts_with("i OK "));

    assert!(status(&s.run("j RENAME Work Play\r\n"), "j").starts_with("j OK "));
    let out = s.run("k LIST \"\" *\r\n");
    assert!(lines(&out, "* LIST").iter().any(|l| l.ends_with(" Play")), "{out}");
    assert!(!lines(&out, "* LIST").iter().any(|l| l.contains(" Work")), "{out}");

    // RENAME took the mailbox beneath it along.
    assert!(lines(&out, "* LIST").iter().any(|l| l.ends_with(" Play/Reports")), "{out}");
    assert!(status(&s.run("l DELETE Play/Reports\r\n"), "l").starts_with("l OK "));
    assert!(status(&s.run("m DELETE Play\r\n"), "m").starts_with("m OK "));
    assert!(status(&s.run("n DELETE Play\r\n"), "n").starts_with("n NO "), "gone");
    assert!(status(&s.run("o RENAME Nope Else\r\n"), "o").starts_with("o NO "));
    assert!(status(&s.run("p SELECT Nope\r\n"), "p").starts_with("p NO "));
}

#[test]
fn status_and_namespace() {
    let mut s = Session::new();
    s.login();
    let body = message("one", "a@x.org", "u@x.org", ALICE, "hello");
    s.append("INBOX", "", &body);
    s.append("INBOX", "\\Seen", &message("two", "b@x.org", "u@x.org", BOB, "again"));
    let out = s.run("a STATUS INBOX (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)\r\n");
    let line = lines(&out, "* STATUS")[0];
    assert!(line.starts_with("* STATUS INBOX ("), "{out}");
    for item in ["MESSAGES 2", "UNSEEN 1", "UIDNEXT 3", "UIDVALIDITY "] {
        assert!(line.contains(item), "{item}: {out}");
    }
    assert!(status(&out, "a").starts_with("a OK "));
    assert!(status(&s.run("b STATUS Nope (MESSAGES)\r\n"), "b").starts_with("b NO "));
    assert!(status(&s.run("c STATUS INBOX (FROB)\r\n"), "c").starts_with("c BAD "));
    let out = s.run("d NAMESPACE\r\n");
    assert!(out.starts_with("* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n"), "{out}");
    // LIST-STATUS: STATUS returned with each LIST entry.
    let out = s.run("e LIST \"\" INBOX RETURN (STATUS (MESSAGES))\r\n");
    assert!(out.contains("* STATUS INBOX (MESSAGES 2)"), "{out}");
}

#[test]
fn append_select_and_fetch() {
    let m1 = message("one", "Alice <a@x.org>", "u@x.org", ALICE, "hello world\r\n");
    let m2 = message("two", "Bob <b@x.org>", "u@x.org", BOB, "second body\r\n");
    let mut s = Session::with_inbox(&[("\\Seen", &m1), ("", &m2)]);

    // SELECT's report.
    let out = s.run("a SELECT INBOX\r\n");
    assert!(out.contains("* 2 EXISTS\r\n"), "{out}");
    assert!(out.contains("* FLAGS ("), "{out}");
    assert!(out.contains("[UIDVALIDITY "), "{out}");
    assert!(out.contains("[UIDNEXT 3]"), "{out}");
    assert!(status(&out, "a").starts_with("a OK [READ-WRITE]"), "{out}");

    // Plain attributes.
    let out = s.run("b FETCH 1:2 (FLAGS UID RFC822.SIZE)\r\n");
    let rows = lines(&out, "* ");
    assert!(rows[0].starts_with("* 1 FETCH (FLAGS (\\Seen) UID 1 RFC822.SIZE "), "{out}");
    assert!(rows[1].starts_with("* 2 FETCH (FLAGS () UID 2 RFC822.SIZE ") || rows[1].contains("UID 2"), "{out}");
    assert!(rows[0].contains(&format!("RFC822.SIZE {}", m1.len())), "{out}");

    // A literal body, a header subset, a partial range, the text.
    let out = s.run("c FETCH 1 BODY.PEEK[]\r\n");
    assert!(out.contains(&format!("BODY[] {{{}}}\r\n{m1}", m1.len())), "{out}");
    let out = s.run("d FETCH 1 BODY.PEEK[HEADER.FIELDS (Subject From)]\r\n");
    assert!(out.contains("Subject: one\r\n") && out.contains("From: Alice <a@x.org>\r\n"), "{out}");
    assert!(!out.contains("Message-ID"), "{out}");
    let out = s.run("e FETCH 1 BODY.PEEK[TEXT]<0.5>\r\n");
    assert!(out.contains("BODY[TEXT]<0> {5}\r\nhello"), "{out}");
    let out = s.run("f FETCH 2 BODY.PEEK[HEADER]\r\n");
    assert!(out.contains("Subject: two\r\n") && !out.contains("second body"), "{out}");

    // BODY[] without PEEK marks the message seen.
    let out = s.run("g FETCH 2 BODY[TEXT]\r\n");
    assert!(out.contains("second body"), "{out}");
    let out = s.run("h FETCH 2 FLAGS\r\n");
    assert!(out.contains("FLAGS (\\Seen)"), "{out}");

    // The structured items.
    let out = s.run("i FETCH 1 (ENVELOPE BODYSTRUCTURE)\r\n");
    assert!(out.contains("ENVELOPE (\"Mon, 1 Jan 2024 10:00:00 +0000\" \"one\" ((\"Alice\" NIL \"a\" \"x.org\"))"), "{out}");
    assert!(out.contains("BODYSTRUCTURE (\"TEXT\" \"PLAIN\""), "{out}");

    // By UID, and by a range that has a hole.
    let out = s.run("j UID FETCH 2 (UID FLAGS)\r\n");
    assert!(out.contains("* 2 FETCH (UID 2 FLAGS (\\Seen)"), "{out}");
    let out = s.run("k UID FETCH 1:* UID\r\n");
    assert_eq!(lines(&out, "* ").len(), 2, "{out}");
    let out = s.run("l FETCH 5 FLAGS\r\n");
    assert!(status(&out, "l").starts_with("l NO ") || status(&out, "l").starts_with("l BAD ") || lines(&out, "* ").is_empty(), "{out}");

    // Wrong requests.
    for bad in ["FETCH 1 BODY[]<0.0>", "FETCH 1 (FLAGS", "FETCH x FLAGS", "FETCH 1 FLAGS UID"] {
        let out = s.run(&format!("z {bad}\r\n"));
        assert!(status(&out, "z").starts_with("z BAD "), "{bad}: {out}");
    }
}

/// A client that has not logged in must not be able to make the server write
/// its literal to disk: the body of an APPEND is spooled as it arrives, before
/// the command itself is dispatched and refused.
#[test]
fn an_append_before_login_is_refused_and_nothing_is_spooled() {
    let mut s = Session::new();
    let out = s.run("x APPEND INBOX {5}\r\nhello\r\n");
    assert!(out.contains("x NO Not authenticated"), "{out}");
    assert!(s.h.pending_append_path.is_none(), "a spool file was kept: {:?}", s.h.pending_append_path);
    assert!(s.h.append_spool.lock().unwrap().path.is_none());
    // And the connection is still usable afterwards.
    assert!(status(&s.run("y NOOP\r\n"), "y").starts_with("y OK "));
}

/// Three messages: from Alice (seen, subject "alpha"), Bob ("beta"), Carol ("gamma").
fn three() -> Session {
    let a = message("alpha", "Alice <a@x.org>", "u@x.org", ALICE, "the quick brown fox\r\n");
    let b = message("beta", "Bob <b@x.org>", "u@x.org", BOB, "jumps over\r\n");
    let c = message("Re: alpha", "Carol <c@x.org>", "u@x.org", "Wed, 3 Jan 2024 10:00:00 +0000", "the lazy dog\r\n");
    Session::with_inbox(&[("\\Seen", &a), ("", &b), ("\\Flagged", &c)])
}

#[test]
fn store_changes_flags_and_reports_them() {
    let mut s = three();
    let out = s.run("a STORE 2 +FLAGS (\\Seen \\Answered)\r\n");
    assert!(out.contains("* 2 FETCH (FLAGS (\\Answered \\Seen)") || out.contains("* 2 FETCH (FLAGS (\\Seen \\Answered)"), "{out}");
    assert!(status(&out, "a").starts_with("a OK "));
    let out = s.run("b STORE 2 -FLAGS (\\Seen)\r\n");
    assert!(out.contains("* 2 FETCH (FLAGS (\\Answered)"), "{out}");
    let out = s.run("c STORE 2 FLAGS (\\Draft)\r\n");
    assert!(out.contains("* 2 FETCH (FLAGS (\\Draft)"), "{out}");
    // .SILENT says nothing, but still changes them.
    let out = s.run("d STORE 2 FLAGS.SILENT (\\Deleted)\r\n");
    assert!(lines(&out, "* ").is_empty(), "{out}");
    assert!(s.run("e FETCH 2 FLAGS\r\n").contains("FLAGS (\\Deleted)"));
    // Keywords, by number and by UID, across a range.
    let out = s.run("f STORE 1:3 +FLAGS ($Important)\r\n");
    assert_eq!(lines(&out, "* ").len(), 3, "{out}");
    assert!(out.contains("$Important"), "{out}");
    let out = s.run("g UID STORE 3 -FLAGS ($Important)\r\n");
    assert!(out.contains("* 3 FETCH (FLAGS (\\Flagged) UID 3"), "{out}");
    // Wrong requests.
    for bad in ["STORE 1 FLAGS", "STORE 1 +FLAGS", "STORE x FLAGS (\\Seen)", "STORE 1 FROB (\\Seen)"] {
        let out = s.run(&format!("z {bad}\r\n"));
        assert!(status(&out, "z").starts_with("z BAD "), "{bad}: {out}");
    }
}

#[test]
fn search_finds_messages_by_every_kind_of_key() {
    let mut s = three();
    let search = |s: &mut Session, keys: &str| -> String {
        let out = s.run(&format!("s SEARCH {keys}\r\n"));
        assert!(status(&out, "s").starts_with("s OK "), "{keys}: {out}");
        lines(&out, "* SEARCH").first().map(|l| l.trim_start_matches("* SEARCH").trim().to_string()).unwrap_or_default()
    };
    assert_eq!(search(&mut s, "ALL"), "1 2 3");
    assert_eq!(search(&mut s, "SEEN"), "1");
    assert_eq!(search(&mut s, "UNSEEN"), "2 3");
    assert_eq!(search(&mut s, "FLAGGED"), "3");
    assert_eq!(search(&mut s, "FROM b@x.org"), "2");
    assert_eq!(search(&mut s, "SUBJECT alpha"), "1 3");
    assert_eq!(search(&mut s, "BODY lazy"), "3");
    assert_eq!(search(&mut s, "TEXT \"quick brown\""), "1");
    assert_eq!(search(&mut s, "HEADER Message-ID <beta@x.org>"), "2");
    assert_eq!(search(&mut s, "NOT SEEN FROM c@x.org"), "3");
    assert_eq!(search(&mut s, "OR FROM a@x.org FROM b@x.org"), "1 2");
    assert_eq!(search(&mut s, "(UNSEEN SUBJECT beta)"), "2");
    assert_eq!(search(&mut s, "2:3"), "2 3");
    assert_eq!(search(&mut s, "UID 1,3"), "1 3");
    assert_eq!(search(&mut s, "LARGER 1 SMALLER 100000"), "1 2 3");
    assert_eq!(search(&mut s, "SINCE 2-Jan-2000"), "1 2 3");
    assert_eq!(search(&mut s, "FROM nobody"), "");
    // A literal as the string.
    let out = s.run("l SEARCH FROM {7}\r\nb@x.org\r\n");
    assert!(out.contains("* SEARCH 2"), "{out}");
    // UID SEARCH answers in UIDs.
    let out = s.run("u UID SEARCH FROM c@x.org\r\n");
    assert!(out.contains("* SEARCH 3"), "{out}");
    // Wrong keys are refused at once.
    for bad in ["SEARCH FROZ x", "SEARCH (SEEN", "SEARCH OR SEEN", "SEARCH SINCE notadate"] {
        let out = s.run(&format!("z {bad}\r\n"));
        assert!(status(&out, "z").starts_with("z BAD "), "{bad}: {out}");
    }
}

#[test]
fn sort_and_thread() {
    let mut s = three();
    let out = s.run("a SORT (SUBJECT) UTF-8 ALL\r\n");
    assert!(out.contains("* SORT 1 2 3") || out.contains("* SORT 1 3 2"), "{out}");
    let out = s.run("b SORT (REVERSE FROM) UTF-8 ALL\r\n");
    assert!(out.contains("* SORT 3 2 1"), "{out}");
    let out = s.run("c SORT (DATE) US-ASCII FROM a@x.org\r\n");
    assert!(out.contains("* SORT 1\r\n"), "{out}");
    let out = s.run("d UID SORT (SIZE) UTF-8 ALL\r\n");
    assert!(out.contains("* SORT "), "{out}");
    assert!(status(&s.run("e SORT (SUBJECT) KOI8-R ALL\r\n"), "e").contains("BADCHARSET"));
    assert!(status(&s.run("f SORT (FROZ) UTF-8 ALL\r\n"), "f").starts_with("f BAD "));

    // "alpha" and "Re: alpha" are one thread.
    let out = s.run("g THREAD ORDEREDSUBJECT UTF-8 ALL\r\n");
    assert!(out.contains("* THREAD (1 3)(2)"), "{out}");
    let out = s.run("h THREAD REFERENCES UTF-8 ALL\r\n");
    assert!(out.contains("* THREAD "), "{out}");
    let out = s.run("i UID THREAD ORDEREDSUBJECT UTF-8 ALL\r\n");
    assert!(out.contains("* THREAD "), "{out}");
    assert!(status(&s.run("j THREAD FROZ UTF-8 ALL\r\n"), "j").starts_with("j BAD "));

    // With the extensions off, they are not available.
    let mut off = Session::with(|mut c| {
        c.enable_sort = false;
        c.enable_thread_ordered_subject = false;
        c
    });
    off.login();
    off.append("INBOX", "", &message("x", "a@x.org", "u@x.org", ALICE, "b"));
    off.run("s SELECT INBOX\r\n");
    assert!(status(&off.run("a SORT (SUBJECT) UTF-8 ALL\r\n"), "a").starts_with("a BAD "));
    assert!(status(&off.run("b THREAD ORDEREDSUBJECT UTF-8 ALL\r\n"), "b").starts_with("b BAD "));
}

#[test]
fn copy_move_and_expunge() {
    let mut s = three();
    assert!(status(&s.run("a CREATE Archive\r\n"), "a").starts_with("a OK "));

    let out = s.run("b COPY 1:2 Archive\r\n");
    assert!(status(&out, "b").starts_with("b OK [COPYUID "), "{out}");
    let out = s.run("c UID COPY 3 Archive\r\n");
    assert!(status(&out, "c").starts_with("c OK [COPYUID "), "{out}");
    assert!(status(&s.run("d COPY 1 INBOX\r\n"), "d").starts_with("d NO "), "a message is not copied onto itself");

    let out = s.run("f STATUS Archive (MESSAGES)\r\n");
    assert!(out.contains("(MESSAGES 3)"), "{out}");

    // MOVE takes them out of the source.
    let out = s.run("g MOVE 3 Archive\r\n");
    assert!(out.contains("* 3 EXPUNGE") || out.contains("VANISHED"), "{out}");
    assert!(status(&out, "g").starts_with("g OK "), "{out}");
    assert!(s.run("h STATUS Archive (MESSAGES)\r\n").contains("(MESSAGES 4)"));
    assert!(s.run("i STATUS INBOX (MESSAGES)\r\n").contains("(MESSAGES 2)"));

    // EXPUNGE removes what is \Deleted.
    s.run("j STORE 1 +FLAGS.SILENT (\\Deleted)\r\n");
    let out = s.run("k EXPUNGE\r\n");
    assert!(out.contains("* 1 EXPUNGE"), "{out}");
    assert!(s.run("l STATUS INBOX (MESSAGES)\r\n").contains("(MESSAGES 1)"));
    // By UID: only the ones named.
    s.run("m STORE 1 +FLAGS.SILENT (\\Deleted)\r\n");
    let out = s.run("n UID EXPUNGE 99\r\n");
    assert!(!out.contains("EXPUNGE\r\n* ") && lines(&out, "* ").is_empty(), "{out}");
    let out = s.run("o UID EXPUNGE 1:*\r\n");
    assert!(out.contains("* 1 EXPUNGE"), "{out}");
    assert!(status(&s.run("p UID EXPUNGE x\r\n"), "p").starts_with("p BAD "));
}

#[test]
fn close_and_unselect_leave_the_selected_state() {
    let mut s = three();
    s.run("a STORE 1 +FLAGS.SILENT (\\Deleted)\r\n");
    let out = s.run("b UNSELECT\r\n");
    assert!(status(&out, "b").starts_with("b OK "), "{out}");
    assert!(status(&s.run("c FETCH 1 FLAGS\r\n"), "c").starts_with("c NO "));
    assert!(s.run("d STATUS INBOX (MESSAGES)\r\n").contains("(MESSAGES 3)"), "UNSELECT does not expunge");
    s.run("e SELECT INBOX\r\n");
    let out = s.run("f CLOSE\r\n");
    assert!(status(&out, "f").starts_with("f OK "), "{out}");
    assert!(s.run("g STATUS INBOX (MESSAGES)\r\n").contains("(MESSAGES 2)"), "CLOSE expunges");
    assert!(status(&s.run("h CLOSE\r\n"), "h").starts_with("h NO "));
    assert!(status(&s.run("i EXPUNGE\r\n"), "i").starts_with("i NO "));
}

#[test]
fn examine_is_read_only() {
    let mut s = three();
    s.run("a CLOSE\r\n");
    let out = s.run("b EXAMINE INBOX\r\n");
    assert!(status(&out, "b").starts_with("b OK [READ-ONLY]"), "{out}");
    let out = s.run("c STORE 1 +FLAGS (\\Deleted)\r\n");
    assert!(status(&out, "c").starts_with("c NO "), "{out}");
    let out = s.run("d FETCH 2 BODY[TEXT]\r\n");
    assert!(status(&out, "d").starts_with("d OK "));
    assert!(s.run("e FETCH 2 FLAGS\r\n").contains("FLAGS ()"), "an EXAMINE does not mark messages seen");
    assert!(status(&s.run("f EXPUNGE\r\n"), "f").starts_with("f NO "));
}

#[test]
fn id_enable_and_starttls() {
    let mut s = Session::new();
    // Before login only ID is allowed of these.
    let out = s.run("a ID (\"name\" \"test\")\r\n");
    assert!(out.starts_with("* ID (\"name\" \"hopf-imap\" \"version\" \"") && status(&out, "a").starts_with("a OK "), "{out}");
    assert!(status(&s.run("b ID (\"name\")\r\n"), "b").starts_with("b BAD "), "a field with no value");
    assert!(status(&s.run("c ENABLE CONDSTORE\r\n"), "c").starts_with("c NO "));
    assert!(status(&s.run("d STARTTLS\r\n"), "d").starts_with("d BAD "), "no TLS is configured");
    assert!(status(&s.run("e AUTHENTICATE PLAIN\r\n"), "e").starts_with("e NO [PRIVACYREQUIRED]"));
    s.login();
    assert!(status(&s.run("f STARTTLS\r\n"), "f").starts_with("f BAD "), "not once logged in");
    let out = s.run("g ENABLE CONDSTORE\r\n");
    assert!(out.starts_with("* ENABLED CONDSTORE\r\n"), "{out}");
    let out = s.run("h ENABLE QRESYNC FROB\r\n");
    assert!(out.contains("* ENABLED QRESYNC\r\n") && !out.contains("FROB"), "{out}");
    assert!(status(&s.run("i ENABLE\r\n"), "i").starts_with("i BAD "));
}

#[test]
fn extensions_that_are_switched_off_say_so() {
    let mut s = Session::with(|mut c| {
        c.enable_quota = false;
        c.enable_move = false;
        c.enable_metadata = false;
        c.enable_notify = false;
        c.enable_compress = false;
        c.enable_namespace = false;
        c.enable_enable = false;
        c
    });
    s.login();
    s.append("INBOX", "", &message("x", "a@x.org", "u@x.org", ALICE, "b"));
    s.run("s SELECT INBOX\r\n");
    for (command, tag) in [
        ("GETQUOTA \"\"", "a"),
        ("GETQUOTAROOT INBOX", "b"),
        ("SETQUOTA \"\" (STORAGE 1)", "c"),
        ("MOVE 1 Other", "d"),
        ("GETMETADATA INBOX /a", "e"),
        ("SETMETADATA INBOX (/a \"b\")", "f"),
        ("NOTIFY NONE", "g"),
        ("COMPRESS DEFLATE", "h"),
        ("NAMESPACE", "i"),
        ("ENABLE CONDSTORE", "j"),
    ] {
        let out = s.run(&format!("{tag} {command}\r\n"));
        assert!(status(&out, tag).starts_with(&format!("{tag} BAD ")) && status(&out, tag).contains("not available"), "{command}: {out}");
    }
}

#[test]
fn quota_reports_the_limits_and_refuses_to_change_unlimited_ones() {
    let mut s = Session::new();
    s.login();
    let out = s.run("a GETQUOTA \"\"\r\n");
    assert!(out.contains("* QUOTA \"\" ()") && status(&out, "a").starts_with("a OK "), "{out}");
    let out = s.run("b GETQUOTAROOT INBOX\r\n");
    assert!(out.contains("* QUOTAROOT INBOX \"\"\r\n* QUOTA \"\" ()"), "{out}");
    assert!(status(&s.run("c SETQUOTA \"\" (STORAGE 100)\r\n"), "c").starts_with("c NO "));
    assert!(status(&s.run("d SETQUOTA \"\" STORAGE 100\r\n"), "d").starts_with("d BAD "));
    assert!(status(&s.run("e SETQUOTA \"\" (STORAGE x)\r\n"), "e").starts_with("e BAD "));
}

#[test]
fn quota_limits_come_from_the_manager() {
    let mut s = Session::with(|c| c.with_quota_manager(Arc::new(crate::server::quota::MemoryQuotaManager::new(Arc::new(hopf_core::MemoryQuotaManager::new())))));
    s.login();
    let out = s.run("a SETQUOTA \"\" (STORAGE 100 MESSAGE 7)\r\n");
    assert!(out.contains("* QUOTA \"\" (") && out.contains("STORAGE ") && out.contains(" 100") && out.contains("MESSAGE "), "{out}");
    assert!(status(&out, "a").starts_with("a OK "), "{out}");
    let out = s.run("b GETQUOTA \"\"\r\n");
    assert!(out.contains("STORAGE 0 100") && out.contains("MESSAGE 0 7"), "{out}");
}

#[test]
fn metadata_set_get_and_delete() {
    let mut s = Session::new();
    s.login();
    assert!(status(&s.run("a SETMETADATA INBOX (/private/comment \"hello\")\r\n"), "a").starts_with("a OK "));
    let out = s.run("b GETMETADATA INBOX /private/comment\r\n");
    assert!(out.contains("* METADATA INBOX (/private/comment \"hello\")"), "{out}");
    let out = s.run("c GETMETADATA INBOX (/private/comment /private/missing)\r\n");
    assert!(out.contains("/private/comment \"hello\"") && !out.contains("missing"), "{out}");
    let out = s.run("d GETMETADATA (DEPTH infinity) INBOX /private\r\n");
    assert!(out.contains("/private/comment"), "{out}");
    let out = s.run("e GETMETADATA (MAXSIZE 2) INBOX /private/comment\r\n");
    assert!(!out.contains("\"hello\""), "a value over MAXSIZE is left out: {out}");
    // A value given as a literal.
    assert!(status(&s.run("f SETMETADATA INBOX (/private/note {5}\r\nl1\r\nx)\r\n"), "f").starts_with("f OK "));
    assert!(s.run("g GETMETADATA INBOX /private/note\r\n").contains("l1"));
    // NIL removes it.
    assert!(status(&s.run("h SETMETADATA INBOX (/private/comment NIL)\r\n"), "h").starts_with("h OK "));
    assert!(!s.run("i GETMETADATA INBOX /private/comment\r\n").contains("hello"));
    // Server annotations, and refusals.
    assert!(status(&s.run("j SETMETADATA \"\" (/private/x \"y\")\r\n"), "j").starts_with("j OK "));
    for bad in ["GETMETADATA INBOX", "SETMETADATA INBOX", "SETMETADATA INBOX ()", "GETMETADATA (DEPTH 3) INBOX /a", "SETMETADATA INBOX (/a)"] {
        assert!(status(&s.run(&format!("z {bad}\r\n")), "z").starts_with("z BAD "), "{bad}");
    }
}

#[test]
fn notify_and_idle() {
    let mut s = three();
    assert!(status(&s.run("a NOTIFY SET (SELECTED MessageNew FlagChange)\r\n"), "a").starts_with("a OK "));
    assert!(status(&s.run("b NOTIFY NONE\r\n"), "b").starts_with("b OK "));
    assert!(status(&s.run("c NOTIFY SET (PERSONAL MessageNew)\r\n"), "c").starts_with("c BAD "));
    assert!(status(&s.run("d NOTIFY SET (SELECTED MailboxName)\r\n"), "d").starts_with("d BAD "));

    // IDLE: a continuation, then only DONE.
    assert_eq!(s.run("e IDLE\r\n"), "+ idling\r\n");
    let out = s.run("e2 NOOP\r\n");
    assert!(out.contains("e2 BAD Expected DONE while IDLEing"), "{out}");
    let out = s.run("DONE\r\n");
    assert!(out.contains("e OK IDLE completed"), "{out}");
    assert!(status(&s.run("f NOOP\r\n"), "f").starts_with("f OK "));
    // DONE outside IDLE.
    assert!(s.run("g DONE\r\n").contains("g BAD Not IDLEing"));
    assert!(s.run("DONE\r\n").contains("* BAD Not IDLEing"));
    // IDLE needs a selected mailbox.
    let mut t = Session::new();
    t.login();
    assert!(status(&t.run("a IDLE\r\n"), "a").starts_with("a NO "));
}

#[test]
fn condstore_reports_modification_sequences() {
    let mut s = three();
    let out = s.run("a SELECT INBOX (CONDSTORE)\r\n");
    assert!(out.contains("[HIGHESTMODSEQ 3]"), "{out}");
    let out = s.run("b FETCH 1 (UID MODSEQ)\r\n");
    assert!(out.contains("* 1 FETCH (UID 1 MODSEQ (1))"), "{out}");
    // Only what has changed since.
    let out = s.run("c FETCH 1:* (UID FLAGS) (CHANGEDSINCE 1)\r\n");
    assert!(out.contains("* 2 FETCH") && out.contains("* 3 FETCH") && !out.contains("* 1 FETCH"), "{out}");
    assert!(out.contains("MODSEQ (2)") && out.contains("MODSEQ (3)"), "{out}");
    assert!(status(&s.run("d FETCH 1 FLAGS (CHANGEDSINCE x)\r\n"), "d").starts_with("d BAD "));
    let out = s.run("e SEARCH MODSEQ 2\r\n");
    assert!(out.contains("* SEARCH 2 3"), "{out}");
    let out = s.run("f STATUS INBOX (HIGHESTMODSEQ MAILBOXID SIZE)\r\n");
    assert!(out.contains("HIGHESTMODSEQ 3") && out.contains("MAILBOXID (") && out.contains("SIZE "), "{out}");
    // A change moves it on.
    s.run("g STORE 1 +FLAGS.SILENT (\\Flagged)\r\n");
    let out = s.run("h STATUS INBOX (HIGHESTMODSEQ)\r\n");
    let moved = out.split("HIGHESTMODSEQ ").nth(1).and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next()).and_then(|n| n.parse::<u64>().ok());
    assert!(moved.is_some_and(|n| n > 3), "{out}");
}

#[test]
fn compress_switches_the_stream_to_deflate() {
    let mut s = Session::new();
    s.login();
    assert!(status(&s.run("a COMPRESS FOO\r\n"), "a").starts_with("a BAD "));
    let out = s.run("b COMPRESS DEFLATE\r\n");
    assert_eq!(out, "b OK DEFLATE active\r\n");
    // From here on the server expects DEFLATE: plain text is not a valid stream.
    let out = s.run("c NOOP\r\n");
    assert!(!out.contains("c OK"), "plain text is not DEFLATE: {out:?}");
}

#[test]
fn input_split_anywhere_makes_the_same_replies() {
    let m = message("hi", "a@x.org", "u@x.org", ALICE, "body\r\n");
    let commands = [
        "a NOOP\r\n".to_string(),
        "b LOGIN u p\r\n".to_string(),
        "c CREATE Box\r\n".to_string(),
        format!("d APPEND Box (\\Seen) {{{}}}\r\n{m}\r\n", m.len()),
        "e SELECT Box\r\n".to_string(),
        "f FETCH 1 (FLAGS BODY.PEEK[HEADER.FIELDS (Subject)])\r\n".to_string(),
        "g SEARCH SUBJECT hi\r\n".to_string(),
        "h LOGOUT\r\n".to_string(),
    ];
    // What varies between runs (the validity numbers) removed, and the `+`
    // continuations (they come with the literal marker, wherever that falls).
    let normalise = |out: String| -> Vec<String> {
        out.lines()
            .filter(|l| !l.starts_with('+'))
            .map(|l| l.split("UIDVALIDITY").next().unwrap().split("APPENDUID").next().unwrap().split("MAILBOXID").next().unwrap().to_string())
            .collect()
    };
    // One command at a time, each sent whole.
    let mut whole = Session::new();
    whole.take();
    let mut want = String::new();
    for command in &commands {
        want.push_str(&whole.run(command));
    }
    let want = normalise(want);
    assert!(want.iter().any(|l| l.starts_with("d OK")) && want.iter().any(|l| l == "* SEARCH 1"), "{want:?}");
    for chunk in [1, 2, 3, 7] {
        let mut s = Session::new();
        let got = normalise(s.run_chunked(&commands.concat(), chunk));
        assert_eq!(got, want, "chunk={chunk}");
    }
}

#[test]
fn append_variants() {
    let mut s = Session::new();
    s.login();
    let out = s.run("a APPEND Nope {1}\r\nx\r\n");
    assert!(status(&out, "a").starts_with("a NO "), "{out}");
    let out = s.run("b APPEND INBOX {0}\r\n\r\n");
    assert!(status(&out, "b").starts_with("b OK [APPENDUID "), "an empty message: {out}");
    let out = s.run("c APPEND INBOX (\\Seen \\Flagged $k) \"01-Jan-2024 10:00:00 +0000\" {5}\r\nhello\r\n");
    assert!(status(&out, "c").starts_with("c OK [APPENDUID "), "{out}");
    // A synchronizing literal waits for the continuation; a LITERAL- one does not.
    let out = s.run("d APPEND INBOX {2+}\r\nhi\r\n");
    assert!(!out.contains('+') || !out.starts_with('+'), "{out}");
    assert!(status(&out, "d").starts_with("d OK "), "{out}");
    s.run("sel SELECT INBOX\r\n");
    let out = s.run("e FETCH 2 FLAGS\r\n");
    assert!(out.contains("\\Seen") && out.contains("\\Flagged") && out.contains("$k"), "keywords are kept: {out}");
    assert!(s.run("e2 FETCH 3 FLAGS\r\n").contains("FLAGS ()"));
    assert!(s.run("e3 SEARCH KEYWORD $k\r\n").contains("* SEARCH 2\r\n"));
    assert!(s.run("e4 SEARCH UNKEYWORD $k\r\n").contains("* SEARCH 1 3\r\n"));
    // A bad flag list is refused before the continuation, and the line is skipped.
    let out = s.run("f APPEND INBOX (\\Seen {1+}\r\nx\r\ng NOOP\r\n");
    assert!(status(&out, "f").starts_with("f BAD "), "{out}");
    assert!(status(&out, "g").starts_with("g OK "), "{out}");
}

/// The guard against spooling for a client that has not logged in must not
/// break a login pipelined ahead of the APPEND, and must not keep a body for
/// an APPEND whose login failed.
#[test]
fn a_pipelined_login_and_append_works_and_a_failed_login_keeps_nothing() {
    let m = message("hi", "a@x.org", "u@x.org", ALICE, "body\r\n");
    let mut s = Session::new();
    let out = s.run(&format!("a LOGIN u p\r\nb APPEND INBOX {{{}}}\r\n{m}\r\n", m.len()));
    assert!(status(&out, "a").starts_with("a OK "), "{out}");
    assert!(status(&out, "b").starts_with("b OK [APPENDUID "), "{out}");

    let mut bad = Session::new();
    let out = bad.run(&format!("a LOGIN u wrong\r\nb APPEND INBOX {{{}}}\r\n{m}\r\n", m.len()));
    assert!(status(&out, "a").starts_with("a NO "), "{out}");
    assert!(status(&out, "b").starts_with("b NO "), "{out}");
    assert!(bad.h.pending_append_path.is_none(), "the spooled body was kept: {:?}", bad.h.pending_append_path);
}

/// Commands sent in one write are answered in order, however long an
/// APPEND's body takes to reach the disk.
#[test]
fn an_append_pipelined_with_other_commands_is_answered_in_order() {
    let m = message("hi", "a@x.org", "u@x.org", ALICE, "body\r\n");
    let n = message("yo", "b@x.org", "u@x.org", BOB, "other\r\n");
    let script = format!(
        "a LOGIN u p\r\nb CREATE Box\r\nc APPEND Box (\\Seen) {{{}}}\r\n{m}\r\nd NOOP\r\ne APPEND Box {{{}}}\r\n{n}\r\nf SELECT Box\r\ng FETCH 1:2 (FLAGS BODY.PEEK[HEADER.FIELDS (Subject)])\r\nh SEARCH SUBJECT yo\r\ni LOGOUT\r\n",
        m.len(),
        n.len()
    );
    let mut s = Session::new();
    s.take();
    let out = s.run(&script);
    let tags: Vec<&str> = out
        .lines()
        .filter(|l| !l.starts_with('+') && !l.starts_with('*') && l.len() > 2 && l.as_bytes()[1] == b' ' && l.as_bytes()[0].is_ascii_lowercase())
        .map(|l| &l[..1])
        .collect();
    assert_eq!(tags, ["a", "b", "c", "d", "e", "f", "g", "h", "i"], "{out}");
    assert!(status(&out, "c").starts_with("c OK [APPENDUID "), "{out}");
    assert!(status(&out, "e").starts_with("e OK [APPENDUID "), "{out}");
    assert!(out.contains("* 2 EXISTS"), "{out}");
    // Each message went to its own APPEND: the first seen, with its subject.
    assert!(out.contains("* 1 FETCH (FLAGS (\\Seen)") && out.contains("Subject: hi"), "{out}");
    assert!(out.contains("* 2 FETCH (FLAGS ()") && out.contains("Subject: yo"), "{out}");
    assert!(out.contains("* SEARCH 2"), "{out}");
}

#[test]
fn list_follows_the_rfc_on_wildcards_references_and_children() {
    let mut s = Session::new();
    s.login();
    s.run("a CREATE Work\r\nb CREATE Work/Reports\r\nc CREATE Work/Reports/Q1\r\nd CREATE Other\r\ne CREATE Deep/Down/Here\r\n");
    let names = |out: &str| -> Vec<String> {
        let mut n: Vec<String> = lines(out, "* LIST").iter().map(|l| l.rsplit(' ').next().unwrap().to_string()).collect();
        n.sort();
        n
    };
    assert_eq!(names(&s.run("p LIST \"\" %\r\n")), ["Deep", "INBOX", "Other", "Work"]);
    assert_eq!(names(&s.run("p LIST \"\" Work/%\r\n")), ["Work/Reports"]);
    assert_eq!(names(&s.run("p LIST \"\" Wo%\r\n")), ["Work"]);
    assert_eq!(names(&s.run("p LIST Work/ %\r\n")), ["Work/Reports"]);
    assert_eq!(names(&s.run("p LIST Work/ *\r\n")), ["Work/Reports", "Work/Reports/Q1"]);
    assert_eq!(names(&s.run("p LIST \"\" inbox\r\n")), ["INBOX"]);

    // What has children, and the names that are only the way to one.
    let out = s.run("q LIST \"\" *\r\n");
    let row = |name: &str| lines(&out, "* LIST").into_iter().find(|l| l.ends_with(&format!(" {name}"))).unwrap_or_else(|| panic!("{name} in {out}")).to_string();
    assert!(row("Work").contains("\\HasChildren"), "{out}");
    assert!(row("Work/Reports/Q1").contains("\\HasNoChildren"), "{out}");
    assert!(row("Other").contains("\\HasNoChildren") && row("INBOX").contains("\\HasNoChildren"), "{out}");
    assert!(row("Deep").contains("\\Noselect") && row("Deep").contains("\\HasChildren"), "{out}");
    assert!(row("Deep/Down").contains("\\Noselect"), "{out}");
    assert!(!row("Deep/Down/Here").contains("\\Noselect"), "{out}");
    assert!(status(&s.run("r SELECT Deep\r\n"), "r").starts_with("r NO "), "an implied name cannot be selected");

    // An empty pattern asks for the delimiter and the root.
    assert_eq!(s.run("t LIST \"\" \"\"\r\n"), "* LIST (\\Noselect) \"/\" \"\"\r\nt OK LIST completed\r\n");
}

#[test]
fn rename_carries_what_is_beneath_a_mailbox_and_its_subscriptions() {
    let mut s = Session::new();
    s.login();
    s.run("a CREATE Work\r\nb CREATE Work/Reports\r\nc SUBSCRIBE Work/Reports\r\n");
    assert!(status(&s.run("d RENAME Work Play\r\n"), "d").starts_with("d OK "));
    let out = s.run("e LIST \"\" *\r\n");
    assert!(out.contains(" Play\r\n") && out.contains(" Play/Reports\r\n") && !out.contains(" Work"), "{out}");
    let out = s.run("f LSUB \"\" *\r\n");
    assert!(out.contains(" Play/Reports\r\n") && !out.contains("Work"), "{out}");
    // A name that is taken (even beneath the new one) stops the whole rename.
    s.run("g CREATE Taken/Child\r\nh CREATE Src\r\ni CREATE Src/Child\r\n");
    assert!(status(&s.run("j RENAME Src Taken\r\n"), "j").starts_with("j NO "));
    assert!(s.run("k LIST \"\" Src*\r\n").contains(" Src/Child\r\n"), "nothing was moved");
}

#[test]
fn a_destination_that_does_not_exist_is_try_create_and_is_not_made() {
    let mut s = three();
    for (tag, command) in [("a", "COPY 1 Nowhere"), ("b", "UID COPY 1 Nowhere"), ("c", "MOVE 1 Nowhere"), ("d", "UID MOVE 1 Nowhere")] {
        let out = s.run(&format!("{tag} {command}\r\n"));
        assert_eq!(status(&out, tag), format!("{tag} NO [TRYCREATE] Mailbox does not exist"), "{command}: {out}");
        assert!(!out.contains("EXPUNGE"), "{command}: nothing was moved: {out}");
    }
    let m = message("x", "a@x.org", "u@x.org", ALICE, "b");
    let out = s.run(&format!("e APPEND Nowhere {{{}}}\r\n{m}\r\n", m.len()));
    assert_eq!(status(&out, "e"), "e NO [TRYCREATE] Mailbox does not exist", "{out}");
    assert!(!s.run("f LIST \"\" *\r\n").contains("Nowhere"), "none of them made it");
    assert!(s.run("g STATUS INBOX (MESSAGES)\r\n").contains("(MESSAGES 3)"), "the messages are where they were");
    // Created, the same commands work.
    s.run("h CREATE Nowhere\r\n");
    assert!(status(&s.run("i COPY 1 Nowhere\r\n"), "i").starts_with("i OK [COPYUID "));
    // A refusal for any other reason does not carry the storage pool's prefix.
    let out = s.run("j COPY 1 INBOX\r\n");
    assert!(status(&out, "j").starts_with("j NO ") && !out.contains("storage task failed"), "{out}");
}

/// A SELECT that fails (the mailbox does not exist, or exists only as the way
/// to others) must leave the connection usable: the handler that would have
/// run it is not thrown away with the attempt.
#[test]
fn a_select_that_fails_leaves_the_session_working() {
    let mut s = three();
    s.run("a CLOSE\r\nb CREATE Deep/Down\r\n");
    // From the authenticated state.
    for name in ["Nope", "Deep"] {
        assert!(status(&s.run(&format!("c SELECT {name}\r\n")), "c").starts_with("c NO "), "{name}");
        let out = s.run("d LIST \"\" INBOX\r\n");
        assert!(out.contains("* LIST") && status(&out, "d").starts_with("d OK "), "after SELECT {name}: {out:?}");
        assert!(status(&s.run("e CREATE Made\r\n"), "e").starts_with("e OK "), "after SELECT {name}");
        assert!(status(&s.run("f DELETE Made\r\n"), "f").starts_with("f OK "));
        assert!(s.run("g STATUS INBOX (MESSAGES)\r\n").contains("(MESSAGES 3)"));
    }
    // From the selected state: the failed attempt deselects, as RFC 9051 §6.3.2 says.
    assert!(status(&s.run("h SELECT INBOX\r\n"), "h").starts_with("h OK "));
    assert!(status(&s.run("i SELECT Nope\r\n"), "i").starts_with("i NO "));
    assert!(status(&s.run("j FETCH 1 FLAGS\r\n"), "j").starts_with("j NO "), "no mailbox is selected any more");
    assert!(status(&s.run("k LIST \"\" INBOX\r\n"), "k").starts_with("k OK "));
    assert!(status(&s.run("l CREATE Again\r\n"), "l").starts_with("l OK "));
    // And the connection can select again.
    let out = s.run("m SELECT INBOX\r\n");
    assert!(out.contains("* 3 EXISTS") && status(&out, "m").starts_with("m OK [READ-WRITE]"), "{out}");
    assert!(s.run("n FETCH 1 FLAGS\r\n").contains("* 1 FETCH"));
}

#[test]
fn from_to_and_cc_searches_find_display_names_and_sort_still_goes_by_address() {
    // Alphabetical by name is the reverse of alphabetical by address.
    let zed = message("one", "Zed Zimmer <a@x.org>", "Pat <p@x.org>", ALICE, "x\r\n");
    let abe = message("two", "Abe Adams <b@x.org>", "Quinn Q <q@x.org>", BOB, "y\r\n");
    let mut s = Session::with_inbox(&[("", &zed), ("", &abe)]);
    let found = |s: &mut Session, keys: &str| -> String {
        let out = s.run(&format!("s SEARCH {keys}\r\n"));
        lines(&out, "* SEARCH").first().map(|l| l.trim_start_matches("* SEARCH").trim().to_string()).unwrap_or_default()
    };
    assert_eq!(found(&mut s, "FROM zimmer"), "1");
    assert_eq!(found(&mut s, "FROM \"abe adams\""), "2");
    assert_eq!(found(&mut s, "FROM b@x.org"), "2");
    assert_eq!(found(&mut s, "TO quinn"), "2");
    assert_eq!(found(&mut s, "HEADER From abe"), "2");
    assert_eq!(found(&mut s, "TEXT zimmer"), "1");
    assert_eq!(found(&mut s, "FROM nobody"), "");
    // SORT by sender goes by the address, as RFC 5256 says (the addr-mailbox).
    let out = s.run("t SORT (FROM) UTF-8 ALL\r\n");
    assert!(out.contains("* SORT 1 2\r\n"), "{out}");
    let out = s.run("u SORT (REVERSE TO) UTF-8 ALL\r\n");
    assert!(out.contains("* SORT 2 1\r\n"), "{out}");
}

/// RFC 9051 §6.4.5: fetching a body without PEEK sets \Seen, and the new
/// flags are reported in the FETCH response that did it.
#[test]
fn a_fetch_that_sets_seen_says_so() {
    let mut s = three();
    // Message 2 is unseen: asked for without FLAGS, they are sent anyway.
    let out = s.run("a FETCH 2 BODY[TEXT]\r\n");
    assert!(out.contains("jumps over") && out.contains("FLAGS (\\Seen)"), "{out}");
    // Asked for with FLAGS, the flags are the ones after the change, wherever they were asked for.
    let out = s.run("b FETCH 3 (FLAGS BODY[HEADER])\r\n");
    assert!(out.contains("FLAGS (\\Seen \\Flagged)") || out.contains("FLAGS (\\Flagged \\Seen)"), "{out}");
    assert_eq!(out.matches("FLAGS").count(), 1, "once: {out}");
    // Already seen: nothing is added.
    let out = s.run("c FETCH 1 BODY[TEXT]\r\n");
    assert!(!out.contains("FLAGS"), "{out}");
    // PEEK does not set it, and says nothing.
    s.run("d STORE 2 -FLAGS.SILENT (\\Seen)\r\n");
    let out = s.run("e FETCH 2 BODY.PEEK[TEXT]\r\n");
    assert!(!out.contains("FLAGS"), "{out}");
    assert!(s.run("f FETCH 2 FLAGS\r\n").contains("FLAGS ()"));
    // RFC822 and RFC822.TEXT set it too; RFC822.HEADER does not.
    let out = s.run("g FETCH 2 RFC822.HEADER\r\n");
    assert!(!out.contains("FLAGS"), "{out}");
    let out = s.run("h FETCH 2 RFC822.TEXT\r\n");
    assert!(out.contains("FLAGS (\\Seen)"), "{out}");
    s.run("i STORE 2 -FLAGS.SILENT (\\Seen)\r\n");
    let out = s.run("j UID FETCH 2 RFC822\r\n");
    assert!(out.contains("FLAGS (\\Seen)") && out.contains("UID 2"), "{out}");
    // A read-only session changes nothing.
    s.run("k STORE 2 -FLAGS.SILENT (\\Seen)\r\n");
    s.run("l CLOSE\r\nm EXAMINE INBOX\r\n");
    let out = s.run("n FETCH 2 BODY[TEXT]\r\n");
    assert!(!out.contains("FLAGS"), "{out}");
    assert!(s.run("o FETCH 2 FLAGS\r\n").contains("FLAGS ()"));
}
