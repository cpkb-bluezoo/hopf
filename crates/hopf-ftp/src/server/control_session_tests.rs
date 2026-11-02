// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-process tests of [`FtpControlHandler`]: the test is the FTP client,
//! over a [`Peer`], against an in-memory file system. The tests that open a
//! data connection use real loopback sockets, and run only with the
//! `integration` feature.

#[cfg_attr(not(feature = "integration"), allow(unused_imports))]
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_auth::PasswordTrustPolicy;
use hopf_core::testing::Peer;
use hopf_core::{Runtime, RuntimeConfig};

use super::*;
use crate::server::fs::FtpFileSystem;
use crate::server::handler::{FtpAuthResult, FtpConnectionHandler, FtpOperation};
use crate::server::memory_fs::{MemoryFtpFileSystem, MemoryFtpHandler};
use crate::server::throttle::{LoginLimits, LoginThrottle};

/// What the authorization hook was asked, and what it refuses.
#[derive(Default)]
struct Policy {
    asked: Mutex<Vec<(String, String)>>,
    deny_containing: Mutex<Option<&'static str>>,
}

/// The stock handler with a refusal rule and a log of what it was asked.
struct PolicyHandler {
    inner: MemoryFtpHandler,
    policy: Arc<Policy>,
}

impl FtpConnectionHandler for PolicyHandler {
    fn authenticate(&mut self, u: &str, p: Option<&str>, a: Option<&str>, m: &FtpConnectionMetadata) -> FtpAuthResult {
        self.inner.authenticate(u, p, a, m)
    }
    fn file_system(&mut self, m: &FtpConnectionMetadata) -> &mut dyn FtpFileSystem {
        self.inner.file_system(m)
    }
    fn file_system_handle(&mut self, m: &FtpConnectionMetadata) -> Option<Arc<dyn FtpFileSystem + Sync>> {
        self.inner.file_system_handle(m)
    }
    fn is_authorized(&self, op: FtpOperation, path: &str, _m: &FtpConnectionMetadata) -> bool {
        self.policy.asked.lock().unwrap().push((format!("{op:?}"), path.to_string()));
        match *self.policy.deny_containing.lock().unwrap() {
            Some(word) => !path.contains(word),
            None => true,
        }
    }
}

fn runtime() -> Arc<Runtime> {
    static RT: std::sync::OnceLock<Arc<Runtime>> = std::sync::OnceLock::new();
    Arc::clone(RT.get_or_init(|| Arc::new(Runtime::start(RuntimeConfig::default()).unwrap())))
}

struct Session {
    peer: Peer<FtpControlHandler>,
    policy: Arc<Policy>,
    fs: MemoryFtpFileSystem,
    greeting: String,
}

impl Session {
    fn new() -> Self {
        Self::with(|c| c)
    }

    fn with(tweak: impl FnOnce(FtpConfig) -> FtpConfig) -> Self {
        let fs = MemoryFtpFileSystem::new();
        fs.put("/pub.txt", b"public text\n");
        fs.put("/docs/a.txt", b"in docs");
        fs.put("/secret/plan.txt", b"hidden");
        let tp = PasswordTrustPolicy::new().with_user("u", "p").shared();
        let policy = Arc::new(Policy::default());
        let app = PolicyHandler {
            inner: MemoryFtpHandler::new(fs.clone(), Arc::clone(&tp)),
            policy: Arc::clone(&policy),
        };
        let local: SocketAddr = "127.0.0.1:2121".parse().unwrap();
        // The tests that are not about the login limits should not wait out
        // the delay a real server puts after a failed login.
        let no_delay = LoginLimits { failure_delay: Duration::ZERO, ..LoginLimits::default() };
        let config = tweak(FtpConfig::new(local, "/", tp).with_login_limits(no_delay));
        let handler = FtpControlHandler::new(
            Box::new(app),
            runtime(),
            FtpServerMetrics::shared(),
            config,
            "127.0.0.1:50000".parse().unwrap(),
            local,
        );
        let mut peer = Peer::connect_timed(
            handler,
            |h| h.busy.load(std::sync::atomic::Ordering::Relaxed),
            |h| h.login_gate.load(std::sync::atomic::Ordering::Relaxed),
        );
        let greeting = peer.take();
        Session { peer, policy, fs, greeting }
    }

    fn run(&mut self, line: &str) -> String {
        self.peer.run(&format!("{line}\r\n"))
    }

    fn login(&mut self) {
        assert!(self.run("USER u").starts_with("331 "));
        assert!(self.run("PASS p").starts_with("230 "));
    }

    fn logged_in() -> Self {
        let mut s = Self::new();
        s.login();
        s
    }

    fn deny(&self, word: &'static str) {
        *self.policy.deny_containing.lock().unwrap() = Some(word);
    }

    fn asked(&self) -> Vec<(String, String)> {
        self.policy.asked.lock().unwrap().clone()
    }

    /// PASV, connect to the port it names.
    #[cfg_attr(not(feature = "integration"), allow(dead_code))]
    fn passive(&mut self) -> TcpStream {
        let r = self.run("PASV");
        assert!(r.starts_with("227 "), "{r}");
        let nums: Vec<u16> = r[r.find('(').unwrap() + 1..r.find(')').unwrap()].split(',').map(|n| n.parse().unwrap()).collect();
        let port = nums[4] * 256 + nums[5];
        TcpStream::connect(("127.0.0.1", port)).unwrap()
    }

    /// Replies that arrive on the control connection after a command was
    /// sent: pumps until `done` holds of everything so far (or 5 s).
    #[cfg_attr(not(feature = "integration"), allow(dead_code))]
    fn until(&mut self, mut acc: String, done: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done(&acc) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
            self.peer.pump();
            acc.push_str(&self.peer.take());
        }
        acc
    }

    /// Run a transfer command over a passive connection; returns the control
    /// replies and the bytes that came over the data connection.
    #[cfg_attr(not(feature = "integration"), allow(dead_code))]
    fn transfer(&mut self, cmd: &str) -> (String, Vec<u8>) {
        let mut data = self.passive();
        data.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let first = self.run(cmd);
        let replies = self.until(first, |s| s.contains("226 ") || s.contains("\r\n4") || s.contains("\r\n5") || s.starts_with('4') || s.starts_with('5'));
        let mut got = Vec::new();
        let _ = data.read_to_end(&mut got);
        (replies, got)
    }
}

// -- login -------------------------------------------------------------------

#[test]
fn the_server_greets_first() {
    assert!(Session::new().greeting.starts_with("220 "));
}

#[test]
fn nothing_but_the_basics_works_before_login() {
    let mut s = Session::new();
    for cmd in [
        "PWD", "CWD docs", "CDUP", "LIST", "NLST", "MLSD", "MLST", "RETR pub.txt", "STOR x", "APPE x", "STOU", "SIZE pub.txt",
        "MDTM pub.txt", "DELE pub.txt", "RMD docs", "MKD d", "RNFR pub.txt", "RNTO x", "PASV", "EPSV", "PORT 127,0,0,1,0,80",
        "EPRT |1|127.0.0.1|80|", "SITE x", "STAT /", "ALLO 1",
    ] {
        let r = s.run(cmd);
        assert!(r.starts_with("530 "), "{cmd} before login: {r}");
    }
    for cmd in ["NOOP", "SYST", "FEAT", "TYPE I", "STRU F", "MODE S", "OPTS UTF8 ON"] {
        let r = s.run(cmd);
        assert!(!r.starts_with("530 ") && !r.is_empty(), "{cmd} before login: {r}");
    }
}

#[test]
fn login_needs_user_then_pass() {
    let mut s = Session::new();
    assert!(s.run("PASS p").starts_with("503 "));
    assert!(s.run("USER").starts_with("501 "));
    assert!(s.run("USER u").starts_with("331 "));
    assert!(s.run("PASS wrong").starts_with("530 "));
    assert!(s.run("PWD").starts_with("530 "), "still not in");
    assert!(s.run("PASS p").starts_with("230 "), "the user name is kept for another try");
    assert!(s.run("PWD").starts_with("257 "));
    assert_eq!(s.peer.handler.metrics.auth_ok.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(s.peer.handler.metrics.auth_fail.load(std::sync::atomic::Ordering::Relaxed), 1);
}

// -- login limits (issue #518) -----------------------------------------------

fn limits(tweak: impl FnOnce(&mut LoginLimits)) -> impl FnOnce(FtpConfig) -> FtpConfig {
    move |c| {
        let mut l = LoginLimits { failure_delay: Duration::ZERO, ..LoginLimits::default() };
        tweak(&mut l);
        c.with_login_limits(l)
    }
}

#[test]
fn a_connection_that_keeps_failing_to_log_in_is_closed_at_the_limit() {
    let mut s = Session::with(limits(|l| l.max_failures_per_connection = 3));
    assert!(s.run("USER u").starts_with("331 "));
    assert!(s.run("PASS wrong1").starts_with("530 "));
    assert!(s.run("PASS wrong2").starts_with("530 "));
    assert!(!s.peer.is_closed());
    let last = s.run("PASS wrong3");
    assert!(last.starts_with("421 "), "{last}");
    assert!(s.peer.is_closed());
}

#[test]
fn the_right_password_after_the_limit_gets_nowhere() {
    let mut s = Session::with(limits(|l| l.max_failures_per_connection = 2));
    s.run("USER u");
    s.run("PASS wrong1");
    assert!(s.run("PASS wrong2").starts_with("421 "));
    assert!(s.peer.is_closed());
    assert!(s.run("PASS p").is_empty(), "nothing is answered on a closed connection");
}

#[test]
fn a_login_that_works_is_not_counted_against_the_limit() {
    let mut s = Session::with(limits(|l| l.max_failures_per_connection = 2));
    s.run("USER u");
    s.run("PASS wrong");
    assert!(s.run("PASS p").starts_with("230 "), "one failure, then the right password");
    assert!(!s.peer.is_closed());
}

#[test]
fn a_limit_of_zero_means_no_limit() {
    let mut s = Session::with(limits(|l| {
        l.max_failures_per_connection = 0;
        l.lockout_after = 0;
    }));
    s.run("USER u");
    for _ in 0..20 {
        assert!(s.run("PASS wrong").starts_with("530 "));
    }
    assert!(s.run("PASS p").starts_with("230 "));
}

#[test]
fn a_failed_login_is_answered_only_after_the_delay() {
    let mut s = Session::with(limits(|l| l.failure_delay = Duration::from_millis(250)));
    s.run("USER u");
    let started = s.peer.elapsed();
    let reply = s.run("PASS wrong");
    assert!(reply.starts_with("530 "), "{reply}");
    let waited = s.peer.elapsed() - started;
    assert!(waited >= Duration::from_millis(250), "answered after {waited:?}");
}

#[test]
fn commands_sent_behind_a_failed_login_wait_for_it_and_are_answered_in_order() {
    let mut s = Session::with(limits(|l| l.failure_delay = Duration::from_millis(150)));
    s.run("USER u");
    // a client that does not wait for the answer cannot get ahead of the delay
    let started = s.peer.elapsed();
    let replies = s.peer.run("PASS wrong\r\nPASS p\r\nPWD\r\n");
    assert!(s.peer.elapsed() - started >= Duration::from_millis(150));
    let codes: Vec<&str> = replies.lines().map(|l| &l[..3]).collect();
    assert_eq!(codes, ["530", "230", "257"], "{replies}");
}

#[test]
fn a_login_that_works_is_not_delayed() {
    let mut s = Session::with(limits(|l| l.failure_delay = Duration::from_secs(5)));
    let started = s.peer.elapsed();
    s.login();
    // nothing waited for the clock to be skipped to a timer
    assert!(s.peer.elapsed() - started < Duration::from_secs(2), "{:?}", s.peer.elapsed() - started);
}

#[test]
fn guesses_pipelined_in_one_burst_stop_at_the_limit() {
    let mut s = Session::with(limits(|l| l.max_failures_per_connection = 3));
    s.run("USER u");
    let replies = s.peer.run("PASS a\r\nPASS b\r\nPASS c\r\nPASS p\r\n");
    let codes: Vec<&str> = replies.lines().map(|l| &l[..3]).collect();
    assert_eq!(codes, ["530", "530", "421"], "the correct password at the end is never looked at: {replies}");
    assert!(s.peer.is_closed());
}

#[test]
fn failures_from_one_address_lock_it_out_across_connections() {
    let shared = Arc::new(LoginThrottle::default());
    let session = |shared: &Arc<LoginThrottle>| {
        let shared = Arc::clone(shared);
        Session::with(move |c| {
            let mut c = limits(|l| {
                l.max_failures_per_connection = 3;
                l.lockout_after = 5;
                l.lockout_duration = Duration::from_secs(600);
            })(c);
            c.throttle = shared;
            c
        })
    };
    let mut first = session(&shared);
    first.run("USER u");
    first.run("PASS x");
    first.run("PASS x");
    assert!(first.run("PASS x").starts_with("421 "), "three failures: the connection limit");
    // the second connection adds two more and reaches the five
    let mut second = session(&shared);
    assert!(second.greeting.starts_with("220 "));
    second.run("USER u");
    assert!(second.run("PASS x").starts_with("530 "));
    let r = second.run("PASS x");
    assert!(r.starts_with("421 "), "the fifth failure from the address locks it out: {r}");
    // a third is turned away before it can try anything
    let third = session(&shared);
    assert!(third.greeting.starts_with("421 "), "{}", third.greeting);
    assert!(third.peer.is_closed());
    // (that the lockout ends is the throttle's own test: it takes the time it is asked at)
}

#[test]
fn lockout_can_be_turned_off() {
    let shared = Arc::new(LoginThrottle::default());
    for _ in 0..4 {
        let shared = Arc::clone(&shared);
        let mut s = Session::with(move |c| {
            let mut c = limits(|l| {
                l.max_failures_per_connection = 2;
                l.lockout_after = 0;
            })(c);
            c.throttle = shared;
            c
        });
        assert!(s.greeting.starts_with("220 "));
        s.run("USER u");
        s.run("PASS x");
        assert!(s.run("PASS x").starts_with("421 "));
    }
}

#[test]
fn an_unknown_user_is_refused_at_pass_not_user() {
    let mut s = Session::new();
    assert!(s.run("USER nobody").starts_with("331 "), "do not reveal which names exist");
    assert!(s.run("PASS p").starts_with("530 "));
}

#[test]
fn a_new_user_command_ends_the_current_login() {
    let mut s = Session::logged_in();
    assert!(s.run("USER u").starts_with("331 "));
    assert!(s.run("PWD").starts_with("530 "));
}

#[test]
fn quit_says_goodbye_and_closes() {
    let mut s = Session::logged_in();
    assert!(s.run("QUIT").starts_with("221 "));
    assert!(s.peer.is_closed());
}

#[test]
fn rein_forgets_the_previous_user_entirely() {
    // RFC 959: REIN flushes all I/O and account information, as at connect.
    let mut s = Session::logged_in();
    s.run("TYPE A");
    s.run("REST 5");
    assert!(s.run("RNFR pub.txt").starts_with("350 "));
    assert!(s.run("REIN").starts_with("220 "));
    assert!(s.run("PWD").starts_with("530 "));
    s.login();
    assert!(s.run("RNTO stolen.txt").starts_with("503 "), "another user's RNFR must not carry over");
    assert!(s.fs.exists("/pub.txt") && !s.fs.exists("/stolen.txt"));
    assert_eq!(s.peer.handler.transfer_type, TransferType::Image);
    assert_eq!(s.peer.handler.restart, 0);
}

#[test]
fn rein_also_forgets_the_tls_protection_negotiated() {
    let mut s = Session::logged_in();
    s.peer.handler.pbsz = true;
    s.peer.handler.prot_p = true;
    s.run("REIN");
    assert!(!s.peer.handler.prot_p);
}

// -- simple commands ---------------------------------------------------------

#[test]
fn the_fixed_replies() {
    let mut s = Session::logged_in();
    assert_eq!(s.run("NOOP"), "200 OK\r\n");
    assert!(s.run("SYST").starts_with("215 "));
    assert!(s.run("ACCT x").starts_with("202 "));
    assert!(s.run("SMNT /").starts_with("502 "));
    assert!(s.run("FROBNICATE").starts_with("502 "));
    assert!(s.run("STRU F").starts_with("200 ") && s.run("STRU R").starts_with("504 "));
    assert!(s.run("MODE S").starts_with("200 ") && s.run("MODE B").starts_with("504 "));
    assert!(s.run("CCC").starts_with("533 "));
    assert!(s.run("STAT").starts_with("211 "));
    assert!(s.run("SITE CHMOD 755 x").starts_with("502 "));
}

#[test]
fn type_accepts_ascii_and_image_only() {
    let mut s = Session::logged_in();
    assert!(s.run("TYPE A").starts_with("200 "));
    assert_eq!(s.peer.handler.transfer_type, TransferType::Ascii);
    assert!(s.run("TYPE I").starts_with("200 "));
    assert_eq!(s.peer.handler.transfer_type, TransferType::Image);
    assert!(s.run("TYPE A N").starts_with("200 "));
    assert!(s.run("TYPE E").starts_with("504 "));
    assert!(s.run("TYPE X").starts_with("504 "));
}

#[test]
fn feat_lists_only_what_the_server_does() {
    let mut s = Session::logged_in();
    let f = s.run("FEAT");
    assert!(f.starts_with("211-") && f.ends_with("211 End\r\n"), "{f}");
    for want in [" UTF8", " SIZE", " MDTM", " MLST ", " MLSD", " REST STREAM", " EPSV", " EPRT"] {
        assert!(f.contains(&format!("\r\n{want}")) || f.contains(want), "{want} in {f}");
    }
    // No TLS configured: AUTH TLS, PBSZ and PROT are not on offer.
    for not in [" AUTH TLS", " PBSZ", " PROT"] {
        assert!(!f.contains(not), "{not} advertised without TLS: {f}");
    }
}

#[test]
fn opts_utf8_switches_pathname_encoding() {
    let mut s = Session::logged_in();
    assert!(s.run("OPTS UTF8 ON").starts_with("200 "));
    assert!(s.run("OPTS UTF8 OFF").starts_with("200 "));
    assert!(s.run("OPTS NOPE").starts_with("501 "));
    // non-ASCII names need UTF8 on
    assert!(s.peer.run("CWD caf\u{e9}\r\n").starts_with("501 "));
    assert!(s.run("OPTS UTF8 ON").starts_with("200 "));
    assert!(s.peer.run("CWD caf\u{e9}\r\n").starts_with("550 "), "now it is just a missing directory");
}

// -- the working directory ---------------------------------------------------

#[test]
fn pwd_cwd_and_cdup_move_around_inside_the_root() {
    let mut s = Session::logged_in();
    assert_eq!(s.run("PWD"), "257 \"/\" is current directory\r\n");
    assert!(s.run("CWD docs").starts_with("250 "));
    assert_eq!(s.run("PWD"), "257 \"/docs\" is current directory\r\n");
    assert!(s.run("CDUP").starts_with("250 "));
    assert_eq!(s.run("PWD"), "257 \"/\" is current directory\r\n");
    assert!(s.run("CDUP").starts_with("250 "), "above the root stays at the root");
    assert_eq!(s.run("PWD"), "257 \"/\" is current directory\r\n");
    assert!(s.run("CWD nowhere").starts_with("550 "));
    assert!(s.run("CWD pub.txt").starts_with("550 "), "a file is not a directory");
    assert!(s.run("CWD /docs").starts_with("250 "));
    assert!(s.run("CWD ../..").starts_with("250 "));
    assert_eq!(s.run("PWD"), "257 \"/\" is current directory\r\n", "no way out of the root");
}

#[test]
fn a_quote_in_a_path_is_doubled_in_the_reply() {
    // RFC 959 section 5 (257 replies): embedded double quotes are doubled.
    let mut s = Session::logged_in();
    let r = s.run("MKD a\"b");
    assert_eq!(r, "257 \"/a\"\"b\" created\r\n");
    assert!(s.run("CWD a\"b").starts_with("250 "));
    assert_eq!(s.run("PWD"), "257 \"/a\"\"b\" is current directory\r\n");
}

// -- authorization -----------------------------------------------------------

#[test]
fn every_operation_asks_the_authorization_hook_for_its_path() {
    let mut s = Session::logged_in();
    s.run("CWD docs");
    s.run("RNFR a.txt");
    s.run("RNTO b.txt");
    s.run("MKD sub");
    s.run("RMD sub");
    s.run("DELE b.txt");
    let ops: Vec<String> = s.asked().into_iter().map(|(o, _)| o).collect();
    for want in ["Navigate", "Rename", "CreateDir", "DeleteDir", "Delete"] {
        assert!(ops.iter().any(|o| o == want), "{want} in {ops:?}");
    }
}

#[test]
fn a_path_the_hook_refuses_is_refused_for_every_way_of_looking_at_it() {
    // FtpOperation::Read covers "RETR, LIST, NLST, STAT, SIZE, MDTM", and MLSD/MLST are listings too.
    let mut s = Session::logged_in();
    s.deny("secret");
    for cmd in ["SIZE secret/plan.txt", "MDTM secret/plan.txt", "MLST secret", "MLST secret/plan.txt", "STAT secret", "RETR secret/plan.txt"] {
        let r = s.run(cmd);
        assert!(r.starts_with("550 "), "{cmd}: {r}");
    }
}

#[cfg(feature = "integration")]
#[test]
fn a_path_the_hook_refuses_is_refused_for_a_listing_too() {
    let mut s = Session::logged_in();
    s.deny("secret");
    for cmd in ["LIST secret", "NLST secret", "MLSD secret"] {
        let _data = s.passive();
        let r = s.run(cmd);
        assert!(r.starts_with("550 "), "{cmd}: {r}");
        s.run("ABOR");
    }
}

#[test]
fn a_refused_path_does_not_stop_the_others() {
    let mut s = Session::logged_in();
    s.deny("secret");
    assert!(s.run("SIZE pub.txt").starts_with("213 "));
    assert!(s.run("MDTM pub.txt").starts_with("213 "));
    assert!(s.run("CWD secret").starts_with("550 "));
    assert!(s.run("DELE secret/plan.txt").starts_with("550 "));
    assert!(s.run("RMD secret").starts_with("550 "));
    assert!(s.run("MKD secret2").starts_with("550 "));
    assert!(s.run("RNFR secret/plan.txt").starts_with("550 "));
    assert!(s.fs.exists("/secret/plan.txt"));
}

#[test]
fn a_rename_into_a_refused_place_is_refused_and_can_be_retried() {
    let mut s = Session::logged_in();
    assert!(s.run("RNFR pub.txt").starts_with("350 "));
    s.deny("secret");
    assert!(s.run("RNTO secret/pub.txt").starts_with("550 "));
    *s.policy.deny_containing.lock().unwrap() = None;
    assert!(s.run("RNTO moved.txt").starts_with("250 "));
    assert!(s.fs.exists("/moved.txt"));
}

// -- commands that name a path -----------------------------------------------

#[test]
fn a_command_that_needs_a_pathname_says_so_when_it_has_none() {
    // Silence would leave the client waiting for a reply that never comes.
    let mut s = Session::logged_in();
    for cmd in ["SIZE", "MDTM", "DELE", "RMD", "MKD", "RNFR", "RNTO", "RETR", "STOR", "APPE"] {
        let r = s.run(cmd);
        assert!(r.starts_with("501 "), "{cmd} with no argument: {r:?}");
    }
}

#[test]
fn size_mdtm_and_mlst() {
    let mut s = Session::logged_in();
    assert_eq!(s.run("SIZE pub.txt"), "213 12\r\n");
    assert!(s.run("SIZE docs").starts_with("550 "), "SIZE of a directory");
    assert!(s.run("SIZE nothing").starts_with("550 "));
    let m = s.run("MDTM pub.txt");
    assert!(m.starts_with("213 ") && m.trim_end().len() == 4 + 14 && m[4..18].bytes().all(|b| b.is_ascii_digit()), "{m}");
    assert!(s.run("MDTM nothing").starts_with("550 "));
    let l = s.run("MLST pub.txt");
    assert!(l.starts_with("250-") && l.contains("Type=file;Size=12;Modify="), "{l}");
    assert!(l.contains("Perm=adfrw;") && l.trim_end().ends_with("250 End"), "{l}");
    let d = s.run("MLST docs");
    assert!(d.contains("Type=dir;"), "{d}");
    assert!(s.run("MLST nothing").starts_with("550 "));
}

#[test]
fn a_read_only_server_reports_read_only_permissions() {
    let mut s = Session::with(|mut c| {
        c.read_only = true;
        c
    });
    s.login();
    let l = s.run("MLST pub.txt");
    assert!(l.contains("Perm=r;"), "{l}");
}

#[test]
fn stat_with_a_path_lists_it_on_the_control_connection() {
    let mut s = Session::logged_in();
    let r = s.run("STAT docs");
    assert!(r.starts_with("213-") && r.contains("a.txt") && r.ends_with("213 End of status\r\n"), "{r}");
    let f = s.run("STAT pub.txt");
    assert!(f.contains("pub.txt") && f.contains("12"), "{f}");
    assert!(s.run("STAT nothing").starts_with("550 "));
}

// -- changing files ----------------------------------------------------------

#[test]
fn mkd_rmd_dele_and_rename() {
    let mut s = Session::logged_in();
    assert!(s.run("MKD fresh").starts_with("257 "));
    assert!(s.fs.is_dir("/fresh"));
    assert!(s.run("MKD fresh").starts_with("550 "), "it exists");
    assert!(s.run("RMD fresh").starts_with("250 "));
    assert!(!s.fs.exists("/fresh"));
    assert!(s.run("RMD fresh").starts_with("550 "));
    assert!(s.run("RMD docs").starts_with("550 "), "not empty");
    assert!(s.run("DELE pub.txt").starts_with("250 "));
    assert!(!s.fs.exists("/pub.txt"));
    assert!(s.run("DELE pub.txt").starts_with("550 "));
    assert!(s.run("RNTO x").starts_with("503 "));
    assert!(s.run("RNFR nothing").starts_with("550 "));
    assert!(s.run("RNFR docs").starts_with("350 "));
    assert!(s.run("RNTO folder").starts_with("250 "));
    assert!(s.fs.exists("/folder/a.txt"));
    assert!(s.run("RNTO again").starts_with("503 "), "the RNFR is used up");
}

#[test]
fn paths_cannot_leave_the_root() {
    let mut s = Session::logged_in();
    // Above the root is the root: "../x" is "/x", inside the jail.
    for cmd in ["SIZE ../outside", "SIZE /../../etc/passwd", "DELE ../../x"] {
        let r = s.run(cmd);
        assert!(r.starts_with("550 "), "{cmd}: {r}");
    }
    assert!(s.run("MKD ../escape").starts_with("257 \"/escape\""));
    assert!(s.fs.is_dir("/escape"));
}

#[test]
fn rest_takes_a_non_negative_number() {
    let mut s = Session::logged_in();
    assert!(s.run("REST 100").starts_with("350 "));
    assert!(s.run("REST -1").starts_with("501 "));
    assert!(s.run("REST abc").starts_with("501 "));
    assert!(s.run("REST").starts_with("501 "));
}

// -- data connections --------------------------------------------------------

#[test]
fn a_transfer_needs_a_data_connection_first() {
    let mut s = Session::logged_in();
    for cmd in ["LIST", "NLST", "MLSD", "RETR pub.txt", "STOR x"] {
        assert!(s.run(cmd).starts_with("425 "), "{cmd}");
    }
}

#[cfg(feature = "integration")]
#[test]
fn pasv_names_a_port_that_is_listening() {
    let mut s = Session::logged_in();
    let r = s.run("PASV");
    assert!(r.starts_with("227 Entering Passive Mode (127,0,0,1,"), "{r}");
    let _c = s.passive();
    assert_eq!(s.peer.handler.metrics.pasv_binds.load(std::sync::atomic::Ordering::Relaxed), 2);
}

#[cfg(feature = "integration")]
#[test]
fn pasv_advertises_the_configured_address() {
    let mut s = Session::with(|mut c| {
        c.pasv_advertised = Some("203.0.113.9".parse().unwrap());
        c
    });
    s.login();
    assert!(s.run("PASV").contains("(203,0,113,9,"));
}

/// A session whose passive ports are confined to one free port, and that port.
#[cfg_attr(not(feature = "integration"), allow(dead_code))]
fn one_port_session() -> (Session, u16) {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut s = Session::with(|mut c| {
        c.pasv_port_min = Some(port);
        c.pasv_port_max = Some(port);
        c
    });
    s.login();
    (s, port)
}

#[cfg(feature = "integration")]
#[test]
fn passive_ports_stay_inside_the_configured_range() {
    let (mut s, port) = one_port_session();
    let r = s.run("PASV");
    let nums: Vec<u16> = r[r.find('(').unwrap() + 1..r.find(')').unwrap()].split(',').map(|n| n.parse().unwrap()).collect();
    assert_eq!(nums[4] * 256 + nums[5], port, "{r}");
}

#[cfg(feature = "integration")]
#[test]
fn extended_passive_ports_stay_inside_the_configured_range_too() {
    let (mut s, port) = one_port_session();
    assert_eq!(s.run("EPSV"), format!("229 Entering Extended Passive Mode (|||{port}|)\r\n"));
}

#[cfg(feature = "integration")]
#[test]
fn epsv_variants() {
    let mut s = Session::logged_in();
    assert!(s.run("EPSV").starts_with("229 "));
    assert!(s.run("EPSV 1").starts_with("229 "));
    assert!(s.run("EPSV 2").starts_with("522 "), "the control connection is IPv4");
    assert!(s.run("EPSV 3").starts_with("522 "));
    assert!(s.run("EPSV ALL").starts_with("200 "));
    assert!(s.run("PASV").starts_with("501 "));
    assert!(s.run("PORT 127,0,0,1,0,80").starts_with("501 "));
    assert!(s.run("EPRT |1|127.0.0.1|80|").starts_with("501 "));
    assert!(s.run("EPSV").starts_with("229 "), "EPSV itself is still allowed");
}

#[test]
fn port_and_eprt_accept_only_the_clients_own_address() {
    let mut s = Session::logged_in();
    assert!(s.run("PORT 127,0,0,1,0,80").starts_with("200 "));
    assert!(s.run("PORT 10,1,2,3,0,80").starts_with("504 "), "a bounce to someone else");
    assert!(s.run("PORT 1,2,3").starts_with("501 "));
    assert!(s.run("EPRT |1|127.0.0.1|80|").starts_with("200 "));
    assert!(s.run("EPRT |1|10.1.2.3|80|").starts_with("504 "));
    assert!(s.run("EPRT |2|::1|80|").starts_with("200 ") || s.run("EPRT |2|::1|80|").starts_with("504 "));
    assert!(s.run("EPRT |9|x|80|").starts_with("522 ") || s.run("EPRT |9|x|80|").starts_with("501 "));
    assert!(s.run("EPRT garbage").starts_with("501 "));
}

#[test]
fn bounce_is_allowed_when_asked_for() {
    let mut s = Session::with(|mut c| {
        c.allow_active_bounce = true;
        c
    });
    s.login();
    assert!(s.run("PORT 10,1,2,3,0,80").starts_with("200 "));
}

#[test]
fn require_tls_for_data_refuses_clear_data_connections() {
    let mut s = Session::with(|mut c| {
        c.require_tls_for_data = true;
        c
    });
    s.login();
    assert!(s.run("PASV").starts_with("522 "));
    assert!(s.run("EPSV").starts_with("522 "));
    assert!(s.run("PORT 127,0,0,1,0,80").starts_with("200 "));
    assert!(s.run("LIST").starts_with("522 "), "checked again when the transfer is asked for");
}

#[cfg(feature = "integration")]
#[test]
fn list_nlst_and_mlsd_over_a_passive_connection() {
    let mut s = Session::logged_in();
    let (replies, data) = s.transfer("NLST");
    let text = String::from_utf8_lossy(&data).into_owned();
    assert!(replies.starts_with("150 ") && replies.contains("226 "), "{replies}");
    let mut names: Vec<&str> = text.lines().collect();
    names.sort();
    assert_eq!(names, ["docs", "pub.txt", "secret"]);

    let (replies, data) = s.transfer("LIST");
    let text = String::from_utf8_lossy(&data).into_owned();
    assert!(replies.contains("226 "), "{replies}");
    assert!(text.lines().any(|l| l.starts_with('d') && l.ends_with(" docs")), "{text}");
    assert!(text.lines().any(|l| l.starts_with('-') && l.contains(" 12 ") && l.ends_with(" pub.txt")), "{text}");

    let (replies, data) = s.transfer("MLSD docs");
    let text = String::from_utf8_lossy(&data).into_owned();
    assert!(replies.contains("226 "), "{replies}");
    assert!(text.contains("Type=file;Size=7;") && text.trim_end().ends_with(" a.txt"), "{text}");
}

#[cfg(feature = "integration")]
#[test]
fn list_ignores_ls_style_options() {
    // Clients send `LIST -la` out of habit; the options are not a pathname.
    let mut s = Session::logged_in();
    for cmd in ["LIST -la", "LIST -a docs", "NLST -l"] {
        let (replies, data) = s.transfer(cmd);
        assert!(replies.contains("226 "), "{cmd}: {replies}");
        assert!(!data.is_empty(), "{cmd}: nothing listed");
    }
    let (_, data) = s.transfer("LIST -la docs");
    assert!(String::from_utf8_lossy(&data).contains("a.txt"));
}

#[cfg(feature = "integration")]
#[test]
fn list_of_a_missing_directory_is_refused() {
    let mut s = Session::logged_in();
    let _d = s.passive();
    assert!(s.run("LIST nowhere").starts_with("550 "));
}

#[cfg(feature = "integration")]
#[test]
fn retr_sends_the_file_and_stor_receives_it() {
    let mut s = Session::logged_in();
    let (replies, data) = s.transfer("RETR pub.txt");
    assert!(replies.starts_with("150 ") && replies.contains("226 "), "{replies}");
    assert_eq!(data, b"public text\n");

    let mut d = s.passive();
    let first = s.run("STOR upload.bin");
    d.write_all(b"uploaded bytes").unwrap();
    drop(d);
    let replies = s.until(first, |r| r.contains("226 "));
    assert!(replies.starts_with("150 ") && replies.contains("226 "), "{replies}");
    assert_eq!(s.fs.contents("/upload.bin").unwrap(), b"uploaded bytes");
}

#[cfg(feature = "integration")]
#[test]
fn restart_resumes_a_download_from_the_offset() {
    let mut s = Session::logged_in();
    assert!(s.run("REST 7").starts_with("350 "));
    let (replies, data) = s.transfer("RETR pub.txt");
    assert!(replies.contains("226 "), "{replies}");
    assert_eq!(data, b"text\n");
    // and the marker applied once only
    let (_, data) = s.transfer("RETR pub.txt");
    assert_eq!(data, b"public text\n");
}

#[cfg(feature = "integration")]
#[test]
fn appe_appends_and_stou_makes_a_unique_name() {
    let mut s = Session::logged_in();
    let mut d = s.passive();
    let first = s.run("APPE pub.txt");
    d.write_all(b"more\n").unwrap();
    drop(d);
    s.until(first, |r| r.contains("226 "));
    assert_eq!(s.fs.contents("/pub.txt").unwrap(), b"public text\nmore\n");

    let mut d = s.passive();
    let first = s.run("STOU");
    assert!(first.starts_with("150 FILE: "), "{first}");
    d.write_all(b"unique").unwrap();
    drop(d);
    s.until(first, |r| r.contains("226 "));
}

#[cfg(feature = "integration")]
#[test]
fn retr_of_a_missing_file_or_a_directory_is_refused() {
    let mut s = Session::logged_in();
    let _d = s.passive();
    assert!(s.run("RETR nothing").starts_with("550 "));
    let _d = s.passive();
    assert!(s.run("RETR docs").starts_with("550 "));
}

#[cfg(feature = "integration")]
#[test]
fn abor_always_answers() {
    let mut s = Session::logged_in();
    assert!(s.run("ABOR").starts_with("226 "), "even with nothing to abort");
    let _d = s.passive();
    // Whether the data connection was already accepted decides if a 426 comes first.
    assert!(s.run("ABOR").contains("226 "));
    assert!(s.run("LIST").starts_with("425 "), "ABOR dropped the data connection it had set up");
}

// -- TLS commands without TLS ------------------------------------------------

#[test]
fn tls_commands_without_a_tls_configuration() {
    let mut s = Session::logged_in();
    assert!(s.run("AUTH TLS").starts_with("534 "));
    assert!(s.run("AUTH GSSAPI").starts_with("504 "));
    // PROT needs PBSZ first (RFC 4217); PBSZ itself is accepted on a clear
    // control connection, where PROT P still protects the data channel.
    assert!(s.run("PROT P").starts_with("503 "));
    assert!(s.run("PROT C").starts_with("503 "));
    assert!(s.run("PBSZ 0").starts_with("200 "));
    assert!(s.run("PROT P").starts_with("536 "), "nothing to protect it with");
}

#[test]
fn pbsz_is_zero_and_prot_follows() {
    let mut s = Session::logged_in();
    assert_eq!(s.run("PBSZ 0"), "200 PBSZ=0\r\n");
    assert!(s.run("PBSZ 4096").starts_with("200 PBSZ=0"), "the server answers with the only size it has");
    assert!(s.run("PROT C").starts_with("200 "));
    assert!(s.run("PROT P").starts_with("536 "), "no acceptor to protect with");
    assert!(s.run("PROT X").starts_with("536 "));
}

#[test]
fn auth_tls_on_a_connection_that_is_already_secure_is_refused() {
    let mut s = Session::new();
    s.peer.handler.meta.tls = true;
    assert!(s.run("AUTH TLS").starts_with("503 "), "RFC 4217: no second AUTH");
}

#[test]
fn pasv_is_refused_on_an_ipv6_control_connection() {
    let mut s = Session::logged_in();
    s.peer.handler.meta.local = "[::1]:2121".parse().unwrap();
    assert!(s.run("PASV").starts_with("501 "));
}

#[test]
fn list_options_are_stripped_but_names_beginning_elsewhere_are_not() {
    assert_eq!(strip_list_options("-la"), "");
    assert_eq!(strip_list_options("-l -a docs"), "docs");
    assert_eq!(strip_list_options("  -la   some dir"), "some dir");
    assert_eq!(strip_list_options("docs"), "docs");
    assert_eq!(strip_list_options(""), "");
}

#[test]
fn quoting_doubles_every_quote() {
    assert_eq!(quote_path("/a"), "\"/a\"");
    assert_eq!(quote_path("/a\"b\"c"), "\"/a\"\"b\"\"c\"");
}
