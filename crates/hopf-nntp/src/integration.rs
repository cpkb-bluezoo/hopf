// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in loopback smoke tests against a scripted NNTP server (not run in
//! CI `--lib`): `cargo test -p hopf-nntp --features integration`.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hopf_core::{
    acceptor_from_pem, connector_from_pem, Endpoint, ProtocolHandler, Runtime, RuntimeConfig,
    SecurityInfo, SharedTlsAcceptor, SharedTlsConnector, TcpListenerConfig,
};

use crate::client::reply::LineBuffer;
use crate::{
    NntpClient, NntpClientHandler, NntpClientTimeouts, NntpGreeting, NntpSession, OverviewEntry,
};

// ---------------------------------------------------------------------------
// Scripted server
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct ServerConfig {
    offer_starttls: bool,
    offer_sasl_plain: bool,
    /// The listener is TLS from the first byte: greet after the handshake.
    implicit_tls: bool,
    /// Never answer this command (timeout tests).
    silent_on: Option<&'static str>,
}

#[derive(Default)]
struct Recorded {
    posted: Vec<Vec<u8>>,
    commands: Vec<String>,
}

struct Server {
    config: ServerConfig,
    recorded: Arc<Mutex<Recorded>>,
    lines: LineBuffer,
    authed: bool,
    pending_user: Option<String>,
    group: Option<String>,
    posting: Option<Vec<u8>>,
    /// `AUTHINFO SASL` sent without an initial response: the next line is
    /// the base64 client response.
    sasl_pending: bool,
}

impl Server {
    fn check_plain(&mut self, ep: &mut dyn Endpoint, b64: &str) {
        let raw = B64.decode(b64.trim()).unwrap_or_default();
        let parts: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
        if parts.len() == 3 && parts[1] == b"alice" && parts[2] == b"secret" {
            self.authed = true;
            Self::reply(ep, "281 Authentication accepted");
        } else {
            Self::reply(ep, "481 Authentication failed");
        }
    }

    fn reply(ep: &mut dyn Endpoint, s: &str) {
        ep.send(s.as_bytes());
        ep.send(b"\r\n");
    }

    fn capabilities(&self, ep: &mut dyn Endpoint) {
        Self::reply(ep, "101 Capability list:");
        Self::reply(ep, "VERSION 2");
        Self::reply(ep, "READER");
        if !ep.is_secure() && self.config.offer_starttls {
            Self::reply(ep, "STARTTLS");
        }
        if !self.authed {
            Self::reply(ep, "AUTHINFO USER");
            if self.config.offer_sasl_plain {
                Self::reply(ep, "SASL PLAIN");
            }
        }
        Self::reply(ep, "LIST ACTIVE");
        Self::reply(ep, "OVER");
        Self::reply(ep, "POST");
        Self::reply(ep, ".");
    }

    fn on_command(&mut self, ep: &mut dyn Endpoint, line: &str) {
        self.recorded.lock().unwrap().commands.push(line.to_string());
        let upper = line.to_ascii_uppercase();
        if let Some(silent) = self.config.silent_on {
            if upper.starts_with(silent) {
                return;
            }
        }
        let mut words = line.split_whitespace();
        let verb = words.next().unwrap_or("").to_ascii_uppercase();
        match verb.as_str() {
            "CAPABILITIES" => self.capabilities(ep),
            "STARTTLS" => {
                if self.config.offer_starttls && !ep.is_secure() {
                    Self::reply(ep, "382 Continue with TLS negotiation");
                    let _ = ep.start_tls();
                } else {
                    Self::reply(ep, "502 Command unavailable");
                }
            }
            "AUTHINFO" => {
                let kind = words.next().unwrap_or("").to_ascii_uppercase();
                match kind.as_str() {
                    "USER" => {
                        self.pending_user = Some(words.next().unwrap_or("").to_string());
                        Self::reply(ep, "381 Enter passphrase");
                    }
                    "PASS" => {
                        let ok = self.pending_user.as_deref() == Some("alice") && words.next() == Some("secret");
                        if ok {
                            self.authed = true;
                            Self::reply(ep, "281 Authentication accepted");
                        } else {
                            Self::reply(ep, "481 Authentication failed");
                        }
                    }
                    "SASL" => {
                        let mech = words.next().unwrap_or("").to_ascii_uppercase();
                        let initial = words.next().unwrap_or("");
                        if mech != "PLAIN" || !self.config.offer_sasl_plain {
                            return Self::reply(ep, "503 Mechanism not supported");
                        }
                        if initial.is_empty() {
                            self.sasl_pending = true;
                            Self::reply(ep, "383 =");
                        } else {
                            self.check_plain(ep, initial);
                        }
                    }
                    _ => Self::reply(ep, "501 Syntax error"),
                }
            }
            "QUIT" => {
                Self::reply(ep, "205 Closing connection");
                ep.close();
            }
            _ if !self.authed => Self::reply(ep, "480 Authentication required"),
            "LIST" => {
                let rest: Vec<&str> = words.collect();
                Self::reply(ep, "215 Newsgroups in form \"group high low flags\"");
                let all = ["comp.lang.rust 1234 12 y", "comp.lang.c 99 1 y", "alt.test 5 5 m"];
                let pattern = rest.get(1).copied().unwrap_or("");
                for g in all {
                    if pattern.is_empty() || (pattern.ends_with('*') && g.starts_with(&pattern[..pattern.len() - 1])) {
                        Self::reply(ep, g);
                    }
                }
                Self::reply(ep, ".");
            }
            "GROUP" => {
                let name = words.next().unwrap_or("");
                if name == "comp.lang.rust" {
                    self.group = Some(name.to_string());
                    Self::reply(ep, "211 3 10 12 comp.lang.rust");
                } else {
                    Self::reply(ep, "411 No such newsgroup");
                }
            }
            "OVER" => {
                if self.group.is_none() {
                    return Self::reply(ep, "412 No newsgroup selected");
                }
                Self::reply(ep, "224 Overview information follows");
                Self::reply(ep, "10\tFirst\tann <ann@example.com>\tMon, 6 Oct 2026 10:00:00 +0000\t<a1@example.com>\t\t120\t3");
                Self::reply(ep, "11\tRe: First\tbob <bob@example.com>\tMon, 6 Oct 2026 11:00:00 +0000\t<b1@example.com>\t<a1@example.com>\t140\t4");
                Self::reply(ep, "12\t.Leading dot subject\tcat <cat@example.com>\tMon, 6 Oct 2026 12:00:00 +0000\t<c1@example.com>\t\t90\t2");
                Self::reply(ep, ".");
            }
            "ARTICLE" | "HEAD" => {
                let n = words.next().unwrap_or("");
                if self.group.is_none() || n != "12" {
                    return Self::reply(ep, "423 No article with that number");
                }
                let is_head = verb == "HEAD";
                Self::reply(ep, if is_head { "221 12 <c1@example.com>" } else { "220 12 <c1@example.com>" });
                Self::reply(ep, "From: cat <cat@example.com>");
                Self::reply(ep, "Subject: .Leading dot subject");
                Self::reply(ep, "Message-ID: <c1@example.com>");
                if !is_head {
                    Self::reply(ep, "");
                    Self::reply(ep, "..starts with a dot");
                    Self::reply(ep, "second line");
                }
                Self::reply(ep, ".");
            }
            "POST" => {
                self.posting = Some(Vec::new());
                Self::reply(ep, "340 Input article; end with <CR-LF>.<CR-LF>");
            }
            _ => Self::reply(ep, "500 Unknown command"),
        }
    }
}

impl ProtocolHandler for Server {
    fn connected(&mut self, ep: &mut dyn Endpoint) {
        if !self.config.implicit_tls {
            Self::reply(ep, "200 scripted news server ready (posting ok)");
        }
    }

    fn security_established(&mut self, ep: &mut dyn Endpoint, _info: &SecurityInfo) {
        if self.config.implicit_tls {
            Self::reply(ep, "200 scripted news server ready (posting ok)");
        }
    }

    fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
        self.lines.push(data);
        *data = &[];
        while let Some(line) = self.lines.next_line() {
            if let Some(body) = self.posting.as_mut() {
                if line == b"." {
                    let article = self.posting.take().unwrap();
                    self.recorded.lock().unwrap().posted.push(article);
                    Self::reply(ep, "240 Article received OK");
                } else {
                    let l: &[u8] = if line.starts_with(b"..") { &line[1..] } else { &line[..] };
                    body.extend_from_slice(l);
                    body.extend_from_slice(b"\r\n");
                }
                continue;
            }
            let text = String::from_utf8_lossy(&line).into_owned();
            if self.sasl_pending {
                self.sasl_pending = false;
                self.recorded.lock().unwrap().commands.push(format!("<sasl response {} bytes>", text.len()));
                self.check_plain(ep, &text);
                continue;
            }
            self.on_command(ep, &text);
        }
    }

    fn disconnected(&mut self, _ep: &mut dyn Endpoint) {}

    fn error(&mut self, _ep: &mut dyn Endpoint, _err: &io::Error) {}
}

fn start_server(rt: &Runtime, mut config: ServerConfig, tls: Option<(SharedTlsAcceptor, bool)>) -> (SocketAddr, Arc<Mutex<Recorded>>) {
    config.implicit_tls = matches!(tls, Some((_, true)));
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let rec = Arc::clone(&recorded);
    let mut cfg = TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
        Box::new(Server {
            config: config.clone(),
            recorded: Arc::clone(&rec),
            lines: LineBuffer::default(),
            authed: false,
            pending_user: None,
            group: None,
            posting: None,
            sasl_pending: false,
        }) as Box<dyn ProtocolHandler>
    });
    if let Some((acceptor, implicit)) = tls {
        cfg = if implicit { cfg.with_tls(acceptor) } else { cfg.with_starttls_acceptor(acceptor) };
    }
    let (addr, _) = rt.add_tcp_listener(cfg).unwrap();
    (addr, recorded)
}

fn tls_pair() -> (SharedTlsAcceptor, SharedTlsConnector, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap().self_signed(&key).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();
    let connector = connector_from_pem(&cert_path, &[]).unwrap();
    (acceptor, connector, dir)
}

// ---------------------------------------------------------------------------
// Client-side recording
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Outcome {
    greeting: Option<NntpGreeting>,
    error: Option<String>,
    disconnected: bool,
    groups: Vec<String>,
    list_done: Option<Result<(), String>>,
    group_result: Option<Result<(u64, u64, u64), String>>,
    missing_group: Option<String>,
    overview: Vec<OverviewEntry>,
    article: Vec<String>,
    head: Vec<String>,
    posted: Option<Result<(), String>>,
    session: Option<NntpSession>,
}

type Shared = Arc<Mutex<Outcome>>;

/// Runs the full command set on connect, then QUITs.
struct FullRun(Shared);

impl NntpClientHandler for FullRun {
    fn on_connected(&mut self, session: &NntpSession, greeting: &NntpGreeting) {
        self.0.lock().unwrap().greeting = Some(greeting.clone());
        self.0.lock().unwrap().session = Some(session.clone());
        let o = Arc::clone(&self.0);
        let o2 = Arc::clone(&self.0);
        session.list_active("comp.*", move |g| o.lock().unwrap().groups.push(g.name), move |r| {
            o2.lock().unwrap().list_done = Some(r.map_err(|e| e.to_string()));
        });
        let o = Arc::clone(&self.0);
        session.group("alt.nope", move |r| {
            o.lock().unwrap().missing_group = r.err().map(|e| e.to_string());
        });
        let o = Arc::clone(&self.0);
        session.group("comp.lang.rust", move |r| {
            o.lock().unwrap().group_result = Some(r.map(|g| (g.count, g.first, g.last)).map_err(|e| e.to_string()));
        });
        let o = Arc::clone(&self.0);
        session.over(10, 12, move |e| o.lock().unwrap().overview.push(e), |_| {});
        let o = Arc::clone(&self.0);
        session.article(12, move |l| o.lock().unwrap().article.push(String::from_utf8_lossy(l).into_owned()), |_| {});
        let o = Arc::clone(&self.0);
        session.head(12, move |l| o.lock().unwrap().head.push(String::from_utf8_lossy(l).into_owned()), |_| {});
        let o = Arc::clone(&self.0);
        session.post(
            b"From: alice <alice@example.com>\r\nNewsgroups: comp.lang.rust\r\nSubject: hi\r\n\r\n.hidden dot\r\nbody line\r\n",
            move |r| o.lock().unwrap().posted = Some(r.map_err(|e| e.to_string())),
        );
        session.quit();
    }

    fn on_error(&mut self, error: &io::Error) {
        self.0.lock().unwrap().error = Some(error.to_string());
    }

    fn on_disconnected(&mut self) {
        self.0.lock().unwrap().disconnected = true;
    }
}

fn wait_for(mut pred: impl FnMut() -> bool, max: Duration) -> bool {
    let deadline = Instant::now() + max;
    loop {
        if pred() {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_full_run(out: &Shared, recorded: &Arc<Mutex<Recorded>>, secure: bool, authenticated: bool) {
    assert!(wait_for(|| out.lock().unwrap().disconnected, Duration::from_secs(5)), "session never ended: {:?}", out.lock().unwrap().error);
    let o = out.lock().unwrap();
    assert_eq!(o.error, None, "server saw: {:?}", recorded.lock().unwrap().commands);
    let g = o.greeting.as_ref().expect("connected");
    assert!(g.posting_allowed);
    assert_eq!(g.secure, secure);
    assert_eq!(g.authenticated, authenticated);
    assert!(g.capabilities.iter().any(|c| c == "VERSION 2"), "{:?}", g.capabilities);
    assert_eq!(o.groups, vec!["comp.lang.rust", "comp.lang.c"]);
    assert_eq!(o.list_done, Some(Ok(())));
    assert!(o.missing_group.as_deref().unwrap_or("").contains("411"), "{:?}", o.missing_group);
    assert_eq!(o.group_result, Some(Ok((3, 10, 12))));
    assert_eq!(o.overview.len(), 3);
    assert_eq!(o.overview[1].references, "<a1@example.com>");
    assert_eq!(o.overview[2].subject, ".Leading dot subject");
    assert_eq!(o.article, vec!["From: cat <cat@example.com>", "Subject: .Leading dot subject", "Message-ID: <c1@example.com>", "", ".starts with a dot", "second line"]);
    assert_eq!(o.head.len(), 3);
    assert_eq!(o.posted, Some(Ok(())));
    let r = recorded.lock().unwrap();
    assert_eq!(r.posted.len(), 1);
    assert_eq!(
        r.posted[0],
        b"From: alice <alice@example.com>\r\nNewsgroups: comp.lang.rust\r\nSubject: hi\r\n\r\n.hidden dot\r\nbody line\r\n".to_vec(),
        "the server saw the article unstuffed"
    );
    assert!(r.commands.iter().any(|c| c == "QUIT"));
    assert!(o.session.as_ref().map(|s| !s.is_alive()).unwrap_or(true), "session reports closed after QUIT");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn cleartext_user_pass_session_runs_every_command() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (addr, recorded) = start_server(&rt, ServerConfig::default(), None);
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .credentials("alice", "secret")
        .connect_with(&rt, Box::new(FullRun(Arc::clone(&out))))
        .unwrap();
    assert_full_run(&out, &recorded, false, true);
    assert!(recorded.lock().unwrap().commands.iter().any(|c| c == "AUTHINFO USER alice"));
}

#[test]
fn sasl_plain_is_preferred_when_offered() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (addr, recorded) = start_server(&rt, ServerConfig { offer_sasl_plain: true, ..Default::default() }, None);
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .credentials("alice", "secret")
        .connect_with(&rt, Box::new(FullRun(Arc::clone(&out))))
        .unwrap();
    assert_full_run(&out, &recorded, false, true);
    let cmds = recorded.lock().unwrap().commands.clone();
    // hopf-auth's PLAIN client answers the server's empty challenge rather
    // than sending an initial response inline; both are RFC 4643 §2.4.
    assert!(cmds.iter().any(|c| c.starts_with("AUTHINFO SASL PLAIN")), "{cmds:?}");
    assert!(cmds.iter().any(|c| c.starts_with("<sasl response")), "{cmds:?}");
    assert!(!cmds.iter().any(|c| c.starts_with("AUTHINFO USER")), "{cmds:?}");
}

#[test]
fn starttls_then_authenticate() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (acceptor, connector, _dir) = tls_pair();
    let (addr, recorded) = start_server(&rt, ServerConfig { offer_starttls: true, ..Default::default() }, Some((acceptor, false)));
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .starttls(connector, "localhost")
        .credentials("alice", "secret")
        .connect_with(&rt, Box::new(FullRun(Arc::clone(&out))))
        .unwrap();
    assert_full_run(&out, &recorded, true, true);
    let cmds = recorded.lock().unwrap().commands.clone();
    let starttls = cmds.iter().position(|c| c == "STARTTLS").expect("STARTTLS sent");
    let auth = cmds.iter().position(|c| c.starts_with("AUTHINFO")).expect("auth sent");
    assert!(starttls < auth, "credentials only after TLS: {cmds:?}");
    assert_eq!(cmds.iter().filter(|c| *c == "CAPABILITIES").count(), 2, "capabilities re-read after TLS");
}

#[test]
fn implicit_tls_session() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (acceptor, connector, _dir) = tls_pair();
    let (addr, recorded) = start_server(&rt, ServerConfig::default(), Some((acceptor, true)));
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .implicit_tls(connector, "localhost")
        .credentials("alice", "secret")
        .connect_with(&rt, Box::new(FullRun(Arc::clone(&out))))
        .unwrap();
    assert_full_run(&out, &recorded, true, true);
}

#[test]
fn required_starttls_fails_when_not_offered() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (_acceptor, connector, _dir) = tls_pair();
    let (addr, _recorded) = start_server(&rt, ServerConfig::default(), None);
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .starttls(connector, "localhost")
        .credentials("alice", "secret")
        .connect_with(&rt, Box::new(FullRun(Arc::clone(&out))))
        .unwrap();
    assert!(wait_for(|| out.lock().unwrap().error.is_some(), Duration::from_secs(5)));
    let o = out.lock().unwrap();
    assert!(o.error.as_deref().unwrap().contains("STARTTLS"), "{:?}", o.error);
    assert!(o.greeting.is_none(), "credentials must not have been sent");
}

#[test]
fn opportunistic_starttls_proceeds_in_the_clear_when_not_offered() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (_acceptor, connector, _dir) = tls_pair();
    let (addr, recorded) = start_server(&rt, ServerConfig::default(), None);
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .opportunistic_starttls(connector, "localhost")
        .credentials("alice", "secret")
        .connect_with(&rt, Box::new(FullRun(Arc::clone(&out))))
        .unwrap();
    assert_full_run(&out, &recorded, false, true);
}

#[test]
fn wrong_password_is_reported_and_nothing_else_is_sent() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (addr, recorded) = start_server(&rt, ServerConfig::default(), None);
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .credentials("alice", "wrong")
        .connect_with(&rt, Box::new(FullRun(Arc::clone(&out))))
        .unwrap();
    assert!(wait_for(|| out.lock().unwrap().error.is_some(), Duration::from_secs(5)));
    let o = out.lock().unwrap();
    assert!(o.error.as_deref().unwrap().contains("481"), "{:?}", o.error);
    assert!(o.greeting.is_none());
    assert!(!recorded.lock().unwrap().commands.iter().any(|c| c.starts_with("LIST")));
}

#[test]
fn a_silent_server_times_out_the_command_and_fails_the_rest() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (addr, _recorded) = start_server(&rt, ServerConfig { silent_on: Some("GROUP"), ..Default::default() }, None);
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .credentials("alice", "secret")
        .timeouts(NntpClientTimeouts { command: Duration::from_millis(300), ..Default::default() })
        .connect_with(&rt, Box::new(FullRun(Arc::clone(&out))))
        .unwrap();
    assert!(wait_for(|| out.lock().unwrap().error.is_some(), Duration::from_secs(5)));
    let o = out.lock().unwrap();
    assert!(o.error.as_deref().unwrap().contains("no reply"), "{:?}", o.error);
    assert_eq!(o.list_done, Some(Ok(())), "the command before the silent one completed");
    assert!(o.posted.as_ref().map(|p| p.is_err()).unwrap_or(false), "queued commands fail with the transport error: {:?}", o.posted);
}

#[test]
fn refused_dial_reaches_on_error() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = free.local_addr().unwrap();
    drop(free);
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .connect_with(&rt, Box::new(FullRun(Arc::clone(&out))))
        .unwrap();
    assert!(wait_for(|| out.lock().unwrap().error.is_some(), Duration::from_secs(5)), "refused connect never reported");
}
