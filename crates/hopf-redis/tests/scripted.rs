// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The client against a scripted RESP server on loopback: what a real server
//! cannot be made to do on cue. An old server that does not know `HELLO`, a
//! wrong password, a connection dropped mid-pipeline, a reply nobody asked for,
//! a slow handshake, TLS.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, TcpListenerConfig};
use hopf_redis::{RedisClient, RedisConfig, RedisError, RespParser, Value};

use common::*;

/// What a script sees of one command and its connection.
struct Session<'a> {
    endpoint: &'a mut dyn Endpoint,
    /// Which connection this is, from 0.
    conn: usize,
    /// The 0-based index of this command on its connection.
    seq: usize,
    /// Commands held back by the script so far on this connection.
    held: &'a mut Vec<Vec<Vec<u8>>>,
}

impl Session<'_> {
    fn reply(&mut self, bytes: impl AsRef<[u8]>) {
        self.endpoint.send(bytes.as_ref());
    }
    fn reply_after(&self, wait: Duration, bytes: impl AsRef<[u8]> + Send + 'static) {
        let handle: ConnHandle = self.endpoint.handle();
        thread::spawn(move || {
            thread::sleep(wait);
            handle.with_endpoint(move |ep| ep.send(bytes.as_ref()));
        });
    }
    fn close(&mut self) {
        self.endpoint.close();
    }
}

type Script = dyn Fn(&mut Session, &[Vec<u8>]) + Send + Sync;

struct Scripted {
    script: Arc<Script>,
    conn: usize,
    parser: RespParser,
    seq: usize,
    held: Vec<Vec<Vec<u8>>>,
}

impl ProtocolHandler for Scripted {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        let mut commands = Vec::new();
        hopf_core::with_slice(buf, |data| {
            self.parser
                .feed(data, &mut |v| {
                    if let Value::Array(words) = v {
                        commands.push(words.iter().map(|w| w.as_bytes().unwrap().to_vec()).collect::<Vec<_>>());
                    }
                })
                .unwrap();
        });
        for words in commands {
            let mut session = Session {
                endpoint,
                conn: self.conn,
                seq: self.seq,
                held: &mut self.held,
            };
            self.seq += 1;
            (self.script)(&mut session, &words);
        }
    }
    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
}

struct Server {
    rt: Runtime,
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

fn serve(script: impl Fn(&mut Session, &[Vec<u8>]) + Send + Sync + 'static) -> Server {
    serve_on("127.0.0.1:0".parse().unwrap(), None, script)
}

fn serve_on(
    addr: SocketAddr,
    tls: Option<hopf_core::SharedTlsAcceptor>,
    script: impl Fn(&mut Session, &[Vec<u8>]) + Send + Sync + 'static,
) -> Server {
    let script: Arc<Script> = Arc::new(script);
    let connections = Arc::new(AtomicUsize::new(0));
    let rt = runtime();
    let (sc, cn) = (Arc::clone(&script), Arc::clone(&connections));
    let mut listener = TcpListenerConfig::new(addr, move || {
        Box::new(Scripted {
            script: Arc::clone(&sc),
            conn: cn.fetch_add(1, Ordering::SeqCst),
            parser: RespParser::new(),
            seq: 0,
            held: Vec::new(),
        }) as Box<dyn ProtocolHandler>
    });
    if let Some(acceptor) = tls {
        listener = listener.with_tls(acceptor);
    }
    let (addr, _) = rt.add_tcp_listener(listener).unwrap();
    Server { rt, addr, connections }
}

fn name_of(words: &[Vec<u8>]) -> String {
    String::from_utf8_lossy(&words[0]).to_ascii_uppercase()
}

fn arg(words: &[Vec<u8>], i: usize) -> String {
    String::from_utf8_lossy(&words[i]).into_owned()
}

/// A RESP3 reply to `HELLO 3`.
const HELLO_OK: &str = "%2\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n";

fn client(server: &Server, config: impl FnOnce(RedisConfig) -> RedisConfig) -> (Runtime, RedisClient) {
    let rt = runtime();
    let c = RedisClient::connect(rt.pick_worker(), config(RedisConfig::from_addr(server.addr)));
    (rt, c)
}

#[test]
fn a_server_without_hello_gets_resp2_with_auth_and_select() {
    let seen: Arc<Mutex<Vec<Vec<String>>>> = Arc::default();
    let log = Arc::clone(&seen);
    let server = serve(move |s, w| {
        log.lock().unwrap().push(w.iter().map(|x| String::from_utf8_lossy(x).into_owned()).collect());
        match name_of(w).as_str() {
            "HELLO" => s.reply("-ERR unknown command 'HELLO', with args beginning with: '3' 'AUTH' 'default' 'pw'\r\n"),
            "AUTH" | "SELECT" | "CLIENT" => s.reply("+OK\r\n"),
            "GET" => s.reply("$1\r\nv\r\n"),
            _ => s.reply("-ERR what\r\n"),
        }
    });
    let (rt, c) = client(&server, |c| c.password("pw").database(1).client_name("me"));
    let got = call!(|cb| c.get("k", cb)).unwrap();
    assert_eq!(got.map(|b| b.to_vec()), Some(b"v".to_vec()));
    assert!(!c.is_resp3());
    let words: Vec<String> = seen.lock().unwrap().iter().map(|w| w.join(" ")).collect();
    assert_eq!(
        words,
        vec![
            "HELLO 3 AUTH default pw SETNAME me",
            "AUTH pw",
            "CLIENT SETNAME me",
            "SELECT 1",
            "GET k"
        ]
    );
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_wrong_password_fails_the_waiting_commands_and_is_not_retried_in_resp2() {
    let hellos = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hellos);
    let server = serve(move |s, w| match name_of(w).as_str() {
        "HELLO" => {
            h.fetch_add(1, Ordering::SeqCst);
            s.reply("-WRONGPASS invalid username-password pair or user is disabled.\r\n");
        }
        other => panic!("nothing should follow a refused HELLO, got {other}"),
    });
    let (rt, c) = client(&server, |c| c.password("nope"));
    let err = call!(|cb| c.ping(cb)).unwrap_err();
    assert_eq!(err.server_code(), Some("WRONGPASS"), "{err}");
    // Soon after, a command fails at once without another attempt.
    let started = Instant::now();
    let err = call!(|cb| c.ping(cb)).unwrap_err();
    assert!(started.elapsed() < Duration::from_millis(80), "it failed fast");
    assert!(matches!(err, RedisError::Server(_) | RedisError::Connect(_)), "{err}");
    assert_eq!(hellos.load(Ordering::SeqCst), 1, "one attempt, not one per command");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn commands_wait_for_the_handshake_and_go_out_in_order_afterwards() {
    #[derive(Debug, PartialEq)]
    enum Ev {
        HelloReplied,
        Got(String),
    }
    let events: Arc<Mutex<Vec<(Ev, Instant)>>> = Arc::default();
    let log = Arc::clone(&events);
    let server = serve(move |s, w| match name_of(w).as_str() {
        "HELLO" => {
            let log = Arc::clone(&log);
            let handle = s.endpoint.handle();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(300));
                log.lock().unwrap().push((Ev::HelloReplied, Instant::now()));
                handle.with_endpoint(|ep| ep.send(HELLO_OK.as_bytes()));
            });
        }
        "GET" => {
            log.lock().unwrap().push((Ev::Got(arg(w, 1)), Instant::now()));
            s.reply("$1\r\nv\r\n");
        }
        _ => s.reply("+OK\r\n"),
    });
    let (rt, c) = client(&server, |c| c);
    let (tx, rx) = mpsc::channel();
    for k in ["first", "second", "third"] {
        let tx = tx.clone();
        c.get(k, move |r| {
            let _ = tx.send((k, r.is_ok()));
        });
    }
    let got: Vec<_> = (0..3).map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap()).collect();
    assert_eq!(got, vec![("first", true), ("second", true), ("third", true)]);
    let ev = events.lock().unwrap();
    assert_eq!(ev[0].0, Ev::HelloReplied, "no command reached the server before HELLO was answered");
    let gets: Vec<_> = ev.iter().filter_map(|(e, _)| if let Ev::Got(k) = e { Some(k.clone()) } else { None }).collect();
    assert_eq!(gets, ["first", "second", "third"]);
    drop(ev);
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn commands_are_written_without_waiting_for_earlier_replies() {
    // The server answers nothing until fifty commands have arrived. A client that
    // waited for each reply before sending the next would never get there.
    let server = serve(move |s, w| match name_of(w).as_str() {
        "HELLO" => s.reply(HELLO_OK),
        "GET" => {
            s.held.push(w.to_vec());
            if s.held.len() == 50 {
                let mut out = Vec::new();
                for words in s.held.drain(..) {
                    let key = String::from_utf8_lossy(&words[1]).into_owned();
                    out.extend_from_slice(format!("${}\r\n{key}\r\n", key.len()).as_bytes());
                }
                s.reply(out);
            }
        }
        _ => s.reply("+OK\r\n"),
    });
    let (rt, c) = client(&server, |c| c);
    let (tx, rx) = mpsc::channel();
    for i in 0..50 {
        let tx = tx.clone();
        c.get(format!("k{i}"), move |r| {
            let _ = tx.send(r.unwrap().map(|b| String::from_utf8_lossy(&b).into_owned()));
        });
    }
    let got: Vec<_> = (0..50).map(|_| rx.recv_timeout(Duration::from_secs(5)).expect("all replies arrived").unwrap()).collect();
    assert_eq!(got, (0..50).map(|i| format!("k{i}")).collect::<Vec<_>>(), "each reply to its own command, in order");
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_connection_dropped_mid_pipeline_fails_the_rest_once_each() {
    // seq 0 is HELLO; the three GETs are seq 1, 2 and 3.
    let server = serve(move |s, w| match (name_of(w).as_str(), s.seq) {
        ("HELLO", _) => s.reply(HELLO_OK),
        ("GET", 1) => s.reply("$3\r\none\r\n"),
        ("GET", 2) => s.close(),
        _ => {}
    });
    let (rt, c) = client(&server, |c| c.command_timeout(None));
    let (tx, rx) = mpsc::channel();
    for i in 1..=3 {
        let tx = tx.clone();
        c.get(format!("k{i}"), move |r| {
            let _ = tx.send((i, r));
        });
    }
    let mut got: Vec<_> = (0..3).map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap()).collect();
    got.sort_by_key(|(i, _)| *i);
    assert!(got[0].1.is_ok(), "answered before the drop");
    assert!(matches!(&got[1].1, Err(RedisError::ConnectionLost(_))), "{:?}", got[1]);
    assert!(matches!(&got[2].1, Err(RedisError::ConnectionLost(_))), "{:?}", got[2]);
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "each callback ran once");
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_reply_nobody_asked_for_drops_the_connection_and_the_next_command_reconnects() {
    let server = serve(move |s, w| match name_of(w).as_str() {
        "HELLO" => s.reply(HELLO_OK),
        "PING" if s.conn == 0 => {
            // Two replies to one command.
            s.reply("+PONG\r\n+SURPRISE\r\n");
        }
        "PING" => s.reply("+PONG\r\n"),
        _ => s.reply("+OK\r\n"),
    });
    let (rt, c) = client(&server, |c| c);
    call!(|cb| c.ping(cb)).unwrap();
    for _ in 0..200 {
        if !c.is_ready() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!c.is_ready(), "the stray reply ended the connection");
    // The failed connection was a working one, so there is no hold-off.
    call!(|cb| c.ping(cb)).unwrap();
    assert_eq!(server.connections.load(Ordering::SeqCst), 2);
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_command_that_timed_out_does_not_steal_the_reply_of_the_one_behind_it() {
    // Both replies come together, in order, 475 ms after `one` was issued: after
    // its 400 ms timeout, and within `two`'s, which was issued 150 ms later.
    let server = serve(move |s, w| match (name_of(w).as_str(), s.seq) {
        ("HELLO", _) => s.reply(HELLO_OK),
        ("GET", 1) => s.held.push(w.to_vec()),
        ("GET", 2) => {
            s.held.push(w.to_vec());
            s.reply_after(Duration::from_millis(325), "$3\r\none\r\n$3\r\ntwo\r\n");
        }
        _ => s.reply("+OK\r\n"),
    });
    let (rt, c) = client(&server, |c| c.command_timeout(Some(Duration::from_millis(400))));
    let (tx1, rx1) = mpsc::channel();
    c.get("one", move |r| {
        let _ = tx1.send(r);
    });
    thread::sleep(Duration::from_millis(150));
    let (tx2, rx2) = mpsc::channel();
    c.get("two", move |r| {
        let _ = tx2.send(r);
    });
    assert_eq!(rx1.recv_timeout(Duration::from_secs(5)).unwrap().unwrap_err(), RedisError::Timeout);
    let two = rx2.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
    assert_eq!(two.as_deref(), Some(&b"two"[..]), "it got its own reply, not one's");
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_server_that_comes_up_later_is_reached_after_the_backoff() {
    // A port nothing listens on yet.
    let addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let rt = runtime();
    let c = RedisClient::connect(
        rt.pick_worker(),
        RedisConfig::from_addr(addr).reconnect_backoff(Duration::from_millis(150), Duration::from_millis(150)),
    );
    let err = call!(|cb| c.ping(cb)).unwrap_err();
    assert!(matches!(err, RedisError::Connect(_)), "{err}");
    // During the hold-off, commands fail at once.
    let started = Instant::now();
    assert!(matches!(call!(|cb| c.ping(cb)).unwrap_err(), RedisError::Connect(_)));
    assert!(started.elapsed() < Duration::from_millis(100));
    // The server starts; once the hold-off is over the next command connects.
    let server = serve_on(addr, None, move |s, w| match name_of(w).as_str() {
        "HELLO" => s.reply(HELLO_OK),
        _ => s.reply("+PONG\r\n"),
    });
    thread::sleep(Duration::from_millis(250));
    call!(|cb| c.ping(cb)).unwrap();
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_name_that_does_not_resolve_is_a_connect_error() {
    let rt = runtime();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new("no-such-host.invalid", 6379));
    let err = call!(|cb| c.ping(cb)).unwrap_err();
    assert!(matches!(err, RedisError::Connect(_)), "{err}");
    rt.shutdown();
}

#[test]
fn tls_to_a_server_with_a_trusted_certificate() {
    use hopf_core::ClientTlsBuilder;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["redis.test".to_string()]).unwrap().self_signed(&key).unwrap();
    let creds = hopf_core::server_credentials_from_pem_bytes(cert.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
    let acceptor = hopf_core::ServerTlsBuilder::new().credentials(creds).build().unwrap();
    let server = serve_on("127.0.0.1:0".parse().unwrap(), Some(acceptor), move |s, w| match name_of(w).as_str() {
        "HELLO" => s.reply(HELLO_OK),
        "GET" => s.reply("$6\r\nsecret\r\n"),
        _ => s.reply("+OK\r\n"),
    });
    let rt = runtime();
    let trusted = ClientTlsBuilder::new().trust_anchors([hopf_core::Bytes::copy_from_slice(cert.der())]).build();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::from_addr(server.addr).tls(trusted, "redis.test"));
    assert_eq!(call!(|cb| c.get("k", cb)).unwrap().map(|b| b.to_vec()), Some(b"secret".to_vec()));
    c.close();

    // The public WebPKI does not know this certificate: the connect fails.
    let untrusting = ClientTlsBuilder::new().public_trust().build();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::from_addr(server.addr).tls(untrusting, "redis.test"));
    let err = call!(|cb| c.ping(cb)).unwrap_err();
    assert!(matches!(err, RedisError::Connect(_)), "{err}");
    // And the wrong name does too.
    let trusted = ClientTlsBuilder::new().trust_anchors([hopf_core::Bytes::copy_from_slice(cert.der())]).build();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::from_addr(server.addr).tls(trusted, "other.test"));
    let err = call!(|cb| c.ping(cb)).unwrap_err();
    assert!(matches!(err, RedisError::Connect(_)), "{err}");
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_command_issued_while_a_callback_holds_a_lock_is_not_reentered() {
    // `send` returns before the callback runs, even when the command fails at once.
    let rt = runtime();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new("127.0.0.1", 1));
    c.close();
    let gate = Arc::new(Mutex::new(()));
    let (tx, rx) = mpsc::channel();
    {
        let _held = gate.lock().unwrap();
        let g = Arc::clone(&gate);
        c.ping(move |r| {
            let _wait = g.lock().unwrap();
            let _ = tx.send(r);
        });
    }
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap_err(), RedisError::Closed);
    rt.shutdown();
}
