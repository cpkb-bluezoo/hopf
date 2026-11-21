// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! A scripted RESP server on loopback, for tests that need a server to do what
//! a real one cannot be made to do on cue.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, TcpListenerConfig};
use hopf_redis::{AggKind, Flow, ReplySink, RespParser, Scalar, StrKind};

use super::runtime;

/// What a script sees of one command and its connection.
pub struct Session<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    /// Which connection this is, from 0.
    pub conn: usize,
    /// The 0-based index of this command on its connection.
    pub seq: usize,
    /// Commands held back by the script so far on this connection.
    pub held: &'a mut Vec<Vec<Vec<u8>>>,
}

impl Session<'_> {
    pub fn reply(&mut self, bytes: impl AsRef<[u8]>) {
        self.endpoint.send(bytes.as_ref());
    }
    pub fn reply_after(&self, wait: Duration, bytes: impl AsRef<[u8]> + Send + 'static) {
        let handle: ConnHandle = self.endpoint.handle();
        thread::spawn(move || {
            thread::sleep(wait);
            handle.with_endpoint(move |ep| ep.send(bytes.as_ref()));
        });
    }
    pub fn close(&mut self) {
        self.endpoint.close();
    }

    /// Send `prefix`, then `size` bytes, then `suffix`, a block at a time as the
    /// connection can take them: a reply far larger than the outbound buffer.
    pub fn stream(&mut self, prefix: &str, size: usize, suffix: &str) {
        self.endpoint.send(prefix.as_bytes());
        pump(self.endpoint, size, suffix.to_string());
    }
}

fn pump(ep: &mut dyn Endpoint, left: usize, suffix: String) {
    const BLOCK: usize = 64 * 1024;
    let n = left.min(BLOCK);
    if n > 0 {
        ep.send(&vec![b'v'; n]);
    }
    let left = left - n;
    if left == 0 {
        ep.send(suffix.as_bytes());
        return;
    }
    ep.on_write_ready(Some(Box::new(move |ep| pump(ep, left, suffix))));
}

/// Reads the commands a client sends: each an array of bulk strings.
#[derive(Default)]
struct Commands {
    words: Vec<Vec<u8>>,
    current: Vec<u8>,
    out: Vec<Vec<Vec<u8>>>,
}

impl ReplySink for Commands {
    fn scalar(&mut self, _v: Scalar<'_>) -> Flow {
        Flow::Continue
    }
    fn error(&mut self, _line: &str) -> Flow {
        Flow::Continue
    }
    fn begin_aggregate(&mut self, _kind: AggKind, _len: Option<usize>) -> Flow {
        self.words.clear();
        Flow::Continue
    }
    fn end_aggregate(&mut self) -> Flow {
        self.out.push(std::mem::take(&mut self.words));
        Flow::Continue
    }
    fn begin_string(&mut self, _kind: StrKind, _len: Option<usize>) -> Flow {
        self.current.clear();
        Flow::Continue
    }
    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        self.current.extend_from_slice(data);
        Flow::Continue
    }
    fn end_string(&mut self) -> Flow {
        self.words.push(std::mem::take(&mut self.current));
        Flow::Continue
    }
}

pub type Script = dyn Fn(&mut Session, &[Vec<u8>]) + Send + Sync;

pub struct Scripted {
    script: Arc<Script>,
    pub conn: usize,
    parser: RespParser,
    /// The command being read, which may take several reads.
    commands: Commands,
    pub seq: usize,
    pub held: Vec<Vec<Vec<u8>>>,
}

impl ProtocolHandler for Scripted {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            self.parser.feed(data, &mut self.commands).unwrap();
        });
        for words in std::mem::take(&mut self.commands.out) {
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

pub struct Server {
    pub rt: Runtime,
    pub addr: SocketAddr,
    pub connections: Arc<AtomicUsize>,
}

pub fn serve(script: impl Fn(&mut Session, &[Vec<u8>]) + Send + Sync + 'static) -> Server {
    serve_on("127.0.0.1:0".parse().unwrap(), None, script)
}

pub fn serve_on(
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
            commands: Commands::default(),
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

pub fn name_of(words: &[Vec<u8>]) -> String {
    String::from_utf8_lossy(&words[0]).to_ascii_uppercase()
}

pub fn arg(words: &[Vec<u8>], i: usize) -> String {
    String::from_utf8_lossy(&words[i]).into_owned()
}

/// A RESP3 reply to `HELLO 3`.
pub const HELLO_OK: &str = "%2\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n";

