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
use hopf_redis::{RespParser, Value};

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
}

pub type Script = dyn Fn(&mut Session, &[Vec<u8>]) + Send + Sync;

pub struct Scripted {
    script: Arc<Script>,
    pub conn: usize,
    parser: RespParser,
    pub seq: usize,
    pub held: Vec<Vec<Vec<u8>>>,
}

impl ProtocolHandler for Scripted {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        let mut commands = Vec::new();
        hopf_core::with_slice(buf, |data| {
            self.parser
                .feed_values(data, &mut |v| {
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

