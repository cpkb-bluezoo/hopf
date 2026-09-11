// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TCP DNS client + connection pool (RFC 7766); DoT via TLS when `dot` feature.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::wire::{DnsMessage, DnsQuestion};

/// Persistent TCP/DoT connection pool (RFC 7766 §6.2.1): a live connection
/// per destination server is kept and reused across queries rather than
/// dialled fresh every time. A reused connection that turns out to be
/// stale (e.g. idle-timed-out by the server) is transparently dropped and
/// replaced with a fresh one — the caller never sees the difference.
pub struct TcpDnsConnectionPool {
    timeout: Duration,
    connections: HashMap<SocketAddr, TcpStream>,
    #[cfg(feature = "dot")]
    dot_connections: HashMap<SocketAddr, (TcpStream, hopf_core::TlsVariant)>,
}

impl Default for TcpDnsConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpDnsConnectionPool {
    /// New pool.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            connections: HashMap::new(),
            #[cfg(feature = "dot")]
            dot_connections: HashMap::new(),
        }
    }

    /// Length-prefixed TCP query (RFC 1035 §4.2.2), reusing a pooled
    /// connection to `server` when one is available.
    pub fn query(
        &mut self,
        server: SocketAddr,
        question: &DnsQuestion,
        id: u16,
    ) -> io::Result<DnsMessage> {
        let msg = DnsMessage::query(id, question.clone(), true);
        let payload = msg
            .serialize()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if let Some(mut stream) = self.connections.remove(&server) {
            if let Ok(buf) = Self::send_receive(&mut stream, &payload) {
                self.connections.insert(server, stream);
                return DnsMessage::parse(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            }
            // Stale (server-side idle timeout, RFC 7766 §6.2.3) — drop it
            // and fall through to a fresh connection.
        }
        let mut stream = TcpStream::connect_timeout(&server, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let buf = Self::send_receive(&mut stream, &payload)?;
        self.connections.insert(server, stream);
        DnsMessage::parse(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn send_receive(stream: &mut TcpStream, payload: &[u8]) -> io::Result<Vec<u8>> {
        let len = payload.len() as u16;
        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(payload)?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf)?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; resp_len];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// DoT query when `dot` feature is enabled, reusing a pooled
    /// already-handshaken TLS session/connection to `server` when one is
    /// available (skipping both the TCP connect and the TLS handshake).
    #[cfg(feature = "dot")]
    pub fn query_dot(
        &mut self,
        server: SocketAddr,
        server_name: &str,
        connector: &hopf_core::SharedTlsConnector,
        question: &DnsQuestion,
        id: u16,
    ) -> io::Result<DnsMessage> {
        let msg = DnsMessage::query(id, question.clone(), true);
        let payload = msg
            .serialize()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut len_payload = Vec::with_capacity(2 + payload.len());
        len_payload.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        len_payload.extend_from_slice(&payload);

        if let Some((mut stream, mut engine)) = self.dot_connections.remove(&server) {
            if let Ok(resp) = drive_tls_write_read(&mut stream, &mut engine, &len_payload) {
                self.dot_connections.insert(server, (stream, engine));
                return Ok(resp);
            }
            // Stale — drop and fall through to a fresh connection + handshake.
        }
        let mut stream = TcpStream::connect_timeout(&server, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let mut engine = connector.connect(server_name)?;
        drive_handshake(&mut stream, &mut engine)?;
        let resp = drive_tls_write_read(&mut stream, &mut engine, &len_payload)?;
        self.dot_connections.insert(server, (stream, engine));
        Ok(resp)
    }
}

/// Thin TCP transport wrapper.
pub struct TcpDnsClientTransport {
    pool: TcpDnsConnectionPool,
}

impl Default for TcpDnsClientTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpDnsClientTransport {
    /// New transport.
    pub fn new() -> Self {
        Self {
            pool: TcpDnsConnectionPool::new(),
        }
    }

    /// Query over cleartext TCP.
    pub fn query(
        &mut self,
        server: SocketAddr,
        question: &DnsQuestion,
        id: u16,
    ) -> io::Result<DnsMessage> {
        self.pool.query(server, question, id)
    }
}

/// Blocking [`hopf_core::tls::TlsRecordSink`] for driving a [`hopf_core::TlsVariant`]
/// synchronously over a real `TcpStream` — the reactive engine pushes
/// ciphertext/plaintext/error events into this instead of a caller
/// pulling them, so [`drive_handshake`]/[`drive_tls_write_read`] collect
/// them here between each blocking socket read.
#[cfg(feature = "dot")]
#[derive(Default)]
struct BlockingDotSink {
    outbound: Vec<u8>,
    handshake_done: bool,
    app_data: Vec<u8>,
    error: Option<String>,
    peer_closed: bool,
}

#[cfg(feature = "dot")]
impl hopf_core::tls::TlsRecordSink for BlockingDotSink {
    fn ciphertext_ready(&mut self, data: &[u8]) {
        self.outbound.extend_from_slice(data);
    }
    fn application_data(&mut self, plaintext: &[u8]) {
        self.app_data.extend_from_slice(plaintext);
    }
    fn handshake_complete(&mut self, _info: hopf_core::SecurityInfo) {
        self.handshake_done = true;
    }
    fn verification_requested(&mut self, _req: hopf_core::VerifyRequest) {
        // Purely informational: the engine always fires this first, then
        // immediately resolves verification inline, synchronously, in
        // the same call, whenever `trust_store`/`verify_override` is set
        // — which every DoT connector (public-trust, pinned, or
        // `insecure_connector`) does. It never waits for a
        // `feed_verification_result` call back from us.
    }
    fn protocol_error(&mut self, err: hopf_core::TlsProtocolError) {
        self.error.get_or_insert(err.message);
    }
    fn peer_closed(&mut self) {
        self.peer_closed = true;
    }
}

#[cfg(feature = "dot")]
impl BlockingDotSink {
    fn flush_outbound(&mut self, stream: &mut TcpStream) -> io::Result<()> {
        if !self.outbound.is_empty() {
            stream.write_all(&self.outbound)?;
            self.outbound.clear();
        }
        Ok(())
    }

    fn check(&mut self) -> io::Result<()> {
        if let Some(msg) = self.error.take() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("DoT TLS error: {msg}")));
        }
        if self.peer_closed {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoT peer closed the connection"));
        }
        Ok(())
    }
}

/// Drive `engine`'s handshake to completion over a real blocking `TcpStream`.
#[cfg(feature = "dot")]
fn drive_handshake(stream: &mut TcpStream, engine: &mut hopf_core::TlsVariant) -> io::Result<()> {
    let mut sink = BlockingDotSink::default();
    engine.start(&mut sink);
    sink.flush_outbound(stream)?;
    sink.check()?;
    let mut buf = [0u8; 8192];
    while !sink.handshake_done {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoT: connection closed during handshake"));
        }
        let mut slice = &buf[..n];
        engine.feed_ciphertext(&mut slice, &mut sink);
        sink.flush_outbound(stream)?;
        sink.check()?;
    }
    Ok(())
}

/// Send one length-prefixed DoT query and read the length-prefixed
/// response, over an already-handshake-complete `engine`.
#[cfg(feature = "dot")]
fn drive_tls_write_read(
    stream: &mut TcpStream,
    engine: &mut hopf_core::TlsVariant,
    len_payload: &[u8],
) -> io::Result<DnsMessage> {
    let mut sink = BlockingDotSink::default();
    engine.send_application_data(len_payload, &mut sink);
    sink.flush_outbound(stream)?;
    sink.check()?;

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        if response.len() >= 2 {
            let len = u16::from_be_bytes([response[0], response[1]]) as usize;
            if response.len() >= 2 + len {
                return DnsMessage::parse(&response[2..2 + len])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoT: connection closed mid-response"));
        }
        let mut slice = &buf[..n];
        engine.feed_ciphertext(&mut slice, &mut sink);
        sink.flush_outbound(stream)?;
        sink.check()?;
        response.append(&mut sink.app_data);
    }
}
