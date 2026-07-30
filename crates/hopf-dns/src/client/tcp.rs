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
    dot_connections: HashMap<SocketAddr, (TcpStream, Box<dyn hopf_core::TlsSession>)>,
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

        if let Some((mut stream, mut session)) = self.dot_connections.remove(&server) {
            if let Ok(resp) = drive_tls_write_read(&mut stream, &mut *session, &len_payload) {
                self.dot_connections.insert(server, (stream, session));
                return Ok(resp);
            }
            // Stale — drop and fall through to a fresh connection + handshake.
        }
        let mut stream = TcpStream::connect_timeout(&server, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let mut session = connector.connect(server_name)?;
        let resp = drive_tls_write_read(&mut stream, &mut *session, &len_payload)?;
        self.dot_connections.insert(server, (stream, session));
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

#[cfg(feature = "dot")]
fn drive_tls_write_read(
    stream: &mut TcpStream,
    session: &mut dyn hopf_core::TlsSession,
    plaintext: &[u8],
) -> io::Result<DnsMessage> {
    use hopf_core::TlsProgress;
    let to_write = plaintext;
    let mut remaining = plaintext;
    // Simplified: write all plaintext into session, flush TLS, read response.
    while !remaining.is_empty() {
        let n = session.write_plaintext(remaining)?;
        if n == 0 {
            break;
        }
        remaining = &remaining[n..];
    }
    let _ = to_write;
    loop {
        let mut tls_out = Vec::new();
        while session.wants_write() {
            let _ = session.write_tls(&mut tls_out)?;
        }
        if !tls_out.is_empty() {
            stream.write_all(&tls_out)?;
        }
        if !session.is_handshaking() {
            break;
        }
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "DoT EOF"));
        }
        let mut slice = &buf[..n];
        while !slice.is_empty() {
            let n = session.read_tls(&mut slice)?;
            if n == 0 {
                break;
            }
        }
        let _ = session.process_new_packets()?;
    }
    // Read length-prefixed response
    let mut plain = Vec::new();
    loop {
        let mut buf = [0u8; 8192];
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut slice = &buf[..n];
                while !slice.is_empty() {
                    let _ = session.read_tls(&mut slice)?;
                }
                let _prog: TlsProgress = session.process_new_packets()?;
                let mut tmp = [0u8; 8192];
                loop {
                    match session.read_plaintext(&mut tmp) {
                        Ok(0) => break,
                        Ok(m) => plain.extend_from_slice(&tmp[..m]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                break;
            }
            Err(e) => return Err(e),
        }
        if plain.len() >= 2 {
            let len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
            if plain.len() >= 2 + len {
                return DnsMessage::parse(&plain[2..2 + len])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "incomplete DoT response",
    ))
}
