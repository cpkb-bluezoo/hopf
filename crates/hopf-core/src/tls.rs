// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS session hooks so `hopf-tls` (rustls) can plug into [`crate::TcpConnection`]
//! without pulling crypto into core.

use std::io;
use std::sync::Arc;

use crate::security::SecurityInfo;

/// Outcome of [`TlsSession::process_new_packets`].
#[derive(Debug, Default, Clone, Copy)]
pub struct TlsProgress {
    /// Handshake completed during this call (fire `security_established` once).
    pub handshake_just_completed: bool,
}

/// Per-connection TLS state (rustls `ServerConnection` / later client).
///
/// All methods run on the connection's reactor thread only.
pub trait TlsSession: Send {
    /// Consume ciphertext from `input`, advancing the slice past bytes read.
    fn read_tls(&mut self, input: &mut &[u8]) -> io::Result<usize>;

    /// Process buffered handshake/application records.
    fn process_new_packets(&mut self) -> io::Result<TlsProgress>;

    /// Read decrypted plaintext into `buf`.
    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Queue plaintext for encryption.
    fn write_plaintext(&mut self, buf: &[u8]) -> io::Result<usize>;

    /// Append pending ciphertext to `output`.
    fn write_tls(&mut self, output: &mut Vec<u8>) -> io::Result<usize>;

    /// Whether ciphertext should be flushed to the socket.
    fn wants_write(&self) -> bool;

    /// Whether the handshake is still in progress.
    fn is_handshaking(&self) -> bool;

    /// Security metadata after handshake (ALPN, version, cipher).
    fn security_info(&self) -> SecurityInfo;

    /// Queue a TLS close_notify (then flush via [`write_tls`](Self::write_tls)).
    fn send_close_notify(&mut self);
}

/// Factory for server-side TLS sessions (shared across accepts).
pub trait TlsAcceptor: Send + Sync {
    /// Create a new server session for one TCP connection.
    fn accept(&self) -> Box<dyn TlsSession>;
}

/// Shared acceptor handle stored on listeners / connections.
pub type SharedTlsAcceptor = Arc<dyn TlsAcceptor>;

/// Factory for client-side TLS sessions (shared across dials).
pub trait TlsConnector: Send + Sync {
    /// Create a new client session for `server_name` (SNI / cert identity).
    fn connect(&self, server_name: &str) -> io::Result<Box<dyn TlsSession>>;
}

/// Shared connector handle stored on dial configs / connections.
pub type SharedTlsConnector = Arc<dyn TlsConnector>;
