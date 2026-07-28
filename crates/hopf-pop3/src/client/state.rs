// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 client state-machine traits.
//!
//! Each trait represents a stage of the POP3 protocol.  Implementations on
//! [`super::endpoint::Pop3ClientEndpoint`] queue command bytes for dispatch;
//! the actual bytes are flushed to the [`Endpoint`] after every driver
//! callback returns.

/// Capabilities advertised by the server in its CAPA response (RFC 2449).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pop3Capabilities {
    /// STLS upgrade (RFC 2595).
    pub stls: bool,
    /// USER/PASS authentication (RFC 1939).
    pub user: bool,
    /// Per-message unique identifiers (UIDL, RFC 1939).
    pub uidl: bool,
    /// Partial message retrieval (TOP, RFC 1939).
    pub top: bool,
    /// APOP challenge present in the greeting.
    pub apop: bool,
    /// SASL AUTH mechanisms advertised (uppercased, RFC 5034).
    pub sasl_mechs: Vec<String>,
    /// UTF8 extension (RFC 6856).
    pub utf8: bool,
    /// PIPELINING extension (RFC 2449).
    pub pipelining: bool,
    /// Server implementation string if advertised.
    pub implementation: Option<String>,
}

// ── Authorization state ───────────────────────────────────────────────────────

/// Initial post-greeting state: select authentication method.
pub trait Pop3ClientAuthorization {
    /// Send `CAPA`.
    fn capa(&mut self);
    /// Send `USER username`.
    fn user(&mut self, username: &str);
    /// Send `APOP username md5digest`.
    ///
    /// `digest` is the lowercase-hex MD5 of `timestamp || password`.
    fn apop(&mut self, username: &str, digest: &str);
    /// Send `AUTH mechanism [initial_response_b64]`.
    fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>);
    /// Negotiate STLS (RFC 2595).
    fn stls(&mut self);
    /// Send `QUIT`.
    fn quit(&mut self);
}

// ── Password state ────────────────────────────────────────────────────────────

/// Post-USER state: send the password.
pub trait Pop3ClientPassword {
    /// Send `PASS password`.
    fn pass(&mut self, password: &str);
    /// Send `QUIT`.
    fn quit(&mut self);
}

// ── Post-STLS state ───────────────────────────────────────────────────────────

/// Post-TLS-handshake state: re-authentication (no further STLS).
pub trait Pop3ClientPostStls {
    /// Send `CAPA`.
    fn capa(&mut self);
    /// Send `USER username`.
    fn user(&mut self, username: &str);
    /// Send `APOP username md5digest`.
    fn apop(&mut self, username: &str, digest: &str);
    /// Send `AUTH mechanism [initial_response_b64]`.
    fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>);
    /// Send `QUIT`.
    fn quit(&mut self);
}

// ── AUTH exchange state ───────────────────────────────────────────────────────

/// Mid-AUTH SASL exchange.
pub trait Pop3ClientAuthExchange {
    /// Send a base64-encoded SASL response line.
    fn respond(&mut self, response: &[u8]);
    /// Abort AUTH with `*`.
    fn abort(&mut self);
}

// ── Transaction state ─────────────────────────────────────────────────────────

/// Post-authentication state: retrieve and manage messages.
pub trait Pop3ClientTransaction {
    /// Send `STAT`.
    fn stat(&mut self);
    /// Send `LIST` (all messages) or `LIST n` (single message).
    fn list(&mut self, message: Option<u32>);
    /// Send `RETR n`.
    fn retr(&mut self, message: u32);
    /// Send `DELE n`.
    fn dele(&mut self, message: u32);
    /// Send `RSET`.
    fn rset(&mut self);
    /// Send `TOP n lines`.
    fn top(&mut self, message: u32, lines: u32);
    /// Send `UIDL` (all messages) or `UIDL n` (single message).
    fn uidl(&mut self, message: Option<u32>);
    /// Send `NOOP`.
    fn noop(&mut self);
    /// Send `QUIT`.
    fn quit(&mut self);
}
