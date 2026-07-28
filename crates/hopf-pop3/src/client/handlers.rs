// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 client handler factory and driver traits.
//!
//! `Pop3ClientHandlerFactory` creates the connection driver per connection.
//! `Pop3ClientDriver` receives all lifecycle and per-reply callbacks and drives
//! the protocol by calling methods on the state trait references it receives.

use std::io;

use hopf_core::Endpoint;

use super::reply::ContentId;
use super::state::{
    Pop3Capabilities, Pop3ClientAuthExchange, Pop3ClientAuthorization, Pop3ClientPassword,
    Pop3ClientPostStls, Pop3ClientTransaction,
};

// ── Factory ───────────────────────────────────────────────────────────────────

/// Creates the connection driver for each new POP3 client connection.
pub trait Pop3ClientHandlerFactory: Send + Sync {
    /// Produce a fresh driver for one connection.
    fn create(&self) -> Box<dyn Pop3ClientDriver>;
}

// ── Driver ────────────────────────────────────────────────────────────────────

/// Receives all POP3 protocol callbacks for a single client connection.
///
/// Implementations drive the protocol by calling state-transition methods on
/// the references they receive.  The implementation is intentionally
/// stateful — one `Pop3ClientDriver` lives for the lifetime of one connection.
pub trait Pop3ClientDriver: Send {
    // ── Greeting ─────────────────────────────────────────────────────────

    /// Server greeting received (the `+OK` line after TCP connect). The
    /// banner's decorative text is not exposed — greeting text has no
    /// protocol meaning beyond the optional APOP challenge, which is
    /// already parsed.
    ///
    /// `apop_challenge` is the `<local@domain>` token from the greeting if
    /// the server supports APOP (RFC 1939 §7).
    ///
    /// Typical next action: call `auth.capa()` to discover capabilities, or
    /// go straight to `auth.user(…)` / `auth.apop(…)`.
    fn on_greeting(
        &mut self,
        auth: &mut dyn Pop3ClientAuthorization,
        ep: &mut dyn Endpoint,
        apop_challenge: Option<&ContentId>,
    );

    // ── CAPA ─────────────────────────────────────────────────────────────

    /// CAPA response received while in Authorization state.
    fn on_capa(
        &mut self,
        auth: &mut dyn Pop3ClientAuthorization,
        ep: &mut dyn Endpoint,
        caps: &Pop3Capabilities,
    );

    /// CAPA response received after STLS / TLS handshake (PostStls state).
    fn on_capa_post_stls(
        &mut self,
        post_stls: &mut dyn Pop3ClientPostStls,
        ep: &mut dyn Endpoint,
        caps: &Pop3Capabilities,
    );

    // ── USER / PASS / APOP ────────────────────────────────────────────────

    /// `USER` accepted (+OK); send the password next.
    fn on_user_ok(&mut self, password: &mut dyn Pop3ClientPassword, ep: &mut dyn Endpoint);

    // ── Authentication outcome ────────────────────────────────────────────

    /// Authentication succeeded: the connection is now in Transaction state.
    fn on_authenticated(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
    );

    /// Authentication failed (-ERR). The connection stays in Authorization
    /// state; the driver may retry or call `auth.quit()`.
    fn on_auth_failed(
        &mut self,
        auth: &mut dyn Pop3ClientAuthorization,
        ep: &mut dyn Endpoint,
        message: &str,
    );

    /// AUTH SASL challenge received (`+` continuation).
    ///
    /// `challenge` is the already base64-decoded data from the `+ data`
    /// line. Call `exchange.respond(…)` or `exchange.abort()`.
    fn on_auth_challenge(
        &mut self,
        exchange: &mut dyn Pop3ClientAuthExchange,
        ep: &mut dyn Endpoint,
        challenge: &[u8],
    );

    // ── STLS ─────────────────────────────────────────────────────────────

    /// TLS handshake completed after STLS. Must re-issue CAPA.
    fn on_tls_established(
        &mut self,
        post_stls: &mut dyn Pop3ClientPostStls,
        ep: &mut dyn Endpoint,
    );

    /// STLS rejected or unavailable.
    fn on_tls_unavailable(
        &mut self,
        auth: &mut dyn Pop3ClientAuthorization,
        ep: &mut dyn Endpoint,
    );

    // ── STAT ─────────────────────────────────────────────────────────────

    /// STAT response: `count` messages totalling `octets` bytes in the maildrop.
    fn on_stat(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
        count: u32,
        octets: u64,
    );

    // ── LIST ─────────────────────────────────────────────────────────────

    /// One entry from a multi-message LIST response.
    ///
    /// Called for each line before [`on_list_complete`].
    fn on_list_entry(&mut self, message: u32, size: u64);

    /// All LIST entries have been delivered.
    fn on_list_complete(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
    );

    /// Response to `LIST n` (single-message form).
    fn on_list_single(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
        message: u32,
        size: u64,
    );

    // ── UIDL ─────────────────────────────────────────────────────────────

    /// One entry from a multi-message UIDL response.
    fn on_uidl_entry(&mut self, message: u32, uid: &str);

    /// All UIDL entries have been delivered.
    fn on_uidl_complete(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
    );

    /// Response to `UIDL n` (single-message form).
    fn on_uidl_single(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
        message: u32,
        uid: &str,
    );

    // ── RETR / TOP ────────────────────────────────────────────────────────

    /// A chunk of the message body arrived (called zero or more times).
    ///
    /// For large messages this may be called multiple times per message.
    fn on_message_content(&mut self, data: &[u8]);

    /// The complete message body has been received.
    ///
    /// `is_top` distinguishes a TOP response from a RETR response.
    /// `message` is the message number that was requested.
    fn on_message_complete(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
        is_top: bool,
        message: u32,
    );

    // ── DELE / RSET / NOOP ────────────────────────────────────────────────

    /// DELE accepted (+OK).
    fn on_dele_ok(&mut self, transaction: &mut dyn Pop3ClientTransaction, ep: &mut dyn Endpoint);

    /// RSET accepted (+OK).
    fn on_rset_ok(&mut self, transaction: &mut dyn Pop3ClientTransaction, ep: &mut dyn Endpoint);

    /// NOOP accepted (+OK).
    fn on_noop_ok(&mut self, transaction: &mut dyn Pop3ClientTransaction, ep: &mut dyn Endpoint);

    // ── Error responses ───────────────────────────────────────────────────

    /// Server returned `-ERR` for a per-message command (RETR/TOP/DELE/LIST n/UIDL n).
    fn on_no_such_message(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
        message: &str,
    );

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /// Unrecoverable I/O or protocol error.
    fn on_error(&mut self, ep: &mut dyn Endpoint, err: &io::Error);

    /// Stage or message timeout fired.
    fn on_timeout(&mut self, ep: &mut dyn Endpoint);

    /// Connection closed by peer or after QUIT.
    fn on_disconnected(&mut self, ep: &mut dyn Endpoint);
}
