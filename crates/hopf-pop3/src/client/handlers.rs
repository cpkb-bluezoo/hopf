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

    /// CAPA failed (-ERR) while in Authorization state. Matches Gumdrop's
    /// `ServerCapaReplyHandler.handleError` — some older servers don't
    /// support CAPA at all; the driver can proceed with authentication
    /// without capability information (e.g. plain `USER`/`PASS`) instead
    /// of a synthesized default capability set silently standing in for a
    /// real response.
    fn on_capa_error(
        &mut self,
        auth: &mut dyn Pop3ClientAuthorization,
        ep: &mut dyn Endpoint,
        message: &str,
    );

    /// CAPA response received after STLS / TLS handshake (PostStls state).
    fn on_capa_post_stls(
        &mut self,
        post_stls: &mut dyn Pop3ClientPostStls,
        ep: &mut dyn Endpoint,
        caps: &Pop3Capabilities,
    );

    /// CAPA failed (-ERR) after STLS / TLS handshake (PostStls state).
    fn on_capa_post_stls_error(
        &mut self,
        post_stls: &mut dyn Pop3ClientPostStls,
        ep: &mut dyn Endpoint,
        message: &str,
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

    /// The server's reply to a client-initiated `exchange.abort()` (`*`).
    /// Fires unconditionally regardless of whether that reply was itself
    /// positive or negative — matches Gumdrop's
    /// `ServerAuthAbortHandler.handleAborted(ClientAuthorizationState)`,
    /// called unconditionally by `dispatchAuthAbortReply` regardless of the
    /// server's `+OK`/`-ERR`, a distinct third outcome from
    /// `on_auth_failed`, not routed through it. Same pattern as SMTP's
    /// `on_auth_aborted`.
    fn on_auth_aborted(&mut self, auth: &mut dyn Pop3ClientAuthorization, ep: &mut dyn Endpoint);

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

    /// STAT failed (-ERR). Matches Gumdrop's `ServerStatReplyHandler.handleError`
    /// — a recoverable per-command failure, not a connection error: the
    /// session stays in Transaction state.
    fn on_stat_error(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
        message: &str,
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

    /// Multi-message LIST failed (-ERR), for a reason other than a
    /// specific missing message (that's [`Self::on_no_such_message`], via
    /// the `LIST n` single-message form). Matches Gumdrop's
    /// `ServerListReplyHandler.handleError` — recoverable, session stays
    /// in Transaction state.
    fn on_list_error(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
        message: &str,
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

    /// Multi-message UIDL failed (-ERR), for a reason other than a
    /// specific missing message. Matches Gumdrop's
    /// `ServerUidlReplyHandler.handleError` — recoverable, session stays
    /// in Transaction state.
    fn on_uidl_error(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
        message: &str,
    );

    // ── RETR / TOP ────────────────────────────────────────────────────────

    /// A chunk of the message body arrived (called zero or more times).
    ///
    /// For large messages this may be called multiple times per message.
    /// `ep` lets the driver call `pause_read`/`resume_read` to apply
    /// backpressure during a large transfer.
    fn on_message_content(&mut self, data: &[u8], ep: &mut dyn Endpoint);

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

    /// Server returned `-ERR` for a per-message command (RETR/TOP/DELE/LIST n/UIDL n),
    /// for a reason other than the message being deleted / already deleted
    /// (those are [`Self::on_message_deleted`] / [`Self::on_already_deleted`]).
    fn on_no_such_message(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
        message: &str,
    );

    /// RETR/TOP failed (-ERR) because the message is already marked
    /// deleted (server's error text contains "deleted"). Matches Gumdrop's
    /// `dispatchRetrReply`/`dispatchTopReply`, which text-sniff the -ERR
    /// message to pick `handleMessageDeleted` over `handleNoSuchMessage`.
    fn on_message_deleted(
        &mut self,
        transaction: &mut dyn Pop3ClientTransaction,
        ep: &mut dyn Endpoint,
        message: &str,
    );

    /// DELE failed (-ERR) because the message was already deleted (server's
    /// error text contains "already deleted" or "already marked"). Matches
    /// Gumdrop's `dispatchDeleReply`, which text-sniffs the -ERR message to
    /// pick `handleAlreadyDeleted` over `handleNoSuchMessage`.
    fn on_already_deleted(
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
    ///
    /// `message` is the most recent `-ERR` text seen before the close, if
    /// any — matches Gumdrop's `ServerReplyHandler.handleServiceClosing`,
    /// the base interface every per-command handler extends, so whichever
    /// handler was active when the server closed unexpectedly gets the
    /// closing text (or `None`).
    fn on_disconnected(&mut self, ep: &mut dyn Endpoint, message: Option<&str>);
}
