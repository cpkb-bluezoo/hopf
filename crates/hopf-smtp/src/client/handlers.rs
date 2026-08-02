// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP client handler factory and driver traits.
//!
//! `SmtpClientHandlerFactory` creates the connection driver. `SmtpClientDriver`
//! receives all lifecycle and per-reply callbacks; it drives the protocol by
//! calling methods on the state trait references it receives.

use std::io;

use hopf_core::Endpoint;

use super::state::{
    SmtpCapabilities, SmtpClientAuthExchange, SmtpClientEnvelope, SmtpClientHello,
    SmtpClientMessageData, SmtpClientPostTls, SmtpClientSession,
};

/// Creates the connection driver for each new SMTP client connection.
pub trait SmtpClientHandlerFactory: Send + Sync {
    /// Produce a fresh driver for one connection.
    fn create(&self) -> Box<dyn SmtpClientDriver>;
}

/// Receives all SMTP protocol callbacks for a single client connection.
///
/// Mirroring Gumdrop's `ServerGreeting` + per-reply handler interfaces, but
/// consolidated into one trait. Implementations should drive the protocol by
/// calling the state-transition methods on the reference they receive.
pub trait SmtpClientDriver: Send {
    // ── Greeting ───────────────────────────────────────────────────────────

    /// 220 greeting received. The banner text is not exposed — it has no
    /// protocol meaning beyond the ESMTP flag, which is already extracted.
    ///
    /// Call `hello.ehlo(hostname)` or `hello.helo(hostname)`.
    fn on_greeting(&mut self, hello: &mut dyn SmtpClientHello, ep: &mut dyn Endpoint, esmtp: bool);

    /// 4xx/5xx greeting (service unavailable).
    fn on_service_unavailable(&mut self, ep: &mut dyn Endpoint, message: &str);

    // ── EHLO / HELO ────────────────────────────────────────────────────────

    /// 250 EHLO response.
    ///
    /// `caps` is the parsed capabilities. Proceed via `session.mail_from(…)`,
    /// `session.starttls()`, `session.auth(…)`, or `session.quit()`.
    fn on_ehlo(
        &mut self,
        session: &mut dyn SmtpClientSession,
        ep: &mut dyn Endpoint,
        caps: &SmtpCapabilities,
    );

    /// 502 — server does not support EHLO. Typically followed by a HELO.
    fn on_ehlo_not_supported(&mut self, session: &mut dyn SmtpClientSession, ep: &mut dyn Endpoint);

    /// EHLO permanent failure (5xx other than 502).
    fn on_ehlo_error(&mut self, ep: &mut dyn Endpoint, message: &str);

    /// 250 HELO response.
    fn on_helo(&mut self, session: &mut dyn SmtpClientSession, ep: &mut dyn Endpoint);

    /// HELO permanent failure (5xx). Distinct from `on_ehlo_error` — this
    /// fires only for a rejected HELO, matching Gumdrop's separate
    /// `ServerHeloReplyHandler`/`ServerEhloReplyHandler` interfaces.
    fn on_helo_error(&mut self, ep: &mut dyn Endpoint, message: &str);

    // ── STARTTLS ───────────────────────────────────────────────────────────

    /// TLS handshake completed (RFC 3207 §4.2 / RFC 8314).
    ///
    /// Must re-issue EHLO: call `post_tls.ehlo(hostname)`.
    fn on_tls_established(&mut self, post_tls: &mut dyn SmtpClientPostTls, ep: &mut dyn Endpoint);

    /// STARTTLS temporarily/optionally unavailable (454 / 502) — the
    /// session continues without TLS.
    fn on_tls_unavailable(&mut self, session: &mut dyn SmtpClientSession, ep: &mut dyn Endpoint);

    /// STARTTLS permanently rejected (5xx other than 502, e.g. 554).
    /// The connection is closed after this callback returns.
    fn on_tls_error(&mut self, ep: &mut dyn Endpoint, message: &str);

    // ── AUTH ───────────────────────────────────────────────────────────────

    /// 235 — AUTH succeeded.
    fn on_auth_ok(&mut self, session: &mut dyn SmtpClientSession, ep: &mut dyn Endpoint);

    /// 334 — AUTH challenge (SASL).
    ///
    /// `challenge` is the base64-decoded challenge bytes. Call
    /// `exchange.respond(…)` or `exchange.abort()`.
    fn on_auth_challenge(
        &mut self,
        exchange: &mut dyn SmtpClientAuthExchange,
        ep: &mut dyn Endpoint,
        challenge: &[u8],
    );

    /// AUTH failed. `code` distinguishes bad credentials (535) from an
    /// unsupported mechanism (504, retry with a different one) or a
    /// temporary failure (454, retry later) — matching Gumdrop's
    /// `handleAuthFailed`/`handleMechanismNotSupported`/`handleTemporaryFailure`.
    fn on_auth_failed(&mut self, session: &mut dyn SmtpClientSession, ep: &mut dyn Endpoint, code: u16);

    /// The server's reply to a client-initiated `exchange.abort()` (`*`).
    /// Fires unconditionally regardless of whether that reply was itself
    /// positive or negative — matching Gumdrop's
    /// `ServerAuthAbortHandler.handleAborted`, which is a distinct third
    /// outcome from `handleAuthFailed`/`on_auth_failed`, not routed through
    /// it. The driver can continue without authentication or try a
    /// different mechanism.
    fn on_auth_aborted(&mut self, session: &mut dyn SmtpClientSession, ep: &mut dyn Endpoint);

    // ── MAIL FROM ──────────────────────────────────────────────────────────

    /// 250 MAIL FROM accepted.
    fn on_mail_ok(&mut self, envelope: &mut dyn SmtpClientEnvelope, ep: &mut dyn Endpoint);

    /// MAIL FROM rejected (4xx/5xx).
    fn on_mail_rejected(
        &mut self,
        session: &mut dyn SmtpClientSession,
        ep: &mut dyn Endpoint,
        code: u16,
        message: &str,
    );

    // ── RCPT TO ────────────────────────────────────────────────────────────

    /// 250/251/252 RCPT TO accepted.
    fn on_rcpt_ok(
        &mut self,
        envelope: &mut dyn SmtpClientEnvelope,
        ep: &mut dyn Endpoint,
        recipient: &str,
    );

    /// 4xx/5xx RCPT TO rejected.
    fn on_rcpt_rejected(
        &mut self,
        envelope: &mut dyn SmtpClientEnvelope,
        ep: &mut dyn Endpoint,
        recipient: &str,
        code: u16,
        message: &str,
    );

    // ── DATA ───────────────────────────────────────────────────────────────

    /// 354 — ready for DATA.
    ///
    /// Also fired (without a preceding 354) when [`SmtpClientEnvelope::start_data`]
    /// enters BDAT mode because the server advertised CHUNKING — check
    /// [`SmtpClientMessageData::is_bdat_mode`] and use
    /// [`SmtpClientMessageData::write_bdat_chunk`] instead of
    /// `write_content` / `end_message`.
    ///
    /// Write message content via `data.write_content(…)` then call
    /// `data.end_message()`, or send BDAT chunks as described above.
    fn on_ready_for_data(&mut self, data: &mut dyn SmtpClientMessageData, ep: &mut dyn Endpoint);

    /// 250 after a non-LAST `BDAT` chunk — send the next chunk via
    /// [`SmtpClientMessageData::write_bdat_chunk`].
    fn on_bdat_chunk_ok(&mut self, data: &mut dyn SmtpClientMessageData, ep: &mut dyn Endpoint);

    /// DATA command itself rejected (4xx/5xx), before any content was
    /// sent. Per RFC 5321 §3.3, the envelope (MAIL FROM, accepted RCPT
    /// TOs) is unaffected — `envelope` lets the driver add more
    /// recipients, retry `start_data()`, or `rset()`. `code` lets the
    /// driver distinguish a temporary (4xx, matching Gumdrop's
    /// `ServerDataReplyHandler.handleTemporaryFailure`, which hands back
    /// `ClientEnvelopeReady`) from a permanent (5xx, `handlePermanentFailure`)
    /// rejection; hopf hands back the envelope either way since it costs
    /// nothing and the driver is free to ignore it and `quit()`.
    fn on_data_rejected(
        &mut self,
        envelope: &mut dyn SmtpClientEnvelope,
        ep: &mut dyn Endpoint,
        code: u16,
        message: &str,
    );

    /// 250 — message accepted for delivery.
    ///
    /// `queue_id` is the server's queue identifier if parseable.
    fn on_message_accepted(
        &mut self,
        session: &mut dyn SmtpClientSession,
        ep: &mut dyn Endpoint,
        queue_id: Option<&str>,
    );

    /// 4xx/5xx — message rejected.
    fn on_message_rejected(
        &mut self,
        session: &mut dyn SmtpClientSession,
        ep: &mut dyn Endpoint,
        code: u16,
        message: &str,
    );

    // ── RSET ───────────────────────────────────────────────────────────────

    /// 250 RSET accepted.
    fn on_rset_ok(&mut self, session: &mut dyn SmtpClientSession, ep: &mut dyn Endpoint);

    // ── VRFY ───────────────────────────────────────────────────────────────

    /// 250/251/252 — VRFY succeeded. `code` distinguishes a fully verified
    /// mailbox (250) from one that will be forwarded (251) or merely
    /// accepted without verification (252); `text` is the resolved-mailbox
    /// text the server returned.
    fn on_vrfy_ok(
        &mut self,
        session: &mut dyn SmtpClientSession,
        ep: &mut dyn Endpoint,
        code: u16,
        text: &str,
    );

    /// VRFY failed (5xx, or 502/504 if VRFY itself isn't implemented).
    fn on_vrfy_failed(
        &mut self,
        session: &mut dyn SmtpClientSession,
        ep: &mut dyn Endpoint,
        code: u16,
        message: &str,
    );

    // ── EXPN ───────────────────────────────────────────────────────────────

    /// 250 — EXPN succeeded; `members` is the expanded mailing-list
    /// membership, one entry per reply line.
    fn on_expn_ok(
        &mut self,
        session: &mut dyn SmtpClientSession,
        ep: &mut dyn Endpoint,
        members: &[String],
    );

    /// EXPN failed (5xx, or 502/504 if EXPN itself isn't implemented).
    fn on_expn_failed(
        &mut self,
        session: &mut dyn SmtpClientSession,
        ep: &mut dyn Endpoint,
        code: u16,
        message: &str,
    );

    // ── Lifecycle ──────────────────────────────────────────────────────────

    /// Unrecoverable I/O or protocol error.
    fn on_error(&mut self, ep: &mut dyn Endpoint, err: &io::Error);

    /// Stage or message timeout fired.
    fn on_timeout(&mut self, ep: &mut dyn Endpoint);

    /// Connection closed by peer or endpoint.
    fn on_disconnected(&mut self, ep: &mut dyn Endpoint);
}
