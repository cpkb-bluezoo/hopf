// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Gumdrop-shaped SMTP client state traits.
//!
//! Each trait represents a stage of the SMTP protocol state machine.
//! Implementations on [`super::endpoint::SmtpClientEndpoint`] accept commands
//! and buffer them for dispatch; the actual bytes are flushed to the endpoint
//! after the driver callback returns.

/// Post-connect stage: send EHLO or HELO.
pub trait SmtpClientHello {
    /// Send `EHLO hostname`.
    fn ehlo(&mut self, hostname: &str);
    /// Send `HELO hostname`.
    fn helo(&mut self, hostname: &str);
}

/// Capabilities advertised by the server in its EHLO response.
#[derive(Debug, Default, Clone)]
pub struct SmtpCapabilities {
    /// Server advertises STARTTLS (RFC 3207).
    pub starttls: bool,
    /// Maximum message size in bytes; 0 = unrestricted (RFC 1870).
    pub max_size: u64,
    /// Advertised AUTH mechanisms (uppercased, RFC 4954).
    pub auth_methods: Vec<String>,
    /// PIPELINING (RFC 2920).
    pub pipelining: bool,
    /// CHUNKING / BDAT (RFC 3030).
    pub chunking: bool,
    /// 8BITMIME (RFC 6152).
    pub eight_bit_mime: bool,
    /// SMTPUTF8 (RFC 6531).
    pub smtp_utf8: bool,
    /// DSN (RFC 3461).
    pub dsn: bool,
    /// ENHANCEDSTATUSCODES (RFC 2034).
    pub enhanced_status_codes: bool,
    /// REQUIRETLS (RFC 8689).
    pub require_tls: bool,
}

/// Post-EHLO stage: envelope, STARTTLS, AUTH, QUIT.
pub trait SmtpClientSession: SmtpClientHello {
    /// Send `MAIL FROM:<sender>` (or `<>` for null sender).
    fn mail_from(&mut self, sender: Option<&str>);

    /// Send `STARTTLS`.
    fn starttls(&mut self);

    /// Send `AUTH mechanism [initial-response]`.
    ///
    /// `initial` is the base64-encoded initial response if provided.
    fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>);

    /// Send `QUIT` and close.
    fn quit(&mut self);

    /// Capabilities from the server's EHLO response.
    fn capabilities(&self) -> &SmtpCapabilities;
}

/// Post-STARTTLS stage: must re-EHLO.
pub trait SmtpClientPostTls: SmtpClientHello {}

/// AUTH SASL exchange (RFC 4954).
pub trait SmtpClientAuthExchange {
    /// Send a base64-encoded SASL response.
    fn respond(&mut self, response: &[u8]);
    /// Abort AUTH with `*`.
    fn abort(&mut self);
}

/// Post-MAIL-FROM stage: RCPT TO, RSET, DATA.
pub trait SmtpClientEnvelope: SmtpClientSession {
    /// Send `RCPT TO:<recipient>`.
    fn rcpt_to(&mut self, recipient: &str);
    /// Send `RSET`.
    fn rset(&mut self);
    /// Send `DATA` (or enter BDAT mode if CHUNKING is available).
    fn start_data(&mut self);
    /// Whether at least one RCPT TO has been accepted.
    fn has_accepted_recipients(&self) -> bool;
}

/// DATA-ready stage: write content then end.
pub trait SmtpClientMessageData {
    /// Append dot-stuffed content to the DATA stream.
    fn write_content(&mut self, content: &[u8]);
    /// End the message (`CRLF.CRLF`).
    fn end_message(&mut self);
}
