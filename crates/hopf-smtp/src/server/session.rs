// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP session and DATA dot-unstuff state machines.

/// High-level SMTP transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmtpSessionState {
    /// Connected; awaiting HELO/EHLO (or greeting not yet sent).
    #[default]
    Initial,
    /// After HELO/EHLO; ready for MAIL FROM.
    Ready,
    /// After accepted MAIL FROM; collecting RCPT TO.
    Mail,
    /// At least one RCPT accepted; DATA/BDAT allowed.
    Rcpt,
    /// Receiving DATA (dot-stuffed) content.
    Data,
    /// Receiving BDAT chunk content.
    Bdat,
    /// Outbound relay / async delivery in progress; awaiting deferred 250/4xx.
    Delivering,
    /// QUIT issued / closing.
    Quit,
}

/// Dot-unstuffing scanner states (RFC 5321 §4.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataDotState {
    /// Ordinary content.
    #[default]
    Normal,
    /// Saw CR.
    SawCr,
    /// Saw CRLF (line boundary — watch for leading `.`).
    SawCrlf,
    /// Saw CRLF `.` (possible end or stuffed dot).
    SawDot,
    /// Saw CRLF `.\r` (awaiting LF for end-of-data).
    SawDotCr,
}
