// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Pluggable SMTP transaction pipeline (auth / filter hooks).

use rmimeparser::EmailAddress;

/// Receives envelope and content notifications during a mail transaction.
pub trait SmtpPipeline: Send {
    /// MAIL FROM accepted (`None` = null reverse-path `<>`).
    fn mail_from(&mut self, sender: Option<&EmailAddress>);
    /// RCPT TO accepted.
    fn rcpt_to(&mut self, recipient: &EmailAddress);
    /// Message body chunk (dot-unstuffed / BDAT payload).
    fn message_content(&mut self, chunk: &[u8]);
    /// End of DATA / final BDAT LAST.
    fn end_data(&mut self);
    /// RSET or transaction end — clear per-message state.
    fn reset(&mut self);
}

/// No-op pipeline.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullPipeline;

impl SmtpPipeline for NullPipeline {
    fn mail_from(&mut self, _sender: Option<&EmailAddress>) {}
    fn rcpt_to(&mut self, _recipient: &EmailAddress) {}
    fn message_content(&mut self, _chunk: &[u8]) {}
    fn end_data(&mut self) {}
    fn reset(&mut self) {}
}

/// Alias for [`NullPipeline`] — discards all notifications.
pub type DiscardPipeline = NullPipeline;
