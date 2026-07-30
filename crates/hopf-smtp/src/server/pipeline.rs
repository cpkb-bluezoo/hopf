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

/// In-memory message buffer pipeline — general-purpose building block for
/// custom handlers that want the whole message as one `Vec<u8>`.
///
/// Neither stock handler (`LocalDeliveryHandler`, `SimpleRelayHandler`) uses
/// this anymore — both spool to a bounded temp file instead (see
/// `crate::server::spool::SpoolPipeline`) so a large message is never held
/// whole in memory. This type remains for custom handlers where buffering
/// the whole thing genuinely is the simplest option (e.g. small, bounded
/// messages, or further in-memory processing before storage).
#[derive(Debug, Default)]
pub struct MessageBufferPipeline {
    buf: Vec<u8>,
}

impl MessageBufferPipeline {
    /// Empty buffer.
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(8192),
        }
    }

    /// Buffered message bytes.
    pub fn message_data(&self) -> &[u8] {
        &self.buf
    }

    /// Take ownership of the buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

impl SmtpPipeline for MessageBufferPipeline {
    fn mail_from(&mut self, _sender: Option<&EmailAddress>) {}
    fn rcpt_to(&mut self, _recipient: &EmailAddress) {}
    fn message_content(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }
    fn end_data(&mut self) {}
    fn reset(&mut self) {
        self.buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_pipeline_buffers_and_resets_content() {
        let mut pipeline = MessageBufferPipeline::new();
        pipeline.message_content(b"one");
        pipeline.message_content(b"-two");
        assert_eq!(pipeline.message_data(), b"one-two");
        pipeline.reset();
        assert!(pipeline.message_data().is_empty());
    }
}
