// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`MimeAnalysisPipeline`] — a real streaming message-analysis hook for
//! library users who want parsed MIME/RFC 5322 events instead of raw
//! bytes, without hand-rolling header-boundary detection themselves.

use rmimeparser::rfc5322::{MessageHandler, MessageParser};
use rmimeparser::EmailAddress;

use crate::auth::find_header_boundary;
use crate::server::pipeline::SmtpPipeline;

/// Tees message content to a caller-supplied [`MessageHandler`], firing its
/// header events (`header`, `date_header`, `address_header`, ...) as soon
/// as the header block completes, then forwarding body bytes to
/// [`rmimeparser::MimeHandler::body_content`] chunk-by-chunk as they
/// arrive.
///
/// Only header bytes are ever buffered (bounded — real messages keep these
/// to a few KB, matching [`crate::auth::AuthPipeline`]'s own documented
/// memory model), never the body: `body_content` receives each
/// `message_content` chunk directly, undivided.
///
/// This intentionally does **not** run full MIME multipart parsing —
/// `body_content` sees the raw, single top-level body (no
/// `start_entity`/`content_type`/`end_entity` events per part). Detecting
/// multipart boundaries incrementally while never buffering the body is
/// real, unimplemented complexity beyond what this hook set out to solve;
/// a caller that genuinely needs full multipart-aware streaming can drive
/// [`rmimeparser::rfc5322::MessageParser`] itself the same way this type
/// does for headers, one entity at a time.
///
/// Register via [`crate::auth::AuthPipelineBuilder::message_handler`] (or
/// standalone as a connection's whole pipeline) to get parsed events
/// alongside — or instead of — auth processing. This is the direct answer
/// to "I need my own streaming message analysis" — e.g. inspecting
/// existing headers to decide what `Received:` line an MTA should add
/// before delivery (see `crate::server::LocalDeliveryHandler`'s
/// `extra_header_lines` for the injection side of that).
pub struct MimeAnalysisPipeline<H: MessageHandler + Send> {
    handler: H,
    header_buf: Vec<u8>,
    headers_done: bool,
}

impl<H: MessageHandler + Send> MimeAnalysisPipeline<H> {
    /// Wrap `handler`, which will receive parsed events as content streams in.
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            header_buf: Vec::new(),
            headers_done: false,
        }
    }

    /// Borrow the wrapped handler (e.g. to read state it's accumulated).
    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// Consume `self`, returning the wrapped handler.
    pub fn into_handler(self) -> H {
        self.handler
    }
}

impl<H: MessageHandler + Send> SmtpPipeline for MimeAnalysisPipeline<H> {
    fn mail_from(&mut self, _sender: Option<&EmailAddress>) {}
    fn rcpt_to(&mut self, _recipient: &EmailAddress) {}

    fn message_content(&mut self, chunk: &[u8]) -> bool {
        if self.headers_done {
            let _ = self.handler.body_content(chunk);
            return true;
        }
        self.header_buf.extend_from_slice(chunk);
        if let Some(boundary) = find_header_boundary(&self.header_buf) {
            let (header_bytes, leftover_body) = self.header_buf.split_at(boundary);
            {
                let mut data: &[u8] = header_bytes;
                let mut parser = MessageParser::new(&mut self.handler);
                let _ = parser.receive(&mut data);
                let _ = parser.close();
            }
            let _ = self.handler.body_content(leftover_body);
            self.headers_done = true;
            self.header_buf = Vec::new();
        }
        true
    }

    fn end_data(&mut self) {}

    fn reset(&mut self) {
        self.header_buf.clear();
        self.headers_done = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmimeparser::mime::MimeHandler;
    use rmimeparser::rfc5322::EmailAddress as Addr;
    use rmimeparser::rfc5322::OffsetDateTime;
    use rmimeparser::ContentId;

    #[derive(Default)]
    struct Recorder {
        subject: String,
        from: String,
        body: Vec<u8>,
    }

    impl MimeHandler for Recorder {
        fn body_content(&mut self, content: &[u8]) -> rmimeparser::ParseResult<()> {
            self.body.extend_from_slice(content);
            Ok(())
        }
    }

    impl MessageHandler for Recorder {
        fn header(&mut self, name: &str, value: &str) -> rmimeparser::ParseResult<()> {
            if name.eq_ignore_ascii_case("Subject") {
                self.subject = value.to_string();
            }
            Ok(())
        }
        fn address_header(&mut self, name: &str, addrs: &[Addr]) -> rmimeparser::ParseResult<()> {
            if name.eq_ignore_ascii_case("From") {
                if let Some(a) = addrs.first() {
                    self.from = a.address().to_string();
                }
            }
            Ok(())
        }
        fn date_header(&mut self, _name: &str, _date: OffsetDateTime) -> rmimeparser::ParseResult<()> {
            Ok(())
        }
        fn message_id_header(
            &mut self,
            _name: &str,
            _ids: &[ContentId],
        ) -> rmimeparser::ParseResult<()> {
            Ok(())
        }
    }

    #[test]
    fn fires_header_events_then_streams_body_regardless_of_chunk_boundaries() {
        let msg = b"From: alice@example.com\r\nSubject: Hi there\r\n\r\nHello, world!\r\nSecond line.\r\n";
        for chunk_size in [1usize, 3, 7, 64, 4096] {
            let mut pipeline = MimeAnalysisPipeline::new(Recorder::default());
            for chunk in msg.chunks(chunk_size) {
                assert!(pipeline.message_content(chunk));
            }
            pipeline.end_data();
            let h = pipeline.into_handler();
            assert_eq!(h.subject, "Hi there", "chunk_size={chunk_size}");
            assert_eq!(h.from, "alice@example.com", "chunk_size={chunk_size}");
            assert_eq!(
                h.body,
                b"Hello, world!\r\nSecond line.\r\n",
                "chunk_size={chunk_size}"
            );
        }
    }

    #[test]
    fn reset_allows_reuse_for_a_new_transaction() {
        // reset() clears the pipeline's own header-boundary state (so a
        // second transaction's headers are parsed correctly); the wrapped
        // handler's own accumulated state is the caller's concern, exactly
        // like AuthPipeline::reset() only clears its own buffers.
        let mut pipeline = MimeAnalysisPipeline::new(Recorder::default());
        pipeline.message_content(b"Subject: first\r\n\r\nbody one\r\n");
        pipeline.end_data();
        assert_eq!(pipeline.handler().subject, "first");

        pipeline.reset();
        pipeline.message_content(b"Subject: second\r\n\r\nbody two\r\n");
        pipeline.end_data();
        assert_eq!(pipeline.handler().subject, "second");
    }
}
