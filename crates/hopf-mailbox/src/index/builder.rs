// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Build [`IndexEntry`](super::IndexEntry) via rmimeparser.

use std::collections::BTreeSet;
use std::io::Read;

use rmimeparser::mime::MimeHandler;
use rmimeparser::rfc5322::{EmailAddress, MessageHandler, MessageParser, OffsetDateTime};
use rmimeparser::ContentId;

use crate::config::IndexConfig;
use crate::error::MailboxResult;
use crate::flag::Flag;

use super::entry::{
    IndexEntry, DESCRIPTOR_COUNT_BODY, DESCRIPTOR_COUNT_HEADERS, DESC_BCC, DESC_BODY, DESC_CC,
    DESC_FROM, DESC_KEYWORDS, DESC_LOCATION, DESC_MESSAGE_ID, DESC_SUBJECT, DESC_TO,
};

/// Collects indexed fields while parsing a message.
#[derive(Default)]
struct CollectHandler {
    from: String,
    to: String,
    cc: String,
    bcc: String,
    subject: String,
    message_id: String,
    sent_millis: i64,
    body: Vec<u8>,
    capture_body: bool,
    max_body: usize,
    headers_done: bool,
}

impl MimeHandler for CollectHandler {
    fn end_headers(&mut self) -> rmimeparser::ParseResult<()> {
        self.headers_done = true;
        Ok(())
    }

    fn body_content(&mut self, content: &[u8]) -> rmimeparser::ParseResult<()> {
        if self.capture_body && self.body.len() < self.max_body {
            let remain = self.max_body - self.body.len();
            self.body
                .extend_from_slice(&content[..content.len().min(remain)]);
        }
        Ok(())
    }
}

impl MessageHandler for CollectHandler {
    fn header(&mut self, name: &str, value: &str) -> rmimeparser::ParseResult<()> {
        if name.eq_ignore_ascii_case("Subject") && self.subject.is_empty() {
            self.subject = value.to_ascii_lowercase();
        }
        Ok(())
    }

    fn date_header(&mut self, name: &str, date: OffsetDateTime) -> rmimeparser::ParseResult<()> {
        if name.eq_ignore_ascii_case("Date") && self.sent_millis == 0 {
            self.sent_millis = offset_to_millis(&date);
        }
        Ok(())
    }

    fn address_header(
        &mut self,
        name: &str,
        addresses: &[EmailAddress],
    ) -> rmimeparser::ParseResult<()> {
        let joined = join_addrs(addresses);
        if name.eq_ignore_ascii_case("From") || name.eq_ignore_ascii_case("Sender") {
            append_field(&mut self.from, &joined);
        } else if name.eq_ignore_ascii_case("To") {
            append_field(&mut self.to, &joined);
        } else if name.eq_ignore_ascii_case("Cc") {
            append_field(&mut self.cc, &joined);
        } else if name.eq_ignore_ascii_case("Bcc") {
            append_field(&mut self.bcc, &joined);
        }
        Ok(())
    }

    fn message_id_header(
        &mut self,
        name: &str,
        content_ids: &[ContentId],
    ) -> rmimeparser::ParseResult<()> {
        if name.eq_ignore_ascii_case("Message-ID") && self.message_id.is_empty() {
            if let Some(id) = content_ids.first() {
                self.message_id = id.to_string().to_ascii_lowercase();
            }
        }
        Ok(())
    }
}

/// Builds index entries from RFC 822 bytes.
pub struct IndexBuilder {
    config: IndexConfig,
}

impl IndexBuilder {
    /// Create with index config.
    pub fn new(config: IndexConfig) -> Self {
        Self { config }
    }

    /// Parse `rfc822` (already fully in memory) into an [`IndexEntry`].
    ///
    /// Convenience wrapper over [`Self::build_streaming`] for callers that
    /// already have the whole message as a slice (e.g. mbox, whose on-disk
    /// format requires a full-file scan to locate message boundaries in the
    /// first place — a separate, structural constraint this method doesn't
    /// try to work around). Prefer `build_streaming` for anything read
    /// incrementally off disk or the wire.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        &self,
        uid: u64,
        message_number: u32,
        size: u64,
        location: &str,
        flags: &BTreeSet<Flag>,
        keywords: &BTreeSet<String>,
        internal_date_millis: i64,
        rfc822: &[u8],
    ) -> IndexEntry {
        // `&[u8]` as `Read` never errors, so this can't fail.
        self.build_streaming(
            uid,
            message_number,
            size,
            location,
            flags,
            keywords,
            internal_date_millis,
            rfc822,
        )
        .expect("reading from a byte slice cannot fail")
    }

    /// Build an [`IndexEntry`] by reading `rfc822` from `reader` in bounded
    /// chunks — the message is never held whole in memory by this method
    /// (the `MessageParser` push-parses each chunk as it arrives, mirroring
    /// how the SMTP/IMAP wire parsers are driven).
    #[allow(clippy::too_many_arguments)]
    pub fn build_streaming(
        &self,
        uid: u64,
        message_number: u32,
        size: u64,
        location: &str,
        flags: &BTreeSet<Flag>,
        keywords: &BTreeSet<String>,
        internal_date_millis: i64,
        mut reader: impl Read,
    ) -> MailboxResult<IndexEntry> {
        let mut handler = CollectHandler {
            capture_body: self.config.body_indexing,
            max_body: self.config.max_body_bytes,
            ..CollectHandler::default()
        };
        {
            let mut parser = MessageParser::new(&mut handler);
            let mut carry: Vec<u8> = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                carry.extend_from_slice(&buf[..n]);
                let mut slice = carry.as_slice();
                // Ignore parse errors — a malformed message still gets a
                // best-effort index rather than failing indexing outright.
                let _ = parser.receive(&mut slice);
                carry = slice.to_vec();
            }
            let _ = parser.close();
        }

        let mut internal = internal_date_millis;
        if internal == 0 && handler.sent_millis != 0 {
            internal = handler.sent_millis;
        }

        let kw = keywords
            .iter()
            .map(|k| k.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",");

        let n = if self.config.body_indexing {
            DESCRIPTOR_COUNT_BODY
        } else {
            DESCRIPTOR_COUNT_HEADERS
        };
        let mut props = vec![String::new(); n];
        props[DESC_LOCATION] = location.to_ascii_lowercase();
        props[DESC_FROM] = handler.from;
        props[DESC_TO] = handler.to;
        props[DESC_CC] = handler.cc;
        props[DESC_BCC] = handler.bcc;
        props[DESC_SUBJECT] = handler.subject;
        props[DESC_MESSAGE_ID] = handler.message_id;
        props[DESC_KEYWORDS] = kw;
        if self.config.body_indexing {
            let body = String::from_utf8_lossy(&handler.body).to_ascii_lowercase();
            props[DESC_BODY] = truncate_str(body, self.config.max_body_bytes);
        }

        Ok(IndexEntry::new(
            uid,
            message_number,
            size,
            internal,
            handler.sent_millis,
            flags,
            props,
        ))
    }
}

fn join_addrs(addrs: &[EmailAddress]) -> String {
    addrs
        .iter()
        .map(|a| a.address().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn append_field(dst: &mut String, src: &str) {
    if src.is_empty() {
        return;
    }
    if !dst.is_empty() {
        dst.push(' ');
    }
    dst.push_str(src);
}

fn truncate_str(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

fn offset_to_millis(dt: &OffsetDateTime) -> i64 {
    // Best-effort: use Debug/fields if available; fall back to 0.
    // rmimeparser OffsetDateTime exposes calendar fields.
    epoch_millis_from_parts(dt)
}

fn epoch_millis_from_parts(dt: &OffsetDateTime) -> i64 {
    // Inspect via string isn't ideal — use public fields from the crate.
    let y = dt.year as i64;
    let m = dt.month as i64;
    let d = dt.day as i64;
    let hh = dt.hour as i64;
    let mm = dt.minute as i64;
    let ss = dt.second as i64;
    let offset_min = (dt.offset_seconds as i64) / 60;
    let days = days_from_civil(y, m, d);
    let secs = days * 86_400 + hh * 3600 + mm * 60 + ss - offset_min * 60;
    secs * 1000
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
    (era * 146_097 + doe as i64) - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IndexConfig;

    const MSG: &[u8] = b"From: alice@example.com\r\n\
Subject: Hello there\r\n\
\r\n\
This is the body.\r\nSecond line of the body.\r\n";

    /// A `Read` impl that hands back at most `chunk_size` bytes per call, to
    /// stress the parser's chunk-boundary/carry-buffer handling regardless
    /// of where a header or body line happens to split.
    struct TinyChunks<'a> {
        data: &'a [u8],
        chunk_size: usize,
    }

    impl Read for TinyChunks<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.chunk_size.min(self.data.len()).min(buf.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn build_whole_slice_indexes_headers() {
        let builder = IndexBuilder::new(IndexConfig::default());
        let entry = builder.build(
            1,
            1,
            MSG.len() as u64,
            "loc",
            &BTreeSet::new(),
            &BTreeSet::new(),
            0,
            MSG,
        );
        assert_eq!(entry.prop(DESC_FROM), "alice@example.com");
        assert_eq!(entry.prop(DESC_SUBJECT), "hello there");
    }

    #[test]
    fn build_streaming_matches_whole_slice_regardless_of_chunk_size() {
        let builder = IndexBuilder::new(IndexConfig::with_body_indexing());
        let whole = builder
            .build_streaming(
                1,
                1,
                MSG.len() as u64,
                "loc",
                &BTreeSet::new(),
                &BTreeSet::new(),
                0,
                MSG,
            )
            .unwrap();

        for chunk_size in [1usize, 2, 3, 7, 64, 4096] {
            let entry = builder
                .build_streaming(
                    1,
                    1,
                    MSG.len() as u64,
                    "loc",
                    &BTreeSet::new(),
                    &BTreeSet::new(),
                    0,
                    TinyChunks {
                        data: MSG,
                        chunk_size,
                    },
                )
                .unwrap();
            assert_eq!(
                entry.prop(DESC_FROM),
                whole.prop(DESC_FROM),
                "chunk_size={chunk_size}"
            );
            assert_eq!(
                entry.prop(DESC_SUBJECT),
                whole.prop(DESC_SUBJECT),
                "chunk_size={chunk_size}"
            );
            assert_eq!(entry.body(), whole.body(), "chunk_size={chunk_size}");
        }
    }

    #[test]
    fn build_streaming_captures_body_when_body_indexing_enabled() {
        let builder = IndexBuilder::new(IndexConfig::with_body_indexing());
        let entry = builder
            .build_streaming(
                1,
                1,
                MSG.len() as u64,
                "loc",
                &BTreeSet::new(),
                &BTreeSet::new(),
                0,
                TinyChunks {
                    data: MSG,
                    chunk_size: 5,
                },
            )
            .unwrap();
        let body = entry.body().expect("body indexing enabled");
        assert!(
            body.contains("this is the body"),
            "body missing first line: {body:?}"
        );
        assert!(
            body.contains("second line of the body"),
            "body missing second line: {body:?}"
        );
    }
}
