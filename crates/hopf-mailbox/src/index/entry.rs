// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Single `.gidx` entry.

use std::collections::BTreeSet;

use crate::flag::{flags_from_byte, flags_to_byte, Flag};

pub(crate) const DESC_LOCATION: usize = 0;
pub(crate) const DESC_FROM: usize = 1;
pub(crate) const DESC_TO: usize = 2;
pub(crate) const DESC_CC: usize = 3;
pub(crate) const DESC_BCC: usize = 4;
pub(crate) const DESC_SUBJECT: usize = 5;
pub(crate) const DESC_MESSAGE_ID: usize = 6;
pub(crate) const DESC_KEYWORDS: usize = 7;
/// Added for issue #407 (RFC 5256 THREAD REFERENCES): the full `References`
/// header, message-IDs space-joined in header order.
pub(crate) const DESC_REFERENCES: usize = 8;
/// Added for issue #407: the full `In-Reply-To` header, message-IDs
/// space-joined (the threading algorithm only ever uses the first one, but
/// the raw header is kept intact here same as `References`).
pub(crate) const DESC_IN_REPLY_TO: usize = 9;
pub(crate) const DESC_BODY: usize = 10;

/// Original (pre-#407) headers-only layout — still accepted when reading an
/// existing on-disk entry built by an older version; never written anymore.
pub(crate) const DESCRIPTOR_COUNT_HEADERS_V1: usize = 8;
/// Original (pre-#407) headers-plus-body layout — read-only, ditto.
pub(crate) const DESCRIPTOR_COUNT_BODY_V1: usize = 9;
/// Current headers layout (adds `References` / `In-Reply-To`).
pub(crate) const DESCRIPTOR_COUNT_HEADERS: usize = 10;
/// Current headers-plus-body layout.
pub(crate) const DESCRIPTOR_COUNT_BODY: usize = 11;

/// Indexed metadata for one message.
#[derive(Clone, Debug)]
pub struct IndexEntry {
    /// IMAP UID.
    pub uid: u64,
    /// Sequence number at index build time.
    pub message_number: u32,
    /// Size in octets.
    pub size: u64,
    /// Internal date (Unix millis); 0 = unknown.
    pub internal_date: i64,
    /// Sent date (Unix millis); 0 = unknown.
    pub sent_date: i64,
    flags_byte: u8,
    /// Parallel to descriptors: location, from, to, cc, bcc, subject, message-id, keywords [, body]
    props: Vec<String>,
}

impl IndexEntry {
    /// Build from parts. `props` length 10 (headers) or 11 (with body) for
    /// entries built by this version; an entry loaded from an older
    /// on-disk index may still be 8 or 9 (see [`DESCRIPTOR_COUNT_HEADERS_V1`]
    /// / [`DESCRIPTOR_COUNT_BODY_V1`]) — those simply read back `None` from
    /// [`Self::references`] / [`Self::in_reply_to`] until the message is
    /// re-indexed.
    pub fn new(
        uid: u64,
        message_number: u32,
        size: u64,
        internal_date: i64,
        sent_date: i64,
        flags: &BTreeSet<Flag>,
        props: Vec<String>,
    ) -> Self {
        assert!(
            matches!(
                props.len(),
                DESCRIPTOR_COUNT_HEADERS_V1
                    | DESCRIPTOR_COUNT_BODY_V1
                    | DESCRIPTOR_COUNT_HEADERS
                    | DESCRIPTOR_COUNT_BODY
            ),
            "props len"
        );
        Self {
            uid,
            message_number,
            size,
            internal_date,
            sent_date,
            flags_byte: flags_to_byte(flags),
            props,
        }
    }

    /// System flags.
    pub fn flags(&self) -> BTreeSet<Flag> {
        flags_from_byte(self.flags_byte)
    }

    /// Set system flags.
    pub fn set_flags(&mut self, flags: &BTreeSet<Flag>) {
        self.flags_byte = flags_to_byte(flags);
    }

    pub(crate) fn flags_byte(&self) -> u8 {
        self.flags_byte
    }

    pub(crate) fn set_flags_byte(&mut self, b: u8) {
        self.flags_byte = b;
    }

    /// Property string.
    pub fn prop(&self, idx: usize) -> &str {
        self.props.get(idx).map(|s| s.as_str()).unwrap_or("")
    }

    /// Keywords split on comma.
    pub fn keywords_set(&self) -> BTreeSet<String> {
        self.prop(DESC_KEYWORDS)
            .split([',', ' '])
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    /// Set keywords property (comma-joined, lowercased).
    pub fn set_keywords(&mut self, keywords: &BTreeSet<String>) {
        let joined = keywords
            .iter()
            .map(|k| k.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        if self.props.len() > DESC_KEYWORDS {
            self.props[DESC_KEYWORDS] = joined;
        }
    }

    /// Body text if present.
    pub fn body(&self) -> Option<&str> {
        if self.props.len() > DESC_BODY {
            Some(self.prop(DESC_BODY))
        } else {
            None
        }
    }

    /// The `References` header's message-IDs, space-joined in header order,
    /// or `None` if this entry predates issue #407's indexing of it (an
    /// old, not-yet-re-indexed on-disk entry) — callers fall back to a live
    /// header read in that case, same as [`Self::in_reply_to`].
    pub fn references(&self) -> Option<&str> {
        if self.props.len() > DESC_REFERENCES {
            Some(self.prop(DESC_REFERENCES))
        } else {
            None
        }
    }

    /// The `In-Reply-To` header's message-IDs, space-joined, or `None` if
    /// this entry predates issue #407's indexing of it.
    pub fn in_reply_to(&self) -> Option<&str> {
        if self.props.len() > DESC_IN_REPLY_TO {
            Some(self.prop(DESC_IN_REPLY_TO))
        } else {
            None
        }
    }

    /// Map header name to indexed field. `None` both for an unindexed
    /// header name and for one this particular entry predates (see
    /// [`Self::references`] / [`Self::in_reply_to`]) — either way, the
    /// caller falls back to a live header read.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        match n.as_str() {
            "references" => return self.references(),
            "in-reply-to" => return self.in_reply_to(),
            _ => {}
        }
        let idx = match n.as_str() {
            "from" | "sender" => DESC_FROM,
            "to" => DESC_TO,
            "cc" => DESC_CC,
            "bcc" => DESC_BCC,
            "subject" => DESC_SUBJECT,
            "message-id" => DESC_MESSAGE_ID,
            _ => return None,
        };
        Some(self.prop(idx))
    }

    pub(crate) fn props(&self) -> &[String] {
        &self.props
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_v1_entry() -> IndexEntry {
        // Pre-issue-#407 layout: exactly `DESCRIPTOR_COUNT_HEADERS_V1` (8)
        // props, as an on-disk entry built by an older hopf version would
        // still be, in memory, right after `IndexFile::load`.
        IndexEntry::new(
            1,
            1,
            100,
            0,
            0,
            &BTreeSet::new(),
            vec![
                "loc".into(),
                "a@b".into(),
                "".into(),
                "".into(),
                "".into(),
                "subj".into(),
                "<id@x>".into(),
                "".into(),
            ],
        )
    }

    #[test]
    fn old_entry_reports_no_references_rather_than_an_empty_string() {
        // The distinction matters: `None` tells `MessageContext::header`
        // (see hopf-imap's `IndexedContext`) to fall back to a live header
        // read; `Some("")` would wrongly assert "no References header",
        // discarding real threading data for mail indexed before #407.
        let e = headers_v1_entry();
        assert_eq!(e.references(), None);
        assert_eq!(e.in_reply_to(), None);
        assert_eq!(e.header_value("references"), None);
        assert_eq!(e.header_value("in-reply-to"), None);
    }

    #[test]
    fn new_entry_reports_references_and_in_reply_to() {
        let e = IndexEntry::new(
            1,
            1,
            100,
            0,
            0,
            &BTreeSet::new(),
            vec![
                "loc".into(),
                "a@b".into(),
                "".into(),
                "".into(),
                "".into(),
                "subj".into(),
                "<id@x>".into(),
                "".into(),
                "<r1@x> <r2@x>".into(),
                "<r2@x>".into(),
            ],
        );
        assert_eq!(e.references(), Some("<r1@x> <r2@x>"));
        assert_eq!(e.in_reply_to(), Some("<r2@x>"));
        assert_eq!(e.header_value("References"), Some("<r1@x> <r2@x>"));
        assert_eq!(e.header_value("In-Reply-To"), Some("<r2@x>"));
    }

    #[test]
    fn new_entry_with_body_still_reports_references() {
        let mut props = vec![
            "loc".into(),
            "a@b".into(),
            String::new(),
            String::new(),
            String::new(),
            "subj".into(),
            "<id@x>".into(),
            String::new(),
            "<r1@x>".into(),
            String::new(),
        ];
        props.push("body text".into());
        assert_eq!(props.len(), DESCRIPTOR_COUNT_BODY);
        let e = IndexEntry::new(1, 1, 100, 0, 0, &BTreeSet::new(), props);
        assert_eq!(e.references(), Some("<r1@x>"));
        assert_eq!(e.body(), Some("body text"));
    }
}
