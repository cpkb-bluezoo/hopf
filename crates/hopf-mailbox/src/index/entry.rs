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
pub(crate) const DESC_BODY: usize = 8;

pub(crate) const DESCRIPTOR_COUNT_HEADERS: usize = 8;
pub(crate) const DESCRIPTOR_COUNT_BODY: usize = 9;

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
    /// Build from parts. `props` length 8 (headers) or 9 (with body).
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
            props.len() == DESCRIPTOR_COUNT_HEADERS || props.len() == DESCRIPTOR_COUNT_BODY,
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

    /// Map header name to indexed field.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
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
