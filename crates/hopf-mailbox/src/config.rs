// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Mailbox configuration.

/// Search-index configuration.
///
/// Body text is **not** indexed by default to limit disk use. Enable
/// [`body_indexing`](Self::body_indexing) when `TEXT`/`BODY` IMAP SEARCH should
/// hit the index instead of parsing each message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexConfig {
    /// When `true`, store lowercased body text in `.gidx` (format version 2).
    /// Default: `false`.
    pub body_indexing: bool,
    /// Maximum body bytes retained in the index when body indexing is on
    /// (UTF-8 truncated at a char boundary). Default: 64 KiB.
    pub max_body_bytes: usize,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            body_indexing: false,
            max_body_bytes: 64 * 1024,
        }
    }
}

impl IndexConfig {
    /// Headers-only indexing (default).
    pub fn headers_only() -> Self {
        Self::default()
    }

    /// Enable body indexing with the default body size cap.
    pub fn with_body_indexing() -> Self {
        Self {
            body_indexing: true,
            ..Self::default()
        }
    }
}
