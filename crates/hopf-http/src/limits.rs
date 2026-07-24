// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Parser and connection limits (Gumdrop defaults).

/// Limits for HTTP/1.x framing.
#[derive(Debug, Clone, Copy)]
pub struct HttpLimits {
    /// Max request-line or header field-line length (default 8192).
    pub max_line_length: usize,
    /// Max number of header fields (default 100).
    pub max_header_count: usize,
    /// Max chunk-size value (default 10 MiB).
    pub max_chunk_size: usize,
    /// Max aggregate request body (default 64 MiB).
    pub max_request_body: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_line_length: 8192,
            max_header_count: 100,
            max_chunk_size: 10 * 1024 * 1024,
            max_request_body: 64 * 1024 * 1024,
        }
    }
}
