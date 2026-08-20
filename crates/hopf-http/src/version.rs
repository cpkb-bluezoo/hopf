// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP version.

/// Negotiated HTTP protocol version (application-facing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2 (RFC 9113).
    Http2,
    /// HTTP/3 (RFC 9114).
    Http3,
}

impl HttpVersion {
    /// Parse `HTTP/1.0` or `HTTP/1.1` from an HTTP/1.x status/request line.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "HTTP/1.0" => Some(Self::Http10),
            "HTTP/1.1" => Some(Self::Http11),
            _ => None,
        }
    }

    /// Wire token including `HTTP/` prefix (HTTP/1.x only).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
        }
    }

    /// True when multiple concurrent request streams are supported (HTTP/2+).
    pub fn supports_multiplexing(self) -> bool {
        matches!(self, Self::Http2 | Self::Http3)
    }
}
