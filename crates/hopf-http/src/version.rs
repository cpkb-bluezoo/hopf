// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP version.

/// Wire protocol version for HTTP/1.x.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
}

impl HttpVersion {
    /// Parse `HTTP/1.0` or `HTTP/1.1`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "HTTP/1.0" => Some(Self::Http10),
            "HTTP/1.1" => Some(Self::Http11),
            _ => None,
        }
    }

    /// Wire token including `HTTP/` prefix.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}
