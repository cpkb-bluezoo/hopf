// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 request/response stream message sequencing (RFC 9114 §4.1).

/// Where a bidirectional request stream is in its HEADERS/DATA sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum StreamMessagePhase {
    /// No request/response HEADERS yet — DATA is forbidden.
    #[default]
    AwaitingHeaders,
    /// Request/response HEADERS seen; DATA and optional trailer HEADERS allowed.
    InMessage,
    /// Trailer HEADERS delivered — no further HEADERS or DATA.
    AfterTrailers,
}

impl StreamMessagePhase {
    /// RFC 9114 §4.1: DATA is only valid after the opening HEADERS frame.
    pub fn data_allowed(self) -> bool {
        matches!(self, Self::InMessage)
    }

    /// Advance after a successfully validated opening HEADERS frame.
    pub fn opened_message(self) -> Self {
        debug_assert_eq!(self, Self::AwaitingHeaders);
        Self::InMessage
    }

    /// Advance after successfully validated trailer HEADERS.
    pub fn opened_trailers(self) -> Self {
        debug_assert_eq!(self, Self::InMessage);
        Self::AfterTrailers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_only_allowed_in_message_body_phase() {
        assert!(!StreamMessagePhase::AwaitingHeaders.data_allowed());
        assert!(StreamMessagePhase::InMessage.data_allowed());
        assert!(!StreamMessagePhase::AfterTrailers.data_allowed());
    }
}
