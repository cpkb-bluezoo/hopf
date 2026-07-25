// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-phase timeout configuration for the POP3 client.

use std::time::Duration;

/// Per-phase timeout configuration for [`super::facade::Pop3Client`].
///
/// All durations default to RFC-aligned values.
#[derive(Debug, Clone)]
pub struct Pop3ClientTimeouts {
    /// DNS resolution budget (default 5 s).
    pub dns: Duration,
    /// Connect budget: dial → greeting (default 30 s).
    pub connect: Duration,
    /// Per-reply idle budget after each command (default 60 s).
    pub stage: Duration,
    /// Message-body transfer budget for RETR / TOP (default 600 s).
    pub message: Duration,
}

impl Default for Pop3ClientTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(30),
            stage: Duration::from_secs(60),
            message: Duration::from_secs(600),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let t = Pop3ClientTimeouts::default();
        assert_eq!(t.dns, Duration::from_secs(5));
        assert_eq!(t.connect, Duration::from_secs(30));
        assert_eq!(t.stage, Duration::from_secs(60));
        assert_eq!(t.message, Duration::from_secs(600));
    }
}
