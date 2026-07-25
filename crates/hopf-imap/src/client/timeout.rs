// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-phase timeout configuration for the IMAP client.

use std::time::Duration;

/// Per-phase timeout configuration for [`super::facade::ImapClient`].
#[derive(Debug, Clone)]
pub struct ImapClientTimeouts {
    /// DNS resolution budget (default 5 s).
    pub dns: Duration,
    /// Connect budget: dial → greeting (default 30 s). Also used as the
    /// greeting wait after TCP (and after implicit TLS handshake).
    pub connect: Duration,
    /// Per-command idle budget while a tagged reply is outstanding (default 60 s).
    pub stage: Duration,
    /// Message-body / FETCH literal transfer budget (default 600 s).
    pub message: Duration,
}

impl Default for ImapClientTimeouts {
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
        let t = ImapClientTimeouts::default();
        assert_eq!(t.dns, Duration::from_secs(5));
        assert_eq!(t.connect, Duration::from_secs(30));
        assert_eq!(t.stage, Duration::from_secs(60));
        assert_eq!(t.message, Duration::from_secs(600));
    }
}
