// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 session phases (RFC 1939).

/// Protocol state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pop3SessionState {
    /// Before successful authentication.
    Authorization,
    /// Authenticated; mailbox open.
    Transaction,
    /// After QUIT in TRANSACTION; committing deletions.
    Update,
}
