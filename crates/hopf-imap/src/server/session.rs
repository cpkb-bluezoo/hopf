// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP session state machine.

/// IMAP4rev2 connection states (RFC 9051 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImapSessionState {
    /// Greeting sent; LOGIN / AUTHENTICATE / STARTTLS allowed.
    NotAuthenticated,
    /// Authenticated; mailbox management allowed.
    Authenticated,
    /// A mailbox is selected.
    Selected,
    /// Connection closing after LOGOUT.
    Logout,
}
