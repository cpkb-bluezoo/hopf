// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Accept/reject state traits for each POP3 stage.

use super::{AuthorizationHandler, TransactionHandler};
use hopf_mailbox::{Mailbox, MailboxStore};

/// Operations right after connect.
pub trait ConnectedState {
    /// Accept with greeting banner; transition to authorization.
    fn accept_connection(&mut self, greeting: &str, handler: Box<dyn AuthorizationHandler>);
    /// Reject and close.
    fn reject_connection(&mut self, message: &str);
    /// Reject and close (alias).
    fn reject_and_close(&mut self, message: &str) {
        self.reject_connection(message);
    }
}

/// After Realm/CredentialStore verified credentials.
pub trait AuthenticateState {
    /// Authorise; protocol opens INBOX on the storage pool.
    fn proceed_open(&mut self, handler: Box<dyn TransactionHandler>);
    /// Accept with an already-opened mailbox (advanced; rare).
    fn accept_opened(
        &mut self,
        store: Box<dyn MailboxStore>,
        mailbox: Box<dyn Mailbox>,
        handler: Box<dyn TransactionHandler>,
    );
    /// Reject access despite valid credentials.
    fn reject(&mut self, message: &str, handler: Box<dyn AuthorizationHandler>);
    /// Reject and close.
    fn reject_and_close(&mut self, message: &str);
}

/// STAT response.
pub trait MailboxStatusState {
    /// `+OK <count> <octets>`.
    fn send_status(&mut self, count: u32, size: u64, handler: Box<dyn TransactionHandler>);
    /// Error.
    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>);
}

/// LIST response writer for multi-line listings.
pub trait ListWriter {
    /// One `<n> <size>` line.
    fn message(&mut self, number: u32, size: u64);
    /// Terminate listing and restore handler.
    fn end(self: Box<Self>, handler: Box<dyn TransactionHandler>);
}

/// LIST response.
pub trait ListState {
    /// Begin multi-line listing (`+OK <count> messages`).
    fn begin_listing(&mut self, count: u32) -> Box<dyn ListWriter>;
    /// Single-message listing.
    fn send_listing(&mut self, number: u32, size: u64, handler: Box<dyn TransactionHandler>);
    /// No such message.
    fn no_such_message(&mut self, handler: Box<dyn TransactionHandler>);
    /// Message marked deleted.
    fn message_deleted(&mut self, handler: Box<dyn TransactionHandler>);
    /// Error.
    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>);
}

/// RETR response.
pub trait RetrieveState {
    /// Protocol loads and streams the message on the storage pool.
    fn proceed_retr(&mut self, size: u64, handler: Box<dyn TransactionHandler>);
    /// No such message.
    fn no_such_message(&mut self, handler: Box<dyn TransactionHandler>);
    /// Message marked deleted.
    fn message_deleted(&mut self, handler: Box<dyn TransactionHandler>);
    /// Error.
    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>);
}

/// DELE response.
pub trait MarkDeletedState {
    /// Marked.
    fn marked_deleted(&mut self, handler: Box<dyn TransactionHandler>);
    /// No such message.
    fn no_such_message(&mut self, handler: Box<dyn TransactionHandler>);
    /// Already deleted.
    fn already_deleted(&mut self, handler: Box<dyn TransactionHandler>);
    /// Error.
    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>);
}

/// RSET response.
pub trait ResetState {
    /// `+OK` with post-reset STAT figures.
    fn reset_complete(&mut self, count: u32, size: u64, handler: Box<dyn TransactionHandler>);
    /// Error.
    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>);
}

/// TOP response.
pub trait TopState {
    /// Protocol loads a TOP prefix on the storage pool.
    fn proceed_top(&mut self, lines: u32, handler: Box<dyn TransactionHandler>);
    /// No such message.
    fn no_such_message(&mut self, handler: Box<dyn TransactionHandler>);
    /// Message marked deleted.
    fn message_deleted(&mut self, handler: Box<dyn TransactionHandler>);
    /// Error.
    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>);
}

/// UIDL listing writer.
pub trait UidlWriter {
    /// One `<n> <uid>` line.
    fn message(&mut self, number: u32, uid: &str);
    /// Terminate listing.
    fn end(self: Box<Self>, handler: Box<dyn TransactionHandler>);
}

/// UIDL response.
pub trait UidlState {
    /// Begin multi-line UID listing.
    fn begin_listing(&mut self) -> Box<dyn UidlWriter>;
    /// Single UID.
    fn send_uid(&mut self, number: u32, uid: &str, handler: Box<dyn TransactionHandler>);
    /// No such message.
    fn no_such_message(&mut self, handler: Box<dyn TransactionHandler>);
    /// Message marked deleted.
    fn message_deleted(&mut self, handler: Box<dyn TransactionHandler>);
    /// Error.
    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>);
}

/// QUIT / UPDATE response.
pub trait UpdateState {
    /// Protocol closes/expunges on the storage pool.
    fn proceed_quit(&mut self, handler: Box<dyn TransactionHandler>);
    /// Error.
    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>);
}
