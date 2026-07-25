// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Staged POP3 handler SPI (Gumdrop `pop3.handler`).

mod default;
mod state;

pub use default::{DefaultPop3Handler, DefaultPop3HandlerFactory};
pub use state::{
    AuthenticateState, ConnectedState, ListState, ListWriter, MailboxStatusState,
    MarkDeletedState, ResetState, RetrieveState, TopState, UidlState, UidlWriter, UpdateState,
};

use hopf_mailbox::{Mailbox, MailboxFactory};

/// Factory for the initial [`ClientConnected`] stage.
pub trait Pop3HandlerFactory: Send + Sync {
    /// Create a handler for a new connection.
    fn create(&self) -> Box<dyn ClientConnected>;
}

/// Entry point after TCP (and optional implicit TLS) accept.
pub trait ClientConnected: Send {
    /// New connection; call accept/reject on `state`.
    fn connected(
        &mut self,
        state: &mut dyn ConnectedState,
        peer: std::net::SocketAddr,
        local: std::net::SocketAddr,
        tls: bool,
    );
    /// Connection closed.
    fn disconnected(&mut self);
}

/// Policy decision after credentials are verified by the protocol.
pub trait AuthorizationHandler: Send {
    /// Credentials ok; decide whether to open the mailbox.
    fn authenticate(
        &mut self,
        state: &mut dyn AuthenticateState,
        username: &str,
        factory: &dyn MailboxFactory,
    );
}

/// TRANSACTION-state commands.
pub trait TransactionHandler: Send {
    /// STAT.
    fn mailbox_status(&mut self, state: &mut dyn MailboxStatusState, mailbox: &dyn Mailbox);
    /// LIST (`message_number == 0` → all).
    fn list(&mut self, state: &mut dyn ListState, mailbox: &dyn Mailbox, message_number: u32);
    /// RETR.
    fn retrieve_message(
        &mut self,
        state: &mut dyn RetrieveState,
        mailbox: &dyn Mailbox,
        message_number: u32,
    );
    /// DELE.
    fn mark_deleted(
        &mut self,
        state: &mut dyn MarkDeletedState,
        mailbox: &mut dyn Mailbox,
        message_number: u32,
    );
    /// RSET.
    fn reset(&mut self, state: &mut dyn ResetState, mailbox: &mut dyn Mailbox);
    /// TOP.
    fn top(
        &mut self,
        state: &mut dyn TopState,
        mailbox: &dyn Mailbox,
        message_number: u32,
        lines: u32,
    );
    /// UIDL (`message_number == 0` → all).
    fn uidl(&mut self, state: &mut dyn UidlState, mailbox: &dyn Mailbox, message_number: u32);
    /// QUIT in TRANSACTION → UPDATE.
    fn quit(&mut self, state: &mut dyn UpdateState, mailbox: &dyn Mailbox);
}
