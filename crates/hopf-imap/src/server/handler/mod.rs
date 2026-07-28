// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Staged IMAP server policy SPI (Gumdrop `imap.handler`).

mod default;
mod state;

pub use default::{DefaultImapHandler, DefaultImapHandlerFactory};
pub use state::{
    AppendState, AuthenticateState, CloseState, ConnectedState, CopyState, CreateState,
    DeleteState, ExpungeState, FetchState, ListState, MoveState, QuotaState, RenameState,
    SearchState, SelectState, StatusState, StoreAction, StoreState, SubscribeState,
};

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::SystemTime;

use hopf_mailbox::{Flag, Mailbox, MailboxFactory, MailboxStore, MessageSet, SearchCriteria};

use crate::server::fetch_format::FetchItem;
use crate::server::quota::QuotaManager;
use crate::server::status_items::StatusItem;

/// Factory for the initial [`ClientConnected`] stage.
pub trait ImapHandlerFactory: Send + Sync {
    /// Create a handler for a new connection.
    fn create(&self) -> Box<dyn ClientConnected>;
}

/// Entry point after TCP (and optional implicit TLS) accept.
pub trait ClientConnected: Send {
    /// New connection; call accept/reject on `state`.
    fn connected(
        &mut self,
        state: &mut dyn ConnectedState,
        peer: SocketAddr,
        local: SocketAddr,
        tls: bool,
    );
    /// Connection closed.
    fn disconnected(&mut self);
}

/// Policy after credentials are verified by the protocol.
pub trait NotAuthenticatedHandler: Send {
    /// Credentials ok; decide whether to open the store.
    fn authenticate(
        &mut self,
        state: &mut dyn AuthenticateState,
        username: &str,
        factory: &dyn MailboxFactory,
    );
}

/// AUTHENTICATED-state mailbox commands.
pub trait AuthenticatedHandler: Send {
    /// SELECT.
    fn select(&mut self, state: &mut dyn SelectState, store: &dyn MailboxStore, name: &str);
    /// EXAMINE.
    fn examine(&mut self, state: &mut dyn SelectState, store: &dyn MailboxStore, name: &str);
    /// CREATE.
    fn create(&mut self, state: &mut dyn CreateState, store: &dyn MailboxStore, name: &str);
    /// DELETE.
    fn delete(&mut self, state: &mut dyn DeleteState, store: &dyn MailboxStore, name: &str);
    /// RENAME.
    fn rename(
        &mut self,
        state: &mut dyn RenameState,
        store: &dyn MailboxStore,
        old: &str,
        new: &str,
    );
    /// SUBSCRIBE.
    fn subscribe(&mut self, state: &mut dyn SubscribeState, store: &dyn MailboxStore, name: &str);
    /// UNSUBSCRIBE.
    fn unsubscribe(&mut self, state: &mut dyn SubscribeState, store: &dyn MailboxStore, name: &str);
    /// LIST.
    fn list(
        &mut self,
        state: &mut dyn ListState,
        store: &dyn MailboxStore,
        reference: &str,
        pattern: &str,
    );
    /// LSUB.
    fn lsub(
        &mut self,
        state: &mut dyn ListState,
        store: &dyn MailboxStore,
        reference: &str,
        pattern: &str,
    );
    /// APPEND (before literal body).
    fn append(
        &mut self,
        state: &mut dyn AppendState,
        store: &dyn MailboxStore,
        name: &str,
        flags: &BTreeSet<Flag>,
        internal_date: Option<SystemTime>,
    );
    /// STATUS.
    fn status(
        &mut self,
        state: &mut dyn StatusState,
        store: &dyn MailboxStore,
        name: &str,
        items: &BTreeSet<StatusItem>,
    );
    /// GETQUOTA.
    fn get_quota(
        &mut self,
        state: &mut dyn QuotaState,
        quota: &dyn QuotaManager,
        store: &dyn MailboxStore,
        quota_root: &str,
    );
    /// GETQUOTAROOT.
    fn get_quota_root(
        &mut self,
        state: &mut dyn QuotaState,
        quota: &dyn QuotaManager,
        store: &dyn MailboxStore,
        mailbox: &str,
    );
    /// SETQUOTA.
    fn set_quota(
        &mut self,
        state: &mut dyn QuotaState,
        quota: &dyn QuotaManager,
        store: &dyn MailboxStore,
        quota_root: &str,
    );
}

/// SELECTED-state message commands (also inherits authenticated mailbox ops).
pub trait SelectedHandler: Send {
    /// SELECT (switch mailbox).
    fn select(&mut self, state: &mut dyn SelectState, store: &dyn MailboxStore, name: &str);
    /// EXAMINE.
    fn examine(&mut self, state: &mut dyn SelectState, store: &dyn MailboxStore, name: &str);
    /// CREATE.
    fn create(&mut self, state: &mut dyn CreateState, store: &dyn MailboxStore, name: &str);
    /// DELETE.
    fn delete(&mut self, state: &mut dyn DeleteState, store: &dyn MailboxStore, name: &str);
    /// RENAME.
    fn rename(
        &mut self,
        state: &mut dyn RenameState,
        store: &dyn MailboxStore,
        old: &str,
        new: &str,
    );
    /// SUBSCRIBE.
    fn subscribe(&mut self, state: &mut dyn SubscribeState, store: &dyn MailboxStore, name: &str);
    /// UNSUBSCRIBE.
    fn unsubscribe(&mut self, state: &mut dyn SubscribeState, store: &dyn MailboxStore, name: &str);
    /// LIST.
    fn list(
        &mut self,
        state: &mut dyn ListState,
        store: &dyn MailboxStore,
        reference: &str,
        pattern: &str,
    );
    /// LSUB.
    fn lsub(
        &mut self,
        state: &mut dyn ListState,
        store: &dyn MailboxStore,
        reference: &str,
        pattern: &str,
    );
    /// APPEND.
    fn append(
        &mut self,
        state: &mut dyn AppendState,
        store: &dyn MailboxStore,
        name: &str,
        flags: &BTreeSet<Flag>,
        internal_date: Option<SystemTime>,
    );
    /// STATUS.
    fn status(
        &mut self,
        state: &mut dyn StatusState,
        store: &dyn MailboxStore,
        name: &str,
        items: &BTreeSet<StatusItem>,
    );
    /// GETQUOTA.
    fn get_quota(
        &mut self,
        state: &mut dyn QuotaState,
        quota: &dyn QuotaManager,
        store: &dyn MailboxStore,
        quota_root: &str,
    );
    /// GETQUOTAROOT.
    fn get_quota_root(
        &mut self,
        state: &mut dyn QuotaState,
        quota: &dyn QuotaManager,
        store: &dyn MailboxStore,
        mailbox: &str,
    );
    /// SETQUOTA.
    fn set_quota(
        &mut self,
        state: &mut dyn QuotaState,
        quota: &dyn QuotaManager,
        store: &dyn MailboxStore,
        quota_root: &str,
    );
    /// CLOSE (expunge + deselect).
    fn close(&mut self, state: &mut dyn CloseState, mailbox: &dyn Mailbox);
    /// UNSELECT (deselect without expunge).
    fn unselect(&mut self, state: &mut dyn CloseState, mailbox: &dyn Mailbox);
    /// FETCH / UID FETCH.
    fn fetch(
        &mut self,
        state: &mut dyn FetchState,
        mailbox: &dyn Mailbox,
        messages: &MessageSet,
        items: &[FetchItem],
        by_uid: bool,
    );
    /// STORE / UID STORE.
    fn store(
        &mut self,
        state: &mut dyn StoreState,
        mailbox: &dyn Mailbox,
        messages: &MessageSet,
        action: StoreAction,
        flags: &BTreeSet<Flag>,
        keywords: &BTreeSet<String>,
        silent: bool,
        by_uid: bool,
    );
    /// SEARCH / UID SEARCH.
    fn search(
        &mut self,
        state: &mut dyn SearchState,
        mailbox: &dyn Mailbox,
        criteria: &SearchCriteria,
        by_uid: bool,
    );
    /// COPY / UID COPY.
    fn copy(
        &mut self,
        state: &mut dyn CopyState,
        mailbox: &dyn Mailbox,
        messages: &MessageSet,
        destination: &str,
        by_uid: bool,
    );
    /// MOVE / UID MOVE.
    fn move_messages(
        &mut self,
        state: &mut dyn MoveState,
        mailbox: &dyn Mailbox,
        messages: &MessageSet,
        destination: &str,
        by_uid: bool,
    );
    /// EXPUNGE.
    fn expunge(&mut self, state: &mut dyn ExpungeState, mailbox: &dyn Mailbox);
    /// UID EXPUNGE.
    fn uid_expunge(
        &mut self,
        state: &mut dyn ExpungeState,
        mailbox: &dyn Mailbox,
        messages: &MessageSet,
    );
}
