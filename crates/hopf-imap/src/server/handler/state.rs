// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Accept/reject state traits for each IMAP stage.

use std::collections::BTreeSet;
use std::time::SystemTime;

use hopf_mailbox::{Flag, MailboxInfo, MailboxStore};

use super::{AuthenticatedHandler, NotAuthenticatedHandler, SelectedHandler};
use crate::server::fetch_format::FetchItem;
use crate::server::status_items::StatusItem;

/// STORE flag operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreAction {
    /// `FLAGS` — replace.
    Replace,
    /// `+FLAGS` — add.
    Add,
    /// `-FLAGS` — remove.
    Remove,
}

/// Operations right after connect.
pub trait ConnectedState {
    /// Accept with greeting text; transition to not-authenticated.
    fn accept_connection(&mut self, greeting: &str, handler: Box<dyn NotAuthenticatedHandler>);
    /// Reject and close.
    fn reject_connection(&mut self, message: &str);
}

/// After CredentialStore verified credentials.
pub trait AuthenticateState {
    /// Authorise; protocol opens the store on the storage pool.
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>);
    /// Accept with an already-opened store.
    fn accept_opened(
        &mut self,
        store: Box<dyn MailboxStore>,
        handler: Box<dyn AuthenticatedHandler>,
    );
    /// Reject access despite valid credentials.
    fn reject(&mut self, message: &str, handler: Box<dyn NotAuthenticatedHandler>);
}

/// SELECT / EXAMINE.
pub trait SelectState {
    /// Protocol opens the mailbox on the storage pool.
    fn proceed(&mut self, handler: Box<dyn SelectedHandler>);
    /// Select failed.
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>);
}

/// CREATE.
pub trait CreateState {
    /// Protocol creates the mailbox on the storage pool.
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>);
    /// Create failed.
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>);
}

/// DELETE.
pub trait DeleteState {
    /// Protocol deletes the mailbox on the storage pool.
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>);
    /// Delete failed.
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>);
}

/// RENAME.
pub trait RenameState {
    /// Protocol renames on the storage pool.
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>);
    /// Rename failed.
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>);
}

/// SUBSCRIBE / UNSUBSCRIBE.
pub trait SubscribeState {
    /// Protocol updates subscription on the storage pool.
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>);
    /// Failed.
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>);
}

/// LIST / LSUB writer.
pub trait ListState {
    /// Protocol lists on the storage pool (`subscribed` selects LSUB).
    fn proceed(&mut self, subscribed: bool, handler: Box<dyn AuthenticatedHandler>);
    /// Emit a listing immediately (advanced).
    fn send_list(&mut self, infos: &[MailboxInfo], handler: Box<dyn AuthenticatedHandler>);
    /// Failed.
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>);
}

/// APPEND.
pub trait AppendState {
    /// Protocol accepts the message literal then appends on the storage pool.
    fn proceed(
        &mut self,
        flags: BTreeSet<Flag>,
        internal_date: Option<SystemTime>,
        handler: Box<dyn AuthenticatedHandler>,
    );
    /// Append not allowed.
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>);
}

/// CLOSE / UNSELECT.
pub trait CloseState {
    /// Protocol closes on the storage pool (`expunge` for CLOSE).
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>);
    /// Failed.
    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>);
}

/// STATUS.
pub trait StatusState {
    /// Protocol runs STATUS on the storage pool for the requested items.
    fn proceed(&mut self, items: BTreeSet<StatusItem>, handler: Box<dyn AuthenticatedHandler>);
    /// Failed.
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>);
}

/// QUOTA / GETQUOTA / GETQUOTAROOT / SETQUOTA.
pub trait QuotaState {
    /// Protocol performs the quota operation.
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>);
    /// Quota not supported / denied.
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>);
}

/// FETCH.
pub trait FetchState {
    /// Protocol performs FETCH on the storage pool.
    fn proceed(&mut self, items: Vec<FetchItem>, by_uid: bool, handler: Box<dyn SelectedHandler>);
    /// Failed.
    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>);
}

/// STORE.
pub trait StoreState {
    /// Protocol performs STORE on the storage pool.
    fn proceed(
        &mut self,
        action: StoreAction,
        flags: BTreeSet<Flag>,
        keywords: BTreeSet<String>,
        silent: bool,
        by_uid: bool,
        handler: Box<dyn SelectedHandler>,
    );
    /// Failed.
    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>);
}

/// SEARCH.
pub trait SearchState {
    /// Protocol performs SEARCH on the storage pool.
    fn proceed(&mut self, by_uid: bool, handler: Box<dyn SelectedHandler>);
    /// Failed.
    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>);
}

/// COPY.
pub trait CopyState {
    /// Protocol performs COPY on the storage pool.
    fn proceed(&mut self, by_uid: bool, handler: Box<dyn SelectedHandler>);
    /// Failed.
    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>);
}

/// MOVE (RFC 6851).
pub trait MoveState {
    /// Protocol performs MOVE (copy + delete + expunge) on the storage pool.
    fn proceed(&mut self, by_uid: bool, handler: Box<dyn SelectedHandler>);
    /// Failed.
    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>);
}

/// EXPUNGE / UID EXPUNGE.
pub trait ExpungeState {
    /// Protocol performs EXPUNGE on the storage pool.
    fn proceed(&mut self, handler: Box<dyn SelectedHandler>);
    /// Failed.
    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>);
}
