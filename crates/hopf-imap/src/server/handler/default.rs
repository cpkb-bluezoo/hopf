// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Default IMAP handler that authorises every request via `proceed`.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use hopf_mailbox::{Flag, Mailbox, MailboxFactory, MailboxStore, MessageSet, SearchCriteria};

use super::{
    AppendState, AuthenticateState, AuthenticatedHandler, ClientConnected, CloseState,
    ConnectedState, CopyState, CreateState, DeleteState, ExpungeState, FetchState,
    ImapHandlerFactory, ListState, MoveState, NotAuthenticatedHandler, QuotaState, RenameState,
    SearchState, SelectState, SelectedHandler, StatusState, StoreAction, StoreState,
    SubscribeState,
};
use crate::server::fetch_format::FetchItem;
use crate::server::quota::QuotaManager;
use crate::server::status_items::StatusItem;

/// Factory for [`DefaultImapHandler`].
pub struct DefaultImapHandlerFactory {
    greeting: Arc<str>,
    preauth_username: Option<Arc<str>>,
}

impl DefaultImapHandlerFactory {
    /// Create with greeting banner text (without untagged OK / PREAUTH prefix).
    pub fn new(greeting: impl Into<String>) -> Self {
        Self {
            greeting: greeting.into().into(),
            preauth_username: None,
        }
    }

    /// When set, connections are greeted with PREAUTH for this user.
    pub fn with_preauth(mut self, username: Option<String>) -> Self {
        self.preauth_username = username.map(|u| Arc::<str>::from(u));
        self
    }
}

impl ImapHandlerFactory for DefaultImapHandlerFactory {
    fn create(&self) -> Box<dyn ClientConnected> {
        Box::new(DefaultImapHandler {
            greeting: Arc::clone(&self.greeting),
            preauth_username: self.preauth_username.clone(),
        })
    }
}

/// Accepts all connections and defers mailbox I/O to the protocol via `proceed`.
#[derive(Clone)]
pub struct DefaultImapHandler {
    greeting: Arc<str>,
    preauth_username: Option<Arc<str>>,
}

impl ClientConnected for DefaultImapHandler {
    fn connected(
        &mut self,
        state: &mut dyn ConnectedState,
        _peer: SocketAddr,
        _local: SocketAddr,
        _tls: bool,
    ) {
        if let Some(user) = self.preauth_username.as_deref() {
            state.accept_preauth(&self.greeting, user, Box::new(self.clone()));
        } else {
            state.accept_connection(&self.greeting, Box::new(self.clone()));
        }
    }

    fn disconnected(&mut self) {}
}

impl NotAuthenticatedHandler for DefaultImapHandler {
    fn authenticate(
        &mut self,
        state: &mut dyn AuthenticateState,
        _username: &str,
        _factory: &dyn MailboxFactory,
    ) {
        state.proceed(Box::new(self.clone()));
    }
}

macro_rules! auth_mailbox_impl {
    ($self:ident) => {
        fn select(&mut self, state: &mut dyn SelectState, _store: &dyn MailboxStore, _name: &str) {
            state.proceed(Box::new(self.clone()));
        }

        fn examine(&mut self, state: &mut dyn SelectState, _store: &dyn MailboxStore, _name: &str) {
            state.proceed(Box::new(self.clone()));
        }

        fn create(&mut self, state: &mut dyn CreateState, _store: &dyn MailboxStore, _name: &str) {
            state.proceed(Box::new(self.clone()));
        }

        fn delete(&mut self, state: &mut dyn DeleteState, _store: &dyn MailboxStore, _name: &str) {
            state.proceed(Box::new(self.clone()));
        }

        fn rename(
            &mut self,
            state: &mut dyn RenameState,
            _store: &dyn MailboxStore,
            _old: &str,
            _new: &str,
        ) {
            state.proceed(Box::new(self.clone()));
        }

        fn subscribe(
            &mut self,
            state: &mut dyn SubscribeState,
            _store: &dyn MailboxStore,
            _name: &str,
        ) {
            state.proceed(Box::new(self.clone()));
        }

        fn unsubscribe(
            &mut self,
            state: &mut dyn SubscribeState,
            _store: &dyn MailboxStore,
            _name: &str,
        ) {
            state.proceed(Box::new(self.clone()));
        }

        fn list(
            &mut self,
            state: &mut dyn ListState,
            _store: &dyn MailboxStore,
            _reference: &str,
            _pattern: &str,
        ) {
            state.proceed(false, Box::new(self.clone()));
        }

        fn lsub(
            &mut self,
            state: &mut dyn ListState,
            _store: &dyn MailboxStore,
            _reference: &str,
            _pattern: &str,
        ) {
            state.proceed(true, Box::new(self.clone()));
        }

        fn append(
            &mut self,
            state: &mut dyn AppendState,
            _store: &dyn MailboxStore,
            _name: &str,
            flags: &BTreeSet<Flag>,
            internal_date: Option<SystemTime>,
        ) {
            state.proceed(flags.clone(), internal_date, Box::new(self.clone()));
        }

        fn status(
            &mut self,
            state: &mut dyn StatusState,
            _store: &dyn MailboxStore,
            _name: &str,
            items: &BTreeSet<StatusItem>,
        ) {
            state.proceed(items.clone(), Box::new(self.clone()));
        }

        fn get_quota(
            &mut self,
            state: &mut dyn QuotaState,
            _quota: &dyn QuotaManager,
            _store: &dyn MailboxStore,
            _quota_root: &str,
        ) {
            state.proceed(Box::new(self.clone()));
        }

        fn get_quota_root(
            &mut self,
            state: &mut dyn QuotaState,
            _quota: &dyn QuotaManager,
            _store: &dyn MailboxStore,
            _mailbox: &str,
        ) {
            state.proceed(Box::new(self.clone()));
        }

        fn set_quota(
            &mut self,
            state: &mut dyn QuotaState,
            _quota: &dyn QuotaManager,
            _store: &dyn MailboxStore,
            _quota_root: &str,
        ) {
            state.proceed(Box::new(self.clone()));
        }
    };
}

impl AuthenticatedHandler for DefaultImapHandler {
    auth_mailbox_impl!(self);
}

impl SelectedHandler for DefaultImapHandler {
    fn select(&mut self, state: &mut dyn SelectState, store: &dyn MailboxStore, name: &str) {
        AuthenticatedHandler::select(self, state, store, name);
    }

    fn examine(&mut self, state: &mut dyn SelectState, store: &dyn MailboxStore, name: &str) {
        AuthenticatedHandler::examine(self, state, store, name);
    }

    fn create(&mut self, state: &mut dyn CreateState, store: &dyn MailboxStore, name: &str) {
        AuthenticatedHandler::create(self, state, store, name);
    }

    fn delete(&mut self, state: &mut dyn DeleteState, store: &dyn MailboxStore, name: &str) {
        AuthenticatedHandler::delete(self, state, store, name);
    }

    fn rename(
        &mut self,
        state: &mut dyn RenameState,
        store: &dyn MailboxStore,
        old: &str,
        new: &str,
    ) {
        AuthenticatedHandler::rename(self, state, store, old, new);
    }

    fn subscribe(&mut self, state: &mut dyn SubscribeState, store: &dyn MailboxStore, name: &str) {
        AuthenticatedHandler::subscribe(self, state, store, name);
    }

    fn unsubscribe(
        &mut self,
        state: &mut dyn SubscribeState,
        store: &dyn MailboxStore,
        name: &str,
    ) {
        AuthenticatedHandler::unsubscribe(self, state, store, name);
    }

    fn list(
        &mut self,
        state: &mut dyn ListState,
        store: &dyn MailboxStore,
        reference: &str,
        pattern: &str,
    ) {
        AuthenticatedHandler::list(self, state, store, reference, pattern);
    }

    fn lsub(
        &mut self,
        state: &mut dyn ListState,
        store: &dyn MailboxStore,
        reference: &str,
        pattern: &str,
    ) {
        AuthenticatedHandler::lsub(self, state, store, reference, pattern);
    }

    fn append(
        &mut self,
        state: &mut dyn AppendState,
        store: &dyn MailboxStore,
        name: &str,
        flags: &BTreeSet<Flag>,
        internal_date: Option<SystemTime>,
    ) {
        AuthenticatedHandler::append(self, state, store, name, flags, internal_date);
    }

    fn status(
        &mut self,
        state: &mut dyn StatusState,
        store: &dyn MailboxStore,
        name: &str,
        items: &BTreeSet<StatusItem>,
    ) {
        AuthenticatedHandler::status(self, state, store, name, items);
    }

    fn get_quota(
        &mut self,
        state: &mut dyn QuotaState,
        quota: &dyn QuotaManager,
        store: &dyn MailboxStore,
        quota_root: &str,
    ) {
        AuthenticatedHandler::get_quota(self, state, quota, store, quota_root);
    }

    fn get_quota_root(
        &mut self,
        state: &mut dyn QuotaState,
        quota: &dyn QuotaManager,
        store: &dyn MailboxStore,
        mailbox: &str,
    ) {
        AuthenticatedHandler::get_quota_root(self, state, quota, store, mailbox);
    }

    fn set_quota(
        &mut self,
        state: &mut dyn QuotaState,
        quota: &dyn QuotaManager,
        store: &dyn MailboxStore,
        quota_root: &str,
    ) {
        AuthenticatedHandler::set_quota(self, state, quota, store, quota_root);
    }

    fn close(&mut self, state: &mut dyn CloseState, _mailbox: &dyn Mailbox) {
        state.proceed(Box::new(self.clone()));
    }

    fn unselect(&mut self, state: &mut dyn CloseState, _mailbox: &dyn Mailbox) {
        state.proceed(Box::new(self.clone()));
    }

    fn fetch(
        &mut self,
        state: &mut dyn FetchState,
        _mailbox: &dyn Mailbox,
        _messages: &MessageSet,
        items: &[FetchItem],
        by_uid: bool,
    ) {
        state.proceed(items.to_vec(), by_uid, Box::new(self.clone()));
    }

    fn store(
        &mut self,
        state: &mut dyn StoreState,
        _mailbox: &dyn Mailbox,
        _messages: &MessageSet,
        action: StoreAction,
        flags: &BTreeSet<Flag>,
        keywords: &BTreeSet<String>,
        silent: bool,
        by_uid: bool,
    ) {
        state.proceed(
            action,
            flags.clone(),
            keywords.clone(),
            silent,
            by_uid,
            Box::new(self.clone()),
        );
    }

    fn search(
        &mut self,
        state: &mut dyn SearchState,
        _mailbox: &dyn Mailbox,
        _criteria: &SearchCriteria,
        by_uid: bool,
    ) {
        state.proceed(by_uid, Box::new(self.clone()));
    }

    fn copy(
        &mut self,
        state: &mut dyn CopyState,
        _mailbox: &dyn Mailbox,
        _messages: &MessageSet,
        _destination: &str,
        by_uid: bool,
    ) {
        state.proceed(by_uid, Box::new(self.clone()));
    }

    fn move_messages(
        &mut self,
        state: &mut dyn MoveState,
        _mailbox: &dyn Mailbox,
        _messages: &MessageSet,
        _destination: &str,
        by_uid: bool,
    ) {
        state.proceed(by_uid, Box::new(self.clone()));
    }

    fn expunge(&mut self, state: &mut dyn ExpungeState, _mailbox: &dyn Mailbox) {
        state.proceed(Box::new(self.clone()));
    }

    fn uid_expunge(
        &mut self,
        state: &mut dyn ExpungeState,
        _mailbox: &dyn Mailbox,
        _messages: &MessageSet,
    ) {
        state.proceed(Box::new(self.clone()));
    }
}
