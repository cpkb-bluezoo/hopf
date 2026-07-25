// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Default POP3 handler using the Mailbox API.

use std::net::SocketAddr;
use std::sync::Arc;

use hopf_mailbox::{Mailbox, MailboxFactory};

use super::{
    AuthenticateState, AuthorizationHandler, ClientConnected, ConnectedState, ListState,
    MailboxStatusState, MarkDeletedState, Pop3HandlerFactory, ResetState, RetrieveState,
    TopState, TransactionHandler, UidlState, UpdateState,
};

/// Factory for [`DefaultPop3Handler`].
pub struct DefaultPop3HandlerFactory {
    greeting: Arc<str>,
}

impl DefaultPop3HandlerFactory {
    /// Create with a greeting banner (without `+OK` prefix).
    pub fn new(greeting: impl Into<String>) -> Self {
        Self {
            greeting: greeting.into().into(),
        }
    }
}

impl Pop3HandlerFactory for DefaultPop3HandlerFactory {
    fn create(&self) -> Box<dyn ClientConnected> {
        Box::new(DefaultPop3Handler {
            greeting: Arc::clone(&self.greeting),
        })
    }
}

/// Accepts all connections and performs mailbox ops via the Mailbox SPI.
///
/// Opening/closing the mailbox and RETR/TOP disk I/O are delegated to the
/// protocol via `proceed_*` so they run on the storage pool.
#[derive(Clone)]
pub struct DefaultPop3Handler {
    greeting: Arc<str>,
}

impl ClientConnected for DefaultPop3Handler {
    fn connected(
        &mut self,
        state: &mut dyn ConnectedState,
        _peer: SocketAddr,
        _local: SocketAddr,
        _tls: bool,
    ) {
        state.accept_connection(&self.greeting, Box::new(self.clone()));
    }

    fn disconnected(&mut self) {}
}

impl AuthorizationHandler for DefaultPop3Handler {
    fn authenticate(
        &mut self,
        state: &mut dyn AuthenticateState,
        _username: &str,
        _factory: &dyn MailboxFactory,
    ) {
        state.proceed_open(Box::new(self.clone()));
    }
}

impl TransactionHandler for DefaultPop3Handler {
    fn mailbox_status(&mut self, state: &mut dyn MailboxStatusState, mailbox: &dyn Mailbox) {
        match (
            mailbox.undeleted_message_count(),
            mailbox.undeleted_mailbox_size(),
        ) {
            (Ok(count), Ok(size)) => state.send_status(count, size, Box::new(self.clone())),
            (Err(e), _) | (_, Err(e)) => {
                state.error(&format!("Unable to get mailbox status: {e}"), Box::new(self.clone()))
            }
        }
    }

    fn list(&mut self, state: &mut dyn ListState, mailbox: &dyn Mailbox, message_number: u32) {
        if message_number > 0 {
            match mailbox.is_deleted(message_number) {
                Ok(true) => {
                    state.message_deleted(Box::new(self.clone()));
                    return;
                }
                Err(_) => {
                    state.no_such_message(Box::new(self.clone()));
                    return;
                }
                Ok(false) => {}
            }
            match mailbox.messages() {
                Ok(msgs) => {
                    if let Some(m) = msgs.iter().find(|m| m.message_number == message_number) {
                        state.send_listing(m.message_number, m.size, Box::new(self.clone()));
                    } else {
                        state.no_such_message(Box::new(self.clone()));
                    }
                }
                Err(e) => state.error(&format!("Unable to list messages: {e}"), Box::new(self.clone())),
            }
            return;
        }

        match mailbox.messages() {
            Ok(msgs) => {
                let visible: Vec<_> = msgs
                    .into_iter()
                    .filter(|m| !mailbox.is_deleted(m.message_number).unwrap_or(true))
                    .collect();
                let mut writer = state.begin_listing(visible.len() as u32);
                for m in &visible {
                    writer.message(m.message_number, m.size);
                }
                writer.end(Box::new(self.clone()));
            }
            Err(e) => state.error(&format!("Unable to list messages: {e}"), Box::new(self.clone())),
        }
    }

    fn retrieve_message(
        &mut self,
        state: &mut dyn RetrieveState,
        mailbox: &dyn Mailbox,
        message_number: u32,
    ) {
        match mailbox.is_deleted(message_number) {
            Ok(true) => {
                state.message_deleted(Box::new(self.clone()));
                return;
            }
            Err(_) => {
                state.no_such_message(Box::new(self.clone()));
                return;
            }
            Ok(false) => {}
        }
        match mailbox.messages() {
            Ok(msgs) => {
                if let Some(m) = msgs.iter().find(|m| m.message_number == message_number) {
                    state.proceed_retr(m.size, Box::new(self.clone()));
                } else {
                    state.no_such_message(Box::new(self.clone()));
                }
            }
            Err(e) => {
                state.error(&format!("Unable to retrieve message: {e}"), Box::new(self.clone()))
            }
        }
    }

    fn mark_deleted(
        &mut self,
        state: &mut dyn MarkDeletedState,
        mailbox: &mut dyn Mailbox,
        message_number: u32,
    ) {
        match mailbox.is_deleted(message_number) {
            Ok(true) => {
                state.already_deleted(Box::new(self.clone()));
                return;
            }
            Err(_) => {
                state.no_such_message(Box::new(self.clone()));
                return;
            }
            Ok(false) => {}
        }
        match mailbox.mark_deleted(message_number) {
            Ok(()) => state.marked_deleted(Box::new(self.clone())),
            Err(e) => {
                state.error(&format!("Unable to delete message: {e}"), Box::new(self.clone()))
            }
        }
    }

    fn reset(&mut self, state: &mut dyn ResetState, mailbox: &mut dyn Mailbox) {
        if let Err(e) = mailbox.undelete_all() {
            state.error(&format!("Unable to reset mailbox: {e}"), Box::new(self.clone()));
            return;
        }
        match (
            mailbox.undeleted_message_count(),
            mailbox.undeleted_mailbox_size(),
        ) {
            (Ok(count), Ok(size)) => state.reset_complete(count, size, Box::new(self.clone())),
            (Err(e), _) | (_, Err(e)) => {
                state.error(&format!("Unable to reset mailbox: {e}"), Box::new(self.clone()))
            }
        }
    }

    fn top(
        &mut self,
        state: &mut dyn TopState,
        mailbox: &dyn Mailbox,
        message_number: u32,
        lines: u32,
    ) {
        match mailbox.is_deleted(message_number) {
            Ok(true) => {
                state.message_deleted(Box::new(self.clone()));
                return;
            }
            Err(_) => {
                state.no_such_message(Box::new(self.clone()));
                return;
            }
            Ok(false) => {}
        }
        match mailbox.messages() {
            Ok(msgs) if msgs.iter().any(|m| m.message_number == message_number) => {
                state.proceed_top(lines, Box::new(self.clone()));
            }
            Ok(_) => state.no_such_message(Box::new(self.clone())),
            Err(e) => state.error(&format!("Unable to get TOP: {e}"), Box::new(self.clone())),
        }
    }

    fn uidl(&mut self, state: &mut dyn UidlState, mailbox: &dyn Mailbox, message_number: u32) {
        if message_number > 0 {
            match mailbox.is_deleted(message_number) {
                Ok(true) => {
                    state.message_deleted(Box::new(self.clone()));
                    return;
                }
                Err(_) => {
                    state.no_such_message(Box::new(self.clone()));
                    return;
                }
                Ok(false) => {}
            }
            match mailbox.unique_id(message_number) {
                Ok(uid) => state.send_uid(message_number, &uid, Box::new(self.clone())),
                Err(_) => state.no_such_message(Box::new(self.clone())),
            }
            return;
        }

        match mailbox.messages() {
            Ok(msgs) => {
                let mut writer = state.begin_listing();
                for m in &msgs {
                    if mailbox.is_deleted(m.message_number).unwrap_or(true) {
                        continue;
                    }
                    match mailbox.unique_id(m.message_number) {
                        Ok(uid) => writer.message(m.message_number, &uid),
                        Err(_) => continue,
                    }
                }
                writer.end(Box::new(self.clone()));
            }
            Err(e) => state.error(&format!("Unable to get unique identifiers: {e}"), Box::new(self.clone())),
        }
    }

    fn quit(&mut self, state: &mut dyn UpdateState, _mailbox: &dyn Mailbox) {
        state.proceed_quit(Box::new(self.clone()));
    }
}
