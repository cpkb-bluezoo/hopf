// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`LocalDeliveryHandler`] — buffer message, APPEND to each recipient INBOX.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Runtime, StorageError};
use hopf_mailbox::{Flag, MailboxFactory};
use rmimeparser::EmailAddress;

use crate::server::delivery::{DeliveryRequirements, DsnRecipientParams};
use crate::server::handler::{
    AuthenticateState, ConnectedState, HelloHandler, HelloState, MailFromHandler, MailFromState,
    MessageDataHandler, MessageEndState, MessageStartState, RecipientHandler, RecipientState,
    ResetState, SmtpClientConnected, SmtpConnectionMetadata, SmtpHandlerFactory,
};
use crate::server::pipeline::SmtpPipeline;
use crate::server::relay::MessageBufferPipeline;

/// Factory for [`LocalDeliveryHandler`].
pub struct LocalDeliveryHandlerFactory {
    mailbox_factory: Arc<dyn MailboxFactory>,
    runtime: Arc<Runtime>,
    local_domain: String,
    hostname: String,
}

impl LocalDeliveryHandlerFactory {
    /// Create a factory.
    pub fn new(
        mailbox_factory: Arc<dyn MailboxFactory>,
        runtime: Arc<Runtime>,
        local_domain: impl Into<String>,
        hostname: impl Into<String>,
    ) -> Self {
        let local_domain = local_domain.into();
        assert!(!local_domain.is_empty(), "local_domain must not be empty");
        Self {
            mailbox_factory,
            runtime,
            local_domain: local_domain.to_ascii_lowercase(),
            hostname: hostname.into(),
        }
    }
}

impl SmtpHandlerFactory for LocalDeliveryHandlerFactory {
    fn create(&self) -> Box<dyn SmtpClientConnected> {
        Box::new(LocalDeliveryHandler {
            mailbox_factory: Arc::clone(&self.mailbox_factory),
            runtime: Arc::clone(&self.runtime),
            local_domain: self.local_domain.clone(),
            hostname: self.hostname.clone(),
            control_handle: None,
            sender: None,
            recipients: Vec::new(),
            pipeline: None,
        })
    }
}

/// Gumdrop-style local delivery: domain check at RCPT TO, APPEND to INBOX.
#[derive(Clone)]
pub struct LocalDeliveryHandler {
    mailbox_factory: Arc<dyn MailboxFactory>,
    runtime: Arc<Runtime>,
    local_domain: String,
    hostname: String,
    control_handle: Option<ConnHandle>,
    sender: Option<EmailAddress>,
    /// Local-parts of accepted recipients (mailbox usernames).
    recipients: Vec<String>,
    pipeline: Option<Arc<Mutex<MessageBufferPipeline>>>,
}

impl LocalDeliveryHandler {
    fn reset_transaction(&mut self) {
        self.sender = None;
        self.recipients.clear();
        self.pipeline = None;
    }
}

impl SmtpClientConnected for LocalDeliveryHandler {
    fn connected(&mut self, state: &mut dyn ConnectedState, meta: &SmtpConnectionMetadata) {
        self.control_handle = meta.control_handle.clone();
        let greeting = format!("{} ESMTP Service ready", self.hostname);
        state.accept_connection(&greeting, Box::new(self.clone()));
    }

    fn disconnected(&mut self) {
        self.reset_transaction();
        self.control_handle = None;
    }
}

impl HelloHandler for LocalDeliveryHandler {
    fn hello(&mut self, state: &mut dyn HelloState, _extended: bool, _hostname: &str) {
        state.accept_hello(Box::new(self.clone()));
    }

    fn tls_established(&mut self) {}

    fn authenticated(&mut self, state: &mut dyn AuthenticateState, _user: &str) {
        state.accept(Box::new(self.clone()));
    }

    fn quit(&mut self) {
        self.reset_transaction();
    }
}

impl MailFromHandler for LocalDeliveryHandler {
    fn pipeline(&mut self) -> Option<Box<dyn SmtpPipeline>> {
        let p = Arc::new(Mutex::new(MessageBufferPipeline::new()));
        self.pipeline = Some(Arc::clone(&p));
        Some(Box::new(PipelineHandle(p)))
    }

    fn mail_from(
        &mut self,
        state: &mut dyn MailFromState,
        sender: Option<&EmailAddress>,
        _smtputf8: bool,
        delivery: &DeliveryRequirements,
    ) {
        self.sender = sender.cloned();
        self.recipients.clear();

        if delivery.is_future_release() {
            state.reject_sender_policy(
                "FUTURERELEASE not supported by local delivery",
                Box::new(self.clone()),
            );
            return;
        }

        state.accept_sender(Box::new(self.clone()));
    }

    fn reset(&mut self, state: &mut dyn ResetState) {
        self.reset_transaction();
        state.accept_reset(Box::new(self.clone()));
    }

    fn quit(&mut self) {
        self.reset_transaction();
    }
}

impl RecipientHandler for LocalDeliveryHandler {
    fn rcpt_to(
        &mut self,
        state: &mut dyn RecipientState,
        recipient: &EmailAddress,
        _dsn: &DsnRecipientParams,
    ) {
        let Some(username) = local_recipient_username(
            recipient.local_part(),
            recipient.domain(),
            &self.local_domain,
        ) else {
            state.reject_recipient_relay_denied(Box::new(self.clone()));
            return;
        };
        self.recipients.push(username);
        state.accept_recipient(Box::new(self.clone()));
    }

    fn start_message(&mut self, state: &mut dyn MessageStartState) {
        if self.recipients.is_empty() {
            state.reject_message("No recipients", Box::new(self.clone()));
            return;
        }
        // 354 must be synchronous (pipelining); mailbox I/O waits until
        // message_complete, then runs on the storage pool.
        state.accept_message(Box::new(self.clone()));
    }

    fn reset(&mut self, state: &mut dyn ResetState) {
        self.reset_transaction();
        state.accept_reset(Box::new(self.clone()));
    }

    fn quit(&mut self) {
        self.reset_transaction();
    }
}

impl MessageDataHandler for LocalDeliveryHandler {
    fn message_content(&mut self, chunk: &[u8]) {
        if let Some(p) = &self.pipeline {
            p.lock().unwrap().message_content(chunk);
        }
    }

    fn message_complete(&mut self, state: &mut dyn MessageEndState) {
        let message = self
            .pipeline
            .as_ref()
            .map(|p| p.lock().unwrap().message_data().to_vec())
            .unwrap_or_default();
        let recipients = self.recipients.clone();
        let factory = Arc::clone(&self.mailbox_factory);
        let storage = Arc::clone(self.runtime.storage());
        let handle = self
            .control_handle
            .clone()
            .expect("control handle set in connected()");
        let deferred = state.defer(Box::new(self.clone()));
        self.reset_transaction();

        storage.submit_on(
            handle,
            move || deliver_buffered(factory.as_ref(), &recipients, &message),
            move |result: Result<Option<String>, StorageError>| match result {
                Ok(None) => deferred.accept(None),
                Ok(Some(msg)) => deferred.reject_temporary(&msg),
                Err(e) => deferred.reject_temporary(&e.to_string()),
            },
        );
    }

    fn message_aborted(&mut self) {
        self.reset_transaction();
    }
}

fn local_recipient_username(
    local_part: &str,
    recipient_domain: &str,
    local_domain: &str,
) -> Option<String> {
    if recipient_domain.eq_ignore_ascii_case(local_domain) {
        Some(local_part.to_string())
    } else {
        None
    }
}

/// Deliver to every recipient; return `None` on full success, or the first
/// error message (other recipients are still attempted).
fn deliver_buffered(
    factory: &dyn MailboxFactory,
    recipients: &[String],
    message: &[u8],
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let flags = BTreeSet::<Flag>::new();
    Ok(deliver_recipients(recipients, |username| {
        deliver_to_mailbox(factory, username, message, &flags)
    }))
}

fn deliver_recipients<E, F>(recipients: &[String], mut deliver: F) -> Option<String>
where
    E: std::fmt::Display,
    F: FnMut(&str) -> Result<(), E>,
{
    let mut first_error: Option<String> = None;
    for username in recipients {
        match deliver(username) {
            Ok(()) => {}
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e.to_string());
                }
            }
        }
    }
    first_error
}

fn deliver_to_mailbox(
    factory: &dyn MailboxFactory,
    username: &str,
    message: &[u8],
    flags: &BTreeSet<Flag>,
) -> hopf_mailbox::MailboxResult<()> {
    let mut store = factory.create_store();
    store.open(username)?;
    let mut mb = store.open_mailbox("INBOX", false)?;
    mb.append_message(message, flags, None)?;
    mb.close(false)?;
    store.close()?;
    Ok(())
}

struct PipelineHandle(Arc<Mutex<MessageBufferPipeline>>);

impl SmtpPipeline for PipelineHandle {
    fn mail_from(&mut self, sender: Option<&EmailAddress>) {
        self.0.lock().unwrap().mail_from(sender);
    }
    fn rcpt_to(&mut self, recipient: &EmailAddress) {
        self.0.lock().unwrap().rcpt_to(recipient);
    }
    fn message_content(&mut self, chunk: &[u8]) {
        self.0.lock().unwrap().message_content(chunk);
    }
    fn end_data(&mut self) {
        self.0.lock().unwrap().end_data();
    }
    fn reset(&mut self) {
        self.0.lock().unwrap().reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_recipient_matches_domain_case_insensitively() {
        assert_eq!(
            local_recipient_username("alice", "MAIL.Example", "mail.example"),
            Some("alice".to_string())
        );
        assert_eq!(
            local_recipient_username("alice", "other.example", "mail.example"),
            None
        );
    }

    #[test]
    fn delivery_attempts_every_recipient() {
        let recipients = vec!["alice".to_string(), "bob".to_string()];
        let mut visited = Vec::new();

        assert_eq!(
            deliver_recipients(&recipients, |username| {
                visited.push(username.to_string());
                Ok::<_, &'static str>(())
            }),
            None
        );
        assert_eq!(visited, recipients);
    }

    #[test]
    fn delivery_reports_first_failure_but_attempts_later_recipients() {
        let recipients = vec![
            "bad-one".to_string(),
            "good".to_string(),
            "bad-two".to_string(),
        ];
        let mut visited = Vec::new();

        let error = deliver_recipients(&recipients, |username| {
            visited.push(username.to_string());
            match username {
                "bad-one" => Err("first failure"),
                "bad-two" => Err("second failure"),
                _ => Ok(()),
            }
        });
        assert_eq!(error.as_deref(), Some("first failure"));
        assert_eq!(visited, recipients);
    }

    #[test]
    fn message_pipeline_buffers_and_resets_content() {
        let mut pipeline = MessageBufferPipeline::new();
        pipeline.message_content(b"one");
        pipeline.message_content(b"-two");
        assert_eq!(pipeline.message_data(), b"one-two");
        pipeline.reset();
        assert!(pipeline.message_data().is_empty());
    }
}
