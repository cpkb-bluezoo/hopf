// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Stock accept-all handler (integration / smoke tests).

use std::sync::{Arc, Mutex};

use rmimeparser::EmailAddress;

use crate::delivery::{DeliveryRequirements, DsnRecipientParams};
use crate::pipeline::SmtpPipeline;

use super::{
    AuthenticateState, ConnectedState, HelloHandler, HelloState, MailFromHandler, MailFromState,
    MessageDataHandler, MessageEndState, MessageStartState, RecipientHandler, RecipientState,
    ResetState, SmtpClientConnected, SmtpConnectionMetadata, SmtpHandlerFactory,
};

/// Accepts every stage; optionally captures message bytes.
#[derive(Clone)]
pub struct AcceptAllSmtpHandler {
    hostname: String,
    capture: Option<Arc<Mutex<Vec<u8>>>>,
}

impl AcceptAllSmtpHandler {
    /// Greeting hostname (e.g. `mail.example.com`).
    pub fn new(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            capture: None,
        }
    }

    /// Accumulate message bytes into the shared buffer (for tests).
    pub fn with_capture(mut self, capture: Arc<Mutex<Vec<u8>>>) -> Self {
        self.capture = Some(capture);
        self
    }
}

impl SmtpClientConnected for AcceptAllSmtpHandler {
    fn connected(&mut self, state: &mut dyn ConnectedState, _meta: &SmtpConnectionMetadata) {
        let greeting = format!("{} ESMTP Hopf", self.hostname);
        state.accept_connection(&greeting, Box::new(self.clone()));
    }

    fn disconnected(&mut self) {}
}

impl HelloHandler for AcceptAllSmtpHandler {
    fn hello(&mut self, state: &mut dyn HelloState, _extended: bool, _hostname: &str) {
        state.accept_hello(Box::new(self.clone()));
    }

    fn tls_established(&mut self) {}

    fn authenticated(&mut self, state: &mut dyn AuthenticateState, _user: &str) {
        state.accept(Box::new(self.clone()));
    }

    fn quit(&mut self) {}
}

impl MailFromHandler for AcceptAllSmtpHandler {
    fn pipeline(&mut self) -> Option<Box<dyn SmtpPipeline>> {
        None
    }

    fn mail_from(
        &mut self,
        state: &mut dyn MailFromState,
        _sender: Option<&EmailAddress>,
        _smtputf8: bool,
        _delivery: &DeliveryRequirements,
    ) {
        state.accept_sender(Box::new(self.clone()));
    }

    fn reset(&mut self, state: &mut dyn ResetState) {
        state.accept_reset(Box::new(self.clone()));
    }

    fn quit(&mut self) {}
}

impl RecipientHandler for AcceptAllSmtpHandler {
    fn rcpt_to(
        &mut self,
        state: &mut dyn RecipientState,
        _recipient: &EmailAddress,
        _dsn: &DsnRecipientParams,
    ) {
        state.accept_recipient(Box::new(self.clone()));
    }

    fn start_message(&mut self, state: &mut dyn MessageStartState) {
        state.accept_message(Box::new(self.clone()));
    }

    fn reset(&mut self, state: &mut dyn ResetState) {
        state.accept_reset(Box::new(self.clone()));
    }

    fn quit(&mut self) {}
}

impl MessageDataHandler for AcceptAllSmtpHandler {
    fn message_content(&mut self, chunk: &[u8]) {
        if let Some(cap) = &self.capture {
            if let Ok(mut g) = cap.lock() {
                g.extend_from_slice(chunk);
            }
        }
    }

    fn message_complete(&mut self, state: &mut dyn MessageEndState) {
        state.accept_message_delivery(None, Box::new(self.clone()));
    }

    fn message_aborted(&mut self) {
        if let Some(cap) = &self.capture {
            if let Ok(mut g) = cap.lock() {
                g.clear();
            }
        }
    }
}

/// Factory that clones an [`AcceptAllSmtpHandler`] per connection.
#[derive(Clone)]
pub struct AcceptAllSmtpHandlerFactory {
    inner: AcceptAllSmtpHandler,
}

impl AcceptAllSmtpHandlerFactory {
    /// Create from a template handler.
    pub fn new(handler: AcceptAllSmtpHandler) -> Self {
        Self { inner: handler }
    }
}

impl SmtpHandlerFactory for AcceptAllSmtpHandlerFactory {
    fn create(&self) -> Box<dyn SmtpClientConnected> {
        Box::new(self.inner.clone())
    }
}
