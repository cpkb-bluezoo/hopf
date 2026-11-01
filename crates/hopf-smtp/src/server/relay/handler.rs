// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`SimpleRelayHandler`] - receives a message, puts it in the relay queue,
//! and accepts it; the [engine](super::engine) delivers it from there.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use hopf_core::{ConnHandle, Runtime, SharedTlsConnector, StorageError};
use hopf_dns::DnsResolver;
use rmimeparser::EmailAddress;

use crate::server::delivery::{DeliveryRequirements, DsnRecipientParams};
use crate::server::handler::{
    AuthenticateState, ConnectedState, HelloHandler, HelloState, MailFromHandler, MailFromState,
    MessageDataHandler, MessageEndState, MessageStartState, RecipientHandler, RecipientState,
    ResetState, SmtpClientConnected, SmtpConnectionMetadata, SmtpHandlerFactory,
};
use crate::server::pipeline::SmtpPipeline;
use crate::server::spool::{SpoolPipeline, SpoolPipelineHandle};

use super::engine::{RelayEngine, RelayOptions};
use super::queue::{QueuedMessage, QueuedRecipient, RelayQueue};

/// Factory for [`SimpleRelayHandler`].
pub struct SimpleRelayHandlerFactory {
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    hostname: String,
    smtp_timeout: Duration,
    outbound_port: u16,
    /// Optional TLS connector for REQUIRETLS outbound (STARTTLS to MX).
    tls_connector: Option<SharedTlsConnector>,
    options: RelayOptions,
    /// Made on first use, once the builder methods above have been applied.
    engine: Mutex<Option<Arc<RelayEngine>>>,
}

impl SimpleRelayHandlerFactory {
    /// Create a factory (outbound SMTP port defaults to 25).
    pub fn new(dns: Arc<DnsResolver>, runtime: Arc<Runtime>, hostname: impl Into<String>) -> Self {
        Self {
            dns,
            runtime,
            hostname: hostname.into(),
            smtp_timeout: Duration::from_secs(60),
            outbound_port: 25,
            tls_connector: None,
            options: RelayOptions::default(),
            engine: Mutex::new(None),
        }
    }

    /// Outbound SMTP stage timeout.
    pub fn with_smtp_timeout(mut self, timeout: Duration) -> Self {
        self.smtp_timeout = timeout;
        self
    }

    /// Destination port for MX/A delivery (default 25; tests use an ephemeral sink).
    pub fn with_outbound_port(mut self, port: u16) -> Self {
        self.outbound_port = port;
        self
    }

    /// TLS connector used when relaying REQUIRETLS messages (STARTTLS +
    /// verified trust roots supplied by the caller).
    pub fn with_tls_connector(mut self, connector: SharedTlsConnector) -> Self {
        self.tls_connector = Some(connector);
        self
    }

    /// Where the queue is kept, how often a message is retried and for how
    /// long. Without this the queue is in a private temporary directory and
    /// does not survive a restart.
    pub fn with_options(mut self, options: RelayOptions) -> Self {
        self.options = options;
        self
    }

    /// Open the queue and start delivering whatever an earlier run left in
    /// it. [`SimpleRelayService::start`](super::SimpleRelayService::start) does
    /// this; call it yourself when the factory is used with a bare
    /// [`SmtpService`](crate::SmtpService).
    pub fn start_queue(&self) -> io::Result<()> {
        self.engine()?.resume();
        Ok(())
    }

    fn engine(&self) -> io::Result<Arc<RelayEngine>> {
        let mut slot = self.engine.lock().unwrap();
        if let Some(engine) = &*slot {
            return Ok(Arc::clone(engine));
        }
        let engine = RelayEngine::new(
            Arc::clone(&self.dns),
            Arc::clone(&self.runtime),
            self.hostname.clone(),
            self.smtp_timeout,
            self.outbound_port,
            self.tls_connector.clone(),
            self.options.clone(),
        )?;
        *slot = Some(Arc::clone(&engine));
        Ok(engine)
    }
}

impl SmtpHandlerFactory for SimpleRelayHandlerFactory {
    fn create(&self) -> Box<dyn SmtpClientConnected> {
        let engine = match self.engine() {
            Ok(engine) => Some(engine),
            Err(e) => {
                hopf_core::log_warn("smtp.relay.queue", format!("cannot open the relay queue: {e}"));
                None
            }
        };
        Box::new(SimpleRelayHandler {
            runtime: Arc::clone(&self.runtime),
            hostname: self.hostname.clone(),
            engine,
            control_handle: None,
            inbound_tls: false,
            sender: None,
            smtputf8: false,
            delivery: DeliveryRequirements::default(),
            recipients: Vec::new(),
            spool: None,
            extra_header_lines: Vec::new(),
        })
    }
}

/// Gumdrop-style open relay: accept all, queue, then MX lookup and forward
/// with the async [`SmtpClient`](crate::SmtpClient), retrying temporary
/// failures from the queue.
#[derive(Clone)]
pub struct SimpleRelayHandler {
    runtime: Arc<Runtime>,
    hostname: String,
    /// `None` when the queue could not be opened: nothing is accepted then.
    engine: Option<Arc<RelayEngine>>,
    control_handle: Option<ConnHandle>,
    inbound_tls: bool,
    sender: Option<EmailAddress>,
    /// The inbound MAIL FROM carried SMTPUTF8 (RFC 6531).
    smtputf8: bool,
    delivery: DeliveryRequirements,
    recipients: Vec<(EmailAddress, DsnRecipientParams)>,
    spool: Option<Arc<Mutex<SpoolPipeline>>>,
    /// Extra header field values (each without a trailing CRLF) to prepend
    /// ahead of the spooled content for every outbound destination - see
    /// [`crate::server::LocalDeliveryHandler::set_extra_header_lines`] for
    /// the same mechanism on the local-delivery side.
    extra_header_lines: Vec<String>,
}

impl SimpleRelayHandler {
    fn reset_transaction(&mut self) {
        self.sender = None;
        self.smtputf8 = false;
        self.delivery = DeliveryRequirements::default();
        self.recipients.clear();
        self.spool = None;
        self.extra_header_lines.clear();
    }

    /// Set the header lines (see the field doc) to prepend ahead of the
    /// next relayed message, to every destination. Cleared automatically
    /// once the transaction completes.
    pub fn set_extra_header_lines(&mut self, lines: Vec<String>) {
        self.extra_header_lines = lines;
    }

    fn control_handle(&self) -> ConnHandle {
        self.control_handle
            .clone()
            .expect("control handle set in connected()")
    }
}

impl SmtpClientConnected for SimpleRelayHandler {
    fn connected(&mut self, state: &mut dyn ConnectedState, meta: &SmtpConnectionMetadata) {
        self.control_handle = meta.control_handle.clone();
        self.inbound_tls = meta.tls;
        let greeting = format!("{} ESMTP SimpleRelay", self.hostname);
        state.accept_connection(&greeting, Box::new(self.clone()));
    }

    fn disconnected(&mut self) {
        self.reset_transaction();
        self.control_handle = None;
    }
}

impl HelloHandler for SimpleRelayHandler {
    fn hello(&mut self, state: &mut dyn HelloState, _extended: bool, _hostname: &str) {
        state.accept_hello(Box::new(self.clone()));
    }

    fn tls_established(&mut self, _info: &hopf_core::SecurityInfo) {
        self.inbound_tls = true;
    }

    fn authenticated(&mut self, state: &mut dyn AuthenticateState, _user: &str) {
        state.accept(Box::new(self.clone()));
    }

    fn quit(&mut self) {
        self.reset_transaction();
    }
}

impl MailFromHandler for SimpleRelayHandler {
    fn pipeline(&mut self) -> Option<Box<dyn SmtpPipeline>> {
        let handle = self
            .control_handle
            .clone()
            .expect("control handle set in connected()");
        let p = Arc::new(Mutex::new(SpoolPipeline::new(Arc::clone(&self.runtime), handle)));
        self.spool = Some(Arc::clone(&p));
        Some(Box::new(SpoolPipelineHandle(p)))
    }

    fn mail_from(
        &mut self,
        state: &mut dyn MailFromState,
        sender: Option<&EmailAddress>,
        smtputf8: bool,
        delivery: &DeliveryRequirements,
    ) {
        self.sender = sender.cloned();
        self.smtputf8 = smtputf8;
        self.delivery = delivery.clone();
        self.recipients.clear();

        if delivery.is_future_release() {
            state.reject_sender_policy(
                "FUTURERELEASE not supported by this relay",
                Box::new(self.clone()),
            );
            return;
        }
        // Belt-and-suspenders with the control-plane check: REQUIRETLS needs
        // an inbound TLS session (RFC 8689 §2).
        if delivery.is_require_tls() && !self.inbound_tls {
            state.reject_sender_policy(
                "REQUIRETLS requires a TLS-protected session",
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

impl RecipientHandler for SimpleRelayHandler {
    fn rcpt_to(
        &mut self,
        state: &mut dyn RecipientState,
        recipient: &EmailAddress,
        dsn: &DsnRecipientParams,
    ) {
        self.recipients.push((recipient.clone(), dsn.clone()));
        state.accept_recipient(Box::new(self.clone()));
    }

    fn start_message(&mut self, state: &mut dyn MessageStartState) {
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

impl MessageDataHandler for SimpleRelayHandler {
    // SpoolPipeline is registered as the transaction pipeline, so all
    // content goes there, not here (see control.rs `feed_data`).
    fn message_content(&mut self, _chunk: &[u8]) {}

    fn message_complete(&mut self, state: &mut dyn MessageEndState) {
        let (spool_path, spool_error) = self
            .spool
            .as_ref()
            .map(|p| {
                let g = p.lock().unwrap();
                (g.path(), g.error())
            })
            .unwrap_or((None, None));

        let Some(engine) = self.engine.clone() else {
            remove_spool(&self.runtime, self.control_handle(), spool_path);
            state.reject_message_temporary("relay queue unavailable", Box::new(self.clone()));
            self.reset_transaction();
            return;
        };

        if let Some(err) = spool_error {
            remove_spool(&self.runtime, self.control_handle(), spool_path);
            state.reject_message_temporary(&format!("could not stage message: {err}"), Box::new(self.clone()));
            self.reset_transaction();
            return;
        }

        // RFC 2852: if the DELIVERBY deadline has passed by the time we
        // finish receiving, refuse delivery (return-mode -> permanent feel
        // via temporary reject that still triggers a failure DSN).
        if let Some(by) = &self.delivery.deliver_by {
            if by.deadline <= SystemTime::now() {
                engine.bounce(
                    self.control_handle(),
                    self.sender.as_ref().map(EmailAddress::address),
                    self.delivery.clone(),
                    self.recipients.iter().map(|(r, p)| (r.address(), p.clone())).collect(),
                    spool_path,
                    "DELIVERBY deadline exceeded before relay",
                );
                state.reject_message_temporary("DELIVERBY deadline exceeded", Box::new(self.clone()));
                self.reset_transaction();
                return;
            }
        }

        // The message is accepted once it is in the queue: from then on the
        // relay is responsible for it (RFC 5321 section 6.1), and a failure
        // to deliver it is reported by retrying or by a notice, not by the
        // reply to the client, which has long gone by then.
        let deferred = state.defer(Box::new(self.clone()));
        let now = SystemTime::now();
        let message = QueuedMessage {
            id: RelayQueue::new_id(),
            queued_at: now,
            sender: self.sender.as_ref().map(EmailAddress::address),
            smtputf8: self.smtputf8,
            delivery: self.delivery.clone(),
            extra_header_lines: self.extra_header_lines.clone(),
            recipients: self
                .recipients
                .iter()
                .map(|(r, params)| QueuedRecipient::new(r.address(), params.clone(), now))
                .collect(),
        };
        let id = message.id.clone();
        self.reset_transaction();
        engine.submit(
            self.control_handle(),
            message,
            spool_path,
            Box::new(move |queued| {
                if queued {
                    deferred.accept(Some(&id));
                } else {
                    deferred.reject_temporary("could not queue message");
                }
            }),
        );
    }

    fn message_aborted(&mut self) {
        self.reset_transaction();
    }
}

/// Remove a spool file off the reactor thread, fire-and-forget (issue #184) -
/// cleanup nothing else waits on.
fn remove_spool(runtime: &Runtime, handle: ConnHandle, path: Option<std::path::PathBuf>) {
    let Some(path) = path else {
        return;
    };
    runtime.storage().submit_on(
        handle,
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let _ = std::fs::remove_file(path);
            Ok(())
        },
        |_: Result<(), StorageError>| {},
    );
}
