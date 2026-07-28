// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`SimpleRelayHandler`] — buffer message, MX lookup, deliver via async [`SmtpClient`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmimeparser::EmailAddress;
use hopf_core::Runtime;
use hopf_dns::DnsResolver;

use crate::client::{SmtpClient, SmtpClientTimeouts, SmtpSend};
use crate::server::delivery::{DeliveryRequirements, DsnRecipientParams};
use crate::server::handler::{
    AuthenticateState, ConnectedState, DeferredDelivery, HelloHandler, HelloState, MailFromHandler,
    MailFromState, MessageDataHandler, MessageEndState, MessageStartState, RecipientHandler,
    RecipientState, ResetState, SmtpClientConnected, SmtpConnectionMetadata, SmtpHandlerFactory,
};
use crate::server::pipeline::SmtpPipeline;

/// In-memory message buffer used as the transaction [`SmtpPipeline`].
#[derive(Debug, Default)]
pub struct MessageBufferPipeline {
    buf: Vec<u8>,
}

impl MessageBufferPipeline {
    /// Empty buffer.
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(8192) }
    }

    /// Buffered message bytes.
    pub fn message_data(&self) -> &[u8] {
        &self.buf
    }

    /// Take ownership of the buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

impl SmtpPipeline for MessageBufferPipeline {
    fn mail_from(&mut self, _sender: Option<&EmailAddress>) {}
    fn rcpt_to(&mut self, _recipient: &EmailAddress) {}
    fn message_content(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }
    fn end_data(&mut self) {}
    fn reset(&mut self) {
        self.buf.clear();
    }
}

/// Factory for [`SimpleRelayHandler`].
pub struct SimpleRelayHandlerFactory {
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    hostname: String,
    smtp_timeout: Duration,
    outbound_port: u16,
}

impl SimpleRelayHandlerFactory {
    /// Create a factory (outbound SMTP port defaults to 25).
    pub fn new(
        dns: Arc<DnsResolver>,
        runtime: Arc<Runtime>,
        hostname: impl Into<String>,
    ) -> Self {
        Self {
            dns,
            runtime,
            hostname: hostname.into(),
            smtp_timeout: Duration::from_secs(60),
            outbound_port: 25,
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
}

impl SmtpHandlerFactory for SimpleRelayHandlerFactory {
    fn create(&self) -> Box<dyn SmtpClientConnected> {
        Box::new(SimpleRelayHandler {
            dns: Arc::clone(&self.dns),
            runtime: Arc::clone(&self.runtime),
            hostname: self.hostname.clone(),
            smtp_timeout: self.smtp_timeout,
            outbound_port: self.outbound_port,
            sender: None,
            delivery: DeliveryRequirements::default(),
            recipients: Vec::new(),
            pipeline: None,
        })
    }
}

/// Gumdrop-style open relay: accept all, MX lookup, forward with async [`SmtpClient`].
#[derive(Clone)]
pub struct SimpleRelayHandler {
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    hostname: String,
    smtp_timeout: Duration,
    outbound_port: u16,
    sender: Option<EmailAddress>,
    delivery: DeliveryRequirements,
    recipients: Vec<EmailAddress>,
    pipeline: Option<Arc<Mutex<MessageBufferPipeline>>>,
}

impl SimpleRelayHandler {
    fn reset_transaction(&mut self) {
        self.sender = None;
        self.delivery = DeliveryRequirements::default();
        self.recipients.clear();
        self.pipeline = None;
    }
}

impl SmtpClientConnected for SimpleRelayHandler {
    fn connected(&mut self, state: &mut dyn ConnectedState, _meta: &SmtpConnectionMetadata) {
        let greeting = format!("{} ESMTP SimpleRelay", self.hostname);
        state.accept_connection(&greeting, Box::new(self.clone()));
    }

    fn disconnected(&mut self) {
        self.reset_transaction();
    }
}

impl HelloHandler for SimpleRelayHandler {
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

impl MailFromHandler for SimpleRelayHandler {
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
        self.delivery = delivery.clone();
        self.recipients.clear();

        if delivery.is_future_release() {
            state.reject_sender_policy(
                "FUTURERELEASE not supported by this relay",
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
        _dsn: &DsnRecipientParams,
    ) {
        self.recipients.push(recipient.clone());
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
        let deferred = state.defer(Box::new(self.clone()));
        let by_domain = group_by_domain(&self.recipients);
        let ctx = DeliveryContext {
            deferred: Some(deferred),
            domains: by_domain.keys().cloned().collect(),
            recipients_by_domain: by_domain,
            message,
            sender: self.sender.clone(),
            require_tls: self.delivery.is_require_tls(),
            dns: Arc::clone(&self.dns),
            runtime: Arc::clone(&self.runtime),
            hostname: self.hostname.clone(),
            smtp_timeout: self.smtp_timeout,
            outbound_port: self.outbound_port,
            current: 0,
            success: 0,
            fail: 0,
        };
        self.reset_transaction();
        ctx.deliver_next();
    }

    fn message_aborted(&mut self) {
        self.reset_transaction();
    }
}

/// Wrapper so pipeline can be shared with the handler.
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

fn group_by_domain(recipients: &[EmailAddress]) -> HashMap<String, Vec<EmailAddress>> {
    let mut map = HashMap::new();
    for r in recipients {
        let domain = r.domain().to_ascii_lowercase();
        map.entry(domain).or_insert_with(Vec::new).push(r.clone());
    }
    map
}

// ── Async delivery context ────────────────────────────────────────────────────

struct DeliveryContext {
    deferred: Option<DeferredDelivery>,
    domains: Vec<String>,
    recipients_by_domain: HashMap<String, Vec<EmailAddress>>,
    message: Vec<u8>,
    sender: Option<EmailAddress>,
    require_tls: bool,
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    hostname: String,
    smtp_timeout: Duration,
    outbound_port: u16,
    current: usize,
    success: usize,
    fail: usize,
}

impl DeliveryContext {
    fn deliver_next(mut self) {
        if self.current >= self.domains.len() {
            self.finish();
            return;
        }
        let domain = self.domains[self.current].clone();
        let recipients = self
            .recipients_by_domain
            .get(&domain)
            .cloned()
            .unwrap_or_default();
        let dns = Arc::clone(&self.dns);
        let domain_fallback = domain.clone();
        dns.query_mx(
            &domain,
            Box::new(move |result| match result {
                Ok(msg) => {
                    let mut mx: Vec<(u16, String)> =
                        msg.answers.iter().filter_map(|rr| rr.as_mx()).collect();
                    mx.sort_by_key(|(pref, _)| *pref);
                    let host = mx
                        .first()
                        .map(|(_, ex)| ex.trim_end_matches('.').to_string())
                        .unwrap_or(domain_fallback);
                    self.deliver_to_host(host, recipients);
                }
                Err(_) => {
                    self.fail += recipients.len();
                    self.current += 1;
                    self.deliver_next();
                }
            }),
        );
    }

    fn deliver_to_host(mut self, host: String, recipients: Vec<EmailAddress>) {
        let require_tls = self.require_tls;
        let port = self.outbound_port;
        let dns = Arc::clone(&self.dns);

        if require_tls {
            // Full STARTTLS to arbitrary MX needs trust roots; bounce for now.
            self.fail += recipients.len();
            self.current += 1;
            self.deliver_next();
            return;
        }

        dns.resolve(
            &host,
            port,
            Box::new(move |result| match result {
                Ok(addrs) if !addrs.is_empty() => {
                    let addr = addrs[0];
                    self.deliver_smtp(addr, recipients);
                }
                _ => {
                    self.fail += recipients.len();
                    self.current += 1;
                    self.deliver_next();
                }
            }),
        );
    }

    fn deliver_smtp(mut self, addr: std::net::SocketAddr, recipients: Vec<EmailAddress>) {
        let hostname = self.hostname.clone();
        let message = self.message.clone();
        let sender = self.sender.as_ref().map(|s| s.address());
        let n = recipients.len();

        // Build completion channel via Arc<Mutex<Option<>>>.
        let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        let done2 = Arc::clone(&done);

        let recipient_addrs: Vec<String> = recipients.iter().map(|r| r.address()).collect();

        let timeouts = SmtpClientTimeouts {
            stage: self.smtp_timeout,
            message: self.smtp_timeout * 10,
            ..Default::default()
        };

        let mut send = SmtpSend::new(hostname)
            .message(message)
            .on_complete(Box::new(move |ok| {
                *done2.lock().unwrap() = Some(ok);
            }));

        if let Some(s) = sender {
            send = send.mail_from(s);
        }
        for r in recipient_addrs {
            send = send.rcpt_to(r);
        }

        let result = SmtpClient::from_addr(addr)
            .timeouts(timeouts)
            .connect(&self.runtime, Arc::new(send));

        if result.is_err() {
            self.fail += n;
            self.current += 1;
            self.deliver_next();
            return;
        }

        // The delivery runs asynchronously; we can't block here. To keep the
        // relay semantics (defer → accept/reject after all domains), we accept
        // optimistically and let the async delivery complete independently.
        // A production relay should use per-domain result tracking via channels.
        self.success += n;
        self.current += 1;
        self.deliver_next();
        let _ = done;
    }

    fn finish(mut self) {
        let deferred = self.deferred.take().unwrap();
        if self.fail > 0 && self.success == 0 {
            deferred.reject_temporary("Delivery failed to all recipients");
        } else {
            deferred.accept(None);
        }
    }
}
