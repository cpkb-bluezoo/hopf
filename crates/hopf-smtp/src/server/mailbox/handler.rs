// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`LocalDeliveryHandler`] — spool message to a temp file, APPEND to each
//! recipient INBOX from that spool (streamed, never buffered whole in RAM).

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Runtime, StorageError};
use hopf_dns::DnsResolver;
use hopf_mailbox::{Flag, MailboxFactory};
use rmimeparser::EmailAddress;

use crate::client::{MailFromParams, SmtpClient, SmtpClientTimeouts, SmtpSend};
use crate::server::delivery::{DeliveryRequirements, DsnRecipientParams};
use crate::server::dsn::{orcpt_field, DeliveryStatusNotification, DsnAction, DsnRecipientReport};
use crate::server::handler::{
    AuthenticateState, ConnectedState, HelloHandler, HelloState, MailFromHandler, MailFromState,
    MessageDataHandler, MessageEndState, MessageStartState, RecipientHandler, RecipientState,
    ResetState, SmtpClientConnected, SmtpConnectionMetadata, SmtpHandlerFactory,
};
use crate::server::pipeline::SmtpPipeline;
use crate::server::spool::{SpoolPipeline, SpoolPipelineHandle};

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
            inbound_tls: false,
            sender: None,
            delivery: DeliveryRequirements::default(),
            recipients: Vec::new(),
            spool: None,
            extra_header_lines: Vec::new(),
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
    inbound_tls: bool,
    sender: Option<EmailAddress>,
    delivery: DeliveryRequirements,
    /// Accepted recipients: (mailbox username, address, DSN params).
    recipients: Vec<(String, EmailAddress, DsnRecipientParams)>,
    spool: Option<Arc<Mutex<SpoolPipeline>>>,
    /// Extra header field values (each without a trailing CRLF — one is
    /// added automatically) to prepend to the message ahead of the
    /// spooled content, e.g. a `Received:` line or an
    /// `Authentication-Results:` field from `crate::auth::AuthPipeline`.
    /// Set via [`Self::set_extra_header_lines`] before [`message_complete`]
    /// runs — a caller composing its own `MessageDataHandler` around this
    /// one (to also drive its own auth pipeline) is the intended place to
    /// call it, once whatever it needs to render the line(s) is ready.
    ///
    /// [`message_complete`]: MessageDataHandler::message_complete
    extra_header_lines: Vec<String>,
}

impl LocalDeliveryHandler {
    fn reset_transaction(&mut self) {
        self.sender = None;
        self.delivery = DeliveryRequirements::default();
        self.recipients.clear();
        self.spool = None;
        self.extra_header_lines.clear();
    }

    /// Set the header lines (see the field doc) to prepend ahead of the
    /// next delivered message. Cleared automatically once the transaction
    /// completes (successfully or not).
    pub fn set_extra_header_lines(&mut self, lines: Vec<String>) {
        self.extra_header_lines = lines;
    }
}

impl SmtpClientConnected for LocalDeliveryHandler {
    fn connected(&mut self, state: &mut dyn ConnectedState, meta: &SmtpConnectionMetadata) {
        self.control_handle = meta.control_handle.clone();
        self.inbound_tls = meta.tls;
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

impl MailFromHandler for LocalDeliveryHandler {
    fn pipeline(&mut self) -> Option<Box<dyn SmtpPipeline>> {
        let p = Arc::new(Mutex::new(SpoolPipeline::new()));
        self.spool = Some(Arc::clone(&p));
        Some(Box::new(SpoolPipelineHandle(p)))
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
                "FUTURERELEASE not supported by local delivery",
                Box::new(self.clone()),
            );
            return;
        }
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

impl RecipientHandler for LocalDeliveryHandler {
    fn rcpt_to(
        &mut self,
        state: &mut dyn RecipientState,
        recipient: &EmailAddress,
        dsn: &DsnRecipientParams,
    ) {
        let Some(username) = local_recipient_username(
            recipient.local_part(),
            recipient.domain(),
            &self.local_domain,
        ) else {
            state.reject_recipient_relay_denied(Box::new(self.clone()));
            return;
        };
        self.recipients
            .push((username, recipient.clone(), dsn.clone()));
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
    // SpoolPipeline is registered as the transaction pipeline, so all
    // content goes there, not here (see control.rs `feed_data`).
    fn message_content(&mut self, _chunk: &[u8]) {}

    fn message_complete(&mut self, state: &mut dyn MessageEndState) {
        let (spool_path, spool_error) = self
            .spool
            .as_ref()
            .map(|p| {
                let g = p.lock().unwrap();
                (g.path().map(|p| p.to_path_buf()), g.error().map(str::to_string))
            })
            .unwrap_or((None, None));

        if let Some(err) = spool_error {
            if let Some(path) = &spool_path {
                let _ = std::fs::remove_file(path);
            }
            state.reject_message_temporary(
                &format!("could not stage message: {err}"),
                Box::new(self.clone()),
            );
            self.reset_transaction();
            return;
        }

        if let Some(by) = &self.delivery.deliver_by {
            if by.deadline <= std::time::SystemTime::now() {
                if let Some(path) = &spool_path {
                    let _ = std::fs::remove_file(path);
                }
                state.reject_message_temporary(
                    "DELIVERBY deadline exceeded",
                    Box::new(self.clone()),
                );
                self.reset_transaction();
                return;
            }
        }

        let recipients = self.recipients.clone();
        let extra_header_lines = self.extra_header_lines.clone();
        let factory = Arc::clone(&self.mailbox_factory);
        let storage = Arc::clone(self.runtime.storage());
        let handle = self
            .control_handle
            .clone()
            .expect("control handle set in connected()");
        let deferred = state.defer(Box::new(self.clone()));
        let sender = self.sender.clone();
        let delivery = self.delivery.clone();
        let hostname = self.hostname.clone();
        let local_domain = self.local_domain.clone();
        let runtime = Arc::clone(&self.runtime);
        self.reset_transaction();

        storage.submit_on(
            handle,
            move || {
                deliver_spooled(
                    factory.as_ref(),
                    &recipients,
                    spool_path.as_deref(),
                    &extra_header_lines,
                    sender.as_ref(),
                    &delivery,
                    &hostname,
                    &local_domain,
                    &runtime,
                )
            },
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

/// Deliver to every recipient by streaming `spool_path`'s content into each
/// mailbox's append triad, then remove the spool file. Emits a DSN to the
/// reverse-path when NOTIFY requests it.
///
/// Returns `None` when at least one recipient succeeded (SMTP 250 — partial
/// failures are reported via DSN so clients do not retry and duplicate).
/// Returns `Some(error)` only when every recipient failed.
fn deliver_spooled(
    factory: &dyn MailboxFactory,
    recipients: &[(String, EmailAddress, DsnRecipientParams)],
    spool_path: Option<&Path>,
    extra_header_lines: &[String],
    sender: Option<&EmailAddress>,
    delivery: &DeliveryRequirements,
    hostname: &str,
    local_domain: &str,
    runtime: &Arc<Runtime>,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let flags = BTreeSet::<Flag>::new();
    let mut first_error: Option<String> = None;
    let mut any_success = false;
    let mut outcomes: Vec<(DsnRecipientParams, DsnRecipientReport)> = Vec::new();

    for (username, addr, params) in recipients {
        match deliver_to_mailbox_streaming(
            factory,
            username,
            spool_path,
            &flags,
            extra_header_lines,
        ) {
            Ok(()) => {
                any_success = true;
                outcomes.push((
                    params.clone(),
                    DsnRecipientReport {
                        final_recipient: addr.address(),
                        original_recipient: orcpt_field(params),
                        action: DsnAction::Delivered,
                        diagnostic: None,
                    },
                ));
            }
            Err(e) => {
                let msg = e.to_string();
                if first_error.is_none() {
                    first_error = Some(msg.clone());
                }
                outcomes.push((
                    params.clone(),
                    DsnRecipientReport {
                        final_recipient: addr.address(),
                        original_recipient: orcpt_field(params),
                        action: DsnAction::Failed,
                        diagnostic: Some(msg),
                    },
                ));
            }
        }
    }

    let reports = DeliveryStatusNotification::filter_reports(outcomes);
    if !reports.is_empty() {
        if let Some(sender) = sender {
            let original = spool_path
                .and_then(|p| std::fs::read(p).ok())
                .unwrap_or_default();
            let dsn = DeliveryStatusNotification {
                reporting_mta: hostname.into(),
                reverse_path: Some(sender.clone()),
                delivery: delivery.clone(),
                recipients: reports,
                original_message: original,
            };
            if let Some(bytes) = dsn.render() {
                deliver_dsn_to_reverse_path(
                    factory,
                    sender,
                    &bytes,
                    local_domain,
                    hostname,
                    runtime,
                    delivery.is_require_tls(),
                );
            }
        }
    }

    if let Some(path) = spool_path {
        let _ = std::fs::remove_file(path);
    }
    if any_success {
        Ok(None)
    } else {
        Ok(first_error.or_else(|| Some("No recipients could be delivered".into())))
    }
}

/// Deliver a rendered DSN: local reverse-path → APPEND; otherwise MX relay.
fn deliver_dsn_to_reverse_path(
    factory: &dyn MailboxFactory,
    reverse_path: &EmailAddress,
    message: &[u8],
    local_domain: &str,
    hostname: &str,
    runtime: &Arc<Runtime>,
    require_tls: bool,
) {
    if let Some(username) = local_recipient_username(
        reverse_path.local_part(),
        reverse_path.domain(),
        local_domain,
    ) {
        let _ = append_bytes_to_mailbox(factory, &username, message);
        return;
    }

    let Ok(dns) = DnsResolver::for_runtime(runtime.as_ref()) else {
        return;
    };
    send_local_dsn_via_mx(
        message,
        reverse_path,
        hostname,
        &Arc::new(dns),
        runtime,
        require_tls,
    );
}

fn append_bytes_to_mailbox(
    factory: &dyn MailboxFactory,
    username: &str,
    message: &[u8],
) -> hopf_mailbox::MailboxResult<()> {
    let flags = BTreeSet::<Flag>::new();
    let mut store = factory.create_store();
    store.open(username)?;
    let mut mb = store.open_mailbox("INBOX", false)?;
    let mut guard = hopf_mailbox::AppendGuard::start(mb.as_mut(), &flags, None)?;
    guard.append_content(message)?;
    guard.commit()?;
    mb.close(false)?;
    store.close()?;
    Ok(())
}

fn send_local_dsn_via_mx(
    message: &[u8],
    reverse_path: &EmailAddress,
    hostname: &str,
    dns: &Arc<DnsResolver>,
    runtime: &Arc<Runtime>,
    require_tls: bool,
) {
    let domain = reverse_path.domain().to_ascii_lowercase();
    let to = reverse_path.address();
    let hostname = hostname.to_string();
    let message = message.to_vec();
    let runtime = Arc::clone(runtime);
    let dns2 = Arc::clone(dns);
    let domain_for_cb = domain.clone();
    dns.query_mx(
        &domain,
        Box::new(move |result| {
            let host = match result {
                Ok(msg) => {
                    let mut mx: Vec<(u16, String)> =
                        msg.answers.iter().filter_map(|rr| rr.as_mx()).collect();
                    mx.sort_by_key(|(pref, _)| *pref);
                    mx.first()
                        .map(|(_, ex)| ex.trim_end_matches('.').to_string())
                        .unwrap_or(domain_for_cb)
                }
                Err(_) => return,
            };
            dns2.resolve(
                &host,
                25,
                Box::new(move |result| {
                    let Ok(addrs) = result else {
                        return;
                    };
                    let Some(&addr) = addrs.first() else {
                        return;
                    };
                    let timeouts = SmtpClientTimeouts::default();
                    let mut body = Some(message);
                    let mut send = SmtpSend::new(hostname)
                        .mail_from("")
                        .rcpt_to(to)
                        .message_with(move || body.take());
                    if require_tls {
                        send = send
                            .require_starttls(true)
                            .mail_from_params(MailFromParams {
                                require_tls: true,
                                ..Default::default()
                            });
                    }
                    let _ = SmtpClient::from_addr(addr)
                        .timeouts(timeouts)
                        .connect(&runtime, Arc::new(send));
                }),
            );
        }),
    );
}

#[cfg(test)]
fn deliver_recipients<E, F>(recipients: &[String], mut deliver: F) -> Option<String>
where
    E: std::fmt::Display,
    F: FnMut(&str) -> Result<(), E>,
{
    let mut first_error: Option<String> = None;
    let mut any_success = false;
    for username in recipients {
        match deliver(username) {
            Ok(()) => any_success = true,
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e.to_string());
                }
            }
        }
    }
    if any_success {
        None
    } else {
        first_error
    }
}

/// Stream `spool_path`'s content into `username`'s INBOX via the append
/// triad in bounded chunks — the message is never held whole in memory,
/// neither here nor (per recipient) duplicated as it was before. A
/// mid-stream failure (e.g. disk full partway through a large message)
/// rolls back via `AppendGuard` instead of leaving an orphaned partial
/// append. `extra_header_lines` (each a complete field value, no trailing
/// CRLF) is written first, ahead of the spooled content — see
/// [`LocalDeliveryHandler::set_extra_header_lines`].
fn deliver_to_mailbox_streaming(
    factory: &dyn MailboxFactory,
    username: &str,
    spool_path: Option<&Path>,
    flags: &BTreeSet<Flag>,
    extra_header_lines: &[String],
) -> hopf_mailbox::MailboxResult<()> {
    let mut store = factory.create_store();
    store.open(username)?;
    let mut mb = store.open_mailbox("INBOX", false)?;
    let mut guard = hopf_mailbox::AppendGuard::start(mb.as_mut(), flags, None)?;
    for line in extra_header_lines {
        guard.append_content(line.as_bytes())?;
        guard.append_content(b"\r\n")?;
    }
    if let Some(path) = spool_path {
        let mut f = File::open(path)?;
        let mut buf = [0u8; 8192];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            guard.append_content(&buf[..n])?;
        }
    }
    guard.commit()?;
    mb.close(false)?;
    store.close()?;
    Ok(())
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
    fn delivery_accepts_on_partial_success_but_attempts_every_recipient() {
        let recipients = vec![
            "bad-one".to_string(),
            "good".to_string(),
            "bad-two".to_string(),
        ];
        let mut visited = Vec::new();

        // Any success → accept (None); failures are reported via DSN, not 4xx.
        let error = deliver_recipients(&recipients, |username| {
            visited.push(username.to_string());
            match username {
                "bad-one" => Err("first failure"),
                "bad-two" => Err("second failure"),
                _ => Ok(()),
            }
        });
        assert_eq!(error, None);
        assert_eq!(visited, recipients);
    }

    #[test]
    fn delivery_rejects_only_when_every_recipient_fails() {
        let recipients = vec!["bad-one".to_string(), "bad-two".to_string()];
        let mut visited = Vec::new();

        let error = deliver_recipients(&recipients, |username| {
            visited.push(username.to_string());
            Err::<(), _>(match username {
                "bad-one" => "first failure",
                _ => "second failure",
            })
        });
        assert_eq!(error.as_deref(), Some("first failure"));
        assert_eq!(visited, recipients);
    }

    #[test]
    fn deliver_to_mailbox_streaming_round_trips_spooled_content() {
        use hopf_mailbox::MaildirFactory;
        let dir = tempfile::tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());

        let spool_dir = tempfile::tempdir().unwrap();
        let spool_path = spool_dir.path().join("spooled.tmp");
        std::fs::write(&spool_path, b"From: a@b\r\n\r\nhello\r\n").unwrap();

        deliver_to_mailbox_streaming(&factory, "alice", Some(&spool_path), &BTreeSet::new(), &[])
            .unwrap();

        let mut store = factory.create_store();
        store.open("alice").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        assert_eq!(mb.message_count().unwrap(), 1);

        struct Collect(Vec<u8>);
        impl hopf_mailbox::MessageReadCallback for Collect {
            fn message_content(&mut self, chunk: &[u8]) -> bool {
                self.0.extend_from_slice(chunk);
                true
            }
        }
        let mut cb = Collect(Vec::new());
        mb.read_message(1, &mut cb).unwrap();
        assert_eq!(cb.0, b"From: a@b\r\n\r\nhello\r\n");
    }

    #[test]
    fn extra_header_lines_are_prepended_ahead_of_spooled_content() {
        use hopf_mailbox::MaildirFactory;
        let dir = tempfile::tempdir().unwrap();
        let factory = MaildirFactory::new(dir.path());

        let spool_dir = tempfile::tempdir().unwrap();
        let spool_path = spool_dir.path().join("spooled.tmp");
        std::fs::write(&spool_path, b"From: a@b\r\n\r\nhello\r\n").unwrap();

        let extra = vec![
            "Received: from mx.example.com".to_string(),
            "Authentication-Results: mail.example.com; spf=pass".to_string(),
        ];
        deliver_to_mailbox_streaming(
            &factory,
            "bob",
            Some(&spool_path),
            &BTreeSet::new(),
            &extra,
        )
        .unwrap();

        let mut store = factory.create_store();
        store.open("bob").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();

        struct Collect(Vec<u8>);
        impl hopf_mailbox::MessageReadCallback for Collect {
            fn message_content(&mut self, chunk: &[u8]) -> bool {
                self.0.extend_from_slice(chunk);
                true
            }
        }
        let mut cb = Collect(Vec::new());
        mb.read_message(1, &mut cb).unwrap();
        assert_eq!(
            cb.0,
            b"Received: from mx.example.com\r\n\
              Authentication-Results: mail.example.com; spf=pass\r\n\
              From: a@b\r\n\r\nhello\r\n"
                .to_vec()
        );
    }
}
