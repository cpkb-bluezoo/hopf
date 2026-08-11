// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`SimpleRelayHandler`] — spool message, MX lookup, deliver via async
//! [`SmtpClient`], streamed from the spool to each destination.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{ConnHandle, Runtime, SharedTlsConnector, StorageError};
use hopf_dns::DnsResolver;
use rmimeparser::EmailAddress;

use crate::client::{MailFromParams, SmtpClient, SmtpClientTimeouts, SmtpSend};
use crate::server::delivery::{DeliveryRequirements, DsnRecipientParams};
use crate::server::dsn::{orcpt_field, DeliveryStatusNotification, DsnAction, DsnRecipientReport};
use crate::server::handler::{
    AuthenticateState, ConnectedState, DeferredDelivery, HelloHandler, HelloState, MailFromHandler,
    MailFromState, MessageDataHandler, MessageEndState, MessageStartState, RecipientHandler,
    RecipientState, ResetState, SmtpClientConnected, SmtpConnectionMetadata, SmtpHandlerFactory,
};
use crate::server::pipeline::SmtpPipeline;
use crate::server::spool::{SpoolPipeline, SpoolPipelineHandle};

/// Factory for [`SimpleRelayHandler`].
pub struct SimpleRelayHandlerFactory {
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    hostname: String,
    smtp_timeout: Duration,
    outbound_port: u16,
    /// Optional TLS connector for REQUIRETLS outbound (STARTTLS to MX).
    tls_connector: Option<SharedTlsConnector>,
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
}

impl SmtpHandlerFactory for SimpleRelayHandlerFactory {
    fn create(&self) -> Box<dyn SmtpClientConnected> {
        Box::new(SimpleRelayHandler {
            dns: Arc::clone(&self.dns),
            runtime: Arc::clone(&self.runtime),
            hostname: self.hostname.clone(),
            smtp_timeout: self.smtp_timeout,
            outbound_port: self.outbound_port,
            tls_connector: self.tls_connector.clone(),
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

/// Gumdrop-style open relay: accept all, MX lookup, forward with async [`SmtpClient`].
#[derive(Clone)]
pub struct SimpleRelayHandler {
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    hostname: String,
    smtp_timeout: Duration,
    outbound_port: u16,
    tls_connector: Option<SharedTlsConnector>,
    control_handle: Option<ConnHandle>,
    inbound_tls: bool,
    sender: Option<EmailAddress>,
    delivery: DeliveryRequirements,
    recipients: Vec<(EmailAddress, DsnRecipientParams)>,
    spool: Option<Arc<Mutex<SpoolPipeline>>>,
    /// Extra header field values (each without a trailing CRLF) to prepend
    /// ahead of the spooled content for every outbound destination — see
    /// [`crate::server::LocalDeliveryHandler::set_extra_header_lines`] for
    /// the same mechanism on the local-delivery side.
    extra_header_lines: Vec<String>,
}

impl SimpleRelayHandler {
    fn reset_transaction(&mut self) {
        self.sender = None;
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

        if let Some(err) = spool_error {
            if let Some(path) = spool_path.clone() {
                remove_spool_file_async(&self.runtime, self.control_handle(), path);
            }
            state.reject_message_temporary(
                &format!("could not stage message: {err}"),
                Box::new(self.clone()),
            );
            self.reset_transaction();
            return;
        }

        // RFC 2852: if the DELIVERBY deadline has passed by the time we
        // finish receiving, refuse delivery (return-mode → permanent feel
        // via temporary reject that still triggers a failure DSN).
        if let Some(by) = &self.delivery.deliver_by {
            if by.deadline <= std::time::SystemTime::now() {
                maybe_send_failure_dsn(
                    &self.hostname,
                    self.sender.as_ref(),
                    &self.delivery,
                    &self.recipients,
                    spool_path.clone(),
                    "DELIVERBY deadline exceeded before relay",
                    &self.dns,
                    &self.runtime,
                    self.smtp_timeout,
                    self.outbound_port,
                    self.tls_connector.clone(),
                    self.control_handle(),
                );
                if let Some(path) = spool_path.clone() {
                    remove_spool_file_async(&self.runtime, self.control_handle(), path);
                }
                state.reject_message_temporary(
                    "DELIVERBY deadline exceeded",
                    Box::new(self.clone()),
                );
                self.reset_transaction();
                return;
            }
        }

        let deferred = state.defer(Box::new(self.clone()));
        let by_domain = group_by_domain(&self.recipients);
        let domains: Vec<String> = by_domain.keys().cloned().collect();
        let tracker = Arc::new(Mutex::new(DeliveryTracker {
            deferred: Some(deferred),
            remaining: domains.len(),
            any_success: false,
            spool_path: spool_path.clone(),
            hostname: self.hostname.clone(),
            sender: self.sender.clone(),
            delivery: self.delivery.clone(),
            recipients: self.recipients.clone(),
            domain_results: HashMap::new(),
            dns: Arc::clone(&self.dns),
            runtime: Arc::clone(&self.runtime),
            smtp_timeout: self.smtp_timeout,
            outbound_port: self.outbound_port,
            tls_connector: self.tls_connector.clone(),
            dsn_sent: false,
            control_handle: self.control_handle(),
        }));
        if domains.is_empty() {
            tracker.lock().unwrap().finish_if_needed_with_zero_domains();
        }
        let ctx = DeliveryContext {
            tracker,
            domains,
            recipients_by_domain: by_domain,
            spool_path,
            extra_header_lines: self.extra_header_lines.clone(),
            sender: self.sender.clone(),
            require_tls: self.delivery.is_require_tls(),
            mail_params: MailFromParams {
                require_tls: self.delivery.is_require_tls(),
                dsn_ret: self.delivery.dsn_ret,
                dsn_envid: self.delivery.dsn_envid.clone(),
                priority: self.delivery.priority,
                ..Default::default()
            },
            dns: Arc::clone(&self.dns),
            runtime: Arc::clone(&self.runtime),
            hostname: self.hostname.clone(),
            smtp_timeout: self.smtp_timeout,
            outbound_port: self.outbound_port,
            tls_connector: self.tls_connector.clone(),
            current: 0,
        };
        self.reset_transaction();
        ctx.deliver_next();
    }

    fn message_aborted(&mut self) {
        self.reset_transaction();
    }
}

/// Each line plus a trailing CRLF, concatenated — small and bounded (a
/// handful of header field values), unlike the message body this precedes.
fn render_extra_header_lines(lines: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn group_by_domain(
    recipients: &[(EmailAddress, DsnRecipientParams)],
) -> HashMap<String, Vec<(EmailAddress, DsnRecipientParams)>> {
    let mut map = HashMap::new();
    for (r, params) in recipients {
        let domain = r.domain().to_ascii_lowercase();
        map.entry(domain)
            .or_insert_with(Vec::new)
            .push((r.clone(), params.clone()));
    }
    map
}

// ── Completion tracking ───────────────────────────────────────────────────────

/// Tracks how many of the destination domains have finished (successfully or
/// not) and issues the single deferred SMTP reply once every domain has
/// reported. Shared across all in-flight per-domain deliveries, which may
/// complete concurrently and in any order.
struct DeliveryTracker {
    deferred: Option<DeferredDelivery>,
    remaining: usize,
    any_success: bool,
    spool_path: Option<PathBuf>,
    hostname: String,
    sender: Option<EmailAddress>,
    delivery: DeliveryRequirements,
    recipients: Vec<(EmailAddress, DsnRecipientParams)>,
    /// Domain → ok for DSN generation once every domain has reported.
    domain_results: HashMap<String, bool>,
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    smtp_timeout: Duration,
    outbound_port: u16,
    tls_connector: Option<SharedTlsConnector>,
    dsn_sent: bool,
    control_handle: ConnHandle,
}

impl DeliveryTracker {
    /// Record one domain's outcome. Once every domain has reported, issues
    /// the final SMTP reply. Partial success accepts the transaction (250)
    /// and relies on failure DSNs for undelivered recipients — rejecting
    /// after some domains already got the message would invite client
    /// retry and duplicate delivery.
    fn record(&mut self, domain: &str, ok: bool) {
        self.domain_results.insert(domain.to_string(), ok);
        if ok {
            self.any_success = true;
        }
        self.remaining = self.remaining.saturating_sub(1);
        if self.remaining == 0 {
            self.finish();
        }
    }

    fn finish_if_needed_with_zero_domains(&mut self) {
        if self.remaining == 0 {
            self.finish();
        }
    }

    /// Reads the spool file (for the DSN's original-message attachment) and
    /// removes it — combined into one offloaded job (issue #184) since both
    /// are blocking filesystem work and must run in that order (removing
    /// first would make the read fail). `deferred.accept`/`reject_temporary`
    /// move into the completion callback too, so the final reply only goes
    /// out once this has actually finished, not while it's still in flight.
    fn finish(&mut self) {
        let dsn_input = self.build_dsn_reports();
        let spool_path = self.spool_path.take();
        let deferred = self.deferred.take();
        let any_success = self.any_success;
        let hostname = self.hostname.clone();
        let hostname_for_op = self.hostname.clone();
        let delivery = self.delivery.clone();
        let dns = Arc::clone(&self.dns);
        let runtime = Arc::clone(&self.runtime);
        let smtp_timeout = self.smtp_timeout;
        let outbound_port = self.outbound_port;
        let tls_connector = self.tls_connector.clone();
        let require_tls = self.delivery.is_require_tls();

        self.runtime.storage().submit_on(
            self.control_handle.clone(),
            move || -> Result<Option<(EmailAddress, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
                let rendered = dsn_input.and_then(|(sender, reports)| {
                    let original = spool_path
                        .as_ref()
                        .and_then(|p| std::fs::read(p).ok())
                        .unwrap_or_default();
                    let bytes = DeliveryStatusNotification {
                        reporting_mta: hostname_for_op,
                        reverse_path: Some(sender.clone()),
                        delivery,
                        recipients: reports,
                        original_message: original,
                    }
                    .render();
                    bytes.map(|b| (sender, b))
                });
                if let Some(path) = &spool_path {
                    let _ = std::fs::remove_file(path);
                }
                Ok(rendered)
            },
            move |result: Result<Option<(EmailAddress, Vec<u8>)>, StorageError>| {
                if let Ok(Some((sender, bytes))) = result {
                    send_dsn_message(
                        &bytes,
                        &sender,
                        &hostname,
                        &dns,
                        &runtime,
                        smtp_timeout,
                        outbound_port,
                        tls_connector,
                        require_tls,
                    );
                }
                let Some(deferred) = deferred else {
                    return;
                };
                if any_success {
                    // Accept even when some domains failed — DSNs cover the rest.
                    deferred.accept(None);
                } else {
                    deferred.reject_temporary("No recipient domains could be delivered");
                }
            },
        );
    }

    /// Builds the DSN recipient reports and reverse-path in memory (no I/O)
    /// if a DSN needs to be sent — `None` once already sent, with no
    /// sender, or nothing wants a report. Idempotent via `dsn_sent`.
    fn build_dsn_reports(&mut self) -> Option<(EmailAddress, Vec<DsnRecipientReport>)> {
        if self.dsn_sent {
            return None;
        }
        self.dsn_sent = true;
        let sender = self.sender.clone()?;
        let mut reports = Vec::new();
        for (addr, params) in &self.recipients {
            let domain = addr.domain().to_ascii_lowercase();
            let ok = self.domain_results.get(&domain).copied().unwrap_or(false);
            let action = if ok {
                DsnAction::Delivered
            } else {
                DsnAction::Failed
            };
            let want = match action {
                DsnAction::Delivered => params.notify.wants_success(),
                DsnAction::Failed => params.notify.wants_failure(),
            };
            if !want {
                continue;
            }
            reports.push(DsnRecipientReport {
                final_recipient: addr.address(),
                original_recipient: orcpt_field(params),
                action,
                diagnostic: if ok {
                    None
                } else {
                    Some("relay to recipient domain failed".into())
                },
            });
        }
        if reports.is_empty() {
            return None;
        }
        Some((sender, reports))
    }
}

/// Remove `path` off the reactor thread, fire-and-forget (issue #184) —
/// cleanup nothing else waits on.
fn remove_spool_file_async(runtime: &Runtime, handle: ConnHandle, path: PathBuf) {
    runtime.storage().submit_on(
        handle,
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let _ = std::fs::remove_file(path);
            Ok(())
        },
        |_: Result<(), StorageError>| {},
    );
}

struct DeliveryContext {
    tracker: Arc<Mutex<DeliveryTracker>>,
    domains: Vec<String>,
    recipients_by_domain: HashMap<String, Vec<(EmailAddress, DsnRecipientParams)>>,
    spool_path: Option<PathBuf>,
    extra_header_lines: Vec<String>,
    sender: Option<EmailAddress>,
    require_tls: bool,
    mail_params: MailFromParams,
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    hostname: String,
    smtp_timeout: Duration,
    outbound_port: u16,
    tls_connector: Option<SharedTlsConnector>,
    current: usize,
}

impl DeliveryContext {
    fn deliver_next(self) {
        if self.current >= self.domains.len() {
            return;
        }
        let domain = self.domains[self.current].clone();
        let recipients = self
            .recipients_by_domain
            .get(&domain)
            .cloned()
            .unwrap_or_default();
        let dns = Arc::clone(&self.dns);
        let domain_query = domain.clone();
        let domain_fallback = domain.clone();
        dns.query_mx(
            &domain_query,
            Box::new(move |result| match result {
                Ok(msg) => {
                    let mut mx: Vec<(u16, String)> =
                        msg.answers.iter().filter_map(|rr| rr.as_mx()).collect();
                    mx.sort_by_key(|(pref, _)| *pref);
                    let host = mx
                        .first()
                        .map(|(_, ex)| ex.trim_end_matches('.').to_string())
                        .unwrap_or(domain_fallback);
                    self.deliver_to_host(domain, host, recipients);
                }
                Err(_) => {
                    self.fail_current(&domain);
                }
            }),
        );
    }

    fn fail_current(mut self, domain: &str) {
        self.tracker.lock().unwrap().record(domain, false);
        self.current += 1;
        self.deliver_next();
    }

    fn deliver_to_host(
        self,
        domain: String,
        host: String,
        recipients: Vec<(EmailAddress, DsnRecipientParams)>,
    ) {
        let port = self.outbound_port;
        let dns = Arc::clone(&self.dns);

        if self.require_tls && self.tls_connector.is_none() {
            self.fail_current(&domain);
            return;
        }

        let tls_connector = self.tls_connector.clone();
        let host_query = host.clone();
        dns.resolve(
            &host_query,
            port,
            Box::new(move |result| match result {
                Ok(addrs) if !addrs.is_empty() => {
                    let addr = addrs[0];
                    self.deliver_smtp(domain, host, addr, recipients, tls_connector);
                }
                _ => {
                    self.fail_current(&domain);
                }
            }),
        );
    }

    fn deliver_smtp(
        mut self,
        domain: String,
        host: String,
        addr: std::net::SocketAddr,
        recipients: Vec<(EmailAddress, DsnRecipientParams)>,
        tls_connector: Option<SharedTlsConnector>,
    ) {
        let hostname = self.hostname.clone();
        let sender = self.sender.as_ref().map(|s| s.address());
        let tracker = Arc::clone(&self.tracker);
        let domain_for_cb = domain.clone();

        let timeouts = SmtpClientTimeouts {
            stage: self.smtp_timeout,
            message: self.smtp_timeout * 10,
            ..Default::default()
        };

        let mut send = SmtpSend::new(hostname).on_complete(Box::new(move |ok| {
            tracker.lock().unwrap().record(&domain_for_cb, ok);
        }));
        send = send.mail_from_params(self.mail_params.clone());
        if self.require_tls {
            send = send.require_starttls(true);
        }
        send = match &self.spool_path {
            Some(path) if self.extra_header_lines.is_empty() => send.message_file(path.clone()),
            Some(path) => {
                let mut prefix = Some(render_extra_header_lines(&self.extra_header_lines));
                let path = path.clone();
                let mut file: Option<std::fs::File> = None;
                let mut buf = [0u8; 8192];
                send.message_with(move || {
                    if let Some(p) = prefix.take() {
                        return Some(p);
                    }
                    let f = match file.as_mut() {
                        Some(f) => f,
                        None => {
                            file = std::fs::File::open(&path).ok();
                            file.as_mut()?
                        }
                    };
                    let n = f.read(&mut buf).ok()?;
                    if n == 0 {
                        return None;
                    }
                    Some(buf[..n].to_vec())
                })
            }
            None => send.message_empty(),
        };

        if let Some(s) = sender {
            send = send.mail_from(s);
        }
        for (addr, params) in &recipients {
            send = send.rcpt_to_with(addr.address(), params.clone());
        }

        let mut client = SmtpClient::from_addr(addr);
        if self.require_tls {
            if let Some(connector) = tls_connector {
                client = client.starttls(connector, host);
            }
        }

        let result = client
            .timeouts(timeouts)
            .connect(&self.runtime, Arc::new(send));

        if result.is_err() {
            self.fail_current(&domain);
            return;
        }

        self.current += 1;
        self.deliver_next();
    }
}

/// Builds and sends a failure DSN for a message that never reaches the
/// per-domain delivery stage (e.g. DELIVERBY deadline already exceeded).
/// The spool read is offloaded (issue #184) — `handle` bounces the
/// completion back to the reactor thread that owns it.
fn maybe_send_failure_dsn(
    hostname: &str,
    sender: Option<&EmailAddress>,
    delivery: &DeliveryRequirements,
    recipients: &[(EmailAddress, DsnRecipientParams)],
    spool_path: Option<PathBuf>,
    diagnostic: &str,
    dns: &Arc<DnsResolver>,
    runtime: &Arc<Runtime>,
    smtp_timeout: Duration,
    outbound_port: u16,
    tls_connector: Option<SharedTlsConnector>,
    handle: ConnHandle,
) {
    let Some(sender) = sender else {
        return;
    };
    let reports: Vec<_> = recipients
        .iter()
        .filter(|(_, p)| p.notify.wants_failure())
        .map(|(addr, params)| DsnRecipientReport {
            final_recipient: addr.address(),
            original_recipient: orcpt_field(params),
            action: DsnAction::Failed,
            diagnostic: Some(diagnostic.into()),
        })
        .collect();
    if reports.is_empty() {
        return;
    }
    let sender = sender.clone();
    let sender_for_op = sender.clone();
    let hostname_owned = hostname.to_string();
    let hostname_for_op = hostname_owned.clone();
    let delivery = delivery.clone();
    let dns = Arc::clone(dns);
    let runtime2 = Arc::clone(runtime);
    let tls_connector2 = tls_connector.clone();
    let require_tls = delivery.is_require_tls();

    runtime.storage().submit_on(
        handle,
        move || -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
            let original = spool_path
                .and_then(|p| std::fs::read(p).ok())
                .unwrap_or_default();
            let dsn = DeliveryStatusNotification {
                reporting_mta: hostname_for_op,
                reverse_path: Some(sender_for_op),
                delivery,
                recipients: reports,
                original_message: original,
            };
            Ok(dsn.render())
        },
        move |result: Result<Option<Vec<u8>>, StorageError>| {
            if let Ok(Some(bytes)) = result {
                send_dsn_message(
                    &bytes,
                    &sender,
                    &hostname_owned,
                    &dns,
                    &runtime2,
                    smtp_timeout,
                    outbound_port,
                    tls_connector2,
                    require_tls,
                );
            }
        },
    );
}

fn send_dsn_message(
    message: &[u8],
    reverse_path: &EmailAddress,
    hostname: &str,
    dns: &Arc<DnsResolver>,
    runtime: &Arc<Runtime>,
    smtp_timeout: Duration,
    outbound_port: u16,
    tls_connector: Option<SharedTlsConnector>,
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
            let host_for_tls = host.clone();
            dns2.resolve(
                &host,
                outbound_port,
                Box::new(move |result| {
                    let Ok(addrs) = result else {
                        return;
                    };
                    let Some(&addr) = addrs.first() else {
                        return;
                    };
                    let timeouts = SmtpClientTimeouts {
                        stage: smtp_timeout,
                        message: smtp_timeout * 10,
                        ..Default::default()
                    };
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
                    let mut client = SmtpClient::from_addr(addr);
                    if require_tls {
                        if let Some(connector) = tls_connector {
                            client = client.starttls(connector, host_for_tls);
                        }
                    }
                    let _ = client.timeouts(timeouts).connect(&runtime, Arc::new(send));
                }),
            );
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::handler::DeferredSlot;
    use hopf_core::RuntimeConfig;
    use std::sync::Mutex as StdMutex;

    #[test]
    fn group_by_domain_buckets_case_insensitively() {
        let recipients = vec![
            (
                EmailAddress::new(None, "a", "Example.com", true),
                DsnRecipientParams::default(),
            ),
            (
                EmailAddress::new(None, "b", "example.COM", true),
                DsnRecipientParams::default(),
            ),
            (
                EmailAddress::new(None, "c", "other.example", true),
                DsnRecipientParams::default(),
            ),
        ];
        let groups = group_by_domain(&recipients);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.get("example.com").map(Vec::len), Some(2));
        assert_eq!(groups.get("other.example").map(Vec::len), Some(1));
    }

    fn test_runtime_and_handle() -> (Arc<Runtime>, ConnHandle) {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let handle = ConnHandle::from_execute(Arc::new(|task| task()));
        (rt, handle)
    }

    fn dummy_relay_handler(dns: Arc<DnsResolver>, runtime: Arc<Runtime>) -> SimpleRelayHandler {
        SimpleRelayHandler {
            dns,
            runtime,
            hostname: "test.example.com".to_string(),
            smtp_timeout: Duration::from_secs(5),
            outbound_port: 25,
            tls_connector: None,
            control_handle: None,
            inbound_tls: false,
            sender: None,
            delivery: DeliveryRequirements::default(),
            recipients: Vec::new(),
            spool: None,
            extra_header_lines: Vec::new(),
        }
    }

    /// Spin-wait up to `max_ms` for `pred` to return true.
    fn wait_for(pred: impl Fn() -> bool, max_ms: u64) -> bool {
        for _ in 0..(max_ms / 5).max(1) {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        pred()
    }

    /// Issue #184: `finish()`'s spool read+remove is offloaded off the
    /// reactor thread, and the deferred SMTP reply must not complete until
    /// that offloaded work actually lands.
    #[test]
    fn finish_removes_spool_file_and_completes_deferred_after_offload() {
        let (rt, handle) = test_runtime_and_handle();
        let dns = Arc::new(DnsResolver::for_runtime(&rt).unwrap());

        let spool_path = std::env::temp_dir().join(format!(
            "hopf-smtp-relay-finish-test-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&spool_path, b"Subject: hi\r\n\r\nbody\r\n").unwrap();

        let slot = Arc::new(StdMutex::new(Some(DeferredSlot {
            resume: Box::new(dummy_relay_handler(Arc::clone(&dns), Arc::clone(&rt))),
            outcome: None,
        })));
        let deferred = DeferredDelivery::new(handle.clone(), Arc::clone(&slot));

        let tracker = Arc::new(Mutex::new(DeliveryTracker {
            deferred: Some(deferred),
            remaining: 0,
            any_success: true,
            spool_path: Some(spool_path.clone()),
            hostname: "test.example.com".to_string(),
            // No sender means no DSN to build/send — isolates this test to
            // the read/remove/deferred-completion race, without needing a
            // live DNS/SMTP round trip.
            sender: None,
            delivery: DeliveryRequirements::default(),
            recipients: Vec::new(),
            domain_results: HashMap::new(),
            dns,
            runtime: Arc::clone(&rt),
            smtp_timeout: Duration::from_secs(5),
            outbound_port: 25,
            tls_connector: None,
            dsn_sent: false,
            control_handle: handle,
        }));

        tracker.lock().unwrap().finish();

        assert!(
            wait_for(|| !spool_path.exists(), 2000),
            "spool file must be removed once finish()'s offloaded job completes"
        );
        assert!(
            wait_for(
                || slot.lock().unwrap().as_ref().unwrap().outcome.is_some(),
                2000
            ),
            "deferred reply must complete once finish()'s offloaded job lands"
        );
    }

    /// `build_dsn_reports` (in-memory, no I/O) must report exactly the
    /// recipients whose domain failed and who asked for a failure notice,
    /// and must be idempotent (issue #184's `dsn_sent` latch).
    #[test]
    fn build_dsn_reports_covers_failed_domains_and_is_idempotent() {
        let (rt, handle) = test_runtime_and_handle();
        let dns = Arc::new(DnsResolver::for_runtime(&rt).unwrap());
        let sender = EmailAddress::new(None, "from", "sender.example", true);
        let ok_recipient = EmailAddress::new(None, "ok", "good.example", true);
        let failed_recipient = EmailAddress::new(None, "bad", "down.example", true);

        let mut domain_results = HashMap::new();
        domain_results.insert("good.example".to_string(), true);
        domain_results.insert("down.example".to_string(), false);

        let mut tracker = DeliveryTracker {
            deferred: None,
            remaining: 0,
            any_success: true,
            spool_path: None,
            hostname: "test.example.com".to_string(),
            sender: Some(sender),
            delivery: DeliveryRequirements::default(),
            recipients: vec![
                (ok_recipient, DsnRecipientParams::default()),
                (failed_recipient.clone(), DsnRecipientParams::default()),
            ],
            domain_results,
            dns,
            runtime: rt,
            smtp_timeout: Duration::from_secs(5),
            outbound_port: 25,
            tls_connector: None,
            dsn_sent: false,
            control_handle: handle,
        };

        let (_sender, reports) = tracker
            .build_dsn_reports()
            .expect("a failed domain with default NOTIFY wants a failure report");
        assert_eq!(reports.len(), 1, "only the failed recipient is reported: {reports:?}");
        assert_eq!(reports[0].final_recipient, failed_recipient.address());
        assert_eq!(reports[0].action, DsnAction::Failed);

        assert!(
            tracker.build_dsn_reports().is_none(),
            "must not build/send a second DSN for the same tracker"
        );
    }
}
