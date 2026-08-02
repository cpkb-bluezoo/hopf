// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`SimpleRelayHandler`] — spool message, MX lookup, deliver via async
//! [`SmtpClient`], streamed from the spool to each destination.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Runtime, SharedTlsConnector};
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
}

impl SmtpClientConnected for SimpleRelayHandler {
    fn connected(&mut self, state: &mut dyn ConnectedState, meta: &SmtpConnectionMetadata) {
        self.inbound_tls = meta.tls;
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
                    spool_path.as_deref(),
                    "DELIVERBY deadline exceeded before relay",
                    &self.dns,
                    &self.runtime,
                    self.smtp_timeout,
                    self.outbound_port,
                    self.tls_connector.clone(),
                );
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

        let deferred = state.defer(Box::new(self.clone()));
        let addrs: Vec<EmailAddress> = self.recipients.iter().map(|(a, _)| a.clone()).collect();
        let by_domain = group_by_domain(&addrs);
        let domains: Vec<String> = by_domain.keys().cloned().collect();
        let tracker = Arc::new(Mutex::new(DeliveryTracker {
            deferred: Some(deferred),
            remaining: domains.len(),
            any_success: false,
            any_fail: false,
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

fn group_by_domain(recipients: &[EmailAddress]) -> HashMap<String, Vec<EmailAddress>> {
    let mut map = HashMap::new();
    for r in recipients {
        let domain = r.domain().to_ascii_lowercase();
        map.entry(domain).or_insert_with(Vec::new).push(r.clone());
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
    any_fail: bool,
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
}

impl DeliveryTracker {
    /// Record one domain's outcome. Once every domain has reported, issues
    /// the final reply: reject if *any* domain failed — even if others
    /// already succeeded — rather than tracking per-recipient state to
    /// retry only the failed ones. A client that retries after a 4xx may
    /// therefore re-deliver to domains that already got the message; that
    /// tradeoff (accepted over adding a durable, cross-attempt spool) mirrors
    /// the one `LocalDeliveryHandler` already makes for its own multi-recipient
    /// case.
    fn record(&mut self, domain: &str, ok: bool) {
        self.domain_results.insert(domain.to_string(), ok);
        if ok {
            self.any_success = true;
        } else {
            self.any_fail = true;
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

    fn finish(&mut self) {
        self.emit_dsn_if_needed();
        if let Some(path) = self.spool_path.take() {
            let _ = std::fs::remove_file(path);
        }
        let Some(deferred) = self.deferred.take() else {
            return;
        };
        if self.any_fail {
            deferred.reject_temporary("Delivery failed to one or more recipient domains");
        } else if self.any_success {
            deferred.accept(None);
        } else {
            deferred.reject_temporary("No recipient domains could be resolved");
        }
    }

    fn emit_dsn_if_needed(&mut self) {
        if self.dsn_sent {
            return;
        }
        self.dsn_sent = true;
        let Some(sender) = self.sender.clone() else {
            return;
        };
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
            return;
        }
        let original = self
            .spool_path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .unwrap_or_default();
        let dsn = DeliveryStatusNotification {
            reporting_mta: self.hostname.clone(),
            reverse_path: Some(sender),
            delivery: self.delivery.clone(),
            recipients: reports,
            original_message: original,
        };
        if let Some(bytes) = dsn.render() {
            send_dsn_message(
                &bytes,
                dsn.reverse_path.as_ref().unwrap(),
                &self.hostname,
                &self.dns,
                &self.runtime,
                self.smtp_timeout,
                self.outbound_port,
                self.tls_connector.clone(),
                self.delivery.is_require_tls(),
            );
        }
    }
}

struct DeliveryContext {
    tracker: Arc<Mutex<DeliveryTracker>>,
    domains: Vec<String>,
    recipients_by_domain: HashMap<String, Vec<EmailAddress>>,
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

    fn deliver_to_host(self, domain: String, host: String, recipients: Vec<EmailAddress>) {
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
        recipients: Vec<EmailAddress>,
        tls_connector: Option<SharedTlsConnector>,
    ) {
        let hostname = self.hostname.clone();
        let sender = self.sender.as_ref().map(|s| s.address());
        let recipient_addrs: Vec<String> = recipients.iter().map(|r| r.address()).collect();
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
        for r in recipient_addrs {
            send = send.rcpt_to(r);
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

fn maybe_send_failure_dsn(
    hostname: &str,
    sender: Option<&EmailAddress>,
    delivery: &DeliveryRequirements,
    recipients: &[(EmailAddress, DsnRecipientParams)],
    spool_path: Option<&std::path::Path>,
    diagnostic: &str,
    dns: &Arc<DnsResolver>,
    runtime: &Arc<Runtime>,
    smtp_timeout: Duration,
    outbound_port: u16,
    tls_connector: Option<SharedTlsConnector>,
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
    let original = spool_path.and_then(|p| std::fs::read(p).ok()).unwrap_or_default();
    let dsn = DeliveryStatusNotification {
        reporting_mta: hostname.into(),
        reverse_path: Some(sender.clone()),
        delivery: delivery.clone(),
        recipients: reports,
        original_message: original,
    };
    if let Some(bytes) = dsn.render() {
        send_dsn_message(
            &bytes,
            sender,
            hostname,
            dns,
            runtime,
            smtp_timeout,
            outbound_port,
            tls_connector,
            delivery.is_require_tls(),
        );
    }
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

    #[test]
    fn group_by_domain_buckets_case_insensitively() {
        let recipients = vec![
            EmailAddress::new(None, "a", "Example.com", true),
            EmailAddress::new(None, "b", "example.COM", true),
            EmailAddress::new(None, "c", "other.example", true),
        ];
        let groups = group_by_domain(&recipients);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.get("example.com").map(Vec::len), Some(2));
        assert_eq!(groups.get("other.example").map(Vec::len), Some(1));
    }
}
