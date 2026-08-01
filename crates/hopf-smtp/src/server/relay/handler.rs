// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`SimpleRelayHandler`] — spool message, MX lookup, deliver via async
//! [`SmtpClient`], streamed from the spool to each destination.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::Runtime;
use hopf_dns::DnsResolver;
use rmimeparser::EmailAddress;

use crate::client::{SmtpClient, SmtpClientTimeouts, SmtpSend};
use crate::server::delivery::{DeliveryRequirements, DsnRecipientParams};
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
    sender: Option<EmailAddress>,
    delivery: DeliveryRequirements,
    recipients: Vec<EmailAddress>,
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

    fn tls_established(&mut self, _info: &hopf_core::SecurityInfo) {}

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

        let deferred = state.defer(Box::new(self.clone()));
        let by_domain = group_by_domain(&self.recipients);
        let domains: Vec<String> = by_domain.keys().cloned().collect();
        let tracker = Arc::new(Mutex::new(DeliveryTracker {
            deferred: Some(deferred),
            remaining: domains.len(),
            any_success: false,
            any_fail: false,
            spool_path: spool_path.clone(),
        }));
        if domains.is_empty() {
            // No recipients survived grouping (shouldn't happen — RCPT TO
            // already required at least one — but stay safe).
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
            dns: Arc::clone(&self.dns),
            runtime: Arc::clone(&self.runtime),
            hostname: self.hostname.clone(),
            smtp_timeout: self.smtp_timeout,
            outbound_port: self.outbound_port,
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
    fn record(&mut self, ok: bool) {
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
}

// ── Async delivery context ────────────────────────────────────────────────────

/// Iterates destination domains (MX lookup → connect → hand off to
/// [`SmtpSend`]); `self` is consumed and rebuilt across each async DNS/connect
/// step exactly like the pre-streaming version, but domain *outcomes* now
/// flow independently to the shared [`DeliveryTracker`] instead of being
/// folded into this struct — so `deliver_next()` can move on to resolving
/// the next domain without waiting for the current one's SMTP delivery to
/// actually finish, while still reporting the real result once it does.
struct DeliveryContext {
    tracker: Arc<Mutex<DeliveryTracker>>,
    domains: Vec<String>,
    recipients_by_domain: HashMap<String, Vec<EmailAddress>>,
    spool_path: Option<PathBuf>,
    extra_header_lines: Vec<String>,
    sender: Option<EmailAddress>,
    require_tls: bool,
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    hostname: String,
    smtp_timeout: Duration,
    outbound_port: u16,
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
                    let recipients_len = recipients.len();
                    self.fail_current(recipients_len);
                }
            }),
        );
    }

    fn fail_current(mut self, _recipients_len: usize) {
        self.tracker.lock().unwrap().record(false);
        self.current += 1;
        self.deliver_next();
    }

    fn deliver_to_host(self, host: String, recipients: Vec<EmailAddress>) {
        let require_tls = self.require_tls;
        let port = self.outbound_port;
        let dns = Arc::clone(&self.dns);

        if require_tls {
            // Full STARTTLS to arbitrary MX needs trust roots; bounce for now.
            self.fail_current(recipients.len());
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
                    let recipients_len = recipients.len();
                    self.fail_current(recipients_len);
                }
            }),
        );
    }

    fn deliver_smtp(mut self, addr: std::net::SocketAddr, recipients: Vec<EmailAddress>) {
        let hostname = self.hostname.clone();
        let sender = self.sender.as_ref().map(|s| s.address());
        let recipient_addrs: Vec<String> = recipients.iter().map(|r| r.address()).collect();
        let tracker = Arc::clone(&self.tracker);

        let timeouts = SmtpClientTimeouts {
            stage: self.smtp_timeout,
            message: self.smtp_timeout * 10,
            ..Default::default()
        };

        let mut send = SmtpSend::new(hostname).on_complete(Box::new(move |ok| {
            tracker.lock().unwrap().record(ok);
        }));
        send = match &self.spool_path {
            // Streamed straight off the spool file per destination — the
            // message is never cloned into a fresh in-memory buffer per MX,
            // unlike before. When there are extra header lines to prepend
            // (see `extra_header_lines`), yield those first (small, bounded)
            // then continue streaming the spool file — still never more
            // than one chunk held in memory at a time.
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

        let result = SmtpClient::from_addr(addr)
            .timeouts(timeouts)
            .connect(&self.runtime, Arc::new(send));

        if result.is_err() {
            self.fail_current(recipients.len());
            return;
        }

        // Connection accepted for delivery; that domain's real outcome now
        // arrives asynchronously via the `on_complete` callback above, which
        // reports straight to the shared tracker. Move on to the next
        // domain immediately — deliveries to different domains proceed
        // concurrently.
        self.current += 1;
        self.deliver_next();
    }
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
