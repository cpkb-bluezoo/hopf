// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The relay's delivery engine: it owns the [`RelayQueue`], decides when each
//! queued message is next tried, delivers it, and settles what happened to
//! each recipient.
//!
//! A message is accepted from the inbound client only once it is in the queue
//! (RFC 5321 section 6.1: from then on the relay is responsible for it). A
//! delivery attempt takes the recipients that are due, groups them by domain,
//! and for each domain walks the MX hosts. The next hop's replies are kept
//! per recipient (see [`SmtpSend::on_recipients`]), and each recipient ends
//! the attempt in one of three states (RFC 5321 section 4.5.4.1):
//!
//! - delivered: the next hop took the message for it;
//! - temporary (a 4xx, or no reply at all): it stays queued and is tried
//!   again after a backoff, until the queue lifetime runs out;
//! - permanent (a 5xx): it is bounced at once.
//!
//! Notices to the sender (RFC 3461) are themselves put in the queue, so they
//! are as durable and as retried as any other message.

use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use hopf_core::retry::RetryPolicy;
use hopf_core::{ConnHandle, Runtime, SharedTlsConnector, StorageError};
use hopf_dns::wire::RCODE_NXDOMAIN;
use hopf_dns::DnsResolver;
use rmimeparser::EmailAddress;

use crate::client::{
    smtp_retry_policy, MailFromParams, SmtpClient, SmtpClientTimeouts, SmtpSend, SmtpSendOutcome,
};
use crate::server::delivery::{DeliveryRequirements, DsnRecipientParams};
use crate::server::dsn::{orcpt_field, DeliveryStatusNotification, DsnAction, DsnRecipientReport};

use super::dane;
use super::queue::{QueuedMessage, QueuedRecipient, RecipientStatus, RelayQueue};

/// How the relay queues and retries mail.
#[derive(Debug, Clone)]
pub struct RelayOptions {
    queue_dir: Option<PathBuf>,
    retry: RetryPolicy,
    max_lifetime: Duration,
    delay_notice_after: Duration,
}

impl Default for RelayOptions {
    /// A private temporary queue directory (not kept across restarts),
    /// [`smtp_retry_policy`] backoff, five days in the queue, and a delay
    /// notice to the sender after four hours.
    fn default() -> Self {
        Self {
            queue_dir: None,
            retry: smtp_retry_policy(),
            max_lifetime: Duration::from_secs(5 * 24 * 60 * 60),
            delay_notice_after: Duration::from_secs(4 * 60 * 60),
        }
    }
}

impl RelayOptions {
    /// Keep the queue in `dir`. Messages found there when the relay starts
    /// are delivered, so mail accepted before a restart is not lost.
    pub fn with_queue_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.queue_dir = Some(dir.into());
        self
    }

    /// The delay before each retry. Only the delays are used;
    /// [`Self::with_max_queue_lifetime`] says when to give up.
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// How long a message may be queued before a recipient that is still
    /// waiting makes the relay tell the sender, once, that delivery is
    /// delayed and being retried (a DSN with `Action: delayed`, if the sender
    /// asked for delay notices, which RFC 3461 makes the default).
    pub fn with_delay_notice_after(mut self, after: Duration) -> Self {
        self.delay_notice_after = after;
        self
    }

    /// How long a message may stay undelivered before the recipients still
    /// waiting are bounced (RFC 5321 section 4.5.4.1 suggests 4-5 days).
    pub fn with_max_queue_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_lifetime = lifetime;
        self
    }
}

/// What one delivery attempt found out about one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Delivered,
    /// Try again later; carries what the next hop said.
    Temporary(String),
    /// Never going to work; carries what the next hop said.
    Permanent(String),
}

/// The verdict a next-hop outcome gives, or `None` when there was no reply
/// to go by (a connection that failed or dropped), in which case another MX
/// host may still take the recipient.
fn verdict_for(outcome: &SmtpSendOutcome) -> Option<Verdict> {
    match outcome {
        SmtpSendOutcome::Delivered => Some(Verdict::Delivered),
        SmtpSendOutcome::Rejected { code, message } => {
            let said = format!("{code} {}", message.trim());
            Some(if (400..500).contains(code) { Verdict::Temporary(said) } else { Verdict::Permanent(said) })
        }
        SmtpSendOutcome::Failed(_) => None,
    }
}

/// The recipients an attempt finished with.
#[derive(Debug, Default, PartialEq, Eq)]
struct Settled {
    delivered: Vec<usize>,
    failed: Vec<usize>,
    /// Still queued, and due a delay notice now.
    delayed: Vec<usize>,
}

/// Fold an attempt's verdicts into the message. A recipient that stays
/// queued is due again after the backoff for its attempt count, but never
/// later than the end of the queue lifetime, so that the last try happens
/// when the lifetime ends and not a whole backoff after it. A recipient that
/// asked for delay notices is also tried when `delay_notice_after` ends, and
/// is noticed then, once.
fn apply_verdicts(
    message: &mut QueuedMessage,
    verdicts: &[Option<Verdict>],
    now: SystemTime,
    retry: &RetryPolicy,
    max_lifetime: Duration,
    delay_notice_after: Duration,
) -> Settled {
    let expiry = message.queued_at + max_lifetime;
    let delay_notice_at = message.queued_at + delay_notice_after;
    let mut settled = Settled::default();
    for (i, verdict) in verdicts.iter().enumerate() {
        let Some(verdict) = verdict else { continue };
        let r = &mut message.recipients[i];
        r.attempts += 1;
        match verdict {
            Verdict::Delivered => {
                r.status = RecipientStatus::Delivered;
                settled.delivered.push(i);
            }
            Verdict::Permanent(said) => {
                r.status = RecipientStatus::Failed;
                r.diagnostic = Some(said.clone());
                settled.failed.push(i);
            }
            Verdict::Temporary(said) if now >= expiry => {
                r.status = RecipientStatus::Failed;
                r.diagnostic = Some(format!("{said} (not delivered within {} seconds)", max_lifetime.as_secs()));
                settled.failed.push(i);
            }
            Verdict::Temporary(said) => {
                r.diagnostic = Some(said.clone());
                r.next_attempt = (now + retry.delay_for_attempt(r.attempts)).min(expiry);
                if r.params.notify.wants_delay() && !r.delay_notified {
                    if now >= delay_notice_at {
                        r.delay_notified = true;
                        settled.delayed.push(i);
                    } else {
                        r.next_attempt = r.next_attempt.min(delay_notice_at);
                    }
                }
            }
        }
    }
    settled
}

/// The notices the sender asked for (RFC 3461 NOTIFY) about the recipients an
/// attempt settled.
fn dsn_reports(message: &QueuedMessage, settled: &Settled) -> Vec<DsnRecipientReport> {
    let mut reports = Vec::new();
    for (i, r) in message.recipients.iter().enumerate() {
        let (action, want) = if settled.delivered.contains(&i) {
            (DsnAction::Delivered, r.params.notify.wants_success())
        } else if settled.failed.contains(&i) {
            (DsnAction::Failed, r.params.notify.wants_failure())
        } else if settled.delayed.contains(&i) {
            (DsnAction::Delayed, r.params.notify.wants_delay())
        } else {
            continue;
        };
        if want {
            reports.push(DsnRecipientReport {
                final_recipient: r.address.clone(),
                original_recipient: orcpt_field(&r.params),
                action,
                diagnostic: if action == DsnAction::Delivered { None } else { r.diagnostic.clone() },
            });
        }
    }
    reports
}

/// Failure notices for recipients that never reached the queue.
fn failure_reports(recipients: &[(String, DsnRecipientParams)], diagnostic: &str) -> Vec<DsnRecipientReport> {
    recipients
        .iter()
        .filter(|(_, p)| p.notify.wants_failure())
        .map(|(address, params)| DsnRecipientReport {
            final_recipient: address.clone(),
            original_recipient: orcpt_field(params),
            action: DsnAction::Failed,
            diagnostic: Some(diagnostic.to_string()),
        })
        .collect()
}

/// An address as the queue stores it, back as an [`EmailAddress`].
fn parse_address(address: &str) -> EmailAddress {
    match address.rsplit_once('@') {
        Some((local, domain)) => EmailAddress::new(None, local, domain, true),
        None => EmailAddress::new(None, address, "", true),
    }
}

/// Recipient indices grouped by domain, in order of first appearance.
fn group_by_domain(message: &QueuedMessage, indices: &[usize]) -> Vec<(String, Vec<usize>)> {
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    for &i in indices {
        let domain = parse_address(&message.recipients[i].address).domain().to_ascii_lowercase();
        match groups.iter_mut().find(|(d, _)| *d == domain) {
            Some((_, members)) => members.push(i),
            None => groups.push((domain, vec![i])),
        }
    }
    groups
}

/// The MAIL FROM parameters for an outbound hop: what the message arrived
/// with that the next server needs to know. `BY` goes on with the time that
/// is left, never the original interval (RFC 2852 section 4.1.4), and not
/// as zero, which would ask for the impossible.
fn outbound_mail_params(delivery: &DeliveryRequirements, smtputf8: bool, now: SystemTime) -> MailFromParams {
    MailFromParams {
        smtputf8,
        require_tls: delivery.is_require_tls(),
        dsn_ret: delivery.dsn_ret,
        dsn_envid: delivery.dsn_envid.clone(),
        priority: delivery.priority,
        deliver_by: delivery.deliver_by.as_ref().map(|by| {
            let left = by.deadline.duration_since(now).unwrap_or_default();
            (left.max(Duration::from_secs(1)), by.return_on_fail)
        }),
        ..Default::default()
    }
}

/// Each line plus a trailing CRLF, concatenated - small and bounded (a
/// handful of header field values), unlike the message body this precedes.
fn render_extra_header_lines(lines: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Build a [`SharedTlsConnector`] that authenticates the peer against
/// `records` via [`hopf_dns::dane::verify_dane_chain`] (issue #352) - used
/// for a DANE-authenticated hop's mandatory STARTTLS.
fn build_dane_connector(records: Vec<hopf_dns::TlsaRecord>) -> SharedTlsConnector {
    hopf_core::connector_with_verify_override(
        Arc::new(move |chain, server_name| hopf_dns::dane::verify_dane_chain(&records, chain, server_name)),
        &[],
    )
}

// The engine --------------------------------------------------------------

/// Shared by every inbound connection of one relay.
pub(super) struct RelayEngine {
    dns: Arc<DnsResolver>,
    runtime: Arc<Runtime>,
    hostname: String,
    smtp_timeout: Duration,
    outbound_port: u16,
    tls_connector: Option<SharedTlsConnector>,
    queue: RelayQueue,
    retry: RetryPolicy,
    max_lifetime: Duration,
    delay_notice_after: Duration,
    /// For storage-pool completions that belong to no connection.
    handle: ConnHandle,
    /// Messages with an attempt running, so a message is never tried twice
    /// at once.
    in_flight: Mutex<HashSet<String>>,
    /// The queue directory, when the engine made it itself: removed on drop
    /// if nothing is left in it.
    owned_dir: Option<PathBuf>,
}

impl Drop for RelayEngine {
    fn drop(&mut self) {
        if let Some(dir) = &self.owned_dir {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

type Done = Box<dyn FnOnce(bool) + Send>;

impl RelayEngine {
    pub(super) fn new(
        dns: Arc<DnsResolver>,
        runtime: Arc<Runtime>,
        hostname: String,
        smtp_timeout: Duration,
        outbound_port: u16,
        tls_connector: Option<SharedTlsConnector>,
        options: RelayOptions,
    ) -> io::Result<Arc<Self>> {
        let (dir, owned_dir) = match options.queue_dir {
            Some(dir) => (dir, None),
            None => {
                let dir = std::env::temp_dir().join(format!("hopf-smtp-relay-{}-{}", std::process::id(), RelayQueue::new_id()));
                (dir.clone(), Some(dir))
            }
        };
        let queue = RelayQueue::open(dir)?;
        let reactor = runtime.pick_worker().clone();
        let handle = ConnHandle::from_execute(Arc::new(move |task| reactor.execute(task)));
        Ok(Arc::new(Self {
            dns,
            runtime,
            hostname,
            smtp_timeout,
            outbound_port,
            tls_connector,
            queue,
            retry: options.retry,
            max_lifetime: options.max_lifetime,
            delay_notice_after: options.delay_notice_after,
            handle,
            in_flight: Mutex::new(HashSet::new()),
            owned_dir,
        }))
    }

    fn warn(&self, key: &'static str, message: String) {
        match self.runtime.telemetry() {
            Some(t) => t.on_warn(&message),
            None => hopf_core::log_warn(key, message),
        }
    }

    /// Deliver what an earlier run left in the queue. Orphaned content is
    /// removed, and envelopes that cannot be read are reported and left for
    /// an operator.
    pub(super) fn resume(self: &Arc<Self>) {
        let engine = Arc::clone(self);
        let job_engine = Arc::clone(self);
        self.runtime.storage().submit_on(
            self.handle.clone(),
            move || -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
                let scan = job_engine.queue.scan()?;
                for orphan in &scan.orphans {
                    let _ = std::fs::remove_file(orphan);
                }
                Ok(scan)
            },
            move |result| match result {
                Ok(scan) => {
                    for (path, why) in scan.unreadable {
                        engine.warn("smtp.relay.queue", format!("cannot read queued message {}: {why}", path.display()));
                    }
                    for message in scan.messages {
                        engine.schedule(message);
                    }
                }
                Err(e) => engine.warn("smtp.relay.queue", format!("cannot read the relay queue: {e}")),
            },
        );
    }

    /// Queue `message`, whose content is in the spool file `spool` (none for
    /// a message with no content), and call `done` on `handle`'s reactor with
    /// whether it is now safely queued. A queued message is then delivered.
    pub(super) fn submit(
        self: &Arc<Self>,
        handle: ConnHandle,
        message: QueuedMessage,
        spool: Option<PathBuf>,
        done: Done,
    ) {
        let engine = Arc::clone(self);
        let job_engine = Arc::clone(self);
        let queued = message.clone();
        self.runtime.storage().submit_on(
            handle,
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let content = match &spool {
                    Some(path) => path.clone(),
                    None => {
                        let empty = job_engine.queue.dir().join(format!("{}.empty.tmp", message.id));
                        std::fs::write(&empty, b"")?;
                        empty
                    }
                };
                if let Err(e) = job_engine.queue.enqueue(&message, &content) {
                    let _ = std::fs::remove_file(&content);
                    return Err(e.into());
                }
                Ok(())
            },
            move |result| {
                let ok = result.is_ok();
                if let Err(e) = result {
                    engine.warn("smtp.relay.queue", format!("cannot queue message: {e}"));
                }
                if ok {
                    engine.schedule(queued);
                }
                done(ok);
            },
        );
    }

    /// Tell the sender that `recipients` will not be delivered, for a message
    /// that is not going to be queued; removes its spool file.
    pub(super) fn bounce(
        self: &Arc<Self>,
        handle: ConnHandle,
        sender: Option<String>,
        delivery: DeliveryRequirements,
        recipients: Vec<(String, DsnRecipientParams)>,
        spool: Option<PathBuf>,
        diagnostic: &str,
    ) {
        let engine = Arc::clone(self);
        let job_engine = Arc::clone(self);
        let reports = failure_reports(&recipients, diagnostic);
        self.runtime.storage().submit_on(
            handle,
            move || -> Result<Option<QueuedMessage>, Box<dyn std::error::Error + Send + Sync>> {
                let original = spool.as_ref().and_then(|p| std::fs::read(p).ok()).unwrap_or_default();
                let notice = match &sender {
                    Some(sender) if !reports.is_empty() => job_engine.enqueue_dsn(sender, &delivery, reports, original),
                    _ => Ok(None),
                };
                if let Some(path) = &spool {
                    let _ = std::fs::remove_file(path);
                }
                Ok(notice?)
            },
            move |result| match result {
                Ok(Some(notice)) => engine.schedule(notice),
                Ok(None) => {}
                Err(e) => engine.warn("smtp.relay.queue", format!("cannot queue a failure notice: {e}")),
            },
        );
    }

    /// Queue a notice (blocking). The notice has the null sender, so a notice
    /// that cannot be delivered is never answered with another.
    fn enqueue_dsn(
        &self,
        sender: &str,
        delivery: &DeliveryRequirements,
        reports: Vec<DsnRecipientReport>,
        original: Vec<u8>,
    ) -> io::Result<Option<QueuedMessage>> {
        let Some(bytes) = (DeliveryStatusNotification {
            reporting_mta: self.hostname.clone(),
            reverse_path: Some(parse_address(sender)),
            delivery: delivery.clone(),
            recipients: reports,
            original_message: original,
        })
        .render() else {
            return Ok(None);
        };
        let now = SystemTime::now();
        let notice = QueuedMessage {
            id: RelayQueue::new_id(),
            queued_at: now,
            sender: None,
            smtputf8: false,
            delivery: DeliveryRequirements { require_tls: delivery.require_tls, ..Default::default() },
            extra_header_lines: Vec::new(),
            recipients: vec![QueuedRecipient::new(sender, DsnRecipientParams::default(), now)],
        };
        let temp = self.queue.dir().join(format!("{}.dsn.tmp", notice.id));
        std::fs::write(&temp, bytes)?;
        if let Err(e) = self.queue.enqueue(&notice, &temp) {
            let _ = std::fs::remove_file(&temp);
            return Err(e);
        }
        Ok(Some(notice))
    }

    /// Arrange for `message` to be tried when its earliest recipient is due.
    fn schedule(self: &Arc<Self>, message: QueuedMessage) {
        let Some(due) = message.next_due() else {
            return;
        };
        let delay = due.duration_since(SystemTime::now()).unwrap_or_default();
        let engine = Arc::clone(self);
        let run: Box<dyn FnOnce() + Send> = Box::new(move || engine.attempt(message));
        if delay.is_zero() {
            self.handle.execute(run);
        } else {
            self.runtime.pick_worker().schedule_timer(delay, run);
        }
    }

    /// One delivery attempt for the recipients of `message` that are due.
    fn attempt(self: &Arc<Self>, message: QueuedMessage) {
        if !self.in_flight.lock().unwrap().insert(message.id.clone()) {
            return;
        }
        let now = SystemTime::now();
        let due: Vec<usize> = message
            .recipients
            .iter()
            .enumerate()
            .filter(|(_, r)| r.status == RecipientStatus::Pending && r.next_attempt <= now)
            .map(|(i, _)| i)
            .collect();
        if due.is_empty() {
            // A timer that went off early: nothing to do yet.
            self.in_flight.lock().unwrap().remove(&message.id);
            self.schedule(message);
            return;
        }
        let mut attempt = Attempt {
            engine: Arc::clone(self),
            groups: group_by_domain(&message, &due),
            current: 0,
            verdicts: vec![None; message.recipients.len()],
            mail_params: outbound_mail_params(&message.delivery, message.smtputf8, now),
            message,
        };
        // RFC 2852: a message past its delivery deadline is not delivered.
        if let Some(by) = &attempt.message.delivery.deliver_by {
            if by.deadline <= now {
                for &i in &due {
                    attempt.verdicts[i] = Some(Verdict::Permanent("DELIVERBY deadline exceeded".into()));
                }
                attempt.settle();
                return;
            }
        }
        attempt.deliver_next();
    }

    /// Record an attempt's outcome: queue the notices the sender asked for,
    /// then save the new state (or remove a finished message), then arrange
    /// the next try. The notices go first so a crash between the two makes a
    /// duplicate notice, not a lost one.
    fn finish_attempt(self: &Arc<Self>, message: QueuedMessage, settled: Settled) {
        let reports = dsn_reports(&message, &settled);
        let engine = Arc::clone(self);
        let job_engine = Arc::clone(self);
        let job_message = message.clone();
        self.runtime.storage().submit_on(
            self.handle.clone(),
            move || -> Result<Option<QueuedMessage>, Box<dyn std::error::Error + Send + Sync>> {
                let notice = match (&job_message.sender, reports.is_empty()) {
                    (Some(sender), false) => {
                        let original = std::fs::read(job_engine.queue.content_path(&job_message.id)).unwrap_or_default();
                        match job_engine.enqueue_dsn(sender, &job_message.delivery, reports, original) {
                            Ok(notice) => notice,
                            Err(e) => {
                                job_engine.warn("smtp.relay.queue", format!("cannot queue a notice for {}: {e}", job_message.id));
                                None
                            }
                        }
                    }
                    _ => None,
                };
                if job_message.is_finished() {
                    job_engine.queue.remove(&job_message.id)?;
                } else {
                    job_engine.queue.update(&job_message)?;
                }
                Ok(notice)
            },
            move |result: Result<Option<QueuedMessage>, StorageError>| {
                engine.in_flight.lock().unwrap().remove(&message.id);
                match result {
                    Ok(Some(notice)) => engine.schedule(notice),
                    Ok(None) => {}
                    Err(e) => engine.warn("smtp.relay.queue", format!("cannot save queued message {}: {e}", message.id)),
                }
                if !message.is_finished() {
                    engine.schedule(message);
                }
            },
        );
    }
}

// One delivery attempt ----------------------------------------------------

/// One pass over the due recipients of a message, a domain at a time. Each
/// step consumes the attempt and hands it to the next, since every step
/// waits on a callback.
struct Attempt {
    engine: Arc<RelayEngine>,
    message: QueuedMessage,
    /// Domains to deliver to, with the indices of their due recipients.
    groups: Vec<(String, Vec<usize>)>,
    current: usize,
    /// By recipient index; `None` for one this attempt did not try.
    verdicts: Vec<Option<Verdict>>,
    mail_params: MailFromParams,
}

impl Attempt {
    fn deliver_next(self) {
        let Some((domain, indices)) = self.groups.get(self.current).cloned() else {
            return self.settle();
        };
        let dns = Arc::clone(&self.engine.dns);
        let implicit_mx = domain.clone();
        dns.query_mx(
            &domain,
            Box::new(move |result| match result {
                Ok(msg) if msg.rcode() == RCODE_NXDOMAIN => {
                    self.finish_group(&indices, Verdict::Permanent(format!("{implicit_mx}: domain does not exist")));
                }
                Ok(msg) => {
                    let mut mx: Vec<(u16, String)> = msg.answers.iter().filter_map(|rr| rr.as_mx()).collect();
                    mx.sort_by_key(|(pref, _)| *pref);
                    let mut hosts: Vec<String> =
                        mx.into_iter().map(|(_, ex)| ex.trim_end_matches('.').to_string()).collect();
                    if hosts.is_empty() {
                        // RFC 5321 section 5.1: no MX records at all - try the
                        // domain name itself as an implicit MX.
                        hosts.push(implicit_mx);
                    }
                    self.deliver_to_mx(hosts, 0, indices, String::new());
                }
                Err(_) => {
                    self.finish_group(&indices, Verdict::Temporary(format!("{implicit_mx}: MX lookup failed")));
                }
            }),
        );
    }

    /// Give `indices` this verdict and go on to the next domain.
    fn finish_group(mut self, indices: &[usize], verdict: Verdict) {
        for &i in indices {
            self.verdicts[i] = Some(verdict.clone());
        }
        self.current += 1;
        self.deliver_next();
    }

    /// Try MX host `hosts[mx_index]` for `indices`. Recipients that got no
    /// reply at all go on to the next host (RFC 5321 section 5.1, and RFC
    /// 7672's DANE fallback); once the hosts are used up they are
    /// temporarily undelivered, with `last` (why the last host failed).
    fn deliver_to_mx(self, hosts: Vec<String>, mx_index: usize, indices: Vec<usize>, last: String) {
        let Some(host) = hosts.get(mx_index).cloned() else {
            let why = if last.is_empty() { "no mail exchanger could be reached".to_string() } else { last };
            return self.finish_group(&indices, Verdict::Temporary(why));
        };
        let dns = Arc::clone(&self.engine.dns);
        let port = self.engine.outbound_port;
        let host_query = host.clone();
        dns.resolve(
            &host_query,
            port,
            Box::new(move |result| match result {
                Ok(addrs) if !addrs.is_empty() => self.resolve_tls_and_deliver(hosts, mx_index, addrs[0], indices),
                _ => self.deliver_to_mx(hosts, mx_index + 1, indices, format!("cannot resolve {host}")),
            }),
        );
    }

    /// Decides what TLS policy applies to this hop, then dials.
    ///
    /// A message-level `REQUIRETLS` (RFC 8689) hop uses the admin-configured,
    /// already-trusted connector, mandatory STARTTLS, and no DANE lookup -
    /// a different, separately-authenticated requirement. Otherwise DANE
    /// applies if usable (issue #352/#353): look up TLSA for
    /// `_<port>._tcp.<host>`, and if DNSSEC-Secure records exist, require
    /// STARTTLS and authenticate against them; if not usable, fall back to
    /// ordinary opportunistic STARTTLS (upgrade if offered, plaintext
    /// otherwise, never authenticated, since there is nothing trustworthy to
    /// check the certificate against).
    fn resolve_tls_and_deliver(self, hosts: Vec<String>, mx_index: usize, addr: std::net::SocketAddr, indices: Vec<usize>) {
        if self.message.delivery.is_require_tls() {
            if self.engine.tls_connector.is_none() {
                return self.finish_group(
                    &indices,
                    Verdict::Permanent("REQUIRETLS asked for, but this relay has no TLS connector configured".into()),
                );
            }
            let connector = self.engine.tls_connector.clone();
            return self.deliver_smtp(hosts, mx_index, addr, indices, connector, true, false);
        }
        let dns = Arc::clone(&self.engine.dns);
        let port = self.engine.outbound_port;
        let host = hosts[mx_index].clone();
        dane::lookup_dane_usability(
            &dns,
            &host,
            port,
            Box::new(move |usability| {
                let (connector, mandatory, opportunistic) = match usability {
                    dane::DaneUsability::Usable(records) => (Some(build_dane_connector(records)), true, false),
                    dane::DaneUsability::NotUsable => (Some(hopf_core::insecure_connector(&[])), false, true),
                };
                self.deliver_smtp(hosts, mx_index, addr, indices, connector, mandatory, opportunistic);
            }),
        );
    }

    /// Dials `addr` and sends the message to `indices`. `mandatory_tls` and
    /// `opportunistic_tls` map to [`SmtpSend::require_starttls`] and
    /// [`SmtpSend::opportunistic_starttls`] (mutually exclusive by
    /// construction in [`Self::resolve_tls_and_deliver`]).
    #[allow(clippy::too_many_arguments)]
    fn deliver_smtp(
        self,
        hosts: Vec<String>,
        mx_index: usize,
        addr: std::net::SocketAddr,
        indices: Vec<usize>,
        connector: Option<SharedTlsConnector>,
        mandatory_tls: bool,
        opportunistic_tls: bool,
    ) {
        let engine = Arc::clone(&self.engine);
        let host = hosts[mx_index].clone();
        let timeouts = SmtpClientTimeouts {
            stage: engine.smtp_timeout,
            message: engine.smtp_timeout * 10,
            ..Default::default()
        };

        let mut send = SmtpSend::new(engine.hostname.clone()).mail_from_params(self.mail_params.clone());
        if mandatory_tls {
            send = send.require_starttls(true);
        } else if opportunistic_tls {
            send = send.opportunistic_starttls(true);
        }
        let content = engine.queue.content_path(&self.message.id);
        send = if self.message.extra_header_lines.is_empty() {
            send.message_file(content)
        } else {
            // The rendered extra header lines go ahead of the file's content,
            // through the same offloaded file read (issue #212).
            send.message_file_with_prefix(content, render_extra_header_lines(&self.message.extra_header_lines))
        };
        if let Some(sender) = &self.message.sender {
            send = send.mail_from(sender.clone());
        }
        for &i in &indices {
            let r = &self.message.recipients[i];
            send = send.rcpt_to_with(r.address.clone(), r.params.clone());
        }

        let each: Arc<Mutex<Option<Vec<SmtpSendOutcome>>>> = Arc::new(Mutex::new(None));
        let each_for_report = Arc::clone(&each);
        let count = indices.len();
        let slot = Arc::new(Mutex::new(Some((self, hosts, indices))));
        let slot_for_result = Arc::clone(&slot);
        send = send
            .on_recipients(Box::new(move |outcomes| {
                *each_for_report.lock().unwrap() = Some(outcomes.into_iter().map(|r| r.outcome).collect());
            }))
            .on_result(Box::new(move |outcome| {
                let outcomes = each.lock().unwrap().take().unwrap_or_else(|| vec![outcome; count]);
                let taken = slot_for_result.lock().unwrap().take();
                if let Some((attempt, hosts, indices)) = taken {
                    attempt.after_host(hosts, mx_index, indices, outcomes);
                }
            }));

        let mut client = SmtpClient::from_addr(addr);
        if let Some(connector) = connector {
            client = client.starttls(connector, host);
        }
        if let Err(e) = client.timeouts(timeouts).connect(&engine.runtime, Arc::new(send)) {
            // The dial could not even be set up, so the result callback above
            // will not fire: take the next host directly.
            let taken = slot.lock().unwrap().take();
            if let Some((attempt, hosts, indices)) = taken {
                let failed = vec![SmtpSendOutcome::Failed(e.to_string()); count];
                attempt.after_host(hosts, mx_index, indices, failed);
            }
        }
    }

    /// What a host said, per recipient (in the order of `indices`). A reply is
    /// final for the recipient it concerns: any working MX host would give
    /// the same verdict (issue #353), so it is not asked again. Recipients
    /// with no reply go on to the next host.
    fn after_host(mut self, hosts: Vec<String>, mx_index: usize, indices: Vec<usize>, outcomes: Vec<SmtpSendOutcome>) {
        let mut unsettled = Vec::new();
        let mut last = String::new();
        for (&i, outcome) in indices.iter().zip(&outcomes) {
            match verdict_for(outcome) {
                Some(verdict) => self.verdicts[i] = Some(verdict),
                None => {
                    if last.is_empty() {
                        last = match outcome {
                            SmtpSendOutcome::Failed(why) if !why.is_empty() => why.clone(),
                            _ => format!("no reply from {}", hosts[mx_index]),
                        };
                    }
                    unsettled.push(i);
                }
            }
        }
        if unsettled.is_empty() {
            self.current += 1;
            self.deliver_next();
        } else {
            self.deliver_to_mx(hosts, mx_index + 1, unsettled, last);
        }
    }

    fn settle(self) {
        let Attempt { engine, mut message, verdicts, .. } = self;
        let settled = apply_verdicts(
            &mut message,
            &verdicts,
            SystemTime::now(),
            &engine.retry,
            engine.max_lifetime,
            engine.delay_notice_after,
        );
        engine.finish_attempt(message, settled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::delivery::{DeliverBy, DsnNotify};

    fn at(s: u64) -> SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(s)
    }

    fn rcpt(address: &str, notify: DsnNotify) -> QueuedRecipient {
        QueuedRecipient::new(address, DsnRecipientParams { notify, ..Default::default() }, at(1000))
    }

    fn message(recipients: Vec<QueuedRecipient>) -> QueuedMessage {
        QueuedMessage {
            id: "aaaa".into(),
            queued_at: at(1000),
            sender: Some("alice@sender.example".into()),
            smtputf8: false,
            delivery: DeliveryRequirements::default(),
            extra_header_lines: Vec::new(),
            recipients,
        }
    }

    fn policy() -> RetryPolicy {
        RetryPolicy::exponential_backoff()
            .with_initial_delay(Duration::from_secs(60))
            .with_max_delay(Duration::from_secs(600))
            .with_jitter(0.0)
    }

    const DAY: Duration = Duration::from_secs(86_400);
    /// A delay-notice interval that is never reached in a test.
    const LATER: Duration = Duration::from_secs(4 * 86_400);

    fn temporary(said: &str) -> Option<Verdict> {
        Some(Verdict::Temporary(said.into()))
    }

    #[test]
    fn a_reply_is_a_verdict_and_no_reply_is_not() {
        assert_eq!(verdict_for(&SmtpSendOutcome::Delivered), Some(Verdict::Delivered));
        let rejected = |code| SmtpSendOutcome::Rejected { code, message: " mailbox busy ".into() };
        assert_eq!(verdict_for(&rejected(451)), Some(Verdict::Temporary("451 mailbox busy".into())));
        assert_eq!(verdict_for(&rejected(499)), Some(Verdict::Temporary("499 mailbox busy".into())));
        assert_eq!(verdict_for(&rejected(550)), Some(Verdict::Permanent("550 mailbox busy".into())));
        assert_eq!(verdict_for(&rejected(554)), Some(Verdict::Permanent("554 mailbox busy".into())));
        assert_eq!(verdict_for(&SmtpSendOutcome::Failed("reset".into())), None);
    }

    #[test]
    fn a_temporary_refusal_keeps_the_recipient_queued_and_backs_off() {
        let mut m = message(vec![rcpt("bob@x.example", DsnNotify::default())]);
        let now = at(2000);
        let s = apply_verdicts(&mut m, &[temporary("451 later")], now, &policy(), 5 * DAY, LATER);
        assert_eq!(s, Settled::default());
        let r = &m.recipients[0];
        assert_eq!((r.status, r.attempts), (RecipientStatus::Pending, 1));
        assert_eq!(r.next_attempt, now + Duration::from_secs(60));
        assert_eq!(r.diagnostic.as_deref(), Some("451 later"));
        // each failure waits longer than the last, up to the cap
        apply_verdicts(&mut m, &[temporary("451 later")], now, &policy(), 5 * DAY, LATER);
        assert_eq!(m.recipients[0].next_attempt, now + Duration::from_secs(120));
        for _ in 0..10 {
            apply_verdicts(&mut m, &[temporary("451 later")], now, &policy(), 5 * DAY, LATER);
        }
        assert_eq!(m.recipients[0].next_attempt, now + Duration::from_secs(600));
    }

    #[test]
    fn a_permanent_refusal_fails_the_recipient_at_once_and_a_delivery_completes_it() {
        let mut m = message(vec![rcpt("a@x.example", DsnNotify::default()), rcpt("b@x.example", DsnNotify::default())]);
        let s = apply_verdicts(
            &mut m,
            &[Some(Verdict::Delivered), Some(Verdict::Permanent("550 no such user".into()))],
            at(2000),
            &policy(),
            5 * DAY,
            LATER,
        );
        assert_eq!(s, Settled { delivered: vec![0], failed: vec![1], delayed: vec![] });
        assert_eq!(m.recipients[0].status, RecipientStatus::Delivered);
        assert_eq!(m.recipients[1].status, RecipientStatus::Failed);
        assert_eq!(m.recipients[1].diagnostic.as_deref(), Some("550 no such user"));
        assert!(m.is_finished());
    }

    #[test]
    fn a_recipient_the_attempt_did_not_try_is_left_alone() {
        let mut m = message(vec![rcpt("a@x.example", DsnNotify::default()), rcpt("b@x.example", DsnNotify::default())]);
        m.recipients[1].next_attempt = at(9999);
        apply_verdicts(&mut m, &[Some(Verdict::Delivered), None], at(2000), &policy(), 5 * DAY, LATER);
        assert_eq!((m.recipients[1].attempts, m.recipients[1].next_attempt), (0, at(9999)));
        assert_eq!(m.recipients[1].status, RecipientStatus::Pending);
    }

    #[test]
    fn a_recipient_still_temporarily_refused_when_the_lifetime_ends_is_failed_with_the_last_reply() {
        let mut m = message(vec![rcpt("a@x.example", DsnNotify::default())]);
        let s = apply_verdicts(&mut m, &[temporary("451 later")], at(1000) + 5 * DAY, &policy(), 5 * DAY, LATER);
        assert_eq!(s.failed, [0]);
        let r = &m.recipients[0];
        assert_eq!(r.status, RecipientStatus::Failed);
        let said = r.diagnostic.as_deref().unwrap();
        assert!(said.starts_with("451 later") && said.contains("not delivered within"), "{said}");
    }

    #[test]
    fn the_last_try_is_made_when_the_lifetime_ends_not_a_whole_backoff_after_it() {
        let mut m = message(vec![rcpt("a@x.example", DsnNotify::default())]);
        let near_end = at(1000) + 5 * DAY - Duration::from_secs(10);
        apply_verdicts(&mut m, &[temporary("451 later")], near_end, &policy(), 5 * DAY, LATER);
        assert_eq!(m.recipients[0].status, RecipientStatus::Pending);
        assert_eq!(m.recipients[0].next_attempt, at(1000) + 5 * DAY);
    }

    #[test]
    fn a_recipient_still_queued_after_the_delay_interval_is_noticed_once() {
        let mut m = message(vec![rcpt("a@x.example", DsnNotify::default())]);
        let delay = Duration::from_secs(3600);
        // before the interval: no notice
        let s = apply_verdicts(&mut m, &[temporary("451 later")], at(1000) + Duration::from_secs(60), &policy(), 5 * DAY, delay);
        assert!(s.delayed.is_empty() && !m.recipients[0].delay_notified);
        // at the interval: one notice, remembered
        let s = apply_verdicts(&mut m, &[temporary("451 later")], at(1000) + delay, &policy(), 5 * DAY, delay);
        assert_eq!(s.delayed, [0]);
        assert!(m.recipients[0].delay_notified);
        assert_eq!(m.recipients[0].status, RecipientStatus::Pending);
        // later tries do not repeat it
        let s = apply_verdicts(&mut m, &[temporary("451 later")], at(1000) + 2 * delay, &policy(), 5 * DAY, delay);
        assert!(s.delayed.is_empty());
    }

    #[test]
    fn a_try_is_made_when_the_delay_interval_ends_so_the_notice_is_not_late() {
        let mut m = message(vec![rcpt("a@x.example", DsnNotify::default())]);
        let delay = Duration::from_secs(100);
        // the next backoff step (60 s) is within the interval, the one after is not
        apply_verdicts(&mut m, &[temporary("451 later")], at(1000) + Duration::from_secs(50), &policy(), 5 * DAY, delay);
        assert_eq!(m.recipients[0].next_attempt, at(1000) + Duration::from_secs(100));
    }

    #[test]
    fn nothing_is_scheduled_for_a_notice_the_sender_did_not_ask_for() {
        let failure_only = DsnNotify { failure: true, ..Default::default() };
        let mut m = message(vec![rcpt("a@x.example", failure_only)]);
        let delay = Duration::from_secs(100);
        let now = at(1000) + Duration::from_secs(50);
        let s = apply_verdicts(&mut m, &[temporary("451 later")], now, &policy(), 5 * DAY, delay);
        assert_eq!(m.recipients[0].next_attempt, now + Duration::from_secs(60), "ordinary backoff");
        let s2 = apply_verdicts(&mut m, &[temporary("451 later")], at(1000) + 2 * delay, &policy(), 5 * DAY, delay);
        assert!(s.delayed.is_empty() && s2.delayed.is_empty());
    }

    #[test]
    fn a_delay_notice_reports_the_last_reply_and_a_recipient_that_failed_gets_no_delay_notice() {
        let mut m = message(vec![rcpt("slow@x.example", DsnNotify::default()), rcpt("bad@x.example", DsnNotify::default())]);
        m.recipients[0].diagnostic = Some("451 later".into());
        m.recipients[1].diagnostic = Some("550 gone".into());
        let settled = Settled { delivered: vec![], failed: vec![1], delayed: vec![0] };
        let got: Vec<(String, DsnAction, Option<String>)> =
            dsn_reports(&m, &settled).into_iter().map(|r| (r.final_recipient, r.action, r.diagnostic)).collect();
        assert_eq!(
            got,
            [
                ("slow@x.example".to_string(), DsnAction::Delayed, Some("451 later".to_string())),
                ("bad@x.example".to_string(), DsnAction::Failed, Some("550 gone".to_string())),
            ]
        );
    }

    #[test]
    fn notices_follow_notify_and_name_the_original_recipient() {
        let never = DsnNotify { never: true, ..Default::default() };
        let success = DsnNotify { success: true, ..Default::default() };
        let mut m = message(vec![
            rcpt("ok-default@x.example", DsnNotify::default()),
            rcpt("ok-success@x.example", success),
            rcpt("bad-default@x.example", DsnNotify::default()),
            rcpt("bad-never@x.example", never),
            rcpt("waiting@x.example", DsnNotify::default()),
        ]);
        m.recipients[2].params.orcpt_type = Some("rfc822".into());
        m.recipients[2].params.orcpt_address = Some("orig@x.example".into());
        m.recipients[2].diagnostic = Some("550 gone".into());
        let settled = Settled { delivered: vec![0, 1], failed: vec![2, 3], delayed: vec![] };
        let got: Vec<(String, DsnAction, Option<String>, Option<String>)> = dsn_reports(&m, &settled)
            .into_iter()
            .map(|r| (r.final_recipient, r.action, r.original_recipient, r.diagnostic))
            .collect();
        assert_eq!(
            got,
            [
                ("ok-success@x.example".to_string(), DsnAction::Delivered, None, None),
                (
                    "bad-default@x.example".to_string(),
                    DsnAction::Failed,
                    Some("rfc822;orig@x.example".to_string()),
                    Some("550 gone".to_string())
                ),
            ]
        );
    }

    #[test]
    fn recipients_are_grouped_by_domain_without_regard_to_case() {
        let m = message(vec![
            rcpt("a@Example.com", DsnNotify::default()),
            rcpt("b@other.example", DsnNotify::default()),
            rcpt("c@example.COM", DsnNotify::default()),
        ]);
        assert_eq!(
            group_by_domain(&m, &[0, 1, 2]),
            [("example.com".to_string(), vec![0, 2]), ("other.example".to_string(), vec![1])]
        );
        assert_eq!(group_by_domain(&m, &[1]), [("other.example".to_string(), vec![1])]);
    }

    #[test]
    fn a_stored_address_parses_back_to_the_one_it_came_from() {
        for a in ["bob@example.net", "\"a@b\"@example.net", "x@y@z.example"] {
            assert_eq!(parse_address(a).address(), a);
        }
        assert_eq!(parse_address("bob@Example.NET").domain(), "Example.NET");
    }

    #[test]
    fn extra_header_lines_are_crlf_terminated() {
        assert_eq!(render_extra_header_lines(&[]), b"");
        assert_eq!(render_extra_header_lines(&["X-A: 1".into(), "X-B: 2".into()]), b"X-A: 1\r\nX-B: 2\r\n");
    }

    #[test]
    fn the_hop_carries_the_envelope_parameters_that_the_message_arrived_with() {
        let d = DeliveryRequirements {
            require_tls: true,
            priority: Some(3),
            dsn_ret: Some(crate::server::delivery::DsnReturn::Hdrs),
            dsn_envid: Some("env-1".into()),
            ..Default::default()
        };
        let p = outbound_mail_params(&d, false, SystemTime::now());
        assert!(p.require_tls && p.priority == Some(3) && p.dsn_envid.as_deref() == Some("env-1"));
        assert!(p.dsn_ret.is_some() && !p.smtputf8);
    }

    #[test]
    fn smtputf8_is_carried_to_the_next_hop() {
        // Without it a relay that accepted a UTF-8 address would hand the
        // next server an address it has not been told it may receive.
        let now = SystemTime::now();
        assert!(outbound_mail_params(&DeliveryRequirements::default(), true, now).smtputf8);
        assert!(!outbound_mail_params(&DeliveryRequirements::default(), false, now).smtputf8);
    }

    #[test]
    fn a_delivery_deadline_is_carried_with_the_time_that_is_left() {
        // RFC 2852 section 4.1.4: a relay passes BY on with the time
        // remaining, never the original interval.
        let now = SystemTime::now();
        let by = |secs, r| DeliveryRequirements {
            deliver_by: Some(DeliverBy { deadline: now + Duration::from_secs(secs), return_on_fail: r }),
            ..Default::default()
        };
        assert_eq!(outbound_mail_params(&by(300, true), false, now).deliver_by, Some((Duration::from_secs(300), true)));
        let later = now + Duration::from_secs(100);
        assert_eq!(outbound_mail_params(&by(300, true), false, later).deliver_by, Some((Duration::from_secs(200), true)));
        assert_eq!(outbound_mail_params(&by(60, false), false, now).deliver_by, Some((Duration::from_secs(60), false)));
    }

    #[test]
    fn a_deadline_about_to_pass_is_not_sent_as_zero() {
        let now = SystemTime::now();
        let d = DeliveryRequirements {
            deliver_by: Some(DeliverBy { deadline: now + Duration::from_millis(200), return_on_fail: true }),
            ..Default::default()
        };
        assert_eq!(outbound_mail_params(&d, false, now).deliver_by.map(|(t, _)| t), Some(Duration::from_secs(1)));
    }
}
