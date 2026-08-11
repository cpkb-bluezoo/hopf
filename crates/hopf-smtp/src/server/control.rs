// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP connection protocol engine (`ProtocolHandler`).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rmimeparser::{EmailAddress, EmailAddressParser};
use hopf_auth::{
    create_server, CredentialStore, SaslMechanism, SaslServer, SaslServerOptions, SaslServerStep,
};
use rmimeparser::charset::base64;
use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, StorageError};
use hopf_otel::{
    ExportHandle, RequestTimer, Span, SpanKind, Trace, SmtpServerMetrics as OtelSmtpMetrics,
};

use crate::server::codec::{SmtpCommand, SmtpServerLexer, MAX_COMMAND_LINE};
use crate::server::data::{BdatAccumulator, DotUnstuffer};
use crate::server::delivery::{
    parse_mail_from_arg, parse_rcpt_to_arg, BodyType, DeliveryRequirements, DsnRecipientParams,
};
use crate::server::handler::{
    AuthenticateState, ConnectedState, DeferredDelivery, HelloHandler, HelloState, MailFromHandler,
    MailFromState, MessageDataHandler, MessageEndState, MessageStartState, RecipientHandler,
    RecipientState, ResetState, SmtpClientConnected, SmtpConnectionMetadata,
};
use crate::server::handler::DeferredSlot;
use crate::server::metrics::SmtpServerMetrics;
use crate::server::pipeline::SmtpPipeline;
use crate::server::reply::{reply, reply_enhanced, reply_ehlo, reply_multiline};
use crate::server::service::SmtpConfig;
use crate::server::session::SmtpSessionState;

/// Result of a SASL step offloaded to the storage pool (issue #181) —
/// `SaslServer::step` can block for LDAP/PAM-backed stores, so it runs off
/// the reactor thread; the outcome lands here for `sync_pending_auth_check`
/// to apply once back on the reactor (the storage callback only has
/// `&mut dyn Endpoint`, never `&mut Self`). `first_step` marks the
/// server-first initial call (no client data yet) — a `Complete` there
/// means the mechanism authenticated nobody, so it's still a failure.
struct AuthCheckOutcome {
    first_step: bool,
    result: Result<(Box<dyn SaslServer>, SaslServerStep), String>,
}

/// Control-channel SMTP protocol handler.
pub struct SmtpControlHandler {
    client_connected: Option<Box<dyn SmtpClientConnected>>,
    hello: Option<Box<dyn HelloHandler>>,
    mail_from: Option<Box<dyn MailFromHandler>>,
    recipient: Option<Box<dyn RecipientHandler>>,
    message: Option<Box<dyn MessageDataHandler>>,
    pipeline: Option<Box<dyn SmtpPipeline>>,
    lexer: SmtpServerLexer,
    session: SmtpSessionState,
    config: SmtpConfig,
    metrics: Arc<SmtpServerMetrics>,
    meta: SmtpConnectionMetadata,
    recipients: Vec<(EmailAddress, DsnRecipientParams)>,
    sender: Option<EmailAddress>,
    delivery: DeliveryRequirements,
    body_type: BodyType,
    declared_size: Option<u64>,
    message_bytes: u64,
    unstuffer: DotUnstuffer,
    bdat: Option<BdatAccumulator>,
    bdat_started: bool,
    helo_name: Option<String>,
    extended: bool,
    expect_implicit_tls: bool,
    greeting_sent: bool,
    /// Pending bytes after DATA terminator (pipelining).
    leftover: Vec<u8>,
    /// Shared slot for [`MessageEndState::defer`].
    deferred: Arc<std::sync::Mutex<Option<DeferredSlot>>>,
    control_handle: Option<ConnHandle>,
    /// In-progress SASL exchange, between the `334` challenge and the
    /// client's continuation line.
    sasl: Option<Box<dyn SaslServer>>,
    /// MAIL FROM commands seen this session (RFC 9422 MAILMAX counter).
    mail_transactions: u32,
    /// Real TCP peer for XCLIENT authorization (never overridden by ADDR).
    tcp_peer: SocketAddr,
    /// Optional OTLP SMTP metrics (from a telemetry pipeline).
    otel_metrics: Option<Arc<OtelSmtpMetrics>>,
    /// Export handle for finishing traces.
    export: Option<ExportHandle>,
    /// Whether to create SERVER spans for this connection.
    traces_enabled: bool,
    /// Connection-level distributed trace (when tracing is enabled).
    conn_trace: Option<Trace>,
    /// Open child span for the current mail transaction.
    tx_span: Option<Span>,
    /// Timer for the current mail transaction (MAIL → end).
    tx_timer: Option<RequestTimer>,
    runtime: Arc<Runtime>,
    /// True while a SASL step is offloaded to the storage pool (issue
    /// #181) — pipelined commands are soft-rejected with a temporary
    /// error (matching the existing `Delivering`-state precedent) rather
    /// than processed against stale pre-auth state.
    busy: Arc<AtomicBool>,
    pending_auth_check: Arc<Mutex<Option<AuthCheckOutcome>>>,
    /// True while `finish_message` is waiting on `self.pipeline`'s queued
    /// (offloaded) writes to finish landing (issue #184) — `end_data()`
    /// returning doesn't mean every chunk is actually on disk yet, so
    /// `message_complete` (which reads pipeline-observable state like the
    /// spool path/error) must not run until `is_pending()` clears. Gates
    /// pipelined commands the same way `busy` does, since `finish_message`
    /// deferring leaves `self.session` unchanged (still `Data`/`Bdat`),
    /// which alone isn't enough to stop a *separate* later `receive()`
    /// call from being misinterpreted as more DATA content.
    pending_finish: bool,
}

impl SmtpControlHandler {
    /// Create for a new connection.
    pub fn new(
        client: Box<dyn SmtpClientConnected>,
        metrics: Arc<SmtpServerMetrics>,
        config: SmtpConfig,
        peer: SocketAddr,
        local: SocketAddr,
        runtime: Arc<Runtime>,
    ) -> Self {
        let expect_implicit_tls = config.implicit_tls && config.tls_acceptor.is_some();
        Self {
            client_connected: Some(client),
            hello: None,
            mail_from: None,
            recipient: None,
            message: None,
            pipeline: None,
            lexer: SmtpServerLexer::new(MAX_COMMAND_LINE),
            session: SmtpSessionState::Initial,
            expect_implicit_tls,
            greeting_sent: false,
            meta: SmtpConnectionMetadata {
                peer,
                local,
                tls: false,
                authenticated_user: None,
                smtputf8: false,
                control_handle: None,
                security_info: hopf_core::SecurityInfo::plaintext(),
                reverse_name: None,
                xclient_login: None,
                traceparent: None,
            },
            config,
            metrics,
            recipients: Vec::new(),
            sender: None,
            delivery: DeliveryRequirements::default(),
            body_type: BodyType::SevenBit,
            declared_size: None,
            message_bytes: 0,
            unstuffer: DotUnstuffer::new(),
            bdat: None,
            bdat_started: false,
            helo_name: None,
            extended: false,
            leftover: Vec::new(),
            deferred: Arc::new(std::sync::Mutex::new(None)),
            control_handle: None,
            sasl: None,
            mail_transactions: 0,
            tcp_peer: peer,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            conn_trace: None,
            tx_span: None,
            tx_timer: None,
            runtime,
            busy: Arc::new(AtomicBool::new(false)),
            pending_auth_check: Arc::new(Mutex::new(None)),
            pending_finish: false,
        }
    }

    /// Attach OTel metrics / traces from a [`hopf_otel::TelemetryPipeline`].
    pub fn with_telemetry(
        mut self,
        otel_metrics: Option<Arc<OtelSmtpMetrics>>,
        export: Option<ExportHandle>,
        traces_enabled: bool,
    ) -> Self {
        self.otel_metrics = otel_metrics;
        self.export = export;
        self.traces_enabled = traces_enabled;
        self
    }

    fn begin_connection_telemetry(&mut self) {
        if let Some(m) = &self.otel_metrics {
            m.connection_opened();
        }
        if self.traces_enabled {
            if let Some(export) = self.export.clone() {
                let t = Trace::new("SMTP connection", SpanKind::Server);
                t.set_exporter(export);
                self.meta.traceparent = Some(t.traceparent());
                self.conn_trace = Some(t);
            }
        }
    }

    fn begin_transaction_telemetry(&mut self) {
        self.tx_timer = Some(RequestTimer::start());
        if let Some(trace) = &self.conn_trace {
            let span = trace.start_span("SMTP transaction", SpanKind::Server);
            self.meta.traceparent = Some(trace.traceparent());
            self.tx_span = Some(span);
        }
    }

    fn end_transaction_telemetry(&mut self, outcome: &str) {
        let duration = self
            .tx_timer
            .take()
            .map(|t| t.elapsed())
            .unwrap_or_default();
        let size = self.message_bytes;
        if let Some(span) = self.tx_span.take() {
            if outcome == "accepted" {
                span.set_status_ok();
            } else {
                span.set_status_error(outcome);
            }
            span.set_attribute("smtp.transaction.outcome", outcome);
            span.end();
        }
        if let Some(trace) = &self.conn_trace {
            self.meta.traceparent = Some(trace.traceparent());
        }
        if let Some(m) = &self.otel_metrics {
            m.transaction_completed(outcome, duration, size);
        }
    }

    fn end_connection_telemetry(&mut self) {
        if self.tx_timer.is_some() || self.tx_span.is_some() {
            self.end_transaction_telemetry("aborted");
        }
        if let Some(trace) = self.conn_trace.take() {
            let root = trace.root_span();
            root.set_status_ok();
            root.end();
            trace.end();
        }
        self.meta.traceparent = None;
        if let Some(m) = &self.otel_metrics {
            m.connection_closed();
        }
    }

    fn record_auth(&self, ok: bool) {
        if ok {
            SmtpServerMetrics::add(&self.metrics.auth_ok, 1);
        } else {
            SmtpServerMetrics::add(&self.metrics.auth_fail, 1);
        }
        if let Some(m) = &self.otel_metrics {
            m.auth(ok);
        }
    }

    fn record_starttls(&self) {
        SmtpServerMetrics::add(&self.metrics.starttls, 1);
        if let Some(m) = &self.otel_metrics {
            m.starttls();
        }
    }

    fn send(&self, endpoint: &mut dyn Endpoint, bytes: Vec<u8>) {
        endpoint.send(&bytes);
    }

    fn send_reply(&self, endpoint: &mut dyn Endpoint, code: u16, text: &str) {
        self.send(endpoint, reply(code, text));
    }

    fn send_enhanced(&self, endpoint: &mut dyn Endpoint, code: u16, ecode: &str, text: &str) {
        self.send(endpoint, reply_enhanced(code, ecode, text));
    }

    fn sync_deferred(&mut self) {
        let outcome = {
            let mut g = self.deferred.lock().unwrap();
            match g.as_mut() {
                Some(slot) if slot.outcome.is_some() => {
                    let outcome = slot.outcome.take().unwrap();
                    let resume = g.take().map(|s| s.resume);
                    Some((outcome, resume))
                }
                _ => None,
            }
        };
        let Some((outcome, resume)) = outcome else {
            return;
        };
        let _ = outcome; // reply already sent by DeferredDelivery
        if let Some(h) = resume {
            self.mail_from = Some(h);
        }
        self.message = None;
        self.recipient = None;
        if self.session == SmtpSessionState::Delivering {
            self.session = SmtpSessionState::Ready;
        }
    }

    fn maybe_greet(&mut self, endpoint: &mut dyn Endpoint) {
        if self.greeting_sent {
            return;
        }
        if self.expect_implicit_tls && !self.meta.tls {
            return;
        }
        self.invoke_connected(endpoint);
    }

    fn invoke_connected(&mut self, endpoint: &mut dyn Endpoint) {
        if self.greeting_sent {
            return;
        }
        let mut client = match self.client_connected.take() {
            Some(c) => c,
            None => return,
        };
        SmtpServerMetrics::add(&self.metrics.connections, 1);
        self.begin_connection_telemetry();
        {
            let mut ctx = ConnectedCtx {
                endpoint,
                hello: &mut self.hello,
                greeting_sent: &mut self.greeting_sent,
                session: &mut self.session,
            };
            client.connected(&mut ctx, &self.meta);
        }
        // Keep client for disconnected() unless rejected (closed).
        self.client_connected = Some(client);
    }

    fn ehlo_capabilities(&self) -> Vec<String> {
        let mut caps = vec![
            format!("SIZE {}", self.config.max_message_size),
            "PIPELINING".into(),
            "8BITMIME".into(),
            "SMTPUTF8".into(),
            "ENHANCEDSTATUSCODES".into(),
            "CHUNKING".into(),
            "BINARYMIME".into(),
            "DSN".into(),
            "DELIVERBY".into(),
            "MT-PRIORITY".into(),
            "REQUIRETLS".into(),
            format!(
                "LIMITS RCPTMAX={} MAILMAX={}",
                self.config.max_recipients, self.config.max_mail_transactions
            ),
            "HELP".into(),
        ];
        if self.config.tls_acceptor.is_some() && !self.meta.tls && !self.config.implicit_tls {
            caps.push("STARTTLS".into());
        }
        if let Some(store) = &self.config.store {
            // RFC 4954 §4: advertise each mechanism the store can drive,
            // except ones that require TLS on a connection that doesn't
            // have it yet (matches hopf-pop3/hopf-imap).
            let mechs: Vec<&str> = store
                .supported_mechanisms()
                .iter()
                .filter(|m| self.meta.tls || !m.requires_tls())
                .map(|m| m.name())
                .collect();
            if !mechs.is_empty() {
                caps.push(format!("AUTH {}", mechs.join(" ")));
            }
        }
        if self.config.xclient_authorized(self.tcp_peer) {
            caps.push("XCLIENT NAME ADDR PORT PROTO HELO LOGIN DESTADDR DESTPORT".into());
        }
        caps
    }

    fn reset_transaction(&mut self) {
        self.sender = None;
        self.recipients.clear();
        self.delivery = DeliveryRequirements::default();
        self.body_type = BodyType::SevenBit;
        self.declared_size = None;
        self.message_bytes = 0;
        self.meta.smtputf8 = false;
        self.unstuffer.reset();
        self.bdat = None;
        self.bdat_started = false;
        if let Some(p) = &mut self.pipeline {
            p.reset();
        }
        self.pipeline = None;
        self.message = None;
        if self.mail_from.is_some() {
            self.session = SmtpSessionState::Ready;
        }
        self.recipient = None;
    }

    fn parse_address(&self, raw: &str) -> Option<EmailAddress> {
        if self.meta.smtputf8 {
            EmailAddressParser::parse_envelope_address_smtp_utf8(raw, true)
        } else {
            EmailAddressParser::parse_envelope_address(raw)
        }
    }

    fn dispatch(&mut self, endpoint: &mut dyn Endpoint, cmd: SmtpCommand) {
        match cmd {
            SmtpCommand::Helo(hostname) => self.cmd_helo(endpoint, &hostname, false),
            SmtpCommand::Ehlo(hostname) => self.cmd_helo(endpoint, &hostname, true),
            SmtpCommand::Mail(arg) => self.cmd_mail(endpoint, arg.trim()),
            SmtpCommand::Rcpt(arg) => self.cmd_rcpt(endpoint, arg.trim()),
            SmtpCommand::Data => self.cmd_data(endpoint),
            SmtpCommand::Bdat(arg) => self.cmd_bdat(endpoint, &arg),
            SmtpCommand::Rset => self.cmd_rset(endpoint),
            SmtpCommand::Quit => self.cmd_quit(endpoint),
            SmtpCommand::Noop => self.send_enhanced(endpoint, 250, "2.0.0", "OK"),
            SmtpCommand::Help => self.cmd_help(endpoint),
            SmtpCommand::Vrfy => self.send_enhanced(
                endpoint,
                252,
                "2.0.0",
                "Cannot VRFY user, but will accept message and attempt delivery",
            ),
            SmtpCommand::Expn => self.send_enhanced(endpoint, 502, "5.5.1", "EXPN not implemented"),
            SmtpCommand::Etrn => {
                if self.extended {
                    self.send_enhanced(
                        endpoint,
                        458,
                        "4.4.0",
                        "Unable to queue messages for node",
                    );
                } else {
                    self.send_enhanced(endpoint, 502, "5.5.1", "ETRN requires EHLO");
                }
            }
            SmtpCommand::Starttls => self.cmd_starttls(endpoint),
            SmtpCommand::Auth { mechanism, initial_response } => {
                self.cmd_auth(endpoint, &mechanism, initial_response)
            }
            SmtpCommand::SaslResponse(data) => self.handle_sasl_response(endpoint, data),
            SmtpCommand::SaslAbort => {
                self.sasl = None;
                self.send_enhanced(endpoint, 501, "5.0.0", "Authentication cancelled");
            }
            SmtpCommand::SaslResponseInvalid => {
                self.sasl = None;
                self.record_auth(false);
                self.send_enhanced(endpoint, 535, "5.7.8", "Authentication credentials invalid");
            }
            SmtpCommand::Xclient(args) => self.cmd_xclient(endpoint, &args),
            SmtpCommand::Malformed { .. } => {
                self.sasl = None;
                self.record_auth(false);
                self.send_enhanced(endpoint, 535, "5.7.8", "Authentication credentials invalid");
            }
            SmtpCommand::Unknown { .. } => {
                self.send_enhanced(endpoint, 500, "5.5.2", "Command unrecognized");
            }
        }
    }

    fn cmd_helo(&mut self, endpoint: &mut dyn Endpoint, hostname: &str, extended: bool) {
        if hostname.is_empty() {
            self.send_enhanced(
                endpoint,
                501,
                "5.5.4",
                if extended {
                    "Syntax: EHLO hostname"
                } else {
                    "Syntax: HELO hostname"
                },
            );
            return;
        }
        self.helo_name = Some(hostname.to_string());
        self.extended = extended;
        let mut hello = match self.hello.take() {
            Some(h) => h,
            None => {
                self.send_enhanced(endpoint, 503, "5.5.1", "Bad sequence of commands");
                return;
            }
        };
        {
            let caps = self.ehlo_capabilities();
            let mut ctx = HelloCtx {
                endpoint,
                mail_from: &mut self.mail_from,
                hello: &mut self.hello,
                session: &mut self.session,
                hostname: &self.config.hostname,
                helo_name: hostname,
                extended,
                caps,
            };
            hello.hello(&mut ctx, extended, hostname);
        }
        // Keep hello for AUTH / tls_established (Gumdrop retains the stage object).
        if self.hello.is_none() {
            self.hello = Some(hello);
        }
    }

    fn cmd_mail(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if self.session != SmtpSessionState::Ready {
            self.send_enhanced(endpoint, 503, "5.5.1", "Bad sequence of commands");
            return;
        }
        if self.mail_from.is_none() {
            self.send_enhanced(endpoint, 503, "5.5.1", "Send HELO/EHLO first");
            return;
        }
        if self.config.auth_required && self.meta.authenticated_user.is_none() {
            self.send_enhanced(endpoint, 530, "5.7.0", "Authentication required");
            return;
        }
        // RFC 9422 §4.1: MAILMAX counts every MAIL FROM, success or failure.
        if self.mail_transactions >= self.config.max_mail_transactions {
            self.send_enhanced(
                endpoint,
                452,
                "4.5.3",
                "Too many MAIL transactions in this session",
            );
            return;
        }
        self.mail_transactions = self.mail_transactions.saturating_add(1);

        let parsed = match parse_mail_from_arg(&format!("FROM:{}", strip_mail_prefix(arg))) {
            Ok(p) => p,
            Err(e) => {
                // try with arg as-is if it already has FROM:
                match parse_mail_from_arg(arg) {
                    Ok(p) => p,
                    Err(_) => {
                        self.send_enhanced(endpoint, 501, "5.5.4", &e.message);
                        return;
                    }
                }
            }
        };
        if let Some(sz) = parsed.size {
            if sz > self.config.max_message_size {
                self.send_enhanced(endpoint, 552, "5.3.4", "Message size exceeds fixed maximum");
                return;
            }
        }
        if parsed.smtputf8 && !self.extended {
            self.send_enhanced(endpoint, 503, "5.5.1", "SMTPUTF8 requires EHLO");
            return;
        }
        // RFC 8689 §2: REQUIRETLS may only be used on a TLS-protected session.
        if parsed.delivery.require_tls && !self.meta.tls {
            self.send_enhanced(
                endpoint,
                530,
                "5.7.10",
                "REQUIRETLS requires a TLS-protected session",
            );
            return;
        }
        // RFC 2852: refuse a DELIVERBY deadline that has already passed.
        if let Some(by) = &parsed.delivery.deliver_by {
            if by.deadline <= std::time::SystemTime::now() {
                self.send_enhanced(
                    endpoint,
                    501,
                    "5.5.4",
                    "DELIVERBY deadline has already passed",
                );
                return;
            }
        }
        self.meta.smtputf8 = parsed.smtputf8;
        self.delivery = parsed.delivery.clone();
        self.body_type = parsed.body;
        self.declared_size = parsed.size;

        let sender = match &parsed.sender_raw {
            None => None,
            Some(raw) => match self.parse_address(raw) {
                Some(a) => Some(a),
                None => {
                    self.send_enhanced(endpoint, 501, "5.1.7", "Bad sender address syntax");
                    return;
                }
            },
        };

        // Fresh transaction
        self.recipients.clear();
        self.message = None;
        self.recipient = None;

        let mut mail = self.mail_from.take().unwrap();
        self.pipeline = mail.pipeline();
        if let Some(p) = &mut self.pipeline {
            p.mail_from(sender.as_ref());
        }
        {
            let mut accepted = false;
            {
                let mut ctx = MailFromCtx {
                    endpoint,
                    recipient: &mut self.recipient,
                    mail_from: &mut self.mail_from,
                    session: &mut self.session,
                    accepted: &mut accepted,
                };
                mail.mail_from(&mut ctx, sender.as_ref(), parsed.smtputf8, &parsed.delivery);
            }
            if accepted {
                self.sender = sender;
                self.begin_transaction_telemetry();
            }
        }
        if self.mail_from.is_none() {
            // Reject path should have restored; if accept, recipient is set.
            if self.recipient.is_none() {
                self.mail_from = Some(mail);
            }
        }
    }

    fn cmd_rcpt(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if self.session != SmtpSessionState::Mail && self.session != SmtpSessionState::Rcpt {
            self.send_enhanced(endpoint, 503, "5.5.1", "Bad sequence of commands");
            return;
        }
        if self.recipients.len() >= self.config.max_recipients {
            self.send_enhanced(endpoint, 452, "4.5.3", "Too many recipients");
            return;
        }
        let (addr_raw, dsn) = match parse_rcpt_to_arg(arg) {
            Ok(v) => v,
            Err(_) => match parse_rcpt_to_arg(&format!("TO:{arg}")) {
                Ok(v) => v,
                Err(e) => {
                    self.send_enhanced(endpoint, 501, "5.5.4", &e.message);
                    return;
                }
            },
        };
        let recipient = match self.parse_address(&addr_raw) {
            Some(a) => a,
            None => {
                self.send_enhanced(endpoint, 501, "5.1.3", "Bad recipient address syntax");
                return;
            }
        };
        let mut rcpt = match self.recipient.take() {
            Some(r) => r,
            None => {
                self.send_enhanced(endpoint, 503, "5.5.1", "Bad sequence of commands");
                return;
            }
        };
        let mut accepted = false;
        {
            let mut ctx = RecipientCtx {
                endpoint,
                recipient_handler: &mut self.recipient,
                session: &mut self.session,
                accepted: &mut accepted,
            };
            rcpt.rcpt_to(&mut ctx, &recipient, &dsn);
        }
        if accepted {
            if let Some(p) = &mut self.pipeline {
                p.rcpt_to(&recipient);
            }
            self.recipients.push((recipient, dsn));
            if self.recipient.is_none() {
                self.recipient = Some(rcpt);
            }
        } else if self.recipient.is_none() {
            self.recipient = Some(rcpt);
        }
    }

    fn cmd_data(&mut self, endpoint: &mut dyn Endpoint) {
        if self.session != SmtpSessionState::Rcpt && self.session != SmtpSessionState::Mail {
            self.send_enhanced(endpoint, 503, "5.5.1", "Bad sequence of commands");
            return;
        }
        if self.recipients.is_empty() {
            self.send_enhanced(endpoint, 503, "5.5.1", "Need RCPT (recipient)");
            return;
        }
        if self.body_type.requires_bdat() {
            self.send_enhanced(endpoint, 503, "5.6.1", "BODY=BINARYMIME requires BDAT, not DATA");
            return;
        }
        let mut rcpt = match self.recipient.take() {
            Some(r) => r,
            None => {
                self.send_enhanced(endpoint, 503, "5.5.1", "Bad sequence of commands");
                return;
            }
        };
        {
            let mut ctx = MessageStartCtx {
                endpoint,
                message: &mut self.message,
                recipient: &mut self.recipient,
                mail_from: &mut self.mail_from,
                session: &mut self.session,
                unstuffer: &mut self.unstuffer,
                message_bytes: &mut self.message_bytes,
                bdat_mode: false,
            };
            rcpt.start_message(&mut ctx);
        }
        if self.message.is_none() && self.recipient.is_none() {
            // rejected to mail-from
        } else if self.message.is_none() {
            self.recipient = Some(rcpt);
        }
    }

    fn cmd_bdat(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.extended {
            self.send_enhanced(endpoint, 503, "5.5.1", "BDAT requires EHLO");
            return;
        }
        if self.session != SmtpSessionState::Rcpt
            && self.session != SmtpSessionState::Mail
            && self.session != SmtpSessionState::Bdat
        {
            self.send_enhanced(endpoint, 503, "5.5.1", "Bad sequence of commands");
            return;
        }
        if self.recipients.is_empty() {
            self.send_enhanced(endpoint, 503, "5.5.1", "Need RCPT (recipient)");
            return;
        }
        let mut parts = arg.split_whitespace();
        let size_s = match parts.next() {
            Some(s) => s,
            None => {
                self.send_enhanced(endpoint, 501, "5.5.4", "Syntax: BDAT size [LAST]");
                return;
            }
        };
        let size: u64 = match size_s.parse() {
            Ok(n) => n,
            Err(_) => {
                self.send_enhanced(endpoint, 501, "5.5.4", "Invalid BDAT size");
                return;
            }
        };
        let last = parts
            .next()
            .map(|s| s.eq_ignore_ascii_case("LAST"))
            .unwrap_or(false);
        if !self.bdat_started {
            let mut rcpt = match self.recipient.take() {
                Some(r) => r,
                None => {
                    self.send_enhanced(endpoint, 503, "5.5.1", "Bad sequence of commands");
                    return;
                }
            };
            {
                let mut ctx = MessageStartCtx {
                    endpoint,
                    message: &mut self.message,
                    recipient: &mut self.recipient,
                    mail_from: &mut self.mail_from,
                    session: &mut self.session,
                    unstuffer: &mut self.unstuffer,
                    message_bytes: &mut self.message_bytes,
                    bdat_mode: true,
                };
                rcpt.start_message(&mut ctx);
            }
            if self.message.is_none() {
                if self.recipient.is_none() && self.mail_from.is_none() {
                    self.recipient = Some(rcpt);
                }
                return;
            }
            self.bdat_started = true;
        }
        self.bdat = Some(BdatAccumulator::new(size, last));
        self.session = SmtpSessionState::Bdat;
        if size == 0 {
            self.finish_bdat_chunk(endpoint);
        }
    }

    fn finish_bdat_chunk(&mut self, endpoint: &mut dyn Endpoint) {
        let last = self.bdat.as_ref().map(|b| b.last).unwrap_or(false);
        self.bdat = None;
        if last {
            self.finish_message(endpoint);
        } else {
            self.send_enhanced(endpoint, 250, "2.0.0", "OK");
            self.session = SmtpSessionState::Bdat;
        }
    }

    fn finish_message(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(p) = &mut self.pipeline {
            p.end_data();
            if p.is_pending() {
                // Chunks are still draining to disk (issue #184) —
                // `message_complete` reads pipeline-observable state
                // (spool path/error) that isn't trustworthy until every
                // queued write has actually landed. Defer the rest of
                // this function; `sync_pending_finish` re-invokes it once
                // `is_pending()` clears, triggered by the last write's
                // `poke_handler` call (see `spool.rs::drain_next`).
                self.pending_finish = true;
                return;
            }
        }
        SmtpServerMetrics::add(&self.metrics.messages, 1);
        SmtpServerMetrics::add(&self.metrics.bytes, self.message_bytes);
        self.end_transaction_telemetry("accepted");
        let mut msg = match self.message.take() {
            Some(m) => m,
            None => {
                self.send_enhanced(endpoint, 250, "2.0.0", "Message accepted for delivery");
                self.reset_transaction();
                return;
            }
        };
        {
            let mut ctx = MessageEndCtx {
                endpoint,
                mail_from: &mut self.mail_from,
                session: &mut self.session,
                recipients: &mut self.recipients,
                sender: &mut self.sender,
                pipeline: &mut self.pipeline,
                message_bytes: &mut self.message_bytes,
                unstuffer: &mut self.unstuffer,
                bdat: &mut self.bdat,
                bdat_started: &mut self.bdat_started,
                body_type: &mut self.body_type,
                delivery: &mut self.delivery,
                meta: &mut self.meta,
                deferred: &self.deferred,
                control_handle: self.control_handle.clone(),
            };
            msg.message_complete(&mut ctx);
        }
        self.message = None;
        self.recipient = None;
    }

    fn feed_data(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        let (chunks, complete_at) = self.unstuffer.feed_with_pending(data);
        for chunk in chunks {
            self.message_bytes += chunk.len() as u64;
            if self.message_bytes > self.config.max_message_size {
                if let Some(m) = &mut self.message {
                    m.message_aborted();
                }
                self.send_enhanced(endpoint, 552, "5.3.4", "Message size exceeds maximum");
                self.reset_transaction();
                *data = &[];
                return;
            }
            if let Some(p) = &mut self.pipeline {
                if !p.message_content(&chunk) {
                    // Unrecoverable pipeline error (e.g. disk full): stop
                    // wasting the transfer on a message that's already
                    // doomed. RFC 5321 gives no way to reply mid-DATA, so
                    // this mirrors the max-size abort above — reply now,
                    // reset the transaction, and discard whatever's left
                    // in this read (the client's own eventual terminator
                    // gets reinterpreted as a fresh command line, same as
                    // any other mid-DATA abort here).
                    if let Some(m) = &mut self.message {
                        m.message_aborted();
                    }
                    self.send_enhanced(endpoint, 452, "4.3.1", "Insufficient system storage");
                    self.reset_transaction();
                    *data = &[];
                    return;
                }
            } else if let Some(m) = &mut self.message {
                m.message_content(&chunk);
            }
        }
        if let Some(n) = complete_at {
            let rest = if n <= data.len() { &data[n..] } else { &[] };
            self.leftover = rest.to_vec();
            *data = &[];
            self.finish_message(endpoint);
        } else {
            *data = &[];
        }
    }

    fn feed_bdat(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        let Some(acc) = self.bdat.as_mut() else {
            *data = &[];
            return;
        };
        let (chunk, rest) = acc.take(data);
        let chunk = chunk.to_vec();
        let rest = rest.to_vec();
        let complete = self.bdat.as_ref().map(|b| b.is_complete()).unwrap_or(false);
        self.message_bytes += chunk.len() as u64;
        if self.message_bytes > self.config.max_message_size {
            if let Some(m) = &mut self.message {
                m.message_aborted();
            }
            self.send_enhanced(endpoint, 552, "5.3.4", "Message size exceeds maximum");
            self.reset_transaction();
            *data = &[];
            return;
        }
        if !chunk.is_empty() {
            if let Some(p) = &mut self.pipeline {
                if !p.message_content(&chunk) {
                    if let Some(m) = &mut self.message {
                        m.message_aborted();
                    }
                    self.send_enhanced(endpoint, 452, "4.3.1", "Insufficient system storage");
                    self.reset_transaction();
                    *data = &[];
                    return;
                }
            } else if let Some(m) = &mut self.message {
                m.message_content(&chunk);
            }
        }
        *data = &[];
        self.leftover = rest;
        if complete {
            self.finish_bdat_chunk(endpoint);
        }
    }

    fn cmd_rset(&mut self, endpoint: &mut dyn Endpoint) {
        if self.tx_timer.is_some() || self.tx_span.is_some() {
            self.end_transaction_telemetry("aborted");
        }
        if let Some(m) = &mut self.message {
            m.message_aborted();
        }
        if let Some(mut mail) = self.mail_from.take() {
            let mut ctx = ResetCtx {
                endpoint,
                mail_from: &mut self.mail_from,
                session: &mut self.session,
            };
            mail.reset(&mut ctx);
            if self.mail_from.is_none() {
                self.mail_from = Some(mail);
            }
        } else if let Some(mut rcpt) = self.recipient.take() {
            let mut ctx = ResetCtx {
                endpoint,
                mail_from: &mut self.mail_from,
                session: &mut self.session,
            };
            rcpt.reset(&mut ctx);
        } else {
            self.send_enhanced(endpoint, 250, "2.0.0", "Reset state");
        }
        self.sender = None;
        self.recipients.clear();
        self.message = None;
        self.recipient = None;
        self.pipeline = None;
        self.unstuffer.reset();
        self.bdat = None;
        self.bdat_started = false;
        self.message_bytes = 0;
        if self.mail_from.is_some() {
            self.session = SmtpSessionState::Ready;
        }
    }

    fn cmd_quit(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(h) = &mut self.hello {
            h.quit();
        }
        if let Some(m) = &mut self.mail_from {
            m.quit();
        }
        if let Some(r) = &mut self.recipient {
            r.quit();
        }
        self.session = SmtpSessionState::Quit;
        self.send_enhanced(endpoint, 221, "2.0.0", "Bye");
        endpoint.close();
    }

    fn cmd_help(&mut self, endpoint: &mut dyn Endpoint) {
        let mut line1 =
            "HELO EHLO MAIL RCPT DATA BDAT RSET NOOP QUIT HELP AUTH STARTTLS".to_string();
        if self.config.xclient_authorized(self.tcp_peer) {
            line1.push_str(" XCLIENT");
        }
        self.send(
            endpoint,
            reply_multiline(214, &[line1.as_str(), "End of HELP"]),
        );
    }

    fn cmd_xclient(&mut self, endpoint: &mut dyn Endpoint, args: &str) {
        use crate::server::xclient::{apply_addr_overrides, parse_xclient_args};

        if !self.config.xclient_authorized(self.tcp_peer) {
            self.send_enhanced(endpoint, 550, "5.7.0", "XCLIENT not permitted");
            return;
        }
        if matches!(
            self.session,
            SmtpSessionState::Mail
                | SmtpSessionState::Rcpt
                | SmtpSessionState::Data
                | SmtpSessionState::Bdat
                | SmtpSessionState::Delivering
        ) {
            self.send_enhanced(endpoint, 503, "5.5.1", "Mail transaction in progress");
            return;
        }

        let overrides = match parse_xclient_args(args) {
            Ok(o) => o,
            Err(e) => {
                self.send_enhanced(endpoint, 501, "5.5.4", &e.0);
                return;
            }
        };

        let (peer, local) = apply_addr_overrides(self.meta.peer, self.meta.local, &overrides);
        self.meta.peer = peer;
        self.meta.local = local;

        if let Some(name) = overrides.name {
            self.meta.reverse_name = name;
        }
        if let Some(login) = overrides.login {
            // Informational only — never treat as SASL AUTH.
            self.meta.xclient_login = login;
        }
        if let Some(helo) = overrides.helo.clone() {
            self.helo_name = helo;
        }
        if let Some(Some(proto)) = &overrides.proto {
            if proto.eq_ignore_ascii_case("ESMTP") {
                self.extended = true;
            }
        }

        // Jump back to greeting stage (Postfix XCLIENT semantics).
        self.reset_transaction();
        self.session = SmtpSessionState::Initial;
        self.mail_from = None;
        self.recipient = None;
        self.message = None;
        // Keep `hello` so the next EHLO can re-enter MAIL FROM; HELO name
        // already reflects XCLIENT HELO when asserted.
        if overrides.helo.is_none() {
            self.helo_name = None;
            self.extended = false;
        }

        self.send_reply(
            endpoint,
            220,
            &format!("{} ESMTP Service ready", self.config.hostname),
        );
    }

    fn cmd_starttls(&mut self, endpoint: &mut dyn Endpoint) {
        if self.meta.tls {
            self.send_enhanced(endpoint, 454, "4.7.0", "TLS already active");
            return;
        }
        if self.config.tls_acceptor.is_none() || self.config.implicit_tls {
            self.send_enhanced(endpoint, 454, "4.7.0", "TLS not available");
            return;
        }
        self.send_reply(endpoint, 220, "2.0.0 Ready to start TLS");
        let _ = endpoint.start_tls();
        // Session reset to Initial; require re-EHLO after security_established.
        self.session = SmtpSessionState::Initial;
        self.extended = false;
        self.helo_name = None;
        self.mail_from = None;
        self.recipient = None;
        self.message = None;
        self.reset_transaction();
        // Keep hello handler for post-TLS EHLO.
    }

    fn cmd_auth(&mut self, endpoint: &mut dyn Endpoint, mechanism: &str, initial_response: Option<Vec<u8>>) {
        let store = match &self.config.store {
            Some(s) => Arc::clone(s),
            None => {
                self.send_enhanced(endpoint, 502, "5.5.1", "AUTH not available");
                return;
            }
        };
        let Some(mech) = SaslMechanism::from_name(mechanism) else {
            self.send_enhanced(endpoint, 504, "5.5.4", "Unrecognized authentication type");
            return;
        };
        if mech.requires_tls() && !self.meta.tls {
            self.send_enhanced(
                endpoint,
                538,
                "5.7.11",
                "Encryption required for requested authentication mechanism",
            );
            return;
        }
        let opts = SaslServerOptions {
            hostname: self.config.hostname.clone(),
            realm: self.config.hostname.clone(),
            peer_certificate: self.meta.security_info.peer_certificate_fingerprint().map(str::to_string),
            channel_binding: None,
        };
        let server = create_server(mech, store, opts);

        if server.server_first() && initial_response.is_none() {
            // A server-first mechanism must send its challenge before any
            // client response exists to step on — "complete" here would
            // mean the mechanism authenticated nobody, so it's still a
            // failure (see `AuthCheckOutcome::first_step`).
            self.sasl_step(endpoint, server, None, true);
            return;
        }

        // RFC 4954 §4 — a bare "=" is an explicit *empty* initial response
        // (present, not absent), fed straight into the mechanism rather
        // than prompting for a continuation line.
        match initial_response {
            None => {
                self.send_reply(endpoint, 334, "");
                self.sasl = Some(server);
                self.lexer.expect_sasl_response();
            }
            Some(data) => self.sasl_step(endpoint, server, Some(&data), false),
        }
    }

    /// Run one SASL step off the reactor thread (issue #181 —
    /// `SaslServer::step` can block for LDAP/PAM-backed stores). The result
    /// is applied later by `sync_pending_auth_check`, once back on the
    /// reactor; `busy` soft-rejects pipelined commands until then (same
    /// precedent as the `Delivering` state check in `receive`).
    fn sasl_step(
        &mut self,
        endpoint: &mut dyn Endpoint,
        mut server: Box<dyn SaslServer>,
        response: Option<&[u8]>,
        first_step: bool,
    ) {
        let Some(handle) = self.control_handle.clone() else {
            self.send_enhanced(endpoint, 454, "4.7.0", "Temporary authentication failure");
            return;
        };
        let response = response.map(<[u8]>::to_vec);
        let pending = Arc::clone(&self.pending_auth_check);
        let busy = Arc::clone(&self.busy);
        self.busy.store(true, Ordering::Relaxed);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let step = server.step(response.as_deref());
                Ok((server, step))
            },
            move |result: Result<(Box<dyn SaslServer>, SaslServerStep), StorageError>| {
                let result = result.map_err(|e| e.to_string());
                *pending.lock().unwrap() = Some(AuthCheckOutcome { first_step, result });
                handle.with_endpoint(move |ep| {
                    busy.store(false, Ordering::Relaxed);
                    // Nothing has been sent to the client yet at this
                    // point — the reply depends entirely on
                    // `sync_pending_auth_check`, which needs `&mut Self`
                    // and so can't run from here. The client is waiting on
                    // us, not about to send more input, so nothing else
                    // would trigger another `receive()` call; `poke_handler`
                    // forces one.
                    ep.poke_handler();
                });
            },
        );
    }

    fn handle_sasl_response(&mut self, endpoint: &mut dyn Endpoint, response: Vec<u8>) {
        let Some(server) = self.sasl.take() else {
            return;
        };
        self.sasl_step(endpoint, server, Some(&response), false);
    }

    /// Apply the outcome of an offloaded SASL step, once `sasl_step`'s
    /// `submit_on` callback has stashed one — see `AuthCheckOutcome`.
    fn sync_pending_auth_check(&mut self, endpoint: &mut dyn Endpoint) {
        let Some(AuthCheckOutcome { first_step, result }) = self.pending_auth_check.lock().unwrap().take() else {
            return;
        };
        match result {
            Ok((server, step)) => match step {
                SaslServerStep::Challenge(c) => {
                    self.send_reply(endpoint, 334, &base64::encode(&c));
                    self.sasl = Some(server);
                    self.lexer.expect_sasl_response();
                }
                SaslServerStep::Complete {
                    username,
                    final_message,
                } if !first_step => {
                    if let Some(fm) = final_message {
                        if !fm.is_empty() {
                            self.send_reply(endpoint, 334, &base64::encode(&fm));
                        }
                    }
                    self.finish_auth(endpoint, username);
                }
                SaslServerStep::Complete { .. } | SaslServerStep::Failure => {
                    self.auth_failed(endpoint);
                }
            },
            Err(e) => {
                self.send_enhanced(
                    endpoint,
                    454,
                    "4.7.0",
                    &format!("Temporary authentication failure: {e}"),
                );
            }
        }
    }

    fn auth_failed(&mut self, endpoint: &mut dyn Endpoint) {
        self.record_auth(false);
        self.send_enhanced(endpoint, 535, "5.7.8", "Authentication credentials invalid");
    }

    /// Re-invoke `finish_message` once its deferred pipeline writes have
    /// landed (issue #184) — see the comment in `finish_message` where
    /// `pending_finish` is set.
    fn sync_pending_finish(&mut self, endpoint: &mut dyn Endpoint) {
        if !self.pending_finish {
            return;
        }
        let still_pending = self
            .pipeline
            .as_ref()
            .map(|p| p.is_pending())
            .unwrap_or(false);
        if still_pending {
            return;
        }
        self.pending_finish = false;
        self.finish_message(endpoint);
    }

    fn finish_auth(&mut self, endpoint: &mut dyn Endpoint, user: String) {
        let mut hello = match self.hello.take() {
            Some(h) => h,
            None => {
                // After EHLO, hello may have been cleared — use mail_from stage.
                self.record_auth(true);
                self.meta.authenticated_user = Some(user);
                self.send_enhanced(endpoint, 235, "2.7.0", "Authentication successful");
                return;
            }
        };
        {
            let mut ctx = AuthCtx {
                endpoint,
                mail_from: &mut self.mail_from,
                hello: &mut self.hello,
                session: &mut self.session,
                meta: &mut self.meta,
                metrics: &self.metrics,
                otel_metrics: self.otel_metrics.as_ref(),
                user: user.clone(),
            };
            hello.authenticated(&mut ctx, &user);
        }
        if self.hello.is_none() && self.mail_from.is_none() {
            // closed
        } else if self.mail_from.is_some() {
            // accepted via state
        } else {
            self.hello = Some(hello);
        }
    }

    fn process_leftover(&mut self, endpoint: &mut dyn Endpoint) {
        if self.leftover.is_empty() {
            return;
        }
        let buf = std::mem::take(&mut self.leftover);
        let mut slice = buf.as_slice();
        self.receive_inner(endpoint, &mut slice);
        if !slice.is_empty() {
            self.leftover = slice.to_vec();
        }
    }

    fn receive_inner(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        match self.session {
            SmtpSessionState::Data => {
                self.feed_data(endpoint, data);
                if !self.leftover.is_empty() && self.session != SmtpSessionState::Data {
                    self.process_leftover(endpoint);
                }
            }
            SmtpSessionState::Bdat if self.bdat.is_some() => {
                self.feed_bdat(endpoint, data);
                if !self.leftover.is_empty()
                    && !(self.session == SmtpSessionState::Bdat && self.bdat.is_some())
                {
                    self.process_leftover(endpoint);
                }
            }
            _ => {
                // SASL continuation lines are read by the same lexer, in
                // raw-line mode — see `SmtpServerLexer::expect_sasl_response`,
                // armed by `cmd_auth` right after the `334` challenge is sent.
                let cmds = self.lexer.feed(data);
                if self.lexer.took_line_too_long() {
                    self.send_enhanced(endpoint, 500, "5.5.2", "Line too long");
                }
                for cmd in cmds {
                    // A SASL continuation line can itself flip `busy` (its
                    // step offloads to the storage pool) partway through
                    // this loop — any command already lexed out of this
                    // same buffer right behind it must not be dispatched
                    // against that now-stale state (issue #181); soft
                    // reject it the same way `receive` does for a command
                    // arriving in a later, separate read while busy.
                    if self.busy.load(Ordering::Relaxed) {
                        self.send_enhanced(
                            endpoint,
                            451,
                            "4.7.0",
                            "Authentication in progress, try again later",
                        );
                        continue;
                    }
                    self.dispatch(endpoint, cmd);
                }
            }
        }
    }
}

impl ProtocolHandler for SmtpControlHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Ok(peer) = endpoint.remote_addr() {
            self.tcp_peer = peer;
            self.meta.peer = peer;
        }
        if let Ok(local) = endpoint.local_addr() {
            self.meta.local = local;
        }
        if endpoint.is_secure() {
            self.meta.tls = true;
            self.meta.security_info = endpoint.security_info().clone();
        }
        let handle = endpoint.handle();
        self.control_handle = Some(handle.clone());
        self.meta.control_handle = Some(handle);
        // Plaintext or already-secure (implicit TLS completed before connected): greet now.
        // For expect_implicit_tls still handshaking, defer to security_established.
        if !self.expect_implicit_tls || self.meta.tls {
            self.maybe_greet(endpoint);
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.sync_deferred();
        self.sync_pending_auth_check(endpoint);
        self.sync_pending_finish(endpoint);
        if self.pending_finish {
            // Spool writes from the just-finished message are still
            // draining (issue #184) — soft reject pipelined commands, same
            // precedent as the `Delivering`/`busy` checks below. Must come
            // before the `session` dispatch in `receive_inner`: `session`
            // is still `Data`/`Bdat` at this point (deferring
            // `finish_message` leaves it untouched), so without this check
            // a later `receive()` call could have its bytes misinterpreted
            // as more DATA content instead of a new command.
            if !data.is_empty() {
                self.send_enhanced(
                    endpoint,
                    451,
                    "4.3.2",
                    "Message processing in progress, try again later",
                );
                *data = &[];
            }
            return;
        }
        if self.session == SmtpSessionState::Delivering {
            // Still waiting for outbound relay to finish — soft reject pipelined cmds.
            if !data.is_empty() {
                self.send_enhanced(
                    endpoint,
                    451,
                    "4.3.2",
                    "Delivery in progress, try again later",
                );
                *data = &[];
            }
            return;
        }
        if self.busy.load(Ordering::Relaxed) {
            // A SASL step is offloaded — soft reject pipelined commands
            // (issue #181), same precedent as the `Delivering` check above.
            if !data.is_empty() {
                self.send_enhanced(
                    endpoint,
                    451,
                    "4.7.0",
                    "Authentication in progress, try again later",
                );
                *data = &[];
            }
            return;
        }
        self.receive_inner(endpoint, data);
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.end_connection_telemetry();
        if let Some(mut c) = self.client_connected.take() {
            c.disconnected();
        }
    }

    fn security_established(
        &mut self,
        endpoint: &mut dyn Endpoint,
        info: &hopf_core::SecurityInfo,
    ) {
        let first = !self.meta.tls;
        self.meta.tls = true;
        self.meta.security_info = info.clone();
        if self.expect_implicit_tls && !self.greeting_sent {
            self.maybe_greet(endpoint);
            return;
        }
        if !first {
            return;
        }
        // STARTTLS completed
        self.record_starttls();
        if let Some(h) = &mut self.hello {
            h.tls_established(info);
        }
        self.session = SmtpSessionState::Initial;
        self.extended = false;
        self.helo_name = None;
        self.mail_from = None;
        self.recipient = None;
        self.message = None;
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        endpoint.close();
    }
}

fn strip_mail_prefix(arg: &str) -> &str {
    let t = arg.trim();
    if let Some(rest) = t.strip_prefix("FROM:") {
        return rest.trim();
    }
    if let Some(rest) = t.strip_prefix("from:") {
        return rest.trim();
    }
    t
}

// ── State context adapters ──────────────────────────────────────────────

struct ConnectedCtx<'a> {
    endpoint: &'a mut dyn Endpoint,
    hello: &'a mut Option<Box<dyn HelloHandler>>,
    greeting_sent: &'a mut bool,
    session: &'a mut SmtpSessionState,
}

impl ConnectedState for ConnectedCtx<'_> {
    fn accept_connection(&mut self, greeting: &str, handler: Box<dyn HelloHandler>) {
        self.endpoint.send(&reply(220, greeting));
        *self.hello = Some(handler);
        *self.greeting_sent = true;
        *self.session = SmtpSessionState::Initial;
    }

    fn reject_connection_msg(&mut self, message: &str) {
        self.endpoint.send(&reply(554, message));
        self.endpoint.close();
        *self.greeting_sent = true;
    }

    fn server_shutting_down(&mut self) {
        self.endpoint
            .send(&reply_enhanced(421, "4.3.2", "Service not available"));
        self.endpoint.close();
        *self.greeting_sent = true;
    }
}

struct HelloCtx<'a> {
    endpoint: &'a mut dyn Endpoint,
    mail_from: &'a mut Option<Box<dyn MailFromHandler>>,
    hello: &'a mut Option<Box<dyn HelloHandler>>,
    session: &'a mut SmtpSessionState,
    hostname: &'a str,
    helo_name: &'a str,
    extended: bool,
    caps: Vec<String>,
}

impl HelloState for HelloCtx<'_> {
    fn accept_hello(&mut self, handler: Box<dyn MailFromHandler>) {
        if self.extended {
            let cap_refs: Vec<&str> = self.caps.iter().map(|s| s.as_str()).collect();
            self.endpoint
                .send(&reply_ehlo(self.hostname, self.helo_name, &cap_refs));
        } else {
            self.endpoint.send(&reply(
                250,
                &format!("{} Hello {}", self.hostname, self.helo_name),
            ));
        }
        *self.mail_from = Some(handler);
        // Keep hello for AUTH / tls_established notifications.
        *self.session = SmtpSessionState::Ready;
    }

    fn reject_hello_temporary(&mut self, message: &str, handler: Box<dyn HelloHandler>) {
        self.endpoint.send(&reply(421, message));
        *self.hello = Some(handler);
    }

    fn reject_hello(&mut self, message: &str, handler: Box<dyn HelloHandler>) {
        self.endpoint.send(&reply(550, message));
        *self.hello = Some(handler);
    }

    fn reject_hello_and_close(&mut self, message: &str) {
        self.endpoint.send(&reply(554, message));
        self.endpoint.close();
    }

    fn reject(&mut self, code: u16, text: &str) {
        self.endpoint.send(&reply(code, text));
    }

    fn server_shutting_down(&mut self) {
        self.endpoint
            .send(&reply_enhanced(421, "4.3.2", "Service not available"));
        self.endpoint.close();
    }
}

struct AuthCtx<'a> {
    endpoint: &'a mut dyn Endpoint,
    mail_from: &'a mut Option<Box<dyn MailFromHandler>>,
    hello: &'a mut Option<Box<dyn HelloHandler>>,
    session: &'a mut SmtpSessionState,
    meta: &'a mut SmtpConnectionMetadata,
    metrics: &'a SmtpServerMetrics,
    otel_metrics: Option<&'a Arc<OtelSmtpMetrics>>,
    user: String,
}

impl AuthenticateState for AuthCtx<'_> {
    fn accept(&mut self, handler: Box<dyn MailFromHandler>) {
        SmtpServerMetrics::add(&self.metrics.auth_ok, 1);
        if let Some(m) = self.otel_metrics {
            m.auth(true);
        }
        self.meta.authenticated_user = Some(self.user.clone());
        self.endpoint
            .send(&reply_enhanced(235, "2.7.0", "Authentication successful"));
        *self.mail_from = Some(handler);
        *self.hello = None;
        *self.session = SmtpSessionState::Ready;
    }

    fn reject(&mut self, handler: Box<dyn HelloHandler>) {
        SmtpServerMetrics::add(&self.metrics.auth_fail, 1);
        if let Some(m) = self.otel_metrics {
            m.auth(false);
        }
        self.endpoint
            .send(&reply_enhanced(535, "5.7.8", "Authentication credentials invalid"));
        *self.hello = Some(handler);
    }

    fn reject_and_close(&mut self) {
        SmtpServerMetrics::add(&self.metrics.auth_fail, 1);
        if let Some(m) = self.otel_metrics {
            m.auth(false);
        }
        self.endpoint
            .send(&reply_enhanced(535, "5.7.8", "Authentication credentials invalid"));
        self.endpoint.close();
    }

    fn server_shutting_down(&mut self) {
        self.endpoint
            .send(&reply_enhanced(421, "4.3.2", "Service not available"));
        self.endpoint.close();
    }
}

struct MailFromCtx<'a> {
    endpoint: &'a mut dyn Endpoint,
    recipient: &'a mut Option<Box<dyn RecipientHandler>>,
    mail_from: &'a mut Option<Box<dyn MailFromHandler>>,
    session: &'a mut SmtpSessionState,
    accepted: &'a mut bool,
}

impl MailFromState for MailFromCtx<'_> {
    fn accept_sender(&mut self, handler: Box<dyn RecipientHandler>) {
        self.endpoint
            .send(&reply_enhanced(250, "2.1.0", "Sender OK"));
        *self.recipient = Some(handler);
        *self.mail_from = None;
        *self.session = SmtpSessionState::Mail;
        *self.accepted = true;
    }

    fn reject(&mut self, code: u16, text: &str, handler: Box<dyn MailFromHandler>) {
        self.endpoint.send(&reply(code, text));
        *self.mail_from = Some(handler);
        *self.accepted = false;
    }

    fn server_shutting_down(&mut self) {
        self.endpoint
            .send(&reply_enhanced(421, "4.3.2", "Service not available"));
        self.endpoint.close();
    }
}

struct RecipientCtx<'a> {
    endpoint: &'a mut dyn Endpoint,
    recipient_handler: &'a mut Option<Box<dyn RecipientHandler>>,
    session: &'a mut SmtpSessionState,
    accepted: &'a mut bool,
}

impl RecipientState for RecipientCtx<'_> {
    fn accept_recipient(&mut self, handler: Box<dyn RecipientHandler>) {
        self.endpoint
            .send(&reply_enhanced(250, "2.1.5", "Recipient OK"));
        *self.recipient_handler = Some(handler);
        *self.session = SmtpSessionState::Rcpt;
        *self.accepted = true;
    }

    fn reject(&mut self, code: u16, text: &str, handler: Box<dyn RecipientHandler>) {
        self.endpoint.send(&reply(code, text));
        *self.recipient_handler = Some(handler);
        *self.accepted = false;
    }

    fn server_shutting_down(&mut self) {
        self.endpoint
            .send(&reply_enhanced(421, "4.3.2", "Service not available"));
        self.endpoint.close();
    }
}

struct MessageStartCtx<'a> {
    endpoint: &'a mut dyn Endpoint,
    message: &'a mut Option<Box<dyn MessageDataHandler>>,
    recipient: &'a mut Option<Box<dyn RecipientHandler>>,
    mail_from: &'a mut Option<Box<dyn MailFromHandler>>,
    session: &'a mut SmtpSessionState,
    unstuffer: &'a mut DotUnstuffer,
    message_bytes: &'a mut u64,
    bdat_mode: bool,
}

impl MessageStartState for MessageStartCtx<'_> {
    fn accept_message(&mut self, handler: Box<dyn MessageDataHandler>) {
        *self.message = Some(handler);
        *self.recipient = None;
        *self.message_bytes = 0;
        self.unstuffer.reset();
        if self.bdat_mode {
            *self.session = SmtpSessionState::Bdat;
            // No 354 for BDAT
        } else {
            *self.session = SmtpSessionState::Data;
            self.endpoint
                .send(&reply(354, "Start mail input; end with <CRLF>.<CRLF>"));
        }
    }

    fn reject_message(&mut self, message: &str, handler: Box<dyn MailFromHandler>) {
        self.endpoint.send(&reply(550, message));
        *self.mail_from = Some(handler);
        *self.recipient = None;
        *self.session = SmtpSessionState::Ready;
    }

    fn reject(&mut self, code: u16, text: &str, handler: Box<dyn RecipientHandler>) {
        self.endpoint.send(&reply(code, text));
        *self.recipient = Some(handler);
    }

    fn server_shutting_down(&mut self) {
        self.endpoint
            .send(&reply_enhanced(421, "4.3.2", "Service not available"));
        self.endpoint.close();
    }
}

struct MessageEndCtx<'a> {
    endpoint: &'a mut dyn Endpoint,
    mail_from: &'a mut Option<Box<dyn MailFromHandler>>,
    session: &'a mut SmtpSessionState,
    recipients: &'a mut Vec<(EmailAddress, DsnRecipientParams)>,
    sender: &'a mut Option<EmailAddress>,
    pipeline: &'a mut Option<Box<dyn SmtpPipeline>>,
    message_bytes: &'a mut u64,
    unstuffer: &'a mut DotUnstuffer,
    bdat: &'a mut Option<BdatAccumulator>,
    bdat_started: &'a mut bool,
    body_type: &'a mut BodyType,
    delivery: &'a mut DeliveryRequirements,
    meta: &'a mut SmtpConnectionMetadata,
    deferred: &'a Arc<std::sync::Mutex<Option<DeferredSlot>>>,
    control_handle: Option<ConnHandle>,
}

impl MessageEndCtx<'_> {
    fn clear_tx(&mut self) {
        self.recipients.clear();
        *self.sender = None;
        *self.pipeline = None;
        *self.message_bytes = 0;
        self.unstuffer.reset();
        *self.bdat = None;
        *self.bdat_started = false;
        *self.body_type = BodyType::SevenBit;
        *self.delivery = DeliveryRequirements::default();
        self.meta.smtputf8 = false;
        *self.session = SmtpSessionState::Ready;
    }
}

impl MessageEndState for MessageEndCtx<'_> {
    fn accept_message_delivery(
        &mut self,
        queue_id: Option<&str>,
        handler: Box<dyn MailFromHandler>,
    ) {
        let msg = match queue_id {
            Some(id) => format!("Queued as {id}"),
            None => "Message accepted for delivery".into(),
        };
        self.endpoint
            .send(&reply_enhanced(250, "2.0.0", &msg));
        *self.mail_from = Some(handler);
        self.clear_tx();
    }

    fn reject(&mut self, code: u16, text: &str, handler: Box<dyn MailFromHandler>) {
        self.endpoint.send(&reply(code, text));
        *self.mail_from = Some(handler);
        self.clear_tx();
    }

    fn defer(&mut self, resume: Box<dyn MailFromHandler>) -> DeferredDelivery {
        let handle = self
            .control_handle
            .clone()
            .unwrap_or_else(|| self.endpoint.handle());
        self.recipients.clear();
        *self.sender = None;
        *self.pipeline = None;
        *self.message_bytes = 0;
        self.unstuffer.reset();
        *self.bdat = None;
        *self.bdat_started = false;
        *self.body_type = BodyType::SevenBit;
        *self.delivery = DeliveryRequirements::default();
        self.meta.smtputf8 = false;
        *self.session = SmtpSessionState::Delivering;
        *self.deferred.lock().unwrap() = Some(DeferredSlot {
            resume,
            outcome: None,
        });
        DeferredDelivery::new(handle, Arc::clone(self.deferred))
    }

    fn server_shutting_down(&mut self) {
        self.endpoint
            .send(&reply_enhanced(421, "4.3.2", "Service not available"));
        self.endpoint.close();
    }
}

struct ResetCtx<'a> {
    endpoint: &'a mut dyn Endpoint,
    mail_from: &'a mut Option<Box<dyn MailFromHandler>>,
    session: &'a mut SmtpSessionState,
}

impl ResetState for ResetCtx<'_> {
    fn accept_reset(&mut self, handler: Box<dyn MailFromHandler>) {
        self.endpoint
            .send(&reply_enhanced(250, "2.0.0", "Reset state"));
        *self.mail_from = Some(handler);
        *self.session = SmtpSessionState::Ready;
    }

    fn server_shutting_down(&mut self) {
        self.endpoint
            .send(&reply_enhanced(421, "4.3.2", "Service not available"));
        self.endpoint.close();
    }
}

#[cfg(test)]
mod telemetry_tests {
    use super::*;
    use crate::server::handler::AcceptAllSmtpHandler;
    use hopf_otel::{OtelConfig, SpanContext, TelemetryPipeline};

    #[test]
    fn with_telemetry_sets_parseable_traceparent_on_connect() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-smtp-tp-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let cfg = OtelConfig::new("smtp-tp-test")
            .with_jsonl_traces(&dir)
            .with_jsonl_metrics(&dir);
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        let peer: SocketAddr = "127.0.0.1:25".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:2525".parse().unwrap();
        let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
        let mut h = SmtpControlHandler::new(
            Box::new(AcceptAllSmtpHandler::new("localhost")),
            SmtpServerMetrics::shared(),
            SmtpConfig::new(local, "localhost").auth_required(false),
            peer,
            local,
            rt,
        )
        .with_telemetry(
            Some(pipeline.smtp_metrics()),
            Some(pipeline.export_handle()),
            true,
        );
        h.begin_connection_telemetry();
        let tp = h.meta.traceparent.clone().expect("traceparent set");
        let ctx = SpanContext::from_traceparent(&tp).expect("valid traceparent");
        assert!(!ctx.trace_id.iter().all(|&b| b == 0));

        h.begin_transaction_telemetry();
        let tx_tp = h.meta.traceparent.clone().expect("tx traceparent");
        let tx_ctx = SpanContext::from_traceparent(&tx_tp).unwrap();
        assert_eq!(tx_ctx.trace_id, ctx.trace_id);
        assert_ne!(tx_ctx.span_id, ctx.span_id);

        h.end_transaction_telemetry("accepted");
        let after = SpanContext::from_traceparent(h.meta.traceparent.as_deref().unwrap()).unwrap();
        assert_eq!(after.span_id, ctx.span_id);

        h.end_connection_telemetry();
        assert!(h.meta.traceparent.is_none());
        pipeline.shutdown();
        let _ = std::fs::remove_file(&dir);
    }
}

/// Issue #184: `finish_message` must not read pipeline-observable state
/// (and must not reply) until every offloaded write has landed, and must
/// soft-reject any pipelined command that arrives while it's waiting. This
/// drives `SmtpControlHandler` directly (no TCP) with a hand-controlled
/// [`SmtpPipeline`] standing in for `SpoolPipeline`'s real async drain —
/// deterministic instead of timing against real disk I/O.
#[cfg(test)]
mod pending_finish_tests {
    use super::*;
    use hopf_core::{RuntimeConfig, StartTlsError, TimerHandle, WriteReadyCallback};
    use std::sync::atomic::AtomicBool;
    use std::sync::OnceLock;
    use std::time::Duration;

    #[derive(Clone, Default)]
    struct ControllablePipeline {
        pending: Arc<AtomicBool>,
    }

    impl SmtpPipeline for ControllablePipeline {
        fn mail_from(&mut self, _sender: Option<&EmailAddress>) {}
        fn rcpt_to(&mut self, _recipient: &EmailAddress) {}
        fn message_content(&mut self, _chunk: &[u8]) -> bool {
            true
        }
        fn end_data(&mut self) {}
        fn reset(&mut self) {}
        fn is_pending(&self) -> bool {
            self.pending.load(Ordering::SeqCst)
        }
    }

    /// Mirrors [`crate::server::handler::AcceptAllSmtpHandler`] but installs
    /// a [`ControllablePipeline`] instead of `None`.
    #[derive(Clone)]
    struct PendingTestHandler {
        pipeline: ControllablePipeline,
    }

    impl SmtpClientConnected for PendingTestHandler {
        fn connected(&mut self, state: &mut dyn ConnectedState, _meta: &SmtpConnectionMetadata) {
            state.accept_connection("test.example.com ESMTP Hopf", Box::new(self.clone()));
        }
        fn disconnected(&mut self) {}
    }
    impl HelloHandler for PendingTestHandler {
        fn hello(&mut self, state: &mut dyn HelloState, _extended: bool, _hostname: &str) {
            state.accept_hello(Box::new(self.clone()));
        }
        fn tls_established(&mut self, _info: &hopf_core::SecurityInfo) {}
        fn authenticated(&mut self, state: &mut dyn AuthenticateState, _user: &str) {
            state.accept(Box::new(self.clone()));
        }
        fn quit(&mut self) {}
    }
    impl MailFromHandler for PendingTestHandler {
        fn pipeline(&mut self) -> Option<Box<dyn SmtpPipeline>> {
            Some(Box::new(self.pipeline.clone()))
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
    impl RecipientHandler for PendingTestHandler {
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
    impl MessageDataHandler for PendingTestHandler {
        fn message_content(&mut self, _chunk: &[u8]) {}
        fn message_complete(&mut self, state: &mut dyn MessageEndState) {
            state.accept_message_delivery(None, Box::new(self.clone()));
        }
        fn message_aborted(&mut self) {}
    }

    /// Minimal `Endpoint`: captures sent bytes, no real I/O or reactor.
    struct MockEndpoint {
        sent: Vec<u8>,
        open: bool,
    }
    impl MockEndpoint {
        fn new() -> Self {
            Self {
                sent: Vec::new(),
                open: true,
            }
        }
    }
    impl hopf_core::Endpoint for MockEndpoint {
        fn send(&mut self, data: &[u8]) {
            self.sent.extend_from_slice(data);
        }
        fn is_open(&self) -> bool {
            self.open
        }
        fn is_closing(&self) -> bool {
            false
        }
        fn close(&mut self) {
            self.open = false;
        }
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok("127.0.0.1:25".parse().unwrap())
        }
        fn remote_addr(&self) -> std::io::Result<SocketAddr> {
            Ok("127.0.0.1:9999".parse().unwrap())
        }
        fn security_info(&self) -> &hopf_core::SecurityInfo {
            static PLAINTEXT: OnceLock<hopf_core::SecurityInfo> = OnceLock::new();
            PLAINTEXT.get_or_init(hopf_core::SecurityInfo::plaintext)
        }
        fn start_tls(&mut self) -> Result<(), StartTlsError> {
            Err(StartTlsError::Unsupported)
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _callback: Option<WriteReadyCallback>) {}
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn schedule_timer(
            &self,
            _delay: Duration,
            _callback: Box<dyn FnOnce() + Send>,
        ) -> TimerHandle {
            TimerHandle::from_cancel(|| {})
        }
        fn handle(&self) -> ConnHandle {
            ConnHandle::from_execute(Arc::new(|task| task()))
        }
    }

    fn new_handler(pipeline: ControllablePipeline) -> SmtpControlHandler {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:25".parse().unwrap();
        let config = SmtpConfig::new(local, "test.example.com").auth_required(false);
        let client = Box::new(PendingTestHandler { pipeline });
        SmtpControlHandler::new(client, SmtpServerMetrics::shared(), config, peer, local, rt)
    }

    fn feed(h: &mut SmtpControlHandler, ep: &mut MockEndpoint, line: &[u8]) {
        let mut data = line;
        h.receive(ep, &mut data);
    }

    /// Numeric code of the last CRLF-terminated reply line seen so far.
    fn last_reply_code(sent: &[u8]) -> Option<u32> {
        let text = String::from_utf8_lossy(sent);
        text.lines()
            .rev()
            .find(|l| !l.is_empty())
            .and_then(|l| l.get(0..3))
            .and_then(|c| c.parse().ok())
    }

    #[test]
    fn finish_message_defers_until_pipeline_drains_and_soft_rejects_pipelined_commands() {
        let pipeline = ControllablePipeline::default();
        // Simulate a write still in flight when the DATA terminator arrives
        // (the exact race `is_pending()`/`pending_finish` close).
        pipeline.pending.store(true, Ordering::SeqCst);
        let mut handler = new_handler(pipeline.clone());
        let mut ep = MockEndpoint::new();

        handler.connected(&mut ep);
        feed(&mut handler, &mut ep, b"EHLO client.example\r\n");
        feed(&mut handler, &mut ep, b"MAIL FROM:<a@b.example>\r\n");
        feed(&mut handler, &mut ep, b"RCPT TO:<c@d.example>\r\n");
        feed(&mut handler, &mut ep, b"DATA\r\n");
        ep.sent.clear();

        feed(&mut handler, &mut ep, b"hello world\r\n.\r\n");
        assert!(
            ep.sent.is_empty(),
            "must not reply while the spool write is still pending: {:?}",
            String::from_utf8_lossy(&ep.sent)
        );
        assert!(handler.pending_finish, "finish_message must have deferred");

        // A pipelined command arriving while the write drains must be
        // soft-rejected, not dispatched against stale session state.
        feed(&mut handler, &mut ep, b"QUIT\r\n");
        assert_eq!(last_reply_code(&ep.sent), Some(451));
        ep.sent.clear();

        // The write "lands" (mirrors `spool.rs::drain_next`'s callback);
        // a subsequent `receive()` call (standing in for the production
        // `poke_handler` re-entry) must now complete the deferred finish.
        pipeline.pending.store(false, Ordering::SeqCst);
        feed(&mut handler, &mut ep, b"");
        assert!(
            !handler.pending_finish,
            "must clear once the pipeline drains"
        );
        assert_eq!(
            last_reply_code(&ep.sent),
            Some(250),
            "deferred finish must complete once no longer pending: {:?}",
            String::from_utf8_lossy(&ep.sent)
        );
    }

    #[test]
    fn finish_message_completes_immediately_when_pipeline_never_pending() {
        let pipeline = ControllablePipeline::default();
        let mut handler = new_handler(pipeline);
        let mut ep = MockEndpoint::new();

        handler.connected(&mut ep);
        feed(&mut handler, &mut ep, b"EHLO client.example\r\n");
        feed(&mut handler, &mut ep, b"MAIL FROM:<a@b.example>\r\n");
        feed(&mut handler, &mut ep, b"RCPT TO:<c@d.example>\r\n");
        feed(&mut handler, &mut ep, b"DATA\r\n");
        ep.sent.clear();

        feed(&mut handler, &mut ep, b"hello world\r\n.\r\n");
        assert!(!handler.pending_finish);
        assert_eq!(last_reply_code(&ep.sent), Some(250));
    }
}
