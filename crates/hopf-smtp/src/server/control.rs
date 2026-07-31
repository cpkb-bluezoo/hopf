// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP connection protocol engine (`ProtocolHandler`).

use std::net::SocketAddr;
use std::sync::Arc;

use rmimeparser::{EmailAddress, EmailAddressParser};
use hopf_auth::{IdentityMaterial, PeerContext, TrustDecision};
use hopf_core::{ConnHandle, Endpoint, ProtocolHandler};

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
}

impl SmtpControlHandler {
    /// Create for a new connection.
    pub fn new(
        client: Box<dyn SmtpClientConnected>,
        metrics: Arc<SmtpServerMetrics>,
        config: SmtpConfig,
        peer: SocketAddr,
        local: SocketAddr,
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
            "HELP".into(),
        ];
        if self.config.tls_acceptor.is_some() && !self.meta.tls && !self.config.implicit_tls {
            caps.push("STARTTLS".into());
        }
        if self.config.policy.is_some() && (self.meta.tls || self.config.tls_acceptor.is_some()) {
            // Advertise AUTH PLAIN when TLS is up, or STARTTLS is available (clients
            // must upgrade first — we still list it when starttls is offered).
            if self.meta.tls {
                caps.push("AUTH PLAIN".into());
            }
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
            SmtpCommand::SaslResponse(data) => self.finish_auth_plain(endpoint, data),
            SmtpCommand::SaslAbort => {
                self.send_enhanced(endpoint, 501, "5.0.0", "Authentication cancelled");
            }
            SmtpCommand::SaslResponseInvalid => {
                SmtpServerMetrics::add(&self.metrics.auth_fail, 1);
                self.send_enhanced(endpoint, 535, "5.7.8", "Authentication credentials invalid");
            }
            SmtpCommand::Xclient => self.send_enhanced(endpoint, 550, "5.7.0", "XCLIENT not permitted"),
            SmtpCommand::Malformed { .. } => {
                SmtpServerMetrics::add(&self.metrics.auth_fail, 1);
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
        }
        SmtpServerMetrics::add(&self.metrics.messages, 1);
        SmtpServerMetrics::add(&self.metrics.bytes, self.message_bytes);
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
        self.send(
            endpoint,
            reply_multiline(
                214,
                &[
                    "HELO EHLO MAIL RCPT DATA BDAT RSET NOOP QUIT HELP AUTH STARTTLS",
                    "End of HELP",
                ],
            ),
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
        if self.config.policy.is_none() {
            self.send_enhanced(endpoint, 502, "5.5.1", "AUTH not available");
            return;
        }
        if !self.meta.tls {
            self.send_enhanced(endpoint, 538, "5.7.11", "Encryption required for requested authentication mechanism");
            return;
        }
        if !mechanism.eq_ignore_ascii_case("PLAIN") {
            self.send_enhanced(endpoint, 504, "5.5.4", "Unrecognized authentication type");
            return;
        }
        match initial_response {
            None => {
                self.send_reply(endpoint, 334, "");
                self.lexer.expect_sasl_response();
            }
            // RFC 4954 §4 — a bare "=" is an explicit *empty* initial
            // response (present, not absent), fed straight into the
            // mechanism rather than prompting for a continuation line.
            Some(data) => self.finish_auth_plain(endpoint, data),
        }
    }

    fn finish_auth_plain(&mut self, endpoint: &mut dyn Endpoint, decoded: Vec<u8>) {
        // AUTH PLAIN: [authzid] \0 authcid \0 passwd
        let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
        if parts.len() < 3 {
            SmtpServerMetrics::add(&self.metrics.auth_fail, 1);
            self.send_enhanced(endpoint, 535, "5.7.8", "Authentication credentials invalid");
            return;
        }
        let user = String::from_utf8_lossy(parts[1]).into_owned();
        let pass = String::from_utf8_lossy(parts[2]).into_owned();
        let policy = match &self.config.policy {
            Some(p) => p,
            None => {
                self.send_enhanced(endpoint, 454, "4.7.0", "Temporary authentication failure");
                return;
            }
        };
        let identity = IdentityMaterial::UsernamePassword {
            username: user.clone(),
            password: pass,
        };
        let peer = PeerContext::from_addr(self.meta.peer);
        match policy.evaluate(&identity, &peer) {
            TrustDecision::Reject => {
                SmtpServerMetrics::add(&self.metrics.auth_fail, 1);
                self.send_enhanced(endpoint, 535, "5.7.8", "Authentication credentials invalid");
            }
            TrustDecision::Accept => {
                let mut hello = match self.hello.take() {
                    Some(h) => h,
                    None => {
                        // After EHLO, hello may have been cleared — use mail_from stage.
                        SmtpServerMetrics::add(&self.metrics.auth_ok, 1);
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
                for cmd in cmds {
                    self.dispatch(endpoint, cmd);
                }
            }
        }
    }
}

impl ProtocolHandler for SmtpControlHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Ok(peer) = endpoint.remote_addr() {
            self.meta.peer = peer;
        }
        if let Ok(local) = endpoint.local_addr() {
            self.meta.local = local;
        }
        if endpoint.is_secure() {
            self.meta.tls = true;
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
        self.receive_inner(endpoint, data);
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Some(mut c) = self.client_connected.take() {
            c.disconnected();
        }
    }

    fn security_established(
        &mut self,
        endpoint: &mut dyn Endpoint,
        _info: &hopf_core::SecurityInfo,
    ) {
        let first = !self.meta.tls;
        self.meta.tls = true;
        if self.expect_implicit_tls && !self.greeting_sent {
            self.maybe_greet(endpoint);
            return;
        }
        if !first {
            return;
        }
        // STARTTLS completed
        SmtpServerMetrics::add(&self.metrics.starttls, 1);
        if let Some(h) = &mut self.hello {
            h.tls_established();
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
    user: String,
}

impl AuthenticateState for AuthCtx<'_> {
    fn accept(&mut self, handler: Box<dyn MailFromHandler>) {
        SmtpServerMetrics::add(&self.metrics.auth_ok, 1);
        self.meta.authenticated_user = Some(self.user.clone());
        self.endpoint
            .send(&reply_enhanced(235, "2.7.0", "Authentication successful"));
        *self.mail_from = Some(handler);
        *self.hello = None;
        *self.session = SmtpSessionState::Ready;
    }

    fn reject(&mut self, handler: Box<dyn HelloHandler>) {
        SmtpServerMetrics::add(&self.metrics.auth_fail, 1);
        self.endpoint
            .send(&reply_enhanced(535, "5.7.8", "Authentication credentials invalid"));
        *self.hello = Some(handler);
    }

    fn reject_and_close(&mut self) {
        SmtpServerMetrics::add(&self.metrics.auth_fail, 1);
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
