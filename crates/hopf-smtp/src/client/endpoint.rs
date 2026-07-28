// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `SmtpClientEndpoint` — async SMTP client as a [`ProtocolHandler`].
//!
//! Holds the protocol state machine, lexer, driver, and EHLO capabilities.
//! Uses a command-queue pattern: state-trait methods write serialised SMTP
//! command bytes to `self.outbound`; after each driver callback returns, the
//! caller's `receive` / `connected` / `security_established` method flushes
//! the queue to the [`Endpoint`].

use std::io;
use std::time::Duration;

use base64::Engine;
use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, SharedTlsConnector, TimerHandle};

use super::handlers::{SmtpClientDriver, SmtpClientHandlerFactory};
use super::reply::{SmtpEvent, SmtpReplyLexer, SmtpReplyShape};
use super::state::{
    SmtpCapabilities, SmtpClientAuthExchange, SmtpClientEnvelope, SmtpClientHello,
    SmtpClientMessageData, SmtpClientPostTls, SmtpClientSession,
};
use crate::client::dot_stuff;

// ── Protocol state ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProtoState {
    /// Waiting for 220 greeting.
    Connecting,
    /// Greeting received; ready for EHLO/HELO.
    Connected,
    /// EHLO sent; waiting for 250 multiline.
    EhloSent,
    /// HELO sent; waiting for 250.
    HeloSent,
    /// STARTTLS sent; waiting for 220.
    StarttlsSent,
    /// AUTH sent; waiting for 235/334/5xx.
    AuthSent,
    /// MAIL FROM sent; waiting for 250/4xx/5xx.
    MailFromSent,
    /// RCPT TO sent; waiting for 250-252/4xx/5xx.
    RcptToSent(String),
    /// DATA sent; waiting for 354.
    DataCommandSent,
    /// Writing message data (dot-stuffed).
    DataMode,
    /// End-of-data sent (CRLF.CRLF); waiting for 250/4xx/5xx.
    DataEndSent,
    /// RSET sent; waiting for 250.
    RsetSent,
    /// QUIT sent.
    QuitSent,
    /// Terminal states.
    Closed,
    Error,
}

// ── SmtpClientEndpoint ────────────────────────────────────────────────────────

/// Async SMTP client [`ProtocolHandler`].
///
/// Created by [`super::facade::SmtpClient::connect`]. The lifecycle and
/// protocol transitions are driven entirely via the [`SmtpClientDriver`]
/// produced by a [`SmtpClientHandlerFactory`].
pub struct SmtpClientEndpoint {
    /// Protocol driver created by the factory.
    driver: Option<Box<dyn SmtpClientDriver>>,
    /// Protocol state machine.
    proto_state: ProtoState,
    /// Capabilities from most recent EHLO.
    caps: SmtpCapabilities,
    /// Incremental reply lexer.
    lexer: SmtpReplyLexer,
    /// TLS connector for STARTTLS (if configured).
    tls_connector: Option<SharedTlsConnector>,
    /// SNI / cert server name for STARTTLS.
    tls_server_name: Option<String>,
    /// Per-stage idle timer. Armed after each command; cancelled on reply.
    stage_timer: Option<TimerHandle>,
    /// Per-stage timeout duration.
    stage_timeout: Duration,
    /// Post-DATA message timeout duration (reserved for future use).
    #[allow(dead_code)]
    message_timeout: Duration,
    /// Number of accepted RCPT TOs.
    accepted_rcpts: usize,
    /// Outbound command queue — flushed to the Endpoint after every callback.
    outbound: Vec<u8>,
    /// Set when TLS STARTTLS handshake is in-flight and we need to arm greeting timer after.
    pending_tls: bool,
    /// Connect budget remaining (reserved for future use).
    #[allow(dead_code)]
    connect_budget_remaining: Option<Duration>,
}

impl SmtpClientEndpoint {
    /// Create a new endpoint from a factory. `stage_timeout` is the per-reply
    /// idle budget; `message_timeout` is the budget after DATA end.
    pub fn new(
        factory: &dyn SmtpClientHandlerFactory,
        stage_timeout: Duration,
        message_timeout: Duration,
        tls_connector: Option<SharedTlsConnector>,
        tls_server_name: Option<String>,
    ) -> Self {
        Self {
            driver: Some(factory.create()),
            proto_state: ProtoState::Connecting,
            caps: SmtpCapabilities::default(),
            lexer: SmtpReplyLexer::new(),
            tls_connector,
            tls_server_name,
            stage_timer: None,
            stage_timeout,
            message_timeout,
            accepted_rcpts: 0,
            outbound: Vec::with_capacity(512),
            pending_tls: false,
            connect_budget_remaining: None,
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Write bytes to the outbound queue.
    fn write_cmd(&mut self, bytes: &[u8]) {
        self.outbound.extend_from_slice(bytes);
    }

    /// Write a CRLF-terminated command line.
    fn write_line(&mut self, line: &str) {
        self.write_cmd(line.as_bytes());
        self.write_cmd(b"\r\n");
    }

    /// Flush `outbound` to the endpoint and arm the stage timer.
    #[allow(dead_code)]
    fn flush(&mut self, ep: &mut dyn Endpoint) {
        if !self.outbound.is_empty() {
            let out = std::mem::take(&mut self.outbound);
            ep.send(&out);
        }
        self.arm_stage_timer(ep);
    }

    /// Cancel any active stage timer.
    fn cancel_timer(&mut self) {
        if let Some(t) = self.stage_timer.take() {
            t.cancel();
        }
    }

    /// Arm a new stage timer. On fire, delivers TimedOut via [`Endpoint::fail`].
    fn arm_stage_timer(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_timer();
        if self.stage_timeout.is_zero() {
            return;
        }
        let handle = ep.handle();
        let timer = ep.schedule_timer(
            self.stage_timeout,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "SMTP stage timed out",
                    ));
                });
            }),
        );
        self.stage_timer = Some(timer);
    }

    /// Dispatch a stage-timer timeout.
    fn on_stage_timeout(&mut self, ep: &mut dyn Endpoint) {
        self.proto_state = ProtoState::Error;
        if let Some(mut driver) = self.driver.take() {
            driver.on_timeout(ep);
            self.driver = Some(driver);
        }
        ep.close();
    }

    /// Handle a protocol parse error.
    fn protocol_error(&mut self, ep: &mut dyn Endpoint, msg: String) {
        self.proto_state = ProtoState::Error;
        let err = io::Error::new(io::ErrorKind::InvalidData, msg);
        if let Some(mut driver) = self.driver.take() {
            driver.on_error(ep, &err);
            self.driver = Some(driver);
        }
        ep.close();
    }

    // ── Event dispatch ────────────────────────────────────────────────────

    fn dispatch_event(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint) {
        self.cancel_timer();

        // RFC 5321 §4.2.1 — 421 service closing: close immediately,
        // regardless of what was expected.
        if let SmtpEvent::ServiceClosing { message } = event {
            self.proto_state = ProtoState::Closed;
            if let Some(mut driver) = self.driver.take() {
                let err = io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("421 service closing: {message}"),
                );
                driver.on_error(ep, &err);
                self.driver = Some(driver);
            }
            ep.close();
            return;
        }

        let state = self.proto_state.clone();
        match state {
            ProtoState::Connecting => self.dispatch_greeting(event, ep),
            ProtoState::EhloSent => self.dispatch_ehlo(event, ep),
            ProtoState::HeloSent => self.dispatch_helo(event, ep),
            ProtoState::StarttlsSent => self.dispatch_starttls(event, ep),
            ProtoState::AuthSent => self.dispatch_auth(event, ep),
            ProtoState::MailFromSent => self.dispatch_mail_from(event, ep),
            ProtoState::RcptToSent(ref recipient) => {
                let r = recipient.clone();
                self.dispatch_rcpt_to(event, ep, &r);
            }
            ProtoState::DataCommandSent => self.dispatch_data_command(event, ep),
            ProtoState::DataMode => {
                // Unexpected reply in DATA mode — ignore (BDAT chunk ack path not implemented).
            }
            ProtoState::DataEndSent => self.dispatch_message_reply(event, ep),
            ProtoState::RsetSent => self.dispatch_rset(event, ep),
            ProtoState::QuitSent | ProtoState::Closed => {
                self.proto_state = ProtoState::Closed;
                ep.close();
            }
            ProtoState::Connected | ProtoState::Error => {}
        }
    }

    fn dispatch_greeting(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            SmtpEvent::Greeting { esmtp } => {
                self.proto_state = ProtoState::Connected;
                driver.on_greeting(self, ep, esmtp);
            }
            SmtpEvent::ServiceUnavailable { message } => {
                self.proto_state = ProtoState::Error;
                driver.on_service_unavailable(ep, &message);
                ep.close();
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn dispatch_ehlo(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            SmtpEvent::Ehlo(caps) => {
                self.caps = caps.clone();
                self.proto_state = ProtoState::Connected;
                driver.on_ehlo(self, ep, &caps);
            }
            SmtpEvent::EhloNotSupported => {
                self.proto_state = ProtoState::Connected;
                driver.on_ehlo_not_supported(self, ep);
            }
            SmtpEvent::EhloError { message } => {
                self.proto_state = ProtoState::Error;
                driver.on_ehlo_error(ep, &message);
                ep.close();
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn dispatch_helo(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            SmtpEvent::Helo => {
                self.caps = SmtpCapabilities::default();
                self.proto_state = ProtoState::Connected;
                driver.on_helo(self, ep);
            }
            SmtpEvent::HeloError { message } => {
                self.proto_state = ProtoState::Error;
                driver.on_helo_error(ep, &message);
                ep.close();
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn dispatch_starttls(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint) {
        match event {
            SmtpEvent::StarttlsAccepted => {
                if let Some(connector) = self.tls_connector.clone() {
                    let name = self.tls_server_name.clone().unwrap_or_else(|| "localhost".into());
                    match ep.start_client_tls(connector, &name) {
                        Ok(()) => {
                            self.pending_tls = true;
                            self.caps = SmtpCapabilities::default();
                            self.accepted_rcpts = 0;
                            self.arm_stage_timer(ep);
                            // security_established callback will fire when handshake completes.
                        }
                        Err(e) => {
                            let err = io::Error::new(io::ErrorKind::Other, format!("start_client_tls: {e}"));
                            self.proto_state = ProtoState::Error;
                            if let Some(mut driver) = self.driver.take() {
                                driver.on_error(ep, &err);
                                self.driver = Some(driver);
                            }
                            ep.close();
                        }
                    }
                } else {
                    // No connector configured — treat as unavailable.
                    let mut driver = match self.driver.take() {
                        Some(d) => d,
                        None => return,
                    };
                    self.proto_state = ProtoState::Connected;
                    driver.on_tls_unavailable(self, ep);
                    self.driver = Some(driver);
                }
            }
            SmtpEvent::TlsUnavailable => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                self.proto_state = ProtoState::Connected;
                driver.on_tls_unavailable(self, ep);
                self.driver = Some(driver);
            }
            SmtpEvent::TlsError { message } => {
                self.proto_state = ProtoState::Error;
                if let Some(mut driver) = self.driver.take() {
                    driver.on_tls_error(ep, &message);
                    self.driver = Some(driver);
                }
                ep.close();
            }
            _ => {}
        }
    }

    fn dispatch_auth(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            SmtpEvent::AuthOk => {
                self.proto_state = ProtoState::Connected;
                driver.on_auth_ok(self, ep);
            }
            SmtpEvent::AuthChallenge { data } => {
                driver.on_auth_challenge(self, ep, &data);
            }
            SmtpEvent::AuthFailed { code } => {
                self.proto_state = ProtoState::Connected;
                driver.on_auth_failed(self, ep, code);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn dispatch_mail_from(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            SmtpEvent::MailOk => {
                self.proto_state = ProtoState::Connected; // stays Connected (envelope phase)
                driver.on_mail_ok(self, ep);
            }
            SmtpEvent::MailRejected { code, message } => {
                self.proto_state = ProtoState::Connected;
                driver.on_mail_rejected(self, ep, code, &message);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn dispatch_rcpt_to(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint, recipient: &str) {
        let r = recipient.to_string();
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            SmtpEvent::RcptOk => {
                self.accepted_rcpts += 1;
                self.proto_state = ProtoState::Connected;
                driver.on_rcpt_ok(self, ep, &r);
            }
            SmtpEvent::RcptRejected { code, message } => {
                self.proto_state = ProtoState::Connected;
                driver.on_rcpt_rejected(self, ep, &r, code, &message);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn dispatch_data_command(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            SmtpEvent::ReadyForData => {
                self.proto_state = ProtoState::DataMode;
                driver.on_ready_for_data(self, ep);
            }
            SmtpEvent::MessageRejected { code, message } => {
                self.proto_state = ProtoState::Connected;
                driver.on_message_rejected(self, ep, code, &message);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn dispatch_message_reply(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            SmtpEvent::MessageAccepted { queue_id } => {
                self.proto_state = ProtoState::Connected;
                self.accepted_rcpts = 0;
                driver.on_message_accepted(self, ep, queue_id.as_deref());
            }
            SmtpEvent::MessageRejected { code, message } => {
                self.proto_state = ProtoState::Connected;
                self.accepted_rcpts = 0;
                driver.on_message_rejected(self, ep, code, &message);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn dispatch_rset(&mut self, event: SmtpEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        // RFC 5321 — RSET always succeeds with 250.
        let _ = event;
        self.accepted_rcpts = 0;
        self.proto_state = ProtoState::Connected;
        driver.on_rset_ok(self, ep);
        self.driver = Some(driver);
    }
}

// ── ProtocolHandler ───────────────────────────────────────────────────────────

impl ProtocolHandler for SmtpClientEndpoint {
    fn connected(&mut self, ep: &mut dyn Endpoint) {
        // Nothing to send yet — wait for 220 greeting.
        // Arm stage timer for the greeting timeout.
        self.lexer.expect(SmtpReplyShape::Greeting);
        self.arm_stage_timer(ep);
    }

    fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
        let events = match self.lexer.feed(data) {
            Ok(e) => e,
            Err(e) => {
                let msg = e.to_string();
                self.protocol_error(ep, msg);
                return;
            }
        };
        for event in events {
            if self.proto_state == ProtoState::Closed || self.proto_state == ProtoState::Error {
                break;
            }
            self.dispatch_event(event, ep);
            // Flush after every dispatched reply.
            if !self.outbound.is_empty() {
                let out = std::mem::take(&mut self.outbound);
                ep.send(&out);
            }
        }
    }

    fn security_established(&mut self, ep: &mut dyn Endpoint, _info: &SecurityInfo) {
        if self.pending_tls {
            self.pending_tls = false;
            self.proto_state = ProtoState::Connected;
            let mut driver = match self.driver.take() {
                Some(d) => d,
                None => return,
            };
            driver.on_tls_established(self, ep);
            self.driver = Some(driver);
            // Flush EHLO command issued by the driver.
            if !self.outbound.is_empty() {
                let out = std::mem::take(&mut self.outbound);
                ep.send(&out);
            }
            self.arm_stage_timer(ep);
        }
    }

    fn disconnected(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_timer();
        if self.proto_state == ProtoState::Closed || self.proto_state == ProtoState::Error {
            return;
        }
        self.proto_state = ProtoState::Closed;
        if let Some(mut driver) = self.driver.take() {
            driver.on_disconnected(ep);
            self.driver = Some(driver);
        }
    }

    fn error(&mut self, ep: &mut dyn Endpoint, err: &io::Error) {
        self.cancel_timer();
        if err.kind() == io::ErrorKind::TimedOut {
            self.on_stage_timeout(ep);
            return;
        }
        self.proto_state = ProtoState::Error;
        if let Some(mut driver) = self.driver.take() {
            driver.on_error(ep, err);
            self.driver = Some(driver);
        }
    }
}

// ── SmtpClientHello ───────────────────────────────────────────────────────────

impl SmtpClientHello for SmtpClientEndpoint {
    fn ehlo(&mut self, hostname: &str) {
        self.proto_state = ProtoState::EhloSent;
        self.lexer.expect(SmtpReplyShape::Ehlo);
        self.write_line(&format!("EHLO {hostname}"));
    }

    fn helo(&mut self, hostname: &str) {
        self.proto_state = ProtoState::HeloSent;
        self.lexer.expect(SmtpReplyShape::Helo);
        self.write_line(&format!("HELO {hostname}"));
    }
}

// ── SmtpClientPostTls ─────────────────────────────────────────────────────────

impl SmtpClientPostTls for SmtpClientEndpoint {}

// ── SmtpClientSession ─────────────────────────────────────────────────────────

impl SmtpClientSession for SmtpClientEndpoint {
    fn mail_from(&mut self, sender: Option<&str>) {
        let arg = match sender {
            Some(s) if !s.is_empty() => format!("MAIL FROM:<{s}>"),
            _ => "MAIL FROM:<>".to_string(),
        };
        self.proto_state = ProtoState::MailFromSent;
        self.lexer.expect(SmtpReplyShape::MailFrom);
        self.write_line(&arg);
    }

    fn starttls(&mut self) {
        self.proto_state = ProtoState::StarttlsSent;
        self.lexer.expect(SmtpReplyShape::Starttls);
        self.write_line("STARTTLS");
    }

    fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>) {
        self.proto_state = ProtoState::AuthSent;
        self.lexer.expect(SmtpReplyShape::Auth);
        let arg = match initial {
            Some(b) => {
                let enc = base64::engine::general_purpose::STANDARD.encode(b);
                format!("AUTH {mechanism} {enc}")
            }
            None => format!("AUTH {mechanism}"),
        };
        self.write_line(&arg);
    }

    fn quit(&mut self) {
        self.proto_state = ProtoState::QuitSent;
        self.lexer.expect(SmtpReplyShape::Quit);
        self.write_line("QUIT");
    }

    fn capabilities(&self) -> &SmtpCapabilities {
        &self.caps
    }
}

// ── SmtpClientAuthExchange ────────────────────────────────────────────────────

impl SmtpClientAuthExchange for SmtpClientEndpoint {
    fn respond(&mut self, response: &[u8]) {
        self.proto_state = ProtoState::AuthSent;
        self.lexer.expect(SmtpReplyShape::Auth);
        let enc = base64::engine::general_purpose::STANDARD.encode(response);
        self.write_line(&enc);
    }

    fn abort(&mut self) {
        self.proto_state = ProtoState::AuthSent;
        self.lexer.expect(SmtpReplyShape::Auth);
        self.write_line("*");
    }
}

// ── SmtpClientEnvelope ────────────────────────────────────────────────────────

impl SmtpClientEnvelope for SmtpClientEndpoint {
    fn rcpt_to(&mut self, recipient: &str) {
        self.proto_state = ProtoState::RcptToSent(recipient.to_string());
        self.lexer.expect(SmtpReplyShape::RcptTo);
        self.write_line(&format!("RCPT TO:<{recipient}>"));
    }

    fn rset(&mut self) {
        self.proto_state = ProtoState::RsetSent;
        self.lexer.expect(SmtpReplyShape::Rset);
        self.write_line("RSET");
    }

    fn start_data(&mut self) {
        self.proto_state = ProtoState::DataCommandSent;
        self.lexer.expect(SmtpReplyShape::DataCommand);
        self.write_line("DATA");
    }

    fn has_accepted_recipients(&self) -> bool {
        self.accepted_rcpts > 0
    }
}

// ── SmtpClientMessageData ─────────────────────────────────────────────────────

impl SmtpClientMessageData for SmtpClientEndpoint {
    fn write_content(&mut self, content: &[u8]) {
        if self.proto_state != ProtoState::DataMode {
            return;
        }
        let stuffed = dot_stuff(content);
        self.outbound.extend_from_slice(&stuffed);
    }

    fn end_message(&mut self) {
        if self.proto_state != ProtoState::DataMode {
            return;
        }
        self.proto_state = ProtoState::DataEndSent;
        self.lexer.expect(SmtpReplyShape::DataEnd);
        // Ensure the buffered data ends with CRLF before the dot.
        // (dot_stuff already handles CRLF normalization for each chunk)
        self.outbound.extend_from_slice(b".\r\n");
    }
}
