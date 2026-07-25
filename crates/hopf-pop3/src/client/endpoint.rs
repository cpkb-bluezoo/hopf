// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `Pop3ClientEndpoint` — async POP3 client as a [`ProtocolHandler`].
//!
//! The protocol state machine is driven entirely via the [`Pop3ClientDriver`]
//! produced by a [`Pop3ClientHandlerFactory`].  Command bytes are queued into
//! `outbound` and flushed to the [`Endpoint`] after each driver callback.

use std::io;
use std::time::Duration;

use base64::Engine;
use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, SharedTlsConnector, TimerHandle};

use super::handlers::{Pop3ClientDriver, Pop3ClientHandlerFactory};
use super::reply::{Pop3ReplyLexer, Pop3WireEvent};
use super::state::{
    Pop3Capabilities, Pop3ClientAuthExchange, Pop3ClientAuthorization, Pop3ClientPassword,
    Pop3ClientPostStls, Pop3ClientTransaction,
};
use super::unstuff::Pop3DotUnstuffer;

// ── Protocol state ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProtoState {
    /// Waiting for the +OK greeting.
    Connecting,
    /// CAPA sent from Authorization state.
    CapaAuthSent,
    /// CAPA sent from post-STLS state.
    CapaPostTlsSent,
    /// USER sent; waiting for +OK/-ERR.
    UserSent,
    /// PASS sent; waiting for +OK/-ERR (authentication).
    PassSent,
    /// APOP sent; waiting for +OK/-ERR.
    ApopSent,
    /// AUTH sent or responding to a challenge; waiting for +OK/-ERR/+.
    AuthSent,
    /// STLS sent; waiting for +OK/-ERR.
    StlsSent,
    /// STLS +OK received; TLS handshake in progress.
    PendingTls,
    /// Authenticated; no command in flight.
    Transaction,
    /// STAT sent; waiting for +OK/-ERR.
    StatSent,
    /// LIST (all) sent; waiting for +OK then listing lines.
    ListAllSent,
    /// LIST n sent; waiting for single-line +OK/-ERR.
    ListOneSent(u32),
    /// UIDL (all) sent; waiting for +OK then listing lines.
    UidlAllSent,
    /// UIDL n sent; waiting for single-line +OK/-ERR.
    UidlOneSent(u32),
    /// RETR n sent; waiting for +OK then body.
    RetrSent(u32),
    /// TOP n sent; waiting for +OK then body.
    TopSent(u32),
    /// DELE sent; waiting for +OK/-ERR.
    DeleSent,
    /// RSET sent; waiting for +OK.
    RsetSent,
    /// NOOP sent; waiting for +OK.
    NoopSent,
    /// QUIT sent; waiting for +OK then EOF.
    QuitSent,
    /// Streaming RETR body via DotUnstuffer.
    RetrBody(u32),
    /// Streaming TOP body via DotUnstuffer.
    TopBody(u32),
    /// Terminal error state.
    Error,
    /// Connection closed cleanly.
    Closed,
}

// ── Endpoint ──────────────────────────────────────────────────────────────────

/// Async POP3 client [`ProtocolHandler`].
///
/// Created by [`super::facade::Pop3Client::connect`].
pub struct Pop3ClientEndpoint {
    driver: Option<Box<dyn Pop3ClientDriver>>,
    proto_state: ProtoState,
    caps: Pop3Capabilities,
    lexer: Pop3ReplyLexer,
    unstuffer: Pop3DotUnstuffer,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    /// `true` while waiting for the TLS handshake on an implicit-TLS connection
    /// (before the POP3 greeting is expected).
    implicit_tls_pending: bool,
    stage_timer: Option<TimerHandle>,
    stage_timeout: Duration,
    message_timeout: Duration,
    message_timer: Option<TimerHandle>,
    /// Command bytes queued by state-trait methods; flushed after each callback.
    outbound: Vec<u8>,
    /// Accumulation buffer for multiline listing responses (CAPA / LIST / UIDL).
    listing_buf: Vec<String>,
}

impl Pop3ClientEndpoint {
    /// Create a new endpoint from a factory.
    pub fn new(
        factory: &dyn Pop3ClientHandlerFactory,
        stage_timeout: Duration,
        message_timeout: Duration,
        tls_connector: Option<SharedTlsConnector>,
        tls_server_name: Option<String>,
        implicit_tls: bool,
    ) -> Self {
        Self {
            driver: Some(factory.create()),
            proto_state: ProtoState::Connecting,
            caps: Pop3Capabilities::default(),
            lexer: Pop3ReplyLexer::new(),
            unstuffer: Pop3DotUnstuffer::new(),
            tls_connector,
            tls_server_name,
            implicit_tls_pending: implicit_tls,
            stage_timer: None,
            stage_timeout,
            message_timeout,
            message_timer: None,
            outbound: Vec::with_capacity(256),
            listing_buf: Vec::new(),
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    fn write_line(&mut self, line: &str) {
        self.outbound.extend_from_slice(line.as_bytes());
        self.outbound.extend_from_slice(b"\r\n");
    }

    fn flush_outbound(&mut self, ep: &mut dyn Endpoint) {
        if !self.outbound.is_empty() {
            let out = std::mem::take(&mut self.outbound);
            ep.send(&out);
        }
    }

    fn cancel_stage_timer(&mut self) {
        if let Some(t) = self.stage_timer.take() {
            t.cancel();
        }
    }

    fn cancel_message_timer(&mut self) {
        if let Some(t) = self.message_timer.take() {
            t.cancel();
        }
    }

    fn arm_stage_timer(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_stage_timer();
        if self.stage_timeout.is_zero() {
            return;
        }
        let handle = ep.handle();
        let timer = ep.schedule_timer(
            self.stage_timeout,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(io::ErrorKind::TimedOut, "POP3 stage timed out"));
                });
            }),
        );
        self.stage_timer = Some(timer);
    }

    fn arm_message_timer(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_message_timer();
        if self.message_timeout.is_zero() {
            return;
        }
        let handle = ep.handle();
        let timer = ep.schedule_timer(
            self.message_timeout,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "POP3 message transfer timed out",
                    ));
                });
            }),
        );
        self.message_timer = Some(timer);
    }

    fn on_timeout_internal(&mut self, ep: &mut dyn Endpoint) {
        self.proto_state = ProtoState::Error;
        if let Some(mut driver) = self.driver.take() {
            driver.on_timeout(ep);
            self.driver = Some(driver);
        }
        ep.close();
    }

    fn protocol_error(&mut self, ep: &mut dyn Endpoint, msg: String) {
        self.proto_state = ProtoState::Error;
        let err = io::Error::new(io::ErrorKind::InvalidData, msg);
        if let Some(mut driver) = self.driver.take() {
            driver.on_error(ep, &err);
            self.driver = Some(driver);
        }
        ep.close();
    }

    // ── CAPA parsing (RFC 2449) ───────────────────────────────────────────

    fn parse_capa(lines: &[String]) -> Pop3Capabilities {
        let mut caps = Pop3Capabilities::default();
        for line in lines {
            let upper = line.to_ascii_uppercase();
            match upper.as_str() {
                "USER" => caps.user = true,
                "TOP" => caps.top = true,
                "UIDL" => caps.uidl = true,
                "STLS" => caps.stls = true,
                "PIPELINING" => caps.pipelining = true,
                "UTF8" => caps.utf8 = true,
                _ => {
                    if upper.starts_with("SASL") {
                        for mech in line[4..].split_whitespace() {
                            caps.sasl_mechs.push(mech.to_ascii_uppercase());
                        }
                    } else if upper.starts_with("IMPLEMENTATION") && line.len() > 14 {
                        caps.implementation = Some(line[14..].trim().to_string());
                    }
                }
            }
        }
        caps
    }

    // ── Event dispatch ────────────────────────────────────────────────────

    fn dispatch_event(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        self.cancel_stage_timer();

        let state = self.proto_state.clone();
        match state {
            ProtoState::Connecting => self.handle_greeting(event, ep),
            ProtoState::CapaAuthSent => self.handle_capa_auth(event, ep),
            ProtoState::CapaPostTlsSent => self.handle_capa_post_tls(event, ep),
            ProtoState::UserSent => self.handle_user(event, ep),
            ProtoState::PassSent => self.handle_pass(event, ep),
            ProtoState::ApopSent => self.handle_apop(event, ep),
            ProtoState::AuthSent => self.handle_auth(event, ep),
            ProtoState::StlsSent => self.handle_stls(event, ep),
            ProtoState::StatSent => self.handle_stat(event, ep),
            ProtoState::ListAllSent => self.handle_list_all(event, ep),
            ProtoState::ListOneSent(n) => self.handle_list_one(event, ep, n),
            ProtoState::UidlAllSent => self.handle_uidl_all(event, ep),
            ProtoState::UidlOneSent(n) => self.handle_uidl_one(event, ep, n),
            ProtoState::RetrSent(n) => self.handle_retr_sent(event, ep, n),
            ProtoState::TopSent(n) => self.handle_top_sent(event, ep, n),
            ProtoState::DeleSent => self.handle_dele(event, ep),
            ProtoState::RsetSent => self.handle_rset(event, ep),
            ProtoState::NoopSent => self.handle_noop(event, ep),
            ProtoState::QuitSent | ProtoState::Closed => {
                self.proto_state = ProtoState::Closed;
                ep.close();
            }
            ProtoState::Transaction
            | ProtoState::PendingTls
            | ProtoState::RetrBody(_)
            | ProtoState::TopBody(_)
            | ProtoState::Error => {}
        }
    }

    // ── Per-state handlers ────────────────────────────────────────────────

    fn handle_greeting(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { text } => {
                let ts = extract_apop_timestamp(&text);
                // Stay in a neutral state; driver will call capa/user/apop/auth.
                // We set Transaction as a "ready to accept auth commands" marker.
                self.proto_state = ProtoState::Transaction;
                driver.on_greeting(self, ep, &text, ts.as_deref());
            }
            _ => {
                self.proto_state = ProtoState::Error;
                let err = io::Error::new(io::ErrorKind::ConnectionRefused, "POP3 server rejected");
                driver.on_error(ep, &err);
                ep.close();
            }
        }
        self.driver = Some(driver);
    }

    fn handle_capa_auth(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        match event {
            Pop3WireEvent::Ok { .. } | Pop3WireEvent::ListingLine { .. } => {
                // Accumulation is done in the receive loop.
            }
            Pop3WireEvent::ListingEnd => {
                let lines = std::mem::take(&mut self.listing_buf);
                let caps = Self::parse_capa(&lines);
                self.caps = caps.clone();
                self.proto_state = ProtoState::Transaction;
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_capa(self, ep, &caps);
                self.driver = Some(driver);
            }
            Pop3WireEvent::Err { .. } => {
                // Server doesn't support CAPA — treat as minimal capabilities.
                let caps = Pop3Capabilities { user: true, ..Default::default() };
                self.caps = caps.clone();
                self.proto_state = ProtoState::Transaction;
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_capa(self, ep, &caps);
                self.driver = Some(driver);
            }
            _ => {}
        }
    }

    fn handle_capa_post_tls(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        match event {
            Pop3WireEvent::Ok { .. } | Pop3WireEvent::ListingLine { .. } => {}
            Pop3WireEvent::ListingEnd => {
                let lines = std::mem::take(&mut self.listing_buf);
                let caps = Self::parse_capa(&lines);
                self.caps = caps.clone();
                self.proto_state = ProtoState::Transaction;
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_capa_post_stls(self, ep, &caps);
                self.driver = Some(driver);
            }
            Pop3WireEvent::Err { .. } => {
                let caps = Pop3Capabilities { user: true, ..Default::default() };
                self.caps = caps.clone();
                self.proto_state = ProtoState::Transaction;
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_capa_post_stls(self, ep, &caps);
                self.driver = Some(driver);
            }
            _ => {}
        }
    }

    fn handle_user(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { .. } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_user_ok(self, ep);
            }
            Pop3WireEvent::Err { text } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_auth_failed(self, ep, &text);
            }
            _ => {
                self.proto_state = ProtoState::Error;
                let err =
                    io::Error::new(io::ErrorKind::InvalidData, "unexpected reply after USER");
                driver.on_error(ep, &err);
                ep.close();
            }
        }
        self.driver = Some(driver);
    }

    fn handle_pass(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { .. } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_authenticated(self, ep);
            }
            Pop3WireEvent::Err { text } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_auth_failed(self, ep, &text);
            }
            _ => {
                self.proto_state = ProtoState::Error;
                let err =
                    io::Error::new(io::ErrorKind::InvalidData, "unexpected reply after PASS");
                driver.on_error(ep, &err);
                ep.close();
            }
        }
        self.driver = Some(driver);
    }

    fn handle_apop(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { .. } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_authenticated(self, ep);
            }
            Pop3WireEvent::Err { text } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_auth_failed(self, ep, &text);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_auth(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { .. } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_authenticated(self, ep);
            }
            Pop3WireEvent::Err { text } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_auth_failed(self, ep, &text);
            }
            Pop3WireEvent::Continue { text } => {
                // Stay in AuthSent; driver may respond or abort.
                driver.on_auth_challenge(self, ep, &text);
            }
            _ => {
                self.proto_state = ProtoState::Error;
                let err =
                    io::Error::new(io::ErrorKind::InvalidData, "unexpected reply in AUTH");
                driver.on_error(ep, &err);
                ep.close();
            }
        }
        self.driver = Some(driver);
    }

    fn handle_stls(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { .. } => {
                if let (Some(connector), Some(server_name)) =
                    (self.tls_connector.clone(), self.tls_server_name.clone())
                {
                    self.proto_state = ProtoState::PendingTls;
                    let _ = ep.start_client_tls(connector, &server_name);
                } else {
                    self.proto_state = ProtoState::Error;
                    let err = io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "STLS accepted but no TLS connector configured",
                    );
                    driver.on_error(ep, &err);
                    ep.close();
                }
            }
            Pop3WireEvent::Err { .. } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_tls_unavailable(self, ep);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_stat(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { text } => {
                let (count, octets) = parse_stat(&text);
                self.proto_state = ProtoState::Transaction;
                driver.on_stat(self, ep, count, octets);
            }
            Pop3WireEvent::Err { text } => {
                self.proto_state = ProtoState::Error;
                let err = io::Error::new(io::ErrorKind::Other, format!("STAT failed: {text}"));
                driver.on_error(ep, &err);
                ep.close();
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_list_all(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        match event {
            Pop3WireEvent::Ok { .. } | Pop3WireEvent::ListingLine { .. } => {
                // Listing lines accumulated in receive loop.
            }
            Pop3WireEvent::ListingEnd => {
                let lines = std::mem::take(&mut self.listing_buf);
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                self.proto_state = ProtoState::Transaction;
                for line in &lines {
                    if let Some((msg, size)) = parse_list_entry(line) {
                        driver.on_list_entry(msg, size);
                    }
                }
                driver.on_list_complete(self, ep);
                self.driver = Some(driver);
            }
            Pop3WireEvent::Err { text } => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                self.proto_state = ProtoState::Error;
                let err = io::Error::new(io::ErrorKind::Other, format!("LIST failed: {text}"));
                driver.on_error(ep, &err);
                ep.close();
                self.driver = Some(driver);
            }
            _ => {}
        }
    }

    fn handle_list_one(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint, _n: u32) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { text } => {
                self.proto_state = ProtoState::Transaction;
                if let Some((msg, size)) = parse_list_entry(&text) {
                    driver.on_list_single(self, ep, msg, size);
                }
            }
            Pop3WireEvent::Err { text } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_no_such_message(self, ep, &text);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_uidl_all(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        match event {
            Pop3WireEvent::Ok { .. } | Pop3WireEvent::ListingLine { .. } => {}
            Pop3WireEvent::ListingEnd => {
                let lines = std::mem::take(&mut self.listing_buf);
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                self.proto_state = ProtoState::Transaction;
                for line in &lines {
                    if let Some((msg, uid)) = parse_uidl_entry(line) {
                        driver.on_uidl_entry(msg, uid);
                    }
                }
                driver.on_uidl_complete(self, ep);
                self.driver = Some(driver);
            }
            Pop3WireEvent::Err { text } => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                self.proto_state = ProtoState::Error;
                let err = io::Error::new(io::ErrorKind::Other, format!("UIDL failed: {text}"));
                driver.on_error(ep, &err);
                ep.close();
                self.driver = Some(driver);
            }
            _ => {}
        }
    }

    fn handle_uidl_one(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint, _n: u32) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { text } => {
                self.proto_state = ProtoState::Transaction;
                if let Some((msg, uid)) = parse_uidl_entry(&text) {
                    driver.on_uidl_single(self, ep, msg, uid);
                }
            }
            Pop3WireEvent::Err { text } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_no_such_message(self, ep, &text);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_retr_sent(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint, n: u32) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { .. } => {
                self.unstuffer.reset();
                self.proto_state = ProtoState::RetrBody(n);
                self.arm_message_timer(ep);
            }
            Pop3WireEvent::Err { text } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_no_such_message(self, ep, &text);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_top_sent(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint, n: u32) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { .. } => {
                self.unstuffer.reset();
                self.proto_state = ProtoState::TopBody(n);
                self.arm_message_timer(ep);
            }
            Pop3WireEvent::Err { text } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_no_such_message(self, ep, &text);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_dele(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3WireEvent::Ok { .. } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_dele_ok(self, ep);
            }
            Pop3WireEvent::Err { text } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_no_such_message(self, ep, &text);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_rset(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        if let Pop3WireEvent::Ok { .. } = event {
            self.proto_state = ProtoState::Transaction;
            driver.on_rset_ok(self, ep);
        }
        self.driver = Some(driver);
    }

    fn handle_noop(&mut self, event: Pop3WireEvent, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        if let Pop3WireEvent::Ok { .. } = event {
            self.proto_state = ProtoState::Transaction;
            driver.on_noop_ok(self, ep);
        }
        self.driver = Some(driver);
    }

    fn handle_body_complete(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_message_timer();
        let is_top = matches!(self.proto_state, ProtoState::TopBody(_));
        let msg_num = match self.proto_state {
            ProtoState::RetrBody(n) | ProtoState::TopBody(n) => n,
            _ => 0,
        };
        self.proto_state = ProtoState::Transaction;
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        driver.on_message_complete(self, ep, is_top, msg_num);
        self.driver = Some(driver);
    }
}

// ── ProtocolHandler ───────────────────────────────────────────────────────────

impl ProtocolHandler for Pop3ClientEndpoint {
    fn connected(&mut self, ep: &mut dyn Endpoint) {
        if self.implicit_tls_pending {
            // Implicit TLS: wait for security_established before expecting the greeting.
            return;
        }
        self.arm_stage_timer(ep);
    }

    fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
        // The outer loop handles transitions between body mode and status/listing
        // mode that may happen mid-buffer (e.g. +OK\r\n<body> in a single TCP segment).
        loop {
            if data.is_empty() || matches!(self.proto_state, ProtoState::Closed | ProtoState::Error) {
                break;
            }

            // Body mode: feed bytes to the dot-unstuffer.
            if matches!(self.proto_state, ProtoState::RetrBody(_) | ProtoState::TopBody(_)) {
                let (chunks, complete) = self.unstuffer.feed(data);
                for chunk in &chunks {
                    if let Some(mut driver) = self.driver.take() {
                        driver.on_message_content(chunk);
                        self.driver = Some(driver);
                    }
                }
                match complete {
                    Some(consumed) => {
                        *data = &data[consumed..];
                        self.handle_body_complete(ep);
                        self.flush_outbound(ep);
                        // Continue loop: remaining bytes go back to status/listing mode.
                    }
                    None => {
                        // All input consumed by the body; wait for more bytes.
                        return;
                    }
                }
                continue;
            }

            // Status / listing mode: feed to the reply lexer.
            // The lexer updates *data after each line, so remaining bytes are
            // available for the next iteration after a body-mode transition.
            let events = match self.lexer.feed(data) {
                Ok(e) => e,
                Err(e) => {
                    self.protocol_error(ep, e.to_string());
                    return;
                }
            };

            if events.is_empty() {
                break; // no complete line yet; wait for more bytes
            }

            for event in events {
                if matches!(self.proto_state, ProtoState::Closed | ProtoState::Error) {
                    break;
                }
                // Listing lines are accumulated in the buffer before dispatching.
                if let Pop3WireEvent::ListingLine { ref text } = event {
                    self.listing_buf.push(text.clone());
                }
                self.dispatch_event(event, ep);
                self.flush_outbound(ep);
                self.arm_stage_timer(ep);
            }
            // After processing events, loop back: may have entered body mode.
        }
    }

    fn security_established(&mut self, ep: &mut dyn Endpoint, _info: &SecurityInfo) {
        if self.implicit_tls_pending {
            // Implicit TLS handshake done; now wait for POP3 greeting.
            self.implicit_tls_pending = false;
            self.arm_stage_timer(ep);
            return;
        }
        if self.proto_state == ProtoState::PendingTls {
            // STLS handshake completed.
            self.proto_state = ProtoState::Transaction;
            let mut driver = match self.driver.take() {
                Some(d) => d,
                None => return,
            };
            driver.on_tls_established(self, ep);
            self.driver = Some(driver);
            self.flush_outbound(ep);
            self.arm_stage_timer(ep);
        }
    }

    fn disconnected(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_stage_timer();
        self.cancel_message_timer();
        if matches!(self.proto_state, ProtoState::Closed | ProtoState::Error) {
            return;
        }
        self.proto_state = ProtoState::Closed;
        if let Some(mut driver) = self.driver.take() {
            driver.on_disconnected(ep);
            self.driver = Some(driver);
        }
    }

    fn error(&mut self, ep: &mut dyn Endpoint, err: &io::Error) {
        self.cancel_stage_timer();
        self.cancel_message_timer();
        if err.kind() == io::ErrorKind::TimedOut {
            self.on_timeout_internal(ep);
            return;
        }
        self.proto_state = ProtoState::Error;
        if let Some(mut driver) = self.driver.take() {
            driver.on_error(ep, err);
            self.driver = Some(driver);
        }
    }
}

// ── Pop3ClientAuthorization ───────────────────────────────────────────────────

impl Pop3ClientAuthorization for Pop3ClientEndpoint {
    fn capa(&mut self) {
        self.proto_state = ProtoState::CapaAuthSent;
        self.listing_buf.clear();
        self.lexer.expect_multiline();
        self.write_line("CAPA");
    }

    fn user(&mut self, username: &str) {
        self.proto_state = ProtoState::UserSent;
        self.write_line(&format!("USER {username}"));
    }

    fn apop(&mut self, username: &str, digest: &str) {
        self.proto_state = ProtoState::ApopSent;
        self.write_line(&format!("APOP {username} {digest}"));
    }

    fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>) {
        self.proto_state = ProtoState::AuthSent;
        match initial {
            Some(b) => {
                let enc = base64::engine::general_purpose::STANDARD.encode(b);
                self.write_line(&format!("AUTH {mechanism} {enc}"));
            }
            None => self.write_line(&format!("AUTH {mechanism}")),
        }
    }

    fn stls(&mut self) {
        self.proto_state = ProtoState::StlsSent;
        self.write_line("STLS");
    }

    fn quit(&mut self) {
        self.proto_state = ProtoState::QuitSent;
        self.write_line("QUIT");
    }
}

// ── Pop3ClientPassword ────────────────────────────────────────────────────────

impl Pop3ClientPassword for Pop3ClientEndpoint {
    fn pass(&mut self, password: &str) {
        self.proto_state = ProtoState::PassSent;
        self.write_line(&format!("PASS {password}"));
    }

    fn quit(&mut self) {
        self.proto_state = ProtoState::QuitSent;
        self.write_line("QUIT");
    }
}

// ── Pop3ClientPostStls ────────────────────────────────────────────────────────

impl Pop3ClientPostStls for Pop3ClientEndpoint {
    fn capa(&mut self) {
        self.proto_state = ProtoState::CapaPostTlsSent;
        self.listing_buf.clear();
        self.lexer.expect_multiline();
        self.write_line("CAPA");
    }

    fn user(&mut self, username: &str) {
        self.proto_state = ProtoState::UserSent;
        self.write_line(&format!("USER {username}"));
    }

    fn apop(&mut self, username: &str, digest: &str) {
        self.proto_state = ProtoState::ApopSent;
        self.write_line(&format!("APOP {username} {digest}"));
    }

    fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>) {
        self.proto_state = ProtoState::AuthSent;
        match initial {
            Some(b) => {
                let enc = base64::engine::general_purpose::STANDARD.encode(b);
                self.write_line(&format!("AUTH {mechanism} {enc}"));
            }
            None => self.write_line(&format!("AUTH {mechanism}")),
        }
    }

    fn quit(&mut self) {
        self.proto_state = ProtoState::QuitSent;
        self.write_line("QUIT");
    }
}

// ── Pop3ClientAuthExchange ────────────────────────────────────────────────────

impl Pop3ClientAuthExchange for Pop3ClientEndpoint {
    fn respond(&mut self, response: &[u8]) {
        self.proto_state = ProtoState::AuthSent;
        let enc = base64::engine::general_purpose::STANDARD.encode(response);
        self.write_line(&enc);
    }

    fn abort(&mut self) {
        self.proto_state = ProtoState::AuthSent;
        self.write_line("*");
    }
}

// ── Pop3ClientTransaction ─────────────────────────────────────────────────────

impl Pop3ClientTransaction for Pop3ClientEndpoint {
    fn stat(&mut self) {
        self.proto_state = ProtoState::StatSent;
        self.write_line("STAT");
    }

    fn list(&mut self, message: Option<u32>) {
        match message {
            Some(n) => {
                self.proto_state = ProtoState::ListOneSent(n);
                self.write_line(&format!("LIST {n}"));
            }
            None => {
                self.proto_state = ProtoState::ListAllSent;
                self.listing_buf.clear();
                self.lexer.expect_multiline();
                self.write_line("LIST");
            }
        }
    }

    fn retr(&mut self, message: u32) {
        self.proto_state = ProtoState::RetrSent(message);
        self.lexer.stop_after_ok = true;
        self.write_line(&format!("RETR {message}"));
    }

    fn dele(&mut self, message: u32) {
        self.proto_state = ProtoState::DeleSent;
        self.write_line(&format!("DELE {message}"));
    }

    fn rset(&mut self) {
        self.proto_state = ProtoState::RsetSent;
        self.write_line("RSET");
    }

    fn top(&mut self, message: u32, lines: u32) {
        self.proto_state = ProtoState::TopSent(message);
        self.lexer.stop_after_ok = true;
        self.write_line(&format!("TOP {message} {lines}"));
    }

    fn uidl(&mut self, message: Option<u32>) {
        match message {
            Some(n) => {
                self.proto_state = ProtoState::UidlOneSent(n);
                self.write_line(&format!("UIDL {n}"));
            }
            None => {
                self.proto_state = ProtoState::UidlAllSent;
                self.listing_buf.clear();
                self.lexer.expect_multiline();
                self.write_line("UIDL");
            }
        }
    }

    fn noop(&mut self) {
        self.proto_state = ProtoState::NoopSent;
        self.write_line("NOOP");
    }

    fn quit(&mut self) {
        self.proto_state = ProtoState::QuitSent;
        self.write_line("QUIT");
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the APOP challenge `<timestamp>` from a POP3 greeting line.
pub(crate) fn extract_apop_timestamp(greeting: &str) -> Option<String> {
    let start = greeting.find('<')?;
    let end = greeting[start..].find('>')? + start + 1;
    Some(greeting[start..end].to_string())
}

/// Parse `count octets` from STAT response text.
fn parse_stat(text: &str) -> (u32, u64) {
    let mut parts = text.split_whitespace();
    let count = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let octets = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (count, octets)
}

/// Parse `n size` from a LIST listing line or single-response text.
fn parse_list_entry(line: &str) -> Option<(u32, u64)> {
    let mut parts = line.split_whitespace();
    let msg: u32 = parts.next()?.parse().ok()?;
    let size: u64 = parts.next()?.parse().ok()?;
    Some((msg, size))
}

/// Parse `n uid` from a UIDL listing line or single-response text.
fn parse_uidl_entry(line: &str) -> Option<(u32, &str)> {
    let space = line.find(' ')?;
    let msg: u32 = line[..space].parse().ok()?;
    let uid = &line[space + 1..];
    Some((msg, uid))
}
