// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `Pop3ClientEndpoint` — async POP3 client as a [`ProtocolHandler`].
//!
//! The protocol state machine is driven entirely via the [`Pop3ClientDriver`]
//! produced by a [`Pop3ClientHandlerFactory`].  Command bytes are queued into
//! `outbound` and flushed to the [`Endpoint`] after each driver callback.

use std::io;
use std::time::Duration;

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, SharedTlsConnector, TimerHandle};
use rmimeparser::charset::base64;

use super::handlers::{Pop3ClientDriver, Pop3ClientHandlerFactory};
use super::reply::{Pop3Event, Pop3ReplyLexer, Pop3ReplyShape};
use super::state::{
    Pop3Capabilities, Pop3ClientAuthExchange, Pop3ClientAuthorization, Pop3ClientPassword,
    Pop3ClientPostStls, Pop3ClientTransaction, Pop3ClientWakeState,
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
    /// Set by `Pop3ClientAuthExchange::abort()`; the next reply in AUTH
    /// state is the server's response to our `*`, routed to
    /// `on_auth_aborted` unconditionally instead of the normal
    /// authenticated/challenge/failed dispatch.
    auth_aborting: bool,
    /// Set once the server has accepted our credentials; decides whether a
    /// wake hands the driver the Authorization or the Transaction state.
    authenticated: bool,
    /// The most recent `-ERR` text seen, if any — surfaced to
    /// `on_disconnected` so an unexpected close carries whatever
    /// diagnostic the server last sent (matches Gumdrop's
    /// `ServerReplyHandler.handleServiceClosing`, the base interface every
    /// per-command handler extends).
    last_err_message: Option<String>,
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
            auth_aborting: false,
            authenticated: false,
            last_err_message: None,
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

    /// Hand the driver the staged state for the current session state so
    /// it can issue commands that did not originate in a reply (see
    /// [`Pop3ClientDriver::on_wake`]), then flush whatever it issued.
    fn wake_driver(&mut self, ep: &mut dyn Endpoint) {
        let Some(mut driver) = self.driver.take() else {
            return;
        };
        let state = if self.proto_state != ProtoState::Transaction {
            Pop3ClientWakeState::Busy
        } else if self.authenticated {
            Pop3ClientWakeState::Transaction(self)
        } else {
            Pop3ClientWakeState::Authorization(self)
        };
        driver.on_wake(state, ep);
        self.driver = Some(driver);
        self.flush_outbound(ep);
        self.arm_stage_timer(ep);
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

    // ── Event dispatch ────────────────────────────────────────────────────

    fn dispatch_event(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        self.cancel_stage_timer();

        if let Pop3Event::Err { ref message } = event {
            self.last_err_message = Some(message.clone());
        }

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
            ProtoState::QuitSent => self.handle_quit(ep),
            ProtoState::Closed => {
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

    fn handle_greeting(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::ServerGreeting { apop_challenge } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_greeting(self, ep, apop_challenge.as_ref());
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Error;
                let err = io::Error::new(io::ErrorKind::ConnectionRefused, message);
                driver.on_error(ep, &err);
                ep.close();
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_capa_auth(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::Capa(caps) => {
                self.caps = caps.clone();
                self.proto_state = ProtoState::Transaction;
                driver.on_capa(self, ep, &caps);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_capa_error(self, ep, &message);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_capa_post_tls(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::Capa(caps) => {
                self.caps = caps.clone();
                self.proto_state = ProtoState::Transaction;
                driver.on_capa_post_stls(self, ep, &caps);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_capa_post_stls_error(self, ep, &message);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_user(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::UserOk => {
                self.proto_state = ProtoState::Transaction;
                driver.on_user_ok(self, ep);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_auth_failed(self, ep, &message);
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

    fn handle_pass(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::Authenticated => {
                self.proto_state = ProtoState::Transaction;
                self.authenticated = true;
                driver.on_authenticated(self, ep);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_auth_failed(self, ep, &message);
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

    fn handle_apop(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::Authenticated => {
                self.proto_state = ProtoState::Transaction;
                self.authenticated = true;
                driver.on_authenticated(self, ep);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_auth_failed(self, ep, &message);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_auth(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        if self.auth_aborting {
            self.auth_aborting = false;
            self.proto_state = ProtoState::Transaction;
            driver.on_auth_aborted(self, ep);
            self.driver = Some(driver);
            return;
        }
        match event {
            Pop3Event::Authenticated => {
                self.proto_state = ProtoState::Transaction;
                self.authenticated = true;
                driver.on_authenticated(self, ep);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_auth_failed(self, ep, &message);
            }
            Pop3Event::AuthChallenge { data } => {
                // Stay in AuthSent; driver may respond or abort.
                driver.on_auth_challenge(self, ep, &data);
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

    fn handle_stls(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::StlsOk => {
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
            Pop3Event::Err { .. } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_tls_unavailable(self, ep);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_stat(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::Stat { count, octets } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_stat(self, ep, count, octets);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_stat_error(self, ep, &message);
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_list_all(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            // ListStart has no driver callback (matches Gumdrop:
            // dispatchListReply's OK branch transitions to LIST_DATA
            // silently — entries just start arriving).
            Pop3Event::ListEntry { message, octets } => {
                driver.on_list_entry(message, octets);
            }
            Pop3Event::ListEnd => {
                self.proto_state = ProtoState::Transaction;
                driver.on_list_complete(self, ep);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                if is_no_such_message(&message) {
                    driver.on_no_such_message(self, ep, &message);
                } else {
                    driver.on_list_error(self, ep, &message);
                }
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_list_one(&mut self, event: Pop3Event, ep: &mut dyn Endpoint, _n: u32) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::ListSingle { message, octets } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_list_single(self, ep, message, octets);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                if is_no_such_message(&message) {
                    driver.on_no_such_message(self, ep, &message);
                } else {
                    driver.on_list_error(self, ep, &message);
                }
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_uidl_all(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            // UidlStart has no driver callback (matches Gumdrop).
            Pop3Event::UidlEntry { message, uid } => {
                driver.on_uidl_entry(message, &uid);
            }
            Pop3Event::UidlEnd => {
                self.proto_state = ProtoState::Transaction;
                driver.on_uidl_complete(self, ep);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                if is_no_such_message(&message) {
                    driver.on_no_such_message(self, ep, &message);
                } else {
                    driver.on_uidl_error(self, ep, &message);
                }
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_uidl_one(&mut self, event: Pop3Event, ep: &mut dyn Endpoint, _n: u32) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::UidlSingle { message, uid } => {
                self.proto_state = ProtoState::Transaction;
                driver.on_uidl_single(self, ep, message, &uid);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                if is_no_such_message(&message) {
                    driver.on_no_such_message(self, ep, &message);
                } else {
                    driver.on_uidl_error(self, ep, &message);
                }
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_retr_sent(&mut self, event: Pop3Event, ep: &mut dyn Endpoint, n: u32) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::RetrStart => {
                // No driver callback here (matches Gumdrop: content just
                // starts arriving via on_message_content).
                self.unstuffer.reset();
                self.proto_state = ProtoState::RetrBody(n);
                self.arm_message_timer(ep);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                if message.to_ascii_lowercase().contains("deleted") {
                    driver.on_message_deleted(self, ep, &message);
                } else {
                    driver.on_no_such_message(self, ep, &message);
                }
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_top_sent(&mut self, event: Pop3Event, ep: &mut dyn Endpoint, n: u32) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::TopStart => {
                // No driver callback here (matches Gumdrop).
                self.unstuffer.reset();
                self.proto_state = ProtoState::TopBody(n);
                self.arm_message_timer(ep);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                if message.to_ascii_lowercase().contains("deleted") {
                    driver.on_message_deleted(self, ep, &message);
                } else {
                    driver.on_no_such_message(self, ep, &message);
                }
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_dele(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        match event {
            Pop3Event::DeleOk => {
                self.proto_state = ProtoState::Transaction;
                driver.on_dele_ok(self, ep);
            }
            Pop3Event::Err { message } => {
                self.proto_state = ProtoState::Transaction;
                let lower = message.to_ascii_lowercase();
                if lower.contains("already deleted") || lower.contains("already marked") {
                    driver.on_already_deleted(self, ep, &message);
                } else {
                    driver.on_no_such_message(self, ep, &message);
                }
            }
            _ => {}
        }
        self.driver = Some(driver);
    }

    fn handle_rset(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        if let Pop3Event::RsetOk = event {
            self.proto_state = ProtoState::Transaction;
            driver.on_rset_ok(self, ep);
        }
        self.driver = Some(driver);
    }

    fn handle_noop(&mut self, event: Pop3Event, ep: &mut dyn Endpoint) {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        if let Pop3Event::NoopOk = event {
            self.proto_state = ProtoState::Transaction;
            driver.on_noop_ok(self, ep);
        }
        self.driver = Some(driver);
    }

    fn handle_quit(&mut self, ep: &mut dyn Endpoint) {
        // No driver callback (matches Gumdrop: dispatchResponse's
        // QUIT_SENT case closes unconditionally, regardless of reply).
        self.proto_state = ProtoState::Closed;
        ep.close();
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
        self.lexer.expect(Pop3ReplyShape::Greeting);
        self.arm_stage_timer(ep);
    }

    fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
        if matches!(self.proto_state, ProtoState::Closed | ProtoState::Error) {
            *data = &[];
            return;
        }
        // First, before any reply is dispatched: a poke from another
        // thread arrives here with no data, and this is its whole purpose.
        self.wake_driver(ep);
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
                        driver.on_message_content(chunk, ep);
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

            // Status / listing mode: feed to the reply lexer. The lexer
            // updates *data after each event batch (and immediately on
            // RetrStart/TopStart), so remaining bytes are available for
            // the next iteration after a body-mode transition.
            let events = match self.lexer.feed(data) {
                Ok(e) => e,
                Err(e) => {
                    self.protocol_error(ep, e.to_string());
                    return;
                }
            };

            if events.is_empty() {
                break; // no complete field yet; wait for more bytes
            }

            for event in events {
                if matches!(self.proto_state, ProtoState::Closed | ProtoState::Error) {
                    break;
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
            self.lexer.expect(Pop3ReplyShape::Greeting);
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
        let message = self.last_err_message.take();
        if let Some(mut driver) = self.driver.take() {
            driver.on_disconnected(ep, message.as_deref());
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
        self.lexer.expect(Pop3ReplyShape::Capa);
        self.write_line("CAPA");
    }

    fn user(&mut self, username: &str) {
        self.proto_state = ProtoState::UserSent;
        self.lexer.expect(Pop3ReplyShape::User);
        self.write_line(&format!("USER {username}"));
    }

    fn apop(&mut self, username: &str, digest: &str) {
        self.proto_state = ProtoState::ApopSent;
        self.lexer.expect(Pop3ReplyShape::Apop);
        self.write_line(&format!("APOP {username} {digest}"));
    }

    fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>) {
        self.proto_state = ProtoState::AuthSent;
        self.lexer.expect(Pop3ReplyShape::Auth);
        self.auth_aborting = false;
        match initial {
            Some(b) => {
                let enc = base64::encode(b);
                self.write_line(&format!("AUTH {mechanism} {enc}"));
            }
            None => self.write_line(&format!("AUTH {mechanism}")),
        }
    }

    fn stls(&mut self) {
        self.proto_state = ProtoState::StlsSent;
        self.lexer.expect(Pop3ReplyShape::Stls);
        self.write_line("STLS");
    }

    fn quit(&mut self) {
        self.proto_state = ProtoState::QuitSent;
        self.lexer.expect(Pop3ReplyShape::Quit);
        self.write_line("QUIT");
    }
}

// ── Pop3ClientPassword ────────────────────────────────────────────────────────

impl Pop3ClientPassword for Pop3ClientEndpoint {
    fn pass(&mut self, password: &str) {
        self.proto_state = ProtoState::PassSent;
        self.lexer.expect(Pop3ReplyShape::Pass);
        self.write_line(&format!("PASS {password}"));
    }

    fn quit(&mut self) {
        self.proto_state = ProtoState::QuitSent;
        self.lexer.expect(Pop3ReplyShape::Quit);
        self.write_line("QUIT");
    }
}

// ── Pop3ClientPostStls ────────────────────────────────────────────────────────

impl Pop3ClientPostStls for Pop3ClientEndpoint {
    fn capa(&mut self) {
        self.proto_state = ProtoState::CapaPostTlsSent;
        self.lexer.expect(Pop3ReplyShape::Capa);
        self.write_line("CAPA");
    }

    fn user(&mut self, username: &str) {
        self.proto_state = ProtoState::UserSent;
        self.lexer.expect(Pop3ReplyShape::User);
        self.write_line(&format!("USER {username}"));
    }

    fn apop(&mut self, username: &str, digest: &str) {
        self.proto_state = ProtoState::ApopSent;
        self.lexer.expect(Pop3ReplyShape::Apop);
        self.write_line(&format!("APOP {username} {digest}"));
    }

    fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>) {
        self.proto_state = ProtoState::AuthSent;
        self.lexer.expect(Pop3ReplyShape::Auth);
        self.auth_aborting = false;
        match initial {
            Some(b) => {
                let enc = base64::encode(b);
                self.write_line(&format!("AUTH {mechanism} {enc}"));
            }
            None => self.write_line(&format!("AUTH {mechanism}")),
        }
    }

    fn quit(&mut self) {
        self.proto_state = ProtoState::QuitSent;
        self.lexer.expect(Pop3ReplyShape::Quit);
        self.write_line("QUIT");
    }
}

// ── Pop3ClientAuthExchange ────────────────────────────────────────────────────

impl Pop3ClientAuthExchange for Pop3ClientEndpoint {
    fn respond(&mut self, response: &[u8]) {
        self.proto_state = ProtoState::AuthSent;
        self.lexer.expect(Pop3ReplyShape::Auth);
        self.auth_aborting = false;
        let enc = base64::encode(response);
        self.write_line(&enc);
    }

    fn abort(&mut self) {
        self.proto_state = ProtoState::AuthSent;
        self.lexer.expect(Pop3ReplyShape::Auth);
        self.auth_aborting = true;
        self.write_line("*");
    }
}

// ── Pop3ClientTransaction ─────────────────────────────────────────────────────

impl Pop3ClientTransaction for Pop3ClientEndpoint {
    fn stat(&mut self) {
        self.proto_state = ProtoState::StatSent;
        self.lexer.expect(Pop3ReplyShape::Stat);
        self.write_line("STAT");
    }

    fn list(&mut self, message: Option<u32>) {
        match message {
            Some(n) => {
                self.proto_state = ProtoState::ListOneSent(n);
                self.lexer.expect(Pop3ReplyShape::ListSingle);
                self.write_line(&format!("LIST {n}"));
            }
            None => {
                self.proto_state = ProtoState::ListAllSent;
                self.lexer.expect(Pop3ReplyShape::ListAll);
                self.write_line("LIST");
            }
        }
    }

    fn retr(&mut self, message: u32) {
        self.proto_state = ProtoState::RetrSent(message);
        self.lexer.expect(Pop3ReplyShape::Retr);
        self.write_line(&format!("RETR {message}"));
    }

    fn dele(&mut self, message: u32) {
        self.proto_state = ProtoState::DeleSent;
        self.lexer.expect(Pop3ReplyShape::Dele);
        self.write_line(&format!("DELE {message}"));
    }

    fn rset(&mut self) {
        self.proto_state = ProtoState::RsetSent;
        self.lexer.expect(Pop3ReplyShape::Rset);
        self.write_line("RSET");
    }

    fn top(&mut self, message: u32, lines: u32) {
        self.proto_state = ProtoState::TopSent(message);
        self.lexer.expect(Pop3ReplyShape::Top);
        self.write_line(&format!("TOP {message} {lines}"));
    }

    fn uidl(&mut self, message: Option<u32>) {
        match message {
            Some(n) => {
                self.proto_state = ProtoState::UidlOneSent(n);
                self.lexer.expect(Pop3ReplyShape::UidlSingle);
                self.write_line(&format!("UIDL {n}"));
            }
            None => {
                self.proto_state = ProtoState::UidlAllSent;
                self.lexer.expect(Pop3ReplyShape::UidlAll);
                self.write_line("UIDL");
            }
        }
    }

    fn noop(&mut self) {
        self.proto_state = ProtoState::NoopSent;
        self.lexer.expect(Pop3ReplyShape::Noop);
        self.write_line("NOOP");
    }

    fn quit(&mut self) {
        self.proto_state = ProtoState::QuitSent;
        self.lexer.expect(Pop3ReplyShape::Quit);
        self.write_line("QUIT");
    }
}

/// Text-sniff a LIST/UIDL `-ERR` message the same way Gumdrop's
/// `dispatchListReply`/`dispatchUidlReply` do, for both the all-messages and
/// single-message (`n`) forms — both funnel through this same
/// classification in Gumdrop, not just the `n` form.
fn is_no_such_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("no such message") || lower.contains("not exist")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::reply::ContentId;
    use crate::client::state::Pop3ClientWakeState;
    use hopf_core::ConnHandle;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct FakeEp {
        sent: Vec<u8>,
        secure: SecurityInfo,
        handle: ConnHandle,
        closed: bool,
    }

    impl FakeEp {
        fn new() -> Self {
            Self {
                sent: Vec::new(),
                secure: SecurityInfo::plaintext(),
                handle: ConnHandle::from_execute(Arc::new(|task| task())),
                closed: false,
            }
        }
        fn sent_str(&self) -> String {
            String::from_utf8_lossy(&self.sent).into_owned()
        }
    }

    impl Endpoint for FakeEp {
        fn send(&mut self, data: &[u8]) {
            self.sent.extend_from_slice(data);
        }
        fn is_open(&self) -> bool {
            !self.closed
        }
        fn is_closing(&self) -> bool {
            false
        }
        fn close(&mut self) {
            self.closed = true;
        }
        fn local_addr(&self) -> io::Result<hopf_core::PeerAddr> {
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .map(hopf_core::PeerAddr::Inet)
                .map_err(io::Error::other)
        }
        fn remote_addr(&self) -> io::Result<hopf_core::PeerAddr> {
            self.local_addr()
        }
        fn security_info(&self) -> &SecurityInfo {
            &self.secure
        }
        fn start_tls(&mut self) -> Result<(), hopf_core::StartTlsError> {
            Err(hopf_core::StartTlsError::Unsupported)
        }
        fn start_client_tls(&mut self, _c: SharedTlsConnector, _n: &str) -> Result<(), hopf_core::StartTlsError> {
            Ok(())
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _cb: Option<hopf_core::WriteReadyCallback>) {}
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn schedule_timer(&self, _delay: Duration, _cb: Box<dyn FnOnce() + Send>) -> TimerHandle {
            TimerHandle::from_cancel(|| {})
        }
        fn handle(&self) -> ConnHandle {
            self.handle.clone()
        }
        fn fail(&mut self, _err: io::Error) {
            self.closed = true;
        }
    }

    /// Logs every callback; logs in with USER/PASS on the greeting; drains
    /// a queue of commands "from another thread" in `on_wake`.
    struct QueueDriver {
        events: Arc<Mutex<Vec<String>>>,
        queue: Arc<Mutex<VecDeque<String>>>,
    }

    impl QueueDriver {
        fn log(&self, s: &str) {
            self.events.lock().unwrap().push(s.to_string());
        }
    }

    impl Pop3ClientDriver for QueueDriver {
        fn on_greeting(&mut self, auth: &mut dyn Pop3ClientAuthorization, _e: &mut dyn Endpoint, _c: Option<&ContentId>) {
            self.log("greeting");
            auth.user("alice");
        }
        fn on_capa(&mut self, _a: &mut dyn Pop3ClientAuthorization, _e: &mut dyn Endpoint, _c: &Pop3Capabilities) {}
        fn on_capa_error(&mut self, _a: &mut dyn Pop3ClientAuthorization, _e: &mut dyn Endpoint, _m: &str) {}
        fn on_capa_post_stls(&mut self, _p: &mut dyn Pop3ClientPostStls, _e: &mut dyn Endpoint, _c: &Pop3Capabilities) {}
        fn on_capa_post_stls_error(&mut self, _p: &mut dyn Pop3ClientPostStls, _e: &mut dyn Endpoint, _m: &str) {}
        fn on_user_ok(&mut self, password: &mut dyn Pop3ClientPassword, _e: &mut dyn Endpoint) {
            self.log("user_ok");
            password.pass("secret");
        }
        fn on_authenticated(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint) {
            self.log("authenticated");
        }
        fn on_auth_failed(&mut self, _a: &mut dyn Pop3ClientAuthorization, _e: &mut dyn Endpoint, _m: &str) {
            self.log("auth_failed");
        }
        fn on_auth_challenge(&mut self, _x: &mut dyn Pop3ClientAuthExchange, _e: &mut dyn Endpoint, _c: &[u8]) {}
        fn on_auth_aborted(&mut self, _a: &mut dyn Pop3ClientAuthorization, _e: &mut dyn Endpoint) {}
        fn on_tls_established(&mut self, _p: &mut dyn Pop3ClientPostStls, _e: &mut dyn Endpoint) {}
        fn on_tls_unavailable(&mut self, _a: &mut dyn Pop3ClientAuthorization, _e: &mut dyn Endpoint) {}
        fn on_stat(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint, count: u32, octets: u64) {
            self.log(&format!("stat:{count}:{octets}"));
        }
        fn on_stat_error(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint, _m: &str) {}
        fn on_list_entry(&mut self, _m: u32, _s: u64) {}
        fn on_list_complete(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint) {}
        fn on_list_single(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint, _m: u32, _s: u64) {}
        fn on_list_error(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint, _m: &str) {}
        fn on_uidl_entry(&mut self, _m: u32, _u: &str) {}
        fn on_uidl_complete(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint) {}
        fn on_uidl_single(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint, _m: u32, _u: &str) {}
        fn on_uidl_error(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint, _m: &str) {}
        fn on_message_content(&mut self, _d: &[u8], _e: &mut dyn Endpoint) {}
        fn on_message_complete(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint, _top: bool, _m: u32) {}
        fn on_dele_ok(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint) {}
        fn on_rset_ok(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint) {}
        fn on_noop_ok(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint) {
            self.log("noop_ok");
        }
        fn on_no_such_message(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint, _m: &str) {}
        fn on_message_deleted(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint, _m: &str) {}
        fn on_already_deleted(&mut self, _t: &mut dyn Pop3ClientTransaction, _e: &mut dyn Endpoint, _m: &str) {}
        fn on_wake(&mut self, state: Pop3ClientWakeState<'_>, _e: &mut dyn Endpoint) {
            self.log(&format!("wake:{}", state.name()));
            let Some(cmd) = self.queue.lock().unwrap().pop_front() else { return };
            match (cmd.as_str(), state) {
                ("stat", Pop3ClientWakeState::Transaction(t)) => t.stat(),
                ("noop", Pop3ClientWakeState::Transaction(t)) => t.noop(),
                ("quit", Pop3ClientWakeState::Authorization(a)) => a.quit(),
                (_, _) => self.queue.lock().unwrap().push_front(cmd),
            }
        }
        fn on_error(&mut self, _e: &mut dyn Endpoint, err: &io::Error) {
            self.log(&format!("err:{err}"));
        }
        fn on_timeout(&mut self, _e: &mut dyn Endpoint) {
            self.log("timeout");
        }
        fn on_disconnected(&mut self, _e: &mut dyn Endpoint, _m: Option<&str>) {
            self.log("disconnected");
        }
    }

    struct QueueFactory(Arc<Mutex<Vec<String>>>, Arc<Mutex<VecDeque<String>>>);

    impl Pop3ClientHandlerFactory for QueueFactory {
        fn create(&self) -> Box<dyn Pop3ClientDriver> {
            Box::new(QueueDriver { events: Arc::clone(&self.0), queue: Arc::clone(&self.1) })
        }
    }

    fn make_ep(log: &Arc<Mutex<Vec<String>>>, queue: &Arc<Mutex<VecDeque<String>>>) -> Pop3ClientEndpoint {
        Pop3ClientEndpoint::new(
            &QueueFactory(Arc::clone(log), Arc::clone(queue)),
            Duration::from_secs(60),
            Duration::from_secs(600),
            None,
            None,
            false,
        )
    }

    fn feed(ep: &mut Pop3ClientEndpoint, fake: &mut FakeEp, wire: &[u8]) {
        let mut data = wire;
        ProtocolHandler::receive(ep, fake, &mut data);
    }

    /// A poke from another thread re-enters `receive` with no data. Before
    /// login the driver gets the Authorization state, after it Transaction,
    /// and while a command is in flight it gets Busy and must wait.
    #[test]
    fn wake_hands_the_driver_the_staged_state_and_flushes() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut ep = make_ep(&log, &queue);
        let mut fake = FakeEp::new();
        ep.connected(&mut fake);

        // Greeting → USER (from the callback), in flight: a wake is Busy.
        feed(&mut ep, &mut fake, b"+OK POP3 ready\r\n");
        assert!(fake.sent_str().contains("USER alice"));
        queue.lock().unwrap().push_back("stat".to_string());
        feed(&mut ep, &mut fake, b"");
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "wake:busy"), "{events:?}");
        assert!(!fake.sent_str().contains("STAT"));

        // USER ok → PASS (from the callback) → authenticated.
        feed(&mut ep, &mut fake, b"+OK\r\n");
        assert!(fake.sent_str().contains("PASS secret"));
        feed(&mut ep, &mut fake, b"+OK logged in\r\n");
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "authenticated"), "{events:?}");

        // Now a poke finds Transaction and the queued STAT goes out.
        feed(&mut ep, &mut fake, b"");
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "wake:transaction"), "{events:?}");
        assert!(fake.sent_str().contains("STAT"), "sent: {:?}", fake.sent_str());
        feed(&mut ep, &mut fake, b"+OK 2 320\r\n");
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "stat:2:320"), "{events:?}");
    }

    /// Before authentication (here: after a failed login) the wake state is
    /// Authorization, whose commands are the only legal ones.
    #[test]
    fn wake_before_login_offers_the_authorization_state() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut ep = make_ep(&log, &queue);
        let mut fake = FakeEp::new();
        ep.connected(&mut fake);
        feed(&mut ep, &mut fake, b"+OK POP3 ready\r\n");
        feed(&mut ep, &mut fake, b"-ERR no such user\r\n");
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "auth_failed"), "{events:?}");

        queue.lock().unwrap().push_back("stat".to_string());
        feed(&mut ep, &mut fake, b"");
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "wake:authorization"), "{events:?}");
        assert!(!fake.sent_str().contains("STAT"), "STAT is not legal before login");
        assert_eq!(queue.lock().unwrap().len(), 1, "kept for later");

        queue.lock().unwrap().clear();
        queue.lock().unwrap().push_back("quit".to_string());
        feed(&mut ep, &mut fake, b"");
        assert!(fake.sent_str().contains("QUIT"), "sent: {:?}", fake.sent_str());
    }
}
