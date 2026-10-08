// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The connection driver: greeting, `CAPABILITIES`, `STARTTLS`,
//! `AUTHINFO`, then the command queue.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hopf_auth::{create_client, SaslClient, SaslClientStep, SaslMechanism};
use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, SharedTlsConnector, TimerHandle};

use super::error::NntpClientError;
use super::handlers::{NntpClientHandler, NntpGreeting};
use super::reply::{
    has_capability, is_multiline_code, normalize_capabilities, parse_status, sasl_mechanisms,
    unstuff_line, LineBuffer, NntpStatus,
};
use super::session::{Command, NntpSession, Queue};

/// Mechanisms tried for a password, in order of preference.
const SASL_PREFERENCE: &[SaslMechanism] = &[
    SaslMechanism::ScramSha256,
    SaslMechanism::CramMd5,
    SaslMechanism::Plain,
    SaslMechanism::Login,
];

/// A command's status line, or a multi-line block, must not exceed this
/// many buffered bytes without a line ending.
const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsMode {
    None,
    Implicit,
    StartTlsRequired,
    StartTlsOpportunistic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the `200`/`201` greeting.
    Greeting,
    /// `CAPABILITIES` sent; `after_tls` says whether this is the second
    /// round, after `STARTTLS`.
    Capabilities { after_tls: bool, collecting: bool },
    /// `STARTTLS` sent, waiting for `382`.
    StartTls,
    /// TLS handshake in progress.
    PendingTls,
    /// `AUTHINFO USER` sent.
    AuthUser,
    /// `AUTHINFO PASS` sent.
    AuthPass,
    /// `AUTHINFO SASL` exchange in progress.
    AuthSasl,
    /// Ready for the command queue.
    Ready,
    Closed,
}

/// What the in-flight command is waiting for.
enum InFlight {
    Status,
    Lines,
    /// The continuation payload went out; a final status is due.
    Final,
}

pub(crate) struct NntpClientEndpoint {
    handler: Option<Box<dyn NntpClientHandler>>,
    phase: Phase,
    lines: LineBuffer,
    credentials: Option<(String, String)>,
    tls: Option<(SharedTlsConnector, String)>,
    tls_mode: TlsMode,
    command_timeout: Duration,
    queue: Arc<Mutex<Queue>>,
    session: Option<NntpSession>,
    greeting: Option<NntpStatus>,
    capabilities: Vec<String>,
    caps_lines: Vec<Vec<u8>>,
    secure: bool,
    authenticated: bool,
    sasl: Option<Box<dyn SaslClient>>,
    in_flight: Option<(Command, InFlight)>,
    timer: Option<TimerHandle>,
    connected_notified: bool,
}

impl NntpClientEndpoint {
    pub fn new(
        handler: Box<dyn NntpClientHandler>,
        credentials: Option<(String, String)>,
        tls: Option<(SharedTlsConnector, String)>,
        tls_mode: TlsMode,
        command_timeout: Duration,
    ) -> Self {
        Self {
            handler: Some(handler),
            phase: Phase::Greeting,
            lines: LineBuffer::default(),
            credentials,
            tls,
            tls_mode,
            command_timeout,
            queue: Arc::new(Mutex::new(Queue::default())),
            session: None,
            greeting: None,
            capabilities: Vec::new(),
            caps_lines: Vec::new(),
            secure: false,
            authenticated: false,
            sasl: None,
            in_flight: None,
            timer: None,
            connected_notified: false,
        }
    }

    fn send_line(&mut self, ep: &mut dyn Endpoint, line: &str) {
        let mut out = Vec::with_capacity(line.len() + 2);
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
        ep.send(&out);
        self.arm_timer(ep);
    }

    fn arm_timer(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_timer();
        if self.command_timeout.is_zero() {
            return;
        }
        let handle = ep.handle();
        let timeout = self.command_timeout;
        self.timer = Some(ep.schedule_timer(
            timeout,
            Box::new(move || {
                handle.with_endpoint(move |ep2| {
                    ep2.fail(io::Error::new(io::ErrorKind::TimedOut, format!("no reply within {timeout:?}")));
                });
            }),
        ));
    }

    fn cancel_timer(&mut self) {
        if let Some(t) = self.timer.take() {
            t.cancel();
        }
    }

    /// Stop everything: fail the in-flight and queued commands, tell the
    /// handler, close.
    fn fail(&mut self, ep: &mut dyn Endpoint, err: io::Error) {
        if self.phase == Phase::Closed {
            return;
        }
        self.phase = Phase::Closed;
        self.cancel_timer();
        self.fail_commands(&err.to_string());
        if let Some(h) = self.handler.as_mut() {
            h.on_error(&err);
        }
        ep.close();
    }

    fn fail_commands(&mut self, reason: &str) {
        let mut q = self.queue.lock().unwrap();
        if q.closed.is_none() {
            q.closed = Some(reason.to_string());
        }
        let pending: Vec<Command> = q.pending.drain(..).collect();
        drop(q);
        if let Some((cmd, _)) = self.in_flight.take() {
            (cmd.on_complete)(Err(NntpClientError::transport(reason)));
        }
        for cmd in pending {
            (cmd.on_complete)(Err(NntpClientError::transport(reason)));
        }
    }

    fn protocol_error(&mut self, ep: &mut dyn Endpoint, what: &str, line: &[u8]) {
        let msg = format!("{what}: {}", String::from_utf8_lossy(line).trim());
        self.fail(ep, io::Error::new(io::ErrorKind::InvalidData, msg));
    }

    // ── handshake ────────────────────────────────────────────────────────

    fn on_greeting(&mut self, ep: &mut dyn Endpoint, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        let Some(status) = parse_status(&text) else {
            return self.protocol_error(ep, "invalid NNTP greeting", line);
        };
        if status.code != 200 && status.code != 201 {
            return self.fail(ep, io::Error::new(io::ErrorKind::ConnectionRefused, format!("NNTP greeting: {} {}", status.code, status.text)));
        }
        self.greeting = Some(status);
        self.request_capabilities(ep, false);
    }

    fn request_capabilities(&mut self, ep: &mut dyn Endpoint, after_tls: bool) {
        self.caps_lines.clear();
        self.phase = Phase::Capabilities { after_tls, collecting: false };
        self.send_line(ep, "CAPABILITIES");
    }

    fn on_capabilities_line(&mut self, ep: &mut dyn Endpoint, after_tls: bool, collecting: bool, line: &[u8]) {
        if !collecting {
            let text = String::from_utf8_lossy(line);
            match parse_status(&text) {
                Some(s) if s.code == 101 => {
                    self.phase = Phase::Capabilities { after_tls, collecting: true };
                }
                Some(_) => {
                    // No CAPABILITIES support: carry on with none.
                    self.capabilities = Vec::new();
                    self.after_capabilities(ep, after_tls);
                }
                None => self.protocol_error(ep, "bad CAPABILITIES reply", line),
            }
            return;
        }
        match unstuff_line(line) {
            Some(l) => self.caps_lines.push(l.to_vec()),
            None => {
                self.capabilities = normalize_capabilities(&self.caps_lines);
                self.after_capabilities(ep, after_tls);
            }
        }
    }

    fn after_capabilities(&mut self, ep: &mut dyn Endpoint, after_tls: bool) {
        if !after_tls && !self.secure {
            match self.tls_mode {
                TlsMode::StartTlsRequired | TlsMode::StartTlsOpportunistic if has_capability(&self.capabilities, "STARTTLS") => {
                    self.phase = Phase::StartTls;
                    self.send_line(ep, "STARTTLS");
                    return;
                }
                TlsMode::StartTlsRequired => {
                    return self.fail(ep, io::Error::new(io::ErrorKind::Unsupported, "STARTTLS is required but the server does not offer it"));
                }
                _ => {}
            }
        }
        self.authenticate(ep);
    }

    fn on_starttls_reply(&mut self, ep: &mut dyn Endpoint, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        match parse_status(&text) {
            Some(s) if s.code == 382 => {
                let Some((connector, name)) = self.tls.clone() else {
                    return self.fail(ep, io::Error::new(io::ErrorKind::InvalidInput, "STARTTLS accepted but no TLS connector configured"));
                };
                self.phase = Phase::PendingTls;
                self.cancel_timer();
                if let Err(e) = ep.start_client_tls(connector, &name) {
                    self.fail(ep, io::Error::other(format!("STARTTLS: {e:?}")));
                }
            }
            Some(s) if self.tls_mode == TlsMode::StartTlsOpportunistic => {
                // Offered but refused: carry on in the clear.
                let _ = s;
                self.authenticate(ep);
            }
            Some(s) => self.fail(ep, io::Error::new(io::ErrorKind::ConnectionRefused, format!("STARTTLS refused: {} {}", s.code, s.text))),
            None => self.protocol_error(ep, "bad STARTTLS reply", line),
        }
    }

    fn authenticate(&mut self, ep: &mut dyn Endpoint) {
        let Some((user, pass)) = self.credentials.clone() else {
            return self.become_ready(ep);
        };
        let offered = sasl_mechanisms(&self.capabilities);
        let mech = SASL_PREFERENCE
            .iter()
            .copied()
            .find(|m| offered.iter().any(|o| o.eq_ignore_ascii_case(m.name())));
        if let Some(mech) = mech {
            let mut client = create_client(mech, &user, &pass, "", "nntp", None);
            let mut line = format!("AUTHINFO SASL {}", mech.name());
            if client.has_initial_response() {
                if let SaslClientStep::Response(initial) = client.evaluate(None) {
                    line.push(' ');
                    line.push_str(&if initial.is_empty() { "=".to_string() } else { B64.encode(&initial) });
                }
            }
            self.sasl = Some(client);
            self.phase = Phase::AuthSasl;
            self.send_line(ep, &line);
            return;
        }
        // AUTHINFO USER/PASS: advertised, or the only thing left to try.
        self.phase = Phase::AuthUser;
        self.send_line(ep, &format!("AUTHINFO USER {user}"));
    }

    fn auth_failed(&mut self, ep: &mut dyn Endpoint, what: &str, s: &NntpStatus) {
        self.fail(ep, io::Error::new(io::ErrorKind::PermissionDenied, format!("{what}: {} {}", s.code, s.text)));
    }

    fn on_auth_user_reply(&mut self, ep: &mut dyn Endpoint, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        let Some(s) = parse_status(&text) else { return self.protocol_error(ep, "bad AUTHINFO USER reply", line) };
        match s.code {
            281 => {
                self.authenticated = true;
                self.become_ready(ep);
            }
            381 => {
                let pass = self.credentials.as_ref().map(|c| c.1.clone()).unwrap_or_default();
                self.phase = Phase::AuthPass;
                self.send_line(ep, &format!("AUTHINFO PASS {pass}"));
            }
            _ => self.auth_failed(ep, "AUTHINFO USER", &s),
        }
    }

    fn on_auth_pass_reply(&mut self, ep: &mut dyn Endpoint, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        let Some(s) = parse_status(&text) else { return self.protocol_error(ep, "bad AUTHINFO PASS reply", line) };
        if s.code == 281 {
            self.authenticated = true;
            self.become_ready(ep);
        } else {
            self.auth_failed(ep, "AUTHINFO PASS", &s);
        }
    }

    fn on_auth_sasl_reply(&mut self, ep: &mut dyn Endpoint, line: &[u8]) {
        let text = String::from_utf8_lossy(line);
        let Some(s) = parse_status(&text) else { return self.protocol_error(ep, "bad AUTHINFO SASL reply", line) };
        match s.code {
            281 => {
                self.sasl = None;
                self.authenticated = true;
                self.become_ready(ep);
            }
            383 => {
                let challenge = if s.text.trim() == "=" { Vec::new() } else {
                    match B64.decode(s.text.trim()) {
                        Ok(c) => c,
                        Err(_) => return self.protocol_error(ep, "undecodable SASL challenge", line),
                    }
                };
                let Some(client) = self.sasl.as_mut() else {
                    return self.protocol_error(ep, "unexpected SASL challenge", line);
                };
                match client.evaluate(Some(&challenge)) {
                    SaslClientStep::Response(r) | SaslClientStep::Complete(r) => {
                        let reply = if r.is_empty() { "=".to_string() } else { B64.encode(&r) };
                        self.send_line(ep, &reply);
                    }
                    SaslClientStep::Failure => {
                        self.send_line(ep, "*");
                        self.fail(ep, io::Error::new(io::ErrorKind::PermissionDenied, "SASL exchange failed (server verification)"));
                    }
                }
            }
            _ => self.auth_failed(ep, "AUTHINFO SASL", &s),
        }
    }

    fn become_ready(&mut self, ep: &mut dyn Endpoint) {
        self.phase = Phase::Ready;
        self.cancel_timer();
        let greeting = self.greeting.clone().unwrap_or(NntpStatus { code: 200, text: String::new() });
        let posting_allowed = greeting.code == 200;
        let session = NntpSession::new(Arc::clone(&self.queue), ep.handle(), posting_allowed, self.capabilities.clone());
        self.session = Some(session.clone());
        let info = NntpGreeting {
            code: greeting.code,
            text: greeting.text,
            posting_allowed,
            capabilities: self.capabilities.clone(),
            secure: self.secure,
            authenticated: self.authenticated,
        };
        self.connected_notified = true;
        if let Some(h) = self.handler.as_mut() {
            h.on_connected(&session, &info);
        }
        self.dispatch(ep);
    }

    // ── command queue ────────────────────────────────────────────────────

    /// Write the next queued command if nothing is in flight.
    fn dispatch(&mut self, ep: &mut dyn Endpoint) {
        if self.phase != Phase::Ready || self.in_flight.is_some() {
            return;
        }
        let next = self.queue.lock().unwrap().pending.pop_front();
        if let Some(cmd) = next {
            let line = cmd.line.clone();
            self.in_flight = Some((cmd, InFlight::Status));
            self.send_line(ep, &line);
        }
    }

    fn on_command_line(&mut self, ep: &mut dyn Endpoint, line: &[u8]) {
        self.arm_timer(ep);
        let Some((mut cmd, waiting)) = self.in_flight.take() else {
            // Nothing asked for this; servers do not speak unprompted.
            return;
        };
        match waiting {
            InFlight::Lines => match unstuff_line(line) {
                Some(l) => {
                    (cmd.on_line)(l);
                    self.in_flight = Some((cmd, InFlight::Lines));
                }
                // The status that opened the block is already captured in
                // the completion wrapper; this placeholder is replaced there.
                None => self.complete(ep, cmd, Ok(NntpStatus { code: 0, text: String::new() })),
            },
            InFlight::Status | InFlight::Final => {
                let text = String::from_utf8_lossy(line);
                let Some(status) = parse_status(&text) else {
                    self.in_flight = Some((cmd, waiting));
                    return self.protocol_error(ep, "bad status line", line);
                };
                if let (InFlight::Status, Some((code, payload))) = (&waiting, cmd.continuation.take()) {
                    if status.code == code {
                        ep.send(&payload);
                        self.arm_timer(ep);
                        self.in_flight = Some((cmd, InFlight::Final));
                        return;
                    }
                }
                if cmd.multiline && is_multiline_code(status.code) {
                    // Remember the status; completion fires at the dot.
                    let code = status.code;
                    let text = status.text;
                    let on_complete = std::mem::replace(&mut cmd.on_complete, Box::new(|_| {}));
                    cmd.on_complete = Box::new(move |r| match r {
                        Ok(_) => on_complete(Ok(NntpStatus { code, text })),
                        Err(e) => on_complete(Err(e)),
                    });
                    self.in_flight = Some((cmd, InFlight::Lines));
                } else {
                    self.complete(ep, cmd, Ok(status));
                }
            }
        }
    }

    fn complete(&mut self, ep: &mut dyn Endpoint, cmd: Command, r: Result<NntpStatus, NntpClientError>) {
        self.cancel_timer();
        (cmd.on_complete)(r);
        self.dispatch(ep);
    }
}

impl ProtocolHandler for NntpClientEndpoint {
    fn connected(&mut self, ep: &mut dyn Endpoint) {
        // The server speaks first; nothing to do but wait (and not for
        // ever).
        self.arm_timer(ep);
    }

    fn security_established(&mut self, ep: &mut dyn Endpoint, _info: &SecurityInfo) {
        self.secure = true;
        if self.phase == Phase::PendingTls {
            self.request_capabilities(ep, true);
        }
    }

    fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
        if !data.is_empty() {
            self.lines.push(data);
            *data = &[];
        }
        loop {
            if self.phase == Phase::Closed {
                return;
            }
            let Some(line) = self.lines.next_line() else {
                if self.lines.len() > MAX_LINE {
                    self.fail(ep, io::Error::new(io::ErrorKind::InvalidData, "reply line too long"));
                }
                break;
            };
            match self.phase {
                Phase::Greeting => self.on_greeting(ep, &line),
                Phase::Capabilities { after_tls, collecting } => self.on_capabilities_line(ep, after_tls, collecting, &line),
                Phase::StartTls => self.on_starttls_reply(ep, &line),
                Phase::PendingTls => {}
                Phase::AuthUser => self.on_auth_user_reply(ep, &line),
                Phase::AuthPass => self.on_auth_pass_reply(ep, &line),
                Phase::AuthSasl => self.on_auth_sasl_reply(ep, &line),
                Phase::Ready => self.on_command_line(ep, &line),
                Phase::Closed => return,
            }
        }
        // A poke, or the end of a reply: send what is queued.
        self.dispatch(ep);
    }

    fn disconnected(&mut self, _ep: &mut dyn Endpoint) {
        self.cancel_timer();
        let was_closed = self.phase == Phase::Closed;
        self.phase = Phase::Closed;
        self.fail_commands("connection closed");
        if let Some(h) = self.handler.as_mut() {
            if !self.connected_notified && !was_closed {
                h.on_error(&io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed before the session was ready"));
            }
            h.on_disconnected();
        }
    }

    fn error(&mut self, ep: &mut dyn Endpoint, err: &io::Error) {
        self.fail(ep, io::Error::new(err.kind(), err.to_string()));
    }
}
