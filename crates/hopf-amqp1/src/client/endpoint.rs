// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `Amqp1ClientEndpoint` — the AMQP 1.0 client connection as a [`ProtocolHandler`].
//!
//! Drives, in order: the SASL sub-protocol (protocol header, mechanism
//! choice, challenge/response), the AMQP protocol header re-exchange, the
//! `open` performative, then dispatches `begin`/`attach`/`flow`/`transfer`/
//! `disposition`/`detach`/`end`/`close` to the right [`SessionState`] /
//! [`LinkState`] and [`Amqp1ClientDriver`] callback.

use std::io;
use std::time::Duration;

use hopf_auth::{create_client, SaslClient, SaslClientStep, SaslMechanism};
use hopf_core::{Endpoint, ProtocolHandler, TimerHandle};

use crate::codec::message::{data_section_header, MessageHandler, MessageHeader, MessageProperties};
use crate::codec::{
    Amqp1CompositeError as CodecError, Amqp1Error, Amqp1FrameHandler, Amqp1FrameParser, Attach,
    Begin, Close, DeliveryState, Detach, Disposition, End, Flow, FrameOutcome, Open, Performative,
    SaslBody, Source, Target, Transfer, Value, DEFAULT_MAX_FRAME_SIZE, FRAME_TYPE_AMQP,
    FRAME_TYPE_SASL, PROTOCOL_ID_AMQP, PROTOCOL_ID_SASL,
};
use crate::codec::serial::{serial_add, serial_diff};
use crate::codec::performative::decode_performative;

use super::error::Amqp1ClientError;
use super::handlers::{Amqp1ClientControl, Amqp1ClientDriver, Amqp1ClientHandlerFactory};
use super::session::SessionState;

/// Connection-wide configuration, cloned into each dialed
/// [`Amqp1ClientEndpoint`].
#[derive(Clone)]
pub struct Amqp1ClientParams {
    /// `open.container-id`.
    pub container_id: String,
    /// `open.hostname` / SASL `sasl-init.hostname` (virtual hosting).
    pub hostname: Option<String>,
    /// SASL PLAIN username; `None` uses ANONYMOUS.
    pub username: Option<String>,
    /// SASL PLAIN password.
    pub password: Option<String>,
    /// Max frame size this side accepts.
    pub max_frame_size: u32,
    /// Max channel number this side accepts.
    pub channel_max: u16,
    /// Handshake (SASL + open) timeout.
    pub handshake_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnState {
    AwaitingSaslMechanisms,
    AwaitingSaslOutcome,
    AwaitingOpen,
    Open,
    Closed,
}

/// The AMQP 1.0 client connection.
pub struct Amqp1ClientEndpoint {
    parser: Amqp1FrameParser,
    driver: Option<Box<dyn Amqp1ClientDriver>>,
    params: Amqp1ClientParams,
    state: ConnState,
    sasl_client: Option<Box<dyn SaslClient>>,
    sessions: std::collections::HashMap<u16, SessionState>,
    remote_channel_to_local: std::collections::HashMap<u16, u16>,
    next_local_channel: u16,
    peer_max_frame_size: u32,
    handshake_timer: Option<TimerHandle>,
    open_sent: bool,
    open_received: bool,
}

impl Amqp1ClientEndpoint {
    /// Create a new connection endpoint from a driver factory and connection params.
    pub fn new(factory: &dyn Amqp1ClientHandlerFactory, params: Amqp1ClientParams) -> Self {
        Self {
            parser: Amqp1FrameParser::new(params.max_frame_size),
            driver: Some(factory.create()),
            params,
            state: ConnState::AwaitingSaslMechanisms,
            sasl_client: None,
            sessions: std::collections::HashMap::new(),
            remote_channel_to_local: std::collections::HashMap::new(),
            next_local_channel: 0,
            peer_max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            handshake_timer: None,
            open_sent: false,
            open_received: false,
        }
    }

    fn with_driver_control<R>(
        &mut self,
        io: &mut dyn Endpoint,
        f: impl FnOnce(&mut dyn Amqp1ClientDriver, &mut dyn Amqp1ClientControl) -> R,
    ) -> Option<R> {
        let mut driver = self.driver.take()?;
        let mut ctrl = EndpointControl { ep: self, io };
        let r = f(driver.as_mut(), &mut ctrl);
        self.driver = Some(driver);
        Some(r)
    }

    fn with_driver(&mut self, f: impl FnOnce(&mut dyn Amqp1ClientDriver)) {
        if let Some(d) = self.driver.as_mut() {
            f(d.as_mut());
        }
    }

    fn fail_io(&mut self, io: &mut dyn Endpoint, msg: impl Into<String>) {
        self.state = ConnState::Closed;
        io.fail(io::Error::other(msg.into()));
    }

    fn clear_handshake_timer(&mut self) {
        if let Some(t) = self.handshake_timer.take() {
            t.cancel();
        }
    }

    fn arm_handshake_timeout(&mut self, io: &mut dyn Endpoint) {
        let handle = io.handle();
        self.handshake_timer = Some(io.schedule_timer(
            self.params.handshake_timeout,
            Box::new(move || {
                handle.with_endpoint(|ep| {
                    ep.fail(io::Error::new(io::ErrorKind::TimedOut, "amqp1 handshake timeout"));
                });
            }),
        ));
    }

    fn send_frame(&mut self, io: &mut dyn Endpoint, frame_type: u8, channel: u16, body: &[u8]) {
        let size = 8 + body.len() as u32;
        let mut buf = Vec::with_capacity(size as usize);
        buf.extend_from_slice(&size.to_be_bytes());
        buf.push(2); // doff
        buf.push(frame_type);
        buf.extend_from_slice(&channel.to_be_bytes());
        buf.extend_from_slice(body);
        io.send(&buf);
    }

    fn send_performative(&mut self, io: &mut dyn Endpoint, channel: u16, performative: &Performative) {
        let body = performative.encode();
        self.send_frame(io, FRAME_TYPE_AMQP, channel, &body);
    }

    fn send_performative_with_payload(
        &mut self,
        io: &mut dyn Endpoint,
        channel: u16,
        performative: &Performative,
        payload: &[u8],
    ) {
        let mut body = performative.encode();
        body.extend_from_slice(payload);
        self.send_frame(io, FRAME_TYPE_AMQP, channel, &body);
    }

    fn choose_mechanism(&self, advertised: &[String]) -> Result<String, Amqp1ClientError> {
        let has = |name: &str| advertised.iter().any(|m| m.eq_ignore_ascii_case(name));
        if self.params.username.is_some() && has("PLAIN") {
            Ok("PLAIN".to_string())
        } else if has("ANONYMOUS") {
            Ok("ANONYMOUS".to_string())
        } else if self.params.username.is_some() && has("PLAIN") {
            Ok("PLAIN".to_string())
        } else {
            Err(Amqp1ClientError::Config(format!(
                "no supported SASL mechanism among peer's advertised {advertised:?}"
            )))
        }
    }

    fn send_sasl_init(&mut self, io: &mut dyn Endpoint, mechanism: String) {
        let initial_response = if mechanism.eq_ignore_ascii_case("PLAIN") {
            let user = self.params.username.clone().unwrap_or_default();
            let pass = self.params.password.clone().unwrap_or_default();
            let mut client = create_client(SaslMechanism::Plain, &user, &pass, "", "amqp", None);
            let resp = match client.evaluate(None) {
                SaslClientStep::Response(r) | SaslClientStep::Complete(r) => r,
                SaslClientStep::Failure => Vec::new(),
            };
            self.sasl_client = Some(client);
            Some(resp)
        } else {
            None
        };
        let body = SaslBody::Init {
            mechanism,
            initial_response,
            hostname: self.params.hostname.clone(),
        }
        .encode();
        self.send_frame(io, FRAME_TYPE_SASL, 0, &body);
        self.state = ConnState::AwaitingSaslOutcome;
    }

    fn send_amqp_header_and_open(&mut self, io: &mut dyn Endpoint) {
        io.send(&protocol_header_bytes(PROTOCOL_ID_AMQP));
        let open = Open {
            container_id: self.params.container_id.clone(),
            hostname: self.params.hostname.clone(),
            max_frame_size: self.params.max_frame_size,
            channel_max: self.params.channel_max,
            idle_time_out: None,
            ..Default::default()
        };
        self.send_performative(io, 0, &Performative::Open(open));
        self.open_sent = true;
        self.state = ConnState::AwaitingOpen;
    }

    fn maybe_complete_open(&mut self, io: &mut dyn Endpoint) {
        if self.open_sent && self.open_received && self.state != ConnState::Open {
            self.clear_handshake_timer();
            self.state = ConnState::Open;
            self.with_driver_control(io, |d, c| d.on_connection_open(c));
        }
    }

    // -----------------------------------------------------------------
    // AMQP-layer performative handling.
    // -----------------------------------------------------------------

    /// Returns the effective max-frame-size (min of both sides' advertised
    /// values) for the caller to apply to the *live* frame parser via the
    /// returned [`FrameOutcome`] — see that type's doc comment for why this
    /// can't just be applied to `self.parser` directly from here.
    fn handle_open(&mut self, io: &mut dyn Endpoint, open: Open) -> u32 {
        self.peer_max_frame_size = open.max_frame_size;
        self.open_received = true;
        self.maybe_complete_open(io);
        self.params.max_frame_size.min(open.max_frame_size)
    }

    fn handle_begin(&mut self, io: &mut dyn Endpoint, frame_channel: u16, begin: Begin) {
        let Some(local_channel) = begin.remote_channel else {
            self.fail_io(io, "peer-initiated sessions are not supported by this client");
            return;
        };
        let Some(session) = self.sessions.get_mut(&local_channel) else {
            self.fail_io(io, "begin.remote-channel does not match a session this side began");
            return;
        };
        session.remote_channel = Some(frame_channel);
        session.next_incoming_id = begin.next_outgoing_id;
        session.remote_incoming_window =
            serial_diff(serial_add(begin.next_outgoing_id, begin.incoming_window), session.next_outgoing_id)
                .max(0) as u32;
        session.active = true;
        self.remote_channel_to_local.insert(frame_channel, local_channel);
        self.with_driver_control(io, |d, c| d.on_session_begin(c, local_channel));
    }

    fn handle_end(&mut self, _io: &mut dyn Endpoint, frame_channel: u16, end: End) {
        let Some(&local_channel) = self.remote_channel_to_local.get(&frame_channel) else {
            return;
        };
        self.sessions.remove(&local_channel);
        self.remote_channel_to_local.remove(&frame_channel);
        let error = end.error;
        self.with_driver(|d| d.on_session_end(local_channel, error.as_ref()));
    }

    fn handle_attach(&mut self, io: &mut dyn Endpoint, frame_channel: u16, attach: Attach) {
        let Some(&local_channel) = self.remote_channel_to_local.get(&frame_channel) else {
            return;
        };
        let Some(session) = self.sessions.get_mut(&local_channel) else { return };
        let is_receiver = !attach.role_receiver; // peer's role is the opposite of ours
        let Some(&local_handle) = session.links_by_name.get(&link_key(&attach.name, is_receiver)) else {
            return; // peer-initiated attach: not supported by this client
        };
        let Some(link) = session.links.get_mut(&local_handle) else { return };
        if link.is_receiver {
            // Our delivery-count, as receiver, starts synced to the sender's.
            link.delivery_count = attach.initial_delivery_count.unwrap_or(0);
        }
        session.links_by_remote_handle.insert(attach.handle, local_handle);
        self.with_driver_control(io, |d, c| d.on_link_attached(c, local_handle, is_receiver));
    }

    fn handle_detach(&mut self, io: &mut dyn Endpoint, frame_channel: u16, detach: Detach) {
        let Some(&local_channel) = self.remote_channel_to_local.get(&frame_channel) else {
            return;
        };
        let Some(session) = self.sessions.get_mut(&local_channel) else { return };
        let Some(&local_handle) = session.links_by_remote_handle.get(&detach.handle) else { return };
        if let Some(link) = session.links.remove(&local_handle) {
            session.links_by_remote_handle.remove(&detach.handle);
            session.links_by_name.remove(&link_key(&link.name, link.is_receiver));
        }
        let error = detach.error;
        let closed = detach.closed;
        self.with_driver(|d| d.on_link_detached(local_handle, error.as_ref(), closed));
        let _ = io;
    }

    fn handle_flow(&mut self, io: &mut dyn Endpoint, frame_channel: u16, flow: Flow) {
        let Some(&local_channel) = self.remote_channel_to_local.get(&frame_channel) else {
            return;
        };
        let Some(session) = self.sessions.get_mut(&local_channel) else { return };
        let peer_next_incoming = flow.next_incoming_id.unwrap_or(session.next_outgoing_id);
        session.remote_incoming_window =
            serial_diff(serial_add(peer_next_incoming, flow.incoming_window), session.next_outgoing_id).max(0) as u32;

        let Some(remote_handle) = flow.handle else {
            if flow.echo {
                self.send_session_flow(io, local_channel);
            }
            return;
        };
        let Some(&local_handle) = session.links_by_remote_handle.get(&remote_handle) else { return };
        let Some(link) = session.links.get_mut(&local_handle) else { return };
        if !link.is_receiver {
            let peer_delivery_count = flow.delivery_count.unwrap_or(link.delivery_count);
            let credit = flow.link_credit.unwrap_or(0);
            link.link_credit = serial_diff(serial_add(peer_delivery_count, credit), link.delivery_count).max(0) as u32;
            if link.link_credit > 0 {
                self.with_driver_control(io, |d, c| d.on_credit(c, local_handle));
            }
        }
        if flow.echo {
            self.send_session_flow(io, local_channel);
        }
    }

    fn send_session_flow(&mut self, io: &mut dyn Endpoint, local_channel: u16) {
        let Some(session) = self.sessions.get(&local_channel) else { return };
        let flow = Flow {
            next_incoming_id: Some(session.next_incoming_id),
            incoming_window: session.incoming_window,
            next_outgoing_id: session.next_outgoing_id,
            outgoing_window: session.outgoing_window,
            ..Default::default()
        };
        self.send_performative(io, local_channel, &Performative::Flow(flow));
    }

    fn handle_transfer(&mut self, io: &mut dyn Endpoint, frame_channel: u16, transfer: Transfer, payload: &[u8]) {
        let Some(&local_channel) = self.remote_channel_to_local.get(&frame_channel) else {
            return;
        };

        let Some(local_handle) = ({
            let Some(session) = self.sessions.get_mut(&local_channel) else { return };
            session.next_incoming_id = serial_add(session.next_incoming_id, 1);
            session.incoming_window = session.incoming_window.saturating_sub(1);
            session.links_by_remote_handle.get(&transfer.handle).copied()
        }) else {
            return;
        };

        if let Some(delivery_id) = transfer.delivery_id {
            let tag = transfer.delivery_tag.clone().unwrap_or_default();
            {
                let session = self.sessions.get_mut(&local_channel).unwrap();
                let link = session.links.get_mut(&local_handle).unwrap();
                link.current_delivery = Some((delivery_id, tag.clone()));
                link.link_credit = link.link_credit.saturating_sub(1);
                link.delivery_count = serial_add(link.delivery_count, 1);
            }
            self.with_driver(|d| d.on_delivery_start(local_handle, delivery_id, &tag));
        }

        let current = {
            let session = self.sessions.get_mut(&local_channel).unwrap();
            let link = session.links.get_mut(&local_handle).unwrap();
            link.current_delivery.clone()
        };
        let Some((delivery_id, _tag)) = current else {
            self.fail_io(io, "transfer continuation with no delivery in progress");
            return;
        };

        {
            let mut mh = DriverMessageHandler { driver: self.driver.as_deref_mut(), handle: local_handle };
            let session = self.sessions.get_mut(&local_channel).unwrap();
            let link = session.links.get_mut(&local_handle).unwrap();
            link.parser.feed(payload, &mut mh);
            if !transfer.more {
                link.parser.end_message(&mut mh);
                link.current_delivery = None;
            }
        }

        let needs_reflow = {
            let session = self.sessions.get(&local_channel).unwrap();
            session.incoming_window <= session.initial_incoming_window / 2
        };
        if needs_reflow {
            if let Some(session) = self.sessions.get_mut(&local_channel) {
                session.incoming_window = session.initial_incoming_window;
            }
            self.send_session_flow(io, local_channel);
        }
        if !transfer.more {
            self.with_driver_control(io, |d, c| d.on_delivery_complete(c, local_handle, delivery_id));
        }
    }

    fn handle_disposition(&mut self, io: &mut dyn Endpoint, frame_channel: u16, disposition: Disposition) {
        let Some(&local_channel) = self.remote_channel_to_local.get(&frame_channel) else {
            return;
        };
        if !disposition.role_receiver {
            return; // peer reporting as sender about its own deliveries: not tracked by this client
        }
        let Some(session) = self.sessions.get_mut(&local_channel) else { return };
        let mut outcomes = Vec::new();
        let mut id = disposition.first;
        loop {
            if let Some((link_handle, tag)) = session.unsettled_sent.get(&id).cloned() {
                if disposition.settled {
                    session.unsettled_sent.remove(&id);
                }
                if let Some(state) = disposition.state.clone() {
                    outcomes.push((link_handle, tag, state, disposition.settled));
                }
            }
            if id == disposition.last {
                break;
            }
            id = serial_add(id, 1);
        }
        for (handle, tag, state, settled) in outcomes {
            self.with_driver(|d| d.on_delivery_outcome(handle, &tag, &state, settled));
        }
        let _ = io;
    }

    fn handle_close(&mut self, io: &mut dyn Endpoint, close: Close) {
        self.state = ConnState::Closed;
        let error = close.error;
        self.with_driver(|d| d.on_connection_close(error.as_ref()));
        io.close();
    }
}

fn link_key(name: &str, is_receiver: bool) -> String {
    if is_receiver {
        format!("r:{name}")
    } else {
        format!("s:{name}")
    }
}

fn protocol_header_bytes(protocol_id: u8) -> Vec<u8> {
    let mut v = b"AMQP".to_vec();
    v.push(protocol_id);
    v.extend_from_slice(&[1, 0, 0]);
    v
}

/// Forwards [`crate::codec::message::MessageHandler`] callbacks from one
/// link's [`crate::codec::message::MessageParser`] to the application driver.
struct DriverMessageHandler<'a> {
    driver: Option<&'a mut (dyn Amqp1ClientDriver + 'static)>,
    handle: u32,
}

impl MessageHandler for DriverMessageHandler<'_> {
    fn header(&mut self, header: MessageHeader) {
        if let Some(d) = self.driver.as_mut() {
            d.on_message_header(self.handle, &header);
        }
    }
    fn properties(&mut self, properties: MessageProperties) {
        if let Some(d) = self.driver.as_mut() {
            d.on_message_properties(self.handle, &properties);
        }
    }
    fn application_properties(&mut self, properties: Vec<(String, Value)>) {
        if let Some(d) = self.driver.as_mut() {
            d.on_message_application_properties(self.handle, &properties);
        }
    }
    fn data_chunk(&mut self, data: &[u8]) {
        if let Some(d) = self.driver.as_mut() {
            d.on_message_data(self.handle, data);
        }
    }
    fn error(&mut self, _err: Amqp1Error) {
        // Surfaced to the application via the connection-level `on_error`
        // path when the caller next observes the transport failing; a
        // malformed message body alone doesn't need a separate signal here.
    }
}

/// Bridges [`Amqp1FrameParser`] callbacks back into [`Amqp1ClientEndpoint`]
/// methods, avoiding a `&mut self` / `&mut self.parser` aliasing conflict
/// (the parser is temporarily moved out of `self` for the duration of one
/// [`ProtocolHandler::receive`] call — see that impl below).
struct ReceiveHandler<'a> {
    ep: &'a mut Amqp1ClientEndpoint,
    io: &'a mut dyn Endpoint,
}

impl Amqp1FrameHandler for ReceiveHandler<'_> {
    fn protocol_header(&mut self, protocol_id: u8, _major: u8, _minor: u8, _revision: u8) {
        match self.ep.state {
            ConnState::AwaitingSaslMechanisms | ConnState::AwaitingSaslOutcome => {
                if protocol_id != PROTOCOL_ID_SASL {
                    self.ep.fail_io(self.io, "expected SASL protocol header");
                }
            }
            ConnState::AwaitingOpen => {
                if protocol_id != PROTOCOL_ID_AMQP {
                    self.ep.fail_io(self.io, "expected AMQP protocol header");
                } else {
                    self.ep.state = ConnState::AwaitingOpen;
                }
            }
            _ => {}
        }
    }

    fn frame(&mut self, frame_type: u8, channel: u16, body: &[u8]) -> FrameOutcome {
        if frame_type == crate::codec::FRAME_TYPE_SASL {
            self.handle_sasl_body(body)
        } else {
            self.handle_amqp_body(channel, body)
        }
    }

    fn empty_frame(&mut self, _frame_type: u8, _channel: u16) -> FrameOutcome {
        // Heartbeat / keep-alive: no action needed (this client doesn't yet
        // enforce peer idle timeouts — see crate README).
        FrameOutcome::NONE
    }

    fn error(&mut self, err: Amqp1Error) {
        self.ep.fail_io(self.io, err.to_string());
    }
}

impl ReceiveHandler<'_> {
    fn handle_sasl_body(&mut self, body: &[u8]) -> FrameOutcome {
        let sasl = match SaslBody::decode(body) {
            Ok(s) => s,
            Err(e) => {
                self.ep.fail_io(self.io, e.to_string());
                return FrameOutcome::NONE;
            }
        };
        match sasl {
            SaslBody::Mechanisms(mechs) => {
                match self.ep.choose_mechanism(&mechs) {
                    Ok(m) => self.ep.send_sasl_init(self.io, m),
                    Err(e) => self.ep.fail_io(self.io, e.to_string()),
                }
                FrameOutcome::NONE
            }
            SaslBody::Challenge(challenge) => {
                let Some(mut client) = self.ep.sasl_client.take() else {
                    self.ep.fail_io(self.io, "unexpected SASL challenge (no exchange in progress)");
                    return FrameOutcome::NONE;
                };
                match client.evaluate(Some(&challenge)) {
                    SaslClientStep::Response(r) | SaslClientStep::Complete(r) => {
                        self.ep.sasl_client = Some(client);
                        let body = SaslBody::Response(r).encode();
                        self.ep.send_frame(self.io, FRAME_TYPE_SASL, 0, &body);
                    }
                    SaslClientStep::Failure => {
                        self.ep.fail_io(self.io, "SASL mechanism rejected broker challenge");
                    }
                }
                FrameOutcome::NONE
            }
            SaslBody::Outcome { code, .. } => {
                self.ep.sasl_client = None;
                if code == crate::codec::sasl::outcome_code::OK {
                    self.ep.send_amqp_header_and_open(self.io);
                    FrameOutcome { expect_protocol_header: true, ..FrameOutcome::NONE }
                } else {
                    self.ep.fail_io(self.io, format!("SASL authentication failed (outcome code {code})"));
                    FrameOutcome::NONE
                }
            }
            SaslBody::Init { .. } | SaslBody::Response(_) => {
                // Client-only: this side never receives its own request types.
                FrameOutcome::NONE
            }
        }
    }

    fn handle_amqp_body(&mut self, channel: u16, body: &[u8]) -> FrameOutcome {
        let (performative, consumed) = match decode_performative(body) {
            Ok(v) => v,
            Err(e) => {
                self.ep.fail_io(self.io, e.to_string());
                return FrameOutcome::NONE;
            }
        };
        match performative {
            Performative::Open(open) => {
                let max_frame_size = self.ep.handle_open(self.io, open);
                return FrameOutcome { max_frame_size: Some(max_frame_size), ..FrameOutcome::NONE };
            }
            Performative::Begin(begin) => self.ep.handle_begin(self.io, channel, begin),
            Performative::Attach(attach) => self.ep.handle_attach(self.io, channel, attach),
            Performative::Flow(flow) => self.ep.handle_flow(self.io, channel, flow),
            Performative::Transfer(transfer) => {
                self.ep.handle_transfer(self.io, channel, transfer, &body[consumed..])
            }
            Performative::Disposition(disposition) => self.ep.handle_disposition(self.io, channel, disposition),
            Performative::Detach(detach) => self.ep.handle_detach(self.io, channel, detach),
            Performative::End(end) => self.ep.handle_end(self.io, channel, end),
            Performative::Close(close) => self.ep.handle_close(self.io, close),
        }
        FrameOutcome::NONE
    }
}

impl ProtocolHandler for Amqp1ClientEndpoint {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        endpoint.send(&protocol_header_bytes(PROTOCOL_ID_SASL));
        self.arm_handshake_timeout(endpoint);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        let mut parser = std::mem::replace(&mut self.parser, Amqp1FrameParser::new(0));
        {
            let mut rh = ReceiveHandler { ep: self, io: endpoint };
            parser.feed(data, &mut rh);
        }
        self.parser = parser;
        *data = &[];
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.clear_handshake_timer();
        self.with_driver(|d| d.on_disconnected());
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
        self.with_driver(|d| d.on_error(err));
    }
}

/// [`Amqp1ClientControl`] implementation, borrowing the endpoint and wire
/// connection for the duration of one driver callback (see
/// [`Amqp1ClientEndpoint::with_driver_control`]).
struct EndpointControl<'a> {
    ep: &'a mut Amqp1ClientEndpoint,
    io: &'a mut dyn Endpoint,
}

impl Amqp1ClientControl for EndpointControl<'_> {
    fn begin_session(&mut self) -> u16 {
        let local_channel = self.ep.next_local_channel;
        self.ep.next_local_channel += 1;
        let session = SessionState::new(local_channel);
        let begin = Begin {
            remote_channel: None,
            next_outgoing_id: session.next_outgoing_id,
            incoming_window: session.incoming_window,
            outgoing_window: session.outgoing_window,
            ..unset_begin_defaults()
        };
        self.ep.sessions.insert(local_channel, session);
        self.ep.send_performative(self.io, local_channel, &Performative::Begin(begin));
        local_channel
    }

    fn attach_sender(&mut self, channel: u16, name: &str, target: Target) -> u32 {
        let Some(session) = self.ep.sessions.get_mut(&channel) else { return 0 };
        let handle = session.add_link(name.to_string(), false);
        let attach = Attach {
            name: name.to_string(),
            handle,
            role_receiver: false,
            snd_settle_mode: 2,
            rcv_settle_mode: 0,
            source: Some(Source::default()),
            target: Some(target),
            unsettled: vec![],
            incomplete_unsettled: false,
            initial_delivery_count: Some(0),
            max_message_size: None,
            offered_capabilities: vec![],
            desired_capabilities: vec![],
            properties: vec![],
        };
        self.ep.send_performative(self.io, channel, &Performative::Attach(attach));
        handle
    }

    fn attach_receiver(&mut self, channel: u16, name: &str, source: Source) -> u32 {
        let Some(session) = self.ep.sessions.get_mut(&channel) else { return 0 };
        let handle = session.add_link(name.to_string(), true);
        let attach = Attach {
            name: name.to_string(),
            handle,
            role_receiver: true,
            snd_settle_mode: 2,
            rcv_settle_mode: 0,
            source: Some(source),
            target: Some(Target::default()),
            unsettled: vec![],
            incomplete_unsettled: false,
            initial_delivery_count: None,
            max_message_size: None,
            offered_capabilities: vec![],
            desired_capabilities: vec![],
            properties: vec![],
        };
        self.ep.send_performative(self.io, channel, &Performative::Attach(attach));
        handle
    }

    fn send(
        &mut self,
        handle: u32,
        delivery_tag: &[u8],
        header: Option<&MessageHeader>,
        properties: Option<&MessageProperties>,
        application_properties: &[(String, Value)],
        body: &[u8],
        settled: bool,
    ) -> Result<(), Amqp1ClientError> {
        let Some(channel) = self.ep.find_link_channel(handle) else {
            return Err(Amqp1ClientError::Config("unknown link handle".into()));
        };

        let mut message = Vec::new();
        if let Some(h) = header {
            let mut enc = crate::codec::Encoder::new();
            enc.value(&h.encode());
            message.extend_from_slice(&enc.into_bytes());
        }
        if let Some(p) = properties {
            let mut enc = crate::codec::Encoder::new();
            enc.value(&p.encode());
            message.extend_from_slice(&enc.into_bytes());
        }
        if !application_properties.is_empty() {
            let mut enc = crate::codec::Encoder::new();
            enc.value(&crate::codec::message::encode_application_properties(application_properties));
            message.extend_from_slice(&enc.into_bytes());
        }
        message.extend_from_slice(&data_section_header(body.len() as u32));
        message.extend_from_slice(body);

        let session = self.ep.sessions.get_mut(&channel).expect("session exists for attached link handle");
        let link = session.links.get_mut(&handle).expect("link exists for attached link handle");
        if link.link_credit == 0 {
            return Err(Amqp1ClientError::NoLinkCredit);
        }

        let delivery_id = session.next_outgoing_id;
        session.next_outgoing_id = serial_add(session.next_outgoing_id, 1);
        link.link_credit -= 1;
        link.delivery_count = serial_add(link.delivery_count, 1);
        if !settled {
            session.unsettled_sent.insert(delivery_id, (handle, delivery_tag.to_vec()));
        }

        // Split across multiple `transfer` frames if the message exceeds
        // what fits in one frame, per the peer's negotiated max-frame-size.
        const TRANSFER_OVERHEAD: usize = 64; // generous bound on the transfer performative's own encoded size
        let max_payload = (self.ep.peer_max_frame_size as usize)
            .saturating_sub(8 + TRANSFER_OVERHEAD)
            .max(64);

        let mut offset = 0;
        let mut first = true;
        loop {
            let end = (offset + max_payload).min(message.len());
            let more = end < message.len();
            let chunk = &message[offset..end];
            let transfer = Transfer {
                handle,
                delivery_id: first.then_some(delivery_id),
                delivery_tag: first.then(|| delivery_tag.to_vec()),
                settled: first.then_some(settled),
                more,
                ..Default::default()
            };
            self.ep.send_performative_with_payload(self.io, channel, &Performative::Transfer(transfer), chunk);
            offset = end;
            first = false;
            if !more {
                break;
            }
        }
        Ok(())
    }

    fn add_credit(&mut self, handle: u32, credit: u32) {
        let Some(channel) = self.ep.find_link_channel(handle) else { return };
        let Some(session) = self.ep.sessions.get_mut(&channel) else { return };
        let Some(link) = session.links.get_mut(&handle) else { return };
        link.link_credit += credit;
        let flow = Flow {
            next_incoming_id: Some(session.next_incoming_id),
            incoming_window: session.incoming_window,
            next_outgoing_id: session.next_outgoing_id,
            outgoing_window: session.outgoing_window,
            handle: Some(handle),
            delivery_count: Some(link.delivery_count),
            link_credit: Some(link.link_credit),
            ..Default::default()
        };
        self.ep.send_performative(self.io, channel, &Performative::Flow(flow));
    }

    fn accept(&mut self, handle: u32, delivery_id: u32) {
        self.settle(handle, delivery_id, DeliveryState::Accepted);
    }

    fn reject(&mut self, handle: u32, delivery_id: u32, error: Option<CodecError>) {
        self.settle(handle, delivery_id, DeliveryState::Rejected(error));
    }

    fn release(&mut self, handle: u32, delivery_id: u32) {
        self.settle(handle, delivery_id, DeliveryState::Released);
    }

    fn modify(&mut self, handle: u32, delivery_id: u32, delivery_failed: bool, undeliverable_here: bool) {
        self.settle(
            handle,
            delivery_id,
            DeliveryState::Modified { delivery_failed, undeliverable_here, message_annotations: vec![] },
        );
    }

    fn detach_link(&mut self, handle: u32, closed: bool, error: Option<CodecError>) {
        let Some(channel) = self.ep.find_link_channel(handle) else { return };
        let detach = Detach { handle, closed, error };
        self.ep.send_performative(self.io, channel, &Performative::Detach(detach));
    }

    fn end_session(&mut self, channel: u16, error: Option<CodecError>) {
        if let Some(session) = self.ep.sessions.get_mut(&channel) {
            session.end_sent = true;
        }
        self.ep.send_performative(self.io, channel, &Performative::End(End { error }));
    }

    fn close(&mut self, error: Option<CodecError>) {
        self.ep.send_performative(self.io, 0, &Performative::Close(Close { error }));
        self.io.close();
    }
}

impl EndpointControl<'_> {
    fn settle(&mut self, handle: u32, delivery_id: u32, state: DeliveryState) {
        let Some(channel) = self.ep.find_link_channel(handle) else { return };
        let disposition = Disposition {
            role_receiver: true,
            first: delivery_id,
            last: delivery_id,
            settled: true,
            state: Some(state),
            batchable: false,
        };
        self.ep.send_performative(self.io, channel, &Performative::Disposition(disposition));
    }
}

impl Amqp1ClientEndpoint {
    fn find_link_channel(&self, handle: u32) -> Option<u16> {
        self.sessions
            .values()
            .find(|session| session.links.contains_key(&handle))
            .map(|session| session.local_channel)
    }
}

fn unset_begin_defaults() -> Begin {
    Begin {
        remote_channel: None,
        next_outgoing_id: 0,
        incoming_window: 0,
        outgoing_window: 0,
        handle_max: u32::MAX,
        offered_capabilities: vec![],
        desired_capabilities: vec![],
        properties: vec![],
    }
}
