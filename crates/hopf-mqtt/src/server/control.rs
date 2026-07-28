// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `MqttControlHandler` — the per-connection `ProtocolHandler` driving the
//! MQTT wire protocol against shared [`BrokerState`].

use std::collections::HashSet;
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{Endpoint, ProtocolHandler, TimerHandle};

use crate::server::broker::{validate_topic_name, BrokerState, SubscriberId, UNLIMITED_RECEIVE_MAXIMUM};
use crate::codec::packet::{reason, ConnectPacket, PublishHeader, QoS, SubscribeFilter, Will};
use crate::codec::parser::{MqttFrameHandler, MqttFrameParser};
use crate::codec::properties::property;
use crate::codec::{encode, MqttError, Properties, ProtocolVersion};

use super::config::MqttConfig;
use super::handler::{ConnectDecision, ConnectHandler};

static NEXT_ASSIGNED_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

fn assign_client_id() -> String {
    format!(
        "hopf-mqtt-{}-{}",
        std::process::id(),
        NEXT_ASSIGNED_CLIENT_ID.fetch_add(1, Ordering::Relaxed)
    )
}

struct ConnectedSession {
    subscriber_id: SubscriberId,
    version: ProtocolVersion,
    will: Option<Will>,
    keep_alive: Duration,
    keepalive_timer: Option<TimerHandle>,
    /// MQTT 5.0 Session Expiry Interval — how long the broker keeps this
    /// session's subscriptions alive (as an "orphan") after an unclean
    /// disconnect before dropping them for good. Zero (the v3.1.1 default)
    /// means drop immediately, same as today.
    session_expiry: Duration,
    graceful_disconnect: bool,
    /// QoS 2 packet ids from the client we've PUBREC'd but not yet PUBREL'd
    /// — lets a duplicate (DUP-flagged) resend before PUBREL be re-acked
    /// without re-publishing to subscribers.
    awaiting_pubrel: HashSet<u16>,
    /// Accumulates one in-progress PUBLISH from the client
    /// (header set in `start_publish`, bytes appended in `publish_data`).
    pending_publish: Option<(PublishHeader, Vec<u8>)>,
}

enum SessionState {
    AwaitingConnect,
    Connected(Box<ConnectedSession>),
}

/// Server-side `ProtocolHandler` for one MQTT TCP connection.
pub struct MqttControlHandler {
    config: Arc<MqttConfig>,
    parser: MqttFrameParser,
    session: SessionState,
    connect_timeout_timer: Option<TimerHandle>,
    connect_handler: Box<dyn ConnectHandler>,
}

impl MqttControlHandler {
    /// New handler bound to `config` (shared across every connection this
    /// listener accepts) and a freshly-created [`ConnectHandler`] (one per
    /// connection, from [`super::handler::MqttHandlerFactory::create`]).
    pub fn new(config: Arc<MqttConfig>, connect_handler: Box<dyn ConnectHandler>) -> Self {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        parser.set_max_packet_size(config.max_packet_size);
        Self {
            config,
            parser,
            session: SessionState::AwaitingConnect,
            connect_timeout_timer: None,
            connect_handler,
        }
    }
}

impl ProtocolHandler for MqttControlHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        let handle = endpoint.handle();
        self.connect_timeout_timer = Some(endpoint.schedule_timer(
            self.config.connect_timeout,
            Box::new(move || handle.close()),
        ));
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        // `Ctx` borrows `self` for the duration of the callbacks, so the
        // parser driving those callbacks can't live inside `self` while
        // it's being called — swap it out for the duration of `push`.
        let mut parser = mem::replace(&mut self.parser, MqttFrameParser::new(ProtocolVersion::V311));
        let mut ctx = Ctx {
            handler: self,
            endpoint: &mut *endpoint,
            pending_version: None,
        };
        parser.push(data, &mut ctx);
        if let Some(version) = ctx.pending_version {
            parser.set_version(version);
        }
        self.parser = parser;
        *data = &[];
        rearm_keepalive(self, endpoint);
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        if let SessionState::Connected(session) = &self.session {
            if let Some(timer) = &session.keepalive_timer {
                timer.cancel();
            }
            if !session.graceful_disconnect {
                if let Some(will) = &session.will {
                    self.config.broker.publish(
                        Some(session.subscriber_id),
                        &will.topic,
                        &will.payload,
                        will.qos,
                        will.retain,
                        &will.properties,
                    );
                }
            }
            if session.session_expiry.is_zero() {
                self.config.broker.unregister(session.subscriber_id);
            } else {
                // Keep subscriptions alive as an orphan for Session Expiry;
                // reap them later unless a matching CONNECT resumes first
                // (`orphan`'s epoch guards against a stale timer reaping a
                // session that has since resumed and orphaned again).
                let epoch = self.config.broker.orphan(session.subscriber_id);
                let broker = Arc::clone(&self.config.broker);
                let id = session.subscriber_id;
                endpoint.schedule_timer(
                    session.session_expiry,
                    Box::new(move || broker.expire_orphan(id, epoch)),
                );
            }
        }
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
}

/// Re-arm the keepalive timer after any inbound activity (MQTT 3.1.1
/// §3.1.2.10: the server must close a connection silent for more than
/// 1.5x the negotiated Keep Alive). A plain `Endpoint::schedule_timer`
/// cancel-and-reschedule, per the project convention for app-level idle
/// timeouts (core `idle_timeout` isn't enforced on the datapath yet).
fn rearm_keepalive(handler: &mut MqttControlHandler, endpoint: &mut dyn Endpoint) {
    if let SessionState::Connected(session) = &mut handler.session {
        if !session.keep_alive.is_zero() {
            if let Some(old) = session.keepalive_timer.take() {
                old.cancel();
            }
            let handle = endpoint.handle();
            session.keepalive_timer = Some(
                endpoint.schedule_timer(session.keep_alive, Box::new(move || handle.close())),
            );
        }
    }
}

/// Ephemeral adapter binding an in-progress `receive()` call's `Endpoint`
/// to the connection's persistent handler state, so [`MqttFrameHandler`]
/// callbacks (which don't carry an `Endpoint` parameter — the codec has no
/// dependency on `hopf-core`) can still send replies and touch broker
/// state. `pending_version` lets `connect()` request a parser version
/// switch without re-entering the parser that's mid-`push` calling it.
struct Ctx<'h, 'e> {
    handler: &'h mut MqttControlHandler,
    endpoint: &'e mut dyn Endpoint,
    pending_version: Option<ProtocolVersion>,
}

impl Ctx<'_, '_> {
    fn broker(&self) -> &Arc<BrokerState> {
        &self.handler.config.broker
    }

    fn connack_and_close(&mut self, version: ProtocolVersion, reason_code: u8) {
        let wire = encode::encode_connack(false, reason_code, &Properties::new(), version);
        self.endpoint.send(&wire);
        self.endpoint.close();
    }

    /// Close the connection, first sending a server-initiated DISCONNECT
    /// with `reason_code` if the session is established and v5 (MQTT 5.0
    /// §3.14 — v3.1.1 has no server-initiated DISCONNECT, and pre-CONNECT
    /// there's no negotiated version to encode one with).
    fn disconnect_and_close(&mut self, reason_code: u8) {
        if let SessionState::Connected(session) = &self.handler.session {
            if session.version.is_v5() {
                let wire = encode::encode_disconnect(reason_code, &Properties::new(), session.version);
                self.endpoint.send(&wire);
            }
        }
        self.endpoint.close();
    }
}

impl MqttFrameHandler for Ctx<'_, '_> {
    fn connect(&mut self, packet: ConnectPacket) {
        if let Some(timer) = self.handler.connect_timeout_timer.take() {
            timer.cancel();
        }
        if matches!(self.handler.session, SessionState::Connected(_)) {
            // A second CONNECT on an established session is a protocol
            // violation (MQTT 3.1.1 §3.1).
            self.disconnect_and_close(reason::PROTOCOL_ERROR);
            return;
        }

        let version = packet.version;
        let fail_code = |v311: u8, v5: u8| if version.is_v5() { v5 } else { v311 };

        let client_id = if packet.client_id.is_empty() {
            if !packet.clean_session {
                self.connack_and_close(
                    version,
                    fail_code(
                        reason::connack_v311::IDENTIFIER_REJECTED,
                        reason::CLIENT_IDENTIFIER_NOT_VALID,
                    ),
                );
                return;
            }
            assign_client_id()
        } else {
            packet.client_id.clone()
        };

        if let ConnectDecision::Reject(reason_code) = self.handler.connect_handler.authorize(&packet) {
            self.connack_and_close(version, reason_code);
            return;
        }

        let keep_alive = if packet.keep_alive == 0 {
            Duration::ZERO
        } else {
            Duration::from_millis(packet.keep_alive as u64 * 1500)
        };

        let receive_maximum = if version.is_v5() {
            packet
                .properties
                .get_u16(property::RECEIVE_MAXIMUM)
                .unwrap_or(UNLIMITED_RECEIVE_MAXIMUM)
                .max(1)
        } else {
            UNLIMITED_RECEIVE_MAXIMUM
        };
        let session_expiry_secs = if version.is_v5() {
            packet.properties.get_u32(property::SESSION_EXPIRY_INTERVAL).unwrap_or(0)
        } else {
            0
        };
        let session_expiry = Duration::from_secs(session_expiry_secs as u64);

        let (subscriber_id, evicted, session_present) = self.broker().register(
            &client_id,
            version,
            receive_maximum,
            packet.clean_session,
            self.endpoint.handle(),
        );
        if let Some(evicted) = evicted {
            evicted.close();
        }

        self.handler.session = SessionState::Connected(Box::new(ConnectedSession {
            subscriber_id,
            version,
            will: packet.will,
            keep_alive,
            keepalive_timer: None,
            session_expiry,
            graceful_disconnect: false,
            awaiting_pubrel: HashSet::new(),
            pending_publish: None,
        }));
        self.pending_version = Some(version);

        let mut connack_props = Properties::new();
        if version.is_v5() {
            if receive_maximum != UNLIMITED_RECEIVE_MAXIMUM {
                connack_props.set_u16(property::RECEIVE_MAXIMUM, receive_maximum);
            }
            if session_expiry_secs != 0 {
                connack_props.set_u32(property::SESSION_EXPIRY_INTERVAL, session_expiry_secs);
            }
        }
        let wire = encode::encode_connack(session_present, 0, &connack_props, version);
        self.endpoint.send(&wire);
    }

    fn connack(&mut self, _session_present: bool, _reason_code: u8, _properties: Properties) {
        self.disconnect_and_close(reason::PROTOCOL_ERROR); // servers don't receive CONNACK
    }

    fn start_publish(&mut self, header: PublishHeader) {
        if validate_topic_name(&header.topic).is_err() {
            self.disconnect_and_close(reason::TOPIC_NAME_INVALID);
            return;
        }
        let SessionState::Connected(session) = &mut self.handler.session else {
            self.disconnect_and_close(reason::PROTOCOL_ERROR);
            return;
        };
        if header.qos == QoS::ExactlyOnce && session.awaiting_pubrel.contains(&header.packet_id) {
            // Duplicate re-delivery of a QoS 2 publish we already PUBREC'd
            // (client retransmitted before our PUBREC arrived, or before it
            // sent PUBREL). Re-ack now and don't re-buffer the payload —
            // `publish_data`/`end_publish` will still fire for it, but
            // `pending_publish` staying `None` makes them no-ops.
            session.pending_publish = None;
            let version = session.version;
            let wire = encode::encode_pubrec(header.packet_id, reason::SUCCESS, &Properties::new(), version);
            self.endpoint.send(&wire);
            return;
        }
        session.pending_publish = Some((header, Vec::new()));
    }

    fn publish_data(&mut self, data: &[u8]) {
        if let SessionState::Connected(session) = &mut self.handler.session {
            if let Some((_, buf)) = &mut session.pending_publish {
                buf.extend_from_slice(data);
            }
        }
    }

    fn end_publish(&mut self) {
        let SessionState::Connected(session) = &mut self.handler.session else {
            return;
        };
        let Some((header, payload)) = session.pending_publish.take() else {
            // Duplicate QoS 2 resend — `start_publish` already re-acked it.
            return;
        };
        let (version, subscriber_id) = (session.version, session.subscriber_id);

        self.broker().publish(
            Some(subscriber_id),
            &header.topic,
            &payload,
            header.qos,
            header.retain,
            &header.properties,
        );

        let SessionState::Connected(session) = &mut self.handler.session else {
            return;
        };
        match header.qos {
            QoS::AtMostOnce => {}
            QoS::AtLeastOnce => {
                let wire = encode::encode_puback(header.packet_id, reason::SUCCESS, &Properties::new(), version);
                self.endpoint.send(&wire);
            }
            QoS::ExactlyOnce => {
                session.awaiting_pubrel.insert(header.packet_id);
                let wire = encode::encode_pubrec(header.packet_id, reason::SUCCESS, &Properties::new(), version);
                self.endpoint.send(&wire);
            }
        }
    }

    fn puback(&mut self, _packet_id: u16, _reason_code: u8, _properties: Properties) {
        // Client acked a QoS 1 message we forwarded to it as a subscriber —
        // frees one Receive Maximum credit.
        if let SessionState::Connected(session) = &self.handler.session {
            self.broker().ack_delivered(session.subscriber_id);
        }
    }

    fn pubrec(&mut self, _packet_id: u16, _reason_code: u8, _properties: Properties) {}

    fn pubrel(&mut self, packet_id: u16, _reason_code: u8, _properties: Properties) {
        let SessionState::Connected(session) = &mut self.handler.session else {
            return;
        };
        session.awaiting_pubrel.remove(&packet_id);
        let wire = encode::encode_pubcomp(packet_id, reason::SUCCESS, &Properties::new(), session.version);
        self.endpoint.send(&wire);
    }

    fn pubcomp(&mut self, _packet_id: u16, _reason_code: u8, _properties: Properties) {
        // Client completed the QoS 2 handshake for a message we forwarded
        // to it as a subscriber — frees one Receive Maximum credit.
        if let SessionState::Connected(session) = &self.handler.session {
            self.broker().ack_delivered(session.subscriber_id);
        }
    }

    fn subscribe(&mut self, packet_id: u16, _properties: Properties, filters: Vec<SubscribeFilter>) {
        let SessionState::Connected(session) = &self.handler.session else {
            self.disconnect_and_close(reason::PROTOCOL_ERROR);
            return;
        };
        let (subscriber_id, version) = (session.subscriber_id, session.version);

        let mut reason_codes = Vec::with_capacity(filters.len());
        for filter in &filters {
            match self.broker().subscribe(subscriber_id, filter) {
                Ok(is_new) => {
                    reason_codes.push(filter.max_qos.value());
                    // Retain Handling (MQTT 5.0 §3.8.3.1; v3.1.1 filters
                    // decode with retain_handling = 0, "always send"):
                    // 0 = always send matching retained messages, 1 = only
                    // for a brand new subscription, 2 = never.
                    let send_retained = match filter.retain_handling {
                        0 => true,
                        1 => is_new,
                        _ => false,
                    };
                    if send_retained {
                        for (topic, msg) in self.broker().retained_matching(&filter.topic_filter) {
                            self.broker().deliver_retained(subscriber_id, &topic, &msg, filter.max_qos);
                        }
                    }
                }
                Err(_) => reason_codes.push(reason::UNSPECIFIED_ERROR),
            }
        }
        let wire = encode::encode_suback(packet_id, &reason_codes, &Properties::new(), version);
        self.endpoint.send(&wire);
    }

    fn suback(&mut self, _packet_id: u16, _properties: Properties, _reason_codes: Vec<u8>) {
        self.disconnect_and_close(reason::PROTOCOL_ERROR); // servers don't receive SUBACK
    }

    fn unsubscribe(&mut self, packet_id: u16, _properties: Properties, topic_filters: Vec<String>) {
        let SessionState::Connected(session) = &self.handler.session else {
            self.disconnect_and_close(reason::PROTOCOL_ERROR);
            return;
        };
        let (subscriber_id, version) = (session.subscriber_id, session.version);

        let mut reason_codes = Vec::with_capacity(topic_filters.len());
        for filter in &topic_filters {
            let existed = self.broker().unsubscribe(subscriber_id, filter);
            reason_codes.push(if existed {
                reason::SUCCESS
            } else {
                reason::NO_SUBSCRIPTION_EXISTED
            });
        }
        let wire = encode::encode_unsuback(packet_id, &reason_codes, &Properties::new(), version);
        self.endpoint.send(&wire);
    }

    fn unsuback(&mut self, _packet_id: u16, _properties: Properties, _reason_codes: Vec<u8>) {
        self.disconnect_and_close(reason::PROTOCOL_ERROR); // servers don't receive UNSUBACK
    }

    fn ping_req(&mut self) {
        self.endpoint.send(&encode::encode_pingresp());
    }

    fn ping_resp(&mut self) {
        self.disconnect_and_close(reason::PROTOCOL_ERROR); // servers don't receive PINGRESP
    }

    fn disconnect(&mut self, _reason_code: u8, _properties: Properties) {
        if let SessionState::Connected(session) = &mut self.handler.session {
            session.graceful_disconnect = true;
        }
        self.endpoint.close();
    }

    fn auth(&mut self, _reason_code: u8, _properties: Properties) {
        // Enhanced AUTH (MQTT 5.0 §4.12) is future work — see the MQTT plan.
    }

    fn parse_error(&mut self, _err: MqttError) {
        self.disconnect_and_close(reason::MALFORMED_PACKET);
    }
}
