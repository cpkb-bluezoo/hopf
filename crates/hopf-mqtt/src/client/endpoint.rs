// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `MqttClientEndpoint` — async MQTT client as a [`ProtocolHandler`].
//!
//! Reuses [`MqttFrameParser`] / [`MqttFrameHandler`] directly — unlike the
//! POP3 / IMAP clients, MQTT's wire format is identical in both directions,
//! so there's no need for a separate client-side codec.

use std::io;
use std::time::Duration;

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, SharedTlsConnector, TimerHandle};

use crate::codec::packet::{reason, ConnectPacket, PublishHeader, QoS, SubscribeFilter, Will};
use crate::codec::parser::{MqttFrameHandler, MqttFrameParser};
use crate::codec::properties::property;
use crate::codec::{encode, MqttError, Properties, ProtocolVersion};

use super::handlers::{MqttClientControl, MqttClientDriver, MqttClientHandlerFactory};

/// Marker text on a [`std::io::ErrorKind::TimedOut`] error delivered via
/// [`Endpoint::fail`] that means "time to send a keepalive PINGREQ", as
/// opposed to a genuine CONNACK / PINGRESP deadline (which fall through to
/// [`MqttClientDriver::on_error`] instead). The scheduled-timer closure
/// that fires this only has `&mut dyn Endpoint` (no access back to `self`),
/// so re-arming the next keepalive tick and the PINGRESP deadline happens
/// in `error()`, which does have `&mut self` — same pattern `hopf-pop3`
/// uses for its stage timers.
const KEEPALIVE_DUE: &str = "hopf-mqtt-keepalive-due";

/// Builder input bundled by [`super::facade::MqttClient`] — one call site,
/// avoids an eleven-plus-argument constructor. `Clone` because the
/// connector factory closure captures one and may run more than once.
#[derive(Clone)]
pub struct MqttClientParams {
    /// Protocol version to CONNECT with.
    pub version: ProtocolVersion,
    /// Client Identifier.
    pub client_id: String,
    /// Clean Session (3.1.1) / Clean Start (5.0).
    pub clean_start: bool,
    /// Keep Alive interval (0 disables keepalive).
    pub keep_alive: Duration,
    /// MQTT 5.0 Session Expiry Interval in seconds (0 = none).
    pub session_expiry_secs: u32,
    /// MQTT 5.0 Receive Maximum to advertise (`None` omits the property).
    pub receive_maximum: Option<u16>,
    /// CONNECT username.
    pub username: Option<String>,
    /// CONNECT password.
    pub password: Option<Vec<u8>>,
    /// Will Message.
    pub will: Option<Will>,
    /// TLS connector, only used for implicit TLS (MQTTS) — MQTT has no
    /// STARTTLS-style upgrade path.
    pub tls_connector: Option<SharedTlsConnector>,
    /// TLS server name (SNI / certificate verification).
    pub tls_server_name: Option<String>,
    /// Whether TLS starts immediately (MQTTS).
    pub implicit_tls: bool,
    /// How long to wait for CONNACK.
    pub connack_timeout: Duration,
    /// How long to wait for PINGRESP after a keepalive PINGREQ.
    pub pingresp_timeout: Duration,
}

/// Async MQTT client [`ProtocolHandler`]. Created by
/// [`super::facade::MqttClient::connect`].
pub struct MqttClientEndpoint {
    driver: Option<Box<dyn MqttClientDriver>>,
    parser: MqttFrameParser,
    version: ProtocolVersion,
    client_id: String,
    clean_start: bool,
    keep_alive: Duration,
    session_expiry_secs: u32,
    receive_maximum: Option<u16>,
    username: Option<String>,
    password: Option<Vec<u8>>,
    will: Option<Will>,
    implicit_tls_pending: bool,
    connack_timeout: Duration,
    connack_timer: Option<TimerHandle>,
    pingresp_timeout: Duration,
    pingresp_timer: Option<TimerHandle>,
    keepalive_timer: Option<TimerHandle>,
    next_packet_id: u16,
    pending_publish_header: Option<PublishHeader>,
    closed: bool,
}

impl MqttClientEndpoint {
    /// Create a new endpoint from a factory and connection parameters.
    pub fn new(factory: &dyn MqttClientHandlerFactory, params: MqttClientParams) -> Self {
        Self {
            driver: Some(factory.create()),
            parser: MqttFrameParser::new(params.version),
            version: params.version,
            client_id: params.client_id,
            clean_start: params.clean_start,
            keep_alive: params.keep_alive,
            session_expiry_secs: params.session_expiry_secs,
            receive_maximum: params.receive_maximum,
            username: params.username,
            password: params.password,
            will: params.will,
            implicit_tls_pending: params.implicit_tls,
            connack_timeout: params.connack_timeout,
            connack_timer: None,
            pingresp_timeout: params.pingresp_timeout,
            pingresp_timer: None,
            keepalive_timer: None,
            next_packet_id: 1,
            pending_publish_header: None,
            closed: false,
        }
    }

    fn next_packet_id(&mut self) -> u16 {
        let id = self.next_packet_id;
        self.next_packet_id = if id == u16::MAX { 1 } else { id + 1 };
        id
    }

    fn send_connect(&mut self, ep: &mut dyn Endpoint) {
        let mut properties = Properties::new();
        if self.version.is_v5() {
            if let Some(rm) = self.receive_maximum {
                properties.set_u16(property::RECEIVE_MAXIMUM, rm);
            }
            if self.session_expiry_secs != 0 {
                properties.set_u32(property::SESSION_EXPIRY_INTERVAL, self.session_expiry_secs);
            }
        }
        let packet = ConnectPacket {
            version: self.version,
            clean_session: self.clean_start,
            keep_alive: self.keep_alive.as_secs().min(u16::MAX as u64) as u16,
            properties,
            client_id: self.client_id.clone(),
            will: self.will.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
        };
        ep.send(&encode::encode_connect(&packet));
        self.arm_connack_timer(ep);
    }

    fn arm_connack_timer(&mut self, ep: &mut dyn Endpoint) {
        if self.connack_timeout.is_zero() {
            return;
        }
        let handle = ep.handle();
        self.connack_timer = Some(ep.schedule_timer(
            self.connack_timeout,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(io::ErrorKind::TimedOut, "MQTT CONNACK timed out"));
                });
            }),
        ));
    }

    fn arm_keepalive_timer(&mut self, ep: &mut dyn Endpoint) {
        if self.keep_alive.is_zero() {
            return;
        }
        let handle = ep.handle();
        self.keepalive_timer = Some(ep.schedule_timer(
            self.keep_alive,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(io::ErrorKind::TimedOut, KEEPALIVE_DUE));
                });
            }),
        ));
    }

    fn arm_pingresp_timer(&mut self, ep: &mut dyn Endpoint) {
        if self.pingresp_timeout.is_zero() {
            return;
        }
        let handle = ep.handle();
        self.pingresp_timer = Some(ep.schedule_timer(
            self.pingresp_timeout,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(io::ErrorKind::TimedOut, "MQTT PINGRESP timed out"));
                });
            }),
        ));
    }

    fn cancel_all_timers(&mut self) {
        if let Some(t) = self.connack_timer.take() {
            t.cancel();
        }
        if let Some(t) = self.keepalive_timer.take() {
            t.cancel();
        }
        if let Some(t) = self.pingresp_timer.take() {
            t.cancel();
        }
    }
}

impl ProtocolHandler for MqttClientEndpoint {
    fn connected(&mut self, ep: &mut dyn Endpoint) {
        if self.implicit_tls_pending {
            return; // wait for security_established before sending CONNECT
        }
        self.send_connect(ep);
    }

    fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
        // `parser.push` calls back into `self` (it implements
        // `MqttFrameHandler` directly below) — take it out of `self` first
        // so that isn't a simultaneous double borrow of the same field.
        let mut parser = std::mem::replace(&mut self.parser, MqttFrameParser::new(self.version));
        let mut ctx = ClientCtx { handler: self, endpoint: ep };
        parser.push(data, &mut ctx);
        self.parser = parser;
        *data = &[];
    }

    fn security_established(&mut self, ep: &mut dyn Endpoint, _info: &SecurityInfo) {
        if self.implicit_tls_pending {
            self.implicit_tls_pending = false;
            self.send_connect(ep);
        }
    }

    fn disconnected(&mut self, _ep: &mut dyn Endpoint) {
        self.cancel_all_timers();
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(mut driver) = self.driver.take() {
            driver.on_disconnected();
            self.driver = Some(driver);
        }
    }

    fn error(&mut self, ep: &mut dyn Endpoint, err: &io::Error) {
        if err.kind() == io::ErrorKind::TimedOut && err.to_string().contains(KEEPALIVE_DUE) {
            ep.send(&encode::encode_pingreq());
            self.arm_keepalive_timer(ep);
            self.arm_pingresp_timer(ep);
            return;
        }
        self.cancel_all_timers();
        self.closed = true;
        if let Some(mut driver) = self.driver.take() {
            driver.on_error(err);
            self.driver = Some(driver);
        }
    }
}

/// Ephemeral adapter binding an in-progress `receive()` call's `Endpoint`
/// to the connection's persistent handler state (same pattern as the
/// server's `MqttControlHandler` `Ctx`). Implements both
/// [`MqttFrameHandler`] (wire callbacks from the parser) and
/// [`MqttClientControl`] (actions the driver can take from within its own
/// callbacks) — both need `handler` and `endpoint` together, and bundling
/// them here means callers of the driver just pass `&mut *self`.
struct ClientCtx<'h, 'e> {
    handler: &'h mut MqttClientEndpoint,
    endpoint: &'e mut dyn Endpoint,
}

impl MqttClientControl for ClientCtx<'_, '_> {
    fn publish(&mut self, topic: &str, payload: &[u8], qos: QoS, retain: bool, properties: &Properties) -> u16 {
        let packet_id = if qos == QoS::AtMostOnce { 0 } else { self.handler.next_packet_id() };
        let wire = encode::encode_publish(topic, qos, false, retain, packet_id, payload, properties, self.handler.version);
        self.endpoint.send(&wire);
        packet_id
    }

    fn subscribe(&mut self, filters: &[SubscribeFilter]) -> u16 {
        let packet_id = self.handler.next_packet_id();
        let wire = encode::encode_subscribe(packet_id, filters, &Properties::new(), self.handler.version);
        self.endpoint.send(&wire);
        packet_id
    }

    fn unsubscribe(&mut self, topic_filters: &[String]) -> u16 {
        let packet_id = self.handler.next_packet_id();
        let wire = encode::encode_unsubscribe(packet_id, topic_filters, &Properties::new(), self.handler.version);
        self.endpoint.send(&wire);
        packet_id
    }

    fn disconnect(&mut self, reason_code: u8) {
        if self.handler.version.is_v5() {
            let wire = encode::encode_disconnect(reason_code, &Properties::new(), self.handler.version);
            self.endpoint.send(&wire);
        }
        self.endpoint.close();
    }
}

impl MqttFrameHandler for ClientCtx<'_, '_> {
    fn connect(&mut self, _packet: ConnectPacket) {
        self.endpoint.close(); // clients don't receive CONNECT
    }

    fn connack(&mut self, session_present: bool, reason_code: u8, properties: Properties) {
        if let Some(t) = self.handler.connack_timer.take() {
            t.cancel();
        }
        self.handler.arm_keepalive_timer(self.endpoint);
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_connack(self, session_present, reason_code, &properties);
            self.handler.driver = Some(driver);
        }
        if reason_code != reason::SUCCESS {
            self.endpoint.close();
        }
    }

    fn start_publish(&mut self, header: PublishHeader) {
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_message_start(&header.topic, header.qos, header.retain, header.packet_id, &header.properties, header.payload_len);
            self.handler.driver = Some(driver);
        }
        self.handler.pending_publish_header = Some(header);
    }

    fn publish_data(&mut self, data: &[u8]) {
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_message_data(data);
            self.handler.driver = Some(driver);
        }
    }

    fn end_publish(&mut self) {
        let Some(header) = self.handler.pending_publish_header.take() else {
            return;
        };
        match header.qos {
            QoS::AtMostOnce => {}
            QoS::AtLeastOnce => {
                let wire = encode::encode_puback(header.packet_id, reason::SUCCESS, &Properties::new(), self.handler.version);
                self.endpoint.send(&wire);
            }
            QoS::ExactlyOnce => {
                let wire = encode::encode_pubrec(header.packet_id, reason::SUCCESS, &Properties::new(), self.handler.version);
                self.endpoint.send(&wire);
            }
        }
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_message_complete(self);
            self.handler.driver = Some(driver);
        }
    }

    fn puback(&mut self, packet_id: u16, _reason_code: u8, _properties: Properties) {
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_publish_acked(self, packet_id);
            self.handler.driver = Some(driver);
        }
    }

    fn pubrec(&mut self, packet_id: u16, _reason_code: u8, _properties: Properties) {
        // Our own outbound QoS 2 publish: broker acked receipt, complete
        // the handshake by releasing it.
        let wire = encode::encode_pubrel(packet_id, reason::SUCCESS, &Properties::new(), self.handler.version);
        self.endpoint.send(&wire);
    }

    fn pubrel(&mut self, packet_id: u16, _reason_code: u8, _properties: Properties) {
        // Broker completing its own QoS 2 publish to us; we already
        // PUBREC'd and told the driver in `end_publish`.
        let wire = encode::encode_pubcomp(packet_id, reason::SUCCESS, &Properties::new(), self.handler.version);
        self.endpoint.send(&wire);
    }

    fn pubcomp(&mut self, packet_id: u16, _reason_code: u8, _properties: Properties) {
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_publish_acked(self, packet_id);
            self.handler.driver = Some(driver);
        }
    }

    fn subscribe(&mut self, _packet_id: u16, _properties: Properties, _filters: Vec<SubscribeFilter>) {
        self.endpoint.close(); // clients don't receive SUBSCRIBE
    }

    fn suback(&mut self, packet_id: u16, _properties: Properties, reason_codes: Vec<u8>) {
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_suback(self, packet_id, &reason_codes);
            self.handler.driver = Some(driver);
        }
    }

    fn unsubscribe(&mut self, _packet_id: u16, _properties: Properties, _topic_filters: Vec<String>) {
        self.endpoint.close(); // clients don't receive UNSUBSCRIBE
    }

    fn unsuback(&mut self, packet_id: u16, _properties: Properties, reason_codes: Vec<u8>) {
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_unsuback(self, packet_id, &reason_codes);
            self.handler.driver = Some(driver);
        }
    }

    fn ping_req(&mut self) {
        self.endpoint.close(); // clients don't receive PINGREQ
    }

    fn ping_resp(&mut self) {
        if let Some(t) = self.handler.pingresp_timer.take() {
            t.cancel();
        }
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_ping_resp(self);
            self.handler.driver = Some(driver);
        }
    }

    fn disconnect(&mut self, reason_code: u8, properties: Properties) {
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_server_disconnect(reason_code, &properties);
            self.handler.driver = Some(driver);
        }
        self.endpoint.close();
    }

    fn auth(&mut self, _reason_code: u8, _properties: Properties) {
        // Enhanced AUTH (MQTT 5.0 §4.12) is future work — see the MQTT plan.
    }

    fn parse_error(&mut self, err: MqttError) {
        let io_err = io::Error::new(io::ErrorKind::InvalidData, err.to_string());
        if let Some(mut driver) = self.handler.driver.take() {
            driver.on_error(&io_err);
            self.handler.driver = Some(driver);
        }
        self.endpoint.close();
    }
}
