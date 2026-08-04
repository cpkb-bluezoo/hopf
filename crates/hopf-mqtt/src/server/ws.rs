// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT-over-WebSocket bridge (feature `websocket`).
//!
//! [`MqttWsHandler`] drives the same [`crate::codec::parser::MqttFrameParser`]
//! and [`crate::server::broker::BrokerState`] as the TCP [`crate::server::MqttControlHandler`]
//! — a WS-connected client and a TCP-connected client can publish and
//! subscribe to each other freely, since both register a real
//! `hopf_core::ConnHandle` with the broker for cross-reactor fan-out.
//!
//! Timers (CONNECT timeout, keepalive, Session Expiry orphan reap, Will
//! Delay, QoS retransmission) are scheduled via
//! [`hopf_core::ConnHandle::schedule_timer`] — the WS event handler holds a
//! framed `ConnHandle` but not a live `Endpoint` borrow.
//!
//! There's also a wire-level caveat inherited from `hopf-websocket`
//! directly: it delivers a `binary_message` only for a single WebSocket
//! frame with `FIN` set (see `crates/hopf-websocket/src/upgrade.rs`) — a
//! client that fragments one WebSocket message across multiple WS frames
//! will have the non-final frames silently dropped. A single MQTT Control
//! Packet spanning multiple WS *frames* is fine either way (the frame
//! parser streams across `binary_message` calls same as it does across TCP
//! reads) — this caveat is specifically about WS-level message
//! fragmentation, which real MQTT-over-WS clients essentially never use.

use std::collections::{HashMap, HashSet};
use std::mem;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{ConnHandle, TimerHandle};
use hopf_http::Headers;
use hopf_websocket::{framed_ws_conn_handle, WsEventHandler, WsEventHandlerFactory, WsFrameError, WsRole, WsSession};

use crate::server::broker::{validate_topic_name, BrokerState, SubscriberId, UNLIMITED_RECEIVE_MAXIMUM};
use crate::server::control::{
    connack_properties, DEFAULT_QOS_RETRY_INTERVAL, PublishTelemetry, SERVER_TOPIC_ALIAS_MAXIMUM,
};
use crate::server::expiry::effective_will_delay;
use crate::server::publish_spool::{publish_whole, PendingPublish};
use crate::codec::packet::{reason, ConnectPacket, PublishHeader, QoS, SubscribeFilter, Will};
use crate::codec::parser::{MqttFrameHandler, MqttFrameParser};
use crate::codec::properties::property;
use crate::codec::{encode, MqttError, Properties, ProtocolVersion};

use crate::server::{
    ConnectDecision, ConnectHandler, MqttConfig, MqttConnectionMetadata, MqttHandlerFactory,
    PublishDecision, PublishHandler, SubscribeDecision, SubscribeHandler,
};
use crate::server::metrics::MqttServerMetrics;
use hopf_otel::{
    ExportHandle, SpanKind, Trace, MqttServerMetrics as OtelMqttMetrics,
};
use std::net::SocketAddr;

struct ConnectedWsSession {
    subscriber_id: SubscriberId,
    client_id: String,
    version: ProtocolVersion,
    will: Option<Will>,
    keep_alive: Duration,
    keepalive_timer: Option<TimerHandle>,
    session_expiry: Duration,
    graceful_disconnect: bool,
    awaiting_pubrel: HashSet<u16>,
    pending_publish: Option<PendingPublish>,
    inbound_aliases: HashMap<u16, String>,
    /// Max alias we accept from the client (advertised in CONNACK).
    server_topic_alias_max: u16,
    /// Max alias the client will accept from us (from CONNECT). Reserved for
    /// outbound Topic Alias assignment.
    #[allow(dead_code)]
    client_topic_alias_max: u16,
    qos_retry_interval: Duration,
    retransmit_timer: Option<TimerHandle>,
}

enum SessionState {
    AwaitingConnect,
    Connected(Box<ConnectedWsSession>),
}

/// `WsEventHandlerFactory` that bridges MQTT onto WebSocket, sharing
/// `config.broker` with any TCP listener built from the same [`MqttConfig`].
pub struct MqttWsFactory {
    config: Arc<MqttConfig>,
    handler_factory: Arc<dyn MqttHandlerFactory>,
    metrics: Arc<MqttServerMetrics>,
    otel_metrics: Option<Arc<OtelMqttMetrics>>,
    export: Option<ExportHandle>,
    traces_enabled: bool,
}

impl MqttWsFactory {
    /// Bridge `config` (and its `broker`) onto WebSocket, authorizing
    /// CONNECT via `handler_factory` (same SPI as the TCP listener —
    /// `server::DefaultMqttHandlerFactory` if you don't need custom policy).
    pub fn new(config: Arc<MqttConfig>, handler_factory: Arc<dyn MqttHandlerFactory>) -> Self {
        Self {
            config,
            handler_factory,
            metrics: MqttServerMetrics::shared(),
            otel_metrics: None,
            export: None,
            traces_enabled: false,
        }
    }

    /// Wire OTLP/JSONL MQTT metrics and traces (same as [`crate::server::MqttService::with_telemetry`]).
    pub fn with_telemetry(mut self, pipeline: &hopf_otel::TelemetryPipeline) -> Self {
        let cfg = pipeline.config();
        if cfg.metrics_enabled {
            self.otel_metrics = Some(pipeline.mqtt_metrics());
        }
        if cfg.traces_enabled {
            self.export = Some(pipeline.export_handle());
            self.traces_enabled = true;
        } else if cfg.metrics_enabled {
            self.export = Some(pipeline.export_handle());
        }
        self
    }
}

impl WsEventHandlerFactory for MqttWsFactory {
    fn create(&self, _path: &str, _request_headers: &Headers, conn: ConnHandle) -> Box<dyn WsEventHandler> {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        parser.set_max_packet_size(self.config.max_packet_size);
        Box::new(MqttWsHandler {
            config: Arc::clone(&self.config),
            parser,
            session: SessionState::AwaitingConnect,
            connect_handler: self.handler_factory.create(),
            publish_handler: self.handler_factory.create_publish(),
            subscribe_handler: self.handler_factory.create_subscribe(),
            // Broker fan-out delivers asynchronously from another connection's
            // reactor via plain `ConnHandle::send` — wrap so those deliveries
            // come out as proper WS binary frames.
            conn: framed_ws_conn_handle(&conn, WsRole::Server),
            connect_timeout_timer: None,
            metrics: Arc::clone(&self.metrics),
            meta: MqttConnectionMetadata {
                peer: SocketAddr::from(([0, 0, 0, 0], 0)),
                local: SocketAddr::from(([0, 0, 0, 0], 0)),
                tls: false,
                client_id: None,
                traceparent: None,
            },
            otel_metrics: self.otel_metrics.clone(),
            export: self.export.clone(),
            traces_enabled: self.traces_enabled,
            conn_trace: None,
            publish_tel: None,
            telemetry_started: false,
        })
    }
}

/// Per-connection MQTT-over-WebSocket handler.
pub struct MqttWsHandler {
    config: Arc<MqttConfig>,
    parser: MqttFrameParser,
    session: SessionState,
    connect_handler: Box<dyn ConnectHandler>,
    publish_handler: Box<dyn PublishHandler>,
    subscribe_handler: Box<dyn SubscribeHandler>,
    conn: ConnHandle,
    connect_timeout_timer: Option<TimerHandle>,
    metrics: Arc<MqttServerMetrics>,
    meta: MqttConnectionMetadata,
    otel_metrics: Option<Arc<OtelMqttMetrics>>,
    export: Option<ExportHandle>,
    traces_enabled: bool,
    conn_trace: Option<Trace>,
    publish_tel: Option<PublishTelemetry>,
    telemetry_started: bool,
}

impl MqttWsHandler {
    fn ensure_connection_telemetry(&mut self) {
        if self.telemetry_started {
            return;
        }
        self.telemetry_started = true;
        MqttServerMetrics::add(&self.metrics.connections, 1);
        if let Some(m) = &self.otel_metrics {
            m.connection_opened();
        }
        if self.traces_enabled {
            if let Some(export) = self.export.clone() {
                let t = Trace::new("MQTT connection", SpanKind::Server);
                t.set_exporter(export);
                self.meta.traceparent = Some(t.traceparent());
                self.conn_trace = Some(t);
            }
        }
    }

    fn end_connection_telemetry(&mut self) {
        if !self.telemetry_started {
            return;
        }
        if let Some(tel) = self.publish_tel.take() {
            tel.finish(false);
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

    fn begin_publish_telemetry(&mut self, qos: QoS, bytes: u64) {
        if self.otel_metrics.is_none() && self.conn_trace.is_none() {
            return;
        }
        let span = if let Some(trace) = &self.conn_trace {
            let s = trace.start_span("MQTT publish", SpanKind::Server);
            self.meta.traceparent = Some(trace.traceparent());
            Some(s)
        } else {
            None
        };
        self.publish_tel = Some(PublishTelemetry::start(
            qos,
            bytes,
            self.otel_metrics.clone(),
            span,
        ));
    }

    fn finish_publish_telemetry(&mut self, ok: bool) {
        if let Some(tel) = self.publish_tel.take() {
            tel.finish(ok);
        }
        if let Some(trace) = &self.conn_trace {
            self.meta.traceparent = Some(trace.traceparent());
        }
        if ok {
            MqttServerMetrics::add(&self.metrics.publishes, 1);
        }
    }

    fn record_auth(&self, ok: bool) {
        if ok {
            MqttServerMetrics::add(&self.metrics.auth_ok, 1);
        } else {
            MqttServerMetrics::add(&self.metrics.auth_fail, 1);
        }
        if let Some(m) = &self.otel_metrics {
            m.auth(ok);
        }
    }

    fn record_subscribe(&self) {
        MqttServerMetrics::add(&self.metrics.subscribes, 1);
        if let Some(m) = &self.otel_metrics {
            m.subscribe();
        }
    }

    fn rearm_keepalive(&mut self) {
        let SessionState::Connected(session) = &mut self.session else {
            return;
        };
        if session.keep_alive.is_zero() {
            return;
        }
        if let Some(old) = session.keepalive_timer.take() {
            old.cancel();
        }
        let handle = self.conn.clone();
        session.keepalive_timer = Some(self.conn.schedule_timer(
            session.keep_alive,
            Box::new(move || handle.close()),
        ));
    }

    fn arm_retransmit_timer(&mut self) {
        let SessionState::Connected(session) = &mut self.session else {
            return;
        };
        if let Some(old) = session.retransmit_timer.take() {
            old.cancel();
        }
        let interval = session.qos_retry_interval;
        if interval.is_zero() {
            return;
        }
        let broker = Arc::clone(&self.config.broker);
        let id = session.subscriber_id;
        let conn = self.conn.clone();
        session.retransmit_timer = Some(schedule_qos_retry(conn, broker, id, interval));
    }

    fn teardown(&mut self) {
        let SessionState::Connected(session) = &self.session else {
            self.end_connection_telemetry();
            return;
        };
        if let Some(timer) = &session.keepalive_timer {
            timer.cancel();
        }
        if let Some(timer) = &session.retransmit_timer {
            timer.cancel();
        }
        if !session.graceful_disconnect {
            if let Some(will) = session.will.clone() {
                let delay = effective_will_delay(&will.properties, session.session_expiry);
                if delay.is_zero() {
                    publish_whole(
                        &self.config.broker,
                        Some(session.subscriber_id),
                        &will.topic,
                        &will.payload,
                        will.qos,
                        will.retain,
                        &will.properties,
                    );
                } else {
                    let epoch = self.config.broker.park_delayed_will(&session.client_id, will);
                    let broker = Arc::clone(&self.config.broker);
                    let client_id = session.client_id.clone();
                    self.conn.schedule_timer(
                        delay,
                        Box::new(move || broker.fire_delayed_will(&client_id, epoch)),
                    );
                }
            }
        } else {
            self.config.broker.cancel_delayed_will(&session.client_id);
        }
        if session.session_expiry.is_zero() {
            self.config.broker.unregister(session.subscriber_id);
        } else {
            let epoch = self.config.broker.orphan(session.subscriber_id);
            let broker = Arc::clone(&self.config.broker);
            let id = session.subscriber_id;
            self.conn.schedule_timer(
                session.session_expiry,
                Box::new(move || broker.expire_orphan(id, epoch)),
            );
        }
        self.session = SessionState::AwaitingConnect;
        self.end_connection_telemetry();
    }
}

fn schedule_qos_retry(
    conn: ConnHandle,
    broker: Arc<BrokerState>,
    id: SubscriberId,
    interval: Duration,
) -> TimerHandle {
    let conn2 = conn.clone();
    let broker2 = Arc::clone(&broker);
    conn.schedule_timer(
        interval,
        Box::new(move || {
            if !broker2.is_connected(id) {
                return;
            }
            broker2.retransmit_due(id, interval);
            let _ = schedule_qos_retry(conn2, broker2, id, interval);
        }),
    )
}

impl WsEventHandler for MqttWsHandler {
    fn opened(&mut self, _session: &mut WsSession<'_>, _conn: &ConnHandle) {
        self.ensure_connection_telemetry();
        let handle = self.conn.clone();
        self.connect_timeout_timer = Some(self.conn.schedule_timer(
            self.config.connect_timeout,
            Box::new(move || handle.close()),
        ));
    }

    fn binary_message(&mut self, session: &mut WsSession<'_>, data: &[u8]) {
        let mut parser = mem::replace(&mut self.parser, MqttFrameParser::new(ProtocolVersion::V311));
        let mut ctx = WsCtx { handler: self, session };
        parser.push(data, &mut ctx);
        self.parser = parser;
        self.rearm_keepalive();
    }

    fn closed(&mut self, _session: &mut WsSession<'_>, _code: u16, _reason: &str) {
        if let Some(t) = self.connect_timeout_timer.take() {
            t.cancel();
        }
        self.teardown();
    }

    fn error(&mut self, _err: WsFrameError) {
        if let Some(t) = self.connect_timeout_timer.take() {
            t.cancel();
        }
        self.teardown();
    }
}

/// Ephemeral adapter binding an in-progress `binary_message` call's
/// `WsSession` to the connection's persistent handler state — same pattern
/// as the TCP `MqttControlHandler`'s `Ctx`, with `WsSession::send_binary`
/// standing in for `Endpoint::send`.
struct WsCtx<'h, 's, 'o> {
    handler: &'h mut MqttWsHandler,
    session: &'s mut WsSession<'o>,
}

impl WsCtx<'_, '_, '_> {
    fn broker(&self) -> &Arc<BrokerState> {
        &self.handler.config.broker
    }

    fn connack_and_close(&mut self, version: ProtocolVersion, reason_code: u8) {
        let wire = encode::encode_connack(false, reason_code, &Properties::new(), version);
        self.session.send_binary(&wire);
        self.session.send_close(1002, "mqtt CONNECT refused");
    }

    fn disconnect_and_close(&mut self, reason_code: u8) {
        if let SessionState::Connected(session) = &self.handler.session {
            if session.version.is_v5() {
                let wire = encode::encode_disconnect(reason_code, &Properties::new(), session.version);
                self.session.send_binary(&wire);
            }
        }
        self.session.send_close(1002, "mqtt protocol error");
    }
}

impl MqttFrameHandler for WsCtx<'_, '_, '_> {
    fn connect(&mut self, packet: ConnectPacket) {
        if let Some(timer) = self.handler.connect_timeout_timer.take() {
            timer.cancel();
        }
        if matches!(self.handler.session, SessionState::Connected(_)) {
            self.disconnect_and_close(reason::PROTOCOL_ERROR);
            return;
        }

        let version = packet.version;
        let fail_code = |v311: u8, v5: u8| if version.is_v5() { v5 } else { v311 };

        let client_id = if packet.client_id.is_empty() {
            if !packet.clean_session {
                self.connack_and_close(
                    version,
                    fail_code(reason::connack_v311::IDENTIFIER_REJECTED, reason::CLIENT_IDENTIFIER_NOT_VALID),
                );
                return;
            }
            format!("hopf-mqtt-ws-{}", uuid_ish())
        } else {
            packet.client_id.clone()
        };

        if let ConnectDecision::Reject(reason_code) =
            self.handler.connect_handler.authorize(&packet, &self.handler.meta)
        {
            self.handler.record_auth(false);
            self.connack_and_close(version, reason_code);
            return;
        }
        self.handler.record_auth(true);
        self.handler.meta.client_id = Some(client_id.clone());

        let keep_alive = if packet.keep_alive == 0 {
            Duration::ZERO
        } else {
            Duration::from_millis(packet.keep_alive as u64 * 1500)
        };

        let receive_maximum = if version.is_v5() {
            packet.properties.get_u16(property::RECEIVE_MAXIMUM).unwrap_or(UNLIMITED_RECEIVE_MAXIMUM).max(1)
        } else {
            UNLIMITED_RECEIVE_MAXIMUM
        };
        let session_expiry_secs = if version.is_v5() {
            packet.properties.get_u32(property::SESSION_EXPIRY_INTERVAL).unwrap_or(0)
        } else {
            0
        };
        let session_expiry = Duration::from_secs(session_expiry_secs as u64);

        let client_topic_alias_max = if version.is_v5() {
            packet.properties.get_u16(property::TOPIC_ALIAS_MAXIMUM).unwrap_or(0)
        } else {
            0
        };
        let server_topic_alias_max = if version.is_v5() {
            SERVER_TOPIC_ALIAS_MAXIMUM
        } else {
            0
        };

        let (subscriber_id, evicted, session_present) = self.broker().register(
            &client_id,
            version,
            receive_maximum,
            packet.clean_session,
            self.handler.conn.clone(),
            true,
        );
        if let Some(evicted) = evicted {
            evicted.close();
        }

        self.handler.session = SessionState::Connected(Box::new(ConnectedWsSession {
            subscriber_id,
            client_id,
            version,
            will: packet.will,
            keep_alive,
            keepalive_timer: None,
            session_expiry,
            graceful_disconnect: false,
            awaiting_pubrel: HashSet::new(),
            pending_publish: None,
            inbound_aliases: HashMap::new(),
            server_topic_alias_max,
            client_topic_alias_max,
            qos_retry_interval: DEFAULT_QOS_RETRY_INTERVAL,
            retransmit_timer: None,
        }));
        self.handler.parser.set_version(version);

        if session_present {
            self.broker().drain_offline(subscriber_id);
        }
        self.handler.arm_retransmit_timer();

        let connack_props = connack_properties(
            version,
            receive_maximum,
            session_expiry_secs,
            server_topic_alias_max,
        );
        let wire = encode::encode_connack(session_present, 0, &connack_props, version);
        self.session.send_binary(&wire);
    }

    fn connack(&mut self, _session_present: bool, _reason_code: u8, _properties: Properties) {
        self.disconnect_and_close(reason::PROTOCOL_ERROR);
    }

    fn start_publish(&mut self, mut header: PublishHeader) {
        let SessionState::Connected(session) = &mut self.handler.session else {
            self.disconnect_and_close(reason::PROTOCOL_ERROR);
            return;
        };
        if session.version.is_v5() {
            if let Some(alias) = header.properties.get_u16(property::TOPIC_ALIAS) {
                if alias == 0 || alias > session.server_topic_alias_max {
                    self.disconnect_and_close(reason::TOPIC_ALIAS_INVALID);
                    return;
                }
                if header.topic.is_empty() {
                    let Some(mapped) = session.inbound_aliases.get(&alias).cloned() else {
                        self.disconnect_and_close(reason::PROTOCOL_ERROR);
                        return;
                    };
                    header.topic = mapped;
                } else {
                    session.inbound_aliases.insert(alias, header.topic.clone());
                }
            } else if header.topic.is_empty() {
                self.disconnect_and_close(reason::TOPIC_NAME_INVALID);
                return;
            }
        }
        if validate_topic_name(&header.topic).is_err() {
            self.disconnect_and_close(reason::TOPIC_NAME_INVALID);
            return;
        }
        if header.payload_len > self.handler.config.max_publish_payload {
            self.disconnect_and_close(reason::PACKET_TOO_LARGE);
            return;
        }
        let SessionState::Connected(session) = &mut self.handler.session else {
            self.disconnect_and_close(reason::PROTOCOL_ERROR);
            return;
        };
        if header.qos == QoS::ExactlyOnce && session.awaiting_pubrel.contains(&header.packet_id) {
            session.pending_publish = None;
            let version = session.version;
            let wire = encode::encode_pubrec(header.packet_id, reason::SUCCESS, &Properties::new(), version);
            self.session.send_binary(&wire);
            return;
        }

        let client_id = session.client_id.clone();
        let qos = header.qos;
        let retain = header.retain;
        let topic = header.topic.clone();
        match self.handler.publish_handler.authorize(
            &client_id,
            &topic,
            qos,
            retain,
            &self.handler.meta,
        ) {
            PublishDecision::Accept => {}
            PublishDecision::Reject(code) => {
                if session.version.is_v5() {
                    match qos {
                        QoS::AtMostOnce => self.disconnect_and_close(code),
                        QoS::AtLeastOnce => {
                            let wire = encode::encode_puback(
                                header.packet_id, code, &Properties::new(), session.version,
                            );
                            self.session.send_binary(&wire);
                        }
                        QoS::ExactlyOnce => {
                            let wire = encode::encode_pubrec(
                                header.packet_id, code, &Properties::new(), session.version,
                            );
                            self.session.send_binary(&wire);
                        }
                    }
                } else {
                    self.disconnect_and_close(reason::PROTOCOL_ERROR);
                }
                return;
            }
        }

        let SessionState::Connected(session) = &mut self.handler.session else {
            return;
        };
        let subscriber_id = session.subscriber_id;
        let qos = header.qos;
        let bytes = header.payload_len as u64;
        let pending = PendingPublish::begin(self.broker(), subscriber_id, header);
        let SessionState::Connected(session) = &mut self.handler.session else {
            return;
        };
        session.pending_publish = Some(pending);
        self.handler.begin_publish_telemetry(qos, bytes);
    }

    fn publish_data(&mut self, data: &[u8]) {
        let SessionState::Connected(session) = &mut self.handler.session else {
            return;
        };
        let Some(pending) = &mut session.pending_publish else {
            return;
        };
        pending.feed(data);
    }

    fn end_publish(&mut self) {
        let SessionState::Connected(session) = &mut self.handler.session else {
            return;
        };
        let Some(pending) = session.pending_publish.take() else {
            return;
        };
        let version = session.version;
        let (qos, packet_id) = (pending.header.qos, pending.header.packet_id);
        pending.finish(self.broker());
        self.handler.finish_publish_telemetry(true);

        let SessionState::Connected(session) = &mut self.handler.session else {
            return;
        };
        match qos {
            QoS::AtMostOnce => {}
            QoS::AtLeastOnce => {
                let wire = encode::encode_puback(packet_id, reason::SUCCESS, &Properties::new(), version);
                self.session.send_binary(&wire);
            }
            QoS::ExactlyOnce => {
                session.awaiting_pubrel.insert(packet_id);
                let wire = encode::encode_pubrec(packet_id, reason::SUCCESS, &Properties::new(), version);
                self.session.send_binary(&wire);
            }
        }
    }

    fn puback(&mut self, packet_id: u16, _reason_code: u8, _properties: Properties) {
        if let SessionState::Connected(session) = &self.handler.session {
            self.broker().ack_delivered(session.subscriber_id);
            self.broker().store.ack_inflight(session.subscriber_id, packet_id);
        }
    }

    fn pubrec(&mut self, _packet_id: u16, _reason_code: u8, _properties: Properties) {}

    fn pubrel(&mut self, packet_id: u16, _reason_code: u8, _properties: Properties) {
        let SessionState::Connected(session) = &mut self.handler.session else {
            return;
        };
        session.awaiting_pubrel.remove(&packet_id);
        let wire = encode::encode_pubcomp(packet_id, reason::SUCCESS, &Properties::new(), session.version);
        self.session.send_binary(&wire);
    }

    fn pubcomp(&mut self, packet_id: u16, _reason_code: u8, _properties: Properties) {
        if let SessionState::Connected(session) = &self.handler.session {
            self.broker().ack_delivered(session.subscriber_id);
            self.broker().store.ack_inflight(session.subscriber_id, packet_id);
        }
    }

    fn subscribe(&mut self, packet_id: u16, _properties: Properties, filters: Vec<SubscribeFilter>) {
        let SessionState::Connected(session) = &self.handler.session else {
            self.disconnect_and_close(reason::PROTOCOL_ERROR);
            return;
        };
        let (subscriber_id, version, client_id) = (
            session.subscriber_id,
            session.version,
            session.client_id.clone(),
        );

        let mut reason_codes = Vec::with_capacity(filters.len());
        for filter in &filters {
            match self.handler.subscribe_handler.authorize(
                &client_id,
                filter,
                &self.handler.meta,
            ) {
                SubscribeDecision::Reject(code) => {
                    reason_codes.push(code);
                    continue;
                }
                SubscribeDecision::Accept(granted_qos) => {
                    let mut filter = filter.clone();
                    filter.max_qos = granted_qos;
                    match self.broker().subscribe(subscriber_id, &filter) {
                        Ok(is_new) => {
                            reason_codes.push(granted_qos.value());
                            let send_retained = match filter.retain_handling {
                                0 => true,
                                1 => is_new,
                                _ => false,
                            };
                            if send_retained {
                                for (topic, msg) in self.broker().retained_matching(&filter.topic_filter) {
                                    self.broker().deliver_retained(
                                        subscriber_id, &topic, &msg, granted_qos,
                                    );
                                }
                            }
                        }
                        Err(_) => reason_codes.push(reason::TOPIC_FILTER_INVALID),
                    }
                }
            }
        }
        let wire = encode::encode_suback(packet_id, &reason_codes, &Properties::new(), version);
        self.session.send_binary(&wire);
        self.handler.record_subscribe();
    }

    fn suback(&mut self, _packet_id: u16, _properties: Properties, _reason_codes: Vec<u8>) {
        self.disconnect_and_close(reason::PROTOCOL_ERROR);
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
            reason_codes.push(if existed { reason::SUCCESS } else { reason::NO_SUBSCRIPTION_EXISTED });
        }
        let wire = encode::encode_unsuback(packet_id, &reason_codes, &Properties::new(), version);
        self.session.send_binary(&wire);
    }

    fn unsuback(&mut self, _packet_id: u16, _properties: Properties, _reason_codes: Vec<u8>) {
        self.disconnect_and_close(reason::PROTOCOL_ERROR);
    }

    fn ping_req(&mut self) {
        self.session.send_binary(&encode::encode_pingresp());
    }

    fn ping_resp(&mut self) {
        self.disconnect_and_close(reason::PROTOCOL_ERROR);
    }

    fn disconnect(&mut self, _reason_code: u8, _properties: Properties) {
        if let SessionState::Connected(session) = &mut self.handler.session {
            session.graceful_disconnect = true;
        }
        self.session.send_close(1000, "");
    }

    fn auth(&mut self, _reason_code: u8, _properties: Properties) {
        // Enhanced AUTH over WS uses the same server::auth path as TCP once
        // Endpoint access is available; WS currently rejects mid-session AUTH.
        self.disconnect_and_close(reason::PROTOCOL_ERROR);
    }

    fn parse_error(&mut self, _err: MqttError) {
        self.disconnect_and_close(reason::MALFORMED_PACKET);
    }
}

/// Cheap process-unique suffix for an assigned client id — avoids pulling
/// in a UUID dependency for what's just a disambiguator.
fn uuid_ish() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
}
