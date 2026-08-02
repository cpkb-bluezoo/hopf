// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `MqttControlHandler` — the per-connection `ProtocolHandler` driving the
//! MQTT wire protocol against shared [`BrokerState`].

use std::collections::HashSet;
use std::mem;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{Endpoint, ProtocolHandler, TimerHandle};
use hopf_otel::{
    ExportHandle, RequestTimer, Span, SpanKind, Trace, MqttServerMetrics as OtelMqttMetrics,
};

use crate::server::broker::{validate_topic_name, BrokerState, SubscriberId, UNLIMITED_RECEIVE_MAXIMUM};
use crate::server::publish_spool::{publish_whole, PendingPublish};
use crate::codec::packet::{reason, ConnectPacket, PublishHeader, QoS, SubscribeFilter, Will};
use crate::codec::parser::{MqttFrameHandler, MqttFrameParser};
use crate::codec::properties::property;
use crate::codec::{encode, MqttError, Properties, ProtocolVersion};

use super::config::MqttConfig;
use super::handler::{ConnectDecision, ConnectHandler, MqttConnectionMetadata};
use super::metrics::MqttServerMetrics;

/// OTel timing/span for one client PUBLISH.
pub(crate) struct PublishTelemetry {
    timer: RequestTimer,
    span: Option<Span>,
    otel: Option<Arc<OtelMqttMetrics>>,
    qos: &'static str,
    bytes: u64,
}

impl PublishTelemetry {
    pub(crate) fn start(
        qos: QoS,
        bytes: u64,
        otel: Option<Arc<OtelMqttMetrics>>,
        span: Option<Span>,
    ) -> Self {
        let qos = match qos {
            QoS::AtMostOnce => "0",
            QoS::AtLeastOnce => "1",
            QoS::ExactlyOnce => "2",
        };
        Self {
            timer: RequestTimer::start(),
            span,
            otel,
            qos,
            bytes,
        }
    }

    pub(crate) fn finish(self, ok: bool) {
        let outcome = if ok { "ok" } else { "fail" };
        if let Some(span) = self.span {
            span.set_attribute("mqtt.publish.qos", self.qos);
            span.set_attribute("outcome", outcome);
            if ok {
                span.set_status_ok();
            } else {
                span.set_status_error(outcome);
            }
            span.end();
        }
        if let Some(m) = &self.otel {
            m.publish_completed(self.qos, outcome, self.timer.elapsed(), self.bytes);
        }
    }
}

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
    /// One in-progress PUBLISH from the client — see [`PendingPublish`].
    pending_publish: Option<PendingPublish>,
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
    metrics: Arc<MqttServerMetrics>,
    meta: MqttConnectionMetadata,
    otel_metrics: Option<Arc<OtelMqttMetrics>>,
    export: Option<ExportHandle>,
    traces_enabled: bool,
    conn_trace: Option<Trace>,
    publish_tel: Option<PublishTelemetry>,
}

impl MqttControlHandler {
    /// New handler bound to `config` (shared across every connection this
    /// listener accepts) and a freshly-created [`ConnectHandler`] (one per
    /// connection, from [`super::handler::MqttHandlerFactory::create`]).
    pub fn new(
        config: Arc<MqttConfig>,
        connect_handler: Box<dyn ConnectHandler>,
        metrics: Arc<MqttServerMetrics>,
    ) -> Self {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        parser.set_max_packet_size(config.max_packet_size);
        Self {
            config,
            parser,
            session: SessionState::AwaitingConnect,
            connect_timeout_timer: None,
            connect_handler,
            metrics,
            meta: MqttConnectionMetadata {
                peer: SocketAddr::from(([0, 0, 0, 0], 0)),
                local: SocketAddr::from(([0, 0, 0, 0], 0)),
                tls: false,
                client_id: None,
                traceparent: None,
            },
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            conn_trace: None,
            publish_tel: None,
        }
    }

    /// Attach OTel metrics / traces from a telemetry pipeline.
    pub fn with_telemetry(
        mut self,
        otel_metrics: Option<Arc<OtelMqttMetrics>>,
        export: Option<ExportHandle>,
        traces_enabled: bool,
    ) -> Self {
        self.otel_metrics = otel_metrics;
        self.export = export;
        self.traces_enabled = traces_enabled;
        self
    }

    fn begin_connection_telemetry(&mut self) {
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
}

impl ProtocolHandler for MqttControlHandler {
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
        self.begin_connection_telemetry();
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
                    publish_whole(
                        &self.config.broker,
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
        self.end_connection_telemetry();
    }

    fn security_established(
        &mut self,
        _endpoint: &mut dyn Endpoint,
        _info: &hopf_core::SecurityInfo,
    ) {
        self.meta.tls = true;
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
            false,
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
        if header.payload_len > self.handler.config.max_publish_payload {
            self.disconnect_and_close(reason::PACKET_TOO_LARGE);
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

        // Fan out to QoS-0 recipients now — their PUBLISH headers go out
        // immediately, payload chunks follow live via `publish_data`.
        // QoS-1/2 recipients (and retain) are resolved in `end_publish`
        // once the whole payload is known, from a spooled copy.
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
            // Duplicate QoS 2 resend — `start_publish` already re-acked it.
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
                self.endpoint.send(&wire);
            }
            QoS::ExactlyOnce => {
                session.awaiting_pubrel.insert(packet_id);
                let wire = encode::encode_pubrec(packet_id, reason::SUCCESS, &Properties::new(), version);
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
        self.handler.record_subscribe();
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

#[cfg(test)]
mod telemetry_tests {
    use super::*;
    use crate::server::handler::DefaultMqttHandlerFactory;
    use crate::server::handler::MqttHandlerFactory;
    use hopf_otel::{OtelConfig, SpanContext, TelemetryPipeline};

    #[test]
    fn with_telemetry_sets_parseable_traceparent_on_connect() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-mqtt-tp-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let cfg = OtelConfig::new("mqtt-tp-test")
            .with_jsonl_traces(&dir)
            .with_jsonl_metrics(&dir);
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        let config = Arc::new(MqttConfig::new(
            "127.0.0.1:1883".parse().unwrap(),
            Arc::new(BrokerState::new()),
        ));
        let mut h = MqttControlHandler::new(
            config,
            DefaultMqttHandlerFactory::new(None).create(),
            MqttServerMetrics::shared(),
        )
        .with_telemetry(
            Some(pipeline.mqtt_metrics()),
            Some(pipeline.export_handle()),
            true,
        );
        h.begin_connection_telemetry();
        let tp = h.meta.traceparent.clone().expect("traceparent set");
        let ctx = SpanContext::from_traceparent(&tp).expect("valid traceparent");
        assert!(!ctx.trace_id.iter().all(|&b| b == 0));

        h.begin_publish_telemetry(QoS::AtMostOnce, 8);
        let pub_tp = h.meta.traceparent.clone().expect("publish traceparent");
        let pub_ctx = SpanContext::from_traceparent(&pub_tp).unwrap();
        assert_eq!(pub_ctx.trace_id, ctx.trace_id);
        assert_ne!(pub_ctx.span_id, ctx.span_id);
        h.finish_publish_telemetry(true);

        h.end_connection_telemetry();
        assert!(h.meta.traceparent.is_none());
        pipeline.shutdown();
        let _ = std::fs::remove_file(&dir);
    }
}
