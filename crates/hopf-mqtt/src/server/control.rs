// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `MqttControlHandler` — the per-connection `ProtocolHandler` driving the
//! MQTT wire protocol against shared [`BrokerState`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::mem;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_auth::{SaslServer, SaslServerStep};
use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, TimerHandle};
use hopf_otel::{
    ExportHandle, RequestTimer, Span, SpanKind, Trace, MqttServerMetrics as OtelMqttMetrics,
};

use crate::server::broker::{validate_topic_name, BrokerState, SubscriberId, UNLIMITED_RECEIVE_MAXIMUM};
use crate::server::expiry::effective_will_delay;
use crate::server::publish_spool::{publish_whole, PendingPublish};
use crate::codec::packet::{reason, ConnectPacket, PublishHeader, QoS, SubscribeFilter, Will};
use crate::codec::parser::{MqttFrameHandler, MqttFrameParser};
use crate::codec::properties::property;
use crate::codec::{encode, MqttError, Properties, ProtocolVersion};

use super::config::MqttConfig;
use super::handler::{
    ConnectDecision, ConnectHandler, MqttConnectionMetadata, PublishDecision,
    PublishHandler, SubscribeDecision, SubscribeHandler,
};
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

/// Default Topic Alias Maximum advertised in CONNACK (MQTT 5.0 §3.2.2.3.8).
pub(crate) const SERVER_TOPIC_ALIAS_MAXIMUM: u16 = 16;

/// Default interval between outbound QoS 1/2 retransmission checks.
pub(crate) const DEFAULT_QOS_RETRY_INTERVAL: Duration = Duration::from_secs(5);

struct ConnectedSession {
    subscriber_id: SubscriberId,
    client_id: String,
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
    /// Client→server Topic Alias map (MQTT 5.0 §3.3.2.3.4).
    inbound_aliases: HashMap<u16, String>,
    /// Max alias we accept from the client (advertised in CONNACK).
    server_topic_alias_max: u16,
    /// Max alias the client will accept from us (from CONNECT). Reserved for
    /// outbound Topic Alias assignment.
    #[allow(dead_code)]
    client_topic_alias_max: u16,
    /// How often to check for due QoS 1/2 retransmits.
    qos_retry_interval: Duration,
    /// Periodic retransmission timer handle (cancelled on disconnect).
    retransmit_timer: Option<TimerHandle>,
}

enum SessionState {
    AwaitingConnect,
    Connected(Box<ConnectedSession>),
}

/// Result of a SASL step offloaded to the storage pool (issue #181) —
/// `SaslServer::step` can block for LDAP/PAM-backed stores, so it runs off
/// the reactor thread; the outcome lands here for `sync_pending_auth_check`
/// to apply once back on the reactor (the storage callback only has
/// `&mut dyn Endpoint`, never `&mut Self`). Carries everything the
/// synchronous `step_and_reply` call site used to close over, since which
/// of the (CONNECT-initial / continuation / re-AUTH) branches to resume
/// can no longer be inferred from the call stack once the step is async.
pub(crate) struct AuthStepOutcome {
    pub(crate) result: Result<(Box<dyn SaslServer>, SaslServerStep), String>,
    pub(crate) method: String,
    pub(crate) version: ProtocolVersion,
    pub(crate) for_connect: bool,
    pub(crate) pending_connect: Option<crate::server::auth::PendingConnectAuth>,
}

/// Result of an offloaded plain-CONNECT `ConnectHandler::authorize` call
/// (issue #210 — the shipped `DefaultConnectHandler`, and any
/// application-supplied one, may block for an LDAP/PAM-backed
/// `CredentialStore`). `connect_handler` travels back with the outcome:
/// it moved into the storage-pool closure to make the call, and
/// `sync_pending_authorize` restores it — `authorize()` runs at most once
/// per connection (a rejected/errored CONNECT always closes the
/// connection), so there's never a second call waiting on it.
pub(crate) struct PendingAuthorizeOutcome {
    pub(crate) result: Result<(Box<dyn ConnectHandler>, ConnectDecision), String>,
    pub(crate) pending_connect: crate::server::auth::PendingConnectAuth,
}

/// Server-side `ProtocolHandler` for one MQTT TCP connection.
pub struct MqttControlHandler {
    pub(crate) config: Arc<MqttConfig>,
    parser: MqttFrameParser,
    session: SessionState,
    connect_timeout_timer: Option<TimerHandle>,
    /// `None` only while offloaded to the storage pool for an in-flight
    /// `authorize()` call (issue #210), or after one has run — `authorize`
    /// is called at most once per connection, so it's never needed back.
    connect_handler: Option<Box<dyn ConnectHandler>>,
    publish_handler: Box<dyn PublishHandler>,
    subscribe_handler: Box<dyn SubscribeHandler>,
    pub(crate) pending_auth: Option<crate::server::auth::PendingAuth>,
    metrics: Arc<MqttServerMetrics>,
    meta: MqttConnectionMetadata,
    otel_metrics: Option<Arc<OtelMqttMetrics>>,
    export: Option<ExportHandle>,
    traces_enabled: bool,
    conn_trace: Option<Trace>,
    publish_tel: Option<PublishTelemetry>,
    pub(crate) runtime: Arc<Runtime>,
    pub(crate) control_handle: Option<ConnHandle>,
    /// True while a SASL step (enhanced AUTH) is offloaded to the storage
    /// pool (issue #181) — `connect()`'s existing second-CONNECT guard also
    /// rejects while this is set, since a pipelined second CONNECT would
    /// otherwise race the in-flight check (session state alone doesn't
    /// protect against that: it only transitions to `Connected` once the
    /// check resolves).
    pub(crate) busy: Arc<AtomicBool>,
    pub(crate) pending_auth_check: Arc<Mutex<Option<AuthStepOutcome>>>,
    /// See [`PendingAuthorizeOutcome`] (issue #210) — same busy-gate
    /// (`busy` above) as the enhanced-AUTH SASL step offload, since only
    /// one of the two ever runs for a given CONNECT.
    pub(crate) pending_authorize: Arc<Mutex<Option<PendingAuthorizeOutcome>>>,
    /// See [`PendingConnackOutcome`] (issue #216) — no busy-gate needed:
    /// by the time this is set, `session` is already `Connected`, which
    /// `connect()`'s existing guard rejects a second CONNECT against
    /// regardless.
    pub(crate) pending_connack: Arc<Mutex<Option<PendingConnackOutcome>>>,
    /// PUBLISHes whose `end_publish` ran before their spool write finished
    /// draining (issue #187) — `sync_pending_publish_finish` completes
    /// each once ready, triggered by the last chunk's `poke_handler` call
    /// (see `publish_spool::drain_next_publish_chunk`). A queue, not a
    /// single slot: MQTT lets a client pipeline multiple in-flight QoS-1/2
    /// PUBLISHes without waiting for each PUBACK, so more than one publish
    /// can legitimately be mid-drain at once.
    pending_publish_finishes: Arc<Mutex<VecDeque<PendingPublishFinish>>>,
}

/// A [`PendingPublish`] whose `end_publish` ran while its spool write was
/// still draining — see `MqttControlHandler::pending_publish_finishes`.
/// Owns `telemetry` itself (rather than leaving it in a single
/// `MqttControlHandler::publish_tel` slot) so two overlapping publishes'
/// telemetry can't clobber each other.
struct PendingPublishFinish {
    pending: PendingPublish,
    version: ProtocolVersion,
    telemetry: Option<PublishTelemetry>,
}

impl MqttControlHandler {
    /// New handler bound to `config` (shared across every connection this
    /// listener accepts) and a freshly-created [`ConnectHandler`] (one per
    /// connection, from [`super::handler::MqttHandlerFactory::create`]).
    pub fn new(
        config: Arc<MqttConfig>,
        connect_handler: Box<dyn ConnectHandler>,
        publish_handler: Box<dyn PublishHandler>,
        subscribe_handler: Box<dyn SubscribeHandler>,
        metrics: Arc<MqttServerMetrics>,
        runtime: Arc<Runtime>,
    ) -> Self {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        parser.set_max_packet_size(config.max_packet_size);
        Self {
            config,
            parser,
            session: SessionState::AwaitingConnect,
            connect_timeout_timer: None,
            connect_handler: Some(connect_handler),
            publish_handler,
            subscribe_handler,
            pending_auth: None,
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
            runtime,
            control_handle: None,
            busy: Arc::new(AtomicBool::new(false)),
            pending_auth_check: Arc::new(Mutex::new(None)),
            pending_authorize: Arc::new(Mutex::new(None)),
            pending_connack: Arc::new(Mutex::new(None)),
            pending_publish_finishes: Arc::new(Mutex::new(VecDeque::new())),
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


    /// Negotiated protocol version for the live session, if connected.
    pub(crate) fn session_version(&self) -> Option<ProtocolVersion> {
        match &self.session {
            SessionState::Connected(s) => Some(s.version),
            SessionState::AwaitingConnect => None,
        }
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
        // Any publish still deferred, waiting on `pending_publish_finishes`
        // (issue #187), never gets a chance for `sync_pending_publish_finish`
        // to finish its telemetry — the connection's gone. Finish each as
        // failed here instead of silently dropping it.
        for pending in self.pending_publish_finishes.lock().unwrap().drain(..) {
            if let Some(tel) = pending.telemetry {
                tel.finish(false);
            }
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

    /// Finish and record `tel` (typically `self.publish_tel.take()` for a
    /// publish that resolved inline, or a [`PendingPublishFinish`]'s own
    /// owned telemetry for one that was deferred — issue #187's deferred-
    /// finish path takes ownership of the telemetry at `end_publish` time
    /// instead of leaving it in the single `publish_tel` slot, so two
    /// overlapping publishes' telemetry can't clobber each other).
    fn finish_publish_telemetry_for(&mut self, tel: Option<PublishTelemetry>, ok: bool) {
        if let Some(tel) = tel {
            tel.finish(ok);
        }
        if let Some(trace) = &self.conn_trace {
            self.meta.traceparent = Some(trace.traceparent());
        }
        if ok {
            MqttServerMetrics::add(&self.metrics.publishes, 1);
        }
    }

    pub(crate) fn record_auth(&self, ok: bool) {
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
        if let Some(peer) = endpoint.remote_addr().ok().and_then(|a| a.as_socket_addr()) {
            self.meta.peer = peer;
        }
        if let Some(local) = endpoint.local_addr().ok().and_then(|a| a.as_socket_addr()) {
            self.meta.local = local;
        }
        if endpoint.is_secure() {
            self.meta.tls = true;
        }
        self.begin_connection_telemetry();
        let handle = endpoint.handle();
        self.control_handle = Some(handle.clone());
        self.connect_timeout_timer = Some(endpoint.schedule_timer(
            self.config.connect_timeout,
            Box::new(move || handle.close()),
        ));
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        crate::server::auth::sync_pending_auth_check(self, endpoint);
        sync_pending_authorize(self, endpoint);
        sync_pending_connack(self, endpoint);
        sync_pending_publish_finish(self, endpoint);
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
                            Arc::clone(&self.runtime),
                            endpoint.handle(),
                        );
                    } else {
                        let epoch = self.config.broker.park_delayed_will(&session.client_id, will);
                        let broker = Arc::clone(&self.config.broker);
                        let client_id = session.client_id.clone();
                        let runtime = Arc::clone(&self.runtime);
                        let handle = endpoint.handle();
                        endpoint.schedule_timer(
                            delay,
                            Box::new(move || broker.fire_delayed_will(&broker, &client_id, epoch, runtime, handle)),
                        );
                    }
                }
            } else {
                self.config.broker.cancel_delayed_will(&session.client_id);
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
                let runtime = Arc::clone(&self.runtime);
                let handle = endpoint.handle();
                endpoint.schedule_timer(
                    session.session_expiry,
                    Box::new(move || broker.expire_orphan(&broker, id, epoch, runtime, handle)),
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

/// Schedule the first QoS retransmission check; the callback re-arms itself
/// via [`ConnHandle::schedule_timer`] while the session stays connected.
fn arm_retransmit_timer(handler: &mut MqttControlHandler, endpoint: &mut dyn Endpoint) {
    let SessionState::Connected(session) = &mut handler.session else {
        return;
    };
    if let Some(old) = session.retransmit_timer.take() {
        old.cancel();
    }
    let interval = session.qos_retry_interval;
    if interval.is_zero() {
        return;
    }
    let broker = Arc::clone(&handler.config.broker);
    let id = session.subscriber_id;
    let conn = endpoint.handle();
    session.retransmit_timer = Some(schedule_qos_retry(conn, broker, id, interval));
}

fn schedule_qos_retry(
    conn: hopf_core::ConnHandle,
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
            // Re-arm; the previous TimerHandle is no longer stored — disconnect
            // cancels only the handle held on the session (first tick). Further
            // ticks stop when `is_connected` is false.
            let _ = schedule_qos_retry(conn2, broker2, id, interval);
        }),
    )
}

/// Build CONNACK properties shared by TCP CONNECT and post-AUTH completion.
pub(crate) fn connack_properties(
    version: ProtocolVersion,
    receive_maximum: u16,
    session_expiry_secs: u32,
    server_topic_alias_max: u16,
) -> Properties {
    let mut connack_props = Properties::new();
    if version.is_v5() {
        if receive_maximum != UNLIMITED_RECEIVE_MAXIMUM {
            connack_props.set_u16(property::RECEIVE_MAXIMUM, receive_maximum);
        }
        if session_expiry_secs != 0 {
            connack_props.set_u32(property::SESSION_EXPIRY_INTERVAL, session_expiry_secs);
        }
        if server_topic_alias_max > 0 {
            connack_props.set_u16(property::TOPIC_ALIAS_MAXIMUM, server_topic_alias_max);
        }
        connack_props.set_byte(property::SHARED_SUBSCRIPTION_AVAILABLE, 1);
    }
    connack_props
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

    /// Run a [`PendingPublish`]'s `finish` (already known ready) and send
    /// the resulting PUBACK/PUBREC. Shared by `end_publish`'s fast path and
    /// `sync_pending_publish_finish`'s deferred one (issue #187).
    fn finish_ready_publish(
        &mut self,
        pending: PendingPublish,
        version: ProtocolVersion,
        telemetry: Option<PublishTelemetry>,
    ) {
        let (qos, packet_id) = (pending.header.qos, pending.header.packet_id);
        pending.finish(self.broker());
        self.handler.finish_publish_telemetry_for(telemetry, true);

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
}

/// Re-invoke every deferred [`PendingPublishFinish`] whose spool write has
/// finished draining (issue #187) — mirrors `sync_pending_auth_check`
/// (#181). Called from the top of `receive()`, since the storage callback
/// that finishes the last chunk only has a bare `ConnHandle`, not `&mut
/// MqttControlHandler`, so it stashes the outcome and pokes instead of
/// calling back in directly.
fn sync_pending_publish_finish(handler: &mut MqttControlHandler, endpoint: &mut dyn Endpoint) {
    let ready: Vec<PendingPublishFinish> = {
        let mut queue = handler.pending_publish_finishes.lock().unwrap();
        if queue.is_empty() {
            return;
        }
        let mut ready = Vec::new();
        let mut remaining = VecDeque::new();
        for item in queue.drain(..) {
            if item.pending.is_ready() {
                ready.push(item);
            } else {
                remaining.push_back(item);
            }
        }
        *queue = remaining;
        ready
    };
    if ready.is_empty() {
        return;
    }
    let mut ctx = Ctx { handler, endpoint, pending_version: None };
    for PendingPublishFinish { pending, version, telemetry } in ready {
        ctx.finish_ready_publish(pending, version, telemetry);
    }
}

impl MqttFrameHandler for Ctx<'_, '_> {
    fn connect(&mut self, packet: ConnectPacket) {
        if let Some(timer) = self.handler.connect_timeout_timer.take() {
            timer.cancel();
        }
        if matches!(self.handler.session, SessionState::Connected(_))
            || self.handler.busy.load(Ordering::Relaxed)
        {
            // A second CONNECT on an established session is a protocol
            // violation (MQTT 3.1.1 §3.1) — also rejected while a SASL
            // step from a first, still-in-flight CONNECT's enhanced AUTH
            // is offloaded (issue #181), or while a plain CONNECT's
            // authorize() call is offloaded (issue #210): `session` alone
            // doesn't protect against either race, since it only becomes
            // `Connected` once the check resolves.
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
        let client_topic_alias_max = if version.is_v5() {
            packet.properties.get_u16(property::TOPIC_ALIAS_MAXIMUM).unwrap_or(0)
        } else {
            0
        };

        if packet.properties.get_utf8(property::AUTHENTICATION_METHOD).is_none() {
            // Plain CONNECT: offload the (possibly blocking — e.g. an
            // LDAP/PAM-backed CredentialStore) authorize() call off the
            // reactor thread (issue #210), same class of risk #181 fixed
            // for enhanced AUTH's SaslServer::step. Everything downstream
            // of a successful check is captured in `pending_connect` and
            // resumed via `finish_connect_after_auth` by
            // `sync_pending_authorize`, once the result is back.
            let pending_connect = crate::server::auth::PendingConnectAuth {
                client_id: client_id.clone(),
                clean_session: packet.clean_session,
                keep_alive_raw: packet.keep_alive,
                will: packet.will.clone(),
                receive_maximum,
                session_expiry_secs,
                client_topic_alias_max,
                version,
            };
            offload_authorize(self.handler, self.endpoint, packet, pending_connect);
            self.pending_version = Some(version);
            return;
        }
        self.handler.meta.client_id = Some(client_id.clone());

        match crate::server::auth::maybe_start_connect_auth(
            self.handler,
            self.endpoint,
            &packet,
            &client_id,
            receive_maximum,
            session_expiry_secs,
            client_topic_alias_max,
        ) {
            Ok(true) => {
                // AUTH exchange in progress — CONNACK deferred.
                self.pending_version = Some(version);
            }
            Ok(false) => unreachable!(
                "maybe_start_connect_auth only returns Ok(false) when no \
                 Authentication Method is present, but connect() only \
                 calls it once one is confirmed present"
            ),
            Err(code) => {
                self.handler.record_auth(false);
                self.connack_and_close(version, code);
            }
        }
    }

    fn connack(&mut self, _session_present: bool, _reason_code: u8, _properties: Properties) {
        self.disconnect_and_close(reason::PROTOCOL_ERROR); // servers don't receive CONNACK
    }

    fn start_publish(&mut self, mut header: PublishHeader) {
        let SessionState::Connected(session) = &mut self.handler.session else {
            self.disconnect_and_close(reason::PROTOCOL_ERROR);
            return;
        };
        // Topic Alias resolution (MQTT 5.0 §3.3.2.3.4).
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
                        QoS::AtMostOnce => {
                            self.disconnect_and_close(code);
                        }
                        QoS::AtLeastOnce => {
                            let wire = encode::encode_puback(
                                header.packet_id, code, &Properties::new(), session.version,
                            );
                            self.endpoint.send(&wire);
                        }
                        QoS::ExactlyOnce => {
                            let wire = encode::encode_pubrec(
                                header.packet_id, code, &Properties::new(), session.version,
                            );
                            self.endpoint.send(&wire);
                        }
                    }
                } else {
                    self.disconnect_and_close(reason::PROTOCOL_ERROR);
                }
                return;
            }
        }

        // Fan out to QoS-0 recipients now — their PUBLISH headers go out
        // immediately, payload chunks follow live via `publish_data`.
        // QoS-1/2 recipients (and retain) are resolved in `end_publish`
        // once the whole payload is known, from a spooled copy.
        let SessionState::Connected(session) = &mut self.handler.session else {
            return;
        };
        let subscriber_id = session.subscriber_id;
        let qos = header.qos;
        let bytes = header.payload_len as u64;
        let runtime = Arc::clone(&self.handler.runtime);
        let handle = self.endpoint.handle();
        let pending = PendingPublish::begin(self.broker(), subscriber_id, header, runtime, handle);
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
        let telemetry = self.handler.publish_tel.take();
        if pending.is_ready() {
            self.finish_ready_publish(pending, version, telemetry);
        } else {
            // Spool writes from this publish are still draining (issue
            // #187) — defer both `finish` and the PUBACK/PUBREC;
            // `sync_pending_publish_finish` picks this back up once
            // `is_ready()` is true, triggered by the last write's
            // `poke_handler` call (see
            // `publish_spool::drain_next_publish_chunk`).
            self.handler
                .pending_publish_finishes
                .lock()
                .unwrap()
                .push_back(PendingPublishFinish { pending, version, telemetry });
        }
    }

    fn puback(&mut self, packet_id: u16, _reason_code: u8, _properties: Properties) {
        // Client acked a QoS 1 message we forwarded to it as a subscriber —
        // frees one Receive Maximum credit.
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
        self.endpoint.send(&wire);
    }

    fn pubcomp(&mut self, packet_id: u16, _reason_code: u8, _properties: Properties) {
        // Client completed the QoS 2 handshake for a message we forwarded
        // to it as a subscriber — frees one Receive Maximum credit.
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
                                        subscriber_id, &topic, &msg, granted_qos, &self.handler.runtime,
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

    fn auth(&mut self, _reason_code: u8, properties: Properties) {
        // Enhanced AUTH continues in `server::auth` once CONNECT requested a method.
        crate::server::auth::handle_auth_packet(self.handler, self.endpoint, properties);
    }

    fn parse_error(&mut self, _err: MqttError) {
        self.disconnect_and_close(reason::MALFORMED_PACKET);
    }
}

/// Complete CONNECT session setup after a successful enhanced AUTH exchange
/// (always v5), or a successful offloaded plain-CONNECT `authorize()` call
/// (issue #210 — any version).
pub(crate) fn finish_connect_after_auth(
    handler: &mut MqttControlHandler,
    endpoint: &mut dyn Endpoint,
    pc: crate::server::auth::PendingConnectAuth,
) {
    let version = pc.version;
    let keep_alive = if pc.keep_alive_raw == 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(pc.keep_alive_raw as u64 * 1500)
    };
    let session_expiry = Duration::from_secs(pc.session_expiry_secs as u64);
    let server_topic_alias_max = if version.is_v5() { SERVER_TOPIC_ALIAS_MAXIMUM } else { 0 };

    let (subscriber_id, evicted, session_present) = handler.config.broker.register(
        &pc.client_id,
        version,
        pc.receive_maximum,
        pc.clean_session,
        endpoint.handle(),
        false,
    );
    if let Some(evicted) = evicted {
        evicted.close();
    }

    handler.meta.client_id = Some(pc.client_id.clone());
    handler.session = SessionState::Connected(Box::new(ConnectedSession {
        subscriber_id,
        client_id: pc.client_id,
        version,
        will: pc.will,
        keep_alive,
        keepalive_timer: None,
        session_expiry,
        graceful_disconnect: false,
        awaiting_pubrel: HashSet::new(),
        pending_publish: None,
        inbound_aliases: HashMap::new(),
        server_topic_alias_max,
        client_topic_alias_max: pc.client_topic_alias_max,
        qos_retry_interval: DEFAULT_QOS_RETRY_INTERVAL,
        retransmit_timer: None,
    }));

    if session_present {
        // Issue #216: the offline-queue read can block for a file-backed
        // store, so it's offloaded — CONNACK (and arming the retransmit
        // timer) waits for it via `pending_connack`/`sync_pending_connack`,
        // same deferred-reply shape as #185/#187/#210. A second CONNECT
        // can't race this window: `handler.session` is already `Connected`
        // by this point, which `connect()`'s existing guard already rejects
        // regardless of any busy flag.
        let outcome = PendingConnackOutcome {
            session_present,
            receive_maximum: pc.receive_maximum,
            session_expiry_secs: pc.session_expiry_secs,
            server_topic_alias_max,
            version,
        };
        match handler.control_handle.clone() {
            Some(conn_handle) => {
                let pending = Arc::clone(&handler.pending_connack);
                let poke_handle = conn_handle.clone();
                handler.config.broker.drain_offline_async(
                    subscriber_id,
                    conn_handle,
                    Box::new(move || {
                        *pending.lock().unwrap() = Some(outcome);
                        poke_handle.with_endpoint(|ep| ep.poke_handler());
                    }),
                );
                return;
            }
            None => {
                // No handle to route the offloaded read's completion
                // through (shouldn't happen — set in `connected()` before
                // any CONNECT can be processed) — fail closed rather than
                // silently skipping the offline drain.
                endpoint.send(&encode::encode_connack(
                    false,
                    reason::UNSPECIFIED_ERROR,
                    &Properties::new(),
                    version,
                ));
                endpoint.close();
                return;
            }
        }
    }
    arm_retransmit_timer(handler, endpoint);

    let connack_props = connack_properties(
        version,
        pc.receive_maximum,
        pc.session_expiry_secs,
        server_topic_alias_max,
    );
    endpoint.send(&encode::encode_connack(session_present, 0, &connack_props, version));
}

/// Result of an offloaded offline-queue drain (issue #216), stashed by
/// [`crate::server::broker::BrokerState::drain_offline_async`]'s completion
/// closure for [`sync_pending_connack`] to apply once back on the reactor
/// — everything `finish_connect_after_auth`'s tail (arm the retransmit
/// timer, send CONNACK) used to do inline once `drain_offline` returned.
pub(crate) struct PendingConnackOutcome {
    session_present: bool,
    receive_maximum: u16,
    session_expiry_secs: u32,
    server_topic_alias_max: u16,
    version: ProtocolVersion,
}

/// Apply the outcome of an offloaded offline-queue drain, once
/// `drain_offline_async`'s completion closure has stashed one — see
/// [`PendingConnackOutcome`]. Called from `MqttControlHandler::receive`
/// before every packet parse, mirroring `sync_pending_auth_check`/
/// `sync_pending_authorize`.
fn sync_pending_connack(handler: &mut MqttControlHandler, endpoint: &mut dyn Endpoint) {
    let Some(PendingConnackOutcome {
        session_present,
        receive_maximum,
        session_expiry_secs,
        server_topic_alias_max,
        version,
    }) = handler.pending_connack.lock().unwrap().take()
    else {
        return;
    };
    arm_retransmit_timer(handler, endpoint);
    let connack_props =
        connack_properties(version, receive_maximum, session_expiry_secs, server_topic_alias_max);
    endpoint.send(&encode::encode_connack(session_present, 0, &connack_props, version));
}

/// Offload a plain (non-enhanced-AUTH) CONNECT's `ConnectHandler::authorize`
/// call to the storage pool (issue #210 — may block for an LDAP/PAM-backed
/// `CredentialStore`, same class of risk #181 fixed for `SaslServer::step`).
/// `connect_handler` moves into the closure; the outcome (including it,
/// restored) lands in `pending_authorize` for [`sync_pending_authorize`] to
/// apply once back on the reactor.
fn offload_authorize(
    handler: &mut MqttControlHandler,
    endpoint: &mut dyn Endpoint,
    packet: ConnectPacket,
    pending_connect: crate::server::auth::PendingConnectAuth,
) {
    let version = pending_connect.version;
    let Some(connect_handler) = handler.connect_handler.take() else {
        // Can't happen (authorize() runs at most once per connection —
        // see `connect_handler`'s doc), but fail closed rather than
        // panicking if it somehow did.
        endpoint.send(&encode::encode_connack(false, reason::UNSPECIFIED_ERROR, &Properties::new(), version));
        endpoint.close();
        return;
    };
    let Some(handle) = handler.control_handle.clone() else {
        endpoint.close();
        return;
    };
    let meta = handler.meta.clone();
    let pending = Arc::clone(&handler.pending_authorize);
    let busy = Arc::clone(&handler.busy);
    handler.busy.store(true, Ordering::Relaxed);
    handler.runtime.storage().submit_on(
        handle.clone(),
        move || {
            let mut connect_handler = connect_handler;
            let decision = connect_handler.authorize(&packet, &meta);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((connect_handler, decision))
        },
        move |result: Result<(Box<dyn ConnectHandler>, ConnectDecision), hopf_core::StorageError>| {
            let result = result.map_err(|e| e.to_string());
            *pending.lock().unwrap() = Some(PendingAuthorizeOutcome { result, pending_connect });
            handle.with_endpoint(move |ep| {
                busy.store(false, Ordering::Relaxed);
                // Nothing sent to the client yet — the reply depends
                // entirely on `sync_pending_authorize`, which needs
                // `&mut MqttControlHandler`. The client is waiting on us,
                // not about to send more input, so `poke_handler` is what
                // triggers the next `receive()` call.
                ep.poke_handler();
            });
        },
    );
}

/// Apply the outcome of an offloaded plain-CONNECT `authorize()` call, once
/// [`offload_authorize`]'s `submit_on` callback has stashed one — see
/// [`PendingAuthorizeOutcome`]. Called from `MqttControlHandler::receive`
/// before every packet parse, mirroring `sync_pending_auth_check`.
fn sync_pending_authorize(handler: &mut MqttControlHandler, endpoint: &mut dyn Endpoint) {
    let Some(PendingAuthorizeOutcome { result, pending_connect }) =
        handler.pending_authorize.lock().unwrap().take()
    else {
        return;
    };
    let version = pending_connect.version;
    let (connect_handler, decision) = match result {
        Ok(ok) => ok,
        Err(_e) => {
            handler.record_auth(false);
            endpoint.send(&encode::encode_connack(
                false,
                reason::SERVER_UNAVAILABLE,
                &Properties::new(),
                version,
            ));
            endpoint.close();
            return;
        }
    };
    handler.connect_handler = Some(connect_handler);
    match decision {
        ConnectDecision::Reject(reason_code) => {
            handler.record_auth(false);
            endpoint.send(&encode::encode_connack(false, reason_code, &Properties::new(), version));
            endpoint.close();
        }
        ConnectDecision::Accept => {
            handler.record_auth(true);
            finish_connect_after_auth(handler, endpoint, pending_connect);
        }
    }
}

#[cfg(test)]
mod publish_finish_tests {
    use super::*;
    use crate::codec::encode;
    use crate::codec::packet::{ConnectPacket, PacketType};
    use crate::server::handler::DefaultMqttHandlerFactory;
    use crate::server::handler::MqttHandlerFactory;
    use hopf_core::{RuntimeConfig, SecurityInfo, StartTlsError, WriteReadyCallback};
    use std::io;
    use std::sync::OnceLock;

    /// Minimal `Endpoint`: captures sent bytes, no real I/O or reactor —
    /// same shape as `hopf-smtp`/`hopf-imap`'s own test-only endpoint stubs.
    struct MockEndpoint {
        sent: Vec<u8>,
        open: bool,
    }
    impl MockEndpoint {
        fn new() -> Self {
            Self { sent: Vec::new(), open: true }
        }
    }
    impl Endpoint for MockEndpoint {
        fn send(&mut self, data: &[u8]) {
            self.sent.extend_from_slice(data);
        }
        fn is_open(&self) -> bool {
            self.open
        }
        fn is_closing(&self) -> bool {
            false
        }
        fn close(&mut self) {
            self.open = false;
        }
        fn local_addr(&self) -> io::Result<hopf_core::PeerAddr> {
            Ok(hopf_core::PeerAddr::Inet("127.0.0.1:1883".parse().unwrap()))
        }
        fn remote_addr(&self) -> io::Result<hopf_core::PeerAddr> {
            Ok(hopf_core::PeerAddr::Inet("127.0.0.1:9999".parse().unwrap()))
        }
        fn security_info(&self) -> &SecurityInfo {
            static PLAINTEXT: OnceLock<SecurityInfo> = OnceLock::new();
            PLAINTEXT.get_or_init(SecurityInfo::plaintext)
        }
        fn start_tls(&mut self) -> Result<(), StartTlsError> {
            Err(StartTlsError::Unsupported)
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _callback: Option<WriteReadyCallback>) {}
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn schedule_timer(&self, _delay: Duration, _callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
            TimerHandle::from_cancel(|| {})
        }
        fn handle(&self) -> ConnHandle {
            ConnHandle::from_execute(Arc::new(|task| task()))
        }
    }

    fn new_handler() -> MqttControlHandler {
        let config = Arc::new(
            MqttConfig::new("127.0.0.1:1883".parse().unwrap(), Arc::new(BrokerState::new()))
                .allow_anonymous(),
        );
        let factory = DefaultMqttHandlerFactory::new(None, true);
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        MqttControlHandler::new(
            config,
            factory.create(),
            factory.create_publish(),
            factory.create_subscribe(),
            MqttServerMetrics::shared(),
            rt,
        )
    }

    fn connect_bytes(client_id: &str) -> Vec<u8> {
        encode::encode_connect(&ConnectPacket {
            version: ProtocolVersion::V311,
            clean_session: true,
            keep_alive: 0,
            properties: Properties::new(),
            client_id: client_id.to_string(),
            will: None,
            username: None,
            password: None,
        })
    }

    fn wait_for(mut pred: impl FnMut() -> bool, max_ms: u64) -> bool {
        for _ in 0..(max_ms / 5).max(1) {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        pred()
    }

    /// The next packet type in `sent` starting at `offset`, if any.
    fn packet_type_at(sent: &[u8], offset: usize) -> Option<PacketType> {
        sent.get(offset).and_then(|b| PacketType::from_value(b >> 4))
    }

    /// Issue #187: PUBACK for a retained, QoS-1 PUBLISH must not be sent
    /// until its spool write has actually landed on disk — proven here by
    /// checking the retained store already has the full expected payload
    /// at the exact moment the PUBACK first appears in `sent`, not merely
    /// "eventually". Whether that write happens to finish before or after
    /// `end_publish` itself runs is a timing coincidence this test doesn't
    /// pin down either way (see the comment at the PUBACK wait below) —
    /// only the on-disk-before-PUBACK invariant is asserted.
    #[test]
    fn end_publish_defers_puback_until_spool_write_lands() {
        let mut h = new_handler();
        let mut ep = MockEndpoint::new();
        h.connected(&mut ep);

        let mut data = connect_bytes("pub1").into_boxed_slice();
        h.receive(&mut ep, &mut &*data);
        // CONNECT's own authorize() check is now offloaded too (issue
        // #210), so the CONNACK no longer lands inline within this call —
        // poll for it, same as the PUBACK further down.
        assert!(
            wait_for(
                || {
                    h.receive(&mut ep, &mut &[][..]);
                    !ep.sent.is_empty()
                },
                3000
            ),
            "CONNACK must eventually be sent once the offloaded authorize() check completes"
        );
        assert_eq!(packet_type_at(&ep.sent, 0), Some(PacketType::Connack));
        let after_connack = ep.sent.len();

        let payload = vec![0x5A; 64 * 1024];
        let publish = encode::encode_publish(
            "t/deferred", QoS::AtLeastOnce, false, true, 42, &payload, &Properties::new(), ProtocolVersion::V311,
        );
        data = publish.into_boxed_slice();
        h.receive(&mut ep, &mut &*data);

        // Whether the spool write's background chunks happen to have
        // already drained by the time `end_publish` runs (in which case
        // the PUBACK goes out inline) or are still in flight (in which
        // case `sync_pending_publish_finish` picks it up on a later
        // `receive()`, once `is_ready()`) is a timing coincidence, not
        // something this test can pin down — either is correct. What
        // matters, checked below, is that the retained payload is always
        // fully on disk by the time the PUBACK is observed either way.
        assert!(
            wait_for(
                || {
                    h.receive(&mut ep, &mut &[][..]);
                    ep.sent.len() > after_connack
                },
                3000
            ),
            "PUBACK must eventually be sent once the spool write drains"
        );
        assert_eq!(packet_type_at(&ep.sent, after_connack), Some(PacketType::Puback));
        assert_eq!(&ep.sent[after_connack + 2..after_connack + 4], &42u16.to_be_bytes());

        let snap = h.config.broker.retained_matching("t/deferred");
        assert_eq!(snap.len(), 1);
        let path = snap[0].1.path.as_ref().expect("spooled").path().to_path_buf();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            payload,
            "retained payload must already be fully on disk by the time PUBACK is observed"
        );
    }

    /// Two pipelined QoS-1 PUBLISHes, both deferred, must each get their
    /// own correct PUBACK (right packet id) and telemetry/publish-count
    /// bookkeeping without clobbering each other (issue #187 — the
    /// `PendingPublishFinish` queue, not a single slot, is what prevents
    /// this).
    #[test]
    fn overlapping_pipelined_publishes_each_finish_independently() {
        let mut h = new_handler();
        let mut ep = MockEndpoint::new();
        h.connected(&mut ep);

        let mut data = connect_bytes("pub2").into_boxed_slice();
        h.receive(&mut ep, &mut &*data);
        // CONNECT's own authorize() check is now offloaded too (issue
        // #210) — poll for the CONNACK before capturing the offset that
        // later PUBACK assertions are measured from.
        assert!(
            wait_for(
                || {
                    h.receive(&mut ep, &mut &[][..]);
                    !ep.sent.is_empty()
                },
                3000
            ),
            "CONNACK must eventually be sent once the offloaded authorize() check completes"
        );
        let after_connack = ep.sent.len();

        let payload_a = vec![0xAA; 32 * 1024];
        let payload_b = vec![0xBB; 48 * 1024];
        let publish_a = encode::encode_publish(
            "t/a", QoS::AtLeastOnce, false, true, 1, &payload_a, &Properties::new(), ProtocolVersion::V311,
        );
        let publish_b = encode::encode_publish(
            "t/b", QoS::AtLeastOnce, false, true, 2, &payload_b, &Properties::new(), ProtocolVersion::V311,
        );
        data = publish_a.into_boxed_slice();
        h.receive(&mut ep, &mut &*data);
        data = publish_b.into_boxed_slice();
        h.receive(&mut ep, &mut &*data);

        assert!(
            wait_for(
                || {
                    h.receive(&mut ep, &mut &[][..]);
                    h.pending_publish_finishes.lock().unwrap().is_empty()
                },
                3000
            ),
            "both pipelined publishes must eventually finish"
        );

        let mut packet_ids = Vec::new();
        let mut offset = after_connack;
        while offset < ep.sent.len() {
            assert_eq!(packet_type_at(&ep.sent, offset), Some(PacketType::Puback));
            packet_ids.push(u16::from_be_bytes([ep.sent[offset + 2], ep.sent[offset + 3]]));
            offset += 4;
        }
        packet_ids.sort_unstable();
        assert_eq!(packet_ids, vec![1, 2], "each publish must get exactly one correctly-numbered PUBACK");

        assert_eq!(
            std::fs::read(h.config.broker.retained_matching("t/a")[0].1.path.as_ref().unwrap().path()).unwrap(),
            payload_a
        );
        assert_eq!(
            std::fs::read(h.config.broker.retained_matching("t/b")[0].1.path.as_ref().unwrap().path()).unwrap(),
            payload_b
        );
        assert_eq!(h.metrics.publishes.load(Ordering::Relaxed), 2);
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
        let config = Arc::new(
            MqttConfig::new(
                "127.0.0.1:1883".parse().unwrap(),
                Arc::new(BrokerState::new()),
            )
            .allow_anonymous(),
        );
        let factory = DefaultMqttHandlerFactory::new(None, true);
        let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
        let mut h = MqttControlHandler::new(
            config,
            factory.create(),
            factory.create_publish(),
            factory.create_subscribe(),
            MqttServerMetrics::shared(),
            rt,
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
        let tel = h.publish_tel.take();
        h.finish_publish_telemetry_for(tel, true);

        h.end_connection_telemetry();
        assert!(h.meta.traceparent.is_none());
        pipeline.shutdown();
        let _ = std::fs::remove_file(&dir);
    }
}
