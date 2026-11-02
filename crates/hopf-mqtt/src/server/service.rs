// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT service registration on a [`Runtime`].

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{BindingId, ProtocolHandler, Runtime, TcpListenerConfig};

use super::config::MqttConfig;
use super::control::MqttControlHandler;
use super::handler::{DefaultMqttHandlerFactory, MqttHandlerFactory};
use super::metrics::MqttServerMetrics;

/// Registers the MQTT TCP listener for a [`MqttConfig`].
pub struct MqttService {
    config: Arc<MqttConfig>,
    handler_factory: Arc<dyn MqttHandlerFactory>,
    metrics: Arc<MqttServerMetrics>,
    otel_metrics: Option<Arc<hopf_otel::MqttServerMetrics>>,
    export: Option<hopf_otel::ExportHandle>,
    traces_enabled: bool,
    /// The listener [`Self::start`] registered, and the runtime it is on,
    /// for [`Self::stop`].
    binding: Mutex<Option<(Arc<Runtime>, BindingId)>>,
}

impl MqttService {
    /// Wrap `config`, authorizing CONNECT via `config.credentials`, or
    /// anonymously only when [`MqttConfig::allow_anonymous`] is set.
    pub fn new(config: MqttConfig) -> Self {
        let handler_factory = Arc::new(DefaultMqttHandlerFactory::new(
            config.credentials.clone(),
            config.allow_anonymous,
        ));
        Self {
            config: Arc::new(config),
            handler_factory,
            metrics: MqttServerMetrics::shared(),
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            binding: Mutex::new(None),
        }
    }

    /// Wrap `config`, authorizing CONNECT via a custom [`MqttHandlerFactory`]
    /// instead of the default `config.credentials` check.
    pub fn with_handler_factory(config: MqttConfig, handler_factory: Arc<dyn MqttHandlerFactory>) -> Self {
        Self {
            config: Arc::new(config),
            handler_factory,
            metrics: MqttServerMetrics::shared(),
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            binding: Mutex::new(None),
        }
    }

    /// Wire OTLP/JSONL MQTT metrics and connection/publish traces from a pipeline.
    ///
    /// When traces are enabled, handlers see a W3C `traceparent` on
    /// [`MqttConnectionMetadata`](crate::server::MqttConnectionMetadata) for
    /// outbound HTTP via `hopf_otel::with_traceparent`.
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

    /// Shared process-local metrics.
    pub fn metrics(&self) -> &Arc<MqttServerMetrics> {
        &self.metrics
    }

    /// Build a [`TcpListenerConfig`] for the MQTT port (for composing with
    /// other listeners via `hopf_core::Composition`, mirroring
    /// `SmtpService::control_listener` / `Pop3Service::control_listener`).
    pub fn control_listener(&self, runtime: Arc<Runtime>) -> TcpListenerConfig {
        let config = Arc::clone(&self.config);
        let handler_factory = Arc::clone(&self.handler_factory);
        let metrics = Arc::clone(&self.metrics);
        let otel_metrics = self.otel_metrics.clone();
        let export = self.export.clone();
        let traces_enabled = self.traces_enabled;
        TcpListenerConfig::new(self.config.listen, move || {
            Box::new(
                MqttControlHandler::new(
                    Arc::clone(&config),
                    handler_factory.create(),
                    handler_factory.create_publish(),
                    handler_factory.create_subscribe(),
                    Arc::clone(&metrics),
                    Arc::clone(&runtime),
                )
                    .with_telemetry(otel_metrics.clone(), export.clone(), traces_enabled),
            ) as Box<dyn ProtocolHandler>
        })
    }

    /// Register the listener directly on `runtime`; returns the bound address.
    pub fn start(&self, runtime: Arc<Runtime>) -> io::Result<SocketAddr> {
        let (addr, id) = runtime.add_tcp_listener(self.control_listener(Arc::clone(&runtime)))?;
        *self.binding.lock().unwrap() = Some((runtime, id));
        Ok(addr)
    }

    /// Stop accepting connections. Sessions already open carry on until they
    /// end; until they have, and this service is dropped, nothing else lets
    /// go of the [`Runtime`]. A service that was not started, or was already
    /// stopped, is left as it is.
    pub fn stop(&self) {
        if let Some((runtime, id)) = self.binding.lock().unwrap().take() {
            runtime.remove_binding(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use std::io::{Read, Write};
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use std::net::TcpStream;
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use std::time::{Duration, Instant};

    use hopf_auth::PasswordStore;
    use hopf_core::RuntimeConfig;

    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use crate::codec::packet::{ConnectPacket, ProtocolVersion};
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use crate::codec::{encode, Properties, QoS};
    use crate::server::broker::BrokerState;
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use crate::server::handler::{ConnectDecision, ConnectHandler, MqttConnectionMetadata};

    fn runtime() -> Arc<Runtime> {
        Arc::new(Runtime::start(RuntimeConfig::default()).unwrap())
    }

    fn config() -> MqttConfig {
        MqttConfig::new("127.0.0.1:0".parse().unwrap(), Arc::new(BrokerState::new()))
    }

    #[cfg(feature = "integration")]
    fn connect(id: &str, user: Option<(&str, &str)>) -> Vec<u8> {
        encode::encode_connect(&ConnectPacket {
            version: ProtocolVersion::V311,
            clean_session: true,
            keep_alive: 0,
            properties: Properties::new(),
            client_id: id.into(),
            will: None,
            username: user.map(|(u, _)| u.to_string()),
            password: user.map(|(_, p)| p.as_bytes().to_vec()),
        })
    }

    #[cfg(feature = "integration")]
    fn publish(topic: &str, payload: &[u8]) -> Vec<u8> {
        encode::encode_publish(
            &encode::PublishFields {
                topic,
                qos: QoS::AtMostOnce,
                dup: false,
                retain: false,
                packet_id: 0,
                props: &Properties::new(),
                version: ProtocolVersion::V311,
            },
            payload,
        )
    }

    #[cfg(feature = "integration")]
    fn client(addr: SocketAddr) -> TcpStream {
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream
    }

    /// Send CONNECT and return the CONNACK return code (MQTT 3.1.1).
    #[cfg(feature = "integration")]
    fn connack(stream: &mut TcpStream, packet: &[u8]) -> u8 {
        stream.write_all(packet).unwrap();
        let mut ack = [0u8; 4];
        stream.read_exact(&mut ack).unwrap();
        assert_eq!(ack[0], 0x20, "not a CONNACK: {ack:?}");
        ack[3]
    }

    /// The server has closed the connection (read gives EOF or a reset).
    #[cfg(feature = "integration")]
    fn closed(stream: &mut TcpStream) -> bool {
        let mut b = [0u8; 16];
        matches!(stream.read(&mut b), Ok(0) | Err(_))
    }

    #[cfg(feature = "integration")]
    fn wait(pred: impl Fn() -> bool) -> bool {
        for _ in 0..500 {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        pred()
    }

    // -- the configuration -----------------------------------------------------

    #[test]
    fn a_new_config_is_secure_by_default() {
        let c = config();
        assert!(c.credentials.is_none() && !c.allow_anonymous, "anonymous CONNECT is denied until asked for");
        assert_eq!(c.max_packet_size, crate::codec::DEFAULT_MAX_PACKET_SIZE);
        assert_eq!(c.max_publish_payload, crate::codec::DEFAULT_MAX_PACKET_SIZE);
        assert_eq!(c.connect_timeout, crate::server::config::DEFAULT_CONNECT_TIMEOUT);
    }

    #[test]
    fn the_builders_set_what_they_say() {
        let c = config()
            .with_credentials(Arc::new(PasswordStore::new().with_user("u", "p")))
            .allow_anonymous()
            .with_max_packet_size(100)
            .with_max_publish_payload(50)
            .with_connect_timeout(Duration::from_secs(3));
        assert!(c.credentials.is_some() && c.allow_anonymous);
        assert_eq!((c.max_packet_size, c.max_publish_payload, c.connect_timeout), (100, 50, Duration::from_secs(3)));
    }

    #[test]
    fn the_listener_is_plain_and_can_be_given_tls_by_whoever_composes_it() {
        let listener = MqttService::new(config()).control_listener(runtime());
        assert!(!listener.secure && listener.tls.is_none());
    }

    // -- who may connect ----------------------------------------------------------------

    #[cfg(feature = "integration")]
    #[test]
    fn an_anonymous_connect_is_refused_unless_the_config_allows_it() {
        let addr = MqttService::new(config()).start(runtime()).unwrap();
        let mut c = client(addr);
        let rc = connack(&mut c, &connect("anon", None));
        assert_ne!(rc, 0, "a default broker accepted a client with no credentials");

        let addr = MqttService::new(config().allow_anonymous()).start(runtime()).unwrap();
        assert_eq!(connack(&mut client(addr), &connect("anon", None)), 0);
    }

    #[cfg(feature = "integration")]
    #[test]
    fn credentials_in_the_config_are_checked_at_connect() {
        let store = Arc::new(PasswordStore::new().with_user("u", "p"));
        let addr = MqttService::new(config().with_credentials(store)).start(runtime()).unwrap();
        assert_ne!(connack(&mut client(addr), &connect("a", Some(("u", "wrong")))), 0, "a wrong password was accepted");
        assert_ne!(connack(&mut client(addr), &connect("b", None)), 0, "no credentials were accepted");
        assert_eq!(connack(&mut client(addr), &connect("c", Some(("u", "p")))), 0);
    }

    // -- limits --------------------------------------------------------------------------

    #[cfg(feature = "integration")]
    #[test]
    fn a_packet_over_the_size_limit_ends_the_connection() {
        let addr = MqttService::new(config().allow_anonymous().with_max_packet_size(64)).start(runtime()).unwrap();
        let mut c = client(addr);
        assert_eq!(connack(&mut c, &connect("big", None)), 0);
        c.write_all(&publish("t", &[7u8; 500])).unwrap();
        assert!(closed(&mut c), "an over-long packet was not refused");
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_publish_over_the_payload_limit_drops_the_publisher_and_is_never_delivered() {
        let addr = MqttService::new(config().allow_anonymous().with_max_publish_payload(32)).start(runtime()).unwrap();
        let mut sub = client(addr);
        assert_eq!(connack(&mut sub, &connect("sub", None)), 0);
        sub.write_all(&{
            let mut body = vec![0x00, 0x01, 0x00, 0x01, b't', 0x00];
            let mut wire = vec![0x82];
            crate::codec::varint::encode(&mut wire, body.len() as u32);
            wire.append(&mut body);
            wire
        })
        .unwrap();
        let mut suback = [0u8; 5];
        sub.read_exact(&mut suback).unwrap();

        let mut greedy = client(addr);
        assert_eq!(connack(&mut greedy, &connect("greedy", None)), 0);
        greedy.write_all(&publish("t", &[1u8; 200])).unwrap();
        assert!(closed(&mut greedy), "the publisher of an over-size payload was kept");

        // The broker goes on for everyone else, and the payload never came.
        let mut polite = client(addr);
        assert_eq!(connack(&mut polite, &connect("polite", None)), 0);
        polite.write_all(&publish("t", b"small")).unwrap();
        let mut buf = [0u8; 64];
        let n = sub.read(&mut buf).unwrap();
        assert!(buf[..n].windows(5).any(|w| w == b"small"), "{:?}", &buf[..n]);
        assert!(!buf[..n].windows(4).any(|w| w == [1, 1, 1, 1]), "the over-size payload was delivered");
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_connection_that_never_sends_connect_is_closed_after_the_connect_timeout() {
        let addr = MqttService::new(config().allow_anonymous().with_connect_timeout(Duration::from_millis(300)))
            .start(runtime())
            .unwrap();
        let mut c = client(addr);
        let started = Instant::now();
        assert!(closed(&mut c), "an idle new connection was kept");
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    }

    // -- a handler per connection ---------------------------------------------------

    #[cfg(feature = "integration")]
    struct Counting {
        created: Arc<AtomicUsize>,
    }

    #[cfg(feature = "integration")]
    struct AcceptAll;

    #[cfg(feature = "integration")]
    impl ConnectHandler for AcceptAll {
        fn authorize(&mut self, _p: &ConnectPacket, _m: &MqttConnectionMetadata) -> ConnectDecision {
            ConnectDecision::Accept
        }
    }

    #[cfg(feature = "integration")]
    impl MqttHandlerFactory for Counting {
        fn create(&self) -> Box<dyn ConnectHandler> {
            self.created.fetch_add(1, Ordering::SeqCst);
            Box::new(AcceptAll)
        }
    }

    #[cfg(feature = "integration")]
    #[test]
    fn each_connection_gets_its_own_handlers_and_the_factory_decides_who_may_connect() {
        let created = Arc::new(AtomicUsize::new(0));
        let svc = MqttService::with_handler_factory(config(), Arc::new(Counting { created: Arc::clone(&created) }));
        let before = svc.metrics().connections.load(Ordering::Relaxed);
        let addr = svc.start(runtime()).unwrap();
        // the config denies anonymous clients, but the factory is the authority
        assert_eq!(connack(&mut client(addr), &connect("one", None)), 0);
        assert_eq!(connack(&mut client(addr), &connect("two", None)), 0);
        assert_eq!(created.load(Ordering::SeqCst), 2, "one handler per connection, not one per service");
        assert!(svc.metrics().connections.load(Ordering::Relaxed) >= before + 2);
    }

    // -- shutdown ---------------------------------------------------------------------

    #[cfg(feature = "integration")]
    #[test]
    fn a_stopped_service_refuses_new_connections_but_lets_open_sessions_finish_and_the_runtime_shut_down() {
        let rt = runtime();
        let svc = MqttService::new(config().allow_anonymous());
        let addr = svc.start(Arc::clone(&rt)).unwrap();
        let mut open = client(addr);
        assert_eq!(connack(&mut open, &connect("open", None)), 0);

        svc.stop();
        svc.stop(); // a second stop is nothing
        assert!(wait(|| TcpStream::connect(addr).is_err()), "a stopped service still accepts connections");
        open.write_all(&[0xC0, 0x00]).unwrap(); // PINGREQ
        let mut pong = [0u8; 2];
        open.read_exact(&mut pong).unwrap();
        assert_eq!(pong, [0xD0, 0x00], "stopping cut an open session off");

        open.write_all(&[0xE0, 0x00]).unwrap(); // DISCONNECT
        assert!(closed(&mut open));
        drop(open);
        drop(svc);
        assert!(wait(|| Arc::strong_count(&rt) == 1), "something still holds the runtime: {} references", Arc::strong_count(&rt));
        Arc::try_unwrap(rt).ok().expect("nothing else holds the runtime").shutdown();
    }
}
