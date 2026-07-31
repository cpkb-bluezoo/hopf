// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in loopback TCP smoke tests for the real `MqttService` /
//! `MqttControlHandler` wiring (not just the codec/broker units).
//!
//! `cargo test -p hopf-mqtt --features integration`

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};

use crate::server::broker::BrokerState;
use crate::codec::packet::{ConnectPacket, ProtocolVersion};
use crate::codec::{encode, Properties};
use crate::server::{MqttConfig, MqttService};

fn wait_connect(addr: SocketAddr) -> TcpStream {
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(addr) {
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
            return s;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("failed to connect to {addr}");
}

fn connect_packet(client_id: &str) -> Vec<u8> {
    encode::encode_connect(&ConnectPacket {
        version: ProtocolVersion::V311,
        clean_session: true,
        keep_alive: 30,
        properties: Properties::new(),
        client_id: client_id.to_string(),
        will: None,
        username: None,
        password: None,
    })
}

fn read_exact_timeout(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).unwrap();
    buf
}

fn v5_connect_packet(client_id: &str, clean_start: bool, session_expiry_secs: u32) -> Vec<u8> {
    let mut properties = Properties::new();
    if session_expiry_secs != 0 {
        properties.set_u32(crate::codec::properties::property::SESSION_EXPIRY_INTERVAL, session_expiry_secs);
    }
    encode::encode_connect(&ConnectPacket {
        version: ProtocolVersion::V5,
        clean_session: clean_start,
        keep_alive: 30,
        properties,
        client_id: client_id.to_string(),
        will: None,
        username: None,
        password: None,
    })
}

/// Hand-built SUBSCRIBE (single filter, requested QoS 0). `version` must
/// match the connection's negotiated version — v5 SUBSCRIBE has an (empty
/// here) properties block right after the packet id that v3.1.1 lacks;
/// getting this wrong makes the server misparse the topic filter length.
fn subscribe_packet(packet_id: u16, topic_filter: &str, version: ProtocolVersion) -> Vec<u8> {
    subscribe_packet_qos(packet_id, topic_filter, 0, version)
}

/// As [`subscribe_packet`], but with an explicit requested max QoS byte.
fn subscribe_packet_qos(packet_id: u16, topic_filter: &str, qos: u8, version: ProtocolVersion) -> Vec<u8> {
    let mut wire = vec![0x82];
    let mut body = packet_id.to_be_bytes().to_vec();
    if version.is_v5() {
        body.push(0x00); // empty properties
    }
    body.extend_from_slice(&(topic_filter.len() as u16).to_be_bytes());
    body.extend_from_slice(topic_filter.as_bytes());
    body.push(qos);
    crate::codec::varint::encode(&mut wire, body.len() as u32);
    wire.extend_from_slice(&body);
    wire
}

#[test]
fn connect_subscribe_publish_fanout_round_trip() {
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 2,
        ..Default::default()
    })
    .unwrap();
    let broker = Arc::new(BrokerState::new());
    let config = MqttConfig::new("127.0.0.1:0".parse().unwrap(), broker);
    let service = MqttService::new(config);
    let addr = service.start(&rt).unwrap();

    // Subscriber: CONNECT, then SUBSCRIBE to "test/topic".
    let mut sub = wait_connect(addr);
    sub.write_all(&connect_packet("subscriber")).unwrap();
    let connack = read_exact_timeout(&mut sub, 4);
    assert_eq!(connack[0], 0x20, "expected CONNACK fixed header byte");
    assert_eq!(connack[3], 0x00, "expected CONNACK accepted reason code");

    sub.write_all(&subscribe_packet(0x2A, "test/topic", ProtocolVersion::V311)).unwrap();

    let suback = read_exact_timeout(&mut sub, 5);
    assert_eq!(suback[0], 0x90, "expected SUBACK fixed header byte");
    assert_eq!(suback[4], 0x00, "expected granted QoS 0");

    // Publisher: CONNECT, then PUBLISH QoS 0 to the same topic.
    let mut publisher = wait_connect(addr);
    publisher.write_all(&connect_packet("publisher")).unwrap();
    let _ = read_exact_timeout(&mut publisher, 4);

    let publish_wire = encode::encode_publish(
        "test/topic",
        crate::codec::QoS::AtMostOnce,
        false,
        false,
        0,
        b"hello subscribers",
        &Properties::new(),
        ProtocolVersion::V311,
    );
    publisher.write_all(&publish_wire).unwrap();

    // The subscriber should receive the forwarded PUBLISH.
    let mut buf = vec![0u8; 256];
    let n = sub.read(&mut buf).unwrap();
    let received = &buf[..n];
    assert_eq!(received[0] & 0xF0, 0x30, "expected a PUBLISH fixed header");
    let text = String::from_utf8_lossy(received);
    assert!(text.contains("test/topic"));
    assert!(text.contains("hello subscribers"));

    rt.shutdown();
}

/// A QoS-1 subscriber's PUBLISH is resolved from the broker's spool once
/// the whole payload has arrived (`BrokerState::deliver_deferred`), rather
/// than the live QoS-0 fast path — exercised here with a payload spanning
/// several of the 8KB chunks `stream_file_publish` reads the spool in, to
/// prove the spool-then-replay round-trips byte for byte regardless of
/// chunk boundaries.
#[test]
fn qos1_subscriber_receives_large_multi_chunk_publish() {
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 2,
        ..Default::default()
    })
    .unwrap();
    let broker = Arc::new(BrokerState::new());
    let config = MqttConfig::new("127.0.0.1:0".parse().unwrap(), broker);
    let service = MqttService::new(config);
    let addr = service.start(&rt).unwrap();

    let mut sub = wait_connect(addr);
    sub.write_all(&connect_packet("qos1-subscriber")).unwrap();
    let _ = read_exact_timeout(&mut sub, 4);
    sub.write_all(&subscribe_packet_qos(0x01, "big/topic", 1, ProtocolVersion::V311))
        .unwrap();
    let _ = read_exact_timeout(&mut sub, 5); // SUBACK

    let payload: Vec<u8> = (0..20_000u32).map(|i| (b'a' + (i % 26) as u8)).collect();
    let mut publisher = wait_connect(addr);
    publisher.write_all(&connect_packet("qos1-publisher")).unwrap();
    let _ = read_exact_timeout(&mut publisher, 4);
    let publish_wire = encode::encode_publish(
        "big/topic",
        crate::codec::QoS::AtLeastOnce,
        false,
        false,
        0x55,
        &payload,
        &Properties::new(),
        ProtocolVersion::V311,
    );
    publisher.write_all(&publish_wire).unwrap();
    let puback = read_exact_timeout(&mut publisher, 4);
    assert_eq!(puback[0], 0x40, "expected PUBACK fixed header byte");

    // Read the forwarded PUBLISH: fixed header, then a varint remaining
    // length, then topic + packet id + the full payload.
    let mut first = [0u8; 1];
    sub.read_exact(&mut first).unwrap();
    assert_eq!(first[0] & 0xF0, 0x30, "expected a PUBLISH fixed header");
    let mut remaining_length = 0u32;
    let mut shift = 0;
    loop {
        let mut b = [0u8; 1];
        sub.read_exact(&mut b).unwrap();
        remaining_length |= ((b[0] & 0x7F) as u32) << shift;
        if b[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    let body = read_exact_timeout(&mut sub, remaining_length as usize);
    let topic_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let topic = &body[2..2 + topic_len];
    assert_eq!(topic, b"big/topic");
    // QoS 1: two-byte packet id follows the topic.
    let payload_start = 2 + topic_len + 2;
    assert_eq!(&body[payload_start..], payload.as_slice(), "payload should round-trip byte for byte");

    rt.shutdown();
}

/// PUBLISH payloads over `max_publish_payload` are rejected before any
/// fan-out/spool work starts, proven here with a tiny cap rather than the
/// real default.
#[test]
fn publish_over_max_payload_is_rejected() {
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 2,
        ..Default::default()
    })
    .unwrap();
    let broker = Arc::new(BrokerState::new());
    let config = MqttConfig::new("127.0.0.1:0".parse().unwrap(), broker).with_max_publish_payload(8);
    let service = MqttService::new(config);
    let addr = service.start(&rt).unwrap();

    let mut publisher = wait_connect(addr);
    publisher.write_all(&connect_packet("oversized-publisher")).unwrap();
    let _ = read_exact_timeout(&mut publisher, 4);

    let publish_wire = encode::encode_publish(
        "t",
        crate::codec::QoS::AtMostOnce,
        false,
        false,
        0,
        b"this payload is over eight bytes",
        &Properties::new(),
        ProtocolVersion::V311,
    );
    publisher.write_all(&publish_wire).unwrap();

    // The server disconnects rather than accepting the oversized PUBLISH.
    let mut buf = [0u8; 16];
    let n = publisher.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "server should have closed the connection, got {n} bytes");

    rt.shutdown();
}

#[test]
fn retained_message_delivered_on_new_subscribe() {
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let broker = Arc::new(BrokerState::new());
    let config = MqttConfig::new("127.0.0.1:0".parse().unwrap(), broker);
    let service = MqttService::new(config);
    let addr = service.start(&rt).unwrap();

    let mut publisher = wait_connect(addr);
    publisher.write_all(&connect_packet("retainer")).unwrap();
    let _ = read_exact_timeout(&mut publisher, 4);
    let publish_wire = encode::encode_publish(
        "status/online",
        crate::codec::QoS::AtMostOnce,
        false,
        true, // retain
        0,
        b"yes",
        &Properties::new(),
        ProtocolVersion::V311,
    );
    publisher.write_all(&publish_wire).unwrap();
    std::thread::sleep(Duration::from_millis(50));

    let mut sub = wait_connect(addr);
    sub.write_all(&connect_packet("late-subscriber")).unwrap();
    let _ = read_exact_timeout(&mut sub, 4);

    sub.write_all(&subscribe_packet(1, "status/online", ProtocolVersion::V311)).unwrap();
    let _ = read_exact_timeout(&mut sub, 5); // SUBACK

    let mut buf = vec![0u8; 256];
    let n = sub.read(&mut buf).unwrap();
    let received = &buf[..n];
    assert_eq!(received[0] & 0xF1, 0x31, "expected a retained PUBLISH (RETAIN bit set)");
    assert!(String::from_utf8_lossy(received).contains("status/online"));

    rt.shutdown();
}

#[test]
fn v5_session_resume_after_unclean_disconnect_preserves_subscription() {
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 2,
        ..Default::default()
    })
    .unwrap();
    let broker = Arc::new(BrokerState::new());
    let config = MqttConfig::new("127.0.0.1:0".parse().unwrap(), broker);
    let service = MqttService::new(config);
    let addr = service.start(&rt).unwrap();

    // First connection: non-clean-start with a 60s Session Expiry, subscribe,
    // then drop the socket without sending DISCONNECT (unclean). CONNACK
    // carries a SESSION_EXPIRY_INTERVAL property (echoed back), so read
    // whatever's available rather than assuming a fixed byte count.
    let mut first = wait_connect(addr);
    first.write_all(&v5_connect_packet("resumable", false, 60)).unwrap();
    let mut buf = vec![0u8; 256];
    let n = first.read(&mut buf).unwrap();
    let connack = &buf[..n];
    assert_eq!(connack[0], 0x20);
    assert_eq!(connack[3], 0x00, "expected accepted");
    assert_eq!(connack[2] & 0x01, 0x00, "first CONNECT: session_present must be false");
    first.write_all(&subscribe_packet(1, "resume/topic", ProtocolVersion::V5)).unwrap();
    let n_suback = first.read(&mut buf).unwrap();
    assert_eq!(buf[0], 0x90, "expected SUBACK fixed header byte");
    assert_eq!(buf[n_suback - 1], 0x00, "expected granted QoS 0");
    drop(first); // unclean disconnect — orphan, don't unregister

    // Give the reactor a moment to process the disconnect and orphan the session.
    std::thread::sleep(Duration::from_millis(100));

    // Second connection, same client id, non-clean-start: should resume.
    let mut second = wait_connect(addr);
    second.write_all(&v5_connect_packet("resumable", false, 60)).unwrap();
    let n2 = second.read(&mut buf).unwrap();
    let connack2 = &buf[..n2];
    assert_eq!(connack2[0], 0x20);
    assert_eq!(connack2[3], 0x00, "expected accepted");
    assert_eq!(connack2[2] & 0x01, 0x01, "resumed CONNECT: session_present must be true");

    // The old subscription should still be active — publish and confirm delivery
    // without the resumed connection sending SUBSCRIBE again.
    let mut publisher = wait_connect(addr);
    publisher.write_all(&connect_packet("publisher")).unwrap();
    let _ = read_exact_timeout(&mut publisher, 4);
    let publish_wire = encode::encode_publish(
        "resume/topic",
        crate::codec::QoS::AtMostOnce,
        false,
        false,
        0,
        b"still subscribed",
        &Properties::new(),
        ProtocolVersion::V311,
    );
    publisher.write_all(&publish_wire).unwrap();

    let mut buf = vec![0u8; 256];
    let n = second.read(&mut buf).unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("still subscribed"));

    rt.shutdown();
}

#[test]
fn real_client_publishes_and_subscribes_against_real_server() {
    use crate::client::{MqttClient, MqttClientControl, MqttClientDriver, MqttClientHandlerFactory};
    use std::sync::mpsc;
    use std::sync::Mutex;

    let rt = Arc::new(
        Runtime::start(RuntimeConfig {
            worker_threads: 2,
            ..Default::default()
        })
        .unwrap(),
    );
    let broker = Arc::new(BrokerState::new());
    let config = MqttConfig::new("127.0.0.1:0".parse().unwrap(), broker);
    let service = MqttService::new(config);
    let addr = service.start(&rt).unwrap();

    // Subscriber driver: on CONNACK, subscribe; report the first received
    // message body (topic, payload) back to the test thread.
    struct SubDriver {
        tx: Mutex<Option<mpsc::Sender<(String, Vec<u8>)>>>,
        topic: Mutex<String>,
        buf: Mutex<Vec<u8>>,
    }
    impl MqttClientDriver for SubDriver {
        fn on_connack(&mut self, client: &mut dyn MqttClientControl, _session_present: bool, reason_code: u8, _properties: &Properties) {
            assert_eq!(reason_code, 0);
            client.subscribe(&[crate::codec::SubscribeFilter {
                topic_filter: "client/topic".into(),
                max_qos: crate::codec::QoS::AtMostOnce,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
            }]);
        }
        fn on_message_start(&mut self, topic: &str, _qos: crate::codec::QoS, _retain: bool, _packet_id: u16, _properties: &Properties, _payload_len: u32) {
            *self.topic.lock().unwrap() = topic.to_string();
            self.buf.lock().unwrap().clear();
        }
        fn on_message_data(&mut self, data: &[u8]) {
            self.buf.lock().unwrap().extend_from_slice(data);
        }
        fn on_message_complete(&mut self, _client: &mut dyn MqttClientControl) {
            if let Some(tx) = self.tx.lock().unwrap().take() {
                let _ = tx.send((self.topic.lock().unwrap().clone(), self.buf.lock().unwrap().clone()));
            }
        }
        fn on_suback(&mut self, _client: &mut dyn MqttClientControl, _packet_id: u16, reason_codes: &[u8]) {
            assert_eq!(reason_codes, &[0]);
        }
        fn on_unsuback(&mut self, _client: &mut dyn MqttClientControl, _packet_id: u16, _reason_codes: &[u8]) {}
        fn on_publish_acked(&mut self, _client: &mut dyn MqttClientControl, _packet_id: u16) {}
        fn on_ping_resp(&mut self, _client: &mut dyn MqttClientControl) {}
        fn on_server_disconnect(&mut self, _reason_code: u8, _properties: &Properties) {}
        fn on_error(&mut self, err: &std::io::Error) {
            panic!("subscriber client error: {err}");
        }
        fn on_disconnected(&mut self) {}
    }
    struct SubFactory(mpsc::Sender<(String, Vec<u8>)>);
    impl MqttClientHandlerFactory for SubFactory {
        fn create(&self) -> Box<dyn MqttClientDriver> {
            Box::new(SubDriver {
                tx: Mutex::new(Some(self.0.clone())),
                topic: Mutex::new(String::new()),
                buf: Mutex::new(Vec::new()),
            })
        }
    }

    // Publisher driver: on CONNACK, publish once.
    struct PubDriver;
    impl MqttClientDriver for PubDriver {
        fn on_connack(&mut self, client: &mut dyn MqttClientControl, _session_present: bool, reason_code: u8, _properties: &Properties) {
            assert_eq!(reason_code, 0);
            client.publish("client/topic", b"hello from the real client", crate::codec::QoS::AtMostOnce, false, &Properties::new());
        }
        fn on_message_start(&mut self, _topic: &str, _qos: crate::codec::QoS, _retain: bool, _packet_id: u16, _properties: &Properties, _payload_len: u32) {}
        fn on_message_data(&mut self, _data: &[u8]) {}
        fn on_message_complete(&mut self, _client: &mut dyn MqttClientControl) {}
        fn on_suback(&mut self, _client: &mut dyn MqttClientControl, _packet_id: u16, _reason_codes: &[u8]) {}
        fn on_unsuback(&mut self, _client: &mut dyn MqttClientControl, _packet_id: u16, _reason_codes: &[u8]) {}
        fn on_publish_acked(&mut self, _client: &mut dyn MqttClientControl, _packet_id: u16) {}
        fn on_ping_resp(&mut self, _client: &mut dyn MqttClientControl) {}
        fn on_server_disconnect(&mut self, _reason_code: u8, _properties: &Properties) {}
        fn on_error(&mut self, err: &std::io::Error) {
            panic!("publisher client error: {err}");
        }
        fn on_disconnected(&mut self) {}
    }
    struct PubFactory;
    impl MqttClientHandlerFactory for PubFactory {
        fn create(&self) -> Box<dyn MqttClientDriver> {
            Box::new(PubDriver)
        }
    }

    let (tx, rx) = mpsc::channel();
    MqttClient::from_addr(addr, "subscriber-client")
        .connect(&rt, Arc::new(SubFactory(tx)))
        .unwrap();
    // Give the subscriber time to CONNECT + SUBSCRIBE before the publisher fires.
    std::thread::sleep(Duration::from_millis(100));

    MqttClient::from_addr(addr, "publisher-client")
        .connect(&rt, Arc::new(PubFactory))
        .unwrap();

    let (topic, payload) = rx.recv_timeout(Duration::from_secs(2)).expect("subscriber never received the message");
    assert_eq!(topic, "client/topic");
    assert_eq!(payload, b"hello from the real client");

    // `rt` is `Arc<Runtime>` here (client connectors need `&Arc<Runtime>`),
    // so there's no single owner to call `Runtime::shutdown` on — drop it,
    // same as the standalone client examples.
    drop(rt);
}

/// Proves the point of threading `ConnHandle` through `hopf-websocket`
/// (see [`crate::server::ws`]): a subscriber connected over WS and a publisher
/// connected over plain TCP, sharing one [`BrokerState`], can reach each
/// other exactly like two TCP connections do.
#[cfg(feature = "websocket")]
#[test]
fn ws_subscriber_and_tcp_publisher_share_broker_state() {
    use hopf_core::{ProtocolHandler, TcpListenerConfig};
    use hopf_http::{CleartextHttpEndpoint, HttpLimits, ServerHandlerFactory};
    use hopf_websocket::{write_frame, Opcode, WebSocketConfig, WebSocketFactory};

    use crate::server::DefaultMqttHandlerFactory;
    use crate::server::ws::MqttWsFactory;

    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 2,
        ..Default::default()
    })
    .unwrap();
    let broker = Arc::new(BrokerState::new());

    // TCP listener: the publisher connects here.
    let tcp_config = MqttConfig::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&broker));
    let tcp_service = MqttService::new(tcp_config);
    let tcp_addr = tcp_service.start(&rt).unwrap();

    // WS listener: the subscriber connects here, sharing the same broker.
    let ws_config = Arc::new(MqttConfig::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&broker)));
    let ws_factory = Arc::new(WebSocketFactory::new(
        MqttWsFactory::new(ws_config, Arc::new(DefaultMqttHandlerFactory::new(None))),
        WebSocketConfig::default(),
    ));
    let (ws_addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
            Box::new(CleartextHttpEndpoint::new(
                Arc::clone(&ws_factory) as Arc<dyn ServerHandlerFactory>,
                HttpLimits::default(),
            )) as Box<dyn ProtocolHandler>
        }))
        .unwrap();

    // WS subscriber: HTTP upgrade handshake, then MQTT CONNECT + SUBSCRIBE as
    // binary WS frames (client frames must be masked, per RFC 6455 §5.1).
    let mut ws = wait_connect(ws_addr);
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let req = format!(
        "GET /mqtt HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    ws.write_all(req.as_bytes()).unwrap();
    let mut buf = [0u8; 4096];
    let n = ws.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("101"), "{resp}");

    let mut connect_frame = Vec::new();
    write_frame(&mut connect_frame, true, Opcode::Binary, Some([1, 2, 3, 4]), &connect_packet("ws-subscriber"));
    ws.write_all(&connect_frame).unwrap();
    let connack_payload = read_ws_frame(&mut ws);
    assert_eq!(connack_payload[0], 0x20, "expected CONNACK fixed header byte");
    assert_eq!(connack_payload[3], 0x00, "expected CONNACK accepted reason code");

    let mut sub_frame = Vec::new();
    write_frame(
        &mut sub_frame,
        true,
        Opcode::Binary,
        Some([5, 6, 7, 8]),
        &subscribe_packet(0x11, "ws/topic", ProtocolVersion::V311),
    );
    ws.write_all(&sub_frame).unwrap();
    let suback_payload = read_ws_frame(&mut ws);
    assert_eq!(suback_payload[0], 0x90, "expected SUBACK fixed header byte");
    assert_eq!(*suback_payload.last().unwrap(), 0x00, "expected granted QoS 0");

    // TCP publisher publishes to the same topic; the WS subscriber should
    // receive it via the shared BrokerState — cross-transport fan-out, not
    // just cross-connection within one transport.
    let mut publisher = wait_connect(tcp_addr);
    publisher.write_all(&connect_packet("tcp-publisher")).unwrap();
    let _ = read_exact_timeout(&mut publisher, 4);
    let publish_wire = encode::encode_publish(
        "ws/topic",
        crate::codec::QoS::AtMostOnce,
        false,
        false,
        0,
        b"hello over ws",
        &Properties::new(),
        ProtocolVersion::V311,
    );
    publisher.write_all(&publish_wire).unwrap();

    let received = read_ws_frame(&mut ws);
    assert_eq!(received[0] & 0xF0, 0x30, "expected a PUBLISH fixed header");
    let text = String::from_utf8_lossy(&received);
    assert!(text.contains("ws/topic"));
    assert!(text.contains("hello over ws"));

    rt.shutdown();
}

/// Read one unfragmented WebSocket frame's payload. Server-to-client frames
/// are never masked (RFC 6455 §5.1), and every payload used in these tests
/// fits in the 1-byte length form.
#[cfg(feature = "websocket")]
fn read_ws_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).unwrap();
    let mut len = (header[1] & 0x7F) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        stream.read_exact(&mut ext).unwrap();
        len = u16::from_be_bytes(ext) as usize;
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).unwrap();
    payload
}
