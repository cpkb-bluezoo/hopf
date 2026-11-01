// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-process tests of [`MqttControlHandler`]: each test plays one or more
//! MQTT clients over [`Peer`]s that share a broker, writing packets and
//! checking what the server sends back and what it delivers to the others.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hopf_auth::{create_client, PasswordStore, SaslClientStep, SaslMechanism};
use hopf_core::testing::Peer;
use hopf_core::{Runtime, RuntimeConfig};

use super::*;
use crate::codec::decode;
use crate::codec::packet::reason;
use crate::server::handler::{DefaultMqttHandlerFactory, MqttHandlerFactory};

const V3: ProtocolVersion = ProtocolVersion::V311;
const V5: ProtocolVersion = ProtocolVersion::V5;

fn runtime() -> Arc<Runtime> {
    static RT: OnceLock<Arc<Runtime>> = OnceLock::new();
    Arc::clone(RT.get_or_init(|| Arc::new(Runtime::start(RuntimeConfig::default()).unwrap())))
}

/// One decoded packet off the wire.
#[derive(Debug, Clone)]
struct Pkt {
    ty: u8,
    flags: u8,
    body: Vec<u8>,
}

const CONNACK: u8 = 2;
const PUBLISH: u8 = 3;
const PUBCOMP: u8 = 7;
const SUBACK: u8 = 9;
const DISCONNECT: u8 = 14;
const AUTH: u8 = 15;

fn packets(mut b: &[u8]) -> Vec<Pkt> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (ty, flags) = (b[0] >> 4, b[0] & 0x0F);
        let (mut len, mut shift, mut i) = (0usize, 0, 1);
        loop {
            let Some(&byte) = b.get(i) else {
                return out; // the rest of the length has not arrived
            };
            len |= ((byte & 0x7F) as usize) << shift;
            i += 1;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        if b.len() < i + len {
            return out; // the rest of the packet has not arrived
        }
        out.push(Pkt { ty, flags, body: b[i..i + len].to_vec() });
        b = &b[i + len..];
    }
    out
}

fn types(b: &[u8]) -> Vec<u8> {
    packets(b).iter().map(|p| p.ty).collect()
}

type Server = Peer<MqttControlHandler>;

#[derive(Clone)]
struct Opts {
    credentials: Option<Arc<dyn hopf_auth::CredentialStore>>,
    anonymous: bool,
    max_payload: Option<u32>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { credentials: None, anonymous: true, max_payload: None }
    }
}

struct RejectPublish(u8);
impl PublishHandler for RejectPublish {
    fn authorize(&mut self, _: &str, topic: &str, _: QoS, _: bool, _: &MqttConnectionMetadata) -> PublishDecision {
        if topic.starts_with("denied") { PublishDecision::Reject(self.0) } else { PublishDecision::Accept }
    }
}

struct SubscribePolicy;
impl SubscribeHandler for SubscribePolicy {
    fn authorize(&mut self, _: &str, filter: &SubscribeFilter, _: &MqttConnectionMetadata) -> SubscribeDecision {
        if filter.topic_filter.starts_with("secret") {
            SubscribeDecision::Reject(reason::NOT_AUTHORIZED)
        } else {
            SubscribeDecision::Accept(QoS::AtMostOnce)
        }
    }
}

fn broker() -> Arc<BrokerState> {
    Arc::new(BrokerState::new())
}

fn connection_with(
    broker: &Arc<BrokerState>,
    opts: &Opts,
    publish: Option<Box<dyn PublishHandler>>,
    subscribe: Option<Box<dyn SubscribeHandler>>,
) -> Server {
    let mut config = MqttConfig::new("127.0.0.1:1883".parse().unwrap(), Arc::clone(broker));
    if opts.anonymous {
        config = config.allow_anonymous();
    }
    if let Some(c) = &opts.credentials {
        config = config.with_credentials(Arc::clone(c));
    }
    if let Some(m) = opts.max_payload {
        config = config.with_max_publish_payload(m);
    }
    let factory = DefaultMqttHandlerFactory::new(opts.credentials.clone(), opts.anonymous);
    let handler = MqttControlHandler::new(
        Arc::new(config),
        factory.create(),
        publish.unwrap_or_else(|| factory.create_publish()),
        subscribe.unwrap_or_else(|| factory.create_subscribe()),
        MqttServerMetrics::shared(),
        runtime(),
    );
    Peer::connect(handler, |h| h.busy.load(Ordering::Relaxed))
}

fn connection(broker: &Arc<BrokerState>) -> Server {
    connection_with(broker, &Opts::default(), None, None)
}

/// Run `wire` and keep playing the reactor until the output has at least
/// `want` packets (storage work completes on other threads) or 3 s pass.
fn run_for(peer: &mut Server, wire: &[u8], want: usize) -> Vec<u8> {
    let mut out = peer.run_bytes(wire);
    let deadline = Instant::now() + Duration::from_secs(10);
    while packets(&out).len() < want && Instant::now() < deadline && !peer.is_closed() {
        std::thread::sleep(Duration::from_millis(2));
        peer.pump();
        out.extend(peer.take_bytes());
    }
    out
}

/// What arrives for `peer` (deliveries from other connections): waits for
/// `want` packets, then a moment longer in case more than that were sent.
fn arrivals(peer: &mut Server, want: usize) -> Vec<u8> {
    let mut out = peer.take_bytes();
    let deadline = Instant::now() + Duration::from_secs(10);
    while packets(&out).len() < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
        peer.pump();
        out.extend(peer.take_bytes());
    }
    std::thread::sleep(Duration::from_millis(30));
    peer.pump();
    out.extend(peer.take_bytes());
    out
}

fn connect_packet(version: ProtocolVersion, id: &str) -> ConnectPacket {
    ConnectPacket {
        version,
        clean_session: true,
        keep_alive: 0,
        properties: Properties::new(),
        client_id: id.into(),
        will: None,
        username: None,
        password: None,
    }
}

fn connect_wire(version: ProtocolVersion, id: &str) -> Vec<u8> {
    encode::encode_connect(&connect_packet(version, id))
}

fn up_with(broker: &Arc<BrokerState>, version: ProtocolVersion, id: &str) -> Server {
    let mut peer = connection(broker);
    let out = run_for(&mut peer, &connect_wire(version, id), 1);
    assert_eq!(types(&out), [CONNACK], "{version:?} {id}");
    assert_eq!(out[3], 0, "accepted");
    peer
}

fn up(version: ProtocolVersion) -> (Server, Arc<BrokerState>) {
    let b = broker();
    (up_with(&b, version, "c1"), b)
}

fn no_props() -> Properties {
    Properties::new()
}

fn filter(f: &str, qos: QoS) -> SubscribeFilter {
    SubscribeFilter { topic_filter: f.into(), max_qos: qos, no_local: false, retain_as_published: false, retain_handling: 0 }
}

fn subscribe_wire(id: u16, filters: &[SubscribeFilter], version: ProtocolVersion) -> Vec<u8> {
    encode::encode_subscribe(id, filters, &no_props(), version)
}

fn publish_wire(topic: &str, payload: &[u8], qos: QoS, retain: bool, id: u16, version: ProtocolVersion) -> Vec<u8> {
    let props = no_props();
    encode::encode_publish(
        &encode::PublishFields { topic, qos, dup: false, retain, packet_id: id, props: &props, version },
        payload,
    )
}

/// `(topic, payload, qos, retain, packet id)` of a PUBLISH off the wire.
fn publish_of(p: &Pkt, version: ProtocolVersion) -> (String, Vec<u8>, u8, bool, u16) {
    assert_eq!(p.ty, PUBLISH);
    let (h, used) = decode::decode_publish_var_header(&p.body, p.flags, p.body.len() as u32, version)
        .unwrap()
        .expect("complete header");
    (h.topic, p.body[used..].to_vec(), h.qos.value(), h.retain, h.packet_id)
}

fn subscribed(b: &Arc<BrokerState>, version: ProtocolVersion, id: &str, f: &str) -> Server {
    let mut sub = up_with(b, version, id);
    let out = sub.run_bytes(&subscribe_wire(1, &[filter(f, QoS::AtMostOnce)], version));
    assert_eq!(types(&out), [SUBACK]);
    sub
}

/// Send `wire` and gather everything that comes back for it: the reply and
/// any deliveries it causes, which may arrive with the reply or after it.
fn run_and_collect(peer: &mut Server, wire: &[u8], want: usize) -> Vec<u8> {
    let mut out = peer.run_bytes(wire);
    let deadline = Instant::now() + Duration::from_secs(10);
    while packets(&out).len() < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
        peer.pump();
        out.extend(peer.take_bytes());
    }
    std::thread::sleep(Duration::from_millis(30));
    peer.pump();
    out.extend(peer.take_bytes());
    out
}

fn connack_of(out: &[u8], version: ProtocolVersion) -> (bool, u8, Properties) {
    let pk = packets(out);
    assert_eq!(pk[0].ty, CONNACK, "{out:?}");
    decode::decode_connack(&pk[0].body, version).unwrap()
}

fn disconnect_reason(out: &[u8]) -> Option<u8> {
    packets(out).iter().find(|p| p.ty == DISCONNECT).map(|p| p.body.first().copied().unwrap_or(0))
}

// -- CONNECT -----------------------------------------------------------------

#[test]
fn a_v311_connect_is_accepted() {
    let mut peer = connection(&broker());
    let out = run_for(&mut peer, &connect_wire(V3, "a"), 1);
    assert_eq!(out, encode::encode_connack(false, 0, &no_props(), V3));
    assert!(!peer.is_closed());
}

#[test]
fn a_v5_connack_advertises_what_the_server_offers() {
    let mut peer = connection(&broker());
    let out = run_for(&mut peer, &connect_wire(V5, "a"), 1);
    let (present, code, props) = connack_of(&out, V5);
    assert!(!present);
    assert_eq!(code, 0);
    assert_eq!(props.get_u16(property::TOPIC_ALIAS_MAXIMUM), Some(SERVER_TOPIC_ALIAS_MAXIMUM));
    assert_eq!(props.get_byte(property::SHARED_SUBSCRIPTION_AVAILABLE), Some(1));
    assert_eq!(props.get_u16(property::RECEIVE_MAXIMUM), None, "unlimited is not advertised");
}

#[test]
fn the_clients_receive_maximum_and_session_expiry_are_echoed_in_a_v5_connack() {
    let mut p = connect_packet(V5, "a");
    p.properties.set_u16(property::RECEIVE_MAXIMUM, 7);
    p.properties.set_u32(property::SESSION_EXPIRY_INTERVAL, 60);
    let mut peer = connection(&broker());
    let out = run_for(&mut peer, &encode::encode_connect(&p), 1);
    let (_, _, props) = connack_of(&out, V5);
    assert_eq!(props.get_u16(property::RECEIVE_MAXIMUM), Some(7));
    assert_eq!(props.get_u32(property::SESSION_EXPIRY_INTERVAL), Some(60));
}

#[test]
fn a_v311_connack_has_no_properties() {
    let mut p = connect_packet(V3, "a");
    p.clean_session = true;
    let mut peer = connection(&broker());
    let out = run_for(&mut peer, &encode::encode_connect(&p), 1);
    assert_eq!(out.len(), 4);
}

#[test]
fn an_empty_client_id_needs_a_clean_session() {
    for (version, code) in [(V3, reason::connack_v311::IDENTIFIER_REJECTED), (V5, reason::CLIENT_IDENTIFIER_NOT_VALID)] {
        let mut p = connect_packet(version, "");
        p.clean_session = false;
        let mut peer = connection(&broker());
        let out = run_for(&mut peer, &encode::encode_connect(&p), 1);
        assert_eq!(connack_of(&out, version).1, code, "{version:?}");
        assert!(peer.is_closed());
    }
}

#[test]
fn an_empty_client_id_with_a_clean_session_gets_one_assigned_and_told_to_a_v5_client() {
    // MQTT 5.0 section 3.2.2.3.7: the server must send the identifier it chose.
    let mut peer = connection(&broker());
    let out = run_for(&mut peer, &connect_wire(V5, ""), 1);
    let (_, code, props) = connack_of(&out, V5);
    assert_eq!(code, 0);
    let assigned = props.get_utf8(property::ASSIGNED_CLIENT_IDENTIFIER).expect("Assigned Client Identifier");
    assert!(!assigned.is_empty());
    assert_eq!(peer.handler.meta.client_id.as_deref(), Some(assigned));
}

#[test]
fn an_empty_client_id_is_accepted_for_v311_too() {
    let mut peer = connection(&broker());
    let out = run_for(&mut peer, &connect_wire(V3, ""), 1);
    assert_eq!(out, encode::encode_connack(false, 0, &no_props(), V3));
}

#[test]
fn assigned_client_ids_differ() {
    let b = broker();
    let (mut a, mut c) = (connection(&b), connection(&b));
    run_for(&mut a, &connect_wire(V3, ""), 1);
    run_for(&mut c, &connect_wire(V3, ""), 1);
    assert_ne!(a.handler.meta.client_id, c.handler.meta.client_id);
}

#[test]
fn without_credentials_or_anonymous_access_a_connect_is_refused() {
    for (version, code) in [(V3, reason::connack_v311::NOT_AUTHORIZED), (V5, reason::NOT_AUTHORIZED)] {
        let mut peer = connection_with(&broker(), &Opts { anonymous: false, ..Opts::default() }, None, None);
        let out = run_for(&mut peer, &connect_wire(version, "a"), 1);
        assert_eq!(connack_of(&out, version).1, code, "{version:?}");
        assert!(peer.is_closed());
    }
}

#[test]
fn credentials_are_checked_on_connect() {
    let store: Arc<dyn hopf_auth::CredentialStore> = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let opts = Opts { credentials: Some(store), anonymous: false, max_payload: None };
    for (user, pass, ok) in [("alice", "secret", true), ("alice", "wrong", false), ("bob", "secret", false)] {
        let mut p = connect_packet(V3, "a");
        p.username = Some(user.into());
        p.password = Some(pass.as_bytes().to_vec());
        let mut peer = connection_with(&broker(), &opts, None, None);
        let out = run_for(&mut peer, &encode::encode_connect(&p), 1);
        let code = connack_of(&out, V3).1;
        if ok {
            assert_eq!(code, 0);
            assert!(!peer.is_closed());
        } else {
            assert_eq!(code, reason::connack_v311::BAD_USER_NAME_OR_PASSWORD, "{user}/{pass}");
            assert!(peer.is_closed());
        }
    }
    let mut peer = connection_with(&broker(), &opts, None, None);
    let out = run_for(&mut peer, &connect_wire(V3, "a"), 1);
    assert_eq!(connack_of(&out, V3).1, reason::connack_v311::BAD_USER_NAME_OR_PASSWORD, "no credentials at all");
}

#[test]
fn a_second_connect_ends_the_connection() {
    let (mut peer, _) = up(V5);
    let out = peer.run_bytes(&connect_wire(V5, "c1"));
    assert_eq!(disconnect_reason(&out), Some(reason::PROTOCOL_ERROR));
    assert!(peer.is_closed());

    let (mut peer, _) = up(V3);
    let out = peer.run_bytes(&connect_wire(V3, "c1"));
    assert!(out.is_empty(), "3.1.1 has no server DISCONNECT");
    assert!(peer.is_closed());
}

#[test]
fn a_connect_split_into_single_bytes_is_accepted() {
    let mut peer = connection(&broker());
    let mut out = peer.run_chunked_bytes(&connect_wire(V3, "a"), 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    while out.is_empty() && Instant::now() < deadline {
        peer.pump();
        out.extend(peer.take_bytes());
    }
    assert_eq!(out, encode::encode_connack(false, 0, &no_props(), V3));
}

#[test]
fn a_client_may_not_send_what_only_servers_send() {
    let wires: Vec<(&str, Vec<u8>)> = vec![
        ("CONNACK", encode::encode_connack(false, 0, &no_props(), V3)),
        ("SUBACK", encode::encode_suback(1, &[0], &no_props(), V3)),
        ("UNSUBACK", encode::encode_unsuback(1, &[], &no_props(), V3)),
        ("PINGRESP", encode::encode_pingresp()),
    ];
    for (name, wire) in wires {
        let (mut peer, _) = up(V3);
        peer.run_bytes(&wire);
        assert!(peer.is_closed(), "{name}");
    }
}

#[test]
fn nothing_but_connect_may_start_a_connection() {
    let wires: Vec<(&str, Vec<u8>)> = vec![
        ("PINGREQ", encode::encode_pingreq()),
        ("SUBSCRIBE", subscribe_wire(1, &[filter("a", QoS::AtMostOnce)], V3)),
        ("UNSUBSCRIBE", encode::encode_unsubscribe(1, &["a".to_string()], &no_props(), V3)),
        ("PUBLISH", publish_wire("a", b"x", QoS::AtMostOnce, false, 0, V3)),
        ("PUBACK", encode::encode_puback(1, 0, &no_props(), V3)),
        ("PUBREL", encode::encode_pubrel(1, 0, &no_props(), V3)),
        ("PUBREC", encode::encode_pubrec(1, 0, &no_props(), V3)),
        ("DISCONNECT", encode::encode_disconnect(0, &no_props(), V3)),
    ];
    for (name, wire) in wires {
        let mut peer = connection(&broker());
        let out = peer.run_bytes(&wire);
        assert!(peer.is_closed(), "{name} before CONNECT must end the connection");
        assert!(out.is_empty(), "{name}: nothing is answered before CONNECT");
    }
}

#[test]
fn garbage_ends_the_connection() {
    let (mut peer, _) = up(V3);
    peer.run_bytes(&[0x00, 0x00]);
    assert!(peer.is_closed());
}

// -- PING, SUBSCRIBE, UNSUBSCRIBE --------------------------------------------

#[test]
fn pingreq_is_answered() {
    let (mut peer, _) = up(V3);
    assert_eq!(peer.run_bytes(&encode::encode_pingreq()), encode::encode_pingresp());
}

#[test]
fn subscribe_grants_what_was_asked_and_unsubscribe_reports_what_existed() {
    for version in [V3, V5] {
        let (mut peer, _) = up(version);
        let out = peer.run_bytes(&subscribe_wire(
            5,
            &[filter("a/+", QoS::AtLeastOnce), filter("b/#", QoS::ExactlyOnce), filter("c", QoS::AtMostOnce)],
            version,
        ));
        assert_eq!(out, encode::encode_suback(5, &[1, 2, 0], &no_props(), version), "{version:?}");
        let out = peer.run_bytes(&encode::encode_unsubscribe(6, &["a/+".to_string(), "zz".to_string()], &no_props(), version));
        let want = if version == V5 {
            vec![reason::SUCCESS, reason::NO_SUBSCRIPTION_EXISTED]
        } else {
            vec![]
        };
        assert_eq!(out, encode::encode_unsuback(6, &want, &no_props(), version), "{version:?}");
    }
}

#[test]
fn an_invalid_topic_filter_is_refused_in_the_suback() {
    let (mut peer, _) = up(V5);
    let out = peer.run_bytes(&subscribe_wire(1, &[filter("a/#/b", QoS::AtMostOnce), filter("ok", QoS::AtMostOnce)], V5));
    assert_eq!(out, encode::encode_suback(1, &[reason::TOPIC_FILTER_INVALID, 0], &no_props(), V5));
}

#[test]
fn the_subscribe_policy_can_refuse_or_lower_each_filter() {
    let b = broker();
    let mut peer = connection_with(&b, &Opts::default(), None, Some(Box::new(SubscribePolicy)));
    run_for(&mut peer, &connect_wire(V5, "c"), 1);
    let out = peer.run_bytes(&subscribe_wire(
        1,
        &[filter("secret/x", QoS::AtLeastOnce), filter("open/x", QoS::ExactlyOnce)],
        V5,
    ));
    assert_eq!(out, encode::encode_suback(1, &[reason::NOT_AUTHORIZED, 0], &no_props(), V5));
    // the refused filter really is not subscribed
    let mut publisher = up_with(&b, V5, "p");
    publisher.run_bytes(&publish_wire("secret/x", b"x", QoS::AtMostOnce, false, 0, V5));
    assert!(arrivals(&mut peer, 0).is_empty());
}

#[test]
fn subscribing_counts_in_the_metrics() {
    let (mut peer, _) = up(V3);
    peer.run_bytes(&subscribe_wire(1, &[filter("a", QoS::AtMostOnce)], V3));
    assert_eq!(peer.handler.metrics.subscribes.load(Ordering::Relaxed), 1);
}

// -- PUBLISH -----------------------------------------------------------------

#[test]
fn a_qos0_publish_reaches_a_subscriber() {
    let b = broker();
    let mut sub = subscribed(&b, V3, "sub", "news/#");
    let mut publisher = up_with(&b, V3, "pub");
    let out = publisher.run_bytes(&publish_wire("news/uk", b"hello", QoS::AtMostOnce, false, 0, V3));
    assert!(out.is_empty(), "no acknowledgement for QoS 0");
    let got = packets(&arrivals(&mut sub, 1));
    assert_eq!(got.len(), 1);
    assert_eq!(publish_of(&got[0], V3), ("news/uk".into(), b"hello".to_vec(), 0, false, 0));
}

#[test]
fn a_publish_matching_no_filter_is_dropped() {
    let b = broker();
    let mut sub = subscribed(&b, V3, "sub", "news/#");
    let mut publisher = up_with(&b, V3, "pub");
    publisher.run_bytes(&publish_wire("sport/uk", b"x", QoS::AtMostOnce, false, 0, V3));
    assert!(arrivals(&mut sub, 0).is_empty());
}

#[test]
fn a_qos1_publish_is_acknowledged() {
    for version in [V3, V5] {
        let (mut peer, _) = up(version);
        let out = run_for(&mut peer, &publish_wire("a", b"hi", QoS::AtLeastOnce, false, 11, version), 1);
        assert_eq!(out, encode::encode_puback(11, 0, &no_props(), version), "{version:?}");
    }
}

#[test]
fn a_qos2_publish_goes_pubrec_pubrel_pubcomp() {
    for version in [V3, V5] {
        let (mut peer, _) = up(version);
        let out = run_for(&mut peer, &publish_wire("a", b"hi", QoS::ExactlyOnce, false, 12, version), 1);
        assert_eq!(out, encode::encode_pubrec(12, 0, &no_props(), version));
        let out = peer.run_bytes(&encode::encode_pubrel(12, 0, &no_props(), version));
        assert_eq!(out, encode::encode_pubcomp(12, 0, &no_props(), version));
        assert!(peer.handler.session_version().is_some());
    }
}

#[test]
fn a_qos2_resend_before_pubrel_is_acknowledged_again_but_delivered_once() {
    let b = broker();
    let mut sub = subscribed(&b, V3, "sub", "t");
    let mut publisher = up_with(&b, V3, "pub");
    let wire = publish_wire("t", b"once", QoS::ExactlyOnce, false, 3, V3);
    let first = run_for(&mut publisher, &wire, 1);
    assert_eq!(first, encode::encode_pubrec(3, 0, &no_props(), V3));
    let again = publisher.run_bytes(&wire);
    assert_eq!(again, encode::encode_pubrec(3, 0, &no_props(), V3));
    let got = packets(&arrivals(&mut sub, 1));
    assert_eq!(got.len(), 1, "delivered once: {got:?}");
}

#[test]
fn a_pubrel_for_an_unknown_id_is_answered() {
    // MQTT 5.0 section 3.6.2.1 would use 0x92 "Packet Identifier not found";
    // 3.1.1 has only the one form of PUBCOMP.
    let (mut peer, _) = up(V5);
    let out = peer.run_bytes(&encode::encode_pubrel(99, 0, &no_props(), V5));
    let pk = packets(&out);
    assert_eq!(pk[0].ty, PUBCOMP);
    let (id, code, _) = decode::decode_simple_ack(&pk[0].body, V5).unwrap();
    assert_eq!(id, 99);
    assert_eq!(code, reason::PACKET_IDENTIFIER_NOT_FOUND);
}

#[test]
fn qos_is_downgraded_to_what_the_subscriber_asked_for() {
    let b = broker();
    let mut sub = subscribed(&b, V3, "sub", "t");
    let mut publisher = up_with(&b, V3, "pub");
    run_for(&mut publisher, &publish_wire("t", b"x", QoS::AtLeastOnce, false, 1, V3), 1);
    let got = packets(&arrivals(&mut sub, 1));
    assert_eq!(publish_of(&got[0], V3).2, 0);
}

#[test]
fn a_qos1_subscriber_gets_a_qos1_delivery_it_can_acknowledge() {
    let b = broker();
    let mut sub = up_with(&b, V3, "sub");
    sub.run_bytes(&subscribe_wire(1, &[filter("t", QoS::AtLeastOnce)], V3));
    let mut publisher = up_with(&b, V3, "pub");
    run_for(&mut publisher, &publish_wire("t", b"x", QoS::AtLeastOnce, false, 1, V3), 1);
    let got = packets(&arrivals(&mut sub, 1));
    let (_, payload, qos, _, id) = publish_of(&got[0], V3);
    assert_eq!((payload.as_slice(), qos), (&b"x"[..], 1));
    assert_ne!(id, 0);
    sub.run_bytes(&encode::encode_puback(id, 0, &no_props(), V3));
    assert!(!sub.is_closed());
}

#[test]
fn a_wildcard_in_a_publish_topic_ends_the_connection() {
    for topic in ["a/+", "a/#", ""] {
        let (mut peer, _) = up(V3);
        peer.run_bytes(&publish_wire(topic, b"x", QoS::AtMostOnce, false, 0, V3));
        assert!(peer.is_closed(), "{topic:?}");
    }
}

#[test]
fn a_payload_over_the_limit_ends_the_connection_with_packet_too_large() {
    let b = broker();
    let mut peer = connection_with(&b, &Opts { max_payload: Some(8), ..Opts::default() }, None, None);
    run_for(&mut peer, &connect_wire(V5, "c"), 1);
    let out = peer.run_bytes(&publish_wire("a", &[0; 9], QoS::AtMostOnce, false, 0, V5));
    assert_eq!(disconnect_reason(&out), Some(reason::PACKET_TOO_LARGE));
    assert!(peer.is_closed());

    let mut ok = connection_with(&b, &Opts { max_payload: Some(8), ..Opts::default() }, None, None);
    run_for(&mut ok, &connect_wire(V5, "d"), 1);
    ok.run_bytes(&publish_wire("a", &[0; 8], QoS::AtMostOnce, false, 0, V5));
    assert!(!ok.is_closed(), "exactly the limit is fine");
}

#[test]
fn a_publish_policy_refusal_is_reported_in_the_ack_for_v5_and_fatal_for_v311() {
    let b = broker();
    // v5, QoS 1: PUBACK with the code
    let mut peer = connection_with(&b, &Opts::default(), Some(Box::new(RejectPublish(reason::NOT_AUTHORIZED))), None);
    run_for(&mut peer, &connect_wire(V5, "c"), 1);
    let out = peer.run_bytes(&publish_wire("denied/x", b"x", QoS::AtLeastOnce, false, 4, V5));
    assert_eq!(out, encode::encode_puback(4, reason::NOT_AUTHORIZED, &no_props(), V5));
    assert!(!peer.is_closed());
    // v5, QoS 2: PUBREC with the code
    let out = peer.run_bytes(&publish_wire("denied/x", b"x", QoS::ExactlyOnce, false, 5, V5));
    assert_eq!(out, encode::encode_pubrec(5, reason::NOT_AUTHORIZED, &no_props(), V5));
    // v5, QoS 0: nothing to ack, so DISCONNECT
    let out = peer.run_bytes(&publish_wire("denied/x", b"x", QoS::AtMostOnce, false, 0, V5));
    assert_eq!(disconnect_reason(&out), Some(reason::NOT_AUTHORIZED));
    assert!(peer.is_closed());
    // v3.1.1: just close
    let mut old = connection_with(&b, &Opts::default(), Some(Box::new(RejectPublish(reason::NOT_AUTHORIZED))), None);
    run_for(&mut old, &connect_wire(V3, "o"), 1);
    old.run_bytes(&publish_wire("denied/x", b"x", QoS::AtLeastOnce, false, 4, V3));
    assert!(old.is_closed());
}

#[test]
fn a_refused_qos2_publish_is_not_remembered_as_awaiting_release() {
    let b = broker();
    let mut peer = connection_with(&b, &Opts::default(), Some(Box::new(RejectPublish(reason::NOT_AUTHORIZED))), None);
    run_for(&mut peer, &connect_wire(V5, "c"), 1);
    peer.run_bytes(&publish_wire("denied/x", b"x", QoS::ExactlyOnce, false, 5, V5));
    let SessionState::Connected(s) = &peer.handler.session else { panic!() };
    assert!(s.awaiting_pubrel.is_empty());
}

#[test]
fn publishing_counts_in_the_metrics() {
    let (mut peer, _) = up(V3);
    run_for(&mut peer, &publish_wire("a", b"x", QoS::AtLeastOnce, false, 1, V3), 1);
    assert_eq!(peer.handler.metrics.publishes.load(Ordering::Relaxed), 1);
}

#[test]
fn a_large_payload_split_into_small_reads_is_delivered_whole() {
    let b = broker();
    let mut sub = subscribed(&b, V3, "sub", "big");
    let mut publisher = up_with(&b, V3, "pub");
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let out = publisher.run_chunked_bytes(&publish_wire("big", &payload, QoS::AtMostOnce, false, 0, V3), 777);
    assert!(out.is_empty());
    let mut got = arrivals(&mut sub, 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    let want_len = payload.len();
    let body = |g: &[u8]| -> Option<Vec<u8>> {
        let pk = std::panic::catch_unwind(|| packets(g)).ok()?;
        let p = pk.first()?;
        Some(publish_of(p, V3).1)
    };
    while body(&got).map(|p| p.len()) != Some(want_len) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
        sub.pump();
        got.extend(sub.take_bytes());
    }
    assert_eq!(body(&got).unwrap(), payload);
}

// -- topic aliases (MQTT 5.0) ------------------------------------------------

fn aliased(topic: &str, alias: u16) -> Vec<u8> {
    let mut props = Properties::new();
    props.set_u16(property::TOPIC_ALIAS, alias);
    encode::encode_publish(
        &encode::PublishFields { topic, qos: QoS::AtMostOnce, dup: false, retain: false, packet_id: 0, props: &props, version: V5 },
        b"x",
    )
}

#[test]
fn a_topic_alias_stands_for_the_topic_it_was_first_sent_with() {
    let b = broker();
    let mut sub = subscribed(&b, V5, "sub", "alias/t");
    let mut publisher = up_with(&b, V5, "pub");
    publisher.run_bytes(&aliased("alias/t", 1));
    publisher.run_bytes(&aliased("", 1));
    assert!(!publisher.is_closed());
    let got = packets(&arrivals(&mut sub, 2));
    assert_eq!(got.len(), 2);
    for p in &got {
        assert_eq!(publish_of(p, V5).0, "alias/t");
    }
}

#[test]
fn bad_topic_aliases_end_the_connection_with_the_right_reason() {
    let cases: Vec<(&str, Vec<u8>, u8)> = vec![
        ("alias 0", aliased("a", 0), reason::TOPIC_ALIAS_INVALID),
        ("above the maximum", aliased("a", SERVER_TOPIC_ALIAS_MAXIMUM + 1), reason::TOPIC_ALIAS_INVALID),
        ("unknown alias with no topic", aliased("", 3), reason::PROTOCOL_ERROR),
        ("no topic and no alias", publish_wire("", b"x", QoS::AtMostOnce, false, 0, V5), reason::TOPIC_NAME_INVALID),
    ];
    for (name, wire, code) in cases {
        let (mut peer, _) = up(V5);
        let out = peer.run_bytes(&wire);
        assert_eq!(disconnect_reason(&out), Some(code), "{name}");
        assert!(peer.is_closed(), "{name}");
    }
}

// -- retained messages -------------------------------------------------------

/// Publish `topic` retained and wait for the broker to have stored it.
fn retain(b: &Arc<BrokerState>, version: ProtocolVersion, topic: &str) {
    let mut publisher = up_with(b, version, "retainer");
    publisher.run_bytes(&publish_wire(topic, b"kept", QoS::AtMostOnce, true, 0, version));
    let deadline = Instant::now() + Duration::from_secs(10);
    while b.retained_matching(topic).is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
        publisher.pump();
    }
    assert!(!b.retained_matching(topic).is_empty(), "the retained message was stored");
}

fn retain_then_subscribe(handling: u8, resubscribe: bool) -> usize {
    let b = broker();
    retain(&b, V5, "ret/t");
    let mut sub = up_with(&b, V5, "sub");
    let mut f = filter("ret/#", QoS::AtMostOnce);
    f.retain_handling = handling;
    // The SUBACK and, unless handling is 2, the retained message.
    let out = run_and_collect(&mut sub, &subscribe_wire(1, &[f.clone()], V5), 1 + usize::from(handling != 2));
    let mut n = packets(&out).iter().filter(|p| p.ty == PUBLISH).count();
    if resubscribe {
        let out = run_and_collect(&mut sub, &subscribe_wire(2, &[f], V5), 1 + usize::from(handling == 0));
        n += packets(&out).iter().filter(|p| p.ty == PUBLISH).count();
    }
    n
}

#[test]
fn a_retained_message_is_sent_to_a_new_subscriber_according_to_retain_handling() {
    assert_eq!(retain_then_subscribe(0, false), 1, "0: always at subscribe time");
    assert_eq!(retain_then_subscribe(1, false), 1, "1: if the subscription is new");
    assert_eq!(retain_then_subscribe(2, false), 0, "2: never");
}

#[test]
fn retain_handling_1_does_not_resend_on_a_repeat_subscription_but_0_does() {
    assert_eq!(retain_then_subscribe(1, true), 1);
    assert_eq!(retain_then_subscribe(0, true), 2);
}

#[test]
fn a_retained_delivery_has_the_retain_flag_set() {
    let b = broker();
    retain(&b, V3, "r");
    let mut sub = up_with(&b, V3, "sub");
    let got = packets(&run_and_collect(&mut sub, &subscribe_wire(1, &[filter("r", QoS::AtMostOnce)], V3), 2));
    let p = got.iter().find(|p| p.ty == PUBLISH).expect("retained delivery");
    let (topic, payload, _, retain, _) = publish_of(p, V3);
    assert_eq!((topic.as_str(), payload.as_slice(), retain), ("r", &b"kept"[..], true));
}

// -- Will messages -----------------------------------------------------------

fn with_will(version: ProtocolVersion, id: &str) -> Vec<u8> {
    let mut p = connect_packet(version, id);
    p.will = Some(Will { qos: QoS::AtMostOnce, retain: false, topic: "will/t".into(), payload: b"gone".to_vec(), properties: no_props() });
    encode::encode_connect(&p)
}

fn will_delivered(version: ProtocolVersion, expect: bool, end: impl FnOnce(&mut Server)) -> bool {
    let b = broker();
    let mut watcher = subscribed(&b, V3, "watch", "will/#");
    let mut victim = connection(&b);
    run_for(&mut victim, &with_will(version, "victim"), 1);
    end(&mut victim);
    let got = packets(&arrivals(&mut watcher, usize::from(expect)));
    got.iter().any(|p| p.ty == PUBLISH && publish_of(p, V3).1 == b"gone")
}

#[test]
fn a_will_is_published_when_the_connection_drops() {
    for version in [V3, V5] {
        assert!(will_delivered(version, true, |p| p.disconnect()), "{version:?}");
    }
}

#[test]
fn a_will_is_not_published_after_a_clean_disconnect() {
    for version in [V3, V5] {
        let got = will_delivered(version, false, |p| {
            p.run_bytes(&encode::encode_disconnect(0, &no_props(), version));
            p.disconnect();
        });
        assert!(!got, "{version:?}");
    }
}

#[test]
fn a_v5_disconnect_with_will_message_publishes_the_will() {
    // MQTT 5.0 section 3.14.2.1: reason 0x04 asks for the Will to be sent.
    let got = will_delivered(V5, true, |p| {
        p.run_bytes(&encode::encode_disconnect(reason::DISCONNECT_WITH_WILL_MESSAGE, &no_props(), V5));
        p.disconnect();
    });
    assert!(got);
}

#[test]
fn a_protocol_error_close_publishes_the_will() {
    let got = will_delivered(V3, true, |p| {
        p.run_bytes(&publish_wire("a/+", b"x", QoS::AtMostOnce, false, 0, V3));
        p.disconnect();
    });
    assert!(got);
}

// -- sessions ----------------------------------------------------------------

#[test]
fn reconnecting_with_a_clean_session_discards_the_old_subscriptions() {
    let b = broker();
    let mut sub = subscribed(&b, V3, "sub", "t");
    sub.disconnect();
    let mut again = up_with(&b, V3, "sub");
    let mut publisher = up_with(&b, V3, "pub");
    publisher.run_bytes(&publish_wire("t", b"x", QoS::AtMostOnce, false, 0, V3));
    assert!(arrivals(&mut again, 0).is_empty());
}

#[test]
fn a_new_connection_with_the_same_client_id_takes_over() {
    let b = broker();
    let mut first = up_with(&b, V3, "same");
    let _second = up_with(&b, V3, "same");
    first.pump();
    assert!(first.is_closed(), "the old connection is closed");
}

#[test]
fn a_persistent_session_keeps_its_subscription_and_reports_session_present() {
    let b = broker();
    let mut sub = connection(&b);
    let mut p = connect_packet(V3, "keeper");
    p.clean_session = false;
    run_for(&mut sub, &encode::encode_connect(&p), 1);
    sub.run_bytes(&subscribe_wire(1, &[filter("t", QoS::AtLeastOnce)], V3));
    sub.disconnect();
    let mut publisher = up_with(&b, V3, "pub");
    run_for(&mut publisher, &publish_wire("t", b"queued", QoS::AtLeastOnce, false, 1, V3), 1);

    let mut back = connection(&b);
    let out = run_for(&mut back, &encode::encode_connect(&p), 2);
    let (present, code, _) = connack_of(&out, V3);
    assert!(present && code == 0);
    let mut all = out;
    all.extend(arrivals(&mut back, 0));
    let queued: Vec<_> = packets(&all).into_iter().filter(|p| p.ty == PUBLISH).collect();
    assert_eq!(queued.len(), 1, "the message published while it was away");
    assert_eq!(publish_of(&queued[0], V3).1, b"queued");
}

// -- enhanced authentication -------------------------------------------------

fn auth_store() -> Opts {
    let store: Arc<dyn hopf_auth::CredentialStore> = Arc::new(
        PasswordStore::new().with_user("alice", "secret"),
    );
    Opts { credentials: Some(store), anonymous: false, max_payload: None }
}

/// The bytes a client step wants sent, whether or not it also finishes.
fn sasl_data(step: SaslClientStep) -> Vec<u8> {
    match step {
        SaslClientStep::Response(d) | SaslClientStep::Complete(d) => d,
        SaslClientStep::Failure => panic!("the client failed"),
    }
}

fn connect_with_method(method: &str, data: Option<&[u8]>) -> Vec<u8> {
    let mut p = connect_packet(V5, "auth-client");
    p.properties.set_utf8(property::AUTHENTICATION_METHOD, method);
    if let Some(d) = data {
        p.properties.set_binary(property::AUTHENTICATION_DATA, d);
    }
    encode::encode_connect(&p)
}

fn auth_wire(code: u8, method: &str, data: Option<&[u8]>) -> Vec<u8> {
    let mut props = Properties::new();
    props.set_utf8(property::AUTHENTICATION_METHOD, method);
    if let Some(d) = data {
        props.set_binary(property::AUTHENTICATION_DATA, d);
    }
    encode::encode_auth(code, &props)
}

fn auth_of(p: &Pkt) -> (u8, Properties) {
    assert_eq!(p.ty, AUTH, "{p:?}");
    decode::decode_auth(&p.body).unwrap()
}

#[test]
fn plain_with_an_initial_response_completes_the_connect() {
    let mut peer = connection_with(&broker(), &auth_store(), None, None);
    let out = run_for(&mut peer, &connect_with_method("PLAIN", Some(b"\0alice\0secret")), 1);
    assert_eq!(connack_of(&out, V5).1, 0);
    assert_eq!(peer.handler.metrics.auth_ok.load(Ordering::Relaxed), 1);
}

#[test]
fn plain_with_a_wrong_password_is_refused() {
    let mut peer = connection_with(&broker(), &auth_store(), None, None);
    let out = run_for(&mut peer, &connect_with_method("PLAIN", Some(b"\0alice\0nope")), 1);
    assert_eq!(connack_of(&out, V5).1, reason::NOT_AUTHORIZED);
    assert!(peer.is_closed());
    assert_eq!(peer.handler.metrics.auth_fail.load(Ordering::Relaxed), 1);
}

#[test]
fn plain_without_an_initial_response_asks_for_it() {
    let mut peer = connection_with(&broker(), &auth_store(), None, None);
    let out = run_for(&mut peer, &connect_with_method("PLAIN", None), 1);
    let pk = packets(&out);
    let (code, props) = auth_of(&pk[0]);
    assert_eq!(code, reason::CONTINUE_AUTHENTICATION);
    assert_eq!(props.get_utf8(property::AUTHENTICATION_METHOD), Some("PLAIN"));
    let out = run_for(&mut peer, &auth_wire(reason::CONTINUE_AUTHENTICATION, "PLAIN", Some(b"\0alice\0secret")), 1);
    assert_eq!(connack_of(&out, V5).1, 0);
}

#[test]
fn scram_delivers_the_server_final_message_in_the_connack_not_in_an_auth_packet() {
    // MQTT 5.0 section 4.12.1: during CONNECT the last server data rides in
    // CONNACK's Authentication Data, and the CONNACK names the method.
    let mut peer = connection_with(&broker(), &auth_store(), None, None);
    let mut client = create_client(SaslMechanism::ScramSha256, "alice", "secret", None);
    let first = sasl_data(client.evaluate(None));
    let out = run_for(&mut peer, &connect_with_method("SCRAM-SHA-256", Some(&first)), 1);
    let (code, props) = auth_of(&packets(&out)[0]);
    assert_eq!(code, reason::CONTINUE_AUTHENTICATION);
    let server_first = props.get_binary(property::AUTHENTICATION_DATA).unwrap().to_vec();
    let client_final = sasl_data(client.evaluate(Some(&server_first)));
    let out = run_for(&mut peer, &auth_wire(reason::CONTINUE_AUTHENTICATION, "SCRAM-SHA-256", Some(&client_final)), 1);
    assert_eq!(types(&out), [CONNACK], "no AUTH(Success) before CONNACK: {:?}", types(&out));
    let (_, code, props) = connack_of(&out, V5);
    assert_eq!(code, 0);
    assert_eq!(props.get_utf8(property::AUTHENTICATION_METHOD), Some("SCRAM-SHA-256"));
    let server_final = props.get_binary(property::AUTHENTICATION_DATA).expect("server-final in CONNACK").to_vec();
    assert!(matches!(client.evaluate(Some(&server_final)), SaslClientStep::Complete(_)), "the client accepts it");
}

#[test]
fn an_unknown_method_or_a_server_without_credentials_refuses_the_connect() {
    let mut peer = connection_with(&broker(), &auth_store(), None, None);
    let out = run_for(&mut peer, &connect_with_method("MAGIC", None), 1);
    assert_eq!(connack_of(&out, V5).1, reason::BAD_AUTHENTICATION_METHOD);
    assert!(peer.is_closed());

    let mut peer = connection(&broker());
    let out = run_for(&mut peer, &connect_with_method("PLAIN", Some(b"\0a\0b")), 1);
    assert_eq!(connack_of(&out, V5).1, reason::BAD_AUTHENTICATION_METHOD, "no credential store");
}

#[test]
fn switching_method_mid_exchange_ends_the_connection() {
    let mut peer = connection_with(&broker(), &auth_store(), None, None);
    run_for(&mut peer, &connect_with_method("PLAIN", None), 1);
    let out = run_for(&mut peer, &auth_wire(reason::CONTINUE_AUTHENTICATION, "SCRAM-SHA-256", Some(b"x")), 1);
    assert_eq!(disconnect_reason(&out), Some(reason::BAD_AUTHENTICATION_METHOD));
    assert!(peer.is_closed());
}

#[test]
fn a_connect_pipelined_behind_a_pending_exchange_is_refused() {
    let mut peer = connection_with(&broker(), &auth_store(), None, None);
    run_for(&mut peer, &connect_with_method("PLAIN", None), 1);
    let out = peer.run_bytes(&connect_with_method("PLAIN", None));
    assert!(peer.is_closed(), "{out:?}");
}

fn authenticated_peer() -> Server {
    let mut peer = connection_with(&broker(), &auth_store(), None, None);
    let out = run_for(&mut peer, &connect_with_method("PLAIN", Some(b"\0alice\0secret")), 1);
    assert_eq!(connack_of(&out, V5).1, 0);
    peer
}

#[test]
fn re_authentication_succeeds_with_an_auth_success_packet() {
    // MQTT 5.0 section 4.12.1: the server ends a re-authentication with AUTH, reason Success.
    let mut peer = authenticated_peer();
    let out = run_for(&mut peer, &auth_wire(reason::REAUTHENTICATE, "PLAIN", Some(b"\0alice\0secret")), 1);
    let (code, props) = auth_of(&packets(&out)[0]);
    assert_eq!(code, reason::SUCCESS);
    assert_eq!(props.get_utf8(property::AUTHENTICATION_METHOD), Some("PLAIN"));
    assert!(!peer.is_closed());
}

#[test]
fn a_failed_re_authentication_disconnects_with_not_authorized() {
    let mut peer = authenticated_peer();
    let out = run_for(&mut peer, &auth_wire(reason::REAUTHENTICATE, "PLAIN", Some(b"\0alice\0wrong")), 1);
    assert_eq!(disconnect_reason(&out), Some(reason::NOT_AUTHORIZED));
    assert!(peer.is_closed());
}

#[test]
fn re_authentication_with_an_unknown_method_or_none_is_refused() {
    let mut peer = authenticated_peer();
    let out = run_for(&mut peer, &auth_wire(reason::REAUTHENTICATE, "MAGIC", None), 1);
    assert_eq!(disconnect_reason(&out), Some(reason::BAD_AUTHENTICATION_METHOD));

    let mut peer = authenticated_peer();
    let out = run_for(&mut peer, &encode::encode_auth(reason::REAUTHENTICATE, &no_props()), 1);
    assert_eq!(disconnect_reason(&out), Some(reason::PROTOCOL_ERROR));
}

#[test]
fn re_authentication_needs_a_credential_store() {
    let mut peer = up_with(&broker(), V5, "anon");
    let out = run_for(&mut peer, &auth_wire(reason::REAUTHENTICATE, "PLAIN", Some(b"x")), 1);
    assert_eq!(disconnect_reason(&out), Some(reason::BAD_AUTHENTICATION_METHOD));
}

#[test]
fn an_auth_packet_before_connect_ends_the_connection() {
    let mut peer = connection_with(&broker(), &auth_store(), None, None);
    let out = peer.run_bytes(&auth_wire(reason::REAUTHENTICATE, "PLAIN", Some(b"\0alice\0secret")));
    assert!(peer.is_closed(), "{out:?}");
    assert!(out.is_empty());
}
