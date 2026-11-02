// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-process tests of [`MqttClientEndpoint`]: the test plays the broker
//! over a [`Peer`], writing packets and comparing what the client sends
//! with the encoded packets it should have sent.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::testing::Peer;

use super::*;
use crate::codec::packet::reason;

#[derive(Clone)]
enum Action {
    Publish(&'static str, &'static [u8], QoS),
    Subscribe(&'static str),
    Unsubscribe(&'static str),
    Auth(u8),
    Disconnect(u8),
}

#[derive(Default)]
struct Shared {
    events: Vec<String>,
    actions: Vec<Action>,
    ids: Vec<u16>,
}

type State = Arc<Mutex<Shared>>;

/// Records every callback; runs the queued [`Action`]s at the next one.
struct Driver(State);

impl Driver {
    fn log(&self, e: String) {
        self.0.lock().unwrap().events.push(e);
    }

    fn act(&self, c: &mut dyn MqttClientControl) {
        let todo = std::mem::take(&mut self.0.lock().unwrap().actions);
        for a in todo {
            let id = match a {
                Action::Publish(t, p, q) => c.publish(t, p, q, false, &Properties::new()),
                Action::Subscribe(f) => c.subscribe(&[filter(f)]),
                Action::Unsubscribe(f) => c.unsubscribe(&[f.to_string()]),
                Action::Auth(r) => {
                    c.auth(r, &Properties::new());
                    continue;
                }
                Action::Disconnect(r) => {
                    c.disconnect(r);
                    continue;
                }
            };
            self.0.lock().unwrap().ids.push(id);
        }
    }
}

impl MqttClientDriver for Driver {
    fn on_connack(&mut self, c: &mut dyn MqttClientControl, present: bool, code: u8, _p: &Properties) {
        self.log(format!("connack present={present} code={code}"));
        self.act(c);
    }
    fn on_message_start(&mut self, topic: &str, qos: QoS, retain: bool, id: u16, _p: &Properties, len: u32) {
        self.log(format!("start {topic} {qos:?} retain={retain} id={id} len={len}"));
    }
    fn on_message_data(&mut self, data: &[u8]) {
        self.log(format!("data {}", String::from_utf8_lossy(data)));
    }
    fn on_message_complete(&mut self, c: &mut dyn MqttClientControl) {
        self.log("complete".into());
        self.act(c);
    }
    fn on_suback(&mut self, c: &mut dyn MqttClientControl, id: u16, codes: &[u8]) {
        self.log(format!("suback {id} {codes:?}"));
        self.act(c);
    }
    fn on_unsuback(&mut self, c: &mut dyn MqttClientControl, id: u16, codes: &[u8]) {
        self.log(format!("unsuback {id} {codes:?}"));
        self.act(c);
    }
    fn on_publish_acked(&mut self, c: &mut dyn MqttClientControl, id: u16) {
        self.log(format!("acked {id}"));
        self.act(c);
    }
    fn on_publish_failed(&mut self, c: &mut dyn MqttClientControl, id: u16, code: u8, _p: &Properties) {
        self.log(format!("failed {id} {code}"));
        self.act(c);
    }
    fn on_ping_resp(&mut self, c: &mut dyn MqttClientControl) {
        self.log("pingresp".into());
        self.act(c);
    }
    fn on_server_disconnect(&mut self, code: u8, _p: &Properties) {
        self.log(format!("server-disconnect {code}"));
    }
    fn on_auth(&mut self, c: &mut dyn MqttClientControl, code: u8, _p: &Properties) {
        self.log(format!("auth {code}"));
        self.act(c);
    }
    fn on_error(&mut self, err: &io::Error) {
        self.log(format!("error {:?}", err.kind()));
    }
    fn on_disconnected(&mut self) {
        self.log("disconnected".into());
    }
}

struct Factory(State);

impl MqttClientHandlerFactory for Factory {
    fn create(&self) -> Box<dyn MqttClientDriver> {
        Box::new(Driver(Arc::clone(&self.0)))
    }
}

fn filter(f: &str) -> SubscribeFilter {
    SubscribeFilter {
        topic_filter: f.into(),
        max_qos: QoS::AtLeastOnce,
        no_local: false,
        retain_as_published: false,
        retain_handling: 0,
    }
}

fn params(version: ProtocolVersion) -> MqttClientParams {
    MqttClientParams {
        version,
        client_id: "c1".into(),
        clean_start: true,
        keep_alive: Duration::from_secs(30),
        session_expiry_secs: 0,
        receive_maximum: None,
        username: None,
        password: None,
        will: None,
        tls_connector: None,
        tls_server_name: None,
        implicit_tls: false,
        connack_timeout: Duration::from_secs(10),
        pingresp_timeout: Duration::from_secs(10),
    }
}

fn connect_with(p: MqttClientParams) -> (Peer<MqttClientEndpoint>, State, Vec<u8>) {
    let state: State = Arc::default();
    let mut peer = Peer::connect(MqttClientEndpoint::new(&Factory(Arc::clone(&state)), p), |_| false);
    let first = peer.take_bytes();
    (peer, state, first)
}

/// Connected and past CONNACK, with nothing outstanding.
fn up(version: ProtocolVersion) -> (Peer<MqttClientEndpoint>, State) {
    let (mut peer, state, _) = connect_with(params(version));
    peer.run_bytes(&encode::encode_connack(false, 0, &Properties::new(), version));
    state.lock().unwrap().events.clear();
    (peer, state)
}

fn events(s: &State) -> Vec<String> {
    s.lock().unwrap().events.clone()
}

fn no_props() -> Properties {
    Properties::new()
}

fn publish_wire(topic: &str, payload: &[u8], qos: QoS, id: u16, version: ProtocolVersion) -> Vec<u8> {
    let props = no_props();
    encode::encode_publish(
        &encode::PublishFields { topic, qos, dup: false, retain: false, packet_id: id, props: &props, version },
        payload,
    )
}

const V3: ProtocolVersion = ProtocolVersion::V311;
const V5: ProtocolVersion = ProtocolVersion::V5;

// -- CONNECT -----------------------------------------------------------------

fn expected_connect(p: &MqttClientParams, properties: Properties) -> Vec<u8> {
    encode::encode_connect(&ConnectPacket {
        version: p.version,
        clean_session: p.clean_start,
        keep_alive: p.keep_alive.as_secs().min(u16::MAX as u64) as u16,
        properties,
        client_id: p.client_id.clone(),
        will: p.will.clone(),
        username: p.username.clone(),
        password: p.password.clone(),
    })
}

#[test]
fn connect_is_sent_as_soon_as_the_connection_is_up() {
    let p = params(V3);
    let (_, _, first) = connect_with(p.clone());
    assert_eq!(first, expected_connect(&p, no_props()));
}

#[test]
fn credentials_and_will_go_into_connect() {
    let mut p = params(V3);
    p.username = Some("u".into());
    p.password = Some(b"pw".to_vec());
    p.will = Some(Will { qos: QoS::AtLeastOnce, retain: true, topic: "w/t".into(), payload: b"bye".to_vec(), properties: no_props() });
    p.clean_start = false;
    let (_, _, first) = connect_with(p.clone());
    assert_eq!(first, expected_connect(&p, no_props()));
}

#[test]
fn v5_connect_carries_receive_maximum_and_session_expiry_only_when_set() {
    let mut p = params(V5);
    p.receive_maximum = Some(20);
    p.session_expiry_secs = 3600;
    let mut props = no_props();
    props.set_u16(property::RECEIVE_MAXIMUM, 20);
    props.set_u32(property::SESSION_EXPIRY_INTERVAL, 3600);
    let (_, _, first) = connect_with(p.clone());
    assert_eq!(first, expected_connect(&p, props));

    let bare = params(V5);
    let (_, _, first) = connect_with(bare.clone());
    assert_eq!(first, expected_connect(&bare, no_props()));
}

#[test]
fn v3_connect_ignores_v5_only_settings() {
    let mut p = params(V3);
    p.receive_maximum = Some(20);
    p.session_expiry_secs = 3600;
    let (_, _, first) = connect_with(p.clone());
    assert_eq!(first, expected_connect(&p, no_props()));
}

#[test]
fn keep_alive_is_clamped_to_what_fits_the_wire() {
    let mut p = params(V3);
    p.keep_alive = Duration::from_secs(100_000);
    let (_, _, first) = connect_with(p.clone());
    assert_eq!(first, expected_connect(&p, no_props()));
    // Keep alive is the two bytes after the protocol name and level and flags.
    let ka = u16::from_be_bytes([first[10], first[11]]);
    assert_eq!(ka, u16::MAX);
}

#[test]
fn with_implicit_tls_connect_waits_for_the_handshake() {
    let mut p = params(V3);
    p.implicit_tls = true;
    let (mut peer, _, first) = connect_with(p.clone());
    assert!(first.is_empty());
    peer.secure(&hopf_core::SecurityInfo::default());
    assert_eq!(peer.take_bytes(), expected_connect(&p, no_props()));
    peer.secure(&hopf_core::SecurityInfo::default());
    assert!(peer.take_bytes().is_empty(), "CONNECT is sent once");
}

// -- CONNACK -----------------------------------------------------------------

#[test]
fn connack_reaches_the_driver_with_the_session_flag() {
    let (mut peer, state, _) = connect_with(params(V3));
    peer.run_bytes(&encode::encode_connack(true, 0, &no_props(), V3));
    assert_eq!(events(&state), ["connack present=true code=0"]);
    assert!(!peer.is_closed());
}

#[test]
fn a_refused_connection_is_reported_and_then_closed() {
    let (mut peer, state, _) = connect_with(params(V3));
    peer.run_bytes(&encode::encode_connack(false, 5, &no_props(), V3));
    assert_eq!(events(&state), ["connack present=false code=5"]);
    assert!(peer.is_closed());
}

#[test]
fn the_driver_can_act_from_connack() {
    let (mut peer, state, _) = connect_with(params(V3));
    state.lock().unwrap().actions = vec![Action::Subscribe("a/b"), Action::Publish("t", b"x", QoS::AtMostOnce)];
    let out = peer.run_bytes(&encode::encode_connack(false, 0, &no_props(), V3));
    let mut want = encode::encode_subscribe(1, &[filter("a/b")], &no_props(), V3);
    want.extend(publish_wire("t", b"x", QoS::AtMostOnce, 0, V3));
    assert_eq!(out, want);
    assert_eq!(state.lock().unwrap().ids, [1, 0]);
}

#[test]
fn connack_split_across_reads_is_the_same() {
    let (mut peer, state, _) = connect_with(params(V3));
    peer.run_chunked_bytes(&encode::encode_connack(false, 0, &no_props(), V3), 1);
    assert_eq!(events(&state), ["connack present=false code=0"]);
}

// -- publishing --------------------------------------------------------------

#[test]
fn packet_ids_count_up_from_one_and_qos0_uses_none() {
    let (mut peer, state) = up(V3);
    state.lock().unwrap().actions = vec![
        Action::Publish("t", b"a", QoS::AtLeastOnce),
        Action::Publish("t", b"b", QoS::AtMostOnce),
        Action::Subscribe("x"),
        Action::Unsubscribe("x"),
        Action::Publish("t", b"c", QoS::ExactlyOnce),
    ];
    peer.run_bytes(&encode::encode_pingresp());
    assert_eq!(state.lock().unwrap().ids, [1, 0, 2, 3, 4]);
}

#[test]
fn packet_ids_wrap_past_65535_to_1_never_0() {
    let (mut peer, state) = up(V3);
    peer.handler.next_packet_id = u16::MAX;
    state.lock().unwrap().actions = vec![Action::Subscribe("x"), Action::Subscribe("y")];
    peer.run_bytes(&encode::encode_pingresp());
    assert_eq!(state.lock().unwrap().ids, [u16::MAX, 1]);
}

#[test]
fn publish_subscribe_and_unsubscribe_are_encoded_for_the_version() {
    for version in [V3, V5] {
        let (mut peer, state) = up(version);
        state.lock().unwrap().actions = vec![
            Action::Publish("a/b", b"hello", QoS::AtLeastOnce),
            Action::Subscribe("c/#"),
            Action::Unsubscribe("c/#"),
        ];
        let out = peer.run_bytes(&encode::encode_pingresp());
        let mut want = publish_wire("a/b", b"hello", QoS::AtLeastOnce, 1, version);
        want.extend(encode::encode_subscribe(2, &[filter("c/#")], &no_props(), version));
        want.extend(encode::encode_unsubscribe(3, &["c/#".to_string()], &no_props(), version));
        assert_eq!(out, want, "{version:?}");
    }
}

#[test]
fn puback_completes_a_qos1_publish() {
    let (mut peer, state) = up(V3);
    state.lock().unwrap().actions = vec![Action::Publish("t", b"a", QoS::AtLeastOnce)];
    peer.run_bytes(&encode::encode_pingresp());
    state.lock().unwrap().events.clear();
    let out = peer.run_bytes(&encode::encode_puback(1, 0, &no_props(), V3));
    assert!(out.is_empty());
    assert_eq!(events(&state), ["acked 1"]);
}

#[test]
fn a_qos2_publish_is_released_on_pubrec_and_done_on_pubcomp() {
    for version in [V3, V5] {
        let (mut peer, state) = up(version);
        state.lock().unwrap().actions = vec![Action::Publish("t", b"a", QoS::ExactlyOnce)];
        peer.run_bytes(&encode::encode_pingresp());
        state.lock().unwrap().events.clear();
        let out = peer.run_bytes(&encode::encode_pubrec(1, 0, &no_props(), version));
        assert_eq!(out, encode::encode_pubrel(1, 0, &no_props(), version), "{version:?}");
        assert!(events(&state).is_empty(), "not done until PUBCOMP");
        peer.run_bytes(&encode::encode_pubcomp(1, 0, &no_props(), version));
        assert_eq!(events(&state), ["acked 1"]);
    }
}

#[test]
fn a_pubrec_refusing_the_publish_is_not_released() {
    // MQTT 5.0 section 4.3.3: a PUBREC with a reason code of 0x80 or more
    // ends the exchange; no PUBREL follows.
    let (mut peer, state) = up(V5);
    state.lock().unwrap().actions = vec![Action::Publish("t", b"a", QoS::ExactlyOnce)];
    peer.run_bytes(&encode::encode_pingresp());
    state.lock().unwrap().events.clear();
    let out = peer.run_bytes(&encode::encode_pubrec(1, reason::UNSPECIFIED_ERROR, &no_props(), V5));
    assert!(out.is_empty(), "{out:?}");
    assert_eq!(events(&state), ["failed 1 128"], "and the driver is told");
}

#[test]
fn a_refusing_puback_is_a_failure_not_an_acknowledgement() {
    let (mut peer, state) = up(V5);
    state.lock().unwrap().actions = vec![Action::Publish("t", b"a", QoS::AtLeastOnce)];
    peer.run_bytes(&encode::encode_pingresp());
    state.lock().unwrap().events.clear();
    peer.run_bytes(&encode::encode_puback(1, reason::NOT_AUTHORIZED, &no_props(), V5));
    assert_eq!(events(&state), [format!("failed 1 {}", reason::NOT_AUTHORIZED)]);
}

#[test]
fn a_refusing_pubcomp_is_a_failure_not_an_acknowledgement() {
    let (mut peer, state) = up(V5);
    state.lock().unwrap().actions = vec![Action::Publish("t", b"a", QoS::ExactlyOnce)];
    peer.run_bytes(&encode::encode_pingresp());
    peer.run_bytes(&encode::encode_pubrec(1, 0, &no_props(), V5));
    state.lock().unwrap().events.clear();
    peer.run_bytes(&encode::encode_pubcomp(1, reason::PACKET_IDENTIFIER_NOT_FOUND, &no_props(), V5));
    assert_eq!(events(&state), [format!("failed 1 {}", reason::PACKET_IDENTIFIER_NOT_FOUND)]);
}

#[test]
fn a_puback_with_a_success_like_reason_is_an_acknowledgement() {
    // 0x10 (no matching subscribers) is below 0x80: the publish was accepted.
    let (mut peer, state) = up(V5);
    state.lock().unwrap().actions = vec![Action::Publish("t", b"a", QoS::AtLeastOnce)];
    peer.run_bytes(&encode::encode_pingresp());
    state.lock().unwrap().events.clear();
    peer.run_bytes(&encode::encode_puback(1, reason::NO_MATCHING_SUBSCRIBERS, &no_props(), V5));
    assert_eq!(events(&state), ["acked 1"]);
}

// -- receiving ---------------------------------------------------------------

#[test]
fn a_qos0_message_is_delivered_without_an_acknowledgement() {
    let (mut peer, state) = up(V3);
    let out = peer.run_bytes(&publish_wire("a/b", b"hello", QoS::AtMostOnce, 0, V3));
    assert!(out.is_empty());
    assert_eq!(events(&state), ["start a/b AtMostOnce retain=false id=0 len=5", "data hello", "complete"]);
}

#[test]
fn a_qos1_message_is_acknowledged_before_the_driver_hears_it_is_complete() {
    for version in [V3, V5] {
        let (mut peer, state) = up(version);
        state.lock().unwrap().actions = vec![Action::Publish("r", b"x", QoS::AtMostOnce)];
        let out = peer.run_bytes(&publish_wire("a", b"hi", QoS::AtLeastOnce, 7, version));
        let mut want = encode::encode_puback(7, 0, &no_props(), version);
        want.extend(publish_wire("r", b"x", QoS::AtMostOnce, 0, version));
        assert_eq!(out, want, "{version:?}: the PUBACK, then what the driver did on completion");
    }
}

#[test]
fn a_qos2_message_is_pubrec_ed_then_pubcomp_ed_on_pubrel() {
    for version in [V3, V5] {
        let (mut peer, state) = up(version);
        let out = peer.run_bytes(&publish_wire("a", b"hi", QoS::ExactlyOnce, 9, version));
        assert_eq!(out, encode::encode_pubrec(9, 0, &no_props(), version));
        assert_eq!(events(&state).last().map(String::as_str), Some("complete"));
        let out = peer.run_bytes(&encode::encode_pubrel(9, 0, &no_props(), version));
        assert_eq!(out, encode::encode_pubcomp(9, 0, &no_props(), version));
    }
}

#[test]
fn a_message_arriving_a_byte_at_a_time_is_delivered_in_pieces() {
    let (mut peer, state) = up(V3);
    let out = peer.run_chunked_bytes(&publish_wire("a/b", b"hello", QoS::AtLeastOnce, 1, V3), 1);
    assert_eq!(out, encode::encode_puback(1, 0, &no_props(), V3));
    let ev = events(&state);
    assert_eq!(ev.first().unwrap(), "start a/b AtLeastOnce retain=false id=1 len=5");
    assert_eq!(ev.last().unwrap(), "complete");
    let data: String = ev.iter().filter_map(|e| e.strip_prefix("data ")).collect();
    assert_eq!(data, "hello");
    assert!(ev.len() > 3, "the payload was handed over as it came: {ev:?}");
}

#[test]
fn an_empty_message_has_no_data_callback() {
    let (mut peer, state) = up(V3);
    peer.run_bytes(&publish_wire("a", b"", QoS::AtMostOnce, 0, V3));
    assert_eq!(events(&state), ["start a AtMostOnce retain=false id=0 len=0", "complete"]);
}

#[test]
fn two_messages_in_one_read_are_both_delivered() {
    let (mut peer, state) = up(V3);
    let mut wire = publish_wire("a", b"1", QoS::AtLeastOnce, 1, V3);
    wire.extend(publish_wire("b", b"2", QoS::AtLeastOnce, 2, V3));
    let out = peer.run_bytes(&wire);
    let mut want = encode::encode_puback(1, 0, &no_props(), V3);
    want.extend(encode::encode_puback(2, 0, &no_props(), V3));
    assert_eq!(out, want);
    assert_eq!(events(&state).iter().filter(|e| *e == "complete").count(), 2);
}

// -- subscriptions -----------------------------------------------------------

#[test]
fn suback_and_unsuback_carry_the_ids_and_codes() {
    let (mut peer, state) = up(V3);
    peer.run_bytes(&encode::encode_suback(4, &[0, 1, 0x80], &no_props(), V3));
    peer.run_bytes(&encode::encode_unsuback(5, &[], &no_props(), V3));
    assert_eq!(events(&state), ["suback 4 [0, 1, 128]", "unsuback 5 []"]);
    peer.run_bytes(&encode::encode_unsuback(6, &[0, 0x11], &no_props(), V5));
}

// -- keepalive ---------------------------------------------------------------

fn pingresp_pending(peer: &Peer<MqttClientEndpoint>) -> bool {
    peer.handler.keepalive.as_ref().is_some_and(|k| k.pingresp_pending())
}

#[test]
fn the_keepalive_timer_sends_a_pingreq_and_the_connection_stays_up() {
    let (mut peer, state) = up(V3);
    peer.advance(Duration::from_secs(30));
    assert_eq!(peer.take_bytes(), encode::encode_pingreq());
    assert!(events(&state).is_empty());
    assert!(!peer.is_closed(), "sending a PINGREQ must not close the connection");
}

/// The client used to signal "keepalive due" through `Endpoint::fail`, which
/// force-closes a real connection, so every connection with a keep-alive was
/// closed one interval after CONNACK.
#[test]
fn pings_keep_the_connection_open_over_many_intervals() {
    let (mut peer, state) = up(V3);
    for i in 1..=4 {
        peer.advance(Duration::from_secs(30));
        assert_eq!(peer.take_bytes(), encode::encode_pingreq(), "interval {i}");
        assert!(!peer.is_closed(), "closed after interval {i}");
        peer.run_bytes(&encode::encode_pingresp());
    }
    assert!(peer.elapsed() >= Duration::from_secs(120));
    assert_eq!(events(&state), ["pingresp"; 4]);
}

#[test]
fn a_missing_pingresp_still_times_the_connection_out() {
    let (mut peer, state) = up(V3);
    peer.advance(Duration::from_secs(30));
    assert_eq!(peer.take_bytes(), encode::encode_pingreq());
    peer.advance(Duration::from_secs(10));
    assert!(peer.is_closed(), "a missed PINGRESP must close the connection");
    assert_eq!(events(&state), ["error TimedOut"]);
    peer.take_bytes();
    peer.advance(Duration::from_secs(90));
    assert!(peer.take_bytes().is_empty(), "no PINGREQ after the connection closed");
}

#[test]
fn pings_stop_when_the_connection_drops() {
    let (mut peer, _) = up(V3);
    peer.disconnect();
    peer.advance(Duration::from_secs(90));
    assert!(peer.take_bytes().is_empty(), "no PINGREQ after a disconnect");
}

#[test]
fn pingresp_reaches_the_driver() {
    let (mut peer, state) = up(V3);
    peer.advance(Duration::from_secs(30));
    peer.run_bytes(&encode::encode_pingresp());
    assert_eq!(events(&state), ["pingresp"]);
}

#[test]
fn other_timeouts_are_errors_for_the_driver() {
    for msg in ["MQTT CONNACK timed out", "MQTT PINGRESP timed out"] {
        let (mut peer, state, _) = connect_with(params(V3));
        peer.fail(&io::Error::new(io::ErrorKind::TimedOut, msg));
        assert_eq!(events(&state), ["error TimedOut"], "{msg}");
        assert!(peer.take_bytes().is_empty(), "no PINGREQ for {msg}");
    }
}

#[test]
fn a_zero_keep_alive_never_arms_the_timer() {
    let mut p = params(V3);
    p.keep_alive = Duration::ZERO;
    let (mut peer, state, _) = connect_with(p);
    peer.run_bytes(&encode::encode_connack(false, 0, &no_props(), V3));
    assert_eq!(events(&state), ["connack present=false code=0"]);
    assert!(peer.handler.keepalive.is_none());
    assert!(peer.handler.connack_timer.is_none(), "cancelled by CONNACK");
}

#[test]
fn zero_timeouts_arm_nothing() {
    let mut p = params(V3);
    p.connack_timeout = Duration::ZERO;
    p.pingresp_timeout = Duration::ZERO;
    let (mut peer, _, _) = connect_with(p);
    assert!(peer.handler.connack_timer.is_none());
    peer.run_bytes(&encode::encode_connack(false, 0, &no_props(), V3));
    peer.advance(Duration::from_secs(30));
    assert_eq!(peer.take_bytes(), encode::encode_pingreq());
    assert!(!pingresp_pending(&peer));
}

#[test]
fn timers_are_armed_by_connect_and_ping_and_cancelled_by_the_answers() {
    let (mut peer, _, _) = connect_with(params(V3));
    assert!(peer.handler.connack_timer.is_some());
    peer.run_bytes(&encode::encode_connack(false, 0, &no_props(), V3));
    assert!(peer.handler.connack_timer.is_none());
    assert!(peer.handler.keepalive.is_some());
    peer.advance(Duration::from_secs(30));
    assert!(pingresp_pending(&peer));
    peer.run_bytes(&encode::encode_pingresp());
    assert!(!pingresp_pending(&peer));
}

// -- disconnecting -----------------------------------------------------------

#[test]
fn disconnect_says_goodbye_in_both_versions_and_closes() {
    // MQTT 3.1.1 section 3.14: without DISCONNECT the broker treats the
    // close as abnormal and publishes the Will.
    for version in [V3, V5] {
        let (mut peer, state) = up(version);
        state.lock().unwrap().actions = vec![Action::Disconnect(0)];
        let out = peer.run_bytes(&encode::encode_pingresp());
        assert_eq!(out, encode::encode_disconnect(0, &no_props(), version), "{version:?}");
        assert!(peer.is_closed());
    }
}

#[test]
fn a_v5_disconnect_carries_the_reason() {
    let (mut peer, state) = up(V5);
    state.lock().unwrap().actions = vec![Action::Disconnect(reason::DISCONNECT_WITH_WILL_MESSAGE)];
    let out = peer.run_bytes(&encode::encode_pingresp());
    assert_eq!(out, encode::encode_disconnect(reason::DISCONNECT_WITH_WILL_MESSAGE, &no_props(), V5));
}

#[test]
fn a_server_disconnect_is_reported_and_closes() {
    let (mut peer, state) = up(V5);
    peer.run_bytes(&encode::encode_disconnect(reason::PROTOCOL_ERROR, &no_props(), V5));
    assert_eq!(events(&state), [format!("server-disconnect {}", reason::PROTOCOL_ERROR)]);
    assert!(peer.is_closed());
}

#[test]
fn the_driver_hears_of_the_end_of_the_connection_once() {
    let (mut peer, state) = up(V3);
    peer.disconnect();
    assert_eq!(events(&state), ["disconnected"]);
    peer.disconnect();
    assert_eq!(events(&state), ["disconnected"]);
}

#[test]
fn an_io_error_is_reported_and_the_later_close_is_not() {
    let (mut peer, state) = up(V3);
    peer.fail(&io::Error::new(io::ErrorKind::ConnectionReset, "reset"));
    peer.disconnect();
    assert_eq!(events(&state), ["error ConnectionReset"]);
}

// -- packets a client must not get ------------------------------------------

#[test]
fn packets_only_a_broker_may_receive_close_the_connection() {
    let wires: Vec<(&str, Vec<u8>)> = vec![
        ("CONNECT", expected_connect(&params(V3), no_props())),
        ("SUBSCRIBE", encode::encode_subscribe(1, &[filter("a")], &no_props(), V3)),
        ("UNSUBSCRIBE", encode::encode_unsubscribe(1, &["a".to_string()], &no_props(), V3)),
        ("PINGREQ", encode::encode_pingreq()),
    ];
    for (name, wire) in wires {
        let (mut peer, _) = up(V3);
        peer.run_bytes(&wire);
        assert!(peer.is_closed(), "{name}");
    }
}

#[test]
fn garbage_is_an_invalid_data_error_and_closes() {
    let (mut peer, state) = up(V3);
    peer.run_bytes(&[0x00, 0x00]);
    assert_eq!(events(&state), ["error InvalidData"]);
    assert!(peer.is_closed());
}

// -- enhanced authentication -------------------------------------------------

#[test]
fn auth_challenges_reach_the_driver_and_it_can_answer() {
    let (mut peer, state) = up(V5);
    state.lock().unwrap().actions = vec![Action::Auth(reason::CONTINUE_AUTHENTICATION)];
    let out = peer.run_bytes(&encode::encode_auth(reason::CONTINUE_AUTHENTICATION, &no_props()));
    assert_eq!(events(&state), [format!("auth {}", reason::CONTINUE_AUTHENTICATION)]);
    assert_eq!(out, encode::encode_auth(reason::CONTINUE_AUTHENTICATION, &no_props()));
}
