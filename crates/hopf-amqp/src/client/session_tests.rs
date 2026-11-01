// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! End-to-end tests of the AMQP 0-9-1 client endpoint.
//!
//! The test plays the broker over an in-process [`Peer`]: it writes frames
//! and decodes the frames the client sends back.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::testing::Peer;

use super::endpoint::{AmqpClientEndpoint, AmqpClientParams};
use super::handlers::{
    AmqpClientControl, AmqpClientDriver, AmqpClientHandlerFactory, BasicReturnInfo,
};
use crate::codec::encode::{
    encode_content_body_chunk, encode_content_header, encode_heartbeat, encode_method,
};
use crate::codec::methods::{CloseArgs, ConnectionTune, MethodFrame};
use crate::codec::parser::{AmqpFrameHandler, AmqpFrameParser};
use crate::codec::table::{
    decode_longstr, decode_shortstr, decode_table, encode_amqplain, encode_longstr,
    encode_shortstr, encode_table, FieldTable,
};
use crate::codec::types::{
    basic, channel, class, confirm, connection, exchange, queue, tx, PROTOCOL_HEADER,
};
use crate::codec::{AmqpError, BasicProperties};

type Events = Arc<Mutex<Vec<String>>>;

/// Called with each event's text and the control it may answer through.
type React = Box<dyn FnMut(&str, &mut dyn AmqpClientControl) + Send>;

struct Driver {
    events: Events,
    react: React,
    body: Vec<u8>,
}

impl Driver {
    fn note(&mut self, c: &mut dyn AmqpClientControl, event: String) {
        self.events.lock().unwrap().push(event.clone());
        (self.react)(&event, c);
    }

    fn plain(&mut self, event: String) {
        self.events.lock().unwrap().push(event);
    }
}

impl AmqpClientDriver for Driver {
    fn on_connection_open(&mut self, c: &mut dyn AmqpClientControl) {
        self.note(c, "open".into());
    }
    fn on_channel_open(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("channel_open:{ch}"));
    }
    fn on_channel_close(&mut self, c: &mut dyn AmqpClientControl, ch: u16, code: u16, text: &str) {
        self.note(c, format!("channel_close:{ch}:{code}:{text}"));
    }
    fn on_exchange_declare_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("exchange_declare_ok:{ch}"));
    }
    fn on_exchange_delete_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("exchange_delete_ok:{ch}"));
    }
    fn on_queue_declare_ok(
        &mut self,
        c: &mut dyn AmqpClientControl,
        ch: u16,
        q: &str,
        messages: u32,
        consumers: u32,
    ) {
        self.note(c, format!("queue_declare_ok:{ch}:{q}:{messages}:{consumers}"));
    }
    fn on_queue_bind_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("queue_bind_ok:{ch}"));
    }
    fn on_queue_unbind_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("queue_unbind_ok:{ch}"));
    }
    fn on_queue_purge_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16, n: u32) {
        self.note(c, format!("queue_purge_ok:{ch}:{n}"));
    }
    fn on_queue_delete_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16, n: u32) {
        self.note(c, format!("queue_delete_ok:{ch}:{n}"));
    }
    fn on_confirm_select_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("confirm_select_ok:{ch}"));
    }
    fn on_basic_qos_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("qos_ok:{ch}"));
    }
    fn on_consume_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16, tag: &str) {
        self.note(c, format!("consume_ok:{ch}:{tag}"));
    }
    fn on_cancel_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16, tag: &str) {
        self.note(c, format!("cancel_ok:{ch}:{tag}"));
    }
    fn on_consumer_cancelled(&mut self, c: &mut dyn AmqpClientControl, ch: u16, tag: &str) {
        self.note(c, format!("consumer_cancelled:{ch}:{tag}"));
    }
    fn on_delivery_start(
        &mut self,
        ch: u16,
        tag: &str,
        delivery_tag: u64,
        redelivered: bool,
        exchange: &str,
        routing_key: &str,
        properties: &BasicProperties,
        body_len: u64,
    ) {
        self.body.clear();
        self.plain(format!(
            "delivery:{ch}:{tag}:{delivery_tag}:{redelivered}:{exchange}:{routing_key}:{}:{body_len}",
            properties.content_type.as_deref().unwrap_or("-"),
        ));
    }
    fn on_delivery_data(&mut self, _ch: u16, data: &[u8]) {
        self.body.extend_from_slice(data);
    }
    fn on_delivery_complete(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        let body = String::from_utf8_lossy(&self.body).into_owned();
        self.note(c, format!("delivered:{ch}:{body}"));
    }
    fn on_return_start(&mut self, ch: u16, info: &BasicReturnInfo) {
        self.body.clear();
        self.plain(format!(
            "return:{ch}:{}:{}:{}:{}:{}",
            info.reply_code, info.reply_text, info.exchange, info.routing_key, info.body_len
        ));
    }
    fn on_return_data(&mut self, _ch: u16, data: &[u8]) {
        self.body.extend_from_slice(data);
    }
    fn on_return_complete(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        let body = String::from_utf8_lossy(&self.body).into_owned();
        self.note(c, format!("returned:{ch}:{body}"));
    }
    fn on_ack(&mut self, c: &mut dyn AmqpClientControl, ch: u16, tag: u64, multiple: bool) {
        self.note(c, format!("ack:{ch}:{tag}:{multiple}"));
    }
    fn on_nack(&mut self, c: &mut dyn AmqpClientControl, ch: u16, tag: u64, multiple: bool, requeue: bool) {
        self.note(c, format!("nack:{ch}:{tag}:{multiple}:{requeue}"));
    }
    fn on_get_ok(
        &mut self,
        c: &mut dyn AmqpClientControl,
        ch: u16,
        tag: u64,
        redelivered: bool,
        exchange: &str,
        routing_key: &str,
        remaining: u32,
        _properties: &BasicProperties,
        body_len: u64,
    ) {
        self.body.clear();
        self.note(
            c,
            format!("get_ok:{ch}:{tag}:{redelivered}:{exchange}:{routing_key}:{remaining}:{body_len}"),
        );
    }
    fn on_get_empty(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("get_empty:{ch}"));
    }
    fn on_recover_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("recover_ok:{ch}"));
    }
    fn on_flow(&mut self, c: &mut dyn AmqpClientControl, ch: u16, active: bool) {
        self.note(c, format!("flow:{ch}:{active}"));
    }
    fn on_flow_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16, active: bool) {
        self.note(c, format!("flow_ok:{ch}:{active}"));
    }
    fn on_tx_select_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("tx_select_ok:{ch}"));
    }
    fn on_tx_commit_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("tx_commit_ok:{ch}"));
    }
    fn on_tx_rollback_ok(&mut self, c: &mut dyn AmqpClientControl, ch: u16) {
        self.note(c, format!("tx_rollback_ok:{ch}"));
    }
    fn on_connection_blocked(&mut self, reason: &str) {
        self.plain(format!("blocked:{reason}"));
    }
    fn on_connection_unblocked(&mut self) {
        self.plain("unblocked".into());
    }
    fn on_connection_close(&mut self, code: u16, text: &str) {
        self.plain(format!("connection_close:{code}:{text}"));
    }
    fn on_error(&mut self, err: &io::Error) {
        self.plain(format!("error:{err}"));
    }
    fn on_disconnected(&mut self) {
        self.plain("disconnected".into());
    }
}

struct Factory {
    events: Events,
    react: Mutex<Option<React>>,
}

impl AmqpClientHandlerFactory for Factory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        let react = self
            .react
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| Box::new(|_, _| {}));
        Box::new(Driver {
            events: Arc::clone(&self.events),
            react,
            body: Vec::new(),
        })
    }
}

fn params() -> AmqpClientParams {
    AmqpClientParams {
        virtual_host: "/".into(),
        username: "guest".into(),
        password: "secret".into(),
        mechanism: None,
        heartbeat: 0,
        frame_max: 0,
        channel_max: 0,
        tls_connector: None,
        tls_server_name: None,
        implicit_tls: false,
        handshake_timeout: Duration::from_secs(10),
        heartbeat_timeout: Duration::ZERO,
    }
}

/// What the client sent, decoded.
#[derive(Debug, PartialEq)]
enum Out {
    Method { ch: u16, class: u16, method: u16, args: Vec<u8> },
    Header { ch: u16, size: u64 },
    Body { ch: u16, len: usize },
    Heartbeat,
}

struct Collect(Vec<Out>);

impl AmqpFrameHandler for Collect {
    fn method(&mut self, f: MethodFrame) {
        self.0.push(Out::Method {
            ch: f.channel,
            class: f.class_id,
            method: f.method_id,
            args: f.args,
        });
    }
    fn content_header(&mut self, ch: u16, _class: u16, size: u64, _p: BasicProperties) {
        self.0.push(Out::Header { ch, size });
    }
    fn content_body(&mut self, ch: u16, data: &[u8]) {
        self.0.push(Out::Body { ch, len: data.len() });
    }
    fn heartbeat(&mut self) {
        self.0.push(Out::Heartbeat);
    }
    fn error(&mut self, err: AmqpError) {
        panic!("the client sent a bad frame: {err}");
    }
}

fn decode(bytes: &[u8]) -> Vec<Out> {
    let mut parser = AmqpFrameParser::new(1 << 24);
    let mut out = Collect(Vec::new());
    parser.feed(bytes, &mut out);
    out.0
}

/// The (channel, class, method) of each method the client sent.
fn methods(bytes: &[u8]) -> Vec<(u16, u16, u16)> {
    decode(bytes)
        .into_iter()
        .filter_map(|o| match o {
            Out::Method { ch, class, method, .. } => Some((ch, class, method)),
            _ => None,
        })
        .collect()
}

fn args_of(bytes: &[u8], class_id: u16, method_id: u16) -> Vec<u8> {
    decode(bytes)
        .into_iter()
        .find_map(|o| match o {
            Out::Method { class, method, args, .. } if class == class_id && method == method_id => {
                Some(args)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no method {class_id}.{method_id} was sent"))
}

// Broker side -------------------------------------------------------------

fn start(mechanisms: &str) -> Vec<u8> {
    let mut args = vec![0, 9];
    encode_table(&mut args, &FieldTable::new()).unwrap();
    encode_longstr(&mut args, mechanisms.as_bytes());
    encode_longstr(&mut args, b"en_US");
    encode_method(0, class::CONNECTION, connection::START, &args)
}

fn tune(channel_max: u16, frame_max: u32, heartbeat: u16) -> Vec<u8> {
    let args = ConnectionTune { channel_max, frame_max, heartbeat }.encode();
    encode_method(0, class::CONNECTION, connection::TUNE, &args)
}

fn open_ok() -> Vec<u8> {
    let mut args = Vec::new();
    encode_shortstr(&mut args, "").unwrap();
    encode_method(0, class::CONNECTION, connection::OPEN_OK, &args)
}

fn m(ch: u16, class_id: u16, method_id: u16, args: &[u8]) -> Vec<u8> {
    encode_method(ch, class_id, method_id, args)
}

fn shortstr(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    encode_shortstr(&mut v, s).unwrap();
    v
}

fn counts(a: u32, b: u32) -> Vec<u8> {
    let mut v = a.to_be_bytes().to_vec();
    v.extend_from_slice(&b.to_be_bytes());
    v
}

fn deliver_args(tag: &str, delivery_tag: u64, redelivered: bool, ex: &str, rk: &str) -> Vec<u8> {
    let mut v = shortstr(tag);
    v.extend_from_slice(&delivery_tag.to_be_bytes());
    v.push(redelivered as u8);
    v.extend(shortstr(ex));
    v.extend(shortstr(rk));
    v
}

fn close_args(code: u16, text: &str) -> Vec<u8> {
    CloseArgs { reply_code: code, reply_text: text.into(), class_id: 0, method_id: 0 }
        .encode()
        .unwrap()
}

/// A delivery of `body` on `ch`, with the body split into frames of at most `piece`.
fn delivery(ch: u16, delivery_tag: u64, body: &[u8], piece: usize) -> Vec<u8> {
    let mut wire = m(
        ch,
        class::BASIC,
        basic::DELIVER,
        &deliver_args("ctag", delivery_tag, false, "ex", "rk"),
    );
    wire.extend(encode_content_header(ch, body.len() as u64, &BasicProperties::new()).unwrap());
    for chunk in body.chunks(piece.max(1)) {
        wire.extend(encode_content_body_chunk(ch, chunk, 1 << 24));
    }
    wire
}

// Harness -----------------------------------------------------------------

type Client = Peer<AmqpClientEndpoint>;

fn connect_with(p: AmqpClientParams, react: React) -> (Client, Events) {
    let events = Events::default();
    let factory = Factory {
        events: Arc::clone(&events),
        react: Mutex::new(Some(react)),
    };
    let ep = AmqpClientEndpoint::new(&factory, p);
    let mut peer = Peer::connect(ep, |_| false);
    assert_eq!(peer.take_bytes(), PROTOCOL_HEADER, "the client speaks first");
    (peer, events)
}

fn connect() -> (Client, Events) {
    connect_with(params(), Box::new(|_, _| {}))
}

/// Run the handshake to the point the connection is open.
fn open(peer: &mut Client) {
    peer.run_bytes(&start("PLAIN AMQPLAIN"));
    peer.run_bytes(&tune(2047, 131_072, 0));
    peer.run_bytes(&open_ok());
}

fn opened() -> (Client, Events) {
    let (mut peer, events) = connect();
    open(&mut peer);
    events.lock().unwrap().clear();
    (peer, events)
}

fn seen(events: &Events) -> Vec<String> {
    events.lock().unwrap().clone()
}

/// Runs the handshake with `react` driving the connection, returning what the
/// client sent once the broker said the connection was open.
fn publisher(react: impl FnMut(&str, &mut dyn AmqpClientControl) + Send + 'static, frame_max: u32) -> Vec<u8> {
    let (mut peer, _events) = connect_with(params(), Box::new(react));
    peer.run_bytes(&start("PLAIN"));
    peer.run_bytes(&tune(2047, frame_max, 0));
    peer.run_bytes(&open_ok())
}

// Handshake ---------------------------------------------------------------

/// `(mechanism, response)` from a `connection.start-ok`.
fn start_ok(bytes: &[u8]) -> (String, Vec<u8>) {
    let args = args_of(bytes, class::CONNECTION, connection::START_OK);
    let mut data = &args[..];
    decode_table(&mut data).unwrap();
    let mech = decode_shortstr(&mut data).unwrap().to_owned();
    let response = decode_longstr(&mut data).unwrap().to_vec();
    (mech, response)
}

#[test]
fn start_is_answered_with_plain_credentials() {
    let (mut peer, _events) = connect();
    let sent = peer.run_bytes(&start("AMQPLAIN PLAIN"));
    assert_eq!(start_ok(&sent), ("PLAIN".to_string(), b"\0guest\0secret".to_vec()));
}

#[test]
fn start_falls_back_to_amqplain() {
    let (mut peer, _events) = connect();
    let sent = peer.run_bytes(&start("AMQPLAIN"));
    let (mech, response) = start_ok(&sent);
    assert_eq!(mech, "AMQPLAIN");
    assert_eq!(response, encode_amqplain("guest", "secret").unwrap());
}

#[test]
fn start_declares_the_extensions_the_client_handles() {
    let (mut peer, _events) = connect();
    let sent = peer.run_bytes(&start("PLAIN"));
    let args = args_of(&sent, class::CONNECTION, connection::START_OK);
    let mut data = &args[..];
    let props = decode_table(&mut data).unwrap();
    let text = format!("{props:?}");
    assert!(text.contains("consumer_cancel_notify"), "{text}");
    assert!(text.contains("connection.blocked"), "{text}");
}

#[test]
fn start_with_no_usable_mechanism_fails() {
    let (mut peer, events) = connect();
    let sent = peer.run_bytes(&start("GSSAPI"));
    assert!(sent.is_empty());
    assert!(seen(&events)[0].starts_with("error:"), "{:?}", seen(&events));
}

#[test]
fn a_forced_mechanism_the_broker_lacks_fails() {
    let mut p = params();
    p.mechanism = Some("EXTERNAL".into());
    let (mut peer, events) = connect_with(p, Box::new(|_, _| {}));
    assert!(peer.run_bytes(&start("PLAIN AMQPLAIN")).is_empty());
    assert!(seen(&events)[0].starts_with("error:"));
}

#[test]
fn external_needs_a_secure_connection() {
    let mut p = params();
    p.mechanism = Some("EXTERNAL".into());
    let (mut peer, events) = connect_with(p, Box::new(|_, _| {}));
    assert!(peer.run_bytes(&start("PLAIN EXTERNAL")).is_empty());
    let e = seen(&events);
    assert!(e[0].contains("TLS"), "{e:?}");
}

#[test]
fn a_mechanism_that_is_not_implemented_fails() {
    let mut p = params();
    p.mechanism = Some("GSSAPI".into());
    let (mut peer, events) = connect_with(p, Box::new(|_, _| {}));
    assert!(peer.run_bytes(&start("GSSAPI")).is_empty());
    assert!(seen(&events)[0].contains("unsupported"), "{:?}", seen(&events));
}

#[test]
fn tune_is_answered_with_tune_ok_and_open() {
    let (mut peer, _events) = connect();
    peer.run_bytes(&start("PLAIN"));
    let sent = peer.run_bytes(&tune(2047, 131_072, 60));
    assert_eq!(
        methods(&sent),
        [(0, class::CONNECTION, connection::TUNE_OK), (0, class::CONNECTION, connection::OPEN)]
    );
    let ok = ConnectionTune::decode(&args_of(&sent, class::CONNECTION, connection::TUNE_OK)).unwrap();
    assert_eq!((ok.channel_max, ok.frame_max, ok.heartbeat), (2047, 131_072, 60));
    let open_args = args_of(&sent, class::CONNECTION, connection::OPEN);
    let mut data = &open_args[..];
    assert_eq!(decode_shortstr(&mut data).unwrap(), "/");
}

#[test]
fn tune_takes_the_smaller_of_what_each_side_wants() {
    let mut p = params();
    p.channel_max = 10;
    p.frame_max = 8192;
    p.heartbeat = 30;
    let (mut peer, _events) = connect_with(p, Box::new(|_, _| {}));
    peer.run_bytes(&start("PLAIN"));
    let sent = peer.run_bytes(&tune(2047, 131_072, 60));
    let ok = ConnectionTune::decode(&args_of(&sent, class::CONNECTION, connection::TUNE_OK)).unwrap();
    assert_eq!((ok.channel_max, ok.frame_max, ok.heartbeat), (10, 8192, 30));
}

#[test]
fn a_broker_that_asks_for_no_limit_gets_the_defaults_or_the_clients_choice() {
    let mut p = params();
    p.heartbeat = 20;
    let (mut peer, _events) = connect_with(p, Box::new(|_, _| {}));
    peer.run_bytes(&start("PLAIN"));
    let sent = peer.run_bytes(&tune(0, 0, 0));
    let ok = ConnectionTune::decode(&args_of(&sent, class::CONNECTION, connection::TUNE_OK)).unwrap();
    assert_eq!((ok.channel_max, ok.frame_max, ok.heartbeat), (2047, 131_072, 20));
}

#[test]
fn open_ok_tells_the_driver_the_connection_is_open() {
    let (mut peer, events) = connect();
    peer.run_bytes(&start("PLAIN"));
    peer.run_bytes(&tune(2047, 131_072, 0));
    assert!(seen(&events).is_empty());
    peer.run_bytes(&open_ok());
    assert_eq!(seen(&events), ["open"]);
}

#[test]
fn the_handshake_is_the_same_at_every_chunking() {
    let mut wire = start("PLAIN AMQPLAIN");
    wire.extend(tune(2047, 131_072, 0));
    wire.extend(open_ok());
    let run = |chunk: usize| {
        let (mut peer, events) = connect();
        let sent = peer.run_chunked_bytes(&wire, chunk);
        (sent, seen(&events))
    };
    let whole = run(wire.len());
    assert_eq!(whole.1, ["open"]);
    for chunk in [1, 2, 3, 7, 11] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

#[test]
fn a_secure_challenge_with_no_exchange_in_progress_fails() {
    let (mut peer, events) = opened();
    let mut args = Vec::new();
    encode_longstr(&mut args, b"challenge");
    peer.run_bytes(&m(0, class::CONNECTION, connection::SECURE, &args));
    assert!(seen(&events)[0].contains("connection.secure"), "{:?}", seen(&events));
}

#[test]
fn the_negotiated_frame_max_governs_what_the_client_will_read() {
    // The broker agrees to frames of up to 1 MiB, then sends one bigger than
    // the 128 KiB default.
    let (mut peer, events) = connect();
    peer.run_bytes(&start("PLAIN"));
    peer.run_bytes(&tune(2047, 1 << 20, 0));
    peer.run_bytes(&open_ok());
    events.lock().unwrap().clear();
    let body = vec![b'x'; 300_000];
    peer.run_bytes(&{
        let mut wire = m(1, class::BASIC, basic::DELIVER, &deliver_args("c", 1, false, "", "q"));
        wire.extend(encode_content_header(1, body.len() as u64, &BasicProperties::new()).unwrap());
        wire.extend(encode_content_body_chunk(1, &body, 1 << 20));
        wire
    });
    let e = seen(&events);
    assert_eq!(e.len(), 2, "{:?}", e.iter().map(|s| s.chars().take(60).collect::<String>()).collect::<Vec<_>>());
    assert!(e[0].starts_with("delivery:1:c:1:false::q:-:300000"), "{}", e[0]);
    assert_eq!(e[1].len(), "delivered:1:".len() + 300_000);
}

#[test]
fn a_smaller_negotiated_frame_max_is_enforced_on_what_the_client_reads() {
    let (mut peer, events) = connect();
    peer.run_bytes(&start("PLAIN"));
    peer.run_bytes(&tune(2047, 4096, 0));
    peer.run_bytes(&open_ok());
    events.lock().unwrap().clear();
    peer.run_bytes(&delivery(1, 1, &[b'x'; 5000], 5000));
    let e = seen(&events);
    assert!(e.iter().any(|e| e.starts_with("error:")), "{} events, last {:.60}", e.len(), e.last().unwrap());
}

// Closing -----------------------------------------------------------------

#[test]
fn the_broker_closing_the_connection_is_acknowledged() {
    let (mut peer, events) = opened();
    let sent = peer.run_bytes(&m(0, class::CONNECTION, connection::CLOSE, &close_args(320, "forced")));
    assert_eq!(methods(&sent), [(0, class::CONNECTION, connection::CLOSE_OK)]);
    assert_eq!(seen(&events), ["connection_close:320:forced"]);
    assert!(peer.is_closed());
}

#[test]
fn close_ok_closes_the_connection() {
    let (mut peer, _events) = opened();
    peer.run_bytes(&m(0, class::CONNECTION, connection::CLOSE_OK, &[]));
    assert!(peer.is_closed());
}

#[test]
fn the_client_can_close_the_connection() {
    let sent = publisher(
        |e, c| {
            if e == "open" {
                c.connection_close(200, "bye");
            }
        },
        131_072,
    );
    let close = CloseArgs::decode(&args_of(&sent, class::CONNECTION, connection::CLOSE)).unwrap();
    assert_eq!((close.reply_code, close.reply_text.as_str()), (200, "bye"));
}

#[test]
fn the_broker_closing_a_channel_is_acknowledged() {
    let (mut peer, events) = opened();
    let sent = peer.run_bytes(&m(3, class::CHANNEL, channel::CLOSE, &close_args(404, "no queue")));
    assert_eq!(methods(&sent), [(3, class::CHANNEL, channel::CLOSE_OK)]);
    assert_eq!(seen(&events), ["channel_close:3:404:no queue"]);
    assert!(!peer.is_closed());
}

#[test]
fn channel_close_ok_reports_a_clean_close() {
    let (mut peer, events) = opened();
    peer.run_bytes(&m(3, class::CHANNEL, channel::CLOSE_OK, &[]));
    assert_eq!(seen(&events), ["channel_close:3:200:OK"]);
}

#[test]
fn channel_flow_is_echoed_with_the_same_setting() {
    let (mut peer, events) = opened();
    for active in [false, true] {
        let sent = peer.run_bytes(&m(1, class::CHANNEL, channel::FLOW, &[active as u8]));
        let (ch, cl, me) = methods(&sent)[0];
        assert_eq!((ch, cl, me), (1, class::CHANNEL, channel::FLOW_OK));
        assert_eq!(args_of(&sent, class::CHANNEL, channel::FLOW_OK), [active as u8]);
    }
    assert_eq!(seen(&events), ["flow:1:false", "flow:1:true"]);
}

#[test]
fn flow_ok_is_passed_to_the_driver() {
    let (mut peer, events) = opened();
    peer.run_bytes(&m(1, class::CHANNEL, channel::FLOW_OK, &[1]));
    assert_eq!(seen(&events), ["flow_ok:1:true"]);
}

#[test]
fn blocked_and_unblocked_are_passed_to_the_driver() {
    let (mut peer, events) = opened();
    peer.run_bytes(&m(0, class::CONNECTION, connection::BLOCKED, &shortstr("low on memory")));
    peer.run_bytes(&m(0, class::CONNECTION, connection::UNBLOCKED, &[]));
    assert_eq!(seen(&events), ["blocked:low on memory", "unblocked"]);
}

// Replies to the client's requests -----------------------------------------

#[test]
fn replies_reach_the_driver_with_their_values() {
    let (mut peer, events) = opened();
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (m(1, class::CHANNEL, channel::OPEN_OK, &[0, 0, 0, 0]), "channel_open:1"),
        (m(1, class::EXCHANGE, exchange::DECLARE_OK, &[]), "exchange_declare_ok:1"),
        (m(1, class::EXCHANGE, exchange::DELETE_OK, &[]), "exchange_delete_ok:1"),
        (
            m(1, class::QUEUE, queue::DECLARE_OK, &{
                let mut a = shortstr("jobs");
                a.extend(counts(7, 2));
                a
            }),
            "queue_declare_ok:1:jobs:7:2",
        ),
        (m(1, class::QUEUE, queue::BIND_OK, &[]), "queue_bind_ok:1"),
        (m(1, class::QUEUE, queue::UNBIND_OK, &[]), "queue_unbind_ok:1"),
        (m(1, class::QUEUE, queue::PURGE_OK, &5u32.to_be_bytes()), "queue_purge_ok:1:5"),
        (m(1, class::QUEUE, queue::DELETE_OK, &9u32.to_be_bytes()), "queue_delete_ok:1:9"),
        (m(1, class::CONFIRM, confirm::SELECT_OK, &[]), "confirm_select_ok:1"),
        (m(1, class::BASIC, basic::QOS_OK, &[]), "qos_ok:1"),
        (m(1, class::BASIC, basic::CONSUME_OK, &shortstr("c1")), "consume_ok:1:c1"),
        (m(1, class::BASIC, basic::CANCEL_OK, &shortstr("c1")), "cancel_ok:1:c1"),
        (m(1, class::BASIC, basic::GET_EMPTY, &shortstr("")), "get_empty:1"),
        (m(1, class::BASIC, basic::RECOVER_OK, &[]), "recover_ok:1"),
        (m(1, class::TX, tx::SELECT_OK, &[]), "tx_select_ok:1"),
        (m(1, class::TX, tx::COMMIT_OK, &[]), "tx_commit_ok:1"),
        (m(1, class::TX, tx::ROLLBACK_OK, &[]), "tx_rollback_ok:1"),
    ];
    for (wire, expect) in cases {
        peer.run_bytes(&wire);
        assert_eq!(seen(&events).pop().as_deref(), Some(expect));
    }
}

#[test]
fn publisher_confirms_are_passed_to_the_driver() {
    let (mut peer, events) = opened();
    let mut ack = 42u64.to_be_bytes().to_vec();
    ack.push(1);
    peer.run_bytes(&m(1, class::BASIC, basic::ACK, &ack));
    let mut nack = 43u64.to_be_bytes().to_vec();
    nack.push(0b10); // multiple = false, requeue = true
    peer.run_bytes(&m(1, class::BASIC, basic::NACK, &nack));
    assert_eq!(seen(&events), ["ack:1:42:true", "nack:1:43:false:true"]);
}

#[test]
fn a_consumer_cancelled_by_the_broker_is_acknowledged_unless_no_wait() {
    let (mut peer, events) = opened();
    let mut wait = shortstr("c1");
    wait.push(0);
    let sent = peer.run_bytes(&m(1, class::BASIC, basic::CANCEL, &wait));
    assert_eq!(methods(&sent), [(1, class::BASIC, basic::CANCEL_OK)]);

    let mut no_wait = shortstr("c2");
    no_wait.push(1);
    let sent = peer.run_bytes(&m(1, class::BASIC, basic::CANCEL, &no_wait));
    assert!(sent.is_empty());
    assert_eq!(seen(&events), ["consumer_cancelled:1:c1", "consumer_cancelled:1:c2"]);
}

// Content -----------------------------------------------------------------

#[test]
fn a_delivery_arrives_as_start_data_and_complete() {
    let (mut peer, events) = opened();
    peer.run_bytes(&delivery(1, 5, b"hello", 1024));
    assert_eq!(seen(&events), ["delivery:1:ctag:5:false:ex:rk:-:5", "delivered:1:hello"]);
}

#[test]
fn a_body_in_several_frames_is_delivered_whole() {
    let (mut peer, events) = opened();
    peer.run_bytes(&delivery(1, 1, b"abcdefghij", 3));
    assert_eq!(seen(&events).last().unwrap(), "delivered:1:abcdefghij");
}

#[test]
fn an_empty_delivery_completes_at_its_header() {
    let (mut peer, events) = opened();
    peer.run_bytes(&delivery(1, 1, b"", 1));
    assert_eq!(seen(&events), ["delivery:1:ctag:1:false:ex:rk:-:0", "delivered:1:"]);
}

#[test]
fn deliveries_are_the_same_at_every_chunking() {
    let mut wire = delivery(1, 1, b"first body", 4);
    wire.extend(delivery(2, 2, b"second", 100));
    wire.extend(delivery(1, 3, b"", 1));
    let run = |chunk: usize| {
        let (mut peer, events) = opened();
        peer.run_chunked_bytes(&wire, chunk);
        seen(&events)
    };
    let whole = run(wire.len());
    assert_eq!(whole.len(), 6, "{whole:?}");
    for chunk in [1, 2, 5, 13] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

#[test]
fn a_returned_message_arrives_with_its_reason() {
    let (mut peer, events) = opened();
    let mut args = 312u16.to_be_bytes().to_vec();
    args.extend(shortstr("NO_ROUTE"));
    args.extend(shortstr("ex"));
    args.extend(shortstr("nowhere"));
    let mut wire = m(1, class::BASIC, basic::RETURN, &args);
    wire.extend(encode_content_header(1, 4, &BasicProperties::new()).unwrap());
    wire.extend(encode_content_body_chunk(1, b"lost", 1 << 20));
    peer.run_bytes(&wire);
    assert_eq!(seen(&events), ["return:1:312:NO_ROUTE:ex:nowhere:4", "returned:1:lost"]);
}

#[test]
fn a_get_ok_message_arrives_with_the_queue_depth() {
    let (mut peer, events) = opened();
    let mut args = 9u64.to_be_bytes().to_vec();
    args.push(1);
    args.extend(shortstr("ex"));
    args.extend(shortstr("rk"));
    args.extend(3u32.to_be_bytes());
    let mut wire = m(1, class::BASIC, basic::GET_OK, &args);
    wire.extend(encode_content_header(1, 2, &BasicProperties::new()).unwrap());
    wire.extend(encode_content_body_chunk(1, b"hi", 1 << 20));
    peer.run_bytes(&wire);
    let e = seen(&events);
    assert_eq!(e[0], "get_ok:1:9:true:ex:rk:3:2");
    assert_eq!(e.len(), 2, "{e:?}");
}

#[test]
fn a_content_header_with_no_method_before_it_fails() {
    let (mut peer, events) = opened();
    peer.run_bytes(&encode_content_header(1, 3, &BasicProperties::new()).unwrap());
    assert!(seen(&events)[0].starts_with("error:"));
}

#[test]
fn body_on_a_channel_with_nothing_in_flight_is_refused() {
    let (mut peer, events) = opened();
    peer.run_bytes(&encode_content_body_chunk(4, b"stray", 1 << 20));
    assert!(seen(&events)[0].starts_with("error:"), "{:?}", seen(&events));
}

// Heartbeats and failures --------------------------------------------------

#[test]
fn a_broker_heartbeat_is_not_an_error() {
    let (mut peer, events) = opened();
    peer.run_bytes(&encode_heartbeat());
    assert!(seen(&events).is_empty());
}

#[test]
fn a_heartbeat_timer_makes_the_client_send_a_heartbeat() {
    let mut p = params();
    p.heartbeat = 30;
    let (mut peer, events) = connect_with(p, Box::new(|_, _| {}));
    peer.run_bytes(&start("PLAIN"));
    peer.run_bytes(&tune(2047, 131_072, 30));
    peer.run_bytes(&open_ok());
    peer.take_bytes();
    peer.fail(&io::Error::new(io::ErrorKind::TimedOut, "hopf-amqp-heartbeat-due"));
    assert_eq!(decode(&peer.take_bytes()), [Out::Heartbeat]);
    assert_eq!(seen(&events), ["open"], "a heartbeat is not an error");
}

#[test]
fn other_connection_errors_reach_the_driver() {
    let (mut peer, events) = opened();
    peer.fail(&io::Error::new(io::ErrorKind::ConnectionReset, "reset"));
    assert_eq!(seen(&events), ["error:reset"]);
}

#[test]
fn a_dropped_connection_reaches_the_driver() {
    let (mut peer, events) = opened();
    peer.disconnect();
    assert_eq!(seen(&events), ["disconnected"]);
}

#[test]
fn a_frame_without_its_end_marker_fails() {
    let (mut peer, events) = opened();
    let mut wire = m(0, class::CONNECTION, connection::BLOCKED, &shortstr("x"));
    let last = wire.len() - 1;
    wire[last] = 0;
    peer.run_bytes(&wire);
    assert!(seen(&events)[0].starts_with("error:"), "{:?}", seen(&events));
}

// What the client sends ----------------------------------------------------

#[test]
fn control_calls_send_the_matching_methods() {
    let sent = publisher(
        |e, c| {
            if e != "open" {
                return;
            }
            let none = FieldTable::new();
            c.channel_open(1);
            c.exchange_declare(1, "ex", "direct", false, true, false, false, &none);
            c.exchange_delete(1, "ex", false);
            c.queue_declare(1, "q", false, true, false, false, &none);
            c.queue_bind(1, "q", "ex", "rk", &none);
            c.queue_unbind(1, "q", "ex", "rk", &none);
            c.queue_purge(1, "q");
            c.queue_delete(1, "q", false, false);
            c.confirm_select(1);
            c.basic_qos(1, 0, 10, false);
            c.basic_consume(1, "q", "c1", false, false, false, &none);
            c.basic_cancel(1, "c1");
            c.basic_get(1, "q", true);
            c.basic_ack(1, 5, false);
            c.basic_nack(1, 6, true, true);
            c.basic_reject(1, 7, false);
            c.basic_recover(1, true);
            c.flow(1, false);
            c.tx_select(1);
            c.tx_commit(1);
            c.tx_rollback(1);
            c.channel_close(1, 200, "done");
        },
        131_072,
    );
    let ids: Vec<(u16, u16)> = methods(&sent).into_iter().map(|(_, c, m)| (c, m)).collect();
    assert_eq!(
        ids,
        [
            (class::CHANNEL, channel::OPEN),
            (class::EXCHANGE, exchange::DECLARE),
            (class::EXCHANGE, exchange::DELETE),
            (class::QUEUE, queue::DECLARE),
            (class::QUEUE, queue::BIND),
            (class::QUEUE, queue::UNBIND),
            (class::QUEUE, queue::PURGE),
            (class::QUEUE, queue::DELETE),
            (class::CONFIRM, confirm::SELECT),
            (class::BASIC, basic::QOS),
            (class::BASIC, basic::CONSUME),
            (class::BASIC, basic::CANCEL),
            (class::BASIC, basic::GET),
            (class::BASIC, basic::ACK),
            (class::BASIC, basic::NACK),
            (class::BASIC, basic::REJECT),
            (class::BASIC, basic::RECOVER),
            (class::CHANNEL, channel::FLOW),
            (class::TX, tx::SELECT),
            (class::TX, tx::COMMIT),
            (class::TX, tx::ROLLBACK),
            (class::CHANNEL, channel::CLOSE),
        ]
    );
}

#[test]
fn channels_beyond_the_negotiated_maximum_are_not_opened() {
    let mut p = params();
    p.channel_max = 4;
    let (mut peer, _events) = connect_with(
        p,
        Box::new(|e, c| {
            if e == "open" {
                c.channel_open(0);
                c.channel_open(5);
                c.channel_open(4);
            }
        }),
    );
    peer.run_bytes(&start("PLAIN"));
    peer.run_bytes(&tune(2047, 131_072, 0));
    let sent = peer.run_bytes(&open_ok());
    assert_eq!(methods(&sent), [(4, class::CHANNEL, channel::OPEN)]);
}

#[test]
fn a_publish_is_a_method_a_header_and_body_frames() {
    let sent = publisher(
        |e, c| {
            if e == "open" {
                let mut props = BasicProperties::new();
                props.content_type = Some("text/plain".into());
                c.basic_publish(1, "ex", "rk", false, false, &props, b"hello");
            }
        },
        131_072,
    );
    assert_eq!(
        decode(&sent),
        [
            Out::Method { ch: 1, class: class::BASIC, method: basic::PUBLISH, args: args_of(&sent, class::BASIC, basic::PUBLISH) },
            Out::Header { ch: 1, size: 5 },
            Out::Body { ch: 1, len: 5 },
        ]
    );
}

#[test]
fn a_big_publish_is_split_to_the_negotiated_frame_size() {
    let sent = publisher(
        |e, c| {
            if e == "open" {
                c.basic_publish(1, "", "q", false, false, &BasicProperties::new(), &[7u8; 10_000]);
            }
        },
        4096,
    );
    let bodies: Vec<usize> = decode(&sent)
        .into_iter()
        .filter_map(|o| match o {
            Out::Body { len, .. } => Some(len),
            _ => None,
        })
        .collect();
    assert_eq!(bodies.iter().sum::<usize>(), 10_000);
    assert!(bodies.len() >= 3, "{bodies:?}");
    assert!(bodies.iter().all(|&l| l <= 4096), "{bodies:?}");
}

#[test]
fn a_streamed_publish_sends_the_header_then_each_chunk() {
    let sent = publisher(
        |e, c| {
            if e == "open" {
                c.basic_publish_start(1, "", "q", false, false, &BasicProperties::new(), 6);
                c.basic_publish_body(1, b"abc");
                c.basic_publish_body(1, b"def");
            }
        },
        131_072,
    );
    let out = decode(&sent);
    assert_eq!(out[1], Out::Header { ch: 1, size: 6 });
    assert_eq!(out[2..], [Out::Body { ch: 1, len: 3 }, Out::Body { ch: 1, len: 3 }]);
}

#[test]
fn small_arguments_round_trip_through_the_encoders() {
    // basic.ack: delivery tag then the multiple bit.
    let sent = publisher(
        |e, c| {
            if e == "open" {
                c.basic_ack(2, 0x0102_0304_0506_0708, true);
            }
        },
        131_072,
    );
    let args = args_of(&sent, class::BASIC, basic::ACK);
    assert_eq!(args, [1, 2, 3, 4, 5, 6, 7, 8, 1]);
}
