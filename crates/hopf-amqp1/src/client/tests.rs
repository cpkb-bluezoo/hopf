// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! End-to-end tests of the real [`Amqp1Client`], on the real `hopf-core`
//! `Runtime`, against a scripted in-tree AMQP 1.0 peer over a real loopback
//! TCP socket — mirrors this workspace's other client protocol crates'
//! fake-peer test pattern (e.g. `hopf-ldap`'s RFC 4533 sync tests).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hopf_core::{Runtime, RuntimeConfig};

use crate::codec::message::{MessageHandler, MessageHeader, MessageParser, MessageProperties};
use crate::codec::sasl::outcome_code;
use crate::codec::{
    decode_performative, Amqp1CompositeError, Attach, Begin, Close, DeliveryState, Disposition,
    Encoder, End, FRAME_TYPE_AMQP, FRAME_TYPE_SASL, Flow, Open, Performative, PROTOCOL_ID_AMQP,
    PROTOCOL_ID_SASL, SaslBody, Source, Target, Transfer,
};
use crate::codec::{Amqp1FrameHandler, Amqp1FrameParser};

use super::{Amqp1Client, Amqp1ClientControl, Amqp1ClientDriver, Amqp1ClientHandlerFactory};

// Generous relative to what this test actually needs (a handful of
// loopback round trips) because `cargo test` runs many test binaries'
// threads concurrently — under heavy parallel load a tight deadline here
// is a source of flakiness having nothing to do with the client's own
// correctness (issue observed: 5s was occasionally too tight when the
// whole workspace's tests ran at once).
const WAIT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------
// Wire helpers (peer side).
// ---------------------------------------------------------------------

fn protocol_header(protocol_id: u8) -> Vec<u8> {
    let mut v = b"AMQP".to_vec();
    v.push(protocol_id);
    v.extend_from_slice(&[1, 0, 0]);
    v
}

fn frame_bytes(frame_type: u8, channel: u16, body: &[u8]) -> Vec<u8> {
    let size = (8 + body.len()) as u32;
    let mut v = Vec::with_capacity(size as usize);
    v.extend_from_slice(&size.to_be_bytes());
    v.push(2);
    v.push(frame_type);
    v.extend_from_slice(&channel.to_be_bytes());
    v.extend_from_slice(body);
    v
}

#[derive(Debug)]
enum Event {
    ProtocolHeader(u8),
    Frame { frame_type: u8, channel: u16, body: Vec<u8> },
}

struct Collector<'a> {
    events: &'a mut Vec<Event>,
}

impl Amqp1FrameHandler for Collector<'_> {
    fn protocol_header(&mut self, protocol_id: u8, _major: u8, _minor: u8, _revision: u8) {
        self.events.push(Event::ProtocolHeader(protocol_id));
    }
    fn frame(&mut self, frame_type: u8, channel: u16, body: &[u8]) -> crate::codec::FrameOutcome {
        self.events.push(Event::Frame { frame_type, channel, body: body.to_vec() });
        crate::codec::FrameOutcome::NONE
    }
    fn empty_frame(&mut self, frame_type: u8, channel: u16) -> crate::codec::FrameOutcome {
        self.events.push(Event::Frame { frame_type, channel, body: Vec::new() });
        crate::codec::FrameOutcome::NONE
    }
    fn error(&mut self, err: crate::codec::Amqp1Error) {
        panic!("peer-side frame parse error: {err}");
    }
}

/// A hand-driven AMQP 1.0 peer connection: reads/decodes with the crate's
/// own frame parser, writes raw bytes built from the crate's own
/// encoder/performative types.
struct WireConn {
    stream: TcpStream,
    parser: Amqp1FrameParser,
    queue: Vec<Event>,
}

impl WireConn {
    fn new(stream: TcpStream) -> Self {
        stream.set_read_timeout(Some(WAIT)).unwrap();
        Self { stream, parser: Amqp1FrameParser::new(0), queue: Vec::new() }
    }

    fn next_event(&mut self) -> Event {
        loop {
            if !self.queue.is_empty() {
                return self.queue.remove(0);
            }
            let mut buf = [0u8; 65536];
            let n = self.stream.read(&mut buf).expect("read from client");
            assert!(n > 0, "client closed the connection unexpectedly");
            let mut collector = Collector { events: &mut self.queue };
            self.parser.feed(&buf[..n], &mut collector);
        }
    }

    fn next_frame(&mut self) -> (u8, u16, Vec<u8>) {
        match self.next_event() {
            Event::Frame { frame_type, channel, body } => (frame_type, channel, body),
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    fn next_amqp_performative(&mut self) -> (Performative, Vec<u8>) {
        let (frame_type, _channel, body) = self.next_frame();
        assert_eq!(frame_type, FRAME_TYPE_AMQP);
        let (performative, consumed) = decode_performative(&body).expect("decode performative");
        (performative, body[consumed..].to_vec())
    }

    fn expect_protocol_header(&mut self, expected: u8) {
        match self.next_event() {
            Event::ProtocolHeader(id) => assert_eq!(id, expected),
            other => panic!("expected a protocol header, got {other:?}"),
        }
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).unwrap();
    }

    fn send_performative(&mut self, channel: u16, performative: &Performative) {
        let body = performative.encode();
        self.send_raw(&frame_bytes(FRAME_TYPE_AMQP, channel, &body));
    }

    fn send_performative_with_payload(&mut self, channel: u16, performative: &Performative, payload: &[u8]) {
        let mut body = performative.encode();
        body.extend_from_slice(payload);
        self.send_raw(&frame_bytes(FRAME_TYPE_AMQP, channel, &body));
    }

    fn send_sasl(&mut self, body: &SaslBody) {
        self.send_raw(&frame_bytes(FRAME_TYPE_SASL, 0, &body.encode()));
    }
}

// ---------------------------------------------------------------------
// Peer script.
// ---------------------------------------------------------------------

fn peer_thread(listener: TcpListener) {
    let (stream, _) = listener.accept().unwrap();
    let mut conn = WireConn::new(stream);

    // --- SASL: offer ANONYMOUS, expect the client to choose it. ---
    conn.expect_protocol_header(PROTOCOL_ID_SASL);
    conn.send_raw(&protocol_header(PROTOCOL_ID_SASL));
    conn.send_sasl(&SaslBody::Mechanisms(vec!["ANONYMOUS".into()]));

    let (frame_type, _channel, body) = conn.next_frame();
    assert_eq!(frame_type, FRAME_TYPE_SASL);
    match SaslBody::decode(&body).unwrap() {
        SaslBody::Init { mechanism, .. } => assert_eq!(mechanism, "ANONYMOUS"),
        other => panic!("expected sasl-init, got {other:?}"),
    }
    conn.send_sasl(&SaslBody::Outcome { code: outcome_code::OK, additional_data: None });

    // --- AMQP layer: header, open, begin. ---
    conn.parser.expect_protocol_header();
    conn.send_raw(&protocol_header(PROTOCOL_ID_AMQP));
    conn.send_performative(
        0,
        &Performative::Open(Open { container_id: "fake-peer".into(), ..Default::default() }),
    );

    conn.expect_protocol_header(PROTOCOL_ID_AMQP);
    match conn.next_amqp_performative().0 {
        Performative::Open(_) => {}
        other => panic!("expected open, got {other:?}"),
    }

    conn.send_performative(
        0,
        &Performative::Begin(Begin {
            remote_channel: Some(0), // client's local_channel for its first session
            next_outgoing_id: 0,
            incoming_window: 2048,
            outgoing_window: 2048,
            handle_max: u32::MAX,
            offered_capabilities: vec![],
            desired_capabilities: vec![],
            properties: vec![],
        }),
    );
    match conn.next_amqp_performative().0 {
        Performative::Begin(b) => {assert_eq!(b.remote_channel, None); }
        other => panic!("expected begin, got {other:?}"),
    }

    // --- Attach: client attaches a sender ("client-out") then a receiver ("client-in"). ---
    let (out_attach, _) = conn.next_amqp_performative();
    let Performative::Attach(out) = out_attach else { panic!("expected attach") };
    assert_eq!(out.name, "client-out");
    assert!(!out.role_receiver, "client should attach as sender on client-out");
    conn.send_performative(
        0,
        &Performative::Attach(Attach {
            name: "client-out".into(),
            handle: 0,
            role_receiver: true,
            snd_settle_mode: 2,
            rcv_settle_mode: 0,
            source: Some(Source::default()),
            target: Some(Target::default()),
            unsettled: vec![],
            incomplete_unsettled: false,
            initial_delivery_count: None,
            max_message_size: None,
            offered_capabilities: vec![],
            desired_capabilities: vec![],
            properties: vec![],
        }),
    );
    // Grant the client 10 credits to send on "client-out".
    conn.send_performative(
        0,
        &Performative::Flow(Flow {
            next_incoming_id: Some(0),
            incoming_window: 2048,
            next_outgoing_id: 0,
            outgoing_window: 2048,
            handle: Some(0),
            delivery_count: Some(0),
            link_credit: Some(10),
            ..Default::default()
        }),
    );

    let (in_attach, _) = conn.next_amqp_performative();
    let Performative::Attach(inn) = in_attach else { panic!("expected attach") };
    assert_eq!(inn.name, "client-in");
    assert!(inn.role_receiver, "client should attach as receiver on client-in");
    conn.send_performative(
        0,
        &Performative::Attach(Attach {
            name: "client-in".into(),
            handle: 1,
            role_receiver: false,
            snd_settle_mode: 2,
            rcv_settle_mode: 0,
            source: Some(Source::default()),
            target: Some(Target::default()),
            unsettled: vec![],
            incomplete_unsettled: false,
            initial_delivery_count: Some(0),
            max_message_size: None,
            offered_capabilities: vec![],
            desired_capabilities: vec![],
            properties: vec![],
        }),
    );

    // --- The client should now send its test message on "client-out". ---
    let (transfer_performative, payload) = conn.next_amqp_performative();
    let Performative::Transfer(transfer) = transfer_performative else { panic!("expected transfer") };
    assert_eq!(transfer.handle, 0);
    assert_eq!(transfer.delivery_tag.as_deref(), Some(&b"tag-1"[..]));
    let delivery_id = transfer.delivery_id.expect("first transfer of a delivery has a delivery-id");
    assert!(!transfer.more, "test message fits in one frame");

    #[derive(Default)]
    struct Collect {
        header: Option<MessageHeader>,
        properties: Option<MessageProperties>,
        body: Vec<u8>,
    }
    impl MessageHandler for Collect {
        fn header(&mut self, header: MessageHeader) {
            self.header = Some(header);
        }
        fn properties(&mut self, properties: MessageProperties) {
            self.properties = Some(properties);
        }
        fn data_chunk(&mut self, data: &[u8]) {
            self.body.extend_from_slice(data);
        }
        fn error(&mut self, err: crate::codec::Amqp1Error) {
            panic!("peer-side message parse error: {err}");
        }
    }
    let mut collected = Collect::default();
    let mut mp = MessageParser::new();
    mp.feed(&payload, &mut collected);
    mp.end_message(&mut collected);

    assert!(collected.header.unwrap().durable);
    assert_eq!(collected.properties.unwrap().content_type.as_deref(), Some("text/plain"));
    assert_eq!(collected.body, b"hello from client");

    conn.send_performative(
        0,
        &Performative::Disposition(Disposition {
            role_receiver: true,
            first: delivery_id,
            last: delivery_id,
            settled: true,
            state: Some(DeliveryState::Accepted),
            batchable: false,
        }),
    );

    // --- The client should add credit for "client-in", then we push a message. ---
    match conn.next_amqp_performative().0 {
        Performative::Flow(f) => {
            assert_eq!(f.handle, Some(1));
            assert!(f.link_credit.unwrap_or(0) > 0);
        }
        other => panic!("expected flow (add_credit), got {other:?}"),
    }

    let peer_header = MessageHeader { durable: false, ..Default::default() };
    let peer_props = MessageProperties { content_type: Some("text/plain".into()), ..Default::default() };
    let mut message_bytes = Vec::new();
    {
        let mut enc = Encoder::new();
        enc.value(&peer_header.encode());
        message_bytes.extend_from_slice(&enc.into_bytes());
    }
    {
        let mut enc = Encoder::new();
        enc.value(&peer_props.encode());
        message_bytes.extend_from_slice(&enc.into_bytes());
    }
    let body = b"hello from peer";
    message_bytes.extend_from_slice(&crate::codec::message::data_section_header(body.len() as u32));
    message_bytes.extend_from_slice(body);

    conn.send_performative_with_payload(
        0,
        &Performative::Transfer(Transfer {
            handle: 1,
            delivery_id: Some(0),
            delivery_tag: Some(b"peer-tag-1".to_vec()),
            settled: Some(false),
            more: false,
            ..Default::default()
        }),
        &message_bytes,
    );

    match conn.next_amqp_performative().0 {
        Performative::Disposition(d) => {
            assert!(d.role_receiver);
            assert_eq!(d.first, 0);
            assert_eq!(d.state, Some(DeliveryState::Accepted));
            assert!(d.settled);
        }
        other => panic!("expected disposition (client accepting our message), got {other:?}"),
    }

    conn.send_performative(0, &Performative::End(End::default()));
    conn.send_performative(0, &Performative::Close(Close::default()));
}

// ---------------------------------------------------------------------
// Client driver under test.
// ---------------------------------------------------------------------

#[derive(Default, Clone)]
struct State {
    connected: bool,
    sent_ok: bool,
    outcome: Option<(Vec<u8>, DeliveryState, bool)>,
    received_header: Option<MessageHeader>,
    received_properties: Option<MessageProperties>,
    received_body: Vec<u8>,
    delivery_complete: bool,
    error: Option<String>,
}

struct Driver {
    state: Arc<Mutex<State>>,
    sender_handle: Option<u32>,
    receiver_handle: Option<u32>,
}

impl Amqp1ClientDriver for Driver {
    fn on_connection_open(&mut self, control: &mut dyn Amqp1ClientControl) {
        self.state.lock().unwrap().connected = true;
        let channel = control.begin_session();
        let _ = channel;
    }

    fn on_session_begin(&mut self, control: &mut dyn Amqp1ClientControl, channel: u16) {
        self.sender_handle = Some(control.attach_sender(channel, "client-out", Target::with_address("peer.in")));
        self.receiver_handle =
            Some(control.attach_receiver(channel, "client-in", Source::with_address("peer.out")));
    }

    fn on_link_attached(&mut self, control: &mut dyn Amqp1ClientControl, handle: u32, is_receiver: bool) {
        if is_receiver {
            control.add_credit(handle, 10);
        }
    }

    fn on_credit(&mut self, control: &mut dyn Amqp1ClientControl, handle: u32) {
        if Some(handle) != self.sender_handle {
            return;
        }
        let header = MessageHeader { durable: true, ..Default::default() };
        let properties = MessageProperties { content_type: Some("text/plain".into()), ..Default::default() };
        let result = control.send(handle, b"tag-1", Some(&header), Some(&properties), &[], b"hello from client", false);
        self.state.lock().unwrap().sent_ok = result.is_ok();
    }

    fn on_message_header(&mut self, _handle: u32, header: &MessageHeader) {
        self.state.lock().unwrap().received_header = Some(header.clone());
    }

    fn on_message_properties(&mut self, _handle: u32, properties: &MessageProperties) {
        self.state.lock().unwrap().received_properties = Some(properties.clone());
    }

    fn on_message_data(&mut self, _handle: u32, data: &[u8]) {
        self.state.lock().unwrap().received_body.extend_from_slice(data);
    }

    fn on_delivery_complete(&mut self, control: &mut dyn Amqp1ClientControl, handle: u32, delivery_id: u32) {
        control.accept(handle, delivery_id);
        self.state.lock().unwrap().delivery_complete = true;
    }

    fn on_delivery_outcome(&mut self, _handle: u32, delivery_tag: &[u8], state: &DeliveryState, settled: bool) {
        self.state.lock().unwrap().outcome = Some((delivery_tag.to_vec(), state.clone(), settled));
    }

    fn on_connection_close(&mut self, _error: Option<&Amqp1CompositeError>) {}

    fn on_error(&mut self, err: &std::io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct Factory {
    state: Arc<Mutex<State>>,
}

impl Amqp1ClientHandlerFactory for Factory {
    fn create(&self) -> Box<dyn Amqp1ClientDriver> {
        Box::new(Driver { state: Arc::clone(&self.state), sender_handle: None, receiver_handle: None })
    }
}

fn wait_for(state: &Arc<Mutex<State>>, done: impl Fn(&State) -> bool, label: &str) -> State {
    let deadline = Instant::now() + WAIT;
    loop {
        {
            let s = state.lock().unwrap();
            if let Some(e) = &s.error {
                panic!("amqp1 client error: {e}");
            }
            if done(&s) {
                return s.clone();
            }
        }
        if Instant::now() > deadline {
            panic!("timeout waiting for {label}");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn send_and_receive_round_trip_against_fake_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let peer = thread::spawn(move || peer_thread(listener));

    let state = Arc::new(Mutex::new(State::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    Amqp1Client::from_addr(addr)
        .container_id("hopf-amqp1-test-client")
        .connect(&rt, Arc::new(Factory { state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(&state, |s| s.delivery_complete && s.outcome.is_some(), "round trip");

    assert!(s.connected);
    assert!(s.sent_ok, "client's send() to the peer must succeed");
    assert_eq!(s.outcome.as_ref().unwrap().0, b"tag-1");
    assert_eq!(s.outcome.as_ref().unwrap().1, DeliveryState::Accepted);
    assert!(s.outcome.as_ref().unwrap().2);

    assert!(!s.received_header.unwrap().durable, "peer's message was sent as non-durable");
    assert_eq!(s.received_properties.unwrap().content_type.as_deref(), Some("text/plain"));
    assert_eq!(s.received_body, b"hello from peer");

    peer.join().unwrap();
}
