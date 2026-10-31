// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental push parser for MQTT control packets, reading the
//! connection's inbound [`LoopBuf`].
//!
//! The parser holds none of the stream. MQTT framing is binary
//! length-prefixed: a packet other than PUBLISH is consumed once the whole
//! of it is in the ring, and decoded from a slice of the ring (copied to a
//! scratch buffer only if it wraps the ring's end).
//!
//! PUBLISH is the one packet type that can carry an unbounded payload, so
//! it gets different treatment: the fixed header, remaining-length varint,
//! and PUBLISH variable header (topic / packet id / properties) are read
//! once whole in the ring, and then payload bytes are forwarded to
//! [`MqttFrameHandler::publish_data`] as they arrive - never held - until
//! the packet's remaining length is exhausted.

use hopf_core::LoopBuf;

use super::decode;
use super::packet::{ConnectPacket, PacketType, ProtocolVersion, PublishHeader, SubscribeFilter};
use super::properties::Properties;
use super::varint::{self, VarIntResult};
use super::MqttError;

/// Default cap on a control packet's Remaining Length (1 MiB). PUBLISH
/// payloads are streamed rather than buffered, so this mostly bounds
/// CONNECT / SUBSCRIBE / PUBLISH-header pathological input.
pub const DEFAULT_MAX_PACKET_SIZE: u32 = 1_048_576;

/// Callback sink for packets emitted by [`MqttFrameParser`].
///
/// PUBLISH uses a start/data/end streaming pattern (payload may span many
/// calls); every other packet type is delivered as a single call with
/// owned, fully-decoded fields.
pub trait MqttFrameHandler {
    /// CONNECT packet received; also fixes the connection's protocol version.
    fn connect(&mut self, packet: ConnectPacket);
    /// CONNACK packet received.
    fn connack(&mut self, session_present: bool, reason_code: u8, properties: Properties);
    /// PUBLISH header parsed; `publish_data` follows for `header.payload_len` bytes total.
    fn start_publish(&mut self, header: PublishHeader);
    /// A chunk of the current PUBLISH payload (zero-copy view, valid for this call only).
    fn publish_data(&mut self, data: &[u8]);
    /// The current PUBLISH payload is complete.
    fn end_publish(&mut self);
    /// PUBACK packet received.
    fn puback(&mut self, packet_id: u16, reason_code: u8, properties: Properties);
    /// PUBREC packet received.
    fn pubrec(&mut self, packet_id: u16, reason_code: u8, properties: Properties);
    /// PUBREL packet received.
    fn pubrel(&mut self, packet_id: u16, reason_code: u8, properties: Properties);
    /// PUBCOMP packet received.
    fn pubcomp(&mut self, packet_id: u16, reason_code: u8, properties: Properties);
    /// SUBSCRIBE packet received.
    fn subscribe(&mut self, packet_id: u16, properties: Properties, filters: Vec<SubscribeFilter>);
    /// SUBACK packet received.
    fn suback(&mut self, packet_id: u16, properties: Properties, reason_codes: Vec<u8>);
    /// UNSUBSCRIBE packet received.
    fn unsubscribe(&mut self, packet_id: u16, properties: Properties, topic_filters: Vec<String>);
    /// UNSUBACK packet received.
    fn unsuback(&mut self, packet_id: u16, properties: Properties, reason_codes: Vec<u8>);
    /// PINGREQ packet received.
    fn ping_req(&mut self);
    /// PINGRESP packet received.
    fn ping_resp(&mut self);
    /// DISCONNECT packet received.
    fn disconnect(&mut self, reason_code: u8, properties: Properties);
    /// AUTH packet received (MQTT 5.0 only).
    fn auth(&mut self, reason_code: u8, properties: Properties);
    /// Unrecoverable parse error; the connection should be closed.
    fn parse_error(&mut self, err: MqttError);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    PublishPayload { remaining: u32 },
}

enum ParseStep {
    NeedMoreData,
    Progressed,
    Fatal,
}

/// Incremental MQTT control packet parser.
pub struct MqttFrameParser {
    version: ProtocolVersion,
    max_packet_size: u32,
    state: State,
    /// A packet or PUBLISH header that wraps the ring's end, copied to be
    /// decoded as one slice.
    scratch: Vec<u8>,
}

impl MqttFrameParser {
    /// Create a parser. `version` is the version to assume until a CONNECT
    /// packet (server side) fixes it, or the version already negotiated
    /// (client side).
    pub fn new(version: ProtocolVersion) -> Self {
        Self {
            version,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            state: State::Idle,
            scratch: Vec::new(),
        }
    }

    /// Current protocol version used to interpret v5-only wire fields.
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Update the protocol version (e.g. after decoding CONNECT).
    pub fn set_version(&mut self, version: ProtocolVersion) {
        self.version = version;
    }

    /// Override the Remaining Length cap (default [`DEFAULT_MAX_PACKET_SIZE`]).
    /// A packet other than PUBLISH must also fit the ring it is read from.
    pub fn set_max_packet_size(&mut self, max_packet_size: u32) {
        self.max_packet_size = max_packet_size;
    }

    /// Dispatches every packet `buf` holds to `handler`, consuming from it. A
    /// packet that is not all there yet stays in `buf` (a PUBLISH payload
    /// goes through as it arrives).
    pub fn receive(&mut self, buf: &mut LoopBuf, handler: &mut dyn MqttFrameHandler) {
        loop {
            match self.state {
                State::PublishPayload { remaining } => {
                    if buf.is_empty() {
                        return;
                    }
                    let n = (remaining as usize).min(buf.len());
                    let (first, second) = buf.readable_spans();
                    let first_len = first.len().min(n);
                    handler.publish_data(&first[..first_len]);
                    if n > first_len {
                        handler.publish_data(&second[..n - first_len]);
                    }
                    buf.advance(n);
                    let left = remaining - n as u32;
                    if left == 0 {
                        handler.end_publish();
                        self.state = State::Idle;
                    } else {
                        self.state = State::PublishPayload { remaining: left };
                        return;
                    }
                }
                State::Idle => match self.try_parse_idle(buf, handler) {
                    ParseStep::NeedMoreData => return,
                    ParseStep::Progressed => {}
                    ParseStep::Fatal => {
                        buf.advance(buf.len());
                        self.state = State::Idle;
                        return;
                    }
                },
            }
        }
    }

    /// Parse the fixed header + remaining-length varint at the front of
    /// `buf`, then either dispatch a complete non-PUBLISH packet or read a
    /// PUBLISH's header and switch to [`State::PublishPayload`].
    fn try_parse_idle(&mut self, buf: &mut LoopBuf, handler: &mut dyn MqttFrameHandler) -> ParseStep {
        if buf.len() < 2 {
            return ParseStep::NeedMoreData;
        }
        // The fixed header is a byte and a varint of up to 4; a fifth byte
        // with the continuation bit set is what makes it malformed.
        let mut head = [0u8; 6];
        let have = buf.len().min(head.len());
        copy_front(buf, &mut head[..have]);
        let byte0 = head[0];
        let type_value = (byte0 >> 4) & 0x0F;
        let flags = byte0 & 0x0F;

        let (remaining_length, varint_len) = match varint::decode(&head[1..have]) {
            VarIntResult::Ok { value, len } => (value, len),
            VarIntResult::NeedMoreData => return ParseStep::NeedMoreData,
            VarIntResult::Malformed => {
                handler.parse_error(MqttError::Malformed("malformed remaining length"));
                return ParseStep::Fatal;
            }
        };
        if remaining_length > self.max_packet_size {
            handler.parse_error(MqttError::PacketTooLarge {
                remaining_length,
                max: self.max_packet_size,
            });
            return ParseStep::Fatal;
        }
        let Some(ty) = PacketType::from_value(type_value) else {
            handler.parse_error(MqttError::UnknownPacketType(type_value));
            return ParseStep::Fatal;
        };
        let header_len = 1 + varint_len;

        if ty == PacketType::Publish {
            return self.try_parse_publish(buf, handler, flags, remaining_length, header_len);
        }

        let total = header_len + remaining_length as usize;
        if total > buf.capacity() {
            // Held whole, so it must fit the ring.
            handler.parse_error(MqttError::PacketTooLarge {
                remaining_length,
                max: (buf.capacity() - header_len) as u32,
            });
            return ParseStep::Fatal;
        }
        if buf.len() < total {
            return ParseStep::NeedMoreData;
        }
        let version = self.version;
        let result = self.with_front(buf, total, |body| {
            dispatch_non_publish(version, ty, flags, &body[header_len..], handler)
        });
        buf.advance(total);
        match result {
            Ok(Some(new_version)) => self.version = new_version,
            Ok(None) => {}
            Err(err) => {
                handler.parse_error(err);
                return ParseStep::Fatal;
            }
        }
        ParseStep::Progressed
    }

    /// Read a PUBLISH's variable header once all of it is in the ring, call
    /// `start_publish`, and switch to streaming its payload (or straight on
    /// if the payload is empty).
    fn try_parse_publish(
        &mut self,
        buf: &mut LoopBuf,
        handler: &mut dyn MqttFrameHandler,
        flags: u8,
        remaining_length: u32,
        header_len: usize,
    ) -> ParseStep {
        // The variable header is at most the whole packet, and never more
        // than the ring holds; decode from whatever of it is there.
        let available = buf.len() - header_len;
        let look = available.min(remaining_length as usize);
        let version = self.version;
        let parsed = self.with_front(buf, header_len + look, |bytes| {
            decode::decode_publish_var_header(&bytes[header_len..], flags, remaining_length, version)
        });
        let (header, consumed) = match parsed {
            Ok(Some(v)) => v,
            Ok(None) => {
                if buf.is_full() {
                    // Nothing more can arrive: the header does not fit.
                    handler.parse_error(MqttError::Malformed("PUBLISH header exceeds the receive buffer"));
                    return ParseStep::Fatal;
                }
                return ParseStep::NeedMoreData;
            }
            Err(err) => {
                handler.parse_error(err);
                return ParseStep::Fatal;
            }
        };
        let payload_len = header.payload_len;
        buf.advance(header_len + consumed);
        handler.start_publish(header);
        if payload_len == 0 {
            handler.end_publish();
            self.state = State::Idle;
        } else {
            self.state = State::PublishPayload {
                remaining: payload_len,
            };
        }
        ParseStep::Progressed
    }

    /// Runs `f` with the first `len` bytes of `buf` as one slice.
    fn with_front<R>(&mut self, buf: &LoopBuf, len: usize, f: impl FnOnce(&[u8]) -> R) -> R {
        let (first, second) = buf.readable_spans();
        if first.len() >= len {
            f(&first[..len])
        } else {
            let mut scratch = std::mem::take(&mut self.scratch);
            scratch.clear();
            scratch.extend_from_slice(first);
            scratch.extend_from_slice(&second[..len - first.len()]);
            let r = f(&scratch);
            self.scratch = scratch;
            r
        }
    }
}

/// Copies the first `out.len()` bytes of `buf` into `out`, which the caller
/// has checked it holds.
fn copy_front(buf: &LoopBuf, out: &mut [u8]) {
    let (first, second) = buf.readable_spans();
    let n = first.len().min(out.len());
    out[..n].copy_from_slice(&first[..n]);
    let rest = out.len() - n;
    out[n..].copy_from_slice(&second[..rest]);
}

/// Decode and dispatch one complete non-PUBLISH packet body. Returns the
/// new protocol version when `ty == Connect` (the caller updates
/// `self.version` after this returns, keeping the borrow of `self.buf`
/// used for `body` disjoint from the `&mut self.buf` drain that follows).
fn dispatch_non_publish(
    version: ProtocolVersion,
    ty: PacketType,
    _flags: u8,
    body: &[u8],
    handler: &mut dyn MqttFrameHandler,
) -> Result<Option<ProtocolVersion>, MqttError> {
    match ty {
        PacketType::Connect => {
            let packet = decode::decode_connect(body)?;
            let new_version = packet.version;
            handler.connect(packet);
            return Ok(Some(new_version));
        }
        PacketType::Connack => {
            let (session_present, reason_code, props) = decode::decode_connack(body, version)?;
            handler.connack(session_present, reason_code, props);
        }
        PacketType::Puback => {
            let (id, rc, props) = decode::decode_simple_ack(body, version)?;
            handler.puback(id, rc, props);
        }
        PacketType::Pubrec => {
            let (id, rc, props) = decode::decode_simple_ack(body, version)?;
            handler.pubrec(id, rc, props);
        }
        PacketType::Pubrel => {
            let (id, rc, props) = decode::decode_simple_ack(body, version)?;
            handler.pubrel(id, rc, props);
        }
        PacketType::Pubcomp => {
            let (id, rc, props) = decode::decode_simple_ack(body, version)?;
            handler.pubcomp(id, rc, props);
        }
        PacketType::Subscribe => {
            let (id, props, filters) = decode::decode_subscribe(body, version)?;
            handler.subscribe(id, props, filters);
        }
        PacketType::Suback => {
            let (id, props, codes) = decode::decode_suback(body, version)?;
            handler.suback(id, props, codes);
        }
        PacketType::Unsubscribe => {
            let (id, props, filters) = decode::decode_unsubscribe(body, version)?;
            handler.unsubscribe(id, props, filters);
        }
        PacketType::Unsuback => {
            let (id, props, codes) = decode::decode_unsuback(body, version)?;
            handler.unsuback(id, props, codes);
        }
        PacketType::Pingreq => handler.ping_req(),
        PacketType::Pingresp => handler.ping_resp(),
        PacketType::Disconnect => {
            let (rc, props) = decode::decode_disconnect(body, version)?;
            handler.disconnect(rc, props);
        }
        PacketType::Auth => {
            let (rc, props) = decode::decode_auth(body)?;
            handler.auth(rc, props);
        }
        PacketType::Publish => unreachable!("PUBLISH is handled by the streaming path"),
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode;
    use crate::codec::packet::{QoS, Will};

    /// Feeds `bytes` in chunks of `chunk` through a ring of `ring` bytes,
    /// returning the ring (so a test can see what it left).
    fn feed(
        parser: &mut MqttFrameParser,
        handler: &mut dyn MqttFrameHandler,
        bytes: &[u8],
        chunk: usize,
        ring: usize,
    ) -> LoopBuf {
        let mut buf = LoopBuf::with_capacity(ring);
        let mut rest = bytes;
        while !rest.is_empty() {
            let taken = buf.extend_from_slice(&rest[..chunk.min(rest.len())]);
            rest = &rest[taken..];
            let before = buf.len();
            parser.receive(&mut buf, handler);
            if taken == 0 && buf.len() == before {
                break;
            }
        }
        buf
    }

    #[derive(Default)]
    struct Collect {
        connects: Vec<ConnectPacket>,
        publishes: Vec<(PublishHeader, Vec<u8>)>,
        current_publish_payload: Vec<u8>,
        pubacks: Vec<(u16, u8)>,
        pings: u32,
        errors: Vec<MqttError>,
    }

    impl MqttFrameHandler for Collect {
        fn connect(&mut self, packet: ConnectPacket) {
            self.connects.push(packet);
        }
        fn connack(&mut self, _session_present: bool, _reason_code: u8, _properties: Properties) {}
        fn start_publish(&mut self, header: PublishHeader) {
            self.current_publish_payload.clear();
            self.publishes.push((header, Vec::new()));
        }
        fn publish_data(&mut self, data: &[u8]) {
            self.current_publish_payload.extend_from_slice(data);
        }
        fn end_publish(&mut self) {
            let last = self.publishes.last_mut().unwrap();
            last.1 = std::mem::take(&mut self.current_publish_payload);
        }
        fn puback(&mut self, packet_id: u16, reason_code: u8, _properties: Properties) {
            self.pubacks.push((packet_id, reason_code));
        }
        fn pubrec(&mut self, _packet_id: u16, _reason_code: u8, _properties: Properties) {}
        fn pubrel(&mut self, _packet_id: u16, _reason_code: u8, _properties: Properties) {}
        fn pubcomp(&mut self, _packet_id: u16, _reason_code: u8, _properties: Properties) {}
        fn subscribe(&mut self, _packet_id: u16, _properties: Properties, _filters: Vec<SubscribeFilter>) {}
        fn suback(&mut self, _packet_id: u16, _properties: Properties, _reason_codes: Vec<u8>) {}
        fn unsubscribe(&mut self, _packet_id: u16, _properties: Properties, _topic_filters: Vec<String>) {}
        fn unsuback(&mut self, _packet_id: u16, _properties: Properties, _reason_codes: Vec<u8>) {}
        fn ping_req(&mut self) {
            self.pings += 1;
        }
        fn ping_resp(&mut self) {}
        fn disconnect(&mut self, _reason_code: u8, _properties: Properties) {}
        fn auth(&mut self, _reason_code: u8, _properties: Properties) {}
        fn parse_error(&mut self, err: MqttError) {
            self.errors.push(err);
        }
    }

    #[test]
    fn parses_connect_and_pingreq_in_one_push() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        let mut handler = Collect::default();

        let connect = ConnectPacket {
            version: ProtocolVersion::V311,
            clean_session: true,
            keep_alive: 60,
            properties: Properties::new(),
            client_id: "abc".into(),
            will: None,
            username: None,
            password: None,
        };
        let mut wire = encode::encode_connect(&connect);
        wire.extend_from_slice(&encode::encode_pingreq());

        let buf = feed(&mut parser, &mut handler, &wire, wire.len(), 4096);
        assert_eq!(handler.connects.len(), 1);
        assert_eq!(handler.connects[0], connect);
        assert_eq!(handler.pings, 1);
        assert!(handler.errors.is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn split_across_many_single_byte_feeds() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        let mut handler = Collect::default();
        let wire = encode::encode_pingreq();
        let buf = feed(&mut parser, &mut handler, &wire, 1, 64);
        assert_eq!(handler.pings, 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn streams_large_publish_payload_through_a_small_ring() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V5);
        let mut handler = Collect::default();

        let payload = vec![0xABu8; 200_000];
        let wire = encode::encode_publish(&encode::PublishFields { topic: "big/topic", qos: QoS::AtMostOnce, dup: false, retain: false, packet_id: 0, props: &Properties::new(), version: ProtocolVersion::V5 }, &payload);

        // Irregular chunks straddling the header/payload boundary, through a
        // ring a hundredth of the size of the payload.
        let buf = feed(&mut parser, &mut handler, &wire, 37, 2048);

        assert_eq!(handler.publishes.len(), 1);
        assert_eq!(handler.publishes[0].0.topic, "big/topic");
        assert_eq!(handler.publishes[0].1, payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn qos1_publish_then_puback_round_trip() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        let mut handler = Collect::default();
        let mut wire = encode::encode_publish(&encode::PublishFields { topic: "t", qos: QoS::AtLeastOnce, dup: false, retain: false, packet_id: 42, props: &Properties::new(), version: ProtocolVersion::V311 }, b"payload");
        wire.extend_from_slice(&encode::encode_puback(42, 0, &Properties::new(), ProtocolVersion::V311));

        feed(&mut parser, &mut handler, &wire, wire.len(), 4096);
        assert_eq!(handler.publishes.len(), 1);
        assert_eq!(handler.publishes[0].0.packet_id, 42);
        assert_eq!(handler.publishes[0].1, b"payload");
        assert_eq!(handler.pubacks, vec![(42, 0)]);
    }

    #[test]
    fn connect_with_will_updates_parser_version() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        let mut handler = Collect::default();
        let connect = ConnectPacket {
            version: ProtocolVersion::V5,
            clean_session: true,
            keep_alive: 10,
            properties: Properties::new(),
            client_id: "c".into(),
            will: Some(Will {
                qos: QoS::AtMostOnce,
                retain: false,
                topic: "w".into(),
                payload: vec![],
                properties: Properties::new(),
            }),
            username: None,
            password: None,
        };
        let wire = encode::encode_connect(&connect);
        feed(&mut parser, &mut handler, &wire, wire.len(), 4096);
        assert_eq!(parser.version(), ProtocolVersion::V5);
    }

    #[test]
    fn malformed_remaining_length_reports_error_and_resets() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        let mut handler = Collect::default();
        // PINGREQ type nibble with 5 continuation-bit bytes (malformed varint).
        feed(&mut parser, &mut handler, &[0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x01], 6, 64);
        assert_eq!(handler.errors.len(), 1);
        assert!(matches!(handler.errors[0], MqttError::Malformed(_)));
    }

    #[test]
    fn packet_too_large_is_rejected() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        parser.set_max_packet_size(10);
        let mut handler = Collect::default();
        let wire = encode::encode_publish(&encode::PublishFields { topic: "t", qos: QoS::AtMostOnce, dup: false, retain: false, packet_id: 0, props: &Properties::new(), version: ProtocolVersion::V311 }, &[0u8; 100]);
        feed(&mut parser, &mut handler, &wire, wire.len(), 4096);
        assert_eq!(handler.errors.len(), 1);
        assert!(matches!(handler.errors[0], MqttError::PacketTooLarge { .. }));
    }

    #[test]
    fn every_chunking_gives_the_same_packets() {
        let mut wire = encode::encode_pingreq();
        wire.extend(encode::encode_publish(&encode::PublishFields { topic: "a/b", qos: QoS::AtLeastOnce, dup: false, retain: false, packet_id: 7, props: &Properties::new(), version: ProtocolVersion::V311 }, b"hello world"));
        wire.extend(encode::encode_puback(7, 0, &Properties::new(), ProtocolVersion::V311));
        for chunk in [1, 2, 3, 5, 8, 13, 100] {
            let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
            let mut handler = Collect::default();
            let buf = feed(&mut parser, &mut handler, &wire, chunk, 256);
            assert!(buf.is_empty(), "chunk={chunk}");
            assert_eq!(handler.pings, 1, "chunk={chunk}");
            assert_eq!(handler.publishes.len(), 1, "chunk={chunk}");
            assert_eq!(handler.publishes[0].1, b"hello world", "chunk={chunk}");
            assert_eq!(handler.pubacks, vec![(7, 0)], "chunk={chunk}");
            assert!(handler.errors.is_empty(), "chunk={chunk}");
        }
    }

    #[test]
    fn a_packet_that_wraps_the_ring_is_decoded_whole() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        let mut handler = Collect::default();
        let wire = encode::encode_puback(300, 0, &Properties::new(), ProtocolVersion::V311);
        let mut buf = LoopBuf::with_capacity(16);
        buf.extend_from_slice(&[0u8; 14]);
        buf.advance(14);
        assert_eq!(buf.extend_from_slice(&wire), wire.len());
        assert!(!buf.readable_spans().1.is_empty(), "the packet wraps");
        parser.receive(&mut buf, &mut handler);
        assert_eq!(handler.pubacks, vec![(300, 0)]);
        assert!(buf.is_empty());
    }

    #[test]
    fn a_packet_too_big_for_the_ring_is_an_error() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        let mut handler = Collect::default();
        // A SUBSCRIBE claiming 100 bytes, in a 32 byte ring.
        let mut wire = vec![0x82, 100];
        wire.extend([0u8; 100]);
        feed(&mut parser, &mut handler, &wire, 10, 32);
        // (A real connection closes on the first error; the rest is garbage.)
        assert!(matches!(handler.errors[0], MqttError::PacketTooLarge { .. }));
    }
}
