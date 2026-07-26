// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental push parser for MQTT control packets.
//!
//! Mirrors this codebase's [`hopf_http::h2` frame parser](../../hopf-http/src/h2/parser.rs)
//! shape (accumulate into an internal buffer, drain complete units) — MQTT
//! framing is binary length-prefixed, not CRLF/text-token oriented, so a
//! small buffer-and-drain parser fits, the same way it does for HTTP/2
//! frames.
//!
//! PUBLISH is the one packet type that can carry an unbounded payload, so
//! it gets different treatment: the fixed header, remaining-length varint,
//! and PUBLISH variable header (topic / packet id / properties) are
//! accumulated exactly like every other packet, but once the variable
//! header is complete, payload bytes are forwarded to
//! [`MqttFrameHandler::publish_data`] as they arrive — never buffered in
//! full — until the packet's remaining length is exhausted.

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
    PublishHeader { flags: u8, remaining_length: u32 },
    PublishPayload { remaining: u32 },
}

enum ParseStep {
    NeedMoreData,
    Progressed,
    Fatal,
}

/// Incremental MQTT control packet parser.
pub struct MqttFrameParser {
    buf: Vec<u8>,
    version: ProtocolVersion,
    max_packet_size: u32,
    state: State,
}

impl MqttFrameParser {
    /// Create a parser. `version` is the version to assume until a CONNECT
    /// packet (server side) fixes it, or the version already negotiated
    /// (client side).
    pub fn new(version: ProtocolVersion) -> Self {
        Self {
            buf: Vec::new(),
            version,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            state: State::Idle,
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
    pub fn set_max_packet_size(&mut self, max_packet_size: u32) {
        self.max_packet_size = max_packet_size;
    }

    /// Bytes currently buffered awaiting a complete header (never includes
    /// unbuffered in-flight PUBLISH payload).
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Feed newly-received bytes; dispatches every complete unit to `handler`.
    pub fn push(&mut self, mut data: &[u8], handler: &mut dyn MqttFrameHandler) {
        loop {
            match self.state {
                State::PublishPayload { remaining } => {
                    if data.is_empty() {
                        return;
                    }
                    let n = (remaining as usize).min(data.len());
                    handler.publish_data(&data[..n]);
                    data = &data[n..];
                    let left = remaining - n as u32;
                    if left == 0 {
                        handler.end_publish();
                        self.state = State::Idle;
                    } else {
                        self.state = State::PublishPayload { remaining: left };
                        return;
                    }
                }
                State::Idle => {
                    if data.is_empty() && self.buf.is_empty() {
                        return;
                    }
                    if !data.is_empty() {
                        self.buf.extend_from_slice(data);
                        data = &[];
                    }
                    match self.try_parse_idle(handler) {
                        ParseStep::NeedMoreData => return,
                        ParseStep::Progressed => {}
                        ParseStep::Fatal => {
                            self.buf.clear();
                            self.state = State::Idle;
                            return;
                        }
                    }
                }
                State::PublishHeader {
                    flags,
                    remaining_length,
                } => {
                    if !data.is_empty() {
                        self.buf.extend_from_slice(data);
                        data = &[];
                    }
                    match self.try_parse_publish_header(flags, remaining_length, handler) {
                        ParseStep::NeedMoreData => return,
                        ParseStep::Progressed => {}
                        ParseStep::Fatal => {
                            self.buf.clear();
                            self.state = State::Idle;
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Parse the fixed header + remaining-length varint from `self.buf`,
    /// then either dispatch a complete non-PUBLISH packet or switch to
    /// [`State::PublishHeader`].
    fn try_parse_idle(&mut self, handler: &mut dyn MqttFrameHandler) -> ParseStep {
        if self.buf.len() < 2 {
            return ParseStep::NeedMoreData;
        }
        let byte0 = self.buf[0];
        let type_value = (byte0 >> 4) & 0x0F;
        let flags = byte0 & 0x0F;

        let (remaining_length, varint_len) = match varint::decode(&self.buf[1..]) {
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
            self.buf.drain(..header_len);
            self.state = State::PublishHeader {
                flags,
                remaining_length,
            };
            return ParseStep::Progressed;
        }

        let total = header_len + remaining_length as usize;
        if self.buf.len() < total {
            return ParseStep::NeedMoreData;
        }
        let result = dispatch_non_publish(self.version, ty, flags, &self.buf[header_len..total], handler);
        self.buf.drain(..total);
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

    /// Try to complete the PUBLISH variable header from `self.buf`; on
    /// success, flush any already-buffered payload bytes and switch to
    /// [`State::PublishPayload`] (or straight back to [`State::Idle`] if
    /// the whole payload was already buffered too).
    fn try_parse_publish_header(
        &mut self,
        flags: u8,
        remaining_length: u32,
        handler: &mut dyn MqttFrameHandler,
    ) -> ParseStep {
        let parsed = match decode::decode_publish_var_header(&self.buf, flags, remaining_length, self.version) {
            Ok(Some(v)) => v,
            Ok(None) => return ParseStep::NeedMoreData,
            Err(err) => {
                handler.parse_error(err);
                return ParseStep::Fatal;
            }
        };
        let (header, consumed) = parsed;
        let mut payload_remaining = header.payload_len;
        self.buf.drain(..consumed);
        handler.start_publish(header);

        let flush = (self.buf.len() as u32).min(payload_remaining);
        if flush > 0 {
            handler.publish_data(&self.buf[..flush as usize]);
            self.buf.drain(..flush as usize);
            payload_remaining -= flush;
        }
        if payload_remaining == 0 {
            handler.end_publish();
            self.state = State::Idle;
        } else {
            self.state = State::PublishPayload {
                remaining: payload_remaining,
            };
        }
        ParseStep::Progressed
    }
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

        parser.push(&wire, &mut handler);
        assert_eq!(handler.connects.len(), 1);
        assert_eq!(handler.connects[0], connect);
        assert_eq!(handler.pings, 1);
        assert!(handler.errors.is_empty());
        assert_eq!(parser.buffered_len(), 0);
    }

    #[test]
    fn split_across_many_single_byte_feeds() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        let mut handler = Collect::default();
        let wire = encode::encode_pingreq();
        for &b in &wire {
            parser.push(&[b], &mut handler);
        }
        assert_eq!(handler.pings, 1);
    }

    #[test]
    fn streams_large_publish_payload_across_many_pushes_without_buffering() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V5);
        let mut handler = Collect::default();

        let payload = vec![0xABu8; 200_000];
        let wire = encode::encode_publish(
            "big/topic",
            QoS::AtMostOnce,
            false,
            false,
            0,
            &payload,
            &Properties::new(),
            ProtocolVersion::V5,
        );

        // Feed in small, irregular chunks straddling the header/payload boundary.
        let mut max_buffered = 0usize;
        for chunk in wire.chunks(37) {
            parser.push(chunk, &mut handler);
            max_buffered = max_buffered.max(parser.buffered_len());
        }

        assert_eq!(handler.publishes.len(), 1);
        assert_eq!(handler.publishes[0].0.topic, "big/topic");
        assert_eq!(handler.publishes[0].1, payload);
        // The parser never had to hold anywhere near the full payload at once.
        assert!(max_buffered < 4096, "buffered {max_buffered} bytes, expected streaming");
    }

    #[test]
    fn qos1_publish_then_puback_round_trip() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        let mut handler = Collect::default();
        let mut wire = encode::encode_publish(
            "t",
            QoS::AtLeastOnce,
            false,
            false,
            42,
            b"payload",
            &Properties::new(),
            ProtocolVersion::V311,
        );
        wire.extend_from_slice(&encode::encode_puback(42, 0, &Properties::new(), ProtocolVersion::V311));

        parser.push(&wire, &mut handler);
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
        parser.push(&encode::encode_connect(&connect), &mut handler);
        assert_eq!(parser.version(), ProtocolVersion::V5);
    }

    #[test]
    fn malformed_remaining_length_reports_error_and_resets() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        let mut handler = Collect::default();
        // PINGREQ type nibble with 5 continuation-bit bytes (malformed varint).
        parser.push(&[0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x01], &mut handler);
        assert_eq!(handler.errors.len(), 1);
        assert!(matches!(handler.errors[0], MqttError::Malformed(_)));
    }

    #[test]
    fn packet_too_large_is_rejected() {
        let mut parser = MqttFrameParser::new(ProtocolVersion::V311);
        parser.set_max_packet_size(10);
        let mut handler = Collect::default();
        let wire = encode::encode_publish(
            "t",
            QoS::AtMostOnce,
            false,
            false,
            0,
            &[0u8; 100],
            &Properties::new(),
            ProtocolVersion::V311,
        );
        parser.push(&wire, &mut handler);
        assert_eq!(handler.errors.len(), 1);
        assert!(matches!(handler.errors[0], MqttError::PacketTooLarge { .. }));
    }
}
