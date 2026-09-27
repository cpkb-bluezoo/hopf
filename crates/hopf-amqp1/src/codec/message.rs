// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP 1.0 message format sections (core spec section 3.2) and an
//! incremental parser for them.
//!
//! A message is a sequence of described-list/binary sections
//! (`header`, `delivery-annotations`, `message-annotations`, `properties`,
//! `application-properties`, one or more `data`/`amqp-sequence` sections or
//! a single `amqp-value`, then an optional `footer`), encoded back to back
//! with no extra framing between them. One AMQP message can span many
//! `transfer` frames (chained with the `more` flag) — see
//! [`crate::codec::performative::Transfer`] — so unlike [`super::frame`]
//! and [`super::performative`], which only ever operate on one already
//! fully-buffered frame at a time, [`MessageParser`] genuinely streams: a
//! `data` section's payload is forwarded to the application as it arrives,
//! never buffered as a whole, so an arbitrarily large message body never
//! costs more memory than one transfer frame's worth.

use super::performative::{bool_field, encode_described_list, field, str_field, uint_field};
use super::types::{decode, value_length, Value};
use super::Amqp1Error;

pub(crate) const HEADER_DESCRIPTOR: u8 = 0x70;
const DELIVERY_ANNOTATIONS_DESCRIPTOR: u8 = 0x71;
const MESSAGE_ANNOTATIONS_DESCRIPTOR: u8 = 0x72;
const PROPERTIES_DESCRIPTOR: u8 = 0x73;
const APPLICATION_PROPERTIES_DESCRIPTOR: u8 = 0x74;
pub(crate) const DATA_DESCRIPTOR: u8 = 0x75;
const AMQP_SEQUENCE_DESCRIPTOR: u8 = 0x76;
const AMQP_VALUE_DESCRIPTOR: u8 = 0x77;
const FOOTER_DESCRIPTOR: u8 = 0x78;

/// Message ordering stage (spec 3.2, sections must appear in this order;
/// `data`/`amqp-sequence` may repeat, an `amqp-value` may not).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Header = 1,
    DeliveryAnnotations = 2,
    MessageAnnotations = 3,
    Properties = 4,
    ApplicationProperties = 5,
    Body = 6,
    Footer = 7,
}

/// `header` section (spec 3.2.1).
#[derive(Debug, Clone, PartialEq)]
pub struct MessageHeader {
    /// Durability request.
    pub durable: bool,
    /// Relative priority (default 4).
    pub priority: u8,
    /// Time-to-live in milliseconds.
    pub ttl: Option<u32>,
    /// Whether this is the first (re)delivery attempt.
    pub first_acquirer: bool,
    /// Number of prior unsuccessful delivery attempts.
    pub delivery_count: u32,
}

impl Default for MessageHeader {
    fn default() -> Self {
        Self {
            durable: false,
            priority: 4,
            ttl: None,
            first_acquirer: false,
            delivery_count: 0,
        }
    }
}

impl MessageHeader {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self {
            durable: bool_field(list, 0, false)?,
            priority: uint_field(list, 1)?.unwrap_or(4) as u8,
            ttl: uint_field(list, 2)?,
            first_acquirer: bool_field(list, 3, false)?,
            delivery_count: uint_field(list, 4)?.unwrap_or(0),
        })
    }

    /// Encode to the section's described-value form.
    pub fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(self.durable.then_some(Value::Bool(true)));
        items.push((self.priority != 4).then_some(Value::Ubyte(self.priority)));
        items.push(self.ttl.map(Value::Uint));
        items.push(self.first_acquirer.then_some(Value::Bool(true)));
        items.push((self.delivery_count != 0).then_some(Value::Uint(self.delivery_count)));
        encode_described_list(HEADER_DESCRIPTOR as u64, items)
    }
}

/// `properties` section (spec 3.2.4). `message_id`/`correlation_id` may be
/// any of `ulong`/`uuid`/`binary`/`string` per spec, so they're kept as the
/// generic [`Value`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MessageProperties {
    /// Application-supplied message identifier.
    pub message_id: Option<Value>,
    /// Authenticated identity of the sending user.
    pub user_id: Option<Vec<u8>>,
    /// Destination node address.
    pub to: Option<String>,
    /// Application-defined subject.
    pub subject: Option<String>,
    /// Node to send replies to.
    pub reply_to: Option<String>,
    /// Correlates a reply to the request that caused it.
    pub correlation_id: Option<Value>,
    /// RFC 2046 MIME type of the message body.
    pub content_type: Option<String>,
    /// Content encoding (e.g. `gzip`).
    pub content_encoding: Option<String>,
    /// Absolute time past which the message is considered expired, in
    /// milliseconds since the Unix epoch.
    pub absolute_expiry_time: Option<i64>,
    /// Creation time, in milliseconds since the Unix epoch.
    pub creation_time: Option<i64>,
    /// Group this message belongs to.
    pub group_id: Option<String>,
    /// Position in the group's message sequence.
    pub group_sequence: Option<u32>,
    /// Group a reply should be considered part of.
    pub reply_to_group_id: Option<String>,
}

impl MessageProperties {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self {
            message_id: field(list, 0).cloned(),
            user_id: match field(list, 1) {
                None => None,
                Some(v) => Some(v.as_binary().ok_or(Amqp1Error::WrongFieldType("binary"))?.to_vec()),
            },
            to: str_field(list, 2)?,
            subject: str_field(list, 3)?,
            reply_to: str_field(list, 4)?,
            correlation_id: field(list, 5).cloned(),
            content_type: str_field(list, 6)?,
            content_encoding: str_field(list, 7)?,
            absolute_expiry_time: match field(list, 8) {
                None => None,
                Some(v) => Some(v.as_u64().map(|x| x as i64).or(match v {
                    Value::Timestamp(t) => Some(*t),
                    _ => None,
                }).ok_or(Amqp1Error::WrongFieldType("timestamp"))?),
            },
            creation_time: match field(list, 9) {
                None => None,
                Some(Value::Timestamp(t)) => Some(*t),
                Some(_) => return Err(Amqp1Error::WrongFieldType("timestamp")),
            },
            group_id: str_field(list, 10)?,
            group_sequence: uint_field(list, 11)?,
            reply_to_group_id: str_field(list, 12)?,
        })
    }

    /// Encode to the section's described-value form.
    pub fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(self.message_id.clone());
        items.push(self.user_id.clone().map(Value::Binary));
        items.push(self.to.clone().map(Value::String));
        items.push(self.subject.clone().map(Value::String));
        items.push(self.reply_to.clone().map(Value::String));
        items.push(self.correlation_id.clone());
        items.push(self.content_type.clone().map(Value::Symbol));
        items.push(self.content_encoding.clone().map(Value::Symbol));
        items.push(self.absolute_expiry_time.map(Value::Timestamp));
        items.push(self.creation_time.map(Value::Timestamp));
        items.push(self.group_id.clone().map(Value::String));
        items.push(self.group_sequence.map(Value::Uint));
        items.push(self.reply_to_group_id.clone().map(Value::String));
        encode_described_list(PROPERTIES_DESCRIPTOR as u64, items)
    }
}

/// A described section whose value is a bare `map` (spec 3.2.2/3.2.3/3.2.5/3.2.7 —
/// `delivery-annotations`, `message-annotations`, `application-properties`,
/// `footer` — unlike `header`/`properties`, whose value is a positional
/// `list`).
fn encode_map_section(descriptor_code: u64, map: Vec<(Value, Value)>) -> Value {
    Value::Described(Box::new(Value::Ulong(descriptor_code)), Box::new(Value::Map(map)))
}

fn as_map(v: &Value) -> Result<Vec<(Value, Value)>, Amqp1Error> {
    match v {
        Value::Map(m) => Ok(m.clone()),
        Value::Null => Ok(Vec::new()),
        _ => Err(Amqp1Error::WrongFieldType("map")),
    }
}

/// Encode `application-properties` (spec 3.2.5 — map keys must be `string`).
pub fn encode_application_properties(props: &[(String, Value)]) -> Value {
    let map: Vec<(Value, Value)> = props.iter().map(|(k, v)| (Value::String(k.clone()), v.clone())).collect();
    encode_map_section(APPLICATION_PROPERTIES_DESCRIPTOR as u64, map)
}

fn decode_application_properties(map: Vec<(Value, Value)>) -> Result<Vec<(String, Value)>, Amqp1Error> {
    map.into_iter()
        .map(|(k, v)| {
            k.as_str()
                .map(|s| (s.to_string(), v))
                .ok_or(Amqp1Error::WrongFieldType("application-properties key must be a string"))
        })
        .collect()
}

/// Just the `data` section header (descriptor + `vbin8`/`vbin32`
/// constructor and length) for `len` bytes, without the payload — lets a
/// caller forward large bodies without copying them into an
/// [`super::types::Encoder`] first.
pub fn data_section_header(len: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(11);
    bytes.push(super::types::DESCRIBED);
    let mut enc = super::types::Encoder::new();
    enc.ulong(DATA_DESCRIPTOR as u64);
    bytes.extend_from_slice(&enc.into_bytes());
    if len <= 0xff {
        bytes.push(super::types::VBIN8);
        bytes.push(len as u8);
    } else {
        bytes.push(super::types::VBIN32);
        bytes.extend_from_slice(&len.to_be_bytes());
    }
    bytes
}

/// Callbacks from [`MessageParser`]. All methods default to a no-op so
/// callers only implement the sections they care about.
#[allow(unused_variables)]
pub trait MessageHandler {
    /// `header` section.
    fn header(&mut self, header: MessageHeader) {}
    /// `delivery-annotations` section (raw map — annotation keys are
    /// broker-extension symbols this client doesn't interpret).
    fn delivery_annotations(&mut self, annotations: Vec<(Value, Value)>) {}
    /// `message-annotations` section.
    fn message_annotations(&mut self, annotations: Vec<(Value, Value)>) {}
    /// `properties` section.
    fn properties(&mut self, properties: MessageProperties) {}
    /// `application-properties` section.
    fn application_properties(&mut self, properties: Vec<(String, Value)>) {}
    /// A `data` section is starting; `data_chunk` follows for `len` bytes total.
    fn start_data(&mut self, len: u32) {}
    /// A chunk of the current `data` section (zero-copy view, valid for this call only).
    fn data_chunk(&mut self, data: &[u8]) {}
    /// The current `data` section is complete.
    fn end_data(&mut self) {}
    /// An `amqp-sequence` body section.
    fn amqp_sequence(&mut self, items: Vec<Value>) {}
    /// An `amqp-value` body section.
    fn amqp_value(&mut self, value: Value) {}
    /// `footer` section.
    fn footer(&mut self, footer: Vec<(Value, Value)>) {}
    /// The message is fully parsed (the transfer with `more == false` had
    /// its payload fully consumed).
    fn end_message(&mut self) {}
    /// Fatal parse error.
    fn error(&mut self, err: Amqp1Error) {}
}

#[derive(Debug, Clone, Copy)]
enum State {
    AwaitingSection,
    Streaming { remaining: u32 },
}

enum Probe {
    Data { header_len: usize, body_len: u32 },
    Other { total_len: usize },
}

/// Bound on a non-`data` section's buffered size, guarding against a
/// malformed/hostile peer claiming an enormous header/properties/footer
/// section that would otherwise grow `scratch` without limit.
const MAX_OTHER_SECTION_SIZE: usize = 1_048_576;

/// Incremental message-section parser. Feed it each transfer frame's
/// payload, in order, for one delivery; call [`Self::end_message`] once the
/// transfer with `more == false` has had its payload fed.
pub struct MessageParser {
    scratch: Vec<u8>,
    state: State,
    last_stage: Option<Stage>,
    failed: bool,
}

impl Default for MessageParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageParser {
    /// New parser, ready for the first section of a message.
    pub fn new() -> Self {
        Self {
            scratch: Vec::new(),
            state: State::AwaitingSection,
            last_stage: None,
            failed: false,
        }
    }

    /// Feed the next chunk of transfer payload bytes.
    pub fn feed(&mut self, mut input: &[u8], handler: &mut dyn MessageHandler) {
        if self.failed {
            return;
        }
        loop {
            match self.state {
                State::Streaming { remaining } => {
                    if !self.scratch.is_empty() {
                        let n = (remaining as usize).min(self.scratch.len());
                        let chunk: Vec<u8> = self.scratch.drain(..n).collect();
                        if n > 0 {
                            handler.data_chunk(&chunk);
                        }
                        self.state = State::Streaming { remaining: remaining - n as u32 };
                        continue;
                    }
                    if remaining == 0 {
                        handler.end_data();
                        self.state = State::AwaitingSection;
                        continue;
                    }
                    if input.is_empty() {
                        return;
                    }
                    let n = (remaining as usize).min(input.len());
                    handler.data_chunk(&input[..n]);
                    input = &input[n..];
                    self.state = State::Streaming { remaining: remaining - n as u32 };
                }
                State::AwaitingSection => {
                    if !input.is_empty() {
                        self.scratch.extend_from_slice(input);
                        input = &[];
                    }
                    if self.scratch.is_empty() {
                        return;
                    }
                    match self.probe() {
                        Ok(None) => return,
                        Ok(Some(Probe::Data { header_len, body_len })) => {
                            self.scratch.drain(..header_len);
                            if let Err(e) = self.advance_stage(Stage::Body) {
                                self.fail(handler, e);
                                return;
                            }
                            handler.start_data(body_len);
                            self.state = State::Streaming { remaining: body_len };
                        }
                        Ok(Some(Probe::Other { total_len })) => {
                            if self.scratch.len() < total_len {
                                if total_len > MAX_OTHER_SECTION_SIZE {
                                    self.fail(handler, Amqp1Error::Malformed("message section too large"));
                                    return;
                                }
                                return;
                            }
                            let bytes: Vec<u8> = self.scratch.drain(..total_len).collect();
                            if let Err(e) = self.dispatch_other(&bytes, handler) {
                                self.fail(handler, e);
                                return;
                            }
                        }
                        Err(e) => {
                            self.fail(handler, e);
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Call once the transfer carrying `more == false` has had its payload
    /// fully fed. Errors if a section is left incomplete.
    pub fn end_message(&mut self, handler: &mut dyn MessageHandler) {
        if self.failed {
            return;
        }
        match self.state {
            State::AwaitingSection if self.scratch.is_empty() => {
                handler.end_message();
                self.reset();
            }
            _ => {
                self.fail(handler, Amqp1Error::Malformed("message ended mid-section"));
            }
        }
    }

    /// Reset to parse a new message, discarding any in-progress state
    /// (used after [`Self::end_message`], or to recover after
    /// [`MessageHandler::error`]).
    pub fn reset(&mut self) {
        self.scratch.clear();
        self.state = State::AwaitingSection;
        self.last_stage = None;
        self.failed = false;
    }

    fn fail(&mut self, handler: &mut dyn MessageHandler, err: Amqp1Error) {
        self.failed = true;
        self.scratch.clear();
        handler.error(err);
    }

    fn advance_stage(&mut self, stage: Stage) -> Result<(), Amqp1Error> {
        if let Some(last) = self.last_stage {
            let ok = stage > last || (stage == last && stage == Stage::Body);
            if !ok {
                return Err(Amqp1Error::Malformed("message sections out of order"));
            }
        }
        self.last_stage = Some(stage);
        Ok(())
    }

    fn probe(&self) -> Result<Option<Probe>, Amqp1Error> {
        let buf = &self.scratch;
        if buf.first() != Some(&super::types::DESCRIBED) {
            return match value_length(buf)? {
                None => Ok(None),
                Some(total) => Ok(Some(Probe::Other { total_len: total })),
            };
        }
        let rest = &buf[1..];
        let Some(dn) = value_length(rest)? else { return Ok(None) };
        if rest.len() < dn {
            return Ok(None);
        }
        let (descriptor, _) = decode(&rest[..dn])?;
        let value_part = &rest[dn..];
        if descriptor.as_u64() == Some(DATA_DESCRIPTOR as u64) {
            match value_part.first() {
                None => return Ok(None),
                Some(&super::types::VBIN8) => {
                    if value_part.len() < 2 {
                        return Ok(None);
                    }
                    let body_len = value_part[1] as u32;
                    return Ok(Some(Probe::Data { header_len: 1 + dn + 2, body_len }));
                }
                Some(&super::types::VBIN32) => {
                    if value_part.len() < 5 {
                        return Ok(None);
                    }
                    let body_len = u32::from_be_bytes([value_part[1], value_part[2], value_part[3], value_part[4]]);
                    return Ok(Some(Probe::Data { header_len: 1 + dn + 5, body_len }));
                }
                Some(_) => return Err(Amqp1Error::Malformed("data section value is not binary")),
            }
        }
        match value_length(buf)? {
            None => Ok(None),
            Some(total) => Ok(Some(Probe::Other { total_len: total })),
        }
    }

    fn dispatch_other(&mut self, bytes: &[u8], handler: &mut dyn MessageHandler) -> Result<(), Amqp1Error> {
        let (value, _) = decode(bytes)?;
        let Value::Described(descriptor, inner) = value else {
            return Err(Amqp1Error::Malformed("message section is not a described type"));
        };
        let code = descriptor.as_u64().ok_or(Amqp1Error::Malformed("non-numeric section descriptor"))?;
        match code {
            c if c == HEADER_DESCRIPTOR as u64 => {
                let list = inner.as_list().ok_or(Amqp1Error::WrongFieldType("list"))?;
                self.advance_stage(Stage::Header)?;
                handler.header(MessageHeader::decode(list)?);
            }
            c if c == DELIVERY_ANNOTATIONS_DESCRIPTOR as u64 => {
                self.advance_stage(Stage::DeliveryAnnotations)?;
                handler.delivery_annotations(as_map(&inner)?);
            }
            c if c == MESSAGE_ANNOTATIONS_DESCRIPTOR as u64 => {
                self.advance_stage(Stage::MessageAnnotations)?;
                handler.message_annotations(as_map(&inner)?);
            }
            c if c == PROPERTIES_DESCRIPTOR as u64 => {
                let list = inner.as_list().ok_or(Amqp1Error::WrongFieldType("list"))?;
                self.advance_stage(Stage::Properties)?;
                handler.properties(MessageProperties::decode(list)?);
            }
            c if c == APPLICATION_PROPERTIES_DESCRIPTOR as u64 => {
                self.advance_stage(Stage::ApplicationProperties)?;
                handler.application_properties(decode_application_properties(as_map(&inner)?)?);
            }
            c if c == AMQP_SEQUENCE_DESCRIPTOR as u64 => {
                let list = inner.as_list().ok_or(Amqp1Error::WrongFieldType("list"))?;
                self.advance_stage(Stage::Body)?;
                handler.amqp_sequence(list.to_vec());
            }
            c if c == AMQP_VALUE_DESCRIPTOR as u64 => {
                self.advance_stage(Stage::Body)?;
                handler.amqp_value(*inner);
            }
            c if c == FOOTER_DESCRIPTOR as u64 => {
                self.advance_stage(Stage::Footer)?;
                handler.footer(as_map(&inner)?);
            }
            other => return Err(Amqp1Error::UnknownDescriptor(other)),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Collect {
        header: Option<MessageHeader>,
        properties: Option<MessageProperties>,
        application_properties: Option<Vec<(String, Value)>>,
        data: Vec<u8>,
        data_starts: Vec<u32>,
        ended_data: u32,
        ended_message: u32,
        errors: Vec<Amqp1Error>,
    }

    impl MessageHandler for Collect {
        fn header(&mut self, header: MessageHeader) {
            self.header = Some(header);
        }
        fn properties(&mut self, properties: MessageProperties) {
            self.properties = Some(properties);
        }
        fn application_properties(&mut self, properties: Vec<(String, Value)>) {
            self.application_properties = Some(properties);
        }
        fn start_data(&mut self, len: u32) {
            self.data_starts.push(len);
        }
        fn data_chunk(&mut self, data: &[u8]) {
            self.data.extend_from_slice(data);
        }
        fn end_data(&mut self) {
            self.ended_data += 1;
        }
        fn end_message(&mut self) {
            self.ended_message += 1;
        }
        fn error(&mut self, err: Amqp1Error) {
            self.errors.push(err);
        }
    }

    fn encode_message(header: &MessageHeader, props: &MessageProperties, app_props: &[(String, Value)], body: &[u8]) -> Vec<u8> {
        let mut enc = super::super::types::Encoder::new();
        enc.value(&header.encode());
        enc.value(&props.encode());
        enc.value(&encode_application_properties(app_props));
        enc.value(&Value::Described(
            Box::new(Value::Ulong(DATA_DESCRIPTOR as u64)),
            Box::new(Value::Binary(body.to_vec())),
        ));
        enc.into_bytes()
    }

    #[test]
    fn full_message_in_one_feed() {
        let header = MessageHeader { durable: true, ..Default::default() };
        let props = MessageProperties { content_type: Some("text/plain".into()), ..Default::default() };
        let app_props = vec![("x-key".to_string(), Value::Uint(7))];
        let body = b"hello amqp1 message";

        let bytes = encode_message(&header, &props, &app_props, body);
        let mut parser = MessageParser::new();
        let mut h = Collect::default();
        parser.feed(&bytes, &mut h);
        parser.end_message(&mut h);

        assert!(h.errors.is_empty(), "{:?}", h.errors);
        assert_eq!(h.header, Some(header));
        assert_eq!(h.properties.unwrap().content_type.as_deref(), Some("text/plain"));
        assert_eq!(h.application_properties, Some(app_props));
        assert_eq!(h.data, body);
        assert_eq!(h.ended_data, 1);
        assert_eq!(h.ended_message, 1);
    }

    #[test]
    fn large_data_section_streams_without_full_buffering() {
        let header = MessageHeader::default();
        let props = MessageProperties::default();
        let body = vec![0xABu8; 500_000];
        let bytes = encode_message(&header, &props, &[], &body);

        let mut parser = MessageParser::new();
        let mut h = Collect::default();
        // Feed in frame-sized chunks, as if each came from a separate transfer.
        for chunk in bytes.chunks(64 * 1024) {
            parser.feed(chunk, &mut h);
        }
        parser.end_message(&mut h);

        assert!(h.errors.is_empty(), "{:?}", h.errors);
        assert_eq!(h.data, body);
        assert_eq!(h.data_starts, vec![500_000]);
    }

    #[test]
    fn split_at_every_byte_boundary_for_a_small_message() {
        let header = MessageHeader { priority: 9, ..Default::default() };
        let props = MessageProperties { content_type: Some("application/json".into()), ..Default::default() };
        let body = b"{}";
        let bytes = encode_message(&header, &props, &[], body);

        for split in 1..=bytes.len() {
            let mut parser = MessageParser::new();
            let mut h = Collect::default();
            let mut off = 0;
            while off < bytes.len() {
                let len = split.min(bytes.len() - off);
                parser.feed(&bytes[off..off + len], &mut h);
                off += len;
            }
            parser.end_message(&mut h);
            assert!(h.errors.is_empty(), "split={split}: {:?}", h.errors);
            assert_eq!(h.header, Some(header.clone()), "split={split}");
            assert_eq!(h.data, body, "split={split}");
            assert_eq!(h.ended_message, 1, "split={split}");
        }
    }

    #[test]
    fn amqp_value_body_instead_of_data() {
        let mut enc = super::super::types::Encoder::new();
        enc.described(AMQP_VALUE_DESCRIPTOR, &Value::String("just a value body".into()));
        let bytes = enc.into_bytes();

        let mut parser = MessageParser::new();
        #[derive(Default)]
        struct C {
            value: Option<Value>,
            ended: u32,
        }
        impl MessageHandler for C {
            fn amqp_value(&mut self, value: Value) {
                self.value = Some(value);
            }
            fn end_message(&mut self) {
                self.ended += 1;
            }
        }
        let mut h = C::default();
        parser.feed(&bytes, &mut h);
        parser.end_message(&mut h);
        assert_eq!(h.value, Some(Value::String("just a value body".into())));
        assert_eq!(h.ended, 1);
    }

    #[test]
    fn sections_out_of_order_is_an_error() {
        // application-properties (0x74) before properties (0x73) is invalid ordering.
        let mut enc = super::super::types::Encoder::new();
        enc.value(&encode_application_properties(&[]));
        enc.value(&MessageProperties::default().encode());
        let bytes = enc.into_bytes();

        let mut parser = MessageParser::new();
        let mut h = Collect::default();
        parser.feed(&bytes, &mut h);
        assert_eq!(h.errors.len(), 1);
    }

    #[test]
    fn ending_message_mid_section_is_an_error() {
        let mut parser = MessageParser::new();
        let mut h = Collect::default();
        // Feed only a partial header section (incomplete list).
        parser.feed(&[super::super::types::DESCRIBED, 0x53, HEADER_DESCRIPTOR], &mut h);
        parser.end_message(&mut h);
        assert_eq!(h.errors.len(), 1);
    }

    #[test]
    fn reset_allows_reuse_for_a_new_message() {
        let header = MessageHeader::default();
        let props = MessageProperties::default();
        let bytes = encode_message(&header, &props, &[], b"one");
        let mut parser = MessageParser::new();
        let mut h = Collect::default();
        parser.feed(&bytes, &mut h);
        parser.end_message(&mut h);

        let bytes2 = encode_message(&header, &props, &[], b"two");
        let mut h2 = Collect::default();
        parser.feed(&bytes2, &mut h2);
        parser.end_message(&mut h2);

        assert_eq!(h.data, b"one");
        assert_eq!(h2.data, b"two");
        assert!(h2.errors.is_empty());
    }
}
