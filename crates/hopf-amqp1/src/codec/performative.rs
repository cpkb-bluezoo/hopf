// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP 1.0 performatives (core spec section 2.7) and the composite types
//! they carry (link termini, delivery state, the error composite).
//!
//! Every performative is wire-encoded as a described list: `0x00`, a
//! `ulong` descriptor code, then a `list` of positional fields. Trailing
//! fields at their default value are omitted from the encoded list (spec
//! section 1.5 — a shorter list implies the omitted trailing fields take
//! their default), which keeps frames small and matches what real brokers
//! send.

use super::types::{decode, Encoder, Value};
use super::Amqp1Error;

// Performative / composite descriptor codes (core spec 2.7, 2.8.15/18-27).
const OPEN: u64 = 0x10;
const BEGIN: u64 = 0x11;
const ATTACH: u64 = 0x12;
const FLOW: u64 = 0x13;
const TRANSFER: u64 = 0x14;
const DISPOSITION: u64 = 0x15;
const DETACH: u64 = 0x16;
const END: u64 = 0x17;
const CLOSE: u64 = 0x18;
const ERROR: u64 = 0x1d;
const SOURCE: u64 = 0x28;
const TARGET: u64 = 0x29;
const STATE_RECEIVED: u64 = 0x23;
const STATE_ACCEPTED: u64 = 0x24;
const STATE_REJECTED: u64 = 0x25;
const STATE_RELEASED: u64 = 0x26;
const STATE_MODIFIED: u64 = 0x27;

// ---------------------------------------------------------------------
// Positional-list field helpers.
// ---------------------------------------------------------------------

/// A list-encoded field slot: absent past the end of the list, or an
/// explicit `null`, both mean "not set" (spec section 1.5).
pub(crate) fn field(list: &[Value], index: usize) -> Option<&Value> {
    match list.get(index) {
        Some(Value::Null) | None => None,
        Some(v) => Some(v),
    }
}

pub(crate) fn required<'a>(list: &'a [Value], index: usize, name: &'static str) -> Result<&'a Value, Amqp1Error> {
    field(list, index).ok_or(Amqp1Error::RequiredFieldMissing(name))
}

pub(crate) fn str_field(list: &[Value], index: usize) -> Result<Option<String>, Amqp1Error> {
    match field(list, index) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(str::to_string)
            .map(Some)
            .ok_or(Amqp1Error::WrongFieldType("string")),
    }
}

pub(crate) fn uint_field(list: &[Value], index: usize) -> Result<Option<u32>, Amqp1Error> {
    match field(list, index) {
        None => Ok(None),
        Some(v) => v.as_u64().map(|x| Some(x as u32)).ok_or(Amqp1Error::WrongFieldType("uint")),
    }
}

pub(crate) fn ushort_field(list: &[Value], index: usize) -> Result<Option<u16>, Amqp1Error> {
    match field(list, index) {
        None => Ok(None),
        Some(v) => v.as_u64().map(|x| Some(x as u16)).ok_or(Amqp1Error::WrongFieldType("ushort")),
    }
}

pub(crate) fn ulong_field(list: &[Value], index: usize) -> Result<Option<u64>, Amqp1Error> {
    match field(list, index) {
        None => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or(Amqp1Error::WrongFieldType("ulong")),
    }
}

pub(crate) fn bool_field(list: &[Value], index: usize, default: bool) -> Result<bool, Amqp1Error> {
    match field(list, index) {
        None => Ok(default),
        Some(v) => v.as_bool().ok_or(Amqp1Error::WrongFieldType("boolean")),
    }
}

pub(crate) fn binary_field(list: &[Value], index: usize) -> Result<Option<Vec<u8>>, Amqp1Error> {
    match field(list, index) {
        None => Ok(None),
        Some(v) => v
            .as_binary()
            .map(<[u8]>::to_vec)
            .map(Some)
            .ok_or(Amqp1Error::WrongFieldType("binary")),
    }
}

pub(crate) fn symbols_field(list: &[Value], index: usize) -> Result<Vec<String>, Amqp1Error> {
    match field(list, index) {
        None => Ok(Vec::new()),
        Some(v) => v.as_symbol_multiple().ok_or(Amqp1Error::WrongFieldType("symbol or symbol-array")),
    }
}

pub(crate) fn map_field(list: &[Value], index: usize) -> Result<Vec<(Value, Value)>, Amqp1Error> {
    match field(list, index) {
        None => Ok(Vec::new()),
        Some(Value::Map(m)) => Ok(m.clone()),
        Some(_) => Err(Amqp1Error::WrongFieldType("map")),
    }
}

/// Encode a `symbol` or `symbol`-array "multiple" field (spec section 1.5).
pub(crate) fn push_symbols(items: &mut Vec<Option<Value>>, symbols: &[String]) {
    match symbols.len() {
        0 => items.push(None),
        1 => items.push(Some(Value::Symbol(symbols[0].clone()))),
        _ => {
            let mut enc = Encoder::new();
            enc.symbol_array(symbols);
            let (v, _) = decode(&enc.into_bytes()).expect("just-encoded symbol array");
            items.push(Some(v));
        }
    }
}

pub(crate) fn push_map(items: &mut Vec<Option<Value>>, map: &[(Value, Value)]) {
    if map.is_empty() {
        items.push(None);
    } else {
        items.push(Some(Value::Map(map.to_vec())));
    }
}

/// Trim trailing omitted (`None`) fields (spec 1.5: a shorter list implies
/// the rest take their default), then materialize remaining `None`s as
/// explicit `null` — the smallest correct encoding.
pub(crate) fn finish_list(mut items: Vec<Option<Value>>) -> Vec<Value> {
    while matches!(items.last(), Some(None)) {
        items.pop();
    }
    items.into_iter().map(|o| o.unwrap_or(Value::Null)).collect()
}

pub(crate) fn encode_described_list(descriptor_code: u64, items: Vec<Option<Value>>) -> Value {
    Value::Described(
        Box::new(Value::Ulong(descriptor_code)),
        Box::new(Value::List(finish_list(items))),
    )
}

/// Unwrap a described value into `(descriptor code, field list)`.
pub(crate) fn as_described_list(v: &Value) -> Result<(u64, &[Value]), Amqp1Error> {
    let Value::Described(descriptor, value) = v else {
        return Err(Amqp1Error::Malformed("expected a described type"));
    };
    let code = descriptor.as_u64().ok_or(Amqp1Error::Malformed("non-numeric descriptor"))?;
    let list = value.as_list().ok_or(Amqp1Error::Malformed("described value is not a list"))?;
    Ok((code, list))
}

// ---------------------------------------------------------------------
// Error composite (core spec 2.8.17).
// ---------------------------------------------------------------------

/// The AMQP 1.0 error composite carried by `close`/`end`/`detach` and
/// rejected/modified delivery states.
#[derive(Debug, Clone, PartialEq)]
pub struct Error {
    /// A symbolic error condition (e.g. `amqp:internal-error`,
    /// `amqp:session:window-violation`, `amqp:link:transfer-limit-exceeded`
    /// — core spec 2.8.15/2.8.18-20).
    pub condition: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Extra diagnostic info.
    pub info: Vec<(Value, Value)>,
}

impl Error {
    /// Construct with just a condition.
    pub fn new(condition: impl Into<String>) -> Self {
        Self {
            condition: condition.into(),
            description: None,
            info: Vec::new(),
        }
    }

    /// Construct with a condition and description.
    pub fn with_description(condition: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            condition: condition.into(),
            description: Some(description.into()),
            info: Vec::new(),
        }
    }

    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        let condition = required(list, 0, "error.condition")?
            .as_str()
            .ok_or(Amqp1Error::WrongFieldType("symbol"))?
            .to_string();
        Ok(Self {
            condition,
            description: str_field(list, 1)?,
            info: map_field(list, 2)?,
        })
    }

    fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(Some(Value::Symbol(self.condition.clone())));
        items.push(self.description.clone().map(Value::String));
        push_map(&mut items, &self.info);
        encode_described_list(ERROR, items)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.description {
            Some(d) => write!(f, "{} ({d})", self.condition),
            None => write!(f, "{}", self.condition),
        }
    }
}

pub(crate) fn decode_error(v: &Value) -> Result<Error, Amqp1Error> {
    let (code, list) = as_described_list(v)?;
    if code != ERROR {
        return Err(Amqp1Error::UnknownDescriptor(code));
    }
    Error::decode(list)
}

pub(crate) fn error_field(list: &[Value], index: usize) -> Result<Option<Error>, Amqp1Error> {
    match field(list, index) {
        None => Ok(None),
        Some(v) => decode_error(v).map(Some),
    }
}

// ---------------------------------------------------------------------
// Link termini: Source (2.8.7) / Target (2.8.10).
// ---------------------------------------------------------------------

/// A link's source terminus.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Source {
    /// Node address, or `None` for a dynamic or no-address source.
    pub address: Option<String>,
    /// Terminus durability (0 = none, 1 = configuration, 2 = unsettled-state).
    pub durable: u32,
    /// Expiry policy symbol (default `"session-end"` if empty).
    pub expiry_policy: Option<String>,
    /// Expiry timeout, in seconds.
    pub timeout: u32,
    /// Whether the node was dynamically created for this attach.
    pub dynamic: bool,
    /// Properties for a dynamically created node.
    pub dynamic_node_properties: Vec<(Value, Value)>,
    /// Distribution mode (`"move"` or `"copy"`).
    pub distribution_mode: Option<String>,
    /// Filter set.
    pub filter: Vec<(Value, Value)>,
    /// Default outcome for unsettled deliveries the receiver doesn't settle.
    pub default_outcome: Option<DeliveryState>,
    /// Outcomes this source can send.
    pub outcomes: Vec<String>,
    /// Extension capabilities.
    pub capabilities: Vec<String>,
}

impl Source {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self {
            address: str_field(list, 0)?,
            durable: uint_field(list, 1)?.unwrap_or(0),
            expiry_policy: str_field(list, 2)?,
            timeout: uint_field(list, 3)?.unwrap_or(0),
            dynamic: bool_field(list, 4, false)?,
            dynamic_node_properties: map_field(list, 5)?,
            distribution_mode: str_field(list, 6)?,
            filter: map_field(list, 7)?,
            default_outcome: match field(list, 8) {
                None => None,
                Some(v) => Some(decode_delivery_state(v)?),
            },
            outcomes: symbols_field(list, 9)?,
            capabilities: symbols_field(list, 10)?,
        })
    }

    fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(self.address.clone().map(Value::String));
        items.push((self.durable != 0).then_some(Value::Uint(self.durable)));
        items.push(self.expiry_policy.clone().map(Value::Symbol));
        items.push((self.timeout != 0).then_some(Value::Uint(self.timeout)));
        items.push(self.dynamic.then_some(Value::Bool(true)));
        push_map(&mut items, &self.dynamic_node_properties);
        items.push(self.distribution_mode.clone().map(Value::Symbol));
        push_map(&mut items, &self.filter);
        items.push(self.default_outcome.as_ref().map(DeliveryState::encode));
        push_symbols(&mut items, &self.outcomes);
        push_symbols(&mut items, &self.capabilities);
        encode_described_list(SOURCE, items)
    }
}

fn decode_source(v: &Value) -> Result<Source, Amqp1Error> {
    let (code, list) = as_described_list(v)?;
    if code != SOURCE {
        return Err(Amqp1Error::UnknownDescriptor(code));
    }
    Source::decode(list)
}

/// A link's target terminus.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Target {
    /// Node address, or `None` for a dynamic or no-address target.
    pub address: Option<String>,
    /// Terminus durability.
    pub durable: u32,
    /// Expiry policy symbol.
    pub expiry_policy: Option<String>,
    /// Expiry timeout, in seconds.
    pub timeout: u32,
    /// Whether the node was dynamically created for this attach.
    pub dynamic: bool,
    /// Properties for a dynamically created node.
    pub dynamic_node_properties: Vec<(Value, Value)>,
    /// Extension capabilities.
    pub capabilities: Vec<String>,
}

impl Target {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self {
            address: str_field(list, 0)?,
            durable: uint_field(list, 1)?.unwrap_or(0),
            expiry_policy: str_field(list, 2)?,
            timeout: uint_field(list, 3)?.unwrap_or(0),
            dynamic: bool_field(list, 4, false)?,
            dynamic_node_properties: map_field(list, 5)?,
            capabilities: symbols_field(list, 6)?,
        })
    }

    fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(self.address.clone().map(Value::String));
        items.push((self.durable != 0).then_some(Value::Uint(self.durable)));
        items.push(self.expiry_policy.clone().map(Value::Symbol));
        items.push((self.timeout != 0).then_some(Value::Uint(self.timeout)));
        items.push(self.dynamic.then_some(Value::Bool(true)));
        push_map(&mut items, &self.dynamic_node_properties);
        push_symbols(&mut items, &self.capabilities);
        encode_described_list(TARGET, items)
    }
}

fn decode_target(v: &Value) -> Result<Target, Amqp1Error> {
    let (code, list) = as_described_list(v)?;
    if code != TARGET {
        return Err(Amqp1Error::UnknownDescriptor(code));
    }
    Target::decode(list)
}

impl Target {
    /// Convenience constructor for the common "just an address" target.
    pub fn with_address(address: impl Into<String>) -> Self {
        Self {
            address: Some(address.into()),
            ..Default::default()
        }
    }
}

impl Source {
    /// Convenience constructor for the common "just an address" source.
    pub fn with_address(address: impl Into<String>) -> Self {
        Self {
            address: Some(address.into()),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------
// Delivery state / outcomes (core spec 3.4).
// ---------------------------------------------------------------------

/// A delivery's state or terminal outcome.
#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryState {
    /// Partial receipt marker for a resumed/recovered delivery.
    Received {
        /// Section number of the last byte received.
        section_number: u32,
        /// Offset within that section.
        section_offset: u64,
    },
    /// Accepted outcome.
    Accepted,
    /// Rejected outcome, with an optional error.
    Rejected(Option<Error>),
    /// Released outcome (redeliverable elsewhere).
    Released,
    /// Modified outcome.
    Modified {
        /// Whether this delivery attempt is being treated as a failure for
        /// retry-count purposes.
        delivery_failed: bool,
        /// Whether the delivery is considered undeliverable at this node.
        undeliverable_here: bool,
        /// Replacement message annotations to merge into the delivery.
        message_annotations: Vec<(Value, Value)>,
    },
}

impl DeliveryState {
    fn encode(&self) -> Value {
        match self {
            DeliveryState::Received {
                section_number,
                section_offset,
            } => encode_described_list(
                STATE_RECEIVED,
                vec![Some(Value::Uint(*section_number)), Some(Value::Ulong(*section_offset))],
            ),
            DeliveryState::Accepted => encode_described_list(STATE_ACCEPTED, vec![]),
            DeliveryState::Rejected(err) => {
                encode_described_list(STATE_REJECTED, vec![err.as_ref().map(Error::encode)])
            }
            DeliveryState::Released => encode_described_list(STATE_RELEASED, vec![]),
            DeliveryState::Modified {
                delivery_failed,
                undeliverable_here,
                message_annotations,
            } => {
                let mut items = Vec::new();
                items.push(delivery_failed.then_some(Value::Bool(true)));
                items.push(undeliverable_here.then_some(Value::Bool(true)));
                push_map(&mut items, message_annotations);
                encode_described_list(STATE_MODIFIED, items)
            }
        }
    }
}

pub(crate) fn decode_delivery_state(v: &Value) -> Result<DeliveryState, Amqp1Error> {
    let (code, list) = as_described_list(v)?;
    Ok(match code {
        STATE_RECEIVED => DeliveryState::Received {
            section_number: uint_field(list, 0)?.ok_or(Amqp1Error::RequiredFieldMissing("section-number"))?,
            section_offset: ulong_field(list, 1)?.ok_or(Amqp1Error::RequiredFieldMissing("section-offset"))?,
        },
        STATE_ACCEPTED => DeliveryState::Accepted,
        STATE_REJECTED => DeliveryState::Rejected(error_field(list, 0)?),
        STATE_RELEASED => DeliveryState::Released,
        STATE_MODIFIED => DeliveryState::Modified {
            delivery_failed: bool_field(list, 0, false)?,
            undeliverable_here: bool_field(list, 1, false)?,
            message_annotations: map_field(list, 2)?,
        },
        other => return Err(Amqp1Error::UnknownDescriptor(other)),
    })
}

pub(crate) fn delivery_state_field(list: &[Value], index: usize) -> Result<Option<DeliveryState>, Amqp1Error> {
    match field(list, index) {
        None => Ok(None),
        Some(v) => decode_delivery_state(v).map(Some),
    }
}

// ---------------------------------------------------------------------
// Performatives (core spec 2.7).
// ---------------------------------------------------------------------

/// `open` (2.7.1).
#[derive(Debug, Clone, PartialEq)]
pub struct Open {
    /// Globally unique container identifier.
    pub container_id: String,
    /// Peer's DNS name, for a multi-tenant/virtual-hosting peer.
    pub hostname: Option<String>,
    /// Max frame size this side will accept.
    pub max_frame_size: u32,
    /// Max concurrent channel number.
    pub channel_max: u16,
    /// Idle timeout, in milliseconds.
    pub idle_time_out: Option<u32>,
    /// Locales this side can use for outgoing text.
    pub outgoing_locales: Vec<String>,
    /// Locales this side can understand in incoming text.
    pub incoming_locales: Vec<String>,
    /// Extension capabilities offered.
    pub offered_capabilities: Vec<String>,
    /// Extension capabilities desired.
    pub desired_capabilities: Vec<String>,
    /// Connection properties.
    pub properties: Vec<(Value, Value)>,
}

impl Default for Open {
    fn default() -> Self {
        Self {
            container_id: String::new(),
            hostname: None,
            max_frame_size: u32::MAX,
            channel_max: u16::MAX,
            idle_time_out: None,
            outgoing_locales: Vec::new(),
            incoming_locales: Vec::new(),
            offered_capabilities: Vec::new(),
            desired_capabilities: Vec::new(),
            properties: Vec::new(),
        }
    }
}

impl Open {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self {
            container_id: required(list, 0, "container-id")?
                .as_str()
                .ok_or(Amqp1Error::WrongFieldType("string"))?
                .to_string(),
            hostname: str_field(list, 1)?,
            max_frame_size: uint_field(list, 2)?.unwrap_or(u32::MAX),
            channel_max: ushort_field(list, 3)?.unwrap_or(u16::MAX),
            idle_time_out: uint_field(list, 4)?,
            outgoing_locales: symbols_field(list, 5)?,
            incoming_locales: symbols_field(list, 6)?,
            offered_capabilities: symbols_field(list, 7)?,
            desired_capabilities: symbols_field(list, 8)?,
            properties: map_field(list, 9)?,
        })
    }

    fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(Some(Value::String(self.container_id.clone())));
        items.push(self.hostname.clone().map(Value::String));
        items.push((self.max_frame_size != u32::MAX).then_some(Value::Uint(self.max_frame_size)));
        items.push((self.channel_max != u16::MAX).then_some(Value::Ushort(self.channel_max)));
        items.push(self.idle_time_out.map(Value::Uint));
        push_symbols(&mut items, &self.outgoing_locales);
        push_symbols(&mut items, &self.incoming_locales);
        push_symbols(&mut items, &self.offered_capabilities);
        push_symbols(&mut items, &self.desired_capabilities);
        push_map(&mut items, &self.properties);
        encode_described_list(OPEN, items)
    }
}

/// `begin` (2.7.3).
#[derive(Debug, Clone, PartialEq)]
pub struct Begin {
    /// The remote channel this begins a session on top of (peer's channel
    /// number), `None` when this side initiates.
    pub remote_channel: Option<u16>,
    /// Initial transfer-id this endpoint will assign to its next outgoing transfer.
    pub next_outgoing_id: u32,
    /// Initial incoming-window.
    pub incoming_window: u32,
    /// Initial outgoing-window.
    pub outgoing_window: u32,
    /// Highest handle value this endpoint will accept.
    pub handle_max: u32,
    /// Extension capabilities offered.
    pub offered_capabilities: Vec<String>,
    /// Extension capabilities desired.
    pub desired_capabilities: Vec<String>,
    /// Session properties.
    pub properties: Vec<(Value, Value)>,
}

impl Begin {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self {
            remote_channel: ushort_field(list, 0)?,
            next_outgoing_id: uint_field(list, 1)?.ok_or(Amqp1Error::RequiredFieldMissing("next-outgoing-id"))?,
            incoming_window: uint_field(list, 2)?.ok_or(Amqp1Error::RequiredFieldMissing("incoming-window"))?,
            outgoing_window: uint_field(list, 3)?.ok_or(Amqp1Error::RequiredFieldMissing("outgoing-window"))?,
            handle_max: uint_field(list, 4)?.unwrap_or(u32::MAX),
            offered_capabilities: symbols_field(list, 5)?,
            desired_capabilities: symbols_field(list, 6)?,
            properties: map_field(list, 7)?,
        })
    }

    fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(self.remote_channel.map(Value::Ushort));
        items.push(Some(Value::Uint(self.next_outgoing_id)));
        items.push(Some(Value::Uint(self.incoming_window)));
        items.push(Some(Value::Uint(self.outgoing_window)));
        items.push((self.handle_max != u32::MAX).then_some(Value::Uint(self.handle_max)));
        push_symbols(&mut items, &self.offered_capabilities);
        push_symbols(&mut items, &self.desired_capabilities);
        push_map(&mut items, &self.properties);
        encode_described_list(BEGIN, items)
    }
}

/// `attach` (2.7.3).
#[derive(Debug, Clone, PartialEq)]
pub struct Attach {
    /// Link name — identifies the link across attach/detach and reconnects.
    pub name: String,
    /// Handle this endpoint chose for the link on this session.
    pub handle: u32,
    /// `false` = sender, `true` = receiver (spec's `role` field).
    pub role_receiver: bool,
    /// Sender settle mode (0 unsettled, 1 settled, 2 mixed).
    pub snd_settle_mode: u8,
    /// Receiver settle mode (0 first, 1 second).
    pub rcv_settle_mode: u8,
    /// Source terminus.
    pub source: Option<Source>,
    /// Target terminus.
    pub target: Option<Target>,
    /// Unsettled delivery state map, keyed by delivery-tag, for link recovery.
    pub unsettled: Vec<(Value, Value)>,
    /// Whether `unsettled` may be incomplete.
    pub incomplete_unsettled: bool,
    /// Sender's initial delivery-count. Required when this endpoint is the
    /// sender; `None` for a receiver.
    pub initial_delivery_count: Option<u32>,
    /// Max message size this endpoint will accept/send, `0` = no limit.
    pub max_message_size: Option<u64>,
    /// Extension capabilities offered.
    pub offered_capabilities: Vec<String>,
    /// Extension capabilities desired.
    pub desired_capabilities: Vec<String>,
    /// Link properties.
    pub properties: Vec<(Value, Value)>,
}

impl Attach {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self {
            name: required(list, 0, "name")?.as_str().ok_or(Amqp1Error::WrongFieldType("string"))?.to_string(),
            handle: uint_field(list, 1)?.ok_or(Amqp1Error::RequiredFieldMissing("handle"))?,
            role_receiver: bool_field(list, 2, false)?,
            snd_settle_mode: uint_field(list, 3)?.unwrap_or(2) as u8,
            rcv_settle_mode: uint_field(list, 4)?.unwrap_or(0) as u8,
            source: match field(list, 5) {
                None => None,
                Some(v) => Some(decode_source(v)?),
            },
            target: match field(list, 6) {
                None => None,
                Some(v) => Some(decode_target(v)?),
            },
            unsettled: map_field(list, 7)?,
            incomplete_unsettled: bool_field(list, 8, false)?,
            initial_delivery_count: uint_field(list, 9)?,
            max_message_size: ulong_field(list, 10)?,
            offered_capabilities: symbols_field(list, 11)?,
            desired_capabilities: symbols_field(list, 12)?,
            properties: map_field(list, 13)?,
        })
    }

    fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(Some(Value::String(self.name.clone())));
        items.push(Some(Value::Uint(self.handle)));
        items.push(self.role_receiver.then_some(Value::Bool(true)).or(Some(Value::Bool(false))));
        items.push((self.snd_settle_mode != 2).then_some(Value::Ubyte(self.snd_settle_mode)));
        items.push((self.rcv_settle_mode != 0).then_some(Value::Ubyte(self.rcv_settle_mode)));
        items.push(self.source.as_ref().map(Source::encode));
        items.push(self.target.as_ref().map(Target::encode));
        push_map(&mut items, &self.unsettled);
        items.push(self.incomplete_unsettled.then_some(Value::Bool(true)));
        items.push(self.initial_delivery_count.map(Value::Uint));
        items.push(self.max_message_size.map(Value::Ulong));
        push_symbols(&mut items, &self.offered_capabilities);
        push_symbols(&mut items, &self.desired_capabilities);
        push_map(&mut items, &self.properties);
        encode_described_list(ATTACH, items)
    }
}

/// `flow` (2.7.4) — carries both session-level window updates and, when
/// `handle` is set, link-level credit updates.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Flow {
    /// The next transfer-id this endpoint expects to receive, if it has
    /// received any transfers on this session yet.
    pub next_incoming_id: Option<u32>,
    /// Current incoming-window.
    pub incoming_window: u32,
    /// The next transfer-id this endpoint will assign.
    pub next_outgoing_id: u32,
    /// Current outgoing-window.
    pub outgoing_window: u32,
    /// Link handle this flow update applies to, `None` for a session-only flow.
    pub handle: Option<u32>,
    /// Sender's current delivery-count.
    pub delivery_count: Option<u32>,
    /// Link credit granted to the sender.
    pub link_credit: Option<u32>,
    /// Sender's current count of deliveries available to send.
    pub available: Option<u32>,
    /// Whether the sender should immediately use up all credit (drain).
    pub drain: bool,
    /// Request the peer to reply with its own flow state.
    pub echo: bool,
    /// Flow properties.
    pub properties: Vec<(Value, Value)>,
}

impl Flow {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self {
            next_incoming_id: uint_field(list, 0)?,
            incoming_window: uint_field(list, 1)?.ok_or(Amqp1Error::RequiredFieldMissing("incoming-window"))?,
            next_outgoing_id: uint_field(list, 2)?.ok_or(Amqp1Error::RequiredFieldMissing("next-outgoing-id"))?,
            outgoing_window: uint_field(list, 3)?.ok_or(Amqp1Error::RequiredFieldMissing("outgoing-window"))?,
            handle: uint_field(list, 4)?,
            delivery_count: uint_field(list, 5)?,
            link_credit: uint_field(list, 6)?,
            available: uint_field(list, 7)?,
            drain: bool_field(list, 8, false)?,
            echo: bool_field(list, 9, false)?,
            properties: map_field(list, 10)?,
        })
    }

    fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(self.next_incoming_id.map(Value::Uint));
        items.push(Some(Value::Uint(self.incoming_window)));
        items.push(Some(Value::Uint(self.next_outgoing_id)));
        items.push(Some(Value::Uint(self.outgoing_window)));
        items.push(self.handle.map(Value::Uint));
        items.push(self.delivery_count.map(Value::Uint));
        items.push(self.link_credit.map(Value::Uint));
        items.push(self.available.map(Value::Uint));
        items.push(self.drain.then_some(Value::Bool(true)));
        items.push(self.echo.then_some(Value::Bool(true)));
        push_map(&mut items, &self.properties);
        encode_described_list(FLOW, items)
    }
}

/// `transfer` (2.7.5). `state`/other delivery-state fields use
/// [`DeliveryState`]; the frame's payload (message bytes) follows separately
/// in the same frame body and is returned by [`decode_performative`]'s
/// `consumed` length, not stored here.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Transfer {
    /// Link handle.
    pub handle: u32,
    /// Delivery-id, required on the first transfer of a delivery.
    pub delivery_id: Option<u32>,
    /// Delivery-tag, required on the first transfer of a delivery.
    pub delivery_tag: Option<Vec<u8>>,
    /// Message format code (`0` = the standard AMQP message format).
    pub message_format: u32,
    /// Whether this delivery is (or, on the first transfer, will be) settled.
    pub settled: Option<bool>,
    /// Whether more transfer frames follow for this delivery.
    pub more: bool,
    /// Receiver settle mode override for this delivery.
    pub rcv_settle_mode: Option<u8>,
    /// Delivery state (e.g. a `received` marker when resuming).
    pub state: Option<DeliveryState>,
    /// Resuming a previously-suspended delivery.
    pub resume: bool,
    /// This delivery is aborted; accumulated payload should be discarded.
    pub aborted: bool,
    /// Batchable hint.
    pub batchable: bool,
}

impl Transfer {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self {
            handle: uint_field(list, 0)?.ok_or(Amqp1Error::RequiredFieldMissing("handle"))?,
            delivery_id: uint_field(list, 1)?,
            delivery_tag: binary_field(list, 2)?,
            message_format: uint_field(list, 3)?.unwrap_or(0),
            settled: match field(list, 4) {
                None => None,
                Some(v) => Some(v.as_bool().ok_or(Amqp1Error::WrongFieldType("boolean"))?),
            },
            more: bool_field(list, 5, false)?,
            rcv_settle_mode: uint_field(list, 6)?.map(|v| v as u8),
            state: delivery_state_field(list, 7)?,
            resume: bool_field(list, 8, false)?,
            aborted: bool_field(list, 9, false)?,
            batchable: bool_field(list, 10, false)?,
        })
    }

    fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(Some(Value::Uint(self.handle)));
        items.push(self.delivery_id.map(Value::Uint));
        items.push(self.delivery_tag.clone().map(Value::Binary));
        items.push((self.message_format != 0).then_some(Value::Uint(self.message_format)));
        items.push(self.settled.map(Value::Bool));
        items.push(self.more.then_some(Value::Bool(true)));
        items.push(self.rcv_settle_mode.map(Value::Ubyte));
        items.push(self.state.as_ref().map(DeliveryState::encode));
        items.push(self.resume.then_some(Value::Bool(true)));
        items.push(self.aborted.then_some(Value::Bool(true)));
        items.push(self.batchable.then_some(Value::Bool(true)));
        encode_described_list(TRANSFER, items)
    }
}

/// `disposition` (2.7.6).
#[derive(Debug, Clone, PartialEq)]
pub struct Disposition {
    /// `false` = sender reporting, `true` = receiver reporting (spec's `role`).
    pub role_receiver: bool,
    /// First delivery-id in the range this disposition updates.
    pub first: u32,
    /// Last delivery-id in the range (defaults to `first`).
    pub last: u32,
    /// Whether the range is now settled.
    pub settled: bool,
    /// New delivery state for the range.
    pub state: Option<DeliveryState>,
    /// Batchable hint.
    pub batchable: bool,
}

impl Disposition {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        let first = uint_field(list, 1)?.ok_or(Amqp1Error::RequiredFieldMissing("first"))?;
        Ok(Self {
            role_receiver: bool_field(list, 0, false)?,
            first,
            last: uint_field(list, 2)?.unwrap_or(first),
            settled: bool_field(list, 3, false)?,
            state: delivery_state_field(list, 4)?,
            batchable: bool_field(list, 5, false)?,
        })
    }

    fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(Some(Value::Bool(self.role_receiver)));
        items.push(Some(Value::Uint(self.first)));
        items.push((self.last != self.first).then_some(Value::Uint(self.last)));
        items.push(self.settled.then_some(Value::Bool(true)));
        items.push(self.state.as_ref().map(DeliveryState::encode));
        items.push(self.batchable.then_some(Value::Bool(true)));
        encode_described_list(DISPOSITION, items)
    }
}

/// `detach` (2.7.7).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Detach {
    /// Link handle being detached.
    pub handle: u32,
    /// Whether this is a full close of the link (not just a suspend).
    pub closed: bool,
    /// Error, if the detach is due to a link-level failure.
    pub error: Option<Error>,
}

impl Detach {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self {
            handle: uint_field(list, 0)?.ok_or(Amqp1Error::RequiredFieldMissing("handle"))?,
            closed: bool_field(list, 1, false)?,
            error: error_field(list, 2)?,
        })
    }

    fn encode(&self) -> Value {
        let mut items = Vec::new();
        items.push(Some(Value::Uint(self.handle)));
        items.push(self.closed.then_some(Value::Bool(true)));
        items.push(self.error.as_ref().map(Error::encode));
        encode_described_list(DETACH, items)
    }
}

/// `end` (2.7.8).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct End {
    /// Error, if the session ended due to a failure.
    pub error: Option<Error>,
}

impl End {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self { error: error_field(list, 0)? })
    }

    fn encode(&self) -> Value {
        encode_described_list(END, vec![self.error.as_ref().map(Error::encode)])
    }
}

/// `close` (2.7.9).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Close {
    /// Error, if the connection closed due to a failure.
    pub error: Option<Error>,
}

impl Close {
    fn decode(list: &[Value]) -> Result<Self, Amqp1Error> {
        Ok(Self { error: error_field(list, 0)? })
    }

    fn encode(&self) -> Value {
        encode_described_list(CLOSE, vec![self.error.as_ref().map(Error::encode)])
    }
}

/// A decoded performative.
///
/// `Attach` is much larger than the other variants (it carries both link
/// termini plus capability/property lists) — boxing it would save stack
/// space per [`Performative`] value at the cost of an extra allocation on
/// every attach, decoded far less often per connection than, say,
/// `Transfer`; not worth it for a value that's immediately matched and
/// consumed rather than stored long-term.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Performative {
    /// `open`.
    Open(Open),
    /// `begin`.
    Begin(Begin),
    /// `attach`.
    Attach(Attach),
    /// `flow`.
    Flow(Flow),
    /// `transfer`.
    Transfer(Transfer),
    /// `disposition`.
    Disposition(Disposition),
    /// `detach`.
    Detach(Detach),
    /// `end`.
    End(End),
    /// `close`.
    Close(Close),
}

impl Performative {
    /// Encode to bytes (the frame body for an AMQP-type frame; for
    /// `transfer`, the caller appends the message payload bytes after this).
    pub fn encode(&self) -> Vec<u8> {
        let value = match self {
            Performative::Open(v) => v.encode(),
            Performative::Begin(v) => v.encode(),
            Performative::Attach(v) => v.encode(),
            Performative::Flow(v) => v.encode(),
            Performative::Transfer(v) => v.encode(),
            Performative::Disposition(v) => v.encode(),
            Performative::Detach(v) => v.encode(),
            Performative::End(v) => v.encode(),
            Performative::Close(v) => v.encode(),
        };
        let mut enc = Encoder::new();
        enc.value(&value);
        enc.into_bytes()
    }
}

/// Decode one performative from the start of an AMQP-type frame's body.
/// Returns the performative and how many bytes it consumed — for
/// `transfer`, `body[consumed..]` is the message payload.
pub fn decode_performative(body: &[u8]) -> Result<(Performative, usize), Amqp1Error> {
    let (value, consumed) = decode(body)?;
    let (code, list) = as_described_list(&value)?;
    let performative = match code {
        OPEN => Performative::Open(Open::decode(list)?),
        BEGIN => Performative::Begin(Begin::decode(list)?),
        ATTACH => Performative::Attach(Attach::decode(list)?),
        FLOW => Performative::Flow(Flow::decode(list)?),
        TRANSFER => Performative::Transfer(Transfer::decode(list)?),
        DISPOSITION => Performative::Disposition(Disposition::decode(list)?),
        DETACH => Performative::Detach(Detach::decode(list)?),
        END => Performative::End(End::decode(list)?),
        CLOSE => Performative::Close(Close::decode(list)?),
        other => return Err(Amqp1Error::UnknownDescriptor(other)),
    };
    Ok((performative, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_roundtrips_with_capabilities() {
        let open = Open {
            container_id: "hopf-amqp1-client".into(),
            hostname: Some("broker.example.test".into()),
            max_frame_size: 65536,
            channel_max: 100,
            idle_time_out: Some(30_000),
            offered_capabilities: vec!["one".into(), "two".into()],
            ..Default::default()
        };
        let bytes = Performative::Open(open.clone()).encode();
        let (decoded, consumed) = decode_performative(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, Performative::Open(open));
    }

    #[test]
    fn open_defaults_are_applied_on_a_minimal_list() {
        // Only container-id present: everything else should take defaults.
        let mut enc = Encoder::new();
        enc.described(0x10, &Value::List(vec![Value::String("c1".into())]));
        let (decoded, _) = decode_performative(&enc.into_bytes()).unwrap();
        match decoded {
            Performative::Open(o) => {
                assert_eq!(o.container_id, "c1");
                assert_eq!(o.max_frame_size, u32::MAX);
                assert_eq!(o.channel_max, u16::MAX);
                assert!(o.hostname.is_none());
            }
            other => panic!("expected Open, got {other:?}"),
        }
    }

    #[test]
    fn begin_roundtrips() {
        let begin = Begin {
            remote_channel: Some(3),
            next_outgoing_id: 1,
            incoming_window: 100,
            outgoing_window: 100,
            handle_max: 10,
            ..unchecked_begin_defaults()
        };
        let bytes = Performative::Begin(begin.clone()).encode();
        let (decoded, _) = decode_performative(&bytes).unwrap();
        assert_eq!(decoded, Performative::Begin(begin));
    }

    fn unchecked_begin_defaults() -> Begin {
        Begin {
            remote_channel: None,
            next_outgoing_id: 0,
            incoming_window: 0,
            outgoing_window: 0,
            handle_max: u32::MAX,
            offered_capabilities: vec![],
            desired_capabilities: vec![],
            properties: vec![],
        }
    }

    #[test]
    fn attach_sender_roundtrips_with_source_and_target() {
        let attach = Attach {
            name: "link-1".into(),
            handle: 0,
            role_receiver: false,
            snd_settle_mode: 2,
            rcv_settle_mode: 0,
            source: Some(Source::with_address("orders")),
            target: Some(Target::with_address("orders")),
            unsettled: vec![],
            incomplete_unsettled: false,
            initial_delivery_count: Some(0),
            max_message_size: Some(1_048_576),
            offered_capabilities: vec![],
            desired_capabilities: vec![],
            properties: vec![],
        };
        let bytes = Performative::Attach(attach.clone()).encode();
        let (decoded, _) = decode_performative(&bytes).unwrap();
        assert_eq!(decoded, Performative::Attach(attach));
    }

    #[test]
    fn attach_receiver_has_no_initial_delivery_count() {
        let attach = Attach {
            name: "link-2".into(),
            handle: 1,
            role_receiver: true,
            snd_settle_mode: 2,
            rcv_settle_mode: 0,
            source: Some(Source::with_address("orders")),
            target: None,
            unsettled: vec![],
            incomplete_unsettled: false,
            initial_delivery_count: None,
            max_message_size: None,
            offered_capabilities: vec![],
            desired_capabilities: vec![],
            properties: vec![],
        };
        let bytes = Performative::Attach(attach.clone()).encode();
        let (decoded, _) = decode_performative(&bytes).unwrap();
        match decoded {
            Performative::Attach(a) => {
                assert!(a.role_receiver);
                assert!(a.initial_delivery_count.is_none());
                assert!(a.target.is_none());
            }
            other => panic!("expected Attach, got {other:?}"),
        }
    }

    #[test]
    fn flow_session_only_has_no_handle() {
        let flow = Flow {
            next_incoming_id: Some(5),
            incoming_window: 10,
            next_outgoing_id: 5,
            outgoing_window: 10,
            ..Default::default()
        };
        let bytes = Performative::Flow(flow.clone()).encode();
        let (decoded, _) = decode_performative(&bytes).unwrap();
        assert_eq!(decoded, Performative::Flow(flow));
    }

    #[test]
    fn flow_link_credit_roundtrips() {
        let flow = Flow {
            next_incoming_id: Some(5),
            incoming_window: 2000,
            next_outgoing_id: 5,
            outgoing_window: 2000,
            handle: Some(0),
            delivery_count: Some(7),
            link_credit: Some(50),
            drain: true,
            ..Default::default()
        };
        let bytes = Performative::Flow(flow.clone()).encode();
        let (decoded, _) = decode_performative(&bytes).unwrap();
        assert_eq!(decoded, Performative::Flow(flow));
    }

    #[test]
    fn transfer_with_payload_reports_correct_consumed_length() {
        let transfer = Transfer {
            handle: 0,
            delivery_id: Some(1),
            delivery_tag: Some(vec![1, 2, 3]),
            settled: Some(false),
            more: false,
            ..Default::default()
        };
        let mut bytes = Performative::Transfer(transfer.clone()).encode();
        let performative_len = bytes.len();
        bytes.extend_from_slice(b"message payload bytes");
        let (decoded, consumed) = decode_performative(&bytes).unwrap();
        assert_eq!(consumed, performative_len);
        assert_eq!(decoded, Performative::Transfer(transfer));
        assert_eq!(&bytes[consumed..], b"message payload bytes");
    }

    #[test]
    fn disposition_defaults_last_to_first() {
        let mut enc = Encoder::new();
        enc.described(0x15, &Value::List(vec![Value::Bool(true), Value::Uint(42)]));
        let (decoded, _) = decode_performative(&enc.into_bytes()).unwrap();
        match decoded {
            Performative::Disposition(d) => {
                assert!(d.role_receiver);
                assert_eq!(d.first, 42);
                assert_eq!(d.last, 42);
            }
            other => panic!("expected Disposition, got {other:?}"),
        }
    }

    #[test]
    fn delivery_states_roundtrip() {
        for state in [
            DeliveryState::Accepted,
            DeliveryState::Released,
            DeliveryState::Rejected(Some(Error::with_description("amqp:decode-error", "bad body"))),
            DeliveryState::Rejected(None),
            DeliveryState::Modified {
                delivery_failed: true,
                undeliverable_here: false,
                message_annotations: vec![(Value::Symbol("x".into()), Value::Uint(1))],
            },
            DeliveryState::Received {
                section_number: 0,
                section_offset: 128,
            },
        ] {
            let disposition = Disposition {
                role_receiver: true,
                first: 1,
                last: 1,
                settled: true,
                state: Some(state.clone()),
                batchable: false,
            };
            let bytes = Performative::Disposition(disposition).encode();
            let (decoded, _) = decode_performative(&bytes).unwrap();
            match decoded {
                Performative::Disposition(d) => assert_eq!(d.state, Some(state)),
                other => panic!("expected Disposition, got {other:?}"),
            }
        }
    }

    #[test]
    fn detach_end_close_with_error_roundtrip() {
        let err = Error::with_description("amqp:link:detach-forced", "administrator action");

        let detach = Detach { handle: 3, closed: true, error: Some(err.clone()) };
        let bytes = Performative::Detach(detach.clone()).encode();
        assert_eq!(decode_performative(&bytes).unwrap().0, Performative::Detach(detach));

        let end = End { error: Some(err.clone()) };
        let bytes = Performative::End(end.clone()).encode();
        assert_eq!(decode_performative(&bytes).unwrap().0, Performative::End(end));

        let close = Close { error: Some(err) };
        let bytes = Performative::Close(close.clone()).encode();
        assert_eq!(decode_performative(&bytes).unwrap().0, Performative::Close(close));
    }

    #[test]
    fn close_with_no_error_encodes_as_empty_list() {
        let bytes = Performative::Close(Close::default()).encode();
        // descriptor + list0: 0x00 0x53 0x18 0x45
        assert_eq!(bytes, vec![0x00, 0x53, 0x18, 0x45]);
    }

    #[test]
    fn unknown_descriptor_errors() {
        let mut enc = Encoder::new();
        enc.described(0x99, &Value::List(vec![]));
        assert!(matches!(
            decode_performative(&enc.into_bytes()),
            Err(Amqp1Error::UnknownDescriptor(0x99))
        ));
    }

    #[test]
    fn missing_required_field_errors() {
        let mut enc = Encoder::new();
        enc.described(0x10, &Value::List(vec![])); // open with no container-id
        assert!(matches!(
            decode_performative(&enc.into_bytes()),
            Err(Amqp1Error::RequiredFieldMissing("container-id"))
        ));
    }
}
