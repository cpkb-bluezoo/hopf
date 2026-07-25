// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT 5.0 properties (§2.2.2).
//!
//! For MQTT 3.1.1 connections, properties are always empty — the same
//! [`Properties`] type is used for both versions so packet decode/encode
//! doesn't need to change shape when v5 is enabled.

use std::collections::BTreeMap;

use super::varint::{self, VarIntResult};
use super::MqttError;

/// MQTT 5.0 property identifiers (§2.2.2.2).
pub mod property {
    /// Payload Format Indicator (byte).
    pub const PAYLOAD_FORMAT_INDICATOR: u8 = 0x01;
    /// Message Expiry Interval (u32 seconds).
    pub const MESSAGE_EXPIRY_INTERVAL: u8 = 0x02;
    /// Content Type (UTF-8 string).
    pub const CONTENT_TYPE: u8 = 0x03;
    /// Response Topic (UTF-8 string).
    pub const RESPONSE_TOPIC: u8 = 0x08;
    /// Correlation Data (binary).
    pub const CORRELATION_DATA: u8 = 0x09;
    /// Subscription Identifier (variable-length integer).
    pub const SUBSCRIPTION_IDENTIFIER: u8 = 0x0B;
    /// Session Expiry Interval (u32 seconds).
    pub const SESSION_EXPIRY_INTERVAL: u8 = 0x11;
    /// Assigned Client Identifier (UTF-8 string).
    pub const ASSIGNED_CLIENT_IDENTIFIER: u8 = 0x12;
    /// Server Keep Alive (u16 seconds).
    pub const SERVER_KEEP_ALIVE: u8 = 0x13;
    /// Authentication Method (UTF-8 string).
    pub const AUTHENTICATION_METHOD: u8 = 0x15;
    /// Authentication Data (binary).
    pub const AUTHENTICATION_DATA: u8 = 0x16;
    /// Request Problem Information (byte).
    pub const REQUEST_PROBLEM_INFORMATION: u8 = 0x17;
    /// Will Delay Interval (u32 seconds).
    pub const WILL_DELAY_INTERVAL: u8 = 0x18;
    /// Request Response Information (byte).
    pub const REQUEST_RESPONSE_INFORMATION: u8 = 0x19;
    /// Response Information (UTF-8 string).
    pub const RESPONSE_INFORMATION: u8 = 0x1A;
    /// Server Reference (UTF-8 string).
    pub const SERVER_REFERENCE: u8 = 0x1C;
    /// Reason String (UTF-8 string).
    pub const REASON_STRING: u8 = 0x1F;
    /// Receive Maximum (u16).
    pub const RECEIVE_MAXIMUM: u8 = 0x21;
    /// Topic Alias Maximum (u16).
    pub const TOPIC_ALIAS_MAXIMUM: u8 = 0x22;
    /// Topic Alias (u16).
    pub const TOPIC_ALIAS: u8 = 0x23;
    /// Maximum QoS (byte).
    pub const MAXIMUM_QOS: u8 = 0x24;
    /// Retain Available (byte).
    pub const RETAIN_AVAILABLE: u8 = 0x25;
    /// User Property (UTF-8 string pair; repeatable — see [`super::Properties::user_properties`]).
    pub const USER_PROPERTY: u8 = 0x26;
    /// Maximum Packet Size (u32).
    pub const MAXIMUM_PACKET_SIZE: u8 = 0x27;
    /// Wildcard Subscription Available (byte).
    pub const WILDCARD_SUBSCRIPTION_AVAILABLE: u8 = 0x28;
    /// Subscription Identifiers Available (byte).
    pub const SUBSCRIPTION_IDENTIFIER_AVAILABLE: u8 = 0x29;
    /// Shared Subscription Available (byte).
    pub const SHARED_SUBSCRIPTION_AVAILABLE: u8 = 0x2A;
}

/// A single decoded property value, tagged by its wire encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue {
    /// One-byte value.
    Byte(u8),
    /// Two-byte big-endian value.
    U16(u16),
    /// Four-byte big-endian value.
    U32(u32),
    /// Variable-length integer value (Subscription Identifier only).
    VarInt(u32),
    /// UTF-8 string value.
    Utf8(String),
    /// Binary value.
    Binary(Vec<u8>),
}

/// MQTT 5.0 property set attached to a packet.
///
/// Every property id except [`property::USER_PROPERTY`] is single-valued
/// (a later `set_*` call for the same id replaces the earlier one, and
/// decode keeps the last occurrence on the wire — this mirrors the Gumdrop
/// implementation; the spec's allowance for repeated Subscription
/// Identifiers on a forwarded PUBLISH is not modelled here). User
/// properties may repeat and are kept in wire order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Properties {
    values: BTreeMap<u8, PropertyValue>,
    user_properties: Vec<(String, String)>,
}

impl Properties {
    /// Empty property set (MQTT 3.1.1 packets always use this).
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether there are no properties at all.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty() && self.user_properties.is_empty()
    }

    /// Set a one-byte property.
    pub fn set_byte(&mut self, id: u8, value: u8) -> &mut Self {
        self.values.insert(id, PropertyValue::Byte(value));
        self
    }

    /// Set a two-byte property.
    pub fn set_u16(&mut self, id: u8, value: u16) -> &mut Self {
        self.values.insert(id, PropertyValue::U16(value));
        self
    }

    /// Set a four-byte property.
    pub fn set_u32(&mut self, id: u8, value: u32) -> &mut Self {
        self.values.insert(id, PropertyValue::U32(value));
        self
    }

    /// Set a variable-length-integer property (Subscription Identifier).
    pub fn set_varint(&mut self, id: u8, value: u32) -> &mut Self {
        self.values.insert(id, PropertyValue::VarInt(value));
        self
    }

    /// Set a UTF-8 string property.
    pub fn set_utf8(&mut self, id: u8, value: impl Into<String>) -> &mut Self {
        self.values.insert(id, PropertyValue::Utf8(value.into()));
        self
    }

    /// Set a binary property.
    pub fn set_binary(&mut self, id: u8, value: impl Into<Vec<u8>>) -> &mut Self {
        self.values.insert(id, PropertyValue::Binary(value.into()));
        self
    }

    /// Append a User Property pair.
    pub fn add_user_property(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.user_properties.push((key.into(), value.into()));
        self
    }

    /// Read a one-byte property.
    pub fn get_byte(&self, id: u8) -> Option<u8> {
        match self.values.get(&id) {
            Some(PropertyValue::Byte(v)) => Some(*v),
            _ => None,
        }
    }

    /// Read a two-byte property.
    pub fn get_u16(&self, id: u8) -> Option<u16> {
        match self.values.get(&id) {
            Some(PropertyValue::U16(v)) => Some(*v),
            _ => None,
        }
    }

    /// Read a four-byte property.
    pub fn get_u32(&self, id: u8) -> Option<u32> {
        match self.values.get(&id) {
            Some(PropertyValue::U32(v)) => Some(*v),
            _ => None,
        }
    }

    /// Read a variable-length-integer property.
    pub fn get_varint(&self, id: u8) -> Option<u32> {
        match self.values.get(&id) {
            Some(PropertyValue::VarInt(v)) => Some(*v),
            _ => None,
        }
    }

    /// Read a UTF-8 string property.
    pub fn get_utf8(&self, id: u8) -> Option<&str> {
        match self.values.get(&id) {
            Some(PropertyValue::Utf8(v)) => Some(v.as_str()),
            _ => None,
        }
    }

    /// Read a binary property.
    pub fn get_binary(&self, id: u8) -> Option<&[u8]> {
        match self.values.get(&id) {
            Some(PropertyValue::Binary(v)) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// All User Property pairs, in wire order.
    pub fn user_properties(&self) -> &[(String, String)] {
        &self.user_properties
    }

    /// Encoded length of the properties themselves (not including the
    /// variable-length integer that encodes this length).
    pub fn encoded_len(&self) -> usize {
        let mut len = 0;
        for val in self.values.values() {
            len += 1; // property id
            len += value_encoded_len(val);
        }
        for (k, v) in &self.user_properties {
            len += 1 + 2 + k.len() + 2 + v.len();
        }
        len
    }

    /// Append the property-length varint followed by the properties.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let len = self.encoded_len();
        varint::encode(out, len as u32);
        for (id, val) in &self.values {
            out.push(*id);
            encode_value(out, val);
        }
        for (k, v) in &self.user_properties {
            out.push(property::USER_PROPERTY);
            encode_utf8(out, k);
            encode_utf8(out, v);
        }
    }

    /// Decode a property-length varint followed by that many bytes of
    /// properties from the front of `buf`.
    ///
    /// Returns the decoded properties and the total bytes consumed
    /// (including the length varint itself), or `None` if `buf` doesn't
    /// yet contain the complete property block.
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>, MqttError> {
        let (prop_len, varint_len) = match varint::decode(buf) {
            VarIntResult::Ok { value, len } => (value as usize, len),
            VarIntResult::NeedMoreData => return Ok(None),
            VarIntResult::Malformed => {
                return Err(MqttError::Malformed("malformed property length"))
            }
        };
        let total = varint_len + prop_len;
        if buf.len() < total {
            return Ok(None);
        }
        let mut props = Properties::new();
        let mut pos = varint_len;
        let end = total;
        while pos < end {
            let id = buf[pos];
            pos += 1;
            match id {
                property::PAYLOAD_FORMAT_INDICATOR
                | property::REQUEST_PROBLEM_INFORMATION
                | property::REQUEST_RESPONSE_INFORMATION
                | property::MAXIMUM_QOS
                | property::RETAIN_AVAILABLE
                | property::WILDCARD_SUBSCRIPTION_AVAILABLE
                | property::SUBSCRIPTION_IDENTIFIER_AVAILABLE
                | property::SHARED_SUBSCRIPTION_AVAILABLE => {
                    let v = read_u8(buf, &mut pos, end)?;
                    props.set_byte(id, v);
                }
                property::MESSAGE_EXPIRY_INTERVAL
                | property::SESSION_EXPIRY_INTERVAL
                | property::WILL_DELAY_INTERVAL
                | property::MAXIMUM_PACKET_SIZE => {
                    let v = read_u32(buf, &mut pos, end)?;
                    props.set_u32(id, v);
                }
                property::SERVER_KEEP_ALIVE
                | property::RECEIVE_MAXIMUM
                | property::TOPIC_ALIAS_MAXIMUM
                | property::TOPIC_ALIAS => {
                    let v = read_u16(buf, &mut pos, end)?;
                    props.set_u16(id, v);
                }
                property::SUBSCRIPTION_IDENTIFIER => {
                    match varint::decode(&buf[pos..end]) {
                        VarIntResult::Ok { value, len } => {
                            pos += len;
                            props.set_varint(id, value);
                        }
                        _ => return Err(MqttError::Malformed("malformed subscription identifier")),
                    }
                }
                property::CONTENT_TYPE
                | property::RESPONSE_TOPIC
                | property::ASSIGNED_CLIENT_IDENTIFIER
                | property::AUTHENTICATION_METHOD
                | property::RESPONSE_INFORMATION
                | property::SERVER_REFERENCE
                | property::REASON_STRING => {
                    let v = read_utf8(buf, &mut pos, end)?;
                    props.set_utf8(id, v);
                }
                property::CORRELATION_DATA | property::AUTHENTICATION_DATA => {
                    let v = read_binary(buf, &mut pos, end)?;
                    props.set_binary(id, v);
                }
                property::USER_PROPERTY => {
                    let k = read_utf8(buf, &mut pos, end)?;
                    let v = read_utf8(buf, &mut pos, end)?;
                    props.add_user_property(k, v);
                }
                _ => return Err(MqttError::Malformed("unknown property identifier")),
            }
        }
        Ok(Some((props, total)))
    }
}

fn value_encoded_len(val: &PropertyValue) -> usize {
    match val {
        PropertyValue::Byte(_) => 1,
        PropertyValue::U16(_) => 2,
        PropertyValue::U32(_) => 4,
        PropertyValue::VarInt(v) => varint::encoded_len(*v),
        PropertyValue::Utf8(s) => 2 + s.len(),
        PropertyValue::Binary(b) => 2 + b.len(),
    }
}

fn encode_value(out: &mut Vec<u8>, val: &PropertyValue) {
    match val {
        PropertyValue::Byte(v) => out.push(*v),
        PropertyValue::U16(v) => out.extend_from_slice(&v.to_be_bytes()),
        PropertyValue::U32(v) => out.extend_from_slice(&v.to_be_bytes()),
        PropertyValue::VarInt(v) => varint::encode(out, *v),
        PropertyValue::Utf8(s) => encode_utf8(out, s),
        PropertyValue::Binary(b) => encode_binary(out, b),
    }
}

fn encode_utf8(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn encode_binary(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

fn read_u8(buf: &[u8], pos: &mut usize, end: usize) -> Result<u8, MqttError> {
    if *pos >= end {
        return Err(MqttError::Malformed("truncated property"));
    }
    let v = buf[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u16(buf: &[u8], pos: &mut usize, end: usize) -> Result<u16, MqttError> {
    if *pos + 2 > end {
        return Err(MqttError::Malformed("truncated property"));
    }
    let v = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn read_u32(buf: &[u8], pos: &mut usize, end: usize) -> Result<u32, MqttError> {
    if *pos + 4 > end {
        return Err(MqttError::Malformed("truncated property"));
    }
    let v = u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

/// Read a length-prefixed UTF-8 string (MQTT 3.1.1 §1.5.3 / MQTT 5.0 §1.5.4).
pub(super) fn read_utf8(buf: &[u8], pos: &mut usize, end: usize) -> Result<String, MqttError> {
    let len = read_u16(buf, pos, end)? as usize;
    if *pos + len > end {
        return Err(MqttError::Malformed("truncated UTF-8 string"));
    }
    let s = String::from_utf8(buf[*pos..*pos + len].to_vec())
        .map_err(|_| MqttError::Malformed("invalid UTF-8 string"))?;
    *pos += len;
    Ok(s)
}

/// Read length-prefixed binary data (MQTT 5.0 §1.5.6).
pub(super) fn read_binary(buf: &[u8], pos: &mut usize, end: usize) -> Result<Vec<u8>, MqttError> {
    let len = read_u16(buf, pos, end)? as usize;
    if *pos + len > end {
        return Err(MqttError::Malformed("truncated binary data"));
    }
    let v = buf[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_properties_encode_as_zero_length() {
        let props = Properties::new();
        let mut out = Vec::new();
        props.encode(&mut out);
        assert_eq!(out, vec![0x00]);
        let (decoded, consumed) = Properties::decode(&out).unwrap().unwrap();
        assert!(decoded.is_empty());
        assert_eq!(consumed, 1);
    }

    #[test]
    fn round_trip_mixed_property_types() {
        let mut props = Properties::new();
        props
            .set_byte(property::PAYLOAD_FORMAT_INDICATOR, 1)
            .set_u32(property::MESSAGE_EXPIRY_INTERVAL, 3600)
            .set_u16(property::RECEIVE_MAXIMUM, 20)
            .set_varint(property::SUBSCRIPTION_IDENTIFIER, 200_000)
            .set_utf8(property::CONTENT_TYPE, "application/json")
            .set_binary(property::CORRELATION_DATA, vec![1, 2, 3])
            .add_user_property("k1", "v1")
            .add_user_property("k2", "v2");

        let mut out = Vec::new();
        props.encode(&mut out);
        let (decoded, consumed) = Properties::decode(&out).unwrap().unwrap();
        assert_eq!(consumed, out.len());
        assert_eq!(decoded.get_byte(property::PAYLOAD_FORMAT_INDICATOR), Some(1));
        assert_eq!(decoded.get_u32(property::MESSAGE_EXPIRY_INTERVAL), Some(3600));
        assert_eq!(decoded.get_u16(property::RECEIVE_MAXIMUM), Some(20));
        assert_eq!(decoded.get_varint(property::SUBSCRIPTION_IDENTIFIER), Some(200_000));
        assert_eq!(decoded.get_utf8(property::CONTENT_TYPE), Some("application/json"));
        assert_eq!(decoded.get_binary(property::CORRELATION_DATA), Some(&[1u8, 2, 3][..]));
        assert_eq!(
            decoded.user_properties(),
            &[("k1".to_string(), "v1".to_string()), ("k2".to_string(), "v2".to_string())]
        );
    }

    #[test]
    fn decode_needs_more_data_on_truncated_block() {
        let mut props = Properties::new();
        props.set_utf8(property::CONTENT_TYPE, "text/plain");
        let mut out = Vec::new();
        props.encode(&mut out);
        // Truncate mid-property.
        let truncated = &out[..out.len() - 2];
        assert_eq!(Properties::decode(truncated).unwrap(), None);
    }

    #[test]
    fn decode_rejects_unknown_property_id() {
        // Length=1, then an unassigned property id.
        let buf = [0x01u8, 0x7E];
        assert!(matches!(Properties::decode(&buf), Err(MqttError::Malformed(_))));
    }

    #[test]
    fn decode_rejects_invalid_utf8() {
        let mut out = vec![property::CONTENT_TYPE, 0x00, 0x01, 0xFF]; // 1-byte "string" that's invalid UTF-8
        out.insert(0, out.len() as u8); // property length prefix
        assert!(matches!(Properties::decode(&out), Err(MqttError::Malformed(_))));
    }
}
