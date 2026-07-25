// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Decoders for complete (already length-delimited) MQTT packet bodies.
//!
//! Every function here operates on a byte slice that the caller has already
//! sliced to exactly one packet's Remaining Length — running out of bytes
//! mid-parse is therefore a genuine [`MqttError::Malformed`], never "need
//! more data" (the exception is [`decode_publish_var_header`], which is
//! called incrementally while payload bytes are still arriving — see
//! [`super::parser`]).

use super::packet::{ConnectPacket, ProtocolVersion, PublishHeader, QoS, SubscribeFilter, Will};
use super::properties::{read_binary, read_utf8, Properties};
use super::MqttError;

fn need(buf: &[u8], pos: usize, n: usize) -> Result<(), MqttError> {
    if pos + n > buf.len() {
        Err(MqttError::Malformed("truncated packet"))
    } else {
        Ok(())
    }
}

fn read_u16(buf: &[u8], pos: &mut usize) -> Result<u16, MqttError> {
    need(buf, *pos, 2)?;
    let v = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn read_str(buf: &[u8], pos: &mut usize) -> Result<String, MqttError> {
    read_utf8(buf, pos, buf.len())
}

fn read_bin(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, MqttError> {
    read_binary(buf, pos, buf.len())
}

fn read_props(buf: &[u8], pos: &mut usize, version: ProtocolVersion) -> Result<Properties, MqttError> {
    if !version.is_v5() {
        return Ok(Properties::new());
    }
    match Properties::decode(&buf[*pos..])? {
        Some((props, consumed)) => {
            *pos += consumed;
            Ok(props)
        }
        None => Err(MqttError::Malformed("truncated properties")),
    }
}

/// Decode a CONNECT packet body (also determines the connection's protocol
/// version from the Protocol Level field).
pub fn decode_connect(buf: &[u8]) -> Result<ConnectPacket, MqttError> {
    let mut pos = 0;
    let _protocol_name = read_str(buf, &mut pos)?;
    need(buf, pos, 1)?;
    let level = buf[pos];
    pos += 1;
    let version = ProtocolVersion::from_level(level)
        .ok_or(MqttError::UnsupportedProtocolVersion(level))?;

    need(buf, pos, 1)?;
    let flags = buf[pos];
    pos += 1;
    let has_username = flags & 0x80 != 0;
    let has_password = flags & 0x40 != 0;
    let will_retain = flags & 0x20 != 0;
    let will_qos = (flags >> 3) & 0x03;
    let will_flag = flags & 0x04 != 0;
    let clean_session = flags & 0x02 != 0;

    let keep_alive = read_u16(buf, &mut pos)?;
    let properties = read_props(buf, &mut pos, version)?;
    let client_id = read_str(buf, &mut pos)?;

    let will = if will_flag {
        let will_properties = read_props(buf, &mut pos, version)?;
        let topic = read_str(buf, &mut pos)?;
        let payload = read_bin(buf, &mut pos)?;
        Some(Will {
            qos: QoS::from_value(will_qos).ok_or(MqttError::Malformed("invalid will QoS"))?,
            retain: will_retain,
            topic,
            payload,
            properties: will_properties,
        })
    } else {
        None
    };

    let username = if has_username { Some(read_str(buf, &mut pos)?) } else { None };
    let password = if has_password { Some(read_bin(buf, &mut pos)?) } else { None };

    Ok(ConnectPacket {
        version,
        clean_session,
        keep_alive,
        properties,
        client_id,
        will,
        username,
        password,
    })
}

/// Decode a CONNACK body: `(session_present, reason_code, properties)`.
pub fn decode_connack(buf: &[u8], version: ProtocolVersion) -> Result<(bool, u8, Properties), MqttError> {
    let mut pos = 0;
    need(buf, pos, 2)?;
    let session_present = buf[0] & 0x01 != 0;
    let reason_code = buf[1];
    pos += 2;
    let props = if version.is_v5() && pos < buf.len() {
        read_props(buf, &mut pos, version)?
    } else {
        Properties::new()
    };
    Ok((session_present, reason_code, props))
}

/// Decode a PUBACK / PUBREC / PUBREL / PUBCOMP body: `(packet_id, reason_code, properties)`.
///
/// All four share this shape (MQTT 5.0 §3.4-3.7). A v3.1.1 packet is always
/// just the 2-byte packet id; the spec also allows a v5 sender to shorten
/// to the same 2 bytes when the reason code is Success and there are no
/// properties, so this accepts that short form on decode even though
/// [`super::encode`] never produces it (it always writes the reason code).
pub fn decode_simple_ack(buf: &[u8], version: ProtocolVersion) -> Result<(u16, u8, Properties), MqttError> {
    let mut pos = 0;
    let packet_id = read_u16(buf, &mut pos)?;
    if !version.is_v5() || pos >= buf.len() {
        return Ok((packet_id, 0, Properties::new()));
    }
    need(buf, pos, 1)?;
    let reason_code = buf[pos];
    pos += 1;
    let props = if pos < buf.len() {
        read_props(buf, &mut pos, version)?
    } else {
        Properties::new()
    };
    Ok((packet_id, reason_code, props))
}

/// Decode a SUBSCRIBE body: `(packet_id, properties, filters)`.
pub fn decode_subscribe(
    buf: &[u8],
    version: ProtocolVersion,
) -> Result<(u16, Properties, Vec<SubscribeFilter>), MqttError> {
    let mut pos = 0;
    let packet_id = read_u16(buf, &mut pos)?;
    let props = read_props(buf, &mut pos, version)?;
    let mut filters = Vec::new();
    while pos < buf.len() {
        let topic_filter = read_str(buf, &mut pos)?;
        need(buf, pos, 1)?;
        let options = buf[pos];
        pos += 1;
        let filter = if version.is_v5() {
            SubscribeFilter::options_from_byte(topic_filter, options)
                .ok_or(MqttError::Malformed("invalid subscription options"))?
        } else {
            SubscribeFilter {
                topic_filter,
                max_qos: QoS::from_value(options & 0x03)
                    .ok_or(MqttError::Malformed("invalid subscribe QoS"))?,
                no_local: false,
                retain_as_published: false,
                retain_handling: 0,
            }
        };
        filters.push(filter);
    }
    if filters.is_empty() {
        return Err(MqttError::Malformed("SUBSCRIBE with no topic filters"));
    }
    Ok((packet_id, props, filters))
}

/// Decode a SUBACK body: `(packet_id, properties, reason_codes)`.
pub fn decode_suback(buf: &[u8], version: ProtocolVersion) -> Result<(u16, Properties, Vec<u8>), MqttError> {
    let mut pos = 0;
    let packet_id = read_u16(buf, &mut pos)?;
    let props = read_props(buf, &mut pos, version)?;
    Ok((packet_id, props, buf[pos..].to_vec()))
}

/// Decode an UNSUBSCRIBE body: `(packet_id, properties, topic_filters)`.
pub fn decode_unsubscribe(
    buf: &[u8],
    version: ProtocolVersion,
) -> Result<(u16, Properties, Vec<String>), MqttError> {
    let mut pos = 0;
    let packet_id = read_u16(buf, &mut pos)?;
    let props = read_props(buf, &mut pos, version)?;
    let mut filters = Vec::new();
    while pos < buf.len() {
        filters.push(read_str(buf, &mut pos)?);
    }
    if filters.is_empty() {
        return Err(MqttError::Malformed("UNSUBSCRIBE with no topic filters"));
    }
    Ok((packet_id, props, filters))
}

/// Decode an UNSUBACK body: `(packet_id, properties, reason_codes)` — v3.1.1
/// has no per-filter reason codes, so the vec is empty for that version.
pub fn decode_unsuback(buf: &[u8], version: ProtocolVersion) -> Result<(u16, Properties, Vec<u8>), MqttError> {
    let mut pos = 0;
    let packet_id = read_u16(buf, &mut pos)?;
    if !version.is_v5() || pos >= buf.len() {
        return Ok((packet_id, Properties::new(), Vec::new()));
    }
    let props = read_props(buf, &mut pos, version)?;
    Ok((packet_id, props, buf[pos..].to_vec()))
}

/// Decode a DISCONNECT body: `(reason_code, properties)`.
pub fn decode_disconnect(buf: &[u8], version: ProtocolVersion) -> Result<(u8, Properties), MqttError> {
    if !version.is_v5() || buf.is_empty() {
        return Ok((0, Properties::new()));
    }
    let mut pos = 1;
    let props = if pos < buf.len() {
        read_props(buf, &mut pos, version)?
    } else {
        Properties::new()
    };
    Ok((buf[0], props))
}

/// Decode an AUTH body: `(reason_code, properties)` (MQTT 5.0 only).
pub fn decode_auth(buf: &[u8]) -> Result<(u8, Properties), MqttError> {
    if buf.is_empty() {
        return Ok((0, Properties::new()));
    }
    let mut pos = 1;
    let props = if pos < buf.len() {
        read_props(buf, &mut pos, ProtocolVersion::V5)?
    } else {
        Properties::new()
    };
    Ok((buf[0], props))
}

/// Try to decode a PUBLISH variable header (topic, packet id, properties)
/// from the front of `buf`.
///
/// `buf` holds whatever PUBLISH body bytes have arrived so far (it may
/// contain payload bytes past the header too, or nothing beyond a partial
/// topic name). Returns `Ok(None)` if `buf` doesn't yet contain the whole
/// variable header; `payload_len` in the returned [`PublishHeader`] is
/// computed from `remaining_length`, not from what's currently buffered.
pub fn decode_publish_var_header(
    buf: &[u8],
    flags: u8,
    remaining_length: u32,
    version: ProtocolVersion,
) -> Result<Option<(PublishHeader, usize)>, MqttError> {
    let mut pos = 0;
    if buf.len() < 2 {
        return Ok(None);
    }
    let topic_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + topic_len {
        return Ok(None);
    }
    pos += 2;
    let topic = String::from_utf8(buf[pos..pos + topic_len].to_vec())
        .map_err(|_| MqttError::Malformed("invalid UTF-8 topic name"))?;
    pos += topic_len;

    let qos = QoS::from_value((flags >> 1) & 0x03).ok_or(MqttError::Malformed("invalid PUBLISH QoS"))?;
    let packet_id = if qos != QoS::AtMostOnce {
        if buf.len() < pos + 2 {
            return Ok(None);
        }
        let id = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        pos += 2;
        id
    } else {
        0
    };

    let properties = if version.is_v5() {
        match Properties::decode(&buf[pos..])? {
            Some((props, consumed)) => {
                pos += consumed;
                props
            }
            None => return Ok(None),
        }
    } else {
        Properties::new()
    };

    let header_len = pos as u32;
    if header_len > remaining_length {
        return Err(MqttError::Malformed("PUBLISH header longer than remaining length"));
    }
    let payload_len = remaining_length - header_len;

    Ok(Some((
        PublishHeader {
            dup: flags & 0x08 != 0,
            qos,
            retain: flags & 0x01 != 0,
            topic,
            packet_id,
            properties,
            payload_len,
        },
        pos,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode;

    #[test]
    fn connect_round_trip_v311_minimal() {
        let packet = ConnectPacket {
            version: ProtocolVersion::V311,
            clean_session: true,
            keep_alive: 60,
            properties: Properties::new(),
            client_id: "client-1".into(),
            will: None,
            username: None,
            password: None,
        };
        let wire = encode::encode_connect(&packet);
        // Strip fixed header (1 byte type/flags) + remaining-length varint (1 byte here).
        let body = &wire[2..];
        let decoded = decode_connect(body).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn connect_round_trip_with_will_and_credentials() {
        let mut props = Properties::new();
        props.set_u32(crate::codec::properties::property::SESSION_EXPIRY_INTERVAL, 30);
        let packet = ConnectPacket {
            version: ProtocolVersion::V5,
            clean_session: false,
            keep_alive: 30,
            properties: props,
            client_id: "will-client".into(),
            will: Some(Will {
                qos: QoS::AtLeastOnce,
                retain: true,
                topic: "clients/will-client/status".into(),
                payload: b"offline".to_vec(),
                properties: Properties::new(),
            }),
            username: Some("alice".into()),
            password: Some(b"s3cret".to_vec()),
        };
        let wire = encode::encode_connect(&packet);
        let body = &wire[2..];
        let decoded = decode_connect(body).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn publish_var_header_needs_more_data_when_topic_incomplete() {
        // topic_len says 5 but only 2 bytes of topic are present.
        let buf = [0x00, 0x05, b'a', b'b'];
        let r = decode_publish_var_header(&buf, 0, 100, ProtocolVersion::V311).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn publish_var_header_qos1_needs_packet_id() {
        let mut buf = vec![0x00, 0x01, b't']; // topic "t"
        let flags = 0x02; // QoS 1
        assert!(decode_publish_var_header(&buf, flags, 10, ProtocolVersion::V311)
            .unwrap()
            .is_none());
        buf.extend_from_slice(&42u16.to_be_bytes());
        let (hdr, consumed) =
            decode_publish_var_header(&buf, flags, 10, ProtocolVersion::V311).unwrap().unwrap();
        assert_eq!(hdr.topic, "t");
        assert_eq!(hdr.packet_id, 42);
        assert_eq!(hdr.qos, QoS::AtLeastOnce);
        assert_eq!(consumed, buf.len());
        assert_eq!(hdr.payload_len, 10 - consumed as u32);
    }
}
