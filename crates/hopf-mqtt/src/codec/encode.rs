// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Encoders producing complete MQTT wire packets.
//!
//! Every `encode_*` function returns a `Vec<u8>` containing one full packet
//! (fixed header, remaining-length varint, variable header, and — except
//! for [`encode_publish_header`] — payload).

use super::packet::{ConnectPacket, PacketType, ProtocolVersion, QoS, SubscribeFilter};
use super::properties::Properties;
use super::varint;

fn write_utf8(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn write_binary(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

fn write_fixed_header(out: &mut Vec<u8>, ty: PacketType, flags: u8, remaining_length: u32) {
    out.push((ty.value() << 4) | flags);
    varint::encode(out, remaining_length);
}

fn props_len_with_varint(props: &Properties) -> usize {
    let len = props.encoded_len();
    varint::encoded_len(len as u32) + len
}

/// Encode a CONNECT packet.
pub fn encode_connect(packet: &ConnectPacket) -> Vec<u8> {
    let v5 = packet.version.is_v5();

    let mut var_header = Vec::new();
    write_utf8(&mut var_header, packet.version.protocol_name());
    var_header.push(packet.version.level());

    let mut connect_flags = 0u8;
    if packet.clean_session {
        connect_flags |= 0x02;
    }
    if let Some(will) = &packet.will {
        connect_flags |= 0x04;
        connect_flags |= will.qos.value() << 3;
        if will.retain {
            connect_flags |= 0x20;
        }
    }
    if packet.password.is_some() {
        connect_flags |= 0x40;
    }
    if packet.username.is_some() {
        connect_flags |= 0x80;
    }
    var_header.push(connect_flags);
    var_header.extend_from_slice(&packet.keep_alive.to_be_bytes());
    if v5 {
        packet.properties.encode(&mut var_header);
    }

    let mut payload = Vec::new();
    write_utf8(&mut payload, &packet.client_id);
    if let Some(will) = &packet.will {
        if v5 {
            will.properties.encode(&mut payload);
        }
        write_utf8(&mut payload, &will.topic);
        write_binary(&mut payload, &will.payload);
    }
    if let Some(u) = &packet.username {
        write_utf8(&mut payload, u);
    }
    if let Some(p) = &packet.password {
        write_binary(&mut payload, p);
    }

    let remaining_length = (var_header.len() + payload.len()) as u32;
    let mut out = Vec::with_capacity(5 + remaining_length as usize);
    write_fixed_header(&mut out, PacketType::Connect, 0, remaining_length);
    out.extend_from_slice(&var_header);
    out.extend_from_slice(&payload);
    out
}

/// Encode a CONNACK packet.
pub fn encode_connack(session_present: bool, reason_code: u8, props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    let v5 = version.is_v5();
    let remaining_length = 2 + if v5 { props_len_with_varint(props) } else { 0 };
    let mut out = Vec::with_capacity(2 + remaining_length);
    write_fixed_header(&mut out, PacketType::Connack, 0, remaining_length as u32);
    out.push(if session_present { 0x01 } else { 0x00 });
    out.push(reason_code);
    if v5 {
        props.encode(&mut out);
    }
    out
}

/// Encode a complete PUBLISH packet (variable header + payload in one buffer).
///
/// For streaming large payloads without materialising them alongside the
/// header, encode the header alone with [`encode_publish_header`] and send
/// the payload separately.
pub fn encode_publish(
    topic: &str,
    qos: QoS,
    dup: bool,
    retain: bool,
    packet_id: u16,
    payload: &[u8],
    props: &Properties,
    version: ProtocolVersion,
) -> Vec<u8> {
    let mut out = encode_publish_header(topic, qos, dup, retain, packet_id, payload.len() as u64, props, version);
    out.extend_from_slice(payload);
    out
}

/// Encode just the PUBLISH fixed header and variable header (topic,
/// optional packet id, properties) for `payload_size` bytes of payload
/// that will be sent separately (e.g. via chunked `Endpoint::send` calls).
///
/// The Remaining Length written into the fixed header includes
/// `payload_size`, so the receiver can determine the frame boundary from
/// this header alone.
pub fn encode_publish_header(
    topic: &str,
    qos: QoS,
    dup: bool,
    retain: bool,
    packet_id: u16,
    payload_size: u64,
    props: &Properties,
    version: ProtocolVersion,
) -> Vec<u8> {
    let v5 = version.is_v5();
    let mut var_header = Vec::new();
    write_utf8(&mut var_header, topic);
    if qos != QoS::AtMostOnce {
        var_header.extend_from_slice(&packet_id.to_be_bytes());
    }
    if v5 {
        props.encode(&mut var_header);
    }

    let mut flags = qos.value() << 1;
    if dup {
        flags |= 0x08;
    }
    if retain {
        flags |= 0x01;
    }

    let remaining_length = var_header.len() as u64 + payload_size;
    let mut out = Vec::with_capacity(5 + var_header.len());
    write_fixed_header(&mut out, PacketType::Publish, flags, remaining_length as u32);
    out.extend_from_slice(&var_header);
    out
}

fn encode_simple_ack(ty: PacketType, fixed_flags: u8, packet_id: u16, reason_code: u8, props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    if !version.is_v5() {
        let mut out = Vec::with_capacity(4);
        write_fixed_header(&mut out, ty, fixed_flags, 2);
        out.extend_from_slice(&packet_id.to_be_bytes());
        return out;
    }
    let p_len = props.encoded_len();
    let remaining_length = if p_len > 0 { 3 + props_len_with_varint(props) } else { 3 };
    let mut out = Vec::with_capacity(2 + remaining_length);
    write_fixed_header(&mut out, ty, fixed_flags, remaining_length as u32);
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(reason_code);
    if p_len > 0 {
        props.encode(&mut out);
    }
    out
}

/// Encode a PUBACK packet.
pub fn encode_puback(packet_id: u16, reason_code: u8, props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    encode_simple_ack(PacketType::Puback, 0, packet_id, reason_code, props, version)
}

/// Encode a PUBREC packet.
pub fn encode_pubrec(packet_id: u16, reason_code: u8, props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    encode_simple_ack(PacketType::Pubrec, 0, packet_id, reason_code, props, version)
}

/// Encode a PUBREL packet (fixed flags `0010` per spec).
pub fn encode_pubrel(packet_id: u16, reason_code: u8, props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    encode_simple_ack(PacketType::Pubrel, 0x02, packet_id, reason_code, props, version)
}

/// Encode a PUBCOMP packet.
pub fn encode_pubcomp(packet_id: u16, reason_code: u8, props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    encode_simple_ack(PacketType::Pubcomp, 0, packet_id, reason_code, props, version)
}

/// Encode a SUBSCRIBE packet.
pub fn encode_subscribe(packet_id: u16, filters: &[SubscribeFilter], props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    let v5 = version.is_v5();
    let mut body = Vec::new();
    body.extend_from_slice(&packet_id.to_be_bytes());
    if v5 {
        props.encode(&mut body);
    }
    for f in filters {
        write_utf8(&mut body, &f.topic_filter);
        body.push(f.options_byte());
    }
    let mut out = Vec::with_capacity(5 + body.len());
    write_fixed_header(&mut out, PacketType::Subscribe, 0x02, body.len() as u32);
    out.extend_from_slice(&body);
    out
}

/// Encode a SUBACK packet.
pub fn encode_suback(packet_id: u16, reason_codes: &[u8], props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    let v5 = version.is_v5();
    let mut body = Vec::new();
    body.extend_from_slice(&packet_id.to_be_bytes());
    if v5 {
        props.encode(&mut body);
    }
    body.extend_from_slice(reason_codes);
    let mut out = Vec::with_capacity(5 + body.len());
    write_fixed_header(&mut out, PacketType::Suback, 0, body.len() as u32);
    out.extend_from_slice(&body);
    out
}

/// Encode an UNSUBSCRIBE packet.
pub fn encode_unsubscribe(packet_id: u16, topic_filters: &[String], props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    let v5 = version.is_v5();
    let mut body = Vec::new();
    body.extend_from_slice(&packet_id.to_be_bytes());
    if v5 {
        props.encode(&mut body);
    }
    for f in topic_filters {
        write_utf8(&mut body, f);
    }
    let mut out = Vec::with_capacity(5 + body.len());
    write_fixed_header(&mut out, PacketType::Unsubscribe, 0x02, body.len() as u32);
    out.extend_from_slice(&body);
    out
}

/// Encode an UNSUBACK packet (v3.1.1 has no reason codes / properties).
pub fn encode_unsuback(packet_id: u16, reason_codes: &[u8], props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    let v5 = version.is_v5();
    let mut body = Vec::new();
    body.extend_from_slice(&packet_id.to_be_bytes());
    if v5 {
        props.encode(&mut body);
        body.extend_from_slice(reason_codes);
    }
    let mut out = Vec::with_capacity(5 + body.len());
    write_fixed_header(&mut out, PacketType::Unsuback, 0, body.len() as u32);
    out.extend_from_slice(&body);
    out
}

/// Encode a PINGREQ packet.
pub fn encode_pingreq() -> Vec<u8> {
    vec![PacketType::Pingreq.value() << 4, 0]
}

/// Encode a PINGRESP packet.
pub fn encode_pingresp() -> Vec<u8> {
    vec![PacketType::Pingresp.value() << 4, 0]
}

/// Encode a DISCONNECT packet (v3.1.1 is always the fixed 2-byte form).
pub fn encode_disconnect(reason_code: u8, props: &Properties, version: ProtocolVersion) -> Vec<u8> {
    if !version.is_v5() {
        return vec![PacketType::Disconnect.value() << 4, 0];
    }
    let remaining_length = 1 + props_len_with_varint(props);
    let mut out = Vec::with_capacity(2 + remaining_length);
    write_fixed_header(&mut out, PacketType::Disconnect, 0, remaining_length as u32);
    out.push(reason_code);
    props.encode(&mut out);
    out
}

/// Encode an AUTH packet (MQTT 5.0 only).
pub fn encode_auth(reason_code: u8, props: &Properties) -> Vec<u8> {
    let remaining_length = 1 + props_len_with_varint(props);
    let mut out = Vec::with_capacity(2 + remaining_length);
    write_fixed_header(&mut out, PacketType::Auth, 0, remaining_length as u32);
    out.push(reason_code);
    props.encode(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::decode;

    #[test]
    fn pingreq_pingresp_are_two_bytes() {
        assert_eq!(encode_pingreq(), vec![0xC0, 0x00]);
        assert_eq!(encode_pingresp(), vec![0xD0, 0x00]);
    }

    #[test]
    fn puback_v311_is_four_bytes_no_reason_code() {
        let wire = encode_puback(7, 0, &Properties::new(), ProtocolVersion::V311);
        assert_eq!(wire, vec![0x40, 0x02, 0x00, 0x07]);
    }

    #[test]
    fn puback_v5_always_includes_reason_code() {
        // The spec allows omitting the reason code + properties when reason
        // is Success and there are no properties, but this encoder always
        // writes it (matching the reference Gumdrop implementation) — the
        // short form is only something `decode_simple_ack` needs to accept
        // from *other* implementations, not something we produce.
        let wire = encode_puback(7, 0, &Properties::new(), ProtocolVersion::V5);
        assert_eq!(wire, vec![0x40, 0x03, 0x00, 0x07, 0x00]);
    }

    #[test]
    fn puback_v5_with_reason_code_includes_it() {
        let wire = encode_puback(7, 0x87, &Properties::new(), ProtocolVersion::V5);
        assert_eq!(wire, vec![0x40, 0x03, 0x00, 0x07, 0x87]);
    }

    #[test]
    fn publish_round_trip_via_header_plus_payload() {
        let mut props = Properties::new();
        props.set_byte(crate::codec::properties::property::PAYLOAD_FORMAT_INDICATOR, 1);
        let payload = b"hello world";
        let header = encode_publish_header(
            "sensors/temp",
            QoS::AtLeastOnce,
            false,
            true,
            99,
            payload.len() as u64,
            &props,
            ProtocolVersion::V5,
        );
        let mut full = header.clone();
        full.extend_from_slice(payload);

        let one_shot = encode_publish("sensors/temp", QoS::AtLeastOnce, false, true, 99, payload, &props, ProtocolVersion::V5);
        assert_eq!(full, one_shot);

        // Decode: skip fixed header (type+flags byte + varint), then var-header.
        let remaining_len_byte_count = match crate::codec::varint::decode(&one_shot[1..]) {
            crate::codec::varint::VarIntResult::Ok { len, .. } => len,
            _ => panic!("bad varint"),
        };
        let body = &one_shot[1 + remaining_len_byte_count..];
        let flags = one_shot[0] & 0x0F;
        let remaining_length = (body.len()) as u32;
        let (hdr, consumed) =
            decode::decode_publish_var_header(body, flags, remaining_length, ProtocolVersion::V5)
                .unwrap()
                .unwrap();
        assert_eq!(hdr.topic, "sensors/temp");
        assert_eq!(hdr.packet_id, 99);
        assert_eq!(hdr.qos, QoS::AtLeastOnce);
        assert!(hdr.retain);
        assert_eq!(hdr.payload_len, payload.len() as u32);
        assert_eq!(&body[consumed..], payload);
    }

    #[test]
    fn subscribe_suback_round_trip_v5_options() {
        let filters = vec![SubscribeFilter {
            topic_filter: "a/#".into(),
            max_qos: QoS::ExactlyOnce,
            no_local: true,
            retain_as_published: false,
            retain_handling: 1,
        }];
        let wire = encode_subscribe(5, &filters, &Properties::new(), ProtocolVersion::V5);
        let remaining_len_byte_count = match crate::codec::varint::decode(&wire[1..]) {
            crate::codec::varint::VarIntResult::Ok { len, .. } => len,
            _ => panic!("bad varint"),
        };
        let body = &wire[1 + remaining_len_byte_count..];
        let (packet_id, _props, decoded_filters) = decode::decode_subscribe(body, ProtocolVersion::V5).unwrap();
        assert_eq!(packet_id, 5);
        assert_eq!(decoded_filters, filters);
    }
}
