// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Encode / decode method argument payloads for the SPI subset.

use super::table::{
    decode_longstr, decode_shortstr, decode_table, encode_longstr, encode_shortstr, encode_table,
    FieldTable,
};
use super::AmqpError;

fn read_u8(data: &mut &[u8]) -> Result<u8, AmqpError> {
    if data.is_empty() {
        return Err(AmqpError::Malformed("truncated octet"));
    }
    let v = data[0];
    *data = &data[1..];
    Ok(v)
}

fn read_u16(data: &mut &[u8]) -> Result<u16, AmqpError> {
    if data.len() < 2 {
        return Err(AmqpError::Malformed("truncated short"));
    }
    let v = u16::from_be_bytes([data[0], data[1]]);
    *data = &data[2..];
    Ok(v)
}

fn read_u32(data: &mut &[u8]) -> Result<u32, AmqpError> {
    if data.len() < 4 {
        return Err(AmqpError::Malformed("truncated long"));
    }
    let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    *data = &data[4..];
    Ok(v)
}

fn read_u64(data: &mut &[u8]) -> Result<u64, AmqpError> {
    if data.len() < 8 {
        return Err(AmqpError::Malformed("truncated longlong"));
    }
    let v = u64::from_be_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    *data = &data[8..];
    Ok(v)
}

fn read_bits(data: &mut &[u8]) -> Result<u8, AmqpError> {
    read_u8(data)
}

/// Decoded method frame.
#[derive(Debug, Clone)]
pub struct MethodFrame {
    /// Channel id.
    pub channel: u16,
    /// Class id.
    pub class_id: u16,
    /// Method id.
    pub method_id: u16,
    /// Raw argument bytes (after class/method ids).
    pub args: Vec<u8>,
}

/// `connection.start` arguments.
#[derive(Debug, Clone)]
pub struct ConnectionStart {
    /// Major version.
    pub version_major: u8,
    /// Minor version.
    pub version_minor: u8,
    /// Server properties.
    pub server_properties: FieldTable,
    /// Space-separated mechanism names.
    pub mechanisms: String,
    /// Space-separated locale names.
    pub locales: String,
}

impl ConnectionStart {
    /// Decode arguments.
    pub fn decode(mut data: &[u8]) -> Result<Self, AmqpError> {
        let version_major = read_u8(&mut data)?;
        let version_minor = read_u8(&mut data)?;
        let server_properties = decode_table(&mut data)?;
        let mechanisms = String::from_utf8_lossy(decode_longstr(&mut data)?).into_owned();
        let locales = String::from_utf8_lossy(decode_longstr(&mut data)?).into_owned();
        Ok(Self {
            version_major,
            version_minor,
            server_properties,
            mechanisms,
            locales,
        })
    }
}

/// Encode `connection.start-ok`.
pub fn encode_connection_start_ok(
    client_properties: &FieldTable,
    mechanism: &str,
    response: &[u8],
    locale: &str,
) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    encode_table(&mut args, client_properties)?;
    encode_shortstr(&mut args, mechanism)?;
    encode_longstr(&mut args, response);
    encode_shortstr(&mut args, locale)?;
    Ok(args)
}

/// Decode `connection.secure`'s single `challenge` longstr.
pub fn decode_connection_secure(mut data: &[u8]) -> Result<Vec<u8>, AmqpError> {
    Ok(decode_longstr(&mut data)?.to_vec())
}

/// Encode `connection.secure-ok`'s single `response` longstr.
pub fn encode_connection_secure_ok(response: &[u8]) -> Vec<u8> {
    let mut args = Vec::new();
    encode_longstr(&mut args, response);
    args
}

/// `connection.tune` arguments.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionTune {
    /// Channel max.
    pub channel_max: u16,
    /// Frame max.
    pub frame_max: u32,
    /// Heartbeat seconds.
    pub heartbeat: u16,
}

impl ConnectionTune {
    /// Decode.
    pub fn decode(mut data: &[u8]) -> Result<Self, AmqpError> {
        Ok(Self {
            channel_max: read_u16(&mut data)?,
            frame_max: read_u32(&mut data)?,
            heartbeat: read_u16(&mut data)?,
        })
    }

    /// Encode tune-ok (same layout).
    pub fn encode(self) -> Vec<u8> {
        let mut args = Vec::with_capacity(8);
        args.extend_from_slice(&self.channel_max.to_be_bytes());
        args.extend_from_slice(&self.frame_max.to_be_bytes());
        args.extend_from_slice(&self.heartbeat.to_be_bytes());
        args
    }
}

/// Encode `connection.open`.
pub fn encode_connection_open(virtual_host: &str) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    encode_shortstr(&mut args, virtual_host)?;
    encode_shortstr(&mut args, "")?; // capabilities (deprecated)
    args.push(0); // insist
    Ok(args)
}

/// Close method (connection or channel).
#[derive(Debug, Clone)]
pub struct CloseArgs {
    /// Reply code.
    pub reply_code: u16,
    /// Reply text.
    pub reply_text: String,
    /// Failing class id (0 if none).
    pub class_id: u16,
    /// Failing method id (0 if none).
    pub method_id: u16,
}

impl CloseArgs {
    /// Decode.
    pub fn decode(mut data: &[u8]) -> Result<Self, AmqpError> {
        Ok(Self {
            reply_code: read_u16(&mut data)?,
            reply_text: decode_shortstr(&mut data)?.to_owned(),
            class_id: read_u16(&mut data)?,
            method_id: read_u16(&mut data)?,
        })
    }

    /// Encode.
    pub fn encode(&self) -> Result<Vec<u8>, AmqpError> {
        let mut args = Vec::new();
        args.extend_from_slice(&self.reply_code.to_be_bytes());
        encode_shortstr(&mut args, &self.reply_text)?;
        args.extend_from_slice(&self.class_id.to_be_bytes());
        args.extend_from_slice(&self.method_id.to_be_bytes());
        Ok(args)
    }
}

/// Encode `channel.open` (out-of-band reserved shortstr, empty).
pub fn encode_channel_open() -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    encode_shortstr(&mut args, "")?;
    Ok(args)
}

/// Encode exchange.declare.
#[allow(clippy::too_many_arguments)]
pub fn encode_exchange_declare(
    exchange: &str,
    exchange_type: &str,
    passive: bool,
    durable: bool,
    auto_delete: bool,
    internal: bool,
    no_wait: bool,
    arguments: &FieldTable,
) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes()); // reserved
    encode_shortstr(&mut args, exchange)?;
    encode_shortstr(&mut args, exchange_type)?;
    let mut bits = 0u8;
    if passive {
        bits |= 1 << 0;
    }
    if durable {
        bits |= 1 << 1;
    }
    if auto_delete {
        bits |= 1 << 2;
    }
    if internal {
        bits |= 1 << 3;
    }
    if no_wait {
        bits |= 1 << 4;
    }
    args.push(bits);
    encode_table(&mut args, arguments)?;
    Ok(args)
}

/// Encode exchange.delete.
pub fn encode_exchange_delete(
    exchange: &str,
    if_unused: bool,
    no_wait: bool,
) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    encode_shortstr(&mut args, exchange)?;
    let mut bits = 0u8;
    if if_unused {
        bits |= 1 << 0;
    }
    if no_wait {
        bits |= 1 << 1;
    }
    args.push(bits);
    Ok(args)
}

/// Encode queue.declare.
#[allow(clippy::too_many_arguments)]
pub fn encode_queue_declare(
    queue: &str,
    passive: bool,
    durable: bool,
    exclusive: bool,
    auto_delete: bool,
    no_wait: bool,
    arguments: &FieldTable,
) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    encode_shortstr(&mut args, queue)?;
    let mut bits = 0u8;
    if passive {
        bits |= 1 << 0;
    }
    if durable {
        bits |= 1 << 1;
    }
    if exclusive {
        bits |= 1 << 2;
    }
    if auto_delete {
        bits |= 1 << 3;
    }
    if no_wait {
        bits |= 1 << 4;
    }
    args.push(bits);
    encode_table(&mut args, arguments)?;
    Ok(args)
}

/// `queue.declare-ok` arguments.
#[derive(Debug, Clone)]
pub struct QueueDeclareOk {
    /// Queue name (server-generated if empty was declared).
    pub queue: String,
    /// Message count.
    pub message_count: u32,
    /// Consumer count.
    pub consumer_count: u32,
}

impl QueueDeclareOk {
    /// Decode.
    pub fn decode(mut data: &[u8]) -> Result<Self, AmqpError> {
        Ok(Self {
            queue: decode_shortstr(&mut data)?.to_owned(),
            message_count: read_u32(&mut data)?,
            consumer_count: read_u32(&mut data)?,
        })
    }
}

/// Encode queue.bind.
pub fn encode_queue_bind(
    queue: &str,
    exchange: &str,
    routing_key: &str,
    no_wait: bool,
    arguments: &FieldTable,
) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    encode_shortstr(&mut args, queue)?;
    encode_shortstr(&mut args, exchange)?;
    encode_shortstr(&mut args, routing_key)?;
    args.push(if no_wait { 1 } else { 0 });
    encode_table(&mut args, arguments)?;
    Ok(args)
}

/// Encode queue.unbind.
pub fn encode_queue_unbind(
    queue: &str,
    exchange: &str,
    routing_key: &str,
    arguments: &FieldTable,
) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    encode_shortstr(&mut args, queue)?;
    encode_shortstr(&mut args, exchange)?;
    encode_shortstr(&mut args, routing_key)?;
    encode_table(&mut args, arguments)?;
    Ok(args)
}

/// Encode queue.purge.
pub fn encode_queue_purge(queue: &str, no_wait: bool) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    encode_shortstr(&mut args, queue)?;
    args.push(if no_wait { 1 } else { 0 });
    Ok(args)
}

/// Encode queue.delete.
pub fn encode_queue_delete(
    queue: &str,
    if_unused: bool,
    if_empty: bool,
    no_wait: bool,
) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    encode_shortstr(&mut args, queue)?;
    let mut bits = 0u8;
    if if_unused {
        bits |= 1 << 0;
    }
    if if_empty {
        bits |= 1 << 1;
    }
    if no_wait {
        bits |= 1 << 2;
    }
    args.push(bits);
    Ok(args)
}

/// Encode basic.qos.
pub fn encode_basic_qos(prefetch_size: u32, prefetch_count: u16, global: bool) -> Vec<u8> {
    let mut args = Vec::with_capacity(7);
    args.extend_from_slice(&prefetch_size.to_be_bytes());
    args.extend_from_slice(&prefetch_count.to_be_bytes());
    args.push(if global { 1 } else { 0 });
    args
}

/// Encode basic.consume.
#[allow(clippy::too_many_arguments)]
pub fn encode_basic_consume(
    queue: &str,
    consumer_tag: &str,
    no_local: bool,
    no_ack: bool,
    exclusive: bool,
    no_wait: bool,
    arguments: &FieldTable,
) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    encode_shortstr(&mut args, queue)?;
    encode_shortstr(&mut args, consumer_tag)?;
    let mut bits = 0u8;
    if no_local {
        bits |= 1 << 0;
    }
    if no_ack {
        bits |= 1 << 1;
    }
    if exclusive {
        bits |= 1 << 2;
    }
    if no_wait {
        bits |= 1 << 3;
    }
    args.push(bits);
    encode_table(&mut args, arguments)?;
    Ok(args)
}

/// `basic.consume-ok` / `basic.cancel-ok` consumer tag.
pub fn decode_consumer_tag(mut data: &[u8]) -> Result<String, AmqpError> {
    Ok(decode_shortstr(&mut data)?.to_owned())
}

/// Encode basic.cancel.
pub fn encode_basic_cancel(consumer_tag: &str, no_wait: bool) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    encode_shortstr(&mut args, consumer_tag)?;
    args.push(if no_wait { 1 } else { 0 });
    Ok(args)
}

/// Encode basic.publish.
pub fn encode_basic_publish(
    exchange: &str,
    routing_key: &str,
    mandatory: bool,
    immediate: bool,
) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    encode_shortstr(&mut args, exchange)?;
    encode_shortstr(&mut args, routing_key)?;
    let mut bits = 0u8;
    if mandatory {
        bits |= 1 << 0;
    }
    if immediate {
        bits |= 1 << 1;
    }
    args.push(bits);
    Ok(args)
}

/// `basic.deliver` arguments (before content).
#[derive(Debug, Clone)]
pub struct BasicDeliver {
    /// Consumer tag.
    pub consumer_tag: String,
    /// Delivery tag.
    pub delivery_tag: u64,
    /// Redelivered flag.
    pub redelivered: bool,
    /// Exchange.
    pub exchange: String,
    /// Routing key.
    pub routing_key: String,
}

impl BasicDeliver {
    /// Decode.
    pub fn decode(mut data: &[u8]) -> Result<Self, AmqpError> {
        let consumer_tag = decode_shortstr(&mut data)?.to_owned();
        let delivery_tag = read_u64(&mut data)?;
        let redelivered = read_bits(&mut data)? & 1 != 0;
        let exchange = decode_shortstr(&mut data)?.to_owned();
        let routing_key = decode_shortstr(&mut data)?.to_owned();
        Ok(Self {
            consumer_tag,
            delivery_tag,
            redelivered,
            exchange,
            routing_key,
        })
    }
}

/// `basic.return` arguments (before content).
#[derive(Debug, Clone)]
pub struct BasicReturn {
    /// Reply code.
    pub reply_code: u16,
    /// Reply text.
    pub reply_text: String,
    /// Exchange.
    pub exchange: String,
    /// Routing key.
    pub routing_key: String,
}

impl BasicReturn {
    /// Decode.
    pub fn decode(mut data: &[u8]) -> Result<Self, AmqpError> {
        Ok(Self {
            reply_code: read_u16(&mut data)?,
            reply_text: decode_shortstr(&mut data)?.to_owned(),
            exchange: decode_shortstr(&mut data)?.to_owned(),
            routing_key: decode_shortstr(&mut data)?.to_owned(),
        })
    }
}

/// Encode basic.ack.
pub fn encode_basic_ack(delivery_tag: u64, multiple: bool) -> Vec<u8> {
    let mut args = Vec::with_capacity(9);
    args.extend_from_slice(&delivery_tag.to_be_bytes());
    args.push(if multiple { 1 } else { 0 });
    args
}

/// Decode basic.ack / basic.nack (delivery_tag + bits).
pub fn decode_ack(mut data: &[u8]) -> Result<(u64, bool), AmqpError> {
    let tag = read_u64(&mut data)?;
    let multiple = read_bits(&mut data)? & 1 != 0;
    Ok((tag, multiple))
}

/// Decode basic.nack (delivery_tag + multiple + requeue).
pub fn decode_nack(mut data: &[u8]) -> Result<(u64, bool, bool), AmqpError> {
    let tag = read_u64(&mut data)?;
    let bits = read_bits(&mut data)?;
    Ok((tag, bits & 1 != 0, bits & 2 != 0))
}

/// Encode basic.nack.
pub fn encode_basic_nack(delivery_tag: u64, multiple: bool, requeue: bool) -> Vec<u8> {
    let mut args = Vec::with_capacity(9);
    args.extend_from_slice(&delivery_tag.to_be_bytes());
    let mut bits = 0u8;
    if multiple {
        bits |= 1 << 0;
    }
    if requeue {
        bits |= 1 << 1;
    }
    args.push(bits);
    args
}

/// Encode basic.reject.
pub fn encode_basic_reject(delivery_tag: u64, requeue: bool) -> Vec<u8> {
    let mut args = Vec::with_capacity(9);
    args.extend_from_slice(&delivery_tag.to_be_bytes());
    args.push(if requeue { 1 } else { 0 });
    args
}

/// Encode confirm.select.
pub fn encode_confirm_select(no_wait: bool) -> Vec<u8> {
    vec![if no_wait { 1 } else { 0 }]
}

/// Encode tx.select / tx.commit / tx.rollback (all empty argument lists).
pub fn encode_tx_method() -> Vec<u8> {
    Vec::new()
}

/// Encode basic.get.
pub fn encode_basic_get(queue: &str, no_ack: bool) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    encode_shortstr(&mut args, queue)?;
    args.push(if no_ack { 1 } else { 0 });
    Ok(args)
}

/// `basic.get-ok` arguments (before content).
#[derive(Debug, Clone)]
pub struct BasicGetOk {
    /// Delivery tag.
    pub delivery_tag: u64,
    /// Redelivered flag.
    pub redelivered: bool,
    /// Exchange.
    pub exchange: String,
    /// Routing key.
    pub routing_key: String,
    /// Remaining messages in the queue (not counting this one).
    pub message_count: u32,
}

impl BasicGetOk {
    /// Decode.
    pub fn decode(mut data: &[u8]) -> Result<Self, AmqpError> {
        let delivery_tag = read_u64(&mut data)?;
        let redelivered = read_bits(&mut data)? & 1 != 0;
        let exchange = decode_shortstr(&mut data)?.to_owned();
        let routing_key = decode_shortstr(&mut data)?.to_owned();
        let message_count = read_u32(&mut data)?;
        Ok(Self {
            delivery_tag,
            redelivered,
            exchange,
            routing_key,
            message_count,
        })
    }
}

/// Encode basic.recover.
pub fn encode_basic_recover(requeue: bool) -> Vec<u8> {
    vec![if requeue { 1 } else { 0 }]
}

/// Encode channel.flow.
pub fn encode_channel_flow(active: bool) -> Vec<u8> {
    vec![if active { 1 } else { 0 }]
}

/// Decode channel.flow / channel.flow-ok `active` bit.
pub fn decode_flow_active(data: &[u8]) -> bool {
    data.first().copied().unwrap_or(1) & 1 != 0
}

/// Encode basic.cancel-ok (reply to a broker-initiated consumer-cancel-notify).
pub fn encode_basic_cancel_ok(consumer_tag: &str) -> Result<Vec<u8>, AmqpError> {
    let mut args = Vec::new();
    encode_shortstr(&mut args, consumer_tag)?;
    Ok(args)
}

/// Decode a broker-initiated basic.cancel (consumer-cancel-notify):
/// `(consumer_tag, no_wait)`.
pub fn decode_basic_cancel(mut data: &[u8]) -> Result<(String, bool), AmqpError> {
    let consumer_tag = decode_shortstr(&mut data)?.to_owned();
    let no_wait = read_bits(&mut data)? & 1 != 0;
    Ok((consumer_tag, no_wait))
}

/// Decode `connection.blocked` `reason` shortstr.
pub fn decode_connection_blocked(mut data: &[u8]) -> Result<String, AmqpError> {
    Ok(decode_shortstr(&mut data)?.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode::encode_method;
    use crate::codec::types::{basic, class};

    #[test]
    fn tune_round_trip() {
        let t = ConnectionTune {
            channel_max: 2047,
            frame_max: 131_072,
            heartbeat: 60,
        };
        let args = t.encode();
        let d = ConnectionTune::decode(&args).unwrap();
        assert_eq!(d.channel_max, 2047);
        assert_eq!(d.frame_max, 131_072);
        assert_eq!(d.heartbeat, 60);
    }

    #[test]
    fn publish_args() {
        let args = encode_basic_publish("amq.direct", "rk", true, false).unwrap();
        let frame = encode_method(1, class::BASIC, basic::PUBLISH, &args);
        assert!(frame.len() > 8);
    }

    #[test]
    fn basic_get_args() {
        let args = encode_basic_get("my-queue", true).unwrap();
        let frame = encode_method(1, class::BASIC, basic::GET, &args);
        assert!(frame.len() > 8);
    }

    #[test]
    fn basic_get_ok_round_trip() {
        let mut args = Vec::new();
        args.extend_from_slice(&42u64.to_be_bytes());
        args.push(1); // redelivered
        encode_shortstr(&mut args, "amq.direct").unwrap();
        encode_shortstr(&mut args, "rk").unwrap();
        args.extend_from_slice(&7u32.to_be_bytes());
        let ok = BasicGetOk::decode(&args).unwrap();
        assert_eq!(ok.delivery_tag, 42);
        assert!(ok.redelivered);
        assert_eq!(ok.exchange, "amq.direct");
        assert_eq!(ok.routing_key, "rk");
        assert_eq!(ok.message_count, 7);
    }

    #[test]
    fn basic_recover_args() {
        assert_eq!(encode_basic_recover(true), vec![1]);
        assert_eq!(encode_basic_recover(false), vec![0]);
    }

    #[test]
    fn channel_flow_round_trip() {
        assert!(decode_flow_active(&encode_channel_flow(true)));
        assert!(!decode_flow_active(&encode_channel_flow(false)));
    }

    #[test]
    fn basic_cancel_ok_args() {
        let args = encode_basic_cancel_ok("ctag-1").unwrap();
        assert_eq!(decode_consumer_tag(&args).unwrap(), "ctag-1");
    }

    #[test]
    fn basic_cancel_notify_round_trip() {
        let args = encode_basic_cancel("ctag-1", true).unwrap();
        let (tag, no_wait) = decode_basic_cancel(&args).unwrap();
        assert_eq!(tag, "ctag-1");
        assert!(no_wait);
    }

    #[test]
    fn connection_blocked_reason() {
        let mut args = Vec::new();
        encode_shortstr(&mut args, "low on memory").unwrap();
        assert_eq!(decode_connection_blocked(&args).unwrap(), "low on memory");
    }

    #[test]
    fn tx_method_args_are_empty() {
        assert!(encode_tx_method().is_empty());
    }

    #[test]
    fn connection_secure_round_trip() {
        let mut args = Vec::new();
        encode_longstr(&mut args, b"digest challenge bytes");
        assert_eq!(
            decode_connection_secure(&args).unwrap(),
            b"digest challenge bytes"
        );
    }

    #[test]
    fn connection_secure_ok_round_trip() {
        let args = encode_connection_secure_ok(b"response bytes");
        assert_eq!(decode_connection_secure(&args).unwrap(), b"response bytes");
    }
}
