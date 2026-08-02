// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP field tables and field values.

use std::collections::BTreeMap;
use std::io::{self, Write};

use super::AmqpError;

/// A field table (sorted map for stable encoding).
pub type FieldTable = BTreeMap<String, FieldValue>;

/// AMQP field-table value.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    /// Boolean (`t`).
    Bool(bool),
    /// Signed 8-bit (`b`).
    I8(i8),
    /// Unsigned 8-bit (`B`).
    U8(u8),
    /// Signed 16-bit (`s` in RabbitMQ / `U` in older docs).
    I16(i16),
    /// Unsigned 16-bit (`u`).
    U16(u16),
    /// Signed 32-bit (`I`).
    I32(i32),
    /// Unsigned 32-bit (`i`).
    U32(u32),
    /// Signed 64-bit (`l` in RabbitMQ).
    I64(i64),
    /// Unsigned 64-bit (`L` rarely; we encode as `l` for RabbitMQ long-long).
    U64(u64),
    /// 32-bit float (`f`).
    F32(f32),
    /// 64-bit float (`d`).
    F64(f64),
    /// Decimal (`D`): scale + signed 32-bit mantissa.
    Decimal {
        /// Decimal scale.
        scale: u8,
        /// Mantissa.
        value: i32,
    },
    /// Short string (`s` in 0-9-1; RabbitMQ uses `S` for longstr — see [`LongString`]).
    ShortString(String),
    /// Long string (`S`).
    LongString(Vec<u8>),
    /// Timestamp (`T`).
    Timestamp(u64),
    /// Nested table (`F`).
    Table(FieldTable),
    /// Array (`A`).
    Array(Vec<FieldValue>),
    /// Void (`V`).
    Void,
}

impl FieldValue {
    /// Convenience: UTF-8 long string.
    pub fn longstr(s: impl Into<String>) -> Self {
        Self::LongString(s.into().into_bytes())
    }
}

/// Encode a short string (`u8` length + bytes, max 255).
pub fn encode_shortstr(buf: &mut Vec<u8>, s: &str) -> Result<(), AmqpError> {
    if s.len() > 255 {
        return Err(AmqpError::Malformed("shortstr too long"));
    }
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Decode a short string; advances `*data`.
pub fn decode_shortstr<'a>(data: &mut &'a [u8]) -> Result<&'a str, AmqpError> {
    if data.is_empty() {
        return Err(AmqpError::Malformed("truncated shortstr length"));
    }
    let len = data[0] as usize;
    *data = &data[1..];
    if data.len() < len {
        return Err(AmqpError::Malformed("truncated shortstr"));
    }
    let s = std::str::from_utf8(&data[..len]).map_err(|_| AmqpError::Malformed("shortstr utf-8"))?;
    *data = &data[len..];
    Ok(s)
}

/// Encode a long string (`u32` length + bytes).
pub fn encode_longstr(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Decode a long string; advances `*data`.
pub fn decode_longstr<'a>(data: &mut &'a [u8]) -> Result<&'a [u8], AmqpError> {
    if data.len() < 4 {
        return Err(AmqpError::Malformed("truncated longstr length"));
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    *data = &data[4..];
    if data.len() < len {
        return Err(AmqpError::Malformed("truncated longstr"));
    }
    let s = &data[..len];
    *data = &data[len..];
    Ok(s)
}

/// Encode a field table as a longstr payload (length + entries).
pub fn encode_table(buf: &mut Vec<u8>, table: &FieldTable) -> Result<(), AmqpError> {
    let mut body = Vec::new();
    for (k, v) in table {
        encode_shortstr(&mut body, k)?;
        encode_field_value(&mut body, v)?;
    }
    encode_longstr(buf, &body);
    Ok(())
}

/// Decode a field table; advances `*data`.
pub fn decode_table(data: &mut &[u8]) -> Result<FieldTable, AmqpError> {
    let body = decode_longstr(data)?;
    let mut rest = body;
    let mut table = FieldTable::new();
    while !rest.is_empty() {
        let key = decode_shortstr(&mut rest)?.to_owned();
        let value = decode_field_value(&mut rest)?;
        table.insert(key, value);
    }
    Ok(table)
}

fn encode_field_value(buf: &mut Vec<u8>, v: &FieldValue) -> Result<(), AmqpError> {
    match v {
        FieldValue::Bool(b) => {
            buf.push(b't');
            buf.push(if *b { 1 } else { 0 });
        }
        FieldValue::I8(n) => {
            buf.push(b'b');
            buf.push(*n as u8);
        }
        FieldValue::U8(n) => {
            buf.push(b'B');
            buf.push(*n);
        }
        FieldValue::I16(n) => {
            // RabbitMQ uses 's' for short-int.
            buf.push(b's');
            buf.extend_from_slice(&n.to_be_bytes());
        }
        FieldValue::U16(n) => {
            buf.push(b'u');
            buf.extend_from_slice(&n.to_be_bytes());
        }
        FieldValue::I32(n) => {
            buf.push(b'I');
            buf.extend_from_slice(&n.to_be_bytes());
        }
        FieldValue::U32(n) => {
            buf.push(b'i');
            buf.extend_from_slice(&n.to_be_bytes());
        }
        FieldValue::I64(n) => {
            buf.push(b'l');
            buf.extend_from_slice(&n.to_be_bytes());
        }
        FieldValue::U64(n) => {
            buf.push(b'l');
            buf.extend_from_slice(&(*n as i64).to_be_bytes());
        }
        FieldValue::F32(n) => {
            buf.push(b'f');
            buf.extend_from_slice(&n.to_bits().to_be_bytes());
        }
        FieldValue::F64(n) => {
            buf.push(b'd');
            buf.extend_from_slice(&n.to_bits().to_be_bytes());
        }
        FieldValue::Decimal { scale, value } => {
            buf.push(b'D');
            buf.push(*scale);
            buf.extend_from_slice(&value.to_be_bytes());
        }
        FieldValue::ShortString(s) => {
            // RabbitMQ: short strings in tables are rare; encode as longstr 'S'.
            buf.push(b'S');
            encode_longstr(buf, s.as_bytes());
        }
        FieldValue::LongString(bytes) => {
            buf.push(b'S');
            encode_longstr(buf, bytes);
        }
        FieldValue::Timestamp(t) => {
            buf.push(b'T');
            buf.extend_from_slice(&t.to_be_bytes());
        }
        FieldValue::Table(t) => {
            buf.push(b'F');
            encode_table(buf, t)?;
        }
        FieldValue::Array(items) => {
            buf.push(b'A');
            let mut body = Vec::new();
            for item in items {
                encode_field_value(&mut body, item)?;
            }
            encode_longstr(buf, &body);
        }
        FieldValue::Void => {
            buf.push(b'V');
        }
    }
    Ok(())
}

fn decode_field_value(data: &mut &[u8]) -> Result<FieldValue, AmqpError> {
    if data.is_empty() {
        return Err(AmqpError::Malformed("truncated field value type"));
    }
    let tag = data[0];
    *data = &data[1..];
    match tag {
        b't' => {
            if data.is_empty() {
                return Err(AmqpError::Malformed("truncated bool"));
            }
            let v = data[0] != 0;
            *data = &data[1..];
            Ok(FieldValue::Bool(v))
        }
        b'b' => {
            if data.is_empty() {
                return Err(AmqpError::Malformed("truncated i8"));
            }
            let v = data[0] as i8;
            *data = &data[1..];
            Ok(FieldValue::I8(v))
        }
        b'B' => {
            if data.is_empty() {
                return Err(AmqpError::Malformed("truncated u8"));
            }
            let v = data[0];
            *data = &data[1..];
            Ok(FieldValue::U8(v))
        }
        b'U' | b's' => {
            if data.len() < 2 {
                return Err(AmqpError::Malformed("truncated i16"));
            }
            let v = i16::from_be_bytes([data[0], data[1]]);
            *data = &data[2..];
            Ok(FieldValue::I16(v))
        }
        b'u' => {
            if data.len() < 2 {
                return Err(AmqpError::Malformed("truncated u16"));
            }
            let v = u16::from_be_bytes([data[0], data[1]]);
            *data = &data[2..];
            Ok(FieldValue::U16(v))
        }
        b'I' => {
            if data.len() < 4 {
                return Err(AmqpError::Malformed("truncated i32"));
            }
            let v = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            *data = &data[4..];
            Ok(FieldValue::I32(v))
        }
        b'i' => {
            if data.len() < 4 {
                return Err(AmqpError::Malformed("truncated u32"));
            }
            let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            *data = &data[4..];
            Ok(FieldValue::U32(v))
        }
        b'L' | b'l' => {
            if data.len() < 8 {
                return Err(AmqpError::Malformed("truncated i64"));
            }
            let v = i64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            *data = &data[8..];
            Ok(FieldValue::I64(v))
        }
        b'f' => {
            if data.len() < 4 {
                return Err(AmqpError::Malformed("truncated f32"));
            }
            let bits = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            *data = &data[4..];
            Ok(FieldValue::F32(f32::from_bits(bits)))
        }
        b'd' => {
            if data.len() < 8 {
                return Err(AmqpError::Malformed("truncated f64"));
            }
            let bits = u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            *data = &data[8..];
            Ok(FieldValue::F64(f64::from_bits(bits)))
        }
        b'D' => {
            if data.len() < 5 {
                return Err(AmqpError::Malformed("truncated decimal"));
            }
            let scale = data[0];
            let value = i32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            *data = &data[5..];
            Ok(FieldValue::Decimal { scale, value })
        }
        b'S' => {
            let bytes = decode_longstr(data)?;
            Ok(FieldValue::LongString(bytes.to_vec()))
        }
        b'T' => {
            if data.len() < 8 {
                return Err(AmqpError::Malformed("truncated timestamp"));
            }
            let v = u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            *data = &data[8..];
            Ok(FieldValue::Timestamp(v))
        }
        b'F' => Ok(FieldValue::Table(decode_table(data)?)),
        b'A' => {
            let body = decode_longstr(data)?;
            let mut rest = body;
            let mut items = Vec::new();
            while !rest.is_empty() {
                items.push(decode_field_value(&mut rest)?);
            }
            Ok(FieldValue::Array(items))
        }
        b'V' => Ok(FieldValue::Void),
        _ => Err(AmqpError::Malformed("unknown field value type")),
    }
}

/// Encode AMQPLAIN SASL response table (`LOGIN` / `PASSWORD` longstrs).
pub fn encode_amqplain(username: &str, password: &str) -> Result<Vec<u8>, AmqpError> {
    let mut table = FieldTable::new();
    table.insert("LOGIN".into(), FieldValue::longstr(username));
    table.insert("PASSWORD".into(), FieldValue::longstr(password));
    let mut body = Vec::new();
    for (k, v) in &table {
        encode_shortstr(&mut body, k)?;
        encode_field_value(&mut body, v)?;
    }
    Ok(body)
}

/// Write raw bytes; helper for tests / callers that use `Write`.
pub fn write_all(w: &mut dyn Write, buf: &[u8]) -> io::Result<()> {
    w.write_all(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_round_trip() {
        let mut t = FieldTable::new();
        t.insert("LOGIN".into(), FieldValue::longstr("guest"));
        t.insert("PASSWORD".into(), FieldValue::longstr("guest"));
        t.insert("n".into(), FieldValue::I32(42));
        t.insert("flag".into(), FieldValue::Bool(true));

        let mut buf = Vec::new();
        encode_table(&mut buf, &t).unwrap();
        let mut rest: &[u8] = &buf;
        let decoded = decode_table(&mut rest).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, t);
    }

    #[test]
    fn shortstr_round_trip() {
        let mut buf = Vec::new();
        encode_shortstr(&mut buf, "hello").unwrap();
        let mut rest: &[u8] = &buf;
        assert_eq!(decode_shortstr(&mut rest).unwrap(), "hello");
        assert!(rest.is_empty());
    }

    #[test]
    fn amqplain_contains_login() {
        let body = encode_amqplain("alice", "secret").unwrap();
        assert!(body.windows(5).any(|w| w == b"LOGIN"));
        assert!(body.windows(8).any(|w| w == b"PASSWORD"));
    }
}
