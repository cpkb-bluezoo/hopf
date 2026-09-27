// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The AMQP 1.0 self-describing type system (spec part 1, section 1.6).
//!
//! Every encoded value starts with a one-octet format code identifying its
//! constructor (fixed-width primitive, variable-width, compound, array, or
//! `0x00` for a described type). [`decode`] and [`Encoder`] operate on
//! **complete** buffers only — [`super::frame::Amqp1FrameParser`] always
//! hands callers a fully assembled frame body (bounded by the negotiated
//! max-frame-size) before any performative or message-section decoding
//! happens, so there is no partial-value case to signal here.

use super::Amqp1Error;

/// Nesting depth guard for lists/maps/arrays/described values, matching the
/// AMQP 1.0 reference decoder's guard against pathological/malicious input.
const MAX_DEPTH: u32 = 32;

// Primitive format codes (spec section 1.6).
pub(crate) const NULL: u8 = 0x40;
pub(crate) const BOOLEAN: u8 = 0x56;
pub(crate) const BOOLEAN_TRUE: u8 = 0x41;
pub(crate) const BOOLEAN_FALSE: u8 = 0x42;
pub(crate) const UBYTE: u8 = 0x50;
pub(crate) const USHORT: u8 = 0x60;
pub(crate) const UINT: u8 = 0x70;
pub(crate) const SMALLUINT: u8 = 0x52;
pub(crate) const UINT0: u8 = 0x43;
pub(crate) const ULONG: u8 = 0x80;
pub(crate) const SMALLULONG: u8 = 0x53;
pub(crate) const ULONG0: u8 = 0x44;
pub(crate) const BYTE: u8 = 0x51;
pub(crate) const SHORT: u8 = 0x61;
pub(crate) const INT: u8 = 0x71;
pub(crate) const SMALLINT: u8 = 0x54;
pub(crate) const LONG: u8 = 0x81;
pub(crate) const SMALLLONG: u8 = 0x55;
pub(crate) const FLOAT: u8 = 0x72;
pub(crate) const DOUBLE: u8 = 0x82;
pub(crate) const DECIMAL32: u8 = 0x74;
pub(crate) const DECIMAL64: u8 = 0x84;
pub(crate) const DECIMAL128: u8 = 0x94;
pub(crate) const CHAR: u8 = 0x73;
pub(crate) const TIMESTAMP: u8 = 0x83;
pub(crate) const UUID: u8 = 0x98;
pub(crate) const VBIN8: u8 = 0xa0;
pub(crate) const VBIN32: u8 = 0xb0;
pub(crate) const STR8: u8 = 0xa1;
pub(crate) const STR32: u8 = 0xb1;
pub(crate) const SYM8: u8 = 0xa3;
pub(crate) const SYM32: u8 = 0xb3;
pub(crate) const LIST0: u8 = 0x45;
pub(crate) const LIST8: u8 = 0xc0;
pub(crate) const LIST32: u8 = 0xd0;
pub(crate) const MAP8: u8 = 0xc1;
pub(crate) const MAP32: u8 = 0xd1;
pub(crate) const ARRAY8: u8 = 0xe0;
pub(crate) const ARRAY32: u8 = 0xf0;
/// Constructor byte for a described type: `0x00` followed by the descriptor
/// value, then the underlying value's own constructor and body.
pub const DESCRIBED: u8 = 0x00;

/// A decoded AMQP 1.0 value. Maps preserve encounter order (spec does not
/// require map keys to be usable as a Rust hash key, and duplicate-detection
/// is a caller concern, not the decoder's).
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `boolean`.
    Bool(bool),
    /// `ubyte`.
    Ubyte(u8),
    /// `ushort`.
    Ushort(u16),
    /// `uint`.
    Uint(u32),
    /// `ulong`.
    Ulong(u64),
    /// `byte`.
    Byte(i8),
    /// `short`.
    Short(i16),
    /// `int`.
    Int(i32),
    /// `long`.
    Long(i64),
    /// `float` (binary32).
    Float(f32),
    /// `double` (binary64).
    Double(f64),
    /// `decimal32` — opaque bit pattern (no arithmetic support needed by a client).
    Decimal32([u8; 4]),
    /// `decimal64` — opaque bit pattern.
    Decimal64([u8; 8]),
    /// `decimal128` — opaque bit pattern.
    Decimal128([u8; 16]),
    /// `char` (Unicode scalar value).
    Char(char),
    /// `timestamp` — milliseconds since the Unix epoch.
    Timestamp(i64),
    /// `uuid`.
    Uuid([u8; 16]),
    /// `binary`.
    Binary(Vec<u8>),
    /// `string` (UTF-8).
    String(String),
    /// `symbol` (ASCII) — kept distinct from [`Value::String`] so it
    /// round-trips through the correct wire constructor.
    Symbol(String),
    /// `list`.
    List(Vec<Value>),
    /// `map`, as encoded key/value pairs in encounter order.
    Map(Vec<(Value, Value)>),
    /// `array` — homogeneous; the element format code isn't retained once
    /// decoded (call sites for a given performative field already know the
    /// expected element type).
    Array(Vec<Value>),
    /// A described type: `(descriptor, value)`. Every AMQP 1.0 performative,
    /// message section, and SASL frame body is a described list under this
    /// representation before [`super::performative`] / [`super::sasl`]
    /// dispatch on the descriptor.
    Described(Box<Value>, Box<Value>),
}

impl Value {
    /// This value as `u64`, widening any unsigned integer type. Used by
    /// [`super::performative`] to read a descriptor code.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Ubyte(v) => Some(*v as u64),
            Value::Ushort(v) => Some(*v as u64),
            Value::Uint(v) => Some(*v as u64),
            Value::Ulong(v) => Some(*v),
            _ => None,
        }
    }

    /// This value as a borrowed `str`, for [`Value::String`] or [`Value::Symbol`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) | Value::Symbol(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// This value as a borrowed `list`.
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// This value as a borrowed `binary`.
    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            Value::Binary(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// This value's `bool`, if it is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Symbols decoded as a single value or as an array of symbols — both
    /// forms are legal wherever the spec allows a "symbol or array of
    /// symbol" field (e.g. `offered-capabilities`).
    pub fn as_symbol_multiple(&self) -> Option<Vec<String>> {
        match self {
            Value::Symbol(s) => Some(vec![s.clone()]),
            Value::Array(items) => items.iter().map(|v| v.as_str().map(str::to_string)).collect(),
            _ => None,
        }
    }
}

/// Decode one complete value from the start of `buf`. `buf` must contain
/// the value in full; returns `(value, bytes_consumed)`.
pub fn decode(buf: &[u8]) -> Result<(Value, usize), Amqp1Error> {
    decode_at_depth(buf, 0)
}

/// Probe how many bytes the value at the start of `buf` will occupy once
/// complete, without requiring the value's own content to be fully present
/// yet — only its constructor and, for variable-width/compound encodings,
/// its size field (at most a few bytes). Returns `Ok(None)` when even that
/// much isn't buffered yet.
///
/// Used by [`super::message::MessageParser`], which — unlike the frame and
/// performative layers, where a whole frame is always buffered before any
/// decoding starts — must detect a `data` section's declared length as soon
/// as possible so it can stream that section's payload to the application
/// as it arrives, rather than waiting for the (possibly very large) section
/// to be fully buffered.
pub fn value_length(buf: &[u8]) -> Result<Option<usize>, Amqp1Error> {
    let Some(&code) = buf.first() else { return Ok(None) };
    let rest = &buf[1..];
    match code {
        NULL | BOOLEAN_TRUE | BOOLEAN_FALSE | UINT0 | ULONG0 | LIST0 => Ok(Some(1)),
        BOOLEAN | UBYTE | BYTE | SMALLUINT | SMALLULONG | SMALLINT | SMALLLONG => Ok(Some(2)),
        USHORT | SHORT => Ok(Some(3)),
        UINT | INT | FLOAT | CHAR | DECIMAL32 => Ok(Some(5)),
        ULONG | LONG | DOUBLE | TIMESTAMP | DECIMAL64 => Ok(Some(9)),
        DECIMAL128 | UUID => Ok(Some(17)),
        // For binary/string/symbol, `n` is the data length; for
        // list/map/array, `n` (the wire `size` field) already includes the
        // count field's own width (spec 1.6.22/23) — either way, total
        // length is `1` (constructor) + size-field-width + `n`.
        VBIN8 | STR8 | SYM8 | LIST8 | MAP8 | ARRAY8 => match rest.first() {
            None => Ok(None),
            Some(&n) => Ok(Some(2 + n as usize)),
        },
        VBIN32 | STR32 | SYM32 | LIST32 | MAP32 | ARRAY32 => {
            if rest.len() < 4 {
                return Ok(None);
            }
            let n = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            Ok(Some(5 + n))
        }
        DESCRIBED => match value_length(rest)? {
            None => Ok(None),
            Some(dn) => {
                if rest.len() < dn {
                    return Ok(None);
                }
                match value_length(&rest[dn..])? {
                    None => Ok(None),
                    Some(vn) => Ok(Some(1 + dn + vn)),
                }
            }
        },
        other => Err(Amqp1Error::UnknownFormatCode(other)),
    }
}

fn decode_at_depth(buf: &[u8], depth: u32) -> Result<(Value, usize), Amqp1Error> {
    if depth > MAX_DEPTH {
        return Err(Amqp1Error::Malformed("nesting too deep"));
    }
    let code = *buf.first().ok_or(Amqp1Error::Malformed("truncated value"))?;
    let rest = &buf[1..];
    match code {
        NULL => Ok((Value::Null, 1)),
        BOOLEAN_TRUE => Ok((Value::Bool(true), 1)),
        BOOLEAN_FALSE => Ok((Value::Bool(false), 1)),
        BOOLEAN => {
            let b = *rest.first().ok_or(Amqp1Error::Malformed("truncated boolean"))?;
            Ok((Value::Bool(b != 0), 2))
        }
        UBYTE => Ok((Value::Ubyte(read_u8(rest)?), 2)),
        USHORT => Ok((Value::Ushort(read_u16(rest)?), 3)),
        UINT0 => Ok((Value::Uint(0), 1)),
        SMALLUINT => Ok((Value::Uint(read_u8(rest)? as u32), 2)),
        UINT => Ok((Value::Uint(read_u32(rest)?), 5)),
        ULONG0 => Ok((Value::Ulong(0), 1)),
        SMALLULONG => Ok((Value::Ulong(read_u8(rest)? as u64), 2)),
        ULONG => Ok((Value::Ulong(read_u64(rest)?), 9)),
        BYTE => Ok((Value::Byte(read_u8(rest)? as i8), 2)),
        SHORT => Ok((Value::Short(read_u16(rest)? as i16), 3)),
        SMALLINT => Ok((Value::Int(read_u8(rest)? as i8 as i32), 2)),
        INT => Ok((Value::Int(read_u32(rest)? as i32), 5)),
        SMALLLONG => Ok((Value::Long(read_u8(rest)? as i8 as i64), 2)),
        LONG => Ok((Value::Long(read_u64(rest)? as i64), 9)),
        FLOAT => Ok((Value::Float(f32::from_bits(read_u32(rest)?)), 5)),
        DOUBLE => Ok((Value::Double(f64::from_bits(read_u64(rest)?)), 9)),
        DECIMAL32 => Ok((Value::Decimal32(read_array::<4>(rest)?), 5)),
        DECIMAL64 => Ok((Value::Decimal64(read_array::<8>(rest)?), 9)),
        DECIMAL128 => Ok((Value::Decimal128(read_array::<16>(rest)?), 17)),
        CHAR => {
            let v = read_u32(rest)?;
            let c = char::from_u32(v).ok_or(Amqp1Error::Malformed("invalid char scalar"))?;
            Ok((Value::Char(c), 5))
        }
        TIMESTAMP => Ok((Value::Timestamp(read_u64(rest)? as i64), 9)),
        UUID => Ok((Value::Uuid(read_array::<16>(rest)?), 17)),
        VBIN8 => {
            let n = read_u8(rest)? as usize;
            let data = read_bytes(&rest[1..], n)?;
            Ok((Value::Binary(data.to_vec()), 2 + n))
        }
        VBIN32 => {
            let n = read_u32(rest)? as usize;
            let data = read_bytes(&rest[4..], n)?;
            Ok((Value::Binary(data.to_vec()), 5 + n))
        }
        STR8 => {
            let n = read_u8(rest)? as usize;
            let data = read_bytes(&rest[1..], n)?;
            let s = std::str::from_utf8(data)
                .map_err(|_| Amqp1Error::Malformed("invalid utf-8 string"))?;
            Ok((Value::String(s.to_string()), 2 + n))
        }
        STR32 => {
            let n = read_u32(rest)? as usize;
            let data = read_bytes(&rest[4..], n)?;
            let s = std::str::from_utf8(data)
                .map_err(|_| Amqp1Error::Malformed("invalid utf-8 string"))?;
            Ok((Value::String(s.to_string()), 5 + n))
        }
        SYM8 => {
            let n = read_u8(rest)? as usize;
            let data = read_bytes(&rest[1..], n)?;
            let s = std::str::from_utf8(data)
                .map_err(|_| Amqp1Error::Malformed("invalid symbol"))?;
            Ok((Value::Symbol(s.to_string()), 2 + n))
        }
        SYM32 => {
            let n = read_u32(rest)? as usize;
            let data = read_bytes(&rest[4..], n)?;
            let s = std::str::from_utf8(data)
                .map_err(|_| Amqp1Error::Malformed("invalid symbol"))?;
            Ok((Value::Symbol(s.to_string()), 5 + n))
        }
        LIST0 => Ok((Value::List(Vec::new()), 1)),
        LIST8 => decode_compound_8(rest, depth, Value::List),
        LIST32 => decode_compound_32(rest, depth, Value::List),
        MAP8 => decode_map_8(rest, depth),
        MAP32 => decode_map_32(rest, depth),
        ARRAY8 => decode_array_8(rest, depth),
        ARRAY32 => decode_array_32(rest, depth),
        DESCRIBED => {
            let (descriptor, dn) = decode_at_depth(rest, depth + 1)?;
            let (value, vn) = decode_at_depth(&rest[dn..], depth + 1)?;
            Ok((
                Value::Described(Box::new(descriptor), Box::new(value)),
                1 + dn + vn,
            ))
        }
        other => Err(Amqp1Error::UnknownFormatCode(other)),
    }
}

fn decode_compound_8(
    rest: &[u8],
    depth: u32,
    wrap: impl FnOnce(Vec<Value>) -> Value,
) -> Result<(Value, usize), Amqp1Error> {
    let size = read_u8(rest)? as usize;
    let count = read_u8(&rest[1..])? as usize;
    let body = read_bytes(&rest[2..], size.checked_sub(1).ok_or(Amqp1Error::Malformed("bad compound size"))?)?;
    let items = decode_elements(body, count, depth + 1)?;
    Ok((wrap(items), 1 + 1 + size))
}

fn decode_compound_32(
    rest: &[u8],
    depth: u32,
    wrap: impl FnOnce(Vec<Value>) -> Value,
) -> Result<(Value, usize), Amqp1Error> {
    let size = read_u32(rest)? as usize;
    let count = read_u32(&rest[4..])? as usize;
    let body = read_bytes(&rest[8..], size.checked_sub(4).ok_or(Amqp1Error::Malformed("bad compound size"))?)?;
    let items = decode_elements(body, count, depth + 1)?;
    Ok((wrap(items), 4 + 4 + size))
}

fn decode_map_8(rest: &[u8], depth: u32) -> Result<(Value, usize), Amqp1Error> {
    let (Value::List(items), n) = decode_compound_8(rest, depth, Value::List)? else {
        unreachable!()
    };
    Ok((Value::Map(pair_up(items)?), n))
}

fn decode_map_32(rest: &[u8], depth: u32) -> Result<(Value, usize), Amqp1Error> {
    let (Value::List(items), n) = decode_compound_32(rest, depth, Value::List)? else {
        unreachable!()
    };
    Ok((Value::Map(pair_up(items)?), n))
}

fn pair_up(items: Vec<Value>) -> Result<Vec<(Value, Value)>, Amqp1Error> {
    if items.len() % 2 != 0 {
        return Err(Amqp1Error::Malformed("map with odd element count"));
    }
    let mut pairs = Vec::with_capacity(items.len() / 2);
    let mut it = items.into_iter();
    while let (Some(k), Some(v)) = (it.next(), it.next()) {
        pairs.push((k, v));
    }
    Ok(pairs)
}

fn decode_array_8(rest: &[u8], depth: u32) -> Result<(Value, usize), Amqp1Error> {
    let size = read_u8(rest)? as usize;
    let count = read_u8(&rest[1..])? as usize;
    let body = read_bytes(&rest[2..], size.checked_sub(1).ok_or(Amqp1Error::Malformed("bad array size"))?)?;
    let items = decode_array_elements(body, count, depth + 1)?;
    Ok((Value::Array(items), 1 + 1 + size))
}

fn decode_array_32(rest: &[u8], depth: u32) -> Result<(Value, usize), Amqp1Error> {
    let size = read_u32(rest)? as usize;
    let count = read_u32(&rest[4..])? as usize;
    let body = read_bytes(&rest[8..], size.checked_sub(4).ok_or(Amqp1Error::Malformed("bad array size"))?)?;
    let items = decode_array_elements(body, count, depth + 1)?;
    Ok((Value::Array(items), 4 + 4 + size))
}

/// A `list`/`map`'s elements each carry their own constructor.
fn decode_elements(mut body: &[u8], count: usize, depth: u32) -> Result<Vec<Value>, Amqp1Error> {
    let mut items = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let (v, n) = decode_at_depth(body, depth)?;
        items.push(v);
        body = &body[n..];
    }
    Ok(items)
}

/// An `array`'s elements share one constructor (and, for compound element
/// types, one shared size/count that isn't re-stated per element) — spec
/// section 1.6.24. Values needed by this client's own performatives never
/// nest a compound inside an array, so only primitive element constructors
/// are supported here.
fn decode_array_elements(body: &[u8], count: usize, depth: u32) -> Result<Vec<Value>, Amqp1Error> {
    if depth > MAX_DEPTH {
        return Err(Amqp1Error::Malformed("nesting too deep"));
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    let ctor = *body.first().ok_or(Amqp1Error::Malformed("truncated array"))?;
    if matches!(
        ctor,
        DESCRIBED | LIST0 | LIST8 | LIST32 | MAP8 | MAP32 | ARRAY8 | ARRAY32
    ) {
        // Not a depth-tracking bug to work around: no performative or
        // message-section field in this client ever needs an array of
        // compound/described elements, so this is simply out of scope
        // (also avoids `decode_fixed_or_variable`'s depth reset below ever
        // being reachable with a compound constructor).
        return Err(Amqp1Error::Malformed("array of compound/described elements not supported"));
    }
    let mut offset = 1;
    let mut items = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let (v, n) = decode_fixed_or_variable(ctor, &body[offset..])?;
        items.push(v);
        offset += n;
    }
    Ok(items)
}

/// Decode one array element given the array's shared constructor byte
/// (never itself `0x00`/described, list, map, or array — see
/// [`decode_array_elements`]).
fn decode_fixed_or_variable(ctor: u8, buf: &[u8]) -> Result<(Value, usize), Amqp1Error> {
    // Reuse the general decoder by prefixing the constructor byte; every
    // primitive constructor's own decode arm doesn't care that it arrived
    // via an array rather than standalone.
    let mut with_ctor = Vec::with_capacity(buf.len() + 1);
    with_ctor.push(ctor);
    with_ctor.extend_from_slice(buf);
    let (v, n) = decode_at_depth(&with_ctor, 0)?;
    Ok((v, n - 1))
}

fn read_u8(buf: &[u8]) -> Result<u8, Amqp1Error> {
    buf.first().copied().ok_or(Amqp1Error::Malformed("truncated value"))
}

fn read_u16(buf: &[u8]) -> Result<u16, Amqp1Error> {
    let a = read_bytes(buf, 2)?;
    Ok(u16::from_be_bytes([a[0], a[1]]))
}

fn read_u32(buf: &[u8]) -> Result<u32, Amqp1Error> {
    let a = read_bytes(buf, 4)?;
    Ok(u32::from_be_bytes([a[0], a[1], a[2], a[3]]))
}

fn read_u64(buf: &[u8]) -> Result<u64, Amqp1Error> {
    let a = read_bytes(buf, 8)?;
    Ok(u64::from_be_bytes(a.try_into().unwrap()))
}

fn read_array<const N: usize>(buf: &[u8]) -> Result<[u8; N], Amqp1Error> {
    let a = read_bytes(buf, N)?;
    Ok(a.try_into().unwrap())
}

fn read_bytes(buf: &[u8], n: usize) -> Result<&[u8], Amqp1Error> {
    if buf.len() < n {
        return Err(Amqp1Error::Malformed("truncated value"));
    }
    Ok(&buf[..n])
}

/// Growable byte-string encoder for the AMQP 1.0 type system. Always
/// chooses the most compact constructor for scalar values; compound values
/// (list/map) are built via [`Encoder::compound`] which measures the
/// encoded elements before choosing the 8- or 32-bit size/count form.
#[derive(Debug, Default, Clone)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// New empty encoder.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Consume the encoder, returning the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the bytes encoded so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Number of bytes encoded so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been encoded yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// `null`.
    pub fn null(&mut self) {
        self.buf.push(NULL);
    }

    /// `boolean`, using the zero-width true/false constructors.
    pub fn boolean(&mut self, v: bool) {
        self.buf.push(if v { BOOLEAN_TRUE } else { BOOLEAN_FALSE });
    }

    /// `ubyte`.
    pub fn ubyte(&mut self, v: u8) {
        self.buf.push(UBYTE);
        self.buf.push(v);
    }

    /// `ushort`.
    pub fn ushort(&mut self, v: u16) {
        self.buf.push(USHORT);
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// `uint`, most compactly (`uint0` / `smalluint` / full width).
    pub fn uint(&mut self, v: u32) {
        if v == 0 {
            self.buf.push(UINT0);
        } else if v <= 0xff {
            self.buf.push(SMALLUINT);
            self.buf.push(v as u8);
        } else {
            self.buf.push(UINT);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// `ulong`, most compactly.
    pub fn ulong(&mut self, v: u64) {
        if v == 0 {
            self.buf.push(ULONG0);
        } else if v <= 0xff {
            self.buf.push(SMALLULONG);
            self.buf.push(v as u8);
        } else {
            self.buf.push(ULONG);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// `byte` (signed 8-bit).
    pub fn byte(&mut self, v: i8) {
        self.buf.push(BYTE);
        self.buf.push(v as u8);
    }

    /// `short` (signed 16-bit).
    pub fn short(&mut self, v: i16) {
        self.buf.push(SHORT);
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// `int`, most compactly.
    pub fn int(&mut self, v: i32) {
        if (-128..=127).contains(&v) {
            self.buf.push(SMALLINT);
            self.buf.push(v as i8 as u8);
        } else {
            self.buf.push(INT);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// `long`, most compactly.
    pub fn long(&mut self, v: i64) {
        if (-128..=127).contains(&v) {
            self.buf.push(SMALLLONG);
            self.buf.push(v as i8 as u8);
        } else {
            self.buf.push(LONG);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// `float` (binary32).
    pub fn float(&mut self, v: f32) {
        self.buf.push(FLOAT);
        self.buf.extend_from_slice(&v.to_bits().to_be_bytes());
    }

    /// `double` (binary64).
    pub fn double(&mut self, v: f64) {
        self.buf.push(DOUBLE);
        self.buf.extend_from_slice(&v.to_bits().to_be_bytes());
    }

    /// `timestamp` (milliseconds since the Unix epoch).
    pub fn timestamp(&mut self, v: i64) {
        self.buf.push(TIMESTAMP);
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// `uuid`.
    pub fn uuid(&mut self, v: [u8; 16]) {
        self.buf.push(UUID);
        self.buf.extend_from_slice(&v);
    }

    /// `binary`, using `vbin8` when it fits, otherwise `vbin32`.
    pub fn binary(&mut self, v: &[u8]) {
        if v.len() <= 0xff {
            self.buf.push(VBIN8);
            self.buf.push(v.len() as u8);
        } else {
            self.buf.push(VBIN32);
            self.buf.extend_from_slice(&(v.len() as u32).to_be_bytes());
        }
        self.buf.extend_from_slice(v);
    }

    /// `string` (UTF-8), using `str8-utf8` when it fits, otherwise `str32-utf8`.
    pub fn string(&mut self, v: &str) {
        let bytes = v.as_bytes();
        if bytes.len() <= 0xff {
            self.buf.push(STR8);
            self.buf.push(bytes.len() as u8);
        } else {
            self.buf.push(STR32);
            self.buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        }
        self.buf.extend_from_slice(bytes);
    }

    /// `symbol`, using `sym8` when it fits, otherwise `sym32`.
    pub fn symbol(&mut self, v: &str) {
        let bytes = v.as_bytes();
        if bytes.len() <= 0xff {
            self.buf.push(SYM8);
            self.buf.push(bytes.len() as u8);
        } else {
            self.buf.push(SYM32);
            self.buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        }
        self.buf.extend_from_slice(bytes);
    }

    /// Append the encoding of a generic [`Value`] (used for map/list
    /// elements and message-body values whose static type isn't known
    /// ahead of time).
    pub fn value(&mut self, v: &Value) {
        match v {
            Value::Null => self.null(),
            Value::Bool(b) => self.boolean(*b),
            Value::Ubyte(x) => self.ubyte(*x),
            Value::Ushort(x) => self.ushort(*x),
            Value::Uint(x) => self.uint(*x),
            Value::Ulong(x) => self.ulong(*x),
            Value::Byte(x) => self.byte(*x),
            Value::Short(x) => self.short(*x),
            Value::Int(x) => self.int(*x),
            Value::Long(x) => self.long(*x),
            Value::Float(x) => self.float(*x),
            Value::Double(x) => self.double(*x),
            Value::Decimal32(b) => {
                self.buf.push(DECIMAL32);
                self.buf.extend_from_slice(b);
            }
            Value::Decimal64(b) => {
                self.buf.push(DECIMAL64);
                self.buf.extend_from_slice(b);
            }
            Value::Decimal128(b) => {
                self.buf.push(DECIMAL128);
                self.buf.extend_from_slice(b);
            }
            Value::Char(c) => {
                self.buf.push(CHAR);
                self.buf.extend_from_slice(&(*c as u32).to_be_bytes());
            }
            Value::Timestamp(t) => self.timestamp(*t),
            Value::Uuid(u) => self.uuid(*u),
            Value::Binary(b) => self.binary(b),
            Value::String(s) => self.string(s),
            Value::Symbol(s) => self.symbol(s),
            Value::List(items) => self.list(items),
            Value::Map(pairs) => self.map(pairs),
            Value::Array(items) => self.array_of_values(items),
            Value::Described(descriptor, value) => self.described_value(descriptor, value),
        }
    }

    /// `list`, choosing `list0`/`list8`/`list32` by encoded size.
    pub fn list(&mut self, items: &[Value]) {
        if items.is_empty() {
            self.buf.push(LIST0);
            return;
        }
        let mut body = Encoder::new();
        for item in items {
            body.value(item);
        }
        self.emit_compound(LIST8, LIST32, items.len() as u32, body.into_bytes());
    }

    /// `map`, choosing `map8`/`map32` by encoded size.
    pub fn map(&mut self, pairs: &[(Value, Value)]) {
        let mut body = Encoder::new();
        for (k, v) in pairs {
            body.value(k);
            body.value(v);
        }
        self.emit_compound(MAP8, MAP32, (pairs.len() * 2) as u32, body.into_bytes());
    }

    /// `array` of already-encoded [`Value`]s, using each value's own
    /// preferred constructor as the shared array constructor (all elements
    /// must share one constructor — spec section 1.6.24 — so this assumes
    /// every element is the same primitive type, which holds for every
    /// symbol-array field this client encodes).
    pub fn array_of_values(&mut self, items: &[Value]) {
        let mut body = Encoder::new();
        for item in items {
            // Constructor is shared, so only the first element's constructor
            // byte is kept; the rest contribute value bytes only.
            let mut one = Encoder::new();
            one.value(item);
            let bytes = one.into_bytes();
            if body.is_empty() {
                body.buf.extend_from_slice(&bytes);
            } else {
                body.buf.extend_from_slice(&bytes[1..]);
            }
        }
        self.emit_compound(ARRAY8, ARRAY32, items.len() as u32, body.into_bytes());
    }

    /// Symbol array — the common case of [`Self::array_of_values`].
    pub fn symbol_array(&mut self, symbols: &[String]) {
        let values: Vec<Value> = symbols.iter().map(|s| Value::Symbol(s.clone())).collect();
        self.array_of_values(&values);
    }

    fn emit_compound(&mut self, code8: u8, code32: u8, count: u32, body: Vec<u8>) {
        // size field counts itself as absent but includes the count field's
        // own width (spec 1.6.22/23): 1 + body.len() for the 8-bit form,
        // 4 + body.len() for the 32-bit form.
        if count <= 0xff && body.len() < 0xff {
            self.buf.push(code8);
            self.buf.push((body.len() + 1) as u8);
            self.buf.push(count as u8);
        } else {
            self.buf.push(code32);
            self.buf.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
            self.buf.extend_from_slice(&count.to_be_bytes());
        }
        self.buf.extend_from_slice(&body);
    }

    /// A described value: `0x00`, the descriptor's encoding, then the
    /// value's own encoding.
    pub fn described_value(&mut self, descriptor: &Value, value: &Value) {
        self.buf.push(DESCRIBED);
        self.value(descriptor);
        self.value(value);
    }

    /// A described value whose descriptor is the compact `smallulong` form
    /// of a performative/section code (every descriptor used by this
    /// client fits in one octet).
    pub fn described(&mut self, descriptor_code: u8, value: &Value) {
        self.described_value(&Value::Ulong(descriptor_code as u64), value);
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: &Value) {
        let mut enc = Encoder::new();
        enc.value(v);
        let bytes = enc.into_bytes();
        let (decoded, consumed) = decode(&bytes).expect("decode");
        assert_eq!(consumed, bytes.len());
        assert_eq!(&decoded, v);
    }

    #[test]
    fn primitives_roundtrip() {
        roundtrip(&Value::Null);
        roundtrip(&Value::Bool(true));
        roundtrip(&Value::Bool(false));
        roundtrip(&Value::Ubyte(200));
        roundtrip(&Value::Ushort(50000));
        roundtrip(&Value::Uint(0));
        roundtrip(&Value::Uint(200));
        roundtrip(&Value::Uint(70000));
        roundtrip(&Value::Ulong(0));
        roundtrip(&Value::Ulong(200));
        roundtrip(&Value::Ulong(1 << 40));
        roundtrip(&Value::Byte(-5));
        roundtrip(&Value::Short(-1000));
        roundtrip(&Value::Int(-5));
        roundtrip(&Value::Int(100_000));
        roundtrip(&Value::Long(-5));
        roundtrip(&Value::Long(1_i64 << 40));
        roundtrip(&Value::Float(1.5));
        roundtrip(&Value::Double(-2.5));
        roundtrip(&Value::Char('R'));
        roundtrip(&Value::Timestamp(1_700_000_000_000));
        roundtrip(&Value::Uuid([7; 16]));
        roundtrip(&Value::Binary(vec![1, 2, 3]));
        roundtrip(&Value::String("hello amqp1".into()));
        roundtrip(&Value::Symbol("amqp:internal-error".into()));
    }

    #[test]
    fn large_binary_uses_vbin32() {
        let big = vec![9u8; 300];
        roundtrip(&Value::Binary(big));
    }

    #[test]
    fn list_and_map_roundtrip() {
        roundtrip(&Value::List(vec![Value::Uint(1), Value::Symbol("x".into()), Value::Null]));
        roundtrip(&Value::Map(vec![
            (Value::Symbol("k1".into()), Value::Uint(1)),
            (Value::Symbol("k2".into()), Value::Binary(vec![1, 2])),
        ]));
        roundtrip(&Value::List(vec![]));
    }

    #[test]
    fn nested_list_roundtrips() {
        let inner = Value::List(vec![Value::Uint(1), Value::Uint(2)]);
        roundtrip(&Value::List(vec![inner, Value::Null]));
    }

    #[test]
    fn symbol_array_roundtrips() {
        let mut enc = Encoder::new();
        enc.symbol_array(&["one".into(), "two".into(), "three".into()]);
        let bytes = enc.into_bytes();
        let (decoded, n) = decode(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(
            decoded.as_symbol_multiple(),
            Some(vec!["one".to_string(), "two".to_string(), "three".to_string()])
        );
    }

    #[test]
    fn described_value_roundtrips() {
        let v = Value::Described(Box::new(Value::Ulong(0x10)), Box::new(Value::List(vec![Value::Uint(5)])));
        roundtrip(&v);
    }

    #[test]
    fn truncated_value_is_malformed_not_panic() {
        assert!(decode(&[UINT, 0, 0]).is_err());
        assert!(decode(&[VBIN8, 10, 1, 2]).is_err());
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn unknown_format_code_errors() {
        match decode(&[0xff]) {
            Err(Amqp1Error::UnknownFormatCode(0xff)) => {}
            other => panic!("expected UnknownFormatCode, got {other:?}"),
        }
    }

    #[test]
    fn value_length_probes_without_full_payload() {
        // vbin32 declaring 1000 bytes: length is knowable from the 5-byte
        // header alone, well before the 1000 payload bytes arrive.
        let mut header = vec![VBIN32];
        header.extend_from_slice(&1000u32.to_be_bytes());
        assert_eq!(value_length(&header).unwrap(), Some(1005));

        // Not even the size field is fully buffered yet.
        assert_eq!(value_length(&[VBIN32, 0, 0]).unwrap(), None);
        assert_eq!(value_length(&[VBIN8]).unwrap(), None);
        assert_eq!(value_length(&[]).unwrap(), None);
    }

    #[test]
    fn value_length_matches_actual_encoded_length() {
        for v in [
            Value::Null,
            Value::Uint(70000),
            Value::Binary(vec![1; 500]),
            Value::List(vec![Value::Uint(1), Value::Symbol("x".into())]),
            Value::Described(Box::new(Value::Ulong(0x75)), Box::new(Value::Binary(vec![9; 42]))),
        ] {
            let mut enc = Encoder::new();
            enc.value(&v);
            let bytes = enc.into_bytes();
            assert_eq!(value_length(&bytes).unwrap(), Some(bytes.len()), "value: {v:?}");
        }
    }

    #[test]
    fn deeply_nested_list_is_rejected() {
        // Build a list nested deeper than MAX_DEPTH by wrapping repeatedly.
        let mut v = Value::List(vec![Value::Null]);
        for _ in 0..MAX_DEPTH + 5 {
            v = Value::List(vec![v]);
        }
        let mut enc = Encoder::new();
        enc.value(&v);
        assert!(decode(&enc.into_bytes()).is_err());
    }
}
