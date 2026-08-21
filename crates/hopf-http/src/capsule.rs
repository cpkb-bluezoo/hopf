// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Capsule Protocol (RFC 9297 §3) — TLV on an HTTP data stream.

use crate::varint;

/// `DATAGRAM` capsule type (RFC 9297 §3.5).
pub const CAPSULE_DATAGRAM: u64 = 0x00;

/// One Capsule (RFC 9297 §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    /// Capsule Type (varint).
    pub ty: u64,
    /// Capsule Value.
    pub value: Vec<u8>,
}

impl Capsule {
    /// Construct a [`CAPSULE_DATAGRAM`] capsule carrying `payload`.
    pub fn datagram(payload: impl Into<Vec<u8>>) -> Self {
        Self {
            ty: CAPSULE_DATAGRAM,
            value: payload.into(),
        }
    }

    /// Encode this capsule onto `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        varint::encode(out, self.ty);
        varint::encode(out, self.value.len() as u64);
        out.extend_from_slice(&self.value);
    }

    /// Encode into a new buffer.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

/// Incremental Capsule Protocol parser (RFC 9297 §3.2).
///
/// Feeds bytes from the HTTP data stream (H1 body / H2–H3 DATA). Unknown
/// capsule types are surfaced so the caller can skip or forward them.
#[derive(Debug, Default)]
pub struct CapsuleParser {
    buf: Vec<u8>,
}

impl CapsuleParser {
    /// Create an empty parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push inbound bytes and return every complete capsule.
    ///
    /// Returns `Err(())` if a capsule is malformed (inconsistent length /
    /// truncated after stream end is the caller's responsibility — call
    /// [`finish`](Self::finish) on clean FIN).
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Capsule>, ()> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            match try_parse_one(&self.buf)? {
                None => break,
                Some((capsule, consumed)) => {
                    self.buf.drain(..consumed);
                    out.push(capsule);
                }
            }
        }
        Ok(out)
    }

    /// Signal that the receive side ended cleanly. Returns `Err` if a
    /// partial capsule remains (RFC 9297 §3.3).
    pub fn finish(&self) -> Result<(), ()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn try_parse_one(buf: &[u8]) -> Result<Option<(Capsule, usize)>, ()> {
    let Some((ty, n_ty)) = varint::decode(buf) else {
        return Ok(None);
    };
    let Some((len, n_len)) = varint::decode(&buf[n_ty..]) else {
        return Ok(None);
    };
    let header = n_ty + n_len;
    let len = usize::try_from(len).map_err(|_| ())?;
    if buf.len() < header + len {
        return Ok(None);
    }
    let value = buf[header..header + len].to_vec();
    Ok(Some((Capsule { ty, value }, header + len)))
}

/// `Capsule-Protocol` structured-field boolean header name (RFC 9297 §3.4).
pub const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";

/// True when `headers` carry `Capsule-Protocol: ?1` (Item Structured Field
/// boolean true). List / other types are treated as absent per §3.4.
pub fn capsule_protocol_enabled(headers: &crate::Headers) -> bool {
    let Some(raw) = headers.get(CAPSULE_PROTOCOL_HEADER) else {
        return false;
    };
    // Accept common spellings of SF boolean true.
    let v = raw.trim();
    v == "?1" || v.eq_ignore_ascii_case("true") || v == "1"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Headers;

    #[test]
    fn datagram_capsule_round_trip() {
        let c = Capsule::datagram(b"ping");
        let bytes = c.to_bytes();
        let mut p = CapsuleParser::new();
        let got = p.push(&bytes).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ty, CAPSULE_DATAGRAM);
        assert_eq!(got[0].value, b"ping");
        p.finish().unwrap();
    }

    #[test]
    fn split_across_pushes() {
        let bytes = Capsule::datagram(b"abcdef").to_bytes();
        let mut p = CapsuleParser::new();
        assert!(p.push(&bytes[..2]).unwrap().is_empty());
        let got = p.push(&bytes[2..]).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, b"abcdef");
    }

    #[test]
    fn unknown_type_is_surfaced() {
        let mut c = Capsule {
            ty: 0x99,
            value: b"x".to_vec(),
        };
        let bytes = c.to_bytes();
        let mut p = CapsuleParser::new();
        let got = p.push(&bytes).unwrap();
        assert_eq!(got[0].ty, 0x99);
        // silence unused mut
        c.value.clear();
    }

    #[test]
    fn finish_rejects_truncated() {
        let mut p = CapsuleParser::new();
        let _ = p.push(&[0x00]).unwrap();
        assert!(p.finish().is_err());
    }

    #[test]
    fn capsule_protocol_header_true() {
        let mut h = Headers::new();
        h.set("Capsule-Protocol", "?1");
        assert!(capsule_protocol_enabled(&h));
        let mut h2 = Headers::new();
        h2.set("capsule-protocol", "?0");
        assert!(!capsule_protocol_enabled(&h2));
    }
}
