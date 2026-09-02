// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Context ID codec for HTTP Datagram payloads (RFC 9298 §5, reused
//! unchanged by RFC 9484 §5).
//!
//! Plain HTTP Datagrams (RFC 9297) carry an opaque payload — [`h3::datagram`](crate::h3::datagram)
//! frames it for the wire, [`capsule`](crate::capsule) frames the
//! capsule-protocol fallback, and neither looks inside it. RFC 9298
//! layers one more thing on top for protocols (CONNECT-UDP, and RFC 9484
//! CONNECT-IP after it) that need to multiplex several logical flows over
//! one request's datagram channel: every payload is prefixed with a
//! Context ID, a QUIC variable-length integer (RFC 9000 §16). Context ID
//! `0` is reserved for the payload registered to the request itself (the
//! proxied UDP datagram or IP packet); other values are free for the
//! protocol layered on top to assign.

use crate::varint;

/// The Context ID reserved for the payload registered to the request
/// itself (RFC 9298 §5) — the proxied UDP datagram or IP packet, as
/// opposed to a value a protocol layered on top assigns for some other
/// purpose.
pub const REGISTERED_CONTEXT_ID: u64 = 0;

/// Prefix `payload` with `context_id` as a QUIC varint.
pub fn encode(context_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    varint::encode(&mut out, context_id);
    out.extend_from_slice(payload);
    out
}

/// Split `data` into `(context_id, payload)`.
///
/// Returns `None` only when `data` doesn't hold a complete varint — an
/// unrecognized-but-well-formed Context ID is not an error at this layer:
/// RFC 9298 §5 says to ignore a datagram whose Context ID isn't in use,
/// not to reset the stream, so deciding what to do with an unknown value
/// is the caller's job.
pub fn decode(data: &[u8]) -> Option<(u64, &[u8])> {
    let (context_id, len) = varint::decode(data)?;
    Some((context_id, &data[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_registered_context_id() {
        let encoded = encode(REGISTERED_CONTEXT_ID, b"udp payload");
        assert_eq!(decode(&encoded), Some((0, &b"udp payload"[..])));
    }

    #[test]
    fn round_trips_a_nonzero_context_id() {
        let encoded = encode(7, b"payload");
        assert_eq!(decode(&encoded), Some((7, &b"payload"[..])));
    }

    #[test]
    fn round_trips_an_empty_payload() {
        let encoded = encode(3, b"");
        assert_eq!(decode(&encoded), Some((3, &b""[..])));
    }

    #[test]
    fn round_trips_context_ids_needing_a_multi_byte_varint() {
        // 64 is the smallest value QUIC's varint encoding no longer fits in
        // one byte for (RFC 9000 §16) — confirms the prefix length isn't
        // hard-coded to the common single-byte case.
        let encoded = encode(64, b"x");
        assert_eq!(encoded.len(), 2 + 1);
        assert_eq!(decode(&encoded), Some((64, &b"x"[..])));
    }

    #[test]
    fn decode_rejects_empty_input() {
        assert_eq!(decode(&[]), None);
    }

    #[test]
    fn decode_rejects_a_truncated_multi_byte_varint() {
        // The leading byte's top two bits (`0x40`) say "2-byte varint", but
        // only one byte is actually present.
        assert_eq!(decode(&[0x40]), None);
    }

    #[test]
    fn decode_accepts_an_unrecognized_but_well_formed_context_id() {
        // Per RFC 9298 §5, an unrecognized Context ID is the caller's
        // concern (ignore the datagram), not this codec's — it must still
        // decode cleanly.
        let encoded = encode(999_999, b"data");
        assert_eq!(decode(&encoded), Some((999_999, &b"data"[..])));
    }
}
