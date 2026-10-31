// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/1.x adapter: one transport [`Endpoint`](hopf_core::Endpoint) → serialized [`HttpStream`]s.
//!
//! Bind or dial creates the Endpoint the same way; [`HttpRole`] selects server vs
//! client codecs. H1 presents Streams one at a time on a single byte pipe.

mod client_codec;
mod encode_request;
mod endpoint;
pub mod parse;
mod response;
mod server_codec;
mod session_client_codec;

pub use client_codec::H1ClientCodec;
pub use endpoint::H1Endpoint;
pub use server_codec::H1ServerCodec;
pub(crate) use session_client_codec::H1SessionClientCodec;

use hopf_core::LoopBuf;

use crate::error::HttpResult;

/// Runs a codec's cursor-based `receive_bytes` over what the inbound ring
/// holds, a span at a time, consuming what it takes. The codecs scan token by
/// token and keep only a bounded token of their own, so a span boundary is
/// no different from a chunk boundary.
///
/// With nothing in the ring it still runs once with an empty cursor: that is
/// how a poke reaches an upgraded handler.
pub(crate) fn over_ring(
    buf: &mut LoopBuf,
    mut receive: impl FnMut(&mut &[u8]) -> HttpResult<()>,
) -> HttpResult<()> {
    if buf.is_empty() {
        return receive(&mut &[][..]);
    }
    let mut result = Ok(());
    loop {
        let first = buf.readable_spans().0;
        if first.is_empty() {
            return result;
        }
        let mut cursor = first;
        let outcome = receive(&mut cursor);
        let used = first.len() - cursor.len();
        buf.advance(used);
        if result.is_ok() {
            result = outcome;
        }
        if used == 0 {
            return result;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn over_ring_visits_both_spans_of_a_wrapped_ring_and_consumes_them() {
        let mut ring = LoopBuf::with_capacity(8);
        ring.extend_from_slice(&[0; 6]);
        ring.advance(6);
        ring.extend_from_slice(b"abcdef");
        assert!(!ring.readable_spans().1.is_empty(), "wrapped");
        let mut seen = Vec::new();
        over_ring(&mut ring, |d| {
            seen.extend_from_slice(d);
            *d = &[];
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, b"abcdef");
        assert!(ring.is_empty());
    }

    #[test]
    fn over_ring_runs_once_on_an_empty_ring() {
        let mut ring = LoopBuf::with_capacity(8);
        let mut calls = 0;
        over_ring(&mut ring, |d| {
            assert!(d.is_empty());
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1);
    }

    #[test]
    fn over_ring_leaves_what_the_codec_does_not_take() {
        let mut ring = LoopBuf::with_capacity(16);
        ring.extend_from_slice(b"abcdef");
        let mut calls = 0;
        over_ring(&mut ring, |_| {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1, "a codec that takes nothing is not asked again");
        assert_eq!(ring.readable_spans().0, b"abcdef");
    }
}
