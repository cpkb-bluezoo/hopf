// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QPACK support for HTTP/3 (RFC 9204): a real dynamic table
//! ([`H3Qpack`]), plus a static-table-only [`encode`]/[`decode`] pair kept
//! around as a simple building block for tests.

use std::sync::Mutex;

mod decode;
mod decoder;
mod decoder_stream;
mod dynamic;
mod encode;
mod encoder;
mod encoder_stream;
mod insert_count;
mod prefix_int;
mod static_table;
mod strings;

pub use decode::{decode, DecodeError};
pub use encode::encode;

/// Dynamic-table capacity hopf uses for its own decoder (advertised via
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`) and as the upper bound for its
/// encoder once the peer advertises a non-zero capacity. Until peer
/// SETTINGS arrive, RFC 9204 §5 defaults the peer's max to 0 — the encoder
/// must not grow the dynamic table.
pub(crate) const MAX_TABLE_CAPACITY: usize = 4096;

/// Per-connection QPACK state: our own encoder (for outgoing field
/// sections, growing our dynamic table) and our mirror of the peer's
/// dynamic table (for incoming ones), plus bytes queued for our own
/// encoder/decoder uni streams — the only two streams besides the control
/// stream that we open ourselves, and the only ones
/// [`hopf_quic::QuicConnection::drive`] can flush queued writes onto.
pub(crate) struct H3Qpack {
    encoder: Mutex<encoder::Encoder>,
    decoder: Mutex<decoder::Decoder>,
    pending_encoder_stream: Mutex<Vec<u8>>,
    pending_decoder_stream: Mutex<Vec<u8>>,
}

impl H3Qpack {
    pub(crate) fn new() -> Self {
        // Encoder starts at capacity 0: RFC 9204 §5 defaults the peer's
        // SETTINGS_QPACK_MAX_TABLE_CAPACITY to 0 until SETTINGS arrives.
        // Decoder uses our advertised ceiling immediately.
        Self {
            encoder: Mutex::new(encoder::Encoder::new(0)),
            decoder: Mutex::new(decoder::Decoder::new(MAX_TABLE_CAPACITY)),
            pending_encoder_stream: Mutex::new(Vec::new()),
            pending_decoder_stream: Mutex::new(Vec::new()),
        }
    }

    /// Apply the peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY` as our encoder's
    /// ceiling (clamped to [`MAX_TABLE_CAPACITY`]). Queues a Set Dynamic
    /// Table Capacity instruction when the value actually changes.
    pub(crate) fn apply_peer_max_table_capacity(&self, peer_max: u64) {
        let cap = usize::try_from(peer_max)
            .unwrap_or(usize::MAX)
            .min(MAX_TABLE_CAPACITY);
        let mut enc = self.encoder.lock().unwrap();
        if enc.capacity() == cap {
            return;
        }
        let instructions = enc.set_capacity(cap);
        if !instructions.is_empty() {
            self.pending_encoder_stream
                .lock()
                .unwrap()
                .extend_from_slice(&instructions);
        }
    }

    /// Encode a field section for `stream_id`, queuing any resulting
    /// encoder-stream instructions for the next flush.
    ///
    /// Field names are lowercased (RFC 9114 §4.2 / RFC 9110 §5.1) so
    /// callers can keep HTTP/1-style canonical casing in [`crate::Headers`].
    pub(crate) fn encode_field_section<'a>(
        &self,
        stream_id: u64,
        fields: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Vec<u8> {
        let lowered: Vec<(String, &str)> = fields
            .into_iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), v))
            .collect();
        let (section, instructions) = self
            .encoder
            .lock()
            .unwrap()
            .encode(stream_id, lowered.iter().map(|(n, v)| (n.as_str(), *v)));
        if !instructions.is_empty() {
            self.pending_encoder_stream.lock().unwrap().extend_from_slice(&instructions);
        }
        section
    }

    /// Decode a field section received on `stream_id`, queuing any
    /// resulting Section Acknowledgment for the next flush. `Err` means
    /// the block is malformed or (against a misbehaving peer) requires
    /// blocking — the caller should close the connection with
    /// `QPACK_DECOMPRESSION_FAILED` (RFC 9204 §4.5.1).
    pub(crate) fn decode_field_section(&self, stream_id: u64, block: &[u8]) -> Result<Vec<(String, String)>, ()> {
        let (fields, ack) = self.decoder.lock().unwrap().decode(stream_id, block).map_err(|_| ())?;
        if !ack.is_empty() {
            self.pending_decoder_stream.lock().unwrap().extend_from_slice(&ack);
        }
        Ok(fields)
    }

    /// Feed newly-received bytes from the peer's encoder stream, applying
    /// every complete instruction and leaving any trailing partial one in
    /// `buf` for next time. `Err` means a malformed instruction — the
    /// caller should close the connection with `QPACK_ENCODER_STREAM_ERROR`
    /// (RFC 9204 §4.3).
    pub(crate) fn feed_encoder_stream(&self, buf: &mut Vec<u8>) -> Result<(), ()> {
        loop {
            match encoder_stream::parse_next(buf) {
                Ok(Some((instr, used))) => {
                    buf.drain(..used);
                    let ack = self.decoder.lock().unwrap().apply_encoder_instruction(instr).map_err(|_| ())?;
                    if !ack.is_empty() {
                        self.pending_decoder_stream.lock().unwrap().extend_from_slice(&ack);
                    }
                }
                Ok(None) => return Ok(()),
                Err(_) => return Err(()),
            }
        }
    }

    /// Feed newly-received bytes from the peer's decoder stream, applying
    /// every complete instruction and leaving any trailing partial one in
    /// `buf` for next time. `Err` means a malformed instruction — the
    /// caller should close the connection with `QPACK_DECODER_STREAM_ERROR`
    /// (RFC 9204 §4.4).
    pub(crate) fn feed_decoder_stream(&self, buf: &mut Vec<u8>) -> Result<(), ()> {
        loop {
            match decoder_stream::parse_next(buf)? {
                Some((instr, used)) => {
                    buf.drain(..used);
                    let mut enc = self.encoder.lock().unwrap();
                    match instr {
                        decoder_stream::DecoderInstruction::SectionAcknowledgment { stream_id } => {
                            enc.on_section_acknowledgment(stream_id)?;
                        }
                        decoder_stream::DecoderInstruction::StreamCancellation { stream_id } => {
                            enc.on_stream_cancellation(stream_id);
                        }
                        decoder_stream::DecoderInstruction::InsertCountIncrement { increment } => {
                            enc.on_insert_count_increment(increment)?;
                        }
                    }
                }
                None => return Ok(()),
            }
        }
    }

    /// Queue a Stream Cancellation for `stream_id` (RFC 9204 §4.4.2) — call
    /// when a stream we were decoding is reset or abandoned before we could
    /// acknowledge it, so the peer's encoder can release any dynamic-table
    /// references it was holding open on our behalf. Harmless to call for
    /// a stream that never referenced the dynamic table, or was already
    /// fully acknowledged — the peer just finds nothing to release.
    pub(crate) fn cancel_stream(&self, stream_id: u64) {
        let mut out = Vec::new();
        decoder_stream::write_stream_cancellation(&mut out, stream_id);
        self.pending_decoder_stream.lock().unwrap().extend_from_slice(&out);
    }

    /// Take any bytes queued for our own encoder stream and our own
    /// decoder stream, for the caller to write onto those streams.
    pub(crate) fn take_pending(&self) -> (Vec<u8>, Vec<u8>) {
        (
            std::mem::take(&mut *self.pending_encoder_stream.lock().unwrap()),
            std::mem::take(&mut *self.pending_decoder_stream.lock().unwrap()),
        )
    }

    #[cfg(test)]
    pub(crate) fn encoder_capacity_for_test(&self) -> usize {
        self.encoder.lock().unwrap().capacity()
    }
}

#[cfg(test)]
mod h3qpack_tests {
    use super::*;

    /// Two independent [`H3Qpack`] instances, wired byte-for-byte the way
    /// [`super::super::endpoint::H3UniStream`]/[`super::super::client::H3ClientStream`]
    /// do in real traffic — proves the whole instruction pipeline (encoder
    /// stream, decoder stream, and the field-line codec) actually
    /// round-trips across multiple requests, not just each piece in
    /// isolation.
    #[test]
    fn two_peers_exchange_qpack_state_across_multiple_requests() {
        let client = H3Qpack::new();
        let server = H3Qpack::new();

        // Simulate SETTINGS exchange: each side learns the peer's
        // SETTINGS_QPACK_MAX_TABLE_CAPACITY and may then grow its encoder.
        assert_eq!(client.encoder_capacity_for_test(), 0);
        client.apply_peer_max_table_capacity(MAX_TABLE_CAPACITY as u64);
        server.apply_peer_max_table_capacity(MAX_TABLE_CAPACITY as u64);
        assert_eq!(client.encoder_capacity_for_test(), MAX_TABLE_CAPACITY);

        // Each side's "Set Dynamic Table Capacity" announcement.
        let (mut client_enc_out, _) = client.take_pending();
        assert!(!client_enc_out.is_empty(), "expected set-capacity after peer SETTINGS");
        server.feed_encoder_stream(&mut client_enc_out).unwrap();
        let (mut server_enc_out, _) = server.take_pending();
        client.feed_encoder_stream(&mut server_enc_out).unwrap();

        // First request: nothing indexable yet, gets inserted for reuse.
        let section1 = client.encode_field_section(0, [("x-custom", "widget"), (":path", "/")]);
        let (mut client_enc_out, _) = client.take_pending();
        assert!(!client_enc_out.is_empty(), "expected an insert instruction");
        server.feed_encoder_stream(&mut client_enc_out).unwrap();

        let fields1 = server.decode_field_section(0, &section1).unwrap();
        assert_eq!(
            fields1,
            vec![("x-custom".into(), "widget".into()), (":path".into(), "/".into())]
        );

        // Server's Section Acknowledgment flows back to the client's encoder.
        let (_, mut server_dec_out) = server.take_pending();
        assert!(!server_dec_out.is_empty(), "expected a section acknowledgment");
        client.feed_decoder_stream(&mut server_dec_out).unwrap();

        // Second request: "x-custom: widget" is now known-received, so the
        // client references it by index instead of re-sending it.
        let section2 = client.encode_field_section(1, [("x-custom", "widget")]);
        let (client_enc_out2, _) = client.take_pending();
        assert!(client_enc_out2.is_empty(), "expected a dynamic-table hit, no new insert");

        let fields2 = server.decode_field_section(1, &section2).unwrap();
        assert_eq!(fields2, vec![("x-custom".into(), "widget".into())]);
    }

    #[test]
    fn encoder_stays_at_zero_until_peer_advertises_capacity() {
        let q = H3Qpack::new();
        assert_eq!(q.encoder_capacity_for_test(), 0);
        // Peer SETTINGS omitted the setting → default 0; still no growth.
        q.apply_peer_max_table_capacity(0);
        assert_eq!(q.encoder_capacity_for_test(), 0);
        let (pending, _) = q.take_pending();
        assert!(pending.is_empty(), "capacity 0→0 must not emit a set-capacity");

        // Peer advertises less than our ceiling — honour their value.
        q.apply_peer_max_table_capacity(1024);
        assert_eq!(q.encoder_capacity_for_test(), 1024);
        let (pending, _) = q.take_pending();
        assert!(!pending.is_empty());

        // Peer advertises more than our ceiling — clamp.
        q.apply_peer_max_table_capacity(u64::from(u32::MAX));
        assert_eq!(q.encoder_capacity_for_test(), MAX_TABLE_CAPACITY);
    }

    #[test]
    fn feed_decoder_stream_rejects_zero_insert_count_increment() {
        let q = H3Qpack::new();
        let mut buf = Vec::new();
        super::decoder_stream::write_insert_count_increment(&mut buf, 0);
        assert!(q.feed_decoder_stream(&mut buf).is_err());
    }

    #[test]
    fn feed_decoder_stream_rejects_increment_beyond_sent_inserts() {
        let q = H3Qpack::new();
        let mut buf = Vec::new();
        super::decoder_stream::write_insert_count_increment(&mut buf, 1);
        assert!(q.feed_decoder_stream(&mut buf).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_status_200() {
        let block = encode([(":status", "200")]);
        assert_eq!(
            decode(&block).unwrap(),
            vec![(":status".into(), "200".into())]
        );
    }

    /// A long, highly-compressible literal value must actually be
    /// Huffman-coded (RFC 9204 §4.5.1's `H` bit set), and round-trip
    /// correctly through the decoder.
    #[test]
    fn long_literal_value_is_huffman_coded_and_round_trips() {
        let value = "a".repeat(200); // 'a' Huffman-codes to 5 bits, so this compresses well
        let block = encode([("x-custom-header", value.as_str())]);

        // The encoded block must be shorter than the raw header would need
        // (proves Huffman actually fired, not just literal passthrough).
        assert!(
            block.len() < value.len(),
            "expected Huffman compression to shrink a 200x repeated byte, got {} bytes for a {}-byte value",
            block.len(),
            value.len()
        );

        assert_eq!(decode(&block).unwrap(), vec![("x-custom-header".into(), value)]);
    }

    /// A value that doesn't compress (already-dense byte patterns) must
    /// still round-trip via the literal (non-Huffman) fallback.
    #[test]
    fn incompressible_value_falls_back_to_literal_and_round_trips() {
        // Short pseudo-random-looking value where Huffman wouldn't help.
        let value = "Q7z$k2!Xv9@pL";
        let block = encode([("x-token", value)]);
        assert_eq!(decode(&block).unwrap(), vec![("x-token".into(), value.to_string())]);
    }
}
