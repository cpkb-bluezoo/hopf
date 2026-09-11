// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DTLS handshake-message fragmentation and reassembly (RFC 9147 §5.2).
//!
//! DTLS's handshake header adds `message_seq`/`fragment_offset`/
//! `fragment_length` (12 bytes total) on top of TLS's `{type(1),
//! length(3)}` (4 bytes) — needed because UDP can lose, reorder, or
//! duplicate the individual DTLS records fragments travel in, none of
//! which TCP/QUIC's reliable, ordered byte streams need to worry about.
//! RFC 9147 §5.2 also specifies that the *transcript hash* uses the TLS
//! 4-byte form, not this 12-byte one — so this module's job is exactly to
//! translate between the two: on write, wrap a complete TLS-shaped message
//! `{type(1), length(3), body}` (what [`crate::tls::HandshakeEngine`]
//! already emits) into one or more DTLS-framed fragments; on read,
//! reassemble arbitrarily reordered/duplicated fragments back into
//! complete TLS-shaped messages, delivered to the engine strictly in
//! `message_seq` order (the engine's transcript/FSM assumes ordered
//! delivery, same as it already does for TCP/QUIC).

use std::collections::BTreeMap;

/// Conservative fragment size — well under a typical safe UDP path MTU
/// (1500-byte Ethernet frame minus IP/UDP/DTLS-record overhead), not tied
/// to any PMTU discovery (none implemented).
pub const MAX_FRAGMENT: usize = 1024;

struct PartialMessage {
    msg_type: u8,
    body: Vec<u8>,
    received: Vec<bool>,
}

impl PartialMessage {
    fn new(msg_type: u8, total_len: usize) -> Self {
        Self {
            msg_type,
            body: vec![0u8; total_len],
            received: vec![false; total_len],
        }
    }

    fn add_fragment(&mut self, offset: usize, data: &[u8]) {
        let Some(end) = offset.checked_add(data.len()) else {
            return;
        };
        if end > self.body.len() {
            return; // malformed fragment claiming to extend past the message's own total length
        }
        self.body[offset..end].copy_from_slice(data);
        self.received[offset..end].fill(true);
    }

    fn is_complete(&self) -> bool {
        self.received.iter().all(|&b| b)
    }
}

/// Fragments outgoing handshake messages and reassembles incoming ones.
/// One instance per direction pair is enough — `message_seq` counters for
/// write and read are independent (RFC 9147 §5.2: each side numbers its
/// own messages from 0, unlike TLS record sequence numbers which are
/// per-epoch-per-direction).
#[derive(Default)]
pub struct Reassembler {
    next_write_message_seq: u16,
    next_read_message_seq: u16,
    pending: BTreeMap<u16, PartialMessage>,
}

impl Reassembler {
    /// New reassembler with both counters at 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fragment one complete TLS-shaped handshake message
    /// (`{type(1), length(3), body}`, exactly what
    /// [`crate::tls::sink::TlsEventSink::handshake_data_ready`] hands over)
    /// into DTLS-framed fragments, each pushed as one element of `out`.
    /// The caller (this crate's `dtls::engine`) wraps each into its own
    /// `DTLSCiphertext` record — this function only produces fragment
    /// bytes, it doesn't touch the record layer.
    pub fn fragment(&mut self, tls_message: &[u8], out: &mut Vec<Vec<u8>>) {
        if tls_message.len() < 4 {
            return;
        }
        let msg_type = tls_message[0];
        let total_len =
            u32::from_be_bytes([0, tls_message[1], tls_message[2], tls_message[3]]) as usize;
        let body = &tls_message[4..(4 + total_len).min(tls_message.len())];
        let message_seq = self.next_write_message_seq;
        self.next_write_message_seq = self.next_write_message_seq.wrapping_add(1);

        if body.is_empty() {
            out.push(dtls_fragment_header(msg_type, total_len, message_seq, 0, 0));
            return;
        }
        let mut offset = 0;
        while offset < body.len() {
            let chunk_len = (body.len() - offset).min(MAX_FRAGMENT);
            let mut frag = dtls_fragment_header(msg_type, total_len, message_seq, offset, chunk_len);
            frag.extend_from_slice(&body[offset..offset + chunk_len]);
            out.push(frag);
            offset += chunk_len;
        }
    }

    /// Feed one DTLS-framed fragment (already stripped of any record-layer
    /// framing — this is the plaintext payload of one `handshake`-content-type
    /// record). Returns zero or more now-deliverable complete messages, as
    /// TLS-shaped bytes, in ascending `message_seq` order — draining any
    /// buffered fragments/messages that were waiting on this one to unblock
    /// their turn.
    pub fn receive_fragment(&mut self, fragment: &[u8]) -> Vec<Vec<u8>> {
        let Some((msg_type, total_len, message_seq, fragment_offset, data)) =
            parse_dtls_fragment_header(fragment)
        else {
            return Vec::new();
        };
        if message_seq < self.next_read_message_seq {
            return Vec::new(); // already delivered (a retransmitted flight) — drop
        }
        let entry = self
            .pending
            .entry(message_seq)
            .or_insert_with(|| PartialMessage::new(msg_type, total_len));
        entry.add_fragment(fragment_offset, data);

        let mut out = Vec::new();
        while let Some(pm) = self.pending.get(&self.next_read_message_seq) {
            if !pm.is_complete() {
                break;
            }
            let pm = self.pending.remove(&self.next_read_message_seq).unwrap();
            let mut tls_shaped = Vec::with_capacity(4 + pm.body.len());
            tls_shaped.push(pm.msg_type);
            tls_shaped.extend_from_slice(&(pm.body.len() as u32).to_be_bytes()[1..]);
            tls_shaped.extend_from_slice(&pm.body);
            out.push(tls_shaped);
            self.next_read_message_seq = self.next_read_message_seq.wrapping_add(1);
        }
        out
    }
}

/// Build one DTLS handshake fragment header + nothing else (caller appends
/// the fragment's own bytes) — `{type(1), length(3)=total, message_seq(2),
/// fragment_offset(3), fragment_length(3)}` (RFC 9147 §5.2).
fn dtls_fragment_header(msg_type: u8, total_len: usize, message_seq: u16, fragment_offset: usize, fragment_length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + fragment_length);
    out.push(msg_type);
    out.extend_from_slice(&(total_len as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&message_seq.to_be_bytes());
    out.extend_from_slice(&(fragment_offset as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&(fragment_length as u32).to_be_bytes()[1..]);
    out
}

/// Parse one DTLS handshake fragment: `(msg_type, total_len, message_seq,
/// fragment_offset, fragment_data)`.
fn parse_dtls_fragment_header(data: &[u8]) -> Option<(u8, usize, u16, usize, &[u8])> {
    if data.len() < 12 {
        return None;
    }
    let msg_type = data[0];
    let total_len = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
    let message_seq = u16::from_be_bytes([data[4], data[5]]);
    let fragment_offset = u32::from_be_bytes([0, data[6], data[7], data[8]]) as usize;
    let fragment_length = u32::from_be_bytes([0, data[9], data[10], data[11]]) as usize;
    if data.len() < 12 + fragment_length {
        return None;
    }
    Some((msg_type, total_len, message_seq, fragment_offset, &data[12..12 + fragment_length]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_an_unfragmented_message() {
        let mut w = Reassembler::new();
        let mut r = Reassembler::new();
        let mut body = vec![0u8; 4];
        body[3] = 42; // small body, well under MAX_FRAGMENT
        let tls_message = {
            let mut m = vec![1u8, 0, 0, body.len() as u8];
            m.extend_from_slice(&body);
            m
        };
        let mut fragments = Vec::new();
        w.fragment(&tls_message, &mut fragments);
        assert_eq!(fragments.len(), 1, "small message shouldn't split");
        let delivered = r.receive_fragment(&fragments[0]);
        assert_eq!(delivered, vec![tls_message]);
    }

    #[test]
    fn splits_and_reassembles_a_large_message() {
        let mut w = Reassembler::new();
        let mut r = Reassembler::new();
        let body = vec![0x7au8; MAX_FRAGMENT * 2 + 100];
        let tls_message = {
            let mut m = vec![11u8]; // Certificate
            m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
            m.extend_from_slice(&body);
            m
        };
        let mut fragments = Vec::new();
        w.fragment(&tls_message, &mut fragments);
        assert_eq!(fragments.len(), 3);

        let mut delivered = Vec::new();
        for f in &fragments {
            delivered.extend(r.receive_fragment(f));
        }
        assert_eq!(delivered, vec![tls_message]);
    }

    #[test]
    fn reassembles_fragments_arriving_out_of_order() {
        let mut w = Reassembler::new();
        let mut r = Reassembler::new();
        let body = vec![0x11u8; MAX_FRAGMENT * 2 + 50];
        let tls_message = {
            let mut m = vec![11u8];
            m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
            m.extend_from_slice(&body);
            m
        };
        let mut fragments = Vec::new();
        w.fragment(&tls_message, &mut fragments);
        assert_eq!(fragments.len(), 3);

        assert!(r.receive_fragment(&fragments[2]).is_empty());
        assert!(r.receive_fragment(&fragments[0]).is_empty());
        let delivered = r.receive_fragment(&fragments[1]);
        assert_eq!(delivered, vec![tls_message]);
    }

    #[test]
    fn delivers_messages_only_in_message_seq_order() {
        let mut w = Reassembler::new();
        let mut r = Reassembler::new();
        let msg_a = vec![1u8, 0, 0, 1, 0xaa]; // ClientHello-shaped, 1-byte body
        let msg_b = vec![2u8, 0, 0, 1, 0xbb]; // ServerHello-shaped, 1-byte body
        let mut frags_a = Vec::new();
        let mut frags_b = Vec::new();
        w.fragment(&msg_a, &mut frags_a); // message_seq 0
        w.fragment(&msg_b, &mut frags_b); // message_seq 1

        // Second message's fragment arrives first — must not be delivered
        // until the first message completes.
        assert!(r.receive_fragment(&frags_b[0]).is_empty());
        let delivered = r.receive_fragment(&frags_a[0]);
        assert_eq!(delivered, vec![msg_a, msg_b], "both now deliverable, in order");
    }

    #[test]
    fn duplicate_fragment_of_an_already_delivered_message_is_ignored() {
        let mut w = Reassembler::new();
        let mut r = Reassembler::new();
        let msg = vec![20u8, 0, 0, 1, 0x01]; // Finished-shaped
        let mut frags = Vec::new();
        w.fragment(&msg, &mut frags);
        assert_eq!(r.receive_fragment(&frags[0]), vec![msg]);
        // A retransmitted copy of the same (already-delivered) message must not re-deliver.
        assert!(r.receive_fragment(&frags[0]).is_empty());
    }
}
