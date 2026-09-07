// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Packet number encode / decode (RFC 9000 §17.1, Appendix A).

/// Encoding length (1–4) given largest acked in this space (`None` if none).
pub fn encoded_length(full_pn: u64, largest_acked: Option<u64>) -> usize {
    let num_unacked = match largest_acked {
        None => full_pn + 1,
        Some(a) => full_pn.saturating_sub(a),
    };
    let min_bits = if num_unacked == 0 {
        1
    } else {
        64 - num_unacked.leading_zeros() as usize + 1
    };
    ((min_bits + 7) / 8).clamp(1, 4)
}

/// Write low-order `length` bytes of `full_pn` big-endian into `out`.
pub fn encode(full_pn: u64, length: usize, out: &mut [u8]) {
    debug_assert!((1..=4).contains(&length));
    debug_assert!(out.len() >= length);
    for i in 0..length {
        let shift = 8 * (length - 1 - i);
        out[i] = ((full_pn >> shift) & 0xff) as u8;
    }
}

/// Reconstruct full packet number (RFC 9000 Appendix A DecodePacketNumber).
pub fn decode(largest_received: Option<u64>, truncated: u64, length: usize) -> u64 {
    let expected = match largest_received {
        Some(n) => n.wrapping_add(1),
        None => 0,
    };
    let pn_bits = length * 8;
    let pn_window = 1u64 << pn_bits;
    let pn_half = pn_window / 2;
    let pn_mask = pn_window - 1;
    let candidate = (expected & !pn_mask) | truncated;
    // Use wrapping signed compare as in the RFC (expected - pn_half may be negative).
    let expected_i = expected as i128;
    let candidate_i = candidate as i128;
    let half = pn_half as i128;
    if candidate_i <= expected_i - half && candidate < (1u64 << 62).saturating_sub(pn_window) {
        return candidate.wrapping_add(pn_window);
    }
    if candidate_i > expected_i + half && candidate >= pn_window {
        return candidate.wrapping_sub(pn_window);
    }
    candidate
}

/// Read truncated PN bytes as unsigned big-endian.
pub fn read_truncated(buf: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in buf {
        v = (v << 8) | u64::from(b);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_first_packet() {
        assert_eq!(encoded_length(0, None), 1);
        let mut buf = [0u8; 4];
        encode(0, 1, &mut buf);
        assert_eq!(buf[0], 0);
        assert_eq!(decode(None, 0, 1), 0);
    }

    #[test]
    fn appendix_a_example() {
        // RFC 9000 Appendix A example: largest = 0xa82f30ea, truncated 16-bit 0x9b32
        let full = decode(Some(0xa82f30ea), 0x9b32, 2);
        assert_eq!(full, 0xa82f9b32);
    }
}
