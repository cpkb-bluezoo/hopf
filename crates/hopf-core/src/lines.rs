// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Reading CRLF-terminated lines straight out of an inbound [`LoopBuf`].

use loopbuf::LoopBuf;

/// Removes the next complete line from `buf` and returns it without its CRLF.
///
/// `None` if `buf` holds no CRLF yet: it is left as it is, the partial line
/// waiting in the ring for the rest. A lone `\r` or `\n` is part of the line.
pub fn take_crlf_line(buf: &mut LoopBuf) -> Option<Vec<u8>> {
    let (first, second) = buf.readable_spans();
    let (line, used) = if let Some(i) = find_crlf(first) {
        (first[..i].to_vec(), i + 2)
    } else if first.last() == Some(&b'\r') && second.first() == Some(&b'\n') {
        // The CRLF straddles the wrap.
        (first[..first.len() - 1].to_vec(), first.len() + 1)
    } else if let Some(j) = find_crlf(second) {
        let mut line = Vec::with_capacity(first.len() + j);
        line.extend_from_slice(first);
        line.extend_from_slice(&second[..j]);
        (line, first.len() + j + 2)
    } else {
        return None;
    };
    buf.advance(used);
    Some(line)
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_with(bytes: &[u8]) -> LoopBuf {
        let mut buf = LoopBuf::with_capacity(64);
        buf.extend_from_slice(bytes);
        buf
    }

    #[test]
    fn takes_lines_one_at_a_time_and_leaves_a_partial_one() {
        let mut buf = ring_with(b"one\r\ntwo\r\nthr");
        assert_eq!(take_crlf_line(&mut buf).as_deref(), Some(&b"one"[..]));
        assert_eq!(take_crlf_line(&mut buf).as_deref(), Some(&b"two"[..]));
        assert_eq!(take_crlf_line(&mut buf), None);
        assert_eq!(buf.readable_spans().0, b"thr");
        buf.extend_from_slice(b"ee\r\n");
        assert_eq!(take_crlf_line(&mut buf).as_deref(), Some(&b"three"[..]));
        assert!(buf.is_empty());
    }

    #[test]
    fn a_lone_cr_or_lf_is_part_of_the_line() {
        let mut buf = ring_with(b"a\rb\nc\r\n");
        assert_eq!(take_crlf_line(&mut buf).as_deref(), Some(&b"a\rb\nc"[..]));
    }

    #[test]
    fn finds_lines_across_the_wrap_wherever_it_falls() {
        for lead in 0..9 {
            let mut buf = LoopBuf::with_capacity(16);
            buf.extend_from_slice(&vec![0u8; lead + 4]);
            buf.advance(lead + 4);
            // Moves the read position to `lead + 4`, so "hello\r\nworld\r\n"
            // wraps somewhere inside it for most values of `lead`.
            assert_eq!(buf.extend_from_slice(b"hello\r\nworld\r\n"), 14);
            assert_eq!(take_crlf_line(&mut buf).as_deref(), Some(&b"hello"[..]), "lead={lead}");
            assert_eq!(take_crlf_line(&mut buf).as_deref(), Some(&b"world"[..]), "lead={lead}");
            assert_eq!(take_crlf_line(&mut buf), None);
            assert!(buf.is_empty());
        }
    }
}
