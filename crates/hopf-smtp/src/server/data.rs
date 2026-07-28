// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DATA dot-unstuffing and BDAT chunk accumulation.

use crate::server::session::DataDotState;

/// RFC 5321 §4.5.2 dot-unstuffer (Gumdrop `processDataBuffer` states).
#[derive(Debug, Default)]
pub struct DotUnstuffer {
    state: DataDotState,
    /// Buffer for emitting contiguous content slices from a feed call.
    /// We accumulate into owned storage when state spans buffers.
    pending: Vec<u8>,
    emit: Vec<u8>,
}

impl DotUnstuffer {
    /// Create unstuffer. Starts in [`DataDotState::SawCrlf`] so a leading
    /// `.\r\n` correctly ends an empty message (RFC line-boundary rule).
    pub fn new() -> Self {
        Self {
            state: DataDotState::SawCrlf,
            pending: Vec::new(),
            emit: Vec::new(),
        }
    }

    /// Reset for a new DATA transfer.
    pub fn reset(&mut self) {
        self.state = DataDotState::SawCrlf;
        self.pending.clear();
        self.emit.clear();
    }

    /// Current scanner state.
    pub fn state(&self) -> DataDotState {
        self.state
    }

    /// Feed inbound DATA bytes. Returns content chunks and optional completion.
    ///
    /// On each call, returns a list of content byte vectors to deliver, plus
    /// whether the transfer completed and any leftover bytes after `.\r\n`.
    pub fn feed(&mut self, input: &[u8]) -> (Vec<Vec<u8>>, Option<usize>) {
        let mut chunks = Vec::new();
        let mut chunk_start = 0usize;
        let mut i = 0usize;
        while i < input.len() {
            let b = input[i];
            match self.state {
                DataDotState::Normal => {
                    if b == b'\r' {
                        self.state = DataDotState::SawCr;
                    }
                    i += 1;
                }
                DataDotState::SawCr => {
                    if b == b'\n' {
                        self.state = DataDotState::SawCrlf;
                    } else if b == b'\r' {
                        // stay SawCr
                    } else {
                        self.state = DataDotState::Normal;
                    }
                    i += 1;
                }
                DataDotState::SawCrlf => {
                    if b == b'.' {
                        // Flush content before the dot (exclude the dot).
                        if i > chunk_start {
                            chunks.push(input[chunk_start..i].to_vec());
                        }
                        self.state = DataDotState::SawDot;
                        i += 1;
                        chunk_start = i;
                    } else {
                        self.state = if b == b'\r' {
                            DataDotState::SawCr
                        } else {
                            DataDotState::Normal
                        };
                        i += 1;
                    }
                }
                DataDotState::SawDot => {
                    if b == b'\r' {
                        self.state = DataDotState::SawDotCr;
                        i += 1;
                    } else {
                        // Stuffed dot: omit the dot (already skipped); emit this byte as content.
                        self.state = if b == b'\r' {
                            DataDotState::SawCr
                        } else {
                            DataDotState::Normal
                        };
                        // chunk_start already after omitted dot; continue including b
                        i += 1;
                    }
                }
                DataDotState::SawDotCr => {
                    if b == b'\n' {
                        // Completing `.\r\n`. Content before `.\r\n` starts at chunk_start
                        // which was set after the `.`, so we should not include `.\r\n`.
                        // Any bytes from chunk_start to (i-1) for `\r` shouldn't be emitted —
                        // chunk_start points after `.`, and we've seen `\r` then `\n`.
                        // The `\r` of terminator was consumed in SawDot without adding to content
                        // wait: when we entered SawDot, chunk_start = after `.`.
                        // Then `\r` moved to SawDotCr without flushing.
                        // So input[chunk_start..i] would be `\r` only if we flush — we must NOT.
                        // Flush nothing from chunk_start..i for terminator.
                        if chunk_start < i.saturating_sub(1) {
                            // There was content between `.` and `\r`? That can't happen in SawDot→SawDotCr
                            // path without going through stuffed-dot. chunk_start == i-1 pointing at `\r`.
                        }
                        // No content to flush for the terminator itself.
                        let consumed = i + 1;
                        self.state = DataDotState::SawCrlf;
                        return (chunks, Some(consumed));
                    } else {
                        // `.\r` + non-LF: treat as stuffed-dot line that had CR?
                        // Emit `.` was skipped; emit `\r` + current as content.
                        // Restore: we need to emit `\r` that was in terminator attempt.
                        let mut extra = Vec::new();
                        extra.push(b'\r');
                        if b != b'\r' {
                            extra.push(b);
                            self.state = DataDotState::Normal;
                        } else {
                            self.state = DataDotState::SawCr;
                        }
                        chunks.push(extra);
                        i += 1;
                        chunk_start = i;
                    }
                }
            }
        }
        if i > chunk_start
            && !matches!(
                self.state,
                DataDotState::SawDot | DataDotState::SawDotCr
            )
        {
            // Don't flush a partial control sequence held at end.
            // For SawCr / SawCrlf we still flush content including the CR/LF
            // (Gumdrop buffers control seq — we flush all for simplicity when
            // not in SawDot*).
            if matches!(self.state, DataDotState::SawCr | DataDotState::SawCrlf) {
                // Keep last 1–2 bytes buffered? Gumdrop saves control sequence.
                // Emit up to control start.
                let hold = match self.state {
                    DataDotState::SawCr => 1,
                    DataDotState::SawCrlf => 2,
                    _ => 0,
                };
                let end = i.saturating_sub(hold);
                if end > chunk_start {
                    chunks.push(input[chunk_start..end].to_vec());
                }
                // Keep held bytes in pending for next feed — simplify: re-push by
                // storing pending control bytes.
                self.pending.clear();
                self.pending.extend_from_slice(&input[end..i]);
            } else if self.state == DataDotState::Normal {
                chunks.push(input[chunk_start..i].to_vec());
            }
        } else if i > chunk_start && self.state == DataDotState::Normal {
            chunks.push(input[chunk_start..i].to_vec());
        }
        (chunks, None)
    }

    /// Feed including any previously held control bytes.
    pub fn feed_with_pending(&mut self, input: &[u8]) -> (Vec<Vec<u8>>, Option<usize>) {
        if self.pending.is_empty() {
            return self.feed(input);
        }
        let mut combined = std::mem::take(&mut self.pending);
        let pend_len = combined.len();
        combined.extend_from_slice(input);
        let (chunks, complete_at) = self.feed(&combined);
        match complete_at {
            Some(n) => {
                // n is index into combined; leftover relative to input:
                let consumed_from_input = n.saturating_sub(pend_len);
                (chunks, Some(consumed_from_input))
            }
            None => (chunks, None),
        }
    }
}

/// BDAT chunk accumulator (RFC 3030).
#[derive(Debug, Clone)]
pub struct BdatAccumulator {
    /// Bytes still expected in the current chunk.
    pub remaining: u64,
    /// LAST flag for this chunk.
    pub last: bool,
}

impl BdatAccumulator {
    /// Start a new BDAT chunk.
    pub fn new(length: u64, last: bool) -> Self {
        Self {
            remaining: length,
            last,
        }
    }

    /// Consume up to `remaining` bytes from `data`; returns (chunk, rest).
    pub fn take<'a>(&mut self, data: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        let n = std::cmp::min(data.len() as u64, self.remaining) as usize;
        self.remaining -= n as u64;
        (&data[..n], &data[n..])
    }

    /// True when the current chunk is fully received.
    pub fn is_complete(&self) -> bool {
        self.remaining == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_message_terminator() {
        let mut u = DotUnstuffer::new();
        let (chunks, done) = u.feed(b".\r\n");
        assert!(chunks.is_empty());
        assert_eq!(done, Some(3));
    }

    #[test]
    fn simple_body() {
        let mut u = DotUnstuffer::new();
        let (chunks, done) = u.feed(b"Hello\r\n.\r\n");
        let body: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(body, b"Hello\r\n");
        assert_eq!(done, Some(10));
    }

    #[test]
    fn dot_stuffing() {
        let mut u = DotUnstuffer::new();
        let (chunks, done) = u.feed(b"..line\r\n.\r\n");
        let body: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(body, b".line\r\n");
        assert!(done.is_some());
    }

    #[test]
    fn bdat_take() {
        let mut b = BdatAccumulator::new(5, true);
        let (a, rest) = b.take(b"abcdefgh");
        assert_eq!(a, b"abcde");
        assert_eq!(rest, b"fgh");
        assert!(b.is_complete());
        assert!(b.last);
    }
}
