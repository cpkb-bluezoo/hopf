// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TYPE A newline normalisation.

/// Convert lone LF / CR to CRLF for ASCII mode transfers.
pub fn normalize_ascii_newlines(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 16);
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'\r' => {
                if i + 1 < input.len() && input[i + 1] == b'\n' {
                    out.extend_from_slice(b"\r\n");
                    i += 2;
                } else {
                    out.extend_from_slice(b"\r\n");
                    i += 1;
                }
            }
            b'\n' => {
                out.extend_from_slice(b"\r\n");
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Incremental, chunk-boundary-safe version of [`normalize_ascii_newlines`].
///
/// A trailing `\r` at the end of a chunk is held back (`pending_cr`) until the
/// next chunk (or [`finish`](Self::finish)) reveals whether it was the first
/// half of a CRLF pair, matching the whole-buffer function byte for byte
/// regardless of how the input is split into chunks.
#[derive(Default)]
pub struct AsciiNewlineNormalizer {
    pending_cr: bool,
}

impl AsciiNewlineNormalizer {
    /// Create a new normalizer with no carried state.
    pub fn new() -> Self {
        Self { pending_cr: false }
    }

    /// Feed the next chunk, appending normalized bytes to `out`.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        let mut i = 0;
        if self.pending_cr {
            self.pending_cr = false;
            out.extend_from_slice(b"\r\n");
            if chunk.first() == Some(&b'\n') {
                i = 1;
            }
        }
        while i < chunk.len() {
            match chunk[i] {
                b'\r' => {
                    if i + 1 < chunk.len() {
                        out.extend_from_slice(b"\r\n");
                        i += if chunk[i + 1] == b'\n' { 2 } else { 1 };
                    } else {
                        self.pending_cr = true;
                        i += 1;
                    }
                }
                b'\n' => {
                    out.extend_from_slice(b"\r\n");
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
    }

    /// Flush any carried trailing `\r` at end of input.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        if self.pending_cr {
            out.extend_from_slice(b"\r\n");
            self.pending_cr = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn streamed(input: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut norm = AsciiNewlineNormalizer::new();
        let mut out = Vec::new();
        for chunk in input.chunks(chunk_size.max(1)) {
            norm.feed(chunk, &mut out);
        }
        norm.finish(&mut out);
        out
    }

    #[test]
    fn streaming_matches_whole_buffer_regardless_of_chunk_size() {
        let input = b"line one\nline two\r\nline three\rline four\r\n\ntrailing\r";
        let expected = normalize_ascii_newlines(input);
        for chunk_size in 1..=input.len() + 1 {
            assert_eq!(
                streamed(input, chunk_size),
                expected,
                "mismatch at chunk_size={chunk_size}"
            );
        }
    }

    #[test]
    fn cr_split_exactly_at_chunk_boundary_still_merges_with_following_lf() {
        let mut norm = AsciiNewlineNormalizer::new();
        let mut out = Vec::new();
        norm.feed(b"abc\r", &mut out);
        norm.feed(b"\ndef", &mut out);
        norm.finish(&mut out);
        assert_eq!(out, b"abc\r\ndef");
    }

    #[test]
    fn lone_trailing_cr_is_flushed_by_finish() {
        let mut norm = AsciiNewlineNormalizer::new();
        let mut out = Vec::new();
        norm.feed(b"abc\r", &mut out);
        norm.finish(&mut out);
        assert_eq!(out, b"abc\r\n");
    }
}
