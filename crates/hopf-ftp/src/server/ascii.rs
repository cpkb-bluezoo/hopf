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

/// Convert network CRLF (and lone CR) to local LF for ASCII-mode uploads.
pub fn denormalize_ascii_newlines(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'\r' => {
                out.push(b'\n');
                if i + 1 < input.len() && input[i + 1] == b'\n' {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Incremental, chunk-boundary-safe version of [`denormalize_ascii_newlines`].
#[derive(Default)]
pub struct AsciiNewlineDenormalizer {
    pending_cr: bool,
}

impl AsciiNewlineDenormalizer {
    /// Create a new denormalizer with no carried state.
    pub fn new() -> Self {
        Self { pending_cr: false }
    }

    /// Feed the next chunk, appending denormalized bytes to `out`.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        let mut i = 0;
        if self.pending_cr {
            self.pending_cr = false;
            out.push(b'\n');
            if chunk.first() == Some(&b'\n') {
                i = 1;
            }
        }
        while i < chunk.len() {
            match chunk[i] {
                b'\r' => {
                    if i + 1 < chunk.len() {
                        out.push(b'\n');
                        i += if chunk[i + 1] == b'\n' { 2 } else { 1 };
                    } else {
                        self.pending_cr = true;
                        i += 1;
                    }
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
            out.push(b'\n');
            self.pending_cr = false;
        }
    }
}

/// Format a [`SystemTime`] as RFC 3659 `YYYYMMDDHHMMSS` (UTC).
pub fn format_ftp_mtime(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d, hh, mm, ss) = civil_parts_utc(secs);
    format!("{y:04}{m:02}{d:02}{hh:02}{mm:02}{ss:02}")
}

/// Howard Hinnant `civil_from_days` + time-of-day breakdown (UTC).
fn civil_parts_utc(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400) as u32;
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let ss = tod % 60;
    // civil_from_days
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d, hh, mm, ss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn streamed(input: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut norm = AsciiNewlineNormalizer::new();
        let mut out = Vec::new();
        for chunk in input.chunks(chunk_size.max(1)) {
            norm.feed(chunk, &mut out);
        }
        norm.finish(&mut out);
        out
    }

    fn streamed_denorm(input: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut den = AsciiNewlineDenormalizer::new();
        let mut out = Vec::new();
        for chunk in input.chunks(chunk_size.max(1)) {
            den.feed(chunk, &mut out);
        }
        den.finish(&mut out);
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

    #[test]
    fn denormalize_crlf_and_lone_cr_to_lf() {
        assert_eq!(denormalize_ascii_newlines(b"a\r\nb\rc\n"), b"a\nb\nc\n");
    }

    #[test]
    fn denormalize_streaming_matches_whole_buffer() {
        let input = b"line one\r\nline two\rline three\ntrailing\r";
        let expected = denormalize_ascii_newlines(input);
        for chunk_size in 1..=input.len() + 1 {
            assert_eq!(
                streamed_denorm(input, chunk_size),
                expected,
                "mismatch at chunk_size={chunk_size}"
            );
        }
    }

    #[test]
    fn format_ftp_mtime_unix_epoch() {
        assert_eq!(format_ftp_mtime(UNIX_EPOCH), "19700101000000");
        assert_eq!(
            format_ftp_mtime(UNIX_EPOCH + Duration::from_secs(1_704_067_200)),
            "20240101000000"
        );
    }
}
