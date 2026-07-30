// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 6376 §3.4 header/body canonicalization.

use rmimeparser::dkim::RawHeader;

/// `simple`/`relaxed` selector (RFC 6376 §3.4), independently selectable for
/// header and body (`c=header/body`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Canonicalization {
    /// No modification beyond what capture already guarantees.
    Simple,
    /// Whitespace-normalizing, case-folding-name canonicalization.
    Relaxed,
}

impl Canonicalization {
    /// Parse one side of a `c=` tag (defaults to `simple` on empty/unknown text
    /// per RFC 6376 §3.5, but callers should validate the raw tag first).
    pub fn parse(s: &str) -> Option<Canonicalization> {
        match s {
            "simple" => Some(Canonicalization::Simple),
            "relaxed" => Some(Canonicalization::Relaxed),
            _ => None,
        }
    }
}

/// Canonicalize one header field for inclusion in the header hash.
pub fn canon_header(header: &RawHeader, c: Canonicalization) -> Vec<u8> {
    match c {
        Canonicalization::Simple => header.bytes().to_vec(),
        Canonicalization::Relaxed => relaxed_header(header.name(), &header.bytes_unfolded()),
    }
}

/// Canonicalize the DKIM-Signature header itself for hashing, with `b=`'s
/// value blanked (RFC 6376 §3.7) and — since it is always the last header
/// fed to the hash — no trailing CRLF.
///
/// `full_unfolded` is the *complete* unfolded header (`"DKIM-Signature:...")`,
/// e.g. [`RawHeader::bytes_unfolded`] — the same shape [`canon_header`] takes.
pub fn canon_signature_header(name: &str, full_unfolded: &[u8], c: Canonicalization) -> Vec<u8> {
    let blanked = blank_b_tag(full_unfolded);
    match c {
        Canonicalization::Simple => {
            let mut out = blanked;
            if out.ends_with(b"\r\n") {
                out.truncate(out.len() - 2);
            } else if out.ends_with(b"\n") {
                out.truncate(out.len() - 1);
            }
            out
        }
        Canonicalization::Relaxed => {
            let mut out = relaxed_header(name, &blanked);
            // relaxed_header always appends a trailing CRLF; strip it since
            // the signature header is never followed by another hashed field.
            if out.ends_with(b"\r\n") {
                out.truncate(out.len() - 2);
            }
            out
        }
    }
}

/// Blank the `b=` tag's value (between `b=` and the next `;` or end) — used
/// so the signature itself isn't part of what it signs.
fn blank_b_tag(unfolded_value_with_leading_colon: &[u8]) -> Vec<u8> {
    // `unfolded_value_with_leading_colon` starts with the ':' separator plus
    // the header value bytes (as captured — see callers).
    let s = String::from_utf8_lossy(unfolded_value_with_leading_colon);
    let mut out = String::with_capacity(s.len());
    let mut rest = s.as_ref();
    loop {
        match find_b_tag(rest) {
            None => {
                out.push_str(rest);
                break;
            }
            Some((prefix, tag_start, val_end)) => {
                out.push_str(&rest[..prefix.len() + tag_start]);
                rest = &rest[prefix.len() + val_end..];
            }
        }
    }
    out.into_bytes()
}

/// Find a `b=` tag (not `bh=`) at a tag boundary (start of string, after
/// `;`, or after whitespace following `;`). Returns
/// `(prefix_before_match, offset_of_value_start_within_match, offset_of_value_end_within_match)`
/// where `match` = `rest[prefix.len()..]`.
fn find_b_tag(s: &str) -> Option<(&str, usize, usize)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut at_boundary = true;
    while i < bytes.len() {
        if at_boundary {
            // Skip FWS before the tag name.
            let mut k = i;
            while k < bytes.len() && (bytes[k] as char).is_whitespace() {
                k += 1;
            }
            let name_start = k;
            let mut j = k;
            while j < bytes.len() && bytes[j].is_ascii_alphanumeric() {
                j += 1;
            }
            if j > name_start && &s[name_start..j] == "b" {
                let mut v = j;
                while v < bytes.len() && (bytes[v] as char).is_whitespace() {
                    v += 1;
                }
                if v < bytes.len() && bytes[v] == b'=' {
                    let val_start = v + 1;
                    let mut val_end = val_start;
                    while val_end < bytes.len() && bytes[val_end] != b';' {
                        val_end += 1;
                    }
                    return Some((
                        &s[..name_start],
                        val_start - name_start,
                        val_end - name_start,
                    ));
                }
            }
        }
        at_boundary = bytes[i] == b';';
        i += 1;
    }
    None
}

fn relaxed_header(name: &str, unfolded_with_colon: &[u8]) -> Vec<u8> {
    // `unfolded_with_colon` = the unfolded bytes starting at ':' (colon plus value).
    let value_start = unfolded_with_colon
        .iter()
        .position(|&b| b == b':')
        .map(|p| p + 1)
        .unwrap_or(0);
    let value = &unfolded_with_colon[value_start..];
    // Strip a single trailing CRLF (or LF) if present before whitespace-normalizing.
    let mut value = value;
    if value.ends_with(b"\r\n") {
        value = &value[..value.len() - 2];
    } else if value.ends_with(b"\n") {
        value = &value[..value.len() - 1];
    }
    let mut compressed: Vec<u8> = Vec::with_capacity(value.len());
    let mut in_ws = false;
    for &b in value {
        if b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' {
            in_ws = true;
        } else {
            if in_ws && !compressed.is_empty() {
                compressed.push(b' ');
            }
            in_ws = false;
            compressed.push(b);
        }
    }
    let mut out = Vec::with_capacity(name.len() + compressed.len() + 3);
    out.extend(name.as_bytes().iter().map(|b| b.to_ascii_lowercase()));
    out.push(b':');
    out.extend_from_slice(&compressed);
    out.extend_from_slice(b"\r\n");
    out
}

/// Canonicalize the message body, optionally truncated to `l` octets of the
/// canonicalized result (RFC 6376 §3.4.5 `l=` tag; `None` = whole body).
pub fn canon_body(body: &[u8], c: Canonicalization, l: Option<u64>) -> Vec<u8> {
    let lines = split_lines(body);
    let mut result = match c {
        Canonicalization::Simple => canon_body_simple(&lines),
        Canonicalization::Relaxed => canon_body_relaxed(&lines),
    };
    if let Some(l) = l {
        let l = l as usize;
        if l < result.len() {
            result.truncate(l);
        }
    }
    result
}

/// Streaming counterpart to [`canon_body`]: feeds canonicalized body bytes
/// directly into a running SHA-256 digest as chunks arrive, instead of
/// materializing the whole canonicalized body in a `Vec<u8>` first (which
/// requires holding the entire message body in memory — see issue #86).
///
/// The only part of body canonicalization that inherently needs lookahead
/// is RFC 6376 §3.4.3/§3.4.4's "strip trailing empty lines" rule — you
/// can't know a blank line is trailing until you've seen what (if
/// anything) follows it. This holds back only a *count* of pending blank
/// lines (each canonicalizes to exactly `\r\n`, so no bytes need
/// retaining) rather than the lines' actual content, and a bounded
/// current-line assembly buffer — memory stays O(one line) instead of
/// O(whole body) for ordinary messages.
pub struct IncrementalBodyCanon {
    c: Canonicalization,
    limit: Option<u64>,
    ctx: ring::digest::Context,
    /// Canonicalized bytes fed to `ctx` so far, for `limit` truncation.
    emitted: u64,
    /// Bytes of the current, not-yet-terminated line.
    line_buf: Vec<u8>,
    /// Number of trailing blank lines seen but not yet hashed — each is
    /// exactly `\r\n` once flushed, so a count is all that's needed.
    pending_blank_lines: u64,
}

impl IncrementalBodyCanon {
    /// Start a new streaming body-hash accumulator for canonicalization `c`,
    /// optionally truncated to `limit` canonicalized octets (`l=` tag).
    pub fn new(c: Canonicalization, limit: Option<u64>) -> Self {
        Self {
            c,
            limit,
            ctx: ring::digest::Context::new(&ring::digest::SHA256),
            emitted: 0,
            line_buf: Vec::new(),
            pending_blank_lines: 0,
        }
    }

    /// Feed the next chunk of raw (pre-canonicalization) body bytes, in
    /// wire order. Chunk boundaries may fall anywhere, including mid-line.
    pub fn feed(&mut self, chunk: &[u8]) {
        let mut start = 0;
        for i in 0..chunk.len() {
            if chunk[i] == b'\n' {
                self.line_buf.extend_from_slice(&chunk[start..=i]);
                self.consume_line();
                start = i + 1;
            }
        }
        self.line_buf.extend_from_slice(&chunk[start..]);
    }

    /// Finish: flush the final unterminated line (if any) and resolve
    /// whether the trailing blank-line run (if any) was truly trailing —
    /// it always is, at true EOF, so it's simply dropped. Returns the
    /// finished SHA-256 digest.
    ///
    /// Matches [`canon_body`]'s existing (slightly asymmetric) empty-body
    /// handling exactly, byte for byte, rather than "fixing" it here:
    /// `simple` hashes a single `\r\n` for a wholly empty/blank body (RFC
    /// 6376 §3.4.3's stated rule); `relaxed` hashes nothing at all for the
    /// same input, matching `canon_body_relaxed`'s existing behavior — see
    /// `relaxed_body_all_blank_is_empty`. Whether `relaxed` *should* also
    /// hash `\r\n` per errata some DKIM implementations apply is a
    /// pre-existing question this streaming rewrite deliberately doesn't
    /// re-litigate.
    pub fn finish(mut self) -> ring::digest::Digest {
        if !self.line_buf.is_empty() {
            let line = std::mem::take(&mut self.line_buf);
            self.consume_line_bytes(&line);
        }
        if self.emitted == 0 && self.c == Canonicalization::Simple {
            self.feed_limited(b"\r\n");
        }
        self.ctx.finish()
    }

    fn consume_line(&mut self) {
        let line = std::mem::take(&mut self.line_buf);
        self.consume_line_bytes(&line);
    }

    fn consume_line_bytes(&mut self, line: &[u8]) {
        let content = line_content(line);
        let transformed = match self.c {
            Canonicalization::Simple => content.to_vec(),
            Canonicalization::Relaxed => relaxed_line_content(content),
        };
        if transformed.is_empty() {
            self.pending_blank_lines += 1;
            return;
        }
        self.flush_pending_blank_lines();
        self.feed_limited(&transformed);
        self.feed_limited(b"\r\n");
    }

    fn flush_pending_blank_lines(&mut self) {
        while self.pending_blank_lines > 0 && !self.at_limit() {
            self.feed_limited(b"\r\n");
            self.pending_blank_lines -= 1;
        }
        self.pending_blank_lines = 0;
    }

    fn at_limit(&self) -> bool {
        matches!(self.limit, Some(l) if self.emitted >= l)
    }

    fn feed_limited(&mut self, bytes: &[u8]) {
        let Some(l) = self.limit else {
            self.ctx.update(bytes);
            self.emitted += bytes.len() as u64;
            return;
        };
        if self.emitted >= l {
            return;
        }
        let remaining = (l - self.emitted) as usize;
        let take = bytes.len().min(remaining);
        self.ctx.update(&bytes[..take]);
        self.emitted += take as u64;
    }
}

/// Whitespace-compress one line's already-terminator-stripped content —
/// the per-line half of [`canon_body_relaxed`]'s transform.
fn relaxed_line_content(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len());
    let mut in_ws = false;
    for &b in content {
        if b == b' ' || b == b'\t' {
            in_ws = true;
        } else {
            if in_ws && !out.is_empty() {
                out.push(b' ');
            }
            in_ws = false;
            out.push(b);
        }
    }
    out
}

/// Split into lines, each retaining its own line terminator (`\r\n`, bare
/// `\n`, or none for a final unterminated line).
fn split_lines(body: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\n' {
            lines.push(&body[start..=i]);
            start = i + 1;
        }
        i += 1;
    }
    if start < body.len() {
        lines.push(&body[start..]);
    }
    lines
}

fn line_content(line: &[u8]) -> &[u8] {
    if line.ends_with(b"\r\n") {
        &line[..line.len() - 2]
    } else if line.ends_with(b"\n") {
        &line[..line.len() - 1]
    } else {
        line
    }
}

fn is_blank_line(line: &[u8]) -> bool {
    line_content(line).is_empty()
}

fn canon_body_simple(lines: &[&[u8]]) -> Vec<u8> {
    let mut end = lines.len();
    while end > 0 && is_blank_line(lines[end - 1]) {
        end -= 1;
    }
    if end == 0 {
        return b"\r\n".to_vec();
    }
    let mut out = Vec::new();
    for &line in &lines[..end] {
        out.extend_from_slice(line_content(line));
        out.extend_from_slice(b"\r\n");
    }
    out
}

fn canon_body_relaxed(lines: &[&[u8]]) -> Vec<u8> {
    let mut processed: Vec<Vec<u8>> = lines
        .iter()
        .map(|&line| {
            let content = line_content(line);
            let mut out = Vec::with_capacity(content.len());
            let mut in_ws = false;
            for &b in content {
                if b == b' ' || b == b'\t' {
                    in_ws = true;
                } else {
                    if in_ws && !out.is_empty() {
                        out.push(b' ');
                    }
                    in_ws = false;
                    out.push(b);
                }
            }
            out
        })
        .collect();
    while matches!(processed.last(), Some(l) if l.is_empty()) {
        processed.pop();
    }
    if processed.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for line in &processed {
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`IncrementalBodyCanon`] must produce byte-identical SHA-256 output
    /// to `sha256(canon_body(..))`, regardless of how the input is chunked
    /// — the property #86's streaming DKIM design depends on.
    fn streaming_matches_whole_buffer(body: &[u8], c: Canonicalization, l: Option<u64>) {
        let expected = ring::digest::digest(&ring::digest::SHA256, &canon_body(body, c, l));
        for chunk_size in [1usize, 2, 3, 5, 7, 16, 64, 4096] {
            let mut streaming = IncrementalBodyCanon::new(c, l);
            for chunk in body.chunks(chunk_size.max(1)) {
                streaming.feed(chunk);
            }
            let got = streaming.finish();
            assert_eq!(
                got.as_ref(),
                expected.as_ref(),
                "mismatch for c={c:?} l={l:?} chunk_size={chunk_size} body={body:?}"
            );
        }
    }

    #[test]
    fn incremental_body_canon_matches_whole_buffer_simple() {
        let bodies: &[&[u8]] = &[
            b"",
            b"\r\n",
            b"\r\n\r\n",
            b"hello",
            b"hello\r\n",
            b"line one\r\nline two\r\n",
            b"line one\r\nline two\r\n\r\n\r\n",
            b"line1\r\n\r\nline2\r\n\r\n\r\n",
            b"line  one  \t\r\nline\ttwo\r\n\r\n\r\n",
            b"only a single unterminated line without CRLF",
            b"multiple\nbare\nlf\nlines\n",
            b"trailing bare lf blanks\n\n\n",
        ];
        for &body in bodies {
            streaming_matches_whole_buffer(body, Canonicalization::Simple, None);
            streaming_matches_whole_buffer(body, Canonicalization::Relaxed, None);
        }
    }

    #[test]
    fn incremental_body_canon_matches_whole_buffer_with_l_truncation() {
        let body: &[u8] = b"0123456789\r\nabcdefghij\r\n\r\n\r\n";
        for l in [0u64, 1, 5, 12, 14, 20, 100] {
            streaming_matches_whole_buffer(body, Canonicalization::Simple, Some(l));
            streaming_matches_whole_buffer(body, Canonicalization::Relaxed, Some(l));
        }
    }

    #[test]
    fn incremental_body_canon_matches_whole_buffer_large_body() {
        // A body large enough that whole-buffer canon would materialize a
        // sizeable Vec<u8> — exercises the streaming path at realistic
        // scale, still cross-checked against the reference implementation.
        let mut body = Vec::new();
        for i in 0..2000u32 {
            body.extend_from_slice(format!("line number {i} with some padding text\r\n").as_bytes());
        }
        body.extend_from_slice(b"\r\n\r\n\r\n");
        streaming_matches_whole_buffer(&body, Canonicalization::Simple, None);
        streaming_matches_whole_buffer(&body, Canonicalization::Relaxed, None);
        streaming_matches_whole_buffer(&body, Canonicalization::Simple, Some(1000));
    }

    #[test]
    fn incremental_body_canon_all_blank_body_hashes_single_crlf() {
        let mut c = IncrementalBodyCanon::new(Canonicalization::Simple, None);
        c.feed(b"\r\n\r\n\r\n");
        let got = c.finish();
        let expected = ring::digest::digest(&ring::digest::SHA256, b"\r\n");
        assert_eq!(got.as_ref(), expected.as_ref());
    }

    #[test]
    fn simple_body_strips_trailing_blank_lines() {
        let body = b"line one\r\nline two\r\n\r\n\r\n";
        assert_eq!(
            canon_body(body, Canonicalization::Simple, None),
            b"line one\r\nline two\r\n".to_vec()
        );
    }

    #[test]
    fn simple_body_empty_is_single_crlf() {
        assert_eq!(
            canon_body(b"", Canonicalization::Simple, None),
            b"\r\n".to_vec()
        );
        assert_eq!(
            canon_body(b"\r\n\r\n", Canonicalization::Simple, None),
            b"\r\n".to_vec()
        );
    }

    #[test]
    fn relaxed_body_collapses_whitespace_and_trims() {
        let body = b"line  one  \t\r\nline\ttwo\r\n\r\n\r\n";
        assert_eq!(
            canon_body(body, Canonicalization::Relaxed, None),
            b"line one\r\nline two\r\n".to_vec()
        );
    }

    #[test]
    fn relaxed_body_all_blank_is_empty() {
        assert_eq!(
            canon_body(b"", Canonicalization::Relaxed, None),
            Vec::<u8>::new()
        );
        assert_eq!(
            canon_body(b"\r\n\r\n", Canonicalization::Relaxed, None),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn body_truncation_l_tag() {
        let body = b"0123456789\r\n";
        assert_eq!(
            canon_body(body, Canonicalization::Simple, Some(5)),
            b"01234".to_vec()
        );
    }

    #[test]
    fn relaxed_header_lowercases_name_and_compresses_whitespace() {
        let raw = RawHeader::new("Subject", b"Subject:  Hello   World  \r\n".to_vec());
        let out = canon_header(&raw, Canonicalization::Relaxed);
        assert_eq!(out, b"subject:Hello World\r\n".to_vec());
    }

    #[test]
    fn simple_header_preserves_bytes() {
        let raw = RawHeader::new("Subject", b"Subject:  Hello   World  \r\n".to_vec());
        let out = canon_header(&raw, Canonicalization::Simple);
        assert_eq!(out, b"Subject:  Hello   World  \r\n".to_vec());
    }

    #[test]
    fn canon_signature_header_blanks_b_and_drops_trailing_crlf() {
        let raw = RawHeader::new(
            "DKIM-Signature",
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel;\r\n bh=abc; b=AAAA\r\n BBBB\r\n".to_vec(),
        );
        let simple = canon_signature_header(
            "DKIM-Signature",
            &raw.bytes_unfolded(),
            Canonicalization::Simple,
        );
        let s = String::from_utf8(simple).unwrap();
        assert!(s.starts_with("DKIM-Signature: v=1;"));
        assert!(s.ends_with("b="));
        assert!(!s.contains("AAAA"));
        assert!(!s.ends_with('\n'));

        let relaxed = canon_signature_header(
            "DKIM-Signature",
            &raw.bytes_unfolded(),
            Canonicalization::Relaxed,
        );
        let r = String::from_utf8(relaxed).unwrap();
        assert!(r.starts_with("dkim-signature:v=1;"));
        assert!(r.ends_with("b="));
        assert!(!r.contains("AAAA"));
        assert!(!r.ends_with('\n'));
    }

    #[test]
    fn blank_b_tag_removes_signature_value_only() {
        let value =
            b":v=1; a=rsa-sha256; d=example.com; s=sel;\r\n bh=abc; b=AAAA\r\n BBBB;".to_vec();
        let out = blank_b_tag(&value);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("b=;"));
        assert!(!s.contains("AAAA"));
        assert!(s.contains("bh=abc"));
    }
}
