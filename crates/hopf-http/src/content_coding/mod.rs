// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental HTTP content codings (RFC 9110 §8.4): `br`, `gzip`, `deflate`.
//!
//! Every codec here is a *push* state machine: the caller feeds compressed
//! (or plain) bytes as they arrive, in chunks of any size down to a single
//! byte, and receives output through a sink callback. Nothing blocks, and
//! memory stays constant in the input size - a decoder holds its window plus
//! one fixed scratch buffer, never the whole body.
//!
//! [`Decoder`] enforces a hard cap on decoded output ([`CodingError::LimitExceeded`])
//! so a decompression bomb fails closed rather than exhausting memory.
//!
//! The same layer serves the client (decode responses, encode request bodies)
//! and the server (encode responses, decode request bodies) on every HTTP
//! version; see [`crate::client`] and [`crate::server`] for the decorators.

mod brotli_codec;
mod gzip;

use std::fmt;
use std::io;

use crate::limits::HttpLimits;
use brotli_codec::{BrotliDecoder, BrotliEncoder};
use gzip::{DeflateDecoder, DeflateEncoder, GzipDecoder, GzipEncoder};

/// Size of the fixed scratch buffer each codec stage decodes through.
pub(crate) const SCRATCH_LEN: usize = 16 * 1024;

/// Most codings a single `Content-Encoding` field may stack (fail closed above).
pub const MAX_CODING_CHAIN: usize = 4;

/// A registered content coding this crate can apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentCoding {
    /// `identity` - no transformation.
    Identity,
    /// `gzip` (RFC 1952). `x-gzip` is accepted as an alias when decoding.
    Gzip,
    /// `deflate` (the zlib format of RFC 1950, as RFC 9110 defines it). The
    /// decoder also accepts a bare RFC 1951 stream, which many peers send.
    Deflate,
    /// `br` (RFC 7932).
    Brotli,
}

impl ContentCoding {
    /// The registered token, as it appears in `Content-Encoding` / `Accept-Encoding`.
    pub fn token(self) -> &'static str {
        match self {
            ContentCoding::Identity => "identity",
            ContentCoding::Gzip => "gzip",
            ContentCoding::Deflate => "deflate",
            ContentCoding::Brotli => "br",
        }
    }

    /// Parse one coding token, case-insensitively. `None` for anything this
    /// crate does not implement.
    pub fn from_token(token: &str) -> Option<Self> {
        let t = token.trim();
        if t.eq_ignore_ascii_case("identity") {
            Some(ContentCoding::Identity)
        } else if t.eq_ignore_ascii_case("gzip") || t.eq_ignore_ascii_case("x-gzip") {
            Some(ContentCoding::Gzip)
        } else if t.eq_ignore_ascii_case("deflate") {
            Some(ContentCoding::Deflate)
        } else if t.eq_ignore_ascii_case("br") {
            Some(ContentCoding::Brotli)
        } else {
            None
        }
    }
}

impl fmt::Display for ContentCoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Failure of a codec. Every variant means the body must be abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodingError {
    /// The data is not a valid stream for the coding (bad header, bad
    /// checksum, corrupt block, trailing garbage).
    Corrupt,
    /// The stream ended before its end marker.
    Truncated,
    /// Decoded output would exceed the configured cap (decompression bomb).
    LimitExceeded,
    /// A `Content-Encoding` names a coding this crate does not implement,
    /// or stacks more than [`MAX_CODING_CHAIN`] codings.
    Unsupported,
}

impl fmt::Display for CodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CodingError::Corrupt => "corrupt content-coded body",
            CodingError::Truncated => "truncated content-coded body",
            CodingError::LimitExceeded => "decoded body exceeds the configured limit",
            CodingError::Unsupported => "unsupported content coding",
        })
    }
}

impl std::error::Error for CodingError {}

impl From<CodingError> for io::Error {
    fn from(e: CodingError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// Parse a `Content-Encoding` field value into the codings to undo.
///
/// The returned list is in the order the codings were *applied* by the
/// sender (RFC 9110 §8.4.1), so decoding must run them in reverse - which
/// [`Decoder::chain`] does. `identity` entries are dropped. Any unknown
/// token, or a chain longer than [`MAX_CODING_CHAIN`], is
/// [`CodingError::Unsupported`].
pub fn parse_content_encoding(value: &str) -> Result<Vec<ContentCoding>, CodingError> {
    let mut out = Vec::new();
    for token in value.split(',') {
        if token.trim().is_empty() {
            continue;
        }
        match ContentCoding::from_token(token) {
            Some(ContentCoding::Identity) => {}
            Some(c) => out.push(c),
            None => return Err(CodingError::Unsupported),
        }
    }
    if out.len() > MAX_CODING_CHAIN {
        return Err(CodingError::Unsupported);
    }
    Ok(out)
}

/// Client-side policy: which codings to advertise in `Accept-Encoding` and
/// decode, and the decoded-size cap.
///
/// Set it on a request ([`crate::HttpRequest::content_encoding`]), a session
/// ([`crate::HttpClientSessionHandle::content_encoding`]) or a whole client
/// ([`crate::HttpClient::content_encoding`]). With a policy in force the
/// handler receives *decoded* body bytes; see
/// [`DecodingResponseHandler`](crate::client::DecodingResponseHandler) for
/// exactly what happens to the `Content-Encoding` and `Content-Length`
/// headers.
#[derive(Debug, Clone)]
pub struct ContentEncodingPolicy {
    accept: Vec<ContentCoding>,
    max_decoded: u64,
}

impl ContentEncodingPolicy {
    /// Accept `br`, `gzip` and `deflate`, capping decoded bodies at
    /// [`HttpLimits::max_decoded_body`].
    pub fn new(limits: &HttpLimits) -> Self {
        Self {
            accept: vec![ContentCoding::Brotli, ContentCoding::Gzip, ContentCoding::Deflate],
            max_decoded: limits.max_decoded_body as u64,
        }
    }

    /// Replace the advertised codings (most preferred first). `identity`
    /// entries are ignored.
    pub fn accept(mut self, codings: &[ContentCoding]) -> Self {
        self.accept = codings
            .iter()
            .copied()
            .filter(|c| *c != ContentCoding::Identity)
            .collect();
        self
    }

    /// Override the decoded-size cap.
    pub fn max_decoded_body(mut self, max: usize) -> Self {
        self.max_decoded = max as u64;
        self
    }

    /// The `Accept-Encoding` field value this policy advertises.
    pub fn accept_encoding_value(&self) -> String {
        if self.accept.is_empty() {
            return "identity".to_string();
        }
        let mut v: Vec<&str> = self.accept.iter().map(|c| c.token()).collect();
        v.push("identity;q=0.5");
        v.join(", ")
    }

    pub(crate) fn max_decoded(&self) -> u64 {
        self.max_decoded
    }
}

enum DecoderKind {
    Gzip(Box<GzipDecoder>),
    Deflate(Box<DeflateDecoder>),
    Brotli(Box<BrotliDecoder>),
}

/// One-coding incremental decoder.
struct Stage {
    kind: DecoderKind,
    /// Bytes of input this stage has been fed - lets `finish` accept a
    /// coding that saw no body at all (e.g. a zero-length response).
    fed: bool,
}

impl Stage {
    fn new(coding: ContentCoding) -> Result<Self, CodingError> {
        let kind = match coding {
            ContentCoding::Gzip => DecoderKind::Gzip(Box::new(GzipDecoder::new())),
            ContentCoding::Deflate => DecoderKind::Deflate(Box::new(DeflateDecoder::new())),
            ContentCoding::Brotli => DecoderKind::Brotli(Box::new(BrotliDecoder::new())),
            ContentCoding::Identity => return Err(CodingError::Unsupported),
        };
        Ok(Self { kind, fed: false })
    }

    fn push(
        &mut self,
        input: &[u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<(), CodingError>,
    ) -> Result<(), CodingError> {
        if !input.is_empty() {
            self.fed = true;
        }
        match &mut self.kind {
            DecoderKind::Gzip(d) => d.push(input, sink),
            DecoderKind::Deflate(d) => d.push(input, sink),
            DecoderKind::Brotli(d) => d.push(input, sink),
        }
    }

    fn finish(&mut self) -> Result<(), CodingError> {
        if !self.fed {
            return Ok(());
        }
        match &mut self.kind {
            DecoderKind::Gzip(d) => d.finish(),
            DecoderKind::Deflate(d) => d.finish(),
            DecoderKind::Brotli(d) => d.finish(),
        }
    }
}

/// Incremental decoder for one `Content-Encoding` value (one or more
/// stacked codings).
///
/// Feed body bytes with [`push`](Self::push) as they arrive and call
/// [`finish`](Self::finish) at end of body. Output is delivered to the sink
/// in chunks of at most [`SCRATCH_LEN`] bytes.
pub struct Decoder {
    /// Outermost coding first: the order data must be decoded in.
    stages: Vec<Stage>,
    max_output: u64,
    produced: u64,
}

impl Decoder {
    /// Decoder for a single coding. `max_output` caps the decoded size.
    pub fn new(coding: ContentCoding, max_output: u64) -> Result<Self, CodingError> {
        Self::chain(&[coding], max_output)
    }

    /// Decoder for stacked codings given in the order the sender *applied*
    /// them (as [`parse_content_encoding`] returns). `identity` is skipped.
    pub fn chain(applied: &[ContentCoding], max_output: u64) -> Result<Self, CodingError> {
        let mut stages = Vec::new();
        for &c in applied.iter().rev() {
            if c != ContentCoding::Identity {
                stages.push(Stage::new(c)?);
            }
        }
        if stages.len() > MAX_CODING_CHAIN {
            return Err(CodingError::Unsupported);
        }
        Ok(Self {
            stages,
            max_output,
            produced: 0,
        })
    }

    /// Decoder for a `Content-Encoding` field value.
    pub fn for_header(value: &str, max_output: u64) -> Result<Self, CodingError> {
        Self::chain(&parse_content_encoding(value)?, max_output)
    }

    /// Whether this decoder does nothing (only `identity` was named).
    pub fn is_passthrough(&self) -> bool {
        self.stages.is_empty()
    }

    /// Total decoded bytes delivered so far.
    pub fn produced(&self) -> u64 {
        self.produced
    }

    /// Feed compressed bytes; decoded bytes go to `sink`.
    ///
    /// The cap applies to the final output and, because every stage is
    /// checked as it emits, to each intermediate stage too.
    pub fn push(
        &mut self,
        input: &[u8],
        sink: &mut dyn FnMut(&[u8]),
    ) -> Result<(), CodingError> {
        let max = self.max_output;
        let produced = &mut self.produced;
        Self::run(&mut self.stages, input, &mut |out: &[u8]| {
            *produced += out.len() as u64;
            if *produced > max {
                return Err(CodingError::LimitExceeded);
            }
            sink(out);
            Ok(())
        })
    }

    fn run(
        stages: &mut [Stage],
        input: &[u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<(), CodingError>,
    ) -> Result<(), CodingError> {
        match stages.split_first_mut() {
            None => sink(input),
            Some((first, rest)) if rest.is_empty() => first.push(input, sink),
            Some((first, rest)) => first.push(input, &mut |mid: &[u8]| {
                Self::run(rest, mid, sink)
            }),
        }
    }

    /// End of body: verifies every stage reached its end marker.
    pub fn finish(&mut self) -> Result<(), CodingError> {
        for s in &mut self.stages {
            s.finish()?;
        }
        Ok(())
    }
}

enum EncoderKind {
    Gzip(Box<GzipEncoder>),
    Deflate(Box<DeflateEncoder>),
    Brotli(Box<BrotliEncoder>),
}

/// Incremental encoder for one coding.
///
/// [`push`](Self::push) plain bytes as the application produces them;
/// compressed bytes go to the sink whenever the compressor emits some (which
/// may be later than the push that supplied the input). Call
/// [`flush`](Self::flush) to force out everything pushed so far - at a
/// latency-sensitive boundary - and [`finish`](Self::finish) exactly once at
/// end of body.
pub struct Encoder {
    kind: EncoderKind,
}

impl Encoder {
    /// New encoder at the coding's default compression level.
    pub fn new(coding: ContentCoding) -> Result<Self, CodingError> {
        let kind = match coding {
            ContentCoding::Gzip => EncoderKind::Gzip(Box::new(GzipEncoder::new())),
            ContentCoding::Deflate => EncoderKind::Deflate(Box::new(DeflateEncoder::new())),
            ContentCoding::Brotli => EncoderKind::Brotli(Box::new(BrotliEncoder::new())),
            ContentCoding::Identity => return Err(CodingError::Unsupported),
        };
        Ok(Self { kind })
    }

    /// Feed plain bytes.
    pub fn push(&mut self, input: &[u8], sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        match &mut self.kind {
            EncoderKind::Gzip(e) => e.push(input, sink),
            EncoderKind::Deflate(e) => e.push(input, sink),
            EncoderKind::Brotli(e) => e.push(input, sink),
        }
    }

    /// Emit everything pushed so far without ending the stream.
    pub fn flush(&mut self, sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        match &mut self.kind {
            EncoderKind::Gzip(e) => e.flush(sink),
            EncoderKind::Deflate(e) => e.flush(sink),
            EncoderKind::Brotli(e) => e.flush(sink),
        }
    }

    /// End the stream and emit the trailer. Call once.
    pub fn finish(&mut self, sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        match &mut self.kind {
            EncoderKind::Gzip(e) => e.finish(sink),
            EncoderKind::Deflate(e) => e.finish(sink),
            EncoderKind::Brotli(e) => e.finish(sink),
        }
    }
}

/// Pick a coding from an `Accept-Encoding` field value, in the server's
/// preference order.
///
/// Honours `q=0` (explicitly refused) and a `*` wildcard. Returns the first
/// of `preference` the client accepts, or `None` when only `identity`
/// remains (send the body uncompressed).
pub fn negotiate_accept_encoding(
    accept_encoding: &str,
    preference: &[ContentCoding],
) -> Option<ContentCoding> {
    let mut wildcard: Option<bool> = None;
    let mut explicit: Vec<(ContentCoding, bool)> = Vec::new();
    for item in accept_encoding.split(',') {
        let mut parts = item.split(';');
        let token = parts.next().unwrap_or("").trim();
        if token.is_empty() {
            continue;
        }
        let mut allowed = true;
        for p in parts {
            let p = p.trim();
            if let Some(q) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")) {
                allowed = q.trim().parse::<f32>().map(|v| v > 0.0).unwrap_or(false);
            }
        }
        if token == "*" {
            wildcard = Some(allowed);
        } else if let Some(c) = ContentCoding::from_token(token) {
            explicit.push((c, allowed));
        }
    }
    preference.iter().copied().find(|&c| {
        c != ContentCoding::Identity
            && explicit
                .iter()
                .find(|(e, _)| *e == c)
                .map(|(_, a)| *a)
                .or(wildcard)
                .unwrap_or(false)
    })
}

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod tests;
