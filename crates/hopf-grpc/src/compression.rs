// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! gRPC message compression, as the gRPC HTTP/2 protocol has it: each
//! message is compressed on its own and flagged in its frame header, the
//! algorithm is the one the call's `grpc-encoding` header names, and
//! `grpc-accept-encoding` lists the algorithms a peer can decode.
//!
//! The algorithms are the [`ContentCoding`]s of `hopf-http`: `gzip` and
//! `deflate` are the specification's and are on by default; `br` (Brotli)
//! is an extension that only works between peers that both have it, so it
//! is used only when asked for. `identity` is always allowed.

use hopf_http::{CodingError, ContentCoding, Decoder, Encoder};

use crate::framing::GrpcEventHandler;

/// What a gRPC peer is assumed to decode unless told otherwise.
pub const DEFAULT_ENCODINGS: &[ContentCoding] = &[ContentCoding::Gzip, ContentCoding::Deflate];

/// Messages smaller than this are sent uncompressed by default.
pub const DEFAULT_COMPRESSION_THRESHOLD: usize = 256;

/// The `grpc-encoding` token for no compression.
pub const IDENTITY: &str = "identity";

pub(crate) const GRPC_STATUS_RESOURCE_EXHAUSTED: i32 = 8;
pub(crate) const GRPC_STATUS_UNIMPLEMENTED: i32 = 12;
pub(crate) const GRPC_STATUS_INTERNAL: i32 = 13;

/// The algorithm a `grpc-encoding` token names; `None` for `identity` and
/// for a token this crate does not know.
pub fn coding_for_token(token: &str) -> Option<ContentCoding> {
    match ContentCoding::from_token(token) {
        Some(ContentCoding::Identity) | None => None,
        other => other,
    }
}

/// Whether a `grpc-encoding` value (or its absence) means no compression.
pub fn is_identity(token: Option<&str>) -> bool {
    token.map_or(true, |t| t.trim().is_empty() || t.trim().eq_ignore_ascii_case(IDENTITY))
}

/// The `grpc-accept-encoding` value for the algorithms a peer decodes:
/// `identity` first, then each of them.
pub fn accept_encoding_header(encodings: &[ContentCoding]) -> String {
    let mut out = String::from(IDENTITY);
    for c in encodings {
        if *c != ContentCoding::Identity {
            out.push(',');
            out.push_str(c.token());
        }
    }
    out
}

/// The algorithms a `grpc-accept-encoding` value lists that this crate
/// knows, in the order listed, without duplicates.
pub fn parse_accept_encoding(header: &str) -> Vec<ContentCoding> {
    let mut out: Vec<ContentCoding> = Vec::new();
    for token in header.split(',') {
        if let Some(c) = coding_for_token(token) {
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

/// Chooses the algorithm to compress with: the first of `offered` that the
/// peer's `grpc-accept-encoding` lists, or `None` if there is none in common.
pub fn select_encoding(
    offered: &[ContentCoding],
    accept_encoding: Option<&str>,
) -> Option<ContentCoding> {
    let accepted = parse_accept_encoding(accept_encoding?);
    offered.iter().copied().find(|c| accepted.contains(c))
}

/// How the messages of one call are coded, from its `grpc-encoding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageCoding {
    /// No `grpc-encoding`, or `identity`: a flagged message is an error.
    Identity,
    /// An algorithm this side decodes.
    Coding(ContentCoding),
    /// A token that is unknown, or an algorithm that is not enabled.
    Unsupported(String),
}

impl MessageCoding {
    /// Resolves a `grpc-encoding` value against the enabled algorithms.
    pub fn resolve(grpc_encoding: Option<&str>, encodings: &[ContentCoding]) -> Self {
        if is_identity(grpc_encoding) {
            return MessageCoding::Identity;
        }
        let token = grpc_encoding.unwrap_or("").trim();
        match coding_for_token(token) {
            Some(c) if encodings.contains(&c) => MessageCoding::Coding(c),
            _ => MessageCoding::Unsupported(token.to_string()),
        }
    }
}

/// The gRPC status a decoding failure is: a message that expands beyond
/// the limit is RESOURCE_EXHAUSTED, an algorithm this side does not have is
/// UNIMPLEMENTED, and a corrupt or truncated message is INTERNAL.
pub fn decode_failure(e: CodingError) -> (i32, &'static str) {
    match e {
        CodingError::LimitExceeded => (
            GRPC_STATUS_RESOURCE_EXHAUSTED,
            "Decompressed message exceeds the limit",
        ),
        CodingError::Unsupported => (GRPC_STATUS_UNIMPLEMENTED, "Unsupported grpc-encoding"),
        CodingError::Corrupt | CodingError::Truncated => {
            (GRPC_STATUS_INTERNAL, "Corrupt compressed message")
        }
    }
}

/// Compresses one message. `None` means it would not be smaller, in which
/// case it is better sent as it is.
pub fn compress(coding: ContentCoding, message: &[u8]) -> Result<Option<Vec<u8>>, CodingError> {
    let mut encoder = Encoder::new(coding)?;
    let mut packed = Vec::with_capacity(message.len());
    let mut sink = |out: &[u8]| packed.extend_from_slice(out);
    encoder.push(message, &mut sink)?;
    encoder.finish(&mut sink)?;
    Ok((packed.len() < message.len()).then_some(packed))
}

/// Gathers one framed message, decompressing it when its frame is flagged,
/// for the server and client bindings. The gRPC status of a failure is
/// kept with its message so the peer can be told.
pub(crate) struct MessageAccum {
    coding: MessageCoding,
    max_message_size: u64,
    decoder: Option<Decoder>,
    pub(crate) buf: Vec<u8>,
    pub(crate) error: Option<(i32, String)>,
    pub(crate) ended: bool,
}

impl MessageAccum {
    pub(crate) fn new(coding: MessageCoding, max_message_size: u64) -> Self {
        Self {
            coding,
            max_message_size,
            decoder: None,
            buf: Vec::new(),
            error: None,
            ended: false,
        }
    }

    fn fail(&mut self, status: i32, message: impl Into<String>) {
        self.decoder = None;
        if self.error.is_none() {
            self.error = Some((status, message.into()));
        }
    }

    fn fail_coding(&mut self, e: CodingError) {
        let (status, message) = decode_failure(e);
        self.fail(status, message);
    }
}

impl GrpcEventHandler for MessageAccum {
    fn start_message(&mut self, compression_flag: u8, length: u32) {
        self.buf.clear();
        self.ended = false;
        if compression_flag == 0 {
            self.buf.reserve(length as usize);
            return;
        }
        match &self.coding {
            MessageCoding::Identity => {
                self.fail(GRPC_STATUS_INTERNAL, "Compressed message without grpc-encoding");
            }
            MessageCoding::Unsupported(token) => {
                let message = format!("Unsupported grpc-encoding: {token}");
                self.fail(GRPC_STATUS_UNIMPLEMENTED, message);
            }
            MessageCoding::Coding(c) => match Decoder::new(*c, self.max_message_size) {
                Ok(d) => self.decoder = Some(d),
                Err(e) => self.fail_coding(e),
            },
        }
    }

    fn message_data(&mut self, data: &[u8]) {
        if self.error.is_some() {
            return;
        }
        match &mut self.decoder {
            None => self.buf.extend_from_slice(data),
            Some(d) => {
                let buf = &mut self.buf;
                if let Err(e) = d.push(data, &mut |out| buf.extend_from_slice(out)) {
                    self.fail_coding(e);
                }
            }
        }
    }

    fn end_message(&mut self) {
        if let Some(mut d) = self.decoder.take() {
            if let Err(e) = d.finish() {
                self.fail_coding(e);
            }
        }
        self.ended = true;
    }

    fn parse_error(&mut self, message: &str) {
        // the frame parser's own size check is the message limit too
        let status = if message.contains("exceeds maximum") {
            GRPC_STATUS_RESOURCE_EXHAUSTED
        } else {
            GRPC_STATUS_INTERNAL
        };
        self.fail(status, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_encoding_lists_identity_first() {
        assert_eq!(accept_encoding_header(DEFAULT_ENCODINGS), "identity,gzip,deflate");
        assert_eq!(accept_encoding_header(&[]), "identity");
        assert_eq!(
            accept_encoding_header(&[ContentCoding::Brotli, ContentCoding::Identity]),
            "identity,br"
        );
    }

    #[test]
    fn parse_and_select() {
        assert_eq!(
            parse_accept_encoding("identity, GZIP,snappy,gzip,br"),
            vec![ContentCoding::Gzip, ContentCoding::Brotli]
        );
        assert_eq!(
            select_encoding(DEFAULT_ENCODINGS, Some("deflate,gzip")),
            Some(ContentCoding::Gzip)
        );
        assert_eq!(select_encoding(DEFAULT_ENCODINGS, Some("br")), None);
        assert_eq!(select_encoding(DEFAULT_ENCODINGS, None), None);
    }

    #[test]
    fn resolve_grpc_encoding() {
        assert_eq!(MessageCoding::resolve(None, DEFAULT_ENCODINGS), MessageCoding::Identity);
        assert_eq!(
            MessageCoding::resolve(Some("identity"), DEFAULT_ENCODINGS),
            MessageCoding::Identity
        );
        assert_eq!(
            MessageCoding::resolve(Some("gzip"), DEFAULT_ENCODINGS),
            MessageCoding::Coding(ContentCoding::Gzip)
        );
        assert_eq!(
            MessageCoding::resolve(Some("br"), DEFAULT_ENCODINGS),
            MessageCoding::Unsupported("br".into())
        );
        assert_eq!(
            MessageCoding::resolve(Some("br"), &[ContentCoding::Brotli]),
            MessageCoding::Coding(ContentCoding::Brotli)
        );
        assert_eq!(
            MessageCoding::resolve(Some("snappy"), DEFAULT_ENCODINGS),
            MessageCoding::Unsupported("snappy".into())
        );
    }

    #[test]
    fn compress_skips_what_would_not_shrink() {
        assert_eq!(compress(ContentCoding::Gzip, b"x").unwrap(), None);
        let big = vec![b'a'; 4096];
        let packed = compress(ContentCoding::Gzip, &big).unwrap().unwrap();
        assert!(packed.len() < big.len());
        let mut d = Decoder::new(ContentCoding::Gzip, 1 << 20).unwrap();
        let mut out = Vec::new();
        d.push(&packed, &mut |o| out.extend_from_slice(o)).unwrap();
        d.finish().unwrap();
        assert_eq!(out, big);
    }
}
