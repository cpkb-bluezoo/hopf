// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Transparent response decoding for the client (RFC 9110 §8.4).
//!
//! [`DecodingResponseHandler`] wraps an application's
//! [`HttpResponseHandler`]. It sits at the one point every HTTP version
//! funnels through, so HTTP/1.1, HTTP/2 and HTTP/3 share it unchanged.

use std::io;

use crate::content_coding::{CodingError, ContentEncodingPolicy, Decoder};
use crate::headers::Headers;

use super::api::HttpResponseHandler;

/// Decodes `Content-Encoding` on responses before they reach `inner`.
///
/// **Header policy.** The status line and every header are held back until
/// the first body byte (or the end of a body-less response) so the wrapper
/// knows whether it will decode. When it does:
///
/// - `Content-Encoding` and `Content-Length` are *removed* from what the
///   handler sees (they describe the coded body, which the handler never
///   receives), and
/// - all other headers, trailers and the status pass through unchanged.
///
/// A response with no body (HEAD, 204, 304, zero-length) is delivered
/// untouched, `Content-Encoding` included, since nothing is decoded.
///
/// **Fail closed.** An unknown coding, a corrupt or truncated stream, or
/// output past the policy's decoded-size cap ends the response with
/// [`HttpResponseHandler::failed`] (`InvalidData`); no further body bytes are
/// delivered.
pub struct DecodingResponseHandler {
    inner: Box<dyn HttpResponseHandler>,
    policy: ContentEncodingPolicy,
    status: Option<(u16, bool)>,
    held: Vec<(String, String)>,
    encoding: Option<String>,
    decoder: Option<Decoder>,
    headers_released: bool,
    failed: bool,
}

impl DecodingResponseHandler {
    /// Wrap `inner` under `policy`.
    pub fn new(inner: Box<dyn HttpResponseHandler>, policy: ContentEncodingPolicy) -> Self {
        Self {
            inner,
            policy,
            status: None,
            held: Vec::new(),
            encoding: None,
            decoder: None,
            headers_released: false,
            failed: false,
        }
    }

    fn release_headers(&mut self, decoding: bool) {
        if self.headers_released {
            return;
        }
        self.headers_released = true;
        if let Some((code, is_ok)) = self.status {
            if is_ok {
                self.inner.ok(code);
            } else {
                self.inner.error(code);
            }
        }
        for (n, v) in std::mem::take(&mut self.held) {
            if decoding
                && (n.eq_ignore_ascii_case("content-encoding")
                    || n.eq_ignore_ascii_case("content-length"))
            {
                continue;
            }
            self.inner.header(&n, &v);
        }
    }

    fn fail(&mut self, e: CodingError) {
        if !self.failed {
            self.failed = true;
            self.decoder = None;
            self.inner.failed(io::Error::from(e));
        }
    }
}

impl HttpResponseHandler for DecodingResponseHandler {
    fn ok(&mut self, status: u16) {
        self.status = Some((status, true));
    }

    fn error(&mut self, status: u16) {
        self.status = Some((status, false));
    }

    fn header(&mut self, name: &str, value: &str) {
        if self.headers_released {
            self.inner.header(name, value);
            return;
        }
        if name.eq_ignore_ascii_case("content-encoding") {
            self.encoding = Some(match self.encoding.take() {
                Some(prev) => format!("{prev}, {value}"),
                None => value.to_string(),
            });
        }
        self.held.push((name.to_string(), value.to_string()));
    }

    fn start_response_body(&mut self) {
        if self.failed {
            return;
        }
        let decoder = match self.encoding.as_deref() {
            None => None,
            Some(v) => match Decoder::for_header(v, self.policy.max_decoded()) {
                Ok(d) if d.is_passthrough() => None,
                Ok(d) => Some(d),
                Err(e) => return self.fail(e),
            },
        };
        self.release_headers(decoder.is_some());
        self.decoder = decoder;
        self.inner.start_response_body();
    }

    fn response_body_content(&mut self, data: &[u8]) {
        if self.failed {
            return;
        }
        let Some(decoder) = self.decoder.as_mut() else {
            self.inner.response_body_content(data);
            return;
        };
        let inner = &mut self.inner;
        if let Err(e) = decoder.push(data, &mut |out| inner.response_body_content(out)) {
            self.fail(e);
        }
    }

    fn end_response_body(&mut self) {
        if self.failed {
            return;
        }
        if let Some(decoder) = self.decoder.as_mut() {
            if let Err(e) = decoder.finish() {
                return self.fail(e);
            }
        }
        self.inner.end_response_body();
    }

    fn response_trailers(&mut self, headers: &Headers) {
        if !self.failed {
            self.inner.response_trailers(headers);
        }
    }

    fn close(&mut self) {
        if self.failed {
            return;
        }
        // Body-less response: nothing was decoded, so headers go through as-is.
        self.release_headers(false);
        self.inner.close();
    }

    fn failed(&mut self, err: io::Error) {
        if !self.failed {
            self.failed = true;
            self.inner.failed(err);
        }
    }
}
