// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Transparent response decoding for the client (RFC 9110 §8.4).
//!
//! [`DecodingResponseHandler`] wraps an application's
//! [`HttpResponseHandler`]. It sits at the one point every HTTP version
//! funnels through, so HTTP/1.1, HTTP/2 and HTTP/3 share it unchanged.

use std::io;
use std::sync::{Arc, Mutex};

use crate::content_coding::{
    acceptable_codings, CodingError, ContentCoding, ContentEncodingPolicy, Decoder, Encoder,
    ALL_CODINGS,
};
use crate::headers::Headers;

use super::api::{HttpClientError, HttpResponseHandler, SessionRequestOps};

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
/// **Capability learning.** An `Accept-Encoding` header on any response is
/// recorded in the policy's [`ContentCodingCache`](crate::ContentCodingCache)
/// as the codings that origin accepts in *requests* (RFC 9110 §12.5.3); a
/// `415` without one clears what was recorded. That is what later lets the
/// client compress a request body for that origin.
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
    /// Origin this response came from, for capability learning.
    origin: Option<(String, u16)>,
    learned: bool,
}

impl DecodingResponseHandler {
    /// Wrap `inner` under `policy`. `origin` (host, port) enables learning
    /// the server's request-body codings from its responses.
    pub fn new(
        inner: Box<dyn HttpResponseHandler>,
        policy: ContentEncodingPolicy,
        origin: Option<(String, u16)>,
    ) -> Self {
        Self {
            inner,
            policy,
            status: None,
            held: Vec::new(),
            encoding: None,
            decoder: None,
            headers_released: false,
            failed: false,
            origin,
            learned: false,
        }
    }

    fn release_headers(&mut self, decoding: bool) {
        if self.headers_released {
            return;
        }
        self.headers_released = true;
        if let (Some((415, _)), false, Some((host, port))) = (self.status, self.learned, &self.origin) {
            // Rejected without saying what it accepts: stop assuming.
            self.policy.cache_arc().forget(host, *port);
        }
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
        if name.eq_ignore_ascii_case("accept-encoding") {
            if let Some((host, port)) = &self.origin {
                self.policy
                    .cache_arc()
                    .put(host, *port, acceptable_codings(value, &ALL_CODINGS));
                self.learned = true;
            }
        }
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

struct CompressorInner {
    enc: Encoder,
    /// Compressed bytes the session has not yet accepted.
    pending: Vec<u8>,
    /// `end_request_body` was called: end the body once `pending` is empty.
    ending: bool,
}

impl CompressorInner {
    /// Offer `pending` to the session. `Ok(true)` when it is all accepted.
    fn drain(&mut self, session: &mut dyn SessionRequestOps) -> Result<bool, HttpClientError> {
        let mut off = 0;
        while off < self.pending.len() {
            let n = session.body_content(&self.pending[off..])?;
            if n == 0 {
                break;
            }
            off += n;
        }
        self.pending.drain(..off);
        Ok(self.pending.is_empty())
    }
}

/// Compresses one request body as the caller streams it.
///
/// Input is compressed as it arrives and handed to the session; whatever the
/// session cannot take yet waits in a backlog that is bounded by one call's
/// output. While a backlog remains, [`Self::push`] reports zero bytes
/// accepted, so the caller's normal short-write handling applies the
/// backpressure. A backlog left after the last push is drained by a
/// writable callback, which also ends the body when the caller has.
pub(crate) struct RequestCompressor {
    inner: Arc<Mutex<CompressorInner>>,
}

type Session = Arc<Mutex<dyn SessionRequestOps + Send>>;

impl RequestCompressor {
    pub(crate) fn new(coding: ContentCoding) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CompressorInner {
                // `request_coding` only ever yields a codable coding.
                enc: Encoder::new(coding).expect("codable coding"),
                pending: Vec::new(),
                ending: false,
            })),
        }
    }

    /// Compress `data`; returns how many input bytes were accepted (all of
    /// them, or none while a backlog is still draining).
    pub(crate) fn push(&self, session: &Session, data: &[u8]) -> Result<usize, HttpClientError> {
        let mut inner = self.inner.lock().unwrap();
        {
            let mut s = session.lock().unwrap();
            if !inner.drain(&mut *s)? {
                drop(s);
                drop(inner);
                Self::schedule_drain(&self.inner, session, None);
                return Ok(0);
            }
        }
        if data.is_empty() {
            return Ok(0);
        }
        let mut out = Vec::new();
        inner
            .enc
            .push(data, &mut |b| out.extend_from_slice(b))
            .map_err(|_| HttpClientError::new("request compression failed"))?;
        inner.pending = out;
        let drained = inner.drain(&mut *session.lock().unwrap())?;
        drop(inner);
        if !drained {
            Self::schedule_drain(&self.inner, session, None);
        }
        Ok(data.len())
    }

    /// Finish the compressed stream and end the request body, now or as soon
    /// as the session has taken the last of it.
    pub(crate) fn finish(&self, session: &Session) -> Result<(), HttpClientError> {
        let mut inner = self.inner.lock().unwrap();
        let mut tail = Vec::new();
        inner
            .enc
            .finish(&mut |b| tail.extend_from_slice(b))
            .map_err(|_| HttpClientError::new("request compression failed"))?;
        inner.pending.extend_from_slice(&tail);
        inner.ending = true;
        let drained = inner.drain(&mut *session.lock().unwrap())?;
        drop(inner);
        if drained {
            session.lock().unwrap().end_body()
        } else {
            Self::schedule_drain(&self.inner, session, None);
            Ok(())
        }
    }

    /// Register `cb` to run once the backlog has drained (immediately if
    /// there is none).
    pub(crate) fn on_writable(
        &self,
        session: &Session,
        cb: Box<dyn FnOnce() + Send>,
    ) -> Result<(), HttpClientError> {
        let empty = self.inner.lock().unwrap().pending.is_empty();
        if empty {
            session.lock().unwrap().on_body_writable(cb);
        } else {
            Self::schedule_drain(&self.inner, session, Some(cb));
        }
        Ok(())
    }

    fn schedule_drain(
        inner: &Arc<Mutex<CompressorInner>>,
        session: &Session,
        then: Option<Box<dyn FnOnce() + Send>>,
    ) {
        let inner2 = Arc::clone(inner);
        let session2 = Arc::clone(session);
        session.lock().unwrap().on_body_writable(Box::new(move || {
            let (drained, ending) = {
                let mut g = inner2.lock().unwrap();
                let mut s = session2.lock().unwrap();
                match g.drain(&mut *s) {
                    Ok(d) => (d, g.ending),
                    // Session gone: nothing more can be sent.
                    Err(_) => return,
                }
            };
            if drained {
                if ending {
                    let _ = session2.lock().unwrap().end_body();
                }
                if let Some(cb) = then {
                    cb();
                }
            } else {
                Self::schedule_drain(&inner2, &session2, then);
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::api::{HttpClientError, HttpResponseHandler, SessionRequestOps};
    use crate::content_coding::{ContentCoding, Decoder};
    use crate::headers::Headers;

    /// A session whose outbound buffer takes `budget` bytes, then refuses
    /// until [`Fake::flush`] - the same contract as a real connection's
    /// short writes.
    #[derive(Default)]
    struct Fake {
        budget: usize,
        wire: Vec<u8>,
        ended: u32,
        cb: Option<Box<dyn FnOnce() + Send>>,
    }

    impl SessionRequestOps for Fake {
        fn is_open(&self) -> bool {
            true
        }
        fn send_no_body(&mut self, _: &str, _: &str, _: Headers, _: Box<dyn HttpResponseHandler>) -> Result<(), HttpClientError> {
            Ok(())
        }
        fn start_body(&mut self, _: &str, _: &str, _: Headers, _: Box<dyn HttpResponseHandler>) -> Result<(), HttpClientError> {
            Ok(())
        }
        fn body_content(&mut self, data: &[u8]) -> Result<usize, HttpClientError> {
            let n = data.len().min(self.budget);
            self.wire.extend_from_slice(&data[..n]);
            self.budget -= n;
            Ok(n)
        }
        fn end_body(&mut self) -> Result<(), HttpClientError> {
            self.ended += 1;
            Ok(())
        }
        fn cancel_request(&mut self) -> Result<(), HttpClientError> {
            Ok(())
        }
        fn on_body_writable(&mut self, cb: Box<dyn FnOnce() + Send>) {
            self.cb = Some(cb);
        }
    }

    /// Give the session room again and fire its writable callback, as the
    /// reactor does after it flushes.
    fn flush(session: &Arc<Mutex<Fake>>, budget: usize) {
        let cb = {
            let mut g = session.lock().unwrap();
            g.budget = budget;
            g.cb.take()
        };
        if let Some(cb) = cb {
            cb();
        }
    }

    /// Incompressible-ish bytes, so the compressed stream is large.
    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn short_writes_apply_backpressure_and_the_body_still_arrives_whole() {
        for coding in [ContentCoding::Gzip, ContentCoding::Deflate, ContentCoding::Brotli] {
            let fake = Arc::new(Mutex::new(Fake::default()));
            let session: Session = fake.clone();
            let c = RequestCompressor::new(coding);
            let input = noise(300_000);

            let mut off = 0;
            let mut refusals = 0;
            while off < input.len() {
                let end = (off + 20_000).min(input.len());
                let n = c.push(&session, &input[off..end]).unwrap();
                off += n;
                if n == 0 {
                    // Backlog: a caller must wait for room, exactly as for a
                    // short write.
                    refusals += 1;
                    flush(&fake, 7_000);
                }
            }
            c.finish(&session).unwrap();
            // The tail may not fit yet: the body must not end early.
            let mut tail_flushes = 0;
            for _ in 0..1000 {
                if fake.lock().unwrap().ended > 0 {
                    break;
                }
                tail_flushes += 1;
                flush(&fake, 7_000);
            }
            let g = fake.lock().unwrap();
            assert_eq!(g.ended, 1, "{coding}: body must end exactly once");
            // Compressors emit lazily, so the backlog may only appear at the end.
            assert!(
                refusals + tail_flushes > 0,
                "{coding}: test never exercised a backlog"
            );

            let mut d = Decoder::new(coding, 1 << 30).unwrap();
            let mut out = Vec::new();
            d.push(&g.wire, &mut |b| out.extend_from_slice(b)).unwrap();
            d.finish().unwrap();
            assert!(out == input, "{coding}: reassembled body differs");
        }
    }

    #[test]
    fn a_backlog_after_the_last_push_still_drains_without_another_call() {
        let fake = Arc::new(Mutex::new(Fake::default()));
        let session: Session = fake.clone();
        let c = RequestCompressor::new(ContentCoding::Gzip);
        let input = noise(50_000);
        // No room at all: everything backs up, the caller believes it was accepted.
        assert_eq!(c.push(&session, &input).unwrap(), input.len());
        assert!(fake.lock().unwrap().wire.is_empty());
        // Room appears later; the drain callback registered by `push` sends it.
        for _ in 0..100 {
            flush(&fake, 8_000);
        }
        let sent = fake.lock().unwrap().wire.len();
        assert!(sent > 0, "backlog was never drained");
        // ...and it stops re-arming once everything has gone out.
        flush(&fake, 8_000);
        assert_eq!(fake.lock().unwrap().wire.len(), sent, "drain did not settle");
        assert!(fake.lock().unwrap().cb.is_none(), "drain callback left armed with nothing to send");
    }
}
