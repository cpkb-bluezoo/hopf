// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 4978 COMPRESS=DEFLATE.
//!
//! Once `COMPRESS DEFLATE` is accepted, every byte on the connection in
//! both directions is raw DEFLATE (RFC 1951, no zlib/gzip wrapper — RFC
//! 4978 §3 points implementers at zlib's negative-`windowBits` raw mode)
//! for the rest of the session: this is a whole-connection byte-stream
//! transform, not a per-command frame. [`ImapCompressLayer`] holds the one
//! compressor/decompressor pair for that; [`ImapControlHandler::receive`]
//! decompresses inbound bytes before they ever reach the command lexer,
//! and [`CompressingEndpoint`] compresses every outbound `send()` — both
//! reuse hopf-imap's existing incremental parser and response-writing
//! paths unchanged, since neither knows compression is active.
//!
//! Each outbound write is flushed with `Z_SYNC_FLUSH` so the peer can
//! decode it without waiting for the stream to end — necessary since IMAP
//! interleaves untagged responses (unsolicited FETCH/EXISTS, IDLE,
//! literal continuations) with tagged completions at unpredictable points.

use std::io;
use std::time::Duration;

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

use hopf_core::{ConnHandle, Endpoint, PeerAddr, SecurityInfo, StartTlsError, TimerHandle, WriteReadyCallback};

const SCRATCH_LEN: usize = 8192;

/// Per-connection DEFLATE compressor/decompressor pair, held once COMPRESS
/// DEFLATE has been negotiated.
pub(crate) struct ImapCompressLayer {
    compress: Compress,
    decompress: Decompress,
    scratch: Box<[u8]>,
}

impl ImapCompressLayer {
    pub(crate) fn new() -> Self {
        Self {
            // `false`: raw DEFLATE, no zlib header/trailer (RFC 4978 §3).
            compress: Compress::new(Compression::default(), false),
            decompress: Decompress::new(false),
            scratch: vec![0u8; SCRATCH_LEN].into_boxed_slice(),
        }
    }

    /// Decompresses every byte of `input`. RFC 4978 compression covers the
    /// whole connection stream rather than per-command frames, so nothing
    /// is ever held back here for "more later" — the underlying
    /// [`Decompress`] keeps whatever partial-symbol state it needs across
    /// calls on its own.
    pub(crate) fn inflate(&mut self, mut input: &[u8]) -> io::Result<Vec<u8>> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(input.len() * 2 + 64);
        loop {
            let in0 = self.decompress.total_in();
            let out0 = self.decompress.total_out();
            let status = self
                .decompress
                .decompress(input, &mut self.scratch, FlushDecompress::None)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let consumed = (self.decompress.total_in() - in0) as usize;
            let produced = (self.decompress.total_out() - out0) as usize;
            input = &input[consumed..];
            out.extend_from_slice(&self.scratch[..produced]);
            if status == Status::StreamEnd {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compressed stream ended before the connection did",
                ));
            }
            let progressed = consumed > 0 || produced > 0;
            let more_to_do = !input.is_empty() || produced == self.scratch.len();
            if !(progressed && more_to_do) {
                return Ok(out);
            }
        }
    }

    /// Compresses `input` and flushes with `Z_SYNC_FLUSH`.
    pub(crate) fn deflate_and_flush(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len() + 32);
        Self::run_deflate(
            &mut self.compress,
            &mut self.scratch,
            input,
            FlushCompress::None,
            &mut out,
        );
        Self::run_deflate(
            &mut self.compress,
            &mut self.scratch,
            &[],
            FlushCompress::Sync,
            &mut out,
        );
        out
    }

    fn run_deflate(
        c: &mut Compress,
        scratch: &mut [u8],
        mut input: &[u8],
        flush: FlushCompress,
        out: &mut Vec<u8>,
    ) {
        loop {
            let in0 = c.total_in();
            let out0 = c.total_out();
            // A raw `Compress` with no dictionary never errors on valid
            // (non-huge) input.
            let status = c
                .compress(input, scratch, flush)
                .expect("raw deflate compression");
            let consumed = (c.total_in() - in0) as usize;
            let produced = (c.total_out() - out0) as usize;
            input = &input[consumed..];
            out.extend_from_slice(&scratch[..produced]);
            if status == Status::StreamEnd {
                return;
            }
            let full = produced == scratch.len();
            if input.is_empty() && !full {
                return;
            }
        }
    }
}

/// Wraps a connection's real [`Endpoint`] so every `send()` is transparently
/// DEFLATE-compressed; every other method delegates straight through. Used
/// for the duration of one `receive()` call once COMPRESS DEFLATE is active,
/// so hopf-imap's existing response-writing code (`self.send`, the
/// `*View::endpoint.send()` call sites) needs no changes at all to become
/// compression-aware.
pub(crate) struct CompressingEndpoint<'a> {
    inner: &'a mut dyn Endpoint,
    layer: &'a mut ImapCompressLayer,
}

impl<'a> CompressingEndpoint<'a> {
    pub(crate) fn new(inner: &'a mut dyn Endpoint, layer: &'a mut ImapCompressLayer) -> Self {
        Self { inner, layer }
    }
}

impl Endpoint for CompressingEndpoint<'_> {
    fn send(&mut self, data: &[u8]) {
        let compressed = self.layer.deflate_and_flush(data);
        self.inner.send(&compressed);
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    fn is_closing(&self) -> bool {
        self.inner.is_closing()
    }

    fn close(&mut self) {
        self.inner.close();
    }

    fn local_addr(&self) -> io::Result<PeerAddr> {
        self.inner.local_addr()
    }

    fn remote_addr(&self) -> io::Result<PeerAddr> {
        self.inner.remote_addr()
    }

    fn security_info(&self) -> &SecurityInfo {
        self.inner.security_info()
    }

    fn start_tls(&mut self) -> Result<(), StartTlsError> {
        self.inner.start_tls()
    }

    fn pause_read(&mut self) {
        self.inner.pause_read();
    }

    fn resume_read(&mut self) {
        self.inner.resume_read();
    }

    fn on_write_ready(&mut self, callback: Option<WriteReadyCallback>) {
        self.inner.on_write_ready(callback);
    }

    fn execute(&self, task: Box<dyn FnOnce() + Send>) {
        self.inner.execute(task);
    }

    fn schedule_timer(&self, delay: Duration, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        self.inner.schedule_timer(delay, callback)
    }

    fn handle(&self) -> ConnHandle {
        self.inner.handle()
    }

    fn poke_handler(&mut self) {
        self.inner.poke_handler();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_single_write() {
        let mut a = ImapCompressLayer::new();
        let mut b = ImapCompressLayer::new();
        let plain = b"a1 NOOP\r\n";
        let wire = a.deflate_and_flush(plain);
        assert_ne!(wire, plain, "compressed bytes must differ from plaintext");
        let back = b.inflate(&wire).unwrap();
        assert_eq!(back, plain);
    }

    #[test]
    fn roundtrip_many_writes_over_one_continuous_stream() {
        // Mirrors real usage: one compressor/decompressor pair persists
        // across many independent command/response writes, not reset per
        // message (RFC 4978's compression is connection-scoped).
        let mut sender = ImapCompressLayer::new();
        let mut receiver = ImapCompressLayer::new();
        let lines: &[&[u8]] = &[
            b"a1 NOOP\r\n",
            b"* 1 EXISTS\r\n* 1 RECENT\r\n",
            b"a1 OK NOOP completed\r\n",
            b"a2 LOGOUT\r\n",
        ];
        let mut decoded = Vec::new();
        for line in lines {
            let wire = sender.deflate_and_flush(line);
            decoded.extend(receiver.inflate(&wire).unwrap());
        }
        assert_eq!(decoded, lines.concat());
    }

    #[test]
    fn inflate_of_split_wire_chunks_still_reassembles() {
        // A TCP read can split a compressed write anywhere; the decompressor
        // must tolerate arbitrary chunk boundaries the same way the plain
        // (uncompressed) lexer already does.
        let mut sender = ImapCompressLayer::new();
        let mut receiver = ImapCompressLayer::new();
        let plain = b"a1 LOGIN alice password\r\n";
        let wire = sender.deflate_and_flush(plain);
        let mut decoded = Vec::new();
        for chunk in wire.chunks(1) {
            decoded.extend(receiver.inflate(chunk).unwrap());
        }
        assert_eq!(decoded, plain);
    }

    #[test]
    fn inflate_rejects_garbage() {
        let mut receiver = ImapCompressLayer::new();
        assert!(receiver.inflate(b"not a deflate stream at all, sorry").is_err());
    }

    #[test]
    fn output_is_smaller_than_input_for_compressible_text() {
        let mut sender = ImapCompressLayer::new();
        let plain = b"a1 FETCH 1:100 (FLAGS)\r\n".repeat(50);
        let wire = sender.deflate_and_flush(&plain);
        assert!(
            wire.len() < plain.len(),
            "expected real compression: {} -> {}",
            plain.len(),
            wire.len()
        );
    }
}
