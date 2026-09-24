// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Brotli (RFC 7932) push codecs over the `brotli` crate's stream API.

use std::io::Write;

use brotli::{BrotliState, CompressorWriter, HeapAlloc, HuffmanCode};

use super::{CodingError, SCRATCH_LEN};

type State = BrotliState<HeapAlloc<u8>, HeapAlloc<u32>, HeapAlloc<HuffmanCode>>;

/// Default encoder quality (0-11). 5 balances ratio against CPU on a reactor.
const DEFAULT_QUALITY: u32 = 5;
/// Default encoder window: 2^22 bytes.
const DEFAULT_LGWIN: u32 = 22;

/// Push brotli decoder: `BrotliDecompressStream` driven with caller-owned
/// input and a fixed scratch buffer, so it never blocks and never buffers a
/// whole body.
pub(crate) struct BrotliDecoder {
    state: State,
    scratch: Box<[u8]>,
    total_out: usize,
    done: bool,
}

impl BrotliDecoder {
    pub(crate) fn new() -> Self {
        let mut state = BrotliState::new(
            HeapAlloc::<u8>::new(0),
            HeapAlloc::<u32>::new(0),
            HeapAlloc::<HuffmanCode>::new(HuffmanCode::default()),
        );
        // Large-window brotli permits windows up to 1 GiB; HTTP's `br` is
        // plain RFC 7932 (window <= 16 MiB), so refuse the extension.
        state.large_window = false;
        Self {
            state,
            scratch: vec![0u8; SCRATCH_LEN].into_boxed_slice(),
            total_out: 0,
            done: false,
        }
    }

    pub(crate) fn push(
        &mut self,
        input: &[u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<(), CodingError>,
    ) -> Result<(), CodingError> {
        use brotli::BrotliResult;
        if self.done {
            // Bytes after the stream's end marker.
            return if input.is_empty() {
                Ok(())
            } else {
                Err(CodingError::Corrupt)
            };
        }
        let mut avail_in = input.len();
        let mut in_off = 0usize;
        loop {
            let mut avail_out = self.scratch.len();
            let mut out_off = 0usize;
            let r = brotli::BrotliDecompressStream(
                &mut avail_in,
                &mut in_off,
                input,
                &mut avail_out,
                &mut out_off,
                &mut self.scratch,
                &mut self.total_out,
                &mut self.state,
            );
            if out_off > 0 {
                sink(&self.scratch[..out_off])?;
            }
            match r {
                BrotliResult::ResultSuccess => {
                    self.done = true;
                    return if in_off < input.len() {
                        Err(CodingError::Corrupt)
                    } else {
                        Ok(())
                    };
                }
                BrotliResult::NeedsMoreOutput => continue,
                BrotliResult::NeedsMoreInput => return Ok(()),
                BrotliResult::ResultFailure => return Err(CodingError::Corrupt),
            }
        }
    }

    pub(crate) fn finish(&mut self) -> Result<(), CodingError> {
        if self.done {
            Ok(())
        } else {
            Err(CodingError::Truncated)
        }
    }
}

/// Collects the compressor's output between calls.
#[derive(Default)]
struct Collect(Vec<u8>);

impl Write for Collect {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Push brotli encoder. Output is drained to the sink after every call, so
/// the collection buffer only ever holds one call's worth.
pub(crate) struct BrotliEncoder {
    w: Option<CompressorWriter<Collect>>,
}

impl BrotliEncoder {
    pub(crate) fn new() -> Self {
        Self {
            w: Some(CompressorWriter::new(
                Collect::default(),
                SCRATCH_LEN,
                DEFAULT_QUALITY,
                DEFAULT_LGWIN,
            )),
        }
    }

    fn drain(w: &mut CompressorWriter<Collect>, sink: &mut dyn FnMut(&[u8])) {
        let buf = &mut w.get_mut().0;
        if !buf.is_empty() {
            sink(buf);
            buf.clear();
        }
    }

    pub(crate) fn push(
        &mut self,
        input: &[u8],
        sink: &mut dyn FnMut(&[u8]),
    ) -> Result<(), CodingError> {
        let w = self.w.as_mut().ok_or(CodingError::Corrupt)?;
        w.write_all(input).map_err(|_| CodingError::Corrupt)?;
        Self::drain(w, sink);
        Ok(())
    }

    pub(crate) fn flush(&mut self, sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        let w = self.w.as_mut().ok_or(CodingError::Corrupt)?;
        w.flush().map_err(|_| CodingError::Corrupt)?;
        Self::drain(w, sink);
        Ok(())
    }

    pub(crate) fn finish(&mut self, sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        let w = self.w.take().ok_or(CodingError::Corrupt)?;
        // `into_inner` finishes the stream (BROTLI_OPERATION_FINISH).
        let out = w.into_inner().0;
        if !out.is_empty() {
            sink(&out);
        }
        Ok(())
    }
}
