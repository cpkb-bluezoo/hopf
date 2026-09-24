// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! gzip (RFC 1952) and deflate (zlib, RFC 1950) push codecs.
//!
//! The pure-Rust `flate2` backend has no gzip-framed `Decompress`, so the
//! gzip header/trailer are handled here around a raw-deflate core; the raw
//! core is shared with the `deflate` coding.

use flate2::{Compress, Compression, Crc, Decompress, FlushCompress, FlushDecompress, Status};

use super::{CodingError, SCRATCH_LEN};

/// Drive `d` over `input`, sending output to `sink`. Returns the number of
/// input bytes consumed and whether the deflate stream ended.
fn inflate(
    d: &mut Decompress,
    scratch: &mut [u8],
    mut input: &[u8],
    sink: &mut dyn FnMut(&[u8]) -> Result<(), CodingError>,
) -> Result<(usize, bool), CodingError> {
    let mut used = 0usize;
    loop {
        let in0 = d.total_in();
        let out0 = d.total_out();
        let status = d
            .decompress(input, scratch, FlushDecompress::None)
            .map_err(|_| CodingError::Corrupt)?;
        let consumed = (d.total_in() - in0) as usize;
        let produced = (d.total_out() - out0) as usize;
        input = &input[consumed..];
        used += consumed;
        if produced > 0 {
            sink(&scratch[..produced])?;
        }
        match status {
            Status::StreamEnd => return Ok((used, true)),
            _ => {
                let progressed = consumed > 0 || produced > 0;
                let more = !input.is_empty() || produced == scratch.len();
                if !(progressed && more) {
                    return Ok((used, false));
                }
            }
        }
    }
}

/// `deflate` content coding: zlib-wrapped, with a bare-RFC 1951 fallback
/// chosen by sniffing the first two bytes.
pub(crate) struct DeflateDecoder {
    d: Option<Decompress>,
    scratch: Box<[u8]>,
    /// First byte held back until the second arrives, to sniff the header.
    held: Option<u8>,
    done: bool,
}

impl DeflateDecoder {
    pub(crate) fn new() -> Self {
        Self {
            d: None,
            scratch: vec![0u8; SCRATCH_LEN].into_boxed_slice(),
            held: None,
            done: false,
        }
    }

    fn looks_like_zlib(b0: u8, b1: u8) -> bool {
        b0 & 0x0f == 8 && b0 >> 4 <= 7 && ((b0 as u16) << 8 | b1 as u16) % 31 == 0
    }

    pub(crate) fn push(
        &mut self,
        input: &[u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<(), CodingError>,
    ) -> Result<(), CodingError> {
        if input.is_empty() {
            return Ok(());
        }
        if self.done {
            return Err(CodingError::Corrupt);
        }
        if self.d.is_none() {
            let (b0, rest) = match self.held.take() {
                Some(b0) => (b0, input),
                None if input.len() == 1 => {
                    self.held = Some(input[0]);
                    return Ok(());
                }
                None => (input[0], &input[1..]),
            };
            let b1 = rest[0];
            self.d = Some(Decompress::new(Self::looks_like_zlib(b0, b1)));
            // Replay the sniffed first byte followed by the rest.
            let first = [b0];
            self.feed(&first, sink)?;
            return self.feed(rest, sink);
        }
        self.feed(input, sink)
    }

    fn feed(
        &mut self,
        input: &[u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<(), CodingError>,
    ) -> Result<(), CodingError> {
        let d = self.d.as_mut().expect("sniffed");
        let (used, ended) = inflate(d, &mut self.scratch, input, sink)?;
        if ended {
            self.done = true;
            if used < input.len() {
                return Err(CodingError::Corrupt);
            }
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<(), CodingError> {
        if self.done {
            Ok(())
        } else {
            Err(CodingError::Truncated)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GzHeader {
    /// Collecting the 10 fixed bytes.
    Fixed,
    /// Collecting the 2-byte XLEN.
    ExtraLen,
    /// Skipping this many FEXTRA bytes.
    Extra(u16),
    /// Skipping FNAME up to NUL.
    Name,
    /// Skipping FCOMMENT up to NUL.
    Comment,
    /// Skipping the 2-byte FHCRC.
    Hcrc(u8),
}

enum GzState {
    Header(GzHeader),
    Body,
    Trailer,
}

/// `gzip` content coding. Concatenated members (RFC 1952 §2.2) are decoded
/// back to back; trailing non-gzip bytes are corruption.
pub(crate) struct GzipDecoder {
    state: GzState,
    flags: u8,
    fixed: [u8; 10],
    fixed_len: usize,
    xlen: [u8; 2],
    xlen_len: usize,
    trailer: [u8; 8],
    trailer_len: usize,
    inflate: Decompress,
    crc: Crc,
    scratch: Box<[u8]>,
    /// At least one member has fully completed.
    members: u32,
    /// Bytes of the current member's header seen (0 = between members).
    in_member: bool,
}

const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;
const FRESERVED: u8 = 0xe0;

impl GzipDecoder {
    pub(crate) fn new() -> Self {
        Self {
            state: GzState::Header(GzHeader::Fixed),
            flags: 0,
            fixed: [0; 10],
            fixed_len: 0,
            xlen: [0; 2],
            xlen_len: 0,
            trailer: [0; 8],
            trailer_len: 0,
            inflate: Decompress::new(false),
            crc: Crc::new(),
            scratch: vec![0u8; SCRATCH_LEN].into_boxed_slice(),
            members: 0,
            in_member: false,
        }
    }

    fn after_fixed_header(&mut self) -> Result<GzHeader, CodingError> {
        if self.fixed[0] != 0x1f || self.fixed[1] != 0x8b || self.fixed[2] != 8 {
            return Err(CodingError::Corrupt);
        }
        self.flags = self.fixed[3];
        if self.flags & FRESERVED != 0 {
            return Err(CodingError::Corrupt);
        }
        Ok(self.next_header_field(GzHeader::Fixed))
    }

    /// The header state that follows `after`, honouring the FLG bits.
    fn next_header_field(&self, after: GzHeader) -> GzHeader {
        let order = [
            (GzHeader::Fixed, FEXTRA, GzHeader::ExtraLen),
            (GzHeader::Extra(0), FNAME, GzHeader::Name),
            (GzHeader::Name, FCOMMENT, GzHeader::Comment),
            (GzHeader::Comment, FHCRC, GzHeader::Hcrc(0)),
        ];
        let mut idx = match after {
            GzHeader::Fixed => 0,
            GzHeader::ExtraLen | GzHeader::Extra(_) => 1,
            GzHeader::Name => 2,
            GzHeader::Comment => 3,
            GzHeader::Hcrc(_) => 4,
        };
        while idx < order.len() {
            let (_, flag, next) = order[idx];
            if self.flags & flag != 0 {
                return next;
            }
            idx += 1;
        }
        GzHeader::Hcrc(2) // sentinel: header complete
    }

    pub(crate) fn push(
        &mut self,
        mut input: &[u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<(), CodingError>,
    ) -> Result<(), CodingError> {
        while !input.is_empty() {
            match &mut self.state {
                GzState::Header(h) => {
                    self.in_member = true;
                    let mut cur = *h;
                    let mut complete = false;
                    // Consume header bytes one at a time; header sizes are
                    // tiny next to the body, and this keeps the state
                    // machine trivially resumable at any split point.
                    while !input.is_empty() && !complete {
                        let b = input[0];
                        input = &input[1..];
                        match cur {
                            GzHeader::Fixed => {
                                self.fixed[self.fixed_len] = b;
                                self.fixed_len += 1;
                                if self.fixed_len == 10 {
                                    cur = self.after_fixed_header()?;
                                }
                            }
                            GzHeader::ExtraLen => {
                                self.xlen[self.xlen_len] = b;
                                self.xlen_len += 1;
                                if self.xlen_len == 2 {
                                    let n = u16::from_le_bytes(self.xlen);
                                    cur = if n == 0 {
                                        self.next_header_field(GzHeader::Extra(0))
                                    } else {
                                        GzHeader::Extra(n)
                                    };
                                }
                            }
                            GzHeader::Extra(n) => {
                                cur = if n <= 1 {
                                    self.next_header_field(GzHeader::Extra(0))
                                } else {
                                    GzHeader::Extra(n - 1)
                                };
                            }
                            GzHeader::Name => {
                                if b == 0 {
                                    cur = self.next_header_field(GzHeader::Name);
                                }
                            }
                            GzHeader::Comment => {
                                if b == 0 {
                                    cur = self.next_header_field(GzHeader::Comment);
                                }
                            }
                            GzHeader::Hcrc(k) => {
                                cur = GzHeader::Hcrc(k + 1);
                            }
                        }
                        if cur == GzHeader::Hcrc(2) {
                            complete = true;
                        }
                    }
                    if complete {
                        self.inflate = Decompress::new(false);
                        self.crc = Crc::new();
                        self.state = GzState::Body;
                    } else {
                        self.state = GzState::Header(cur);
                    }
                }
                GzState::Body => {
                    let crc = &mut self.crc;
                    let (used, ended) = inflate(&mut self.inflate, &mut self.scratch, input, &mut |out| {
                        crc.update(out);
                        sink(out)
                    })?;
                    input = &input[used..];
                    if ended {
                        self.trailer_len = 0;
                        self.state = GzState::Trailer;
                    }
                }
                GzState::Trailer => {
                    let take = (8 - self.trailer_len).min(input.len());
                    self.trailer[self.trailer_len..self.trailer_len + take]
                        .copy_from_slice(&input[..take]);
                    self.trailer_len += take;
                    input = &input[take..];
                    if self.trailer_len == 8 {
                        let crc = u32::from_le_bytes(self.trailer[..4].try_into().unwrap());
                        let isize = u32::from_le_bytes(self.trailer[4..].try_into().unwrap());
                        if crc != self.crc.sum() || isize != self.crc.amount() {
                            return Err(CodingError::Corrupt);
                        }
                        self.members += 1;
                        self.in_member = false;
                        self.fixed_len = 0;
                        self.xlen_len = 0;
                        self.state = GzState::Header(GzHeader::Fixed);
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<(), CodingError> {
        if self.members > 0 && !self.in_member {
            Ok(())
        } else {
            Err(CodingError::Truncated)
        }
    }
}

/// Feed `input` through a raw/zlib `Compress`, emitting to `sink`.
fn deflate(
    c: &mut Compress,
    scratch: &mut [u8],
    mut input: &[u8],
    flush: FlushCompress,
    sink: &mut dyn FnMut(&[u8]),
) -> Result<(), CodingError> {
    loop {
        let in0 = c.total_in();
        let out0 = c.total_out();
        let status = c
            .compress(input, scratch, flush)
            .map_err(|_| CodingError::Corrupt)?;
        let consumed = (c.total_in() - in0) as usize;
        let produced = (c.total_out() - out0) as usize;
        input = &input[consumed..];
        if produced > 0 {
            sink(&scratch[..produced]);
        }
        let full = produced == scratch.len();
        match status {
            Status::StreamEnd => return Ok(()),
            _ if flush == FlushCompress::None => {
                if input.is_empty() && !full {
                    return Ok(());
                }
                if consumed == 0 && produced == 0 {
                    return Ok(());
                }
            }
            // Sync/Finish: keep going until the compressor stops filling
            // the buffer with nothing left to consume.
            _ => {
                if input.is_empty() && !full {
                    return Ok(());
                }
            }
        }
    }
}

/// `deflate` content coding (zlib-wrapped).
pub(crate) struct DeflateEncoder {
    c: Compress,
    scratch: Box<[u8]>,
}

impl DeflateEncoder {
    pub(crate) fn new() -> Self {
        Self {
            c: Compress::new(Compression::default(), true),
            scratch: vec![0u8; SCRATCH_LEN].into_boxed_slice(),
        }
    }

    pub(crate) fn push(&mut self, input: &[u8], sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        deflate(&mut self.c, &mut self.scratch, input, FlushCompress::None, sink)
    }

    pub(crate) fn flush(&mut self, sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        deflate(&mut self.c, &mut self.scratch, &[], FlushCompress::Sync, sink)
    }

    pub(crate) fn finish(&mut self, sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        deflate(&mut self.c, &mut self.scratch, &[], FlushCompress::Finish, sink)
    }
}

/// `gzip` content coding: 10-byte header, raw deflate body, CRC32/ISIZE trailer.
pub(crate) struct GzipEncoder {
    c: Compress,
    crc: Crc,
    scratch: Box<[u8]>,
    header_sent: bool,
}

impl GzipEncoder {
    pub(crate) fn new() -> Self {
        Self {
            c: Compress::new(Compression::default(), false),
            crc: Crc::new(),
            scratch: vec![0u8; SCRATCH_LEN].into_boxed_slice(),
            header_sent: false,
        }
    }

    fn header(&mut self, sink: &mut dyn FnMut(&[u8])) {
        if !self.header_sent {
            self.header_sent = true;
            // ID1 ID2 CM FLG MTIME(4, none) XFL OS(255 = unknown)
            sink(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255]);
        }
    }

    pub(crate) fn push(&mut self, input: &[u8], sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        self.header(sink);
        self.crc.update(input);
        deflate(&mut self.c, &mut self.scratch, input, FlushCompress::None, sink)
    }

    pub(crate) fn flush(&mut self, sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        self.header(sink);
        deflate(&mut self.c, &mut self.scratch, &[], FlushCompress::Sync, sink)
    }

    pub(crate) fn finish(&mut self, sink: &mut dyn FnMut(&[u8])) -> Result<(), CodingError> {
        self.header(sink);
        deflate(&mut self.c, &mut self.scratch, &[], FlushCompress::Finish, sink)?;
        let mut trailer = [0u8; 8];
        trailer[..4].copy_from_slice(&self.crc.sum().to_le_bytes());
        trailer[4..].copy_from_slice(&self.crc.amount().to_le_bytes());
        sink(&trailer);
        Ok(())
    }
}
