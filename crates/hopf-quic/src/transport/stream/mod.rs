// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Stream send / receive state.

mod reassembler;

use std::collections::VecDeque;

use bytes::Bytes;

pub use reassembler::StreamReassembler;

/// Outbound stream half.
#[derive(Debug, Default)]
pub struct SendStream {
    /// Next offset to send for new data.
    pub offset: u64,
    /// Queued chunks waiting for packetization.
    pub pending: VecDeque<Bytes>,
    /// Lost chunks awaiting retransmission at their original offsets.
    pub retransmit: VecDeque<(u64, Bytes, bool)>,
    /// FIN queued.
    pub fin: bool,
    /// FIN sent.
    pub fin_sent: bool,
    /// Max data peer allows.
    pub max_data: u64,
}

impl SendStream {
    /// Queue data for send.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, ()> {
        if self.fin {
            return Err(());
        }
        if data.is_empty() {
            return Ok(0);
        }
        if self.offset + data.len() as u64 > self.max_data {
            return Err(());
        }
        self.pending.push_back(Bytes::copy_from_slice(data));
        Ok(data.len())
    }

    /// Mark FIN.
    pub fn finish(&mut self) {
        self.fin = true;
    }

    /// Requeue a lost STREAM chunk for retransmission at `offset`.
    pub fn requeue(&mut self, offset: u64, data: Bytes, fin: bool) {
        self.retransmit.push_back((offset, data, fin));
        if fin {
            self.fin_sent = false;
        }
    }

    /// Take next chunk up to `max` bytes (retransmits first).
    pub fn take_chunk(&mut self, max: usize) -> Option<(u64, Bytes, bool)> {
        if let Some((offset, chunk, fin)) = self.retransmit.pop_front() {
            let (data, rest) = if chunk.len() > max {
                (chunk.slice(..max), Some(chunk.slice(max..)))
            } else {
                (chunk, None)
            };
            if let Some(r) = rest {
                self.retransmit
                    .push_front((offset + data.len() as u64, r, fin));
                return Some((offset, data, false));
            }
            return Some((offset, data, fin));
        }

        if let Some(chunk) = self.pending.pop_front() {
            let offset = self.offset;
            let (data, rest) = if chunk.len() > max {
                (chunk.slice(..max), Some(chunk.slice(max..)))
            } else {
                (chunk, None)
            };
            if let Some(r) = rest {
                self.pending.push_front(r);
            }
            self.offset += data.len() as u64;
            let fin = self.fin && self.pending.is_empty() && self.retransmit.is_empty();
            if fin {
                self.fin_sent = true;
            }
            return Some((offset, data, fin));
        }

        // FIN-only frame after all data has already been sent.
        if self.fin && !self.fin_sent {
            let offset = self.offset;
            self.fin_sent = true;
            return Some((offset, Bytes::new(), true));
        }
        None
    }
}

/// Inbound stream half.
#[derive(Debug)]
pub struct RecvStream {
    /// Reassembler.
    pub reassembler: StreamReassembler,
    /// Delivered but not yet read by the application.
    pub readable: VecDeque<Bytes>,
    /// Peer sent FIN.
    pub fin: bool,
    /// Max data we advertise.
    pub max_data: u64,
}

impl RecvStream {
    /// Create with flow-control max.
    pub fn new(max_data: u64) -> Self {
        Self {
            reassembler: StreamReassembler::new(max_data),
            readable: VecDeque::new(),
            fin: false,
            max_data,
        }
    }

    /// Ingest a STREAM frame chunk.
    pub fn ingest(&mut self, offset: u64, data: Bytes, fin: bool) -> Result<bool, ()> {
        let contiguous = self.reassembler.receive(offset, data)?;
        let became_readable = !contiguous.is_empty();
        if !contiguous.is_empty() {
            self.readable.push_back(contiguous);
        }
        if fin {
            self.fin = true;
        }
        Ok(became_readable)
    }

    /// Read buffered data into `buf`; returns (bytes, fin_seen).
    pub fn read(&mut self, max: usize) -> (Bytes, bool) {
        if max == 0 {
            return (Bytes::new(), false);
        }
        let Some(front) = self.readable.pop_front() else {
            return (Bytes::new(), self.fin && self.reassembler.next_offset() > 0 || self.fin);
        };
        if front.len() <= max {
            let fin = self.fin && self.readable.is_empty();
            (front, fin)
        } else {
            let got = front.slice(..max);
            self.readable.push_front(front.slice(max..));
            (got, false)
        }
    }
}
