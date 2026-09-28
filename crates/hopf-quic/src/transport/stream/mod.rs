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

    /// Offset of the chunk `take_chunk` would return next.
    pub fn next_offset(&self) -> u64 {
        self.retransmit
            .front()
            .map_or(self.offset, |(offset, _, _)| *offset)
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
    /// Total stream length, known once a FIN-bearing frame has been seen.
    final_size: Option<u64>,
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
            final_size: None,
            max_data,
        }
    }

    /// Ingest a STREAM frame chunk.
    pub fn ingest(&mut self, offset: u64, data: Bytes, fin: bool) -> Result<bool, ()> {
        let end = offset.saturating_add(data.len() as u64);
        let contiguous = self.reassembler.receive(offset, data)?;
        let became_readable = !contiguous.is_empty();
        if !contiguous.is_empty() {
            self.readable.push_back(contiguous);
        }
        if fin {
            self.fin = true;
            self.final_size = Some(end);
        }
        Ok(became_readable)
    }

    /// Whether every byte up to the peer's declared final size has been
    /// reassembled contiguously (as opposed to merely having seen a FIN,
    /// which may have arrived out of order ahead of a gap).
    fn fully_reassembled(&self) -> bool {
        self.final_size
            .is_some_and(|fs| self.reassembler.next_offset() >= fs)
    }

    /// Read buffered data into `buf`; returns (bytes, fin_seen).
    pub fn read(&mut self, max: usize) -> (Bytes, bool) {
        if max == 0 {
            return (Bytes::new(), false);
        }
        let Some(front) = self.readable.pop_front() else {
            return (Bytes::new(), self.fully_reassembled());
        };
        if front.len() <= max {
            let fin = self.readable.is_empty() && self.fully_reassembled();
            (front, fin)
        } else {
            let got = front.slice(..max);
            self.readable.push_front(front.slice(max..));
            (got, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_does_not_report_fin_while_a_gap_remains() {
        let mut recv = RecvStream::new(1024);
        // Peer's final chunk (offset 4, carrying FIN) arrives before the
        // preceding bytes at offset 0..4, so a gap remains.
        recv.ingest(4, Bytes::from_static(b"ef"), true).unwrap();
        let (data, fin) = recv.read(1024);
        assert!(data.is_empty());
        assert!(
            !fin,
            "must not report end-of-stream while a gap precedes the FIN offset"
        );

        // The missing prefix arrives, closing the gap.
        recv.ingest(0, Bytes::from_static(b"abcd"), false).unwrap();
        let (data, fin) = recv.read(1024);
        assert_eq!(data.as_ref(), b"abcdef");
        assert!(fin, "stream is fully reassembled and should now report FIN");
    }
}
