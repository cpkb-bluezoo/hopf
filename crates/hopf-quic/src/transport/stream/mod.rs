// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Stream send / receive state.

mod reassembler;

use std::collections::VecDeque;
use std::time::Instant;

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
    /// Bytes in `pending` (queued, not yet sent for the first time).
    pub queued: u64,
    /// The last write was cut short by `max_data`: the application has
    /// more to send than the peer currently allows.
    pub wants_more: bool,
    /// The `max_data` a STREAM_DATA_BLOCKED was last sent for, so the
    /// hint goes once per limit (RFC 9000 section 4.1).
    pub blocked_sent_at: Option<u64>,
    /// Locally reset: the application error code and the final size (the
    /// bytes sent before the reset). No more STREAM frames are sent.
    pub reset: Option<(u64, u64)>,
    /// A RESET_STREAM for `reset` is due (new or lost).
    pub pending_reset: bool,
    /// The peer acknowledged the packet carrying our FIN.
    pub fin_acked: bool,
    /// The peer acknowledged the packet carrying our RESET_STREAM.
    pub reset_acked: bool,
}

impl SendStream {
    /// Queue data for send: as much of `data` as the peer's limit allows
    /// (a short write when the limit falls inside it), or `Err` when the
    /// stream is finished or nothing fits.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, ()> {
        if self.fin || self.reset.is_some() {
            return Err(());
        }
        if data.is_empty() {
            return Ok(0);
        }
        let credit = self.max_data.saturating_sub(self.offset + self.queued);
        let n = (data.len() as u64).min(credit) as usize;
        self.wants_more = n < data.len();
        if n == 0 {
            return Err(());
        }
        self.pending.push_back(Bytes::copy_from_slice(&data[..n]));
        self.queued += n as u64;
        Ok(n)
    }

    /// Whether the next chunk `take_chunk` returns is new data, which
    /// counts against the peer's limits (retransmissions and a bare FIN do
    /// not).
    pub fn next_chunk_is_new_data(&self) -> bool {
        self.retransmit.is_empty() && !self.pending.is_empty()
    }

    /// Whether this stream is waiting on the peer to raise `max_data`: the
    /// application wanted to queue more than fits, or queued data cannot
    /// leave because the limit already sits at the offset sent so far.
    pub fn blocked_on_peer(&self) -> bool {
        self.reset.is_none()
            && (self.wants_more && self.max_data.saturating_sub(self.offset + self.queued) == 0)
            || (!self.pending.is_empty() && self.max_data.saturating_sub(self.offset) == 0)
    }

    /// Mark FIN.
    pub fn finish(&mut self) {
        self.fin = true;
    }

    /// Abort the send side (RFC 9000 section 3.1): queued and lost data is
    /// dropped and the final size is the bytes sent so far. Returns the
    /// queued bytes released, or `None` if already reset or complete and
    /// acknowledged (a reset then would misstate the final size).
    pub fn reset(&mut self, error_code: u64) -> Option<u64> {
        if self.reset.is_some() || self.fin_acked {
            return None;
        }
        self.pending.clear();
        self.retransmit.clear();
        let released = self.queued;
        self.queued = 0;
        self.wants_more = false;
        self.reset = Some((error_code, self.offset));
        self.pending_reset = true;
        Some(released)
    }

    /// Requeue a lost STREAM chunk for retransmission at `offset`; nothing
    /// is retransmitted on a reset stream.
    pub fn requeue(&mut self, offset: u64, data: Bytes, fin: bool) {
        if self.reset.is_some() {
            return;
        }
        self.retransmit.push_back((offset, data, fin));
        if fin {
            self.fin_sent = false;
        }
    }

    /// Whether `take_chunk` has anything left to return.
    pub fn has_data(&self) -> bool {
        self.reset.is_none()
            && (!self.pending.is_empty() || !self.retransmit.is_empty() || (self.fin && !self.fin_sent))
    }

    /// Offset of the chunk `take_chunk` would return next.
    pub fn next_offset(&self) -> u64 {
        self.retransmit
            .front()
            .map_or(self.offset, |(offset, _, _)| *offset)
    }

    /// Take next chunk up to `max` bytes (retransmits first).
    pub fn take_chunk(&mut self, max: usize) -> Option<(u64, Bytes, bool)> {
        if self.reset.is_some() {
            return None;
        }
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
            self.queued -= data.len() as u64;
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
    /// Max data we advertise: the current MAX_STREAM_DATA limit.
    pub max_data: u64,
    /// Receive window: `max_data` is kept at `consumed + window`.
    pub window: u64,
    /// When the current window was advertised (for the growth rule).
    pub opened_at: Instant,
    /// Bytes the application has read.
    pub consumed: u64,
    /// Largest offset the peer has sent (or declared as final size).
    pub highest: u64,
    /// A MAX_STREAM_DATA for the current `max_data` is due (new or lost).
    pub pending_max: bool,
    /// Peer sent RESET_STREAM: no more data is delivered or credited.
    pub reset: bool,
    /// We sent STOP_SENDING with this error code: data still arriving is
    /// counted for flow control but not delivered.
    pub stop_sending: Option<u64>,
    /// A STOP_SENDING for `stop_sending` is due (new or lost).
    pub pending_stop: bool,
}

impl RecvStream {
    /// Create with the initial flow-control window.
    pub fn new(window: u64, now: Instant) -> Self {
        Self {
            reassembler: StreamReassembler::new(window),
            readable: VecDeque::new(),
            fin: false,
            final_size: None,
            max_data: window,
            window,
            opened_at: now,
            consumed: 0,
            highest: 0,
            pending_max: false,
            reset: false,
            stop_sending: None,
            pending_stop: false,
        }
    }

    /// Whether every byte up to the final size has arrived (RFC 9000
    /// "Data Recvd"): nothing is left to stop the peer sending.
    pub fn all_data_received(&self) -> bool {
        self.fully_reassembled()
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
            self.consumed += front.len() as u64;
            (front, fin)
        } else {
            let got = front.slice(..max);
            self.readable.push_front(front.slice(max..));
            self.consumed += got.len() as u64;
            (got, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_does_not_report_fin_while_a_gap_remains() {
        let mut recv = RecvStream::new(1024, Instant::now());
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
