// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Stream byte reassembly (CRYPTO + STREAM).

use std::collections::BTreeMap;

use bytes::{Bytes, BytesMut};

/// Reassembles out-of-order / overlapping chunks into contiguous front data.
#[derive(Debug, Default)]
pub struct StreamReassembler {
    pending: BTreeMap<u64, Bytes>,
    next_offset: u64,
    buffered: u64,
    max_buffered: u64,
}

impl StreamReassembler {
    /// Create with a buffer limit.
    pub fn new(max_buffered: u64) -> Self {
        Self {
            pending: BTreeMap::new(),
            next_offset: 0,
            buffered: 0,
            max_buffered,
        }
    }

    /// Next contiguous offset expected.
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// Insert chunk at `offset`; returns newly contiguous bytes at the front.
    pub fn receive(&mut self, offset: u64, data: Bytes) -> Result<Bytes, ()> {
        if data.is_empty() {
            return Ok(Bytes::new());
        }
        let end = offset.saturating_add(data.len() as u64);
        if end <= self.next_offset {
            return Ok(Bytes::new());
        }
        let (offset, data) = if offset < self.next_offset {
            let skip = (self.next_offset - offset) as usize;
            (self.next_offset, data.slice(skip..))
        } else {
            (offset, data)
        };
        if self.buffered.saturating_add(data.len() as u64) > self.max_buffered {
            return Err(());
        }
        // Coalesce into pending (simple: store; merge on drain).
        if let Some(existing) = self.pending.get(&offset) {
            if existing.len() >= data.len() {
                return Ok(Bytes::new());
            }
        }
        self.buffered = self
            .buffered
            .saturating_add(data.len() as u64)
            .saturating_sub(
                self.pending
                    .insert(offset, data)
                    .map(|b| b.len() as u64)
                    .unwrap_or(0),
            );

        let mut out = BytesMut::new();
        while let Some(entry) = self.pending.first_entry() {
            let off = *entry.key();
            if off > self.next_offset {
                break;
            }
            let chunk = entry.remove();
            self.buffered = self.buffered.saturating_sub(chunk.len() as u64);
            if off + chunk.len() as u64 <= self.next_offset {
                continue;
            }
            let skip = (self.next_offset - off) as usize;
            let slice = chunk.slice(skip..);
            self.next_offset += slice.len() as u64;
            out.extend_from_slice(&slice);
        }
        Ok(out.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order() {
        let mut r = StreamReassembler::new(1024);
        let got = r.receive(0, Bytes::from_static(b"ab")).unwrap();
        assert_eq!(got.as_ref(), b"ab");
        assert_eq!(r.next_offset(), 2);
    }

    #[test]
    fn out_of_order() {
        let mut r = StreamReassembler::new(1024);
        assert!(r.receive(2, Bytes::from_static(b"cd")).unwrap().is_empty());
        let got = r.receive(0, Bytes::from_static(b"ab")).unwrap();
        assert_eq!(got.as_ref(), b"abcd");
    }
}
