// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/2 flow control windows (RFC 9113 §5.2).
//!
//! Tracks both the connection-level and per-stream windows for sending
//! and receiving. Generates WINDOW_UPDATE frames when the receive side
//! drops to half the initial size.

use std::collections::HashMap;

/// Initial flow-control window size (65535 octets) per RFC 9113 §6.9.2.
pub const INITIAL_WINDOW_SIZE: i32 = 65535;

/// Threshold at which we emit a WINDOW_UPDATE: when available space falls
/// to ≤ half the initial window.
const UPDATE_THRESHOLD: i32 = INITIAL_WINDOW_SIZE / 2;

/// Connection + per-stream send/receive window accounting.
pub struct FlowControl {
    /// Remaining bytes the local endpoint may receive before issuing a WINDOW_UPDATE.
    conn_recv: i32,
    /// Remaining bytes the local endpoint may send (limited by peer's advertised window).
    conn_send: i32,
    /// Per-stream receive windows (bytes we may still accept from peer).
    stream_recv: HashMap<u32, i32>,
    /// Per-stream send windows (bytes we may still send to peer).
    stream_send: HashMap<u32, i32>,
}

impl FlowControl {
    /// Create with default initial window sizes.
    pub fn new() -> Self {
        Self {
            conn_recv: INITIAL_WINDOW_SIZE,
            conn_send: INITIAL_WINDOW_SIZE,
            stream_recv: HashMap::new(),
            stream_send: HashMap::new(),
        }
    }

    /// Register a new stream with the default initial window.
    pub fn open_stream(&mut self, stream_id: u32, initial_send_window: i32) {
        self.stream_recv.insert(stream_id, INITIAL_WINDOW_SIZE);
        self.stream_send.insert(stream_id, initial_send_window);
    }

    /// Remove a stream's window entries when it closes.
    pub fn close_stream(&mut self, stream_id: u32) {
        self.stream_recv.remove(&stream_id);
        self.stream_send.remove(&stream_id);
    }

    /// Record that `len` bytes of DATA were received on `stream_id`.
    ///
    /// Returns the connection WINDOW_UPDATE increment (0 if not needed) and the
    /// stream WINDOW_UPDATE increment (0 if not needed), each to be sent immediately.
    pub fn on_data_received(&mut self, stream_id: u32, len: usize) -> (u32, u32) {
        let len = len as i32;
        self.conn_recv -= len;
        let conn_update = if self.conn_recv <= UPDATE_THRESHOLD {
            let inc = INITIAL_WINDOW_SIZE - self.conn_recv;
            self.conn_recv += inc;
            inc as u32
        } else {
            0
        };

        let stream_update = if let Some(w) = self.stream_recv.get_mut(&stream_id) {
            *w -= len;
            if *w <= UPDATE_THRESHOLD {
                let inc = INITIAL_WINDOW_SIZE - *w;
                *w += inc;
                inc as u32
            } else {
                0
            }
        } else {
            0
        };

        (conn_update, stream_update)
    }

    /// Record a WINDOW_UPDATE received from the peer for `stream_id`.
    ///
    /// Pass `stream_id = 0` for a connection-level update. Returns `false`
    /// (window left unchanged) if applying it would push the window past
    /// 2³¹−1 — RFC 9113 §6.9.1 requires treating that as a
    /// `FLOW_CONTROL_ERROR`, not silently clamping it.
    #[must_use]
    pub fn on_window_update(&mut self, stream_id: u32, increment: u32) -> bool {
        let inc = increment as i32;
        if stream_id == 0 {
            match self.conn_send.checked_add(inc) {
                Some(v) => {
                    self.conn_send = v;
                    true
                }
                None => false,
            }
        } else if let Some(w) = self.stream_send.get_mut(&stream_id) {
            match w.checked_add(inc) {
                Some(v) => {
                    *w = v;
                    true
                }
                None => false,
            }
        } else {
            true
        }
    }

    /// How many bytes we can currently send on `stream_id` (the minimum of
    /// connection and stream windows). Returns 0 if either is exhausted.
    pub fn available_send(&self, stream_id: u32) -> usize {
        let stream = self.stream_send.get(&stream_id).copied().unwrap_or(0);
        self.conn_send.min(stream).max(0) as usize
    }

    /// Deduct `len` bytes from both the connection and stream send windows.
    ///
    /// Call after writing DATA bytes to the wire.
    pub fn consume_send(&mut self, stream_id: u32, len: usize) {
        let len = len as i32;
        self.conn_send -= len;
        if let Some(w) = self.stream_send.get_mut(&stream_id) {
            *w -= len;
        }
    }

    /// Apply a peer-advertised change to the initial window size for all
    /// existing streams (RFC 9113 §6.9.2).
    pub fn apply_initial_window_size_change(&mut self, new_initial: i32, old_initial: i32) {
        let delta = new_initial - old_initial;
        for w in self.stream_send.values_mut() {
            *w = w.saturating_add(delta);
        }
    }

    /// Connection-level send window (for diagnostics).
    pub fn conn_send_window(&self) -> i32 {
        self.conn_send
    }
}

impl Default for FlowControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_send_consume_and_peer_window_update() {
        let mut fc = FlowControl::new();
        fc.open_stream(1, 100);
        assert_eq!(fc.available_send(1), 100);
        fc.consume_send(1, 40);
        assert_eq!(fc.available_send(1), 60);
        assert_eq!(fc.conn_send_window(), INITIAL_WINDOW_SIZE - 40);
        assert!(fc.on_window_update(1, 10));
        assert_eq!(fc.available_send(1), 70);
        assert!(fc.on_window_update(0, 1000));
        assert_eq!(fc.conn_send_window(), INITIAL_WINDOW_SIZE - 40 + 1000);
        fc.close_stream(1);
        assert_eq!(fc.available_send(1), 0);
    }

    #[test]
    fn recv_triggers_window_update_at_half() {
        let mut fc = FlowControl::new();
        fc.open_stream(3, INITIAL_WINDOW_SIZE);
        // Drain just past threshold on both conn and stream.
        let chunk = (UPDATE_THRESHOLD + 1) as usize;
        let (conn_u, stream_u) = fc.on_data_received(3, chunk);
        assert!(conn_u > 0);
        assert!(stream_u > 0);
        // Small receive should not update.
        let (c2, s2) = fc.on_data_received(3, 1);
        assert_eq!(c2, 0);
        assert_eq!(s2, 0);
    }

    #[test]
    fn stream_window_update_overflowing_2_31_minus_1_is_rejected_not_clamped() {
        let mut fc = FlowControl::new();
        fc.open_stream(1, i32::MAX - 5);
        // Raise the connection window out of the way so `available_send`
        // reflects the stream window alone.
        assert!(fc.on_window_update(0, (i32::MAX - INITIAL_WINDOW_SIZE) as u32));
        assert_eq!(fc.available_send(1), (i32::MAX - 5) as usize);

        // Stream window is already within 5 of the RFC 9113 §6.9.1 ceiling
        // (2^31-1) -- an increment of 10 must be rejected, and the window
        // must be left exactly as it was, not clamped to the max.
        assert!(!fc.on_window_update(1, 10));
        assert_eq!(
            fc.available_send(1),
            (i32::MAX - 5) as usize,
            "must not silently clamp past the ceiling"
        );
    }

    #[test]
    fn connection_window_update_overflowing_2_31_minus_1_is_rejected_not_clamped() {
        let mut fc = FlowControl::new();
        assert!(fc.on_window_update(0, (i32::MAX - INITIAL_WINDOW_SIZE) as u32));
        assert_eq!(fc.conn_send_window(), i32::MAX);

        assert!(!fc.on_window_update(0, 1));
        assert_eq!(
            fc.conn_send_window(),
            i32::MAX,
            "must not silently clamp past the ceiling"
        );
    }

    #[test]
    fn initial_window_size_change_applies_delta() {
        let mut fc = FlowControl::new();
        fc.open_stream(1, 1000);
        fc.apply_initial_window_size_change(2000, 1000);
        assert_eq!(fc.available_send(1), 2000);
    }
}

