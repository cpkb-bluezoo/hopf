// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! qlog `frames` arrays for packet events.

use crate::transport::frame::Frame;
use crate::transport::recovery::RecoverableFrame;

/// Builder for one packet's frame list.
pub struct QlogFrames {
    sb: String,
    count: usize,
}

impl QlogFrames {
    /// Empty list.
    pub fn new() -> Self {
        Self {
            sb: String::new(),
            count: 0,
        }
    }

    fn open(&mut self, frame_type: &str) -> &mut String {
        if self.count == 0 {
            self.sb.push('[');
        } else {
            self.sb.push(',');
        }
        self.count += 1;
        self.sb.push_str("{\"frame_type\":\"");
        self.sb.push_str(frame_type);
        self.sb.push('"');
        &mut self.sb
    }

    fn close_frame(&mut self) {
        self.sb.push('}');
    }

    /// JSON array text (`[]` when empty).
    pub fn array(&self) -> String {
        if self.count == 0 {
            "[]".into()
        } else {
            format!("{}]", self.sb)
        }
    }

    pub fn padding(&mut self, length: usize) {
        let sb = self.open("padding");
        sb.push_str(",\"length\":");
        sb.push_str(&length.to_string());
        self.close_frame();
    }

    pub fn ping(&mut self) {
        self.open("ping");
        self.close_frame();
    }

    pub fn crypto(&mut self, offset: u64, length: usize) {
        let sb = self.open("crypto");
        sb.push_str(",\"offset\":");
        sb.push_str(&offset.to_string());
        sb.push_str(",\"length\":");
        sb.push_str(&length.to_string());
        self.close_frame();
    }

    pub fn stream(&mut self, id: u64, offset: u64, length: usize, fin: bool) {
        let sb = self.open("stream");
        sb.push_str(",\"stream_id\":");
        sb.push_str(&id.to_string());
        sb.push_str(",\"offset\":");
        sb.push_str(&offset.to_string());
        sb.push_str(",\"length\":");
        sb.push_str(&length.to_string());
        if fin {
            sb.push_str(",\"fin\":true");
        }
        self.close_frame();
    }

    pub fn ack(&mut self, delay_micros: u64, ranges: &[(u64, u64)]) {
        let sb = self.open("ack");
        sb.push_str(",\"ack_delay\":");
        sb.push_str(&micros_to_millis_json(delay_micros as i64));
        sb.push_str(",\"acked_ranges\":[");
        for (i, (lo, hi)) in ranges.iter().enumerate() {
            if i > 0 {
                sb.push(',');
            }
            sb.push('[');
            sb.push_str(&lo.to_string());
            sb.push(',');
            sb.push_str(&hi.to_string());
            sb.push(']');
        }
        sb.push(']');
        self.close_frame();
    }

    pub fn handshake_done(&mut self) {
        self.open("handshake_done");
        self.close_frame();
    }

    pub fn unknown(&mut self, code: u64) {
        let sb = self.open("unknown");
        sb.push_str(",\"raw_frame_type\":");
        sb.push_str(&code.to_string());
        self.close_frame();
    }
}

impl Default for QlogFrames {
    fn default() -> Self {
        Self::new()
    }
}

pub fn from_recoverable(frames: &[RecoverableFrame]) -> QlogFrames {
    let mut q = QlogFrames::new();
    for f in frames {
        match f {
            RecoverableFrame::Crypto { offset, data } => q.crypto(*offset, data.len()),
            RecoverableFrame::Stream { id, offset, data, fin } => {
                q.stream(id.as_u64(), *offset, data.len(), *fin);
            }
            RecoverableFrame::Ping => q.ping(),
            RecoverableFrame::HandshakeDone => q.handshake_done(),
            RecoverableFrame::Ack { .. } => q.ping(), // ack frames are not retransmitted as ack
            _ => q.ping(),
        }
    }
    q
}

pub fn from_parsed(frames: &[Frame]) -> QlogFrames {
    let mut q = QlogFrames::new();
    for f in frames {
        match f {
            Frame::Padding { len } => q.padding(*len),
            Frame::Ping => q.ping(),
            Frame::Crypto { offset, data } => q.crypto(*offset, data.len()),
            Frame::Stream { id, offset, data, fin } => {
                q.stream(id.as_u64(), *offset, data.len(), *fin);
            }
            Frame::Ack { delay, ranges, .. } => q.ack(*delay, ranges),
            Frame::HandshakeDone => q.handshake_done(),
            _ => q.unknown(0),
        }
    }
    q
}

fn micros_to_millis_json(micros: i64) -> String {
    let negative = micros < 0;
    let abs = micros.unsigned_abs();
    let fraction = abs % 1000;
    let millis = abs / 1000;
    let mut sb = String::with_capacity(24);
    if negative {
        sb.push('-');
    }
    sb.push_str(&millis.to_string());
    sb.push('.');
    if fraction < 100 {
        sb.push('0');
    }
    if fraction < 10 {
        sb.push('0');
    }
    sb.push_str(&fraction.to_string());
    sb
}
