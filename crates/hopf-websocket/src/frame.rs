// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Push-incremental WebSocket frame parser (RFC 6455 §5).

/// Maximum control-frame payload (RFC 6455 §5.5).
pub const MAX_CONTROL_PAYLOAD: usize = 125;

/// WebSocket opcodes (RFC 6455 §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// Continuation.
    Continuation = 0x0,
    /// Text.
    Text = 0x1,
    /// Binary.
    Binary = 0x2,
    /// Close.
    Close = 0x8,
    /// Ping.
    Ping = 0x9,
    /// Pong.
    Pong = 0xa,
}

impl Opcode {
    /// Parse from the low 4 bits of the first header byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x0f {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xa => Some(Self::Pong),
            _ => None,
        }
    }

    /// Whether this is a control opcode.
    pub fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// Peer role — controls masking expectations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsRole {
    /// Server: inbound frames must be masked; outbound must not.
    Server,
    /// Client: inbound frames must be unmasked; outbound must be masked.
    Client,
}

/// Frame parse / protocol error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WsFrameError {
    /// Reserved opcode or RSV bits set without negotiated extension.
    Protocol(&'static str),
    /// Control frame payload too large or fragmented.
    ControlFrame,
    /// Masking bit does not match role.
    Masking,
    /// Payload exceeds configured limit.
    TooLarge,
}

impl std::fmt::Display for WsFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(m) => write!(f, "websocket protocol: {m}"),
            Self::ControlFrame => write!(f, "invalid control frame"),
            Self::Masking => write!(f, "invalid masking"),
            Self::TooLarge => write!(f, "payload too large"),
        }
    }
}

impl std::error::Error for WsFrameError {}

/// Callbacks for recognized frames (zero-copy payload for the call).
pub trait WsFrameHandler {
    /// Data or continuation frame.
    fn data_frame(&mut self, fin: bool, opcode: Opcode, payload: &[u8]);
    /// Ping.
    fn ping_frame(&mut self, payload: &[u8]);
    /// Pong.
    fn pong_frame(&mut self, payload: &[u8]);
    /// Close (payload is raw close body: optional 2-byte code + reason).
    fn close_frame(&mut self, payload: &[u8]);
    /// Fatal protocol error — caller should abort the connection.
    fn frame_error(&mut self, err: WsFrameError);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Header,
    ExtLen,
    MaskKey,
    Payload,
}

/// Incremental WebSocket frame parser.
pub struct WsFrameParser {
    role: WsRole,
    max_payload: usize,
    step: Step,
    buf: Vec<u8>,
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload_len: u64,
    mask: [u8; 4],
    payload: Vec<u8>,
    need: usize,
}

impl WsFrameParser {
    /// Create a parser for `role` with a maximum data-frame payload size.
    pub fn new(role: WsRole, max_payload: usize) -> Self {
        Self {
            role,
            max_payload,
            step: Step::Header,
            buf: Vec::with_capacity(14),
            fin: false,
            opcode: Opcode::Text,
            masked: false,
            payload_len: 0,
            mask: [0; 4],
            payload: Vec::new(),
            need: 2,
        }
    }

    /// Feed bytes; invokes handler callbacks as frames complete.
    pub fn receive(&mut self, mut data: &[u8], handler: &mut dyn WsFrameHandler) {
        while !data.is_empty() {
            let take = data.len().min(self.need.saturating_sub(self.buf.len()));
            if take == 0 && self.need == 0 {
                break;
            }
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() < self.need {
                continue;
            }
            match self.step {
                Step::Header => {
                    if !self.parse_header(handler) {
                        return;
                    }
                }
                Step::ExtLen => {
                    if !self.parse_ext_len(handler) {
                        return;
                    }
                }
                Step::MaskKey => {
                    self.mask.copy_from_slice(&self.buf[..4]);
                    self.buf.clear();
                    if !self.begin_payload(handler) {
                        return;
                    }
                }
                Step::Payload => {
                    self.payload.extend_from_slice(&self.buf);
                    self.buf.clear();
                    self.finish_frame(handler);
                }
            }
        }
    }

    fn parse_header(&mut self, handler: &mut dyn WsFrameHandler) -> bool {
        let b0 = self.buf[0];
        let b1 = self.buf[1];
        self.buf.clear();

        if b0 & 0x70 != 0 {
            handler.frame_error(WsFrameError::Protocol("RSV bits set"));
            return false;
        }
        self.fin = b0 & 0x80 != 0;
        let Some(opcode) = Opcode::from_u8(b0) else {
            handler.frame_error(WsFrameError::Protocol("unknown opcode"));
            return false;
        };
        self.opcode = opcode;
        self.masked = b1 & 0x80 != 0;
        let len7 = b1 & 0x7f;

        match (self.role, self.masked) {
            (WsRole::Server, false) | (WsRole::Client, true) => {
                handler.frame_error(WsFrameError::Masking);
                return false;
            }
            _ => {}
        }

        if self.opcode.is_control() {
            if !self.fin || len7 > MAX_CONTROL_PAYLOAD as u8 {
                handler.frame_error(WsFrameError::ControlFrame);
                return false;
            }
        }

        match len7 {
            126 => {
                self.step = Step::ExtLen;
                self.need = 2;
                true
            }
            127 => {
                self.step = Step::ExtLen;
                self.need = 8;
                true
            }
            n => {
                self.payload_len = u64::from(n);
                if self.payload_len as usize > self.max_payload && !self.opcode.is_control() {
                    handler.frame_error(WsFrameError::TooLarge);
                    return false;
                }
                self.after_length(handler)
            }
        }
    }

    fn parse_ext_len(&mut self, handler: &mut dyn WsFrameHandler) -> bool {
        let len = if self.need == 2 {
            u64::from(u16::from_be_bytes([self.buf[0], self.buf[1]]))
        } else {
            u64::from_be_bytes(self.buf[..8].try_into().unwrap())
        };
        self.buf.clear();
        if len > self.max_payload as u64 && !self.opcode.is_control() {
            handler.frame_error(WsFrameError::TooLarge);
            return false;
        }
        self.payload_len = len;
        self.after_length(handler)
    }

    fn after_length(&mut self, handler: &mut dyn WsFrameHandler) -> bool {
        if self.masked {
            self.step = Step::MaskKey;
            self.need = 4;
            true
        } else {
            self.begin_payload(handler)
        }
    }

    /// Returns false if a fatal error was reported.
    fn begin_payload(&mut self, handler: &mut dyn WsFrameHandler) -> bool {
        self.payload.clear();
        let n = self.payload_len as usize;
        if n == 0 {
            self.finish_frame(handler);
            true
        } else {
            self.step = Step::Payload;
            self.need = n;
            self.payload.reserve(n);
            true
        }
    }

    fn finish_frame(&mut self, handler: &mut dyn WsFrameHandler) {
        if self.masked {
            for (i, b) in self.payload.iter_mut().enumerate() {
                *b ^= self.mask[i % 4];
            }
        }

        match self.opcode {
            Opcode::Ping => handler.ping_frame(&self.payload),
            Opcode::Pong => handler.pong_frame(&self.payload),
            Opcode::Close => handler.close_frame(&self.payload),
            op => handler.data_frame(self.fin, op, &self.payload),
        }

        self.step = Step::Header;
        self.need = 2;
        self.buf.clear();
        self.payload.clear();
    }
}

/// Apply a 4-byte mask to `payload` in place (client→server).
pub fn apply_mask(mask: [u8; 4], payload: &mut [u8]) {
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
}

/// Write a frame header + payload into `out`.
pub fn write_frame(
    out: &mut Vec<u8>,
    fin: bool,
    opcode: Opcode,
    mask: Option<[u8; 4]>,
    payload: &[u8],
) {
    let mut b0 = opcode as u8;
    if fin {
        b0 |= 0x80;
    }
    out.push(b0);

    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    let len = payload.len();
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len <= 0xffff {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }

    if let Some(m) = mask {
        out.extend_from_slice(&m);
        let start = out.len();
        out.extend_from_slice(payload);
        apply_mask(m, &mut out[start..]);
    } else {
        out.extend_from_slice(payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rec {
        events: Vec<String>,
    }

    impl WsFrameHandler for Rec {
        fn data_frame(&mut self, fin: bool, opcode: Opcode, payload: &[u8]) {
            self.events.push(format!(
                "data fin={fin} op={opcode:?} {}",
                String::from_utf8_lossy(payload)
            ));
        }
        fn ping_frame(&mut self, payload: &[u8]) {
            self.events
                .push(format!("ping {}", String::from_utf8_lossy(payload)));
        }
        fn pong_frame(&mut self, _payload: &[u8]) {
            self.events.push("pong".into());
        }
        fn close_frame(&mut self, _payload: &[u8]) {
            self.events.push("close".into());
        }
        fn frame_error(&mut self, err: WsFrameError) {
            self.events.push(format!("err:{err}"));
        }
    }

    #[test]
    fn server_receives_masked_text() {
        let mut out = Vec::new();
        let mask = [1, 2, 3, 4];
        write_frame(&mut out, true, Opcode::Text, Some(mask), b"hi");

        let mut p = WsFrameParser::new(WsRole::Server, 1024);
        let mut h = Rec { events: vec![] };
        p.receive(&out, &mut h);
        assert_eq!(h.events, vec!["data fin=true op=Text hi".to_string()]);
    }

    #[test]
    fn split_feed() {
        let mut out = Vec::new();
        write_frame(&mut out, true, Opcode::Text, Some([9, 8, 7, 6]), b"abc");
        let mut p = WsFrameParser::new(WsRole::Server, 1024);
        let mut h = Rec { events: vec![] };
        p.receive(&out[..1], &mut h);
        assert!(h.events.is_empty());
        p.receive(&out[1..], &mut h);
        assert_eq!(h.events.len(), 1);
    }

    #[test]
    fn unmasked_to_server_is_error() {
        let mut out = Vec::new();
        write_frame(&mut out, true, Opcode::Text, None, b"x");
        let mut p = WsFrameParser::new(WsRole::Server, 1024);
        let mut h = Rec { events: vec![] };
        p.receive(&out, &mut h);
        assert!(h.events[0].starts_with("err:"));
    }
}
