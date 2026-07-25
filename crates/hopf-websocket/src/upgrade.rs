// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Bridge from HTTP [`ProtocolUpgradeHandler`] to WebSocket framing.

use hopf_core::ConnHandle;
use hopf_http::ProtocolUpgradeHandler;

use crate::frame::{Opcode, WsFrameError, WsFrameHandler, WsFrameParser, WsRole};
use crate::session::WsSession;

/// Application callbacks after the WebSocket is open.
pub trait WsEventHandler: Send {
    /// Connection established (after 101 / Extended CONNECT 200).
    ///
    /// `conn` is a cloneable handle to this connection, for hopping work
    /// back onto its reactor from another thread (e.g. a pub/sub bridge
    /// delivering a message published on a different connection) — see
    /// [`hopf_core::ConnHandle`].
    fn opened(&mut self, session: &mut WsSession<'_>, conn: &ConnHandle);

    /// Complete text message (single-frame; fragmented messages not reassembled yet).
    fn text_message(&mut self, session: &mut WsSession<'_>, text: &str) {
        let _ = (session, text);
    }

    /// Complete binary message (single-frame).
    fn binary_message(&mut self, session: &mut WsSession<'_>, data: &[u8]) {
        let _ = (session, data);
    }

    /// Ping received (default: auto-pong).
    fn ping(&mut self, session: &mut WsSession<'_>, payload: &[u8]) {
        session.send_pong(payload);
    }

    /// Pong received.
    fn pong(&mut self, _session: &mut WsSession<'_>, _payload: &[u8]) {}

    /// Close received.
    fn closed(&mut self, _session: &mut WsSession<'_>, _code: u16, _reason: &str) {}

    /// Protocol error.
    fn error(&mut self, _err: WsFrameError) {}
}

/// [`ProtocolUpgradeHandler`] that runs a [`WsFrameParser`] and [`WsEventHandler`].
pub struct WsUpgradeHandler {
    parser: WsFrameParser,
    event: Box<dyn WsEventHandler>,
    out: Vec<u8>,
    role: WsRole,
    conn: ConnHandle,
    opened: bool,
    dead: bool,
}

impl WsUpgradeHandler {
    /// Server-side upgrade handler. `conn` is this connection's
    /// [`ConnHandle`] (from `ServerWriter::conn_handle()`), passed through
    /// to [`WsEventHandler::opened`].
    pub fn server(event: Box<dyn WsEventHandler>, max_payload: usize, conn: ConnHandle) -> Self {
        Self {
            parser: WsFrameParser::new(WsRole::Server, max_payload),
            event,
            out: Vec::new(),
            role: WsRole::Server,
            conn,
            opened: false,
            dead: false,
        }
    }

    /// Client-side upgrade handler. `conn` is this connection's [`ConnHandle`]
    /// (from `Endpoint::handle()`), passed through to [`WsEventHandler::opened`].
    pub fn client(event: Box<dyn WsEventHandler>, max_payload: usize, conn: ConnHandle) -> Self {
        Self {
            parser: WsFrameParser::new(WsRole::Client, max_payload),
            event,
            out: Vec::new(),
            role: WsRole::Client,
            conn,
            opened: false,
            dead: false,
        }
    }

    fn ensure_opened(&mut self) {
        if self.opened {
            return;
        }
        self.opened = true;
        let mut session = WsSession::new(&mut self.out, self.role);
        self.event.opened(&mut session, &self.conn);
    }
}

impl ProtocolUpgradeHandler for WsUpgradeHandler {
    fn receive(&mut self, data: &[u8]) {
        if self.dead {
            return;
        }
        self.ensure_opened();
        let mut bridge = FrameBridge {
            event: &mut *self.event,
            out: &mut self.out,
            role: self.role,
            dead: &mut self.dead,
        };
        self.parser.receive(data, &mut bridge);
    }

    fn take_outbound(&mut self) -> Vec<u8> {
        self.ensure_opened();
        std::mem::take(&mut self.out)
    }

    fn closed(&mut self) {
        if self.dead {
            return;
        }
        self.dead = true;
        let mut session = WsSession::new(&mut self.out, self.role);
        self.event.closed(&mut session, 1006, "abnormal closure");
    }
}

struct FrameBridge<'a> {
    event: &'a mut dyn WsEventHandler,
    out: &'a mut Vec<u8>,
    role: WsRole,
    dead: &'a mut bool,
}

impl WsFrameHandler for FrameBridge<'_> {
    fn data_frame(&mut self, fin: bool, opcode: Opcode, payload: &[u8]) {
        if !fin {
            // Fragmented messages: deliver as binary/text chunks only when FIN
            // for v1 single-frame messages.
            return;
        }
        let mut session = WsSession::new(self.out, self.role);
        match opcode {
            Opcode::Text => {
                if let Ok(s) = std::str::from_utf8(payload) {
                    self.event.text_message(&mut session, s);
                } else {
                    self.event.error(WsFrameError::Protocol("invalid utf-8 text"));
                    *self.dead = true;
                }
            }
            Opcode::Binary | Opcode::Continuation => {
                self.event.binary_message(&mut session, payload);
            }
            _ => {}
        }
    }

    fn ping_frame(&mut self, payload: &[u8]) {
        let mut session = WsSession::new(self.out, self.role);
        self.event.ping(&mut session, payload);
    }

    fn pong_frame(&mut self, payload: &[u8]) {
        let mut session = WsSession::new(self.out, self.role);
        self.event.pong(&mut session, payload);
    }

    fn close_frame(&mut self, payload: &[u8]) {
        let (code, reason) = parse_close(payload);
        let mut session = WsSession::new(self.out, self.role);
        session.send_close(code, "");
        self.event.closed(&mut session, code, reason);
        *self.dead = true;
    }

    fn frame_error(&mut self, err: WsFrameError) {
        self.event.error(err);
        *self.dead = true;
    }
}

fn parse_close(payload: &[u8]) -> (u16, &str) {
    if payload.len() >= 2 {
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        let reason = std::str::from_utf8(&payload[2..]).unwrap_or("");
        (code, reason)
    } else {
        (1005, "")
    }
}
