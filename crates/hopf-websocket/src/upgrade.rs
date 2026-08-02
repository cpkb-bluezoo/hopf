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

    /// Complete text message (single-frame or reassembled fragments).
    fn text_message(&mut self, session: &mut WsSession<'_>, text: &str) {
        let _ = (session, text);
    }

    /// Complete binary message (single-frame or reassembled fragments).
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

/// In-progress fragmented message (RFC 6455 §5.4).
struct FragmentBuf {
    opcode: Opcode,
    buf: Vec<u8>,
}

/// [`ProtocolUpgradeHandler`] that runs a [`WsFrameParser`] and [`WsEventHandler`].
pub struct WsUpgradeHandler {
    parser: WsFrameParser,
    event: Box<dyn WsEventHandler>,
    out: Vec<u8>,
    role: WsRole,
    conn: ConnHandle,
    max_payload: usize,
    opened: bool,
    dead: bool,
    fragment: Option<FragmentBuf>,
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
            max_payload,
            opened: false,
            dead: false,
            fragment: None,
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
            max_payload,
            opened: false,
            dead: false,
            fragment: None,
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
            max_payload: self.max_payload,
            dead: &mut self.dead,
            fragment: &mut self.fragment,
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

    fn wants_close(&self) -> bool {
        self.dead
    }
}

struct FrameBridge<'a> {
    event: &'a mut dyn WsEventHandler,
    out: &'a mut Vec<u8>,
    role: WsRole,
    max_payload: usize,
    dead: &'a mut bool,
    fragment: &'a mut Option<FragmentBuf>,
}

impl FrameBridge<'_> {
    fn fail(&mut self, close_code: u16, err: WsFrameError) {
        if *self.dead {
            return;
        }
        {
            let mut session = WsSession::new(self.out, self.role);
            session.send_close(close_code, "");
        }
        self.event.error(err);
        *self.dead = true;
        self.fragment.take();
    }

    fn deliver_complete(&mut self, opcode: Opcode, payload: &[u8]) {
        let mut session = WsSession::new(self.out, self.role);
        match opcode {
            Opcode::Text => {
                if let Ok(s) = std::str::from_utf8(payload) {
                    self.event.text_message(&mut session, s);
                } else {
                    drop(session);
                    self.fail(1007, WsFrameError::Protocol("invalid utf-8 text"));
                }
            }
            Opcode::Binary => {
                self.event.binary_message(&mut session, payload);
            }
            _ => {}
        }
    }
}

impl WsFrameHandler for FrameBridge<'_> {
    fn data_frame(&mut self, fin: bool, opcode: Opcode, payload: &[u8]) {
        if *self.dead {
            return;
        }
        match opcode {
            Opcode::Text | Opcode::Binary => {
                if self.fragment.is_some() {
                    self.fail(
                        1002,
                        WsFrameError::Protocol("data frame while fragment in progress"),
                    );
                    return;
                }
                if !fin {
                    if payload.len() > self.max_payload {
                        self.fail(1009, WsFrameError::TooLarge);
                        return;
                    }
                    *self.fragment = Some(FragmentBuf {
                        opcode,
                        buf: payload.to_vec(),
                    });
                    return;
                }
                self.deliver_complete(opcode, payload);
            }
            Opcode::Continuation => {
                let Some(frag) = self.fragment.as_mut() else {
                    // RFC 6455 §5.4 — continuation with no message in progress.
                    self.fail(
                        1002,
                        WsFrameError::Protocol("unexpected continuation frame"),
                    );
                    return;
                };
                if frag.buf.len().saturating_add(payload.len()) > self.max_payload {
                    self.fail(1009, WsFrameError::TooLarge);
                    return;
                }
                frag.buf.extend_from_slice(payload);
                if fin {
                    let frag = self.fragment.take().unwrap();
                    self.deliver_complete(frag.opcode, &frag.buf);
                }
            }
            _ => {}
        }
    }

    fn ping_frame(&mut self, payload: &[u8]) {
        if *self.dead {
            return;
        }
        let mut session = WsSession::new(self.out, self.role);
        self.event.ping(&mut session, payload);
    }

    fn pong_frame(&mut self, payload: &[u8]) {
        if *self.dead {
            return;
        }
        let mut session = WsSession::new(self.out, self.role);
        self.event.pong(&mut session, payload);
    }

    fn close_frame(&mut self, payload: &[u8]) {
        if *self.dead {
            return;
        }
        if payload.len() == 1 {
            // Single-byte close payload is illegal (§5.5.1).
            self.fail(1002, WsFrameError::Protocol("invalid close payload length"));
            return;
        }
        if payload.len() >= 2 {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            if !is_valid_close_code(code) {
                self.fail(1002, WsFrameError::Protocol("invalid close status code"));
                return;
            }
            if std::str::from_utf8(&payload[2..]).is_err() {
                self.fail(1007, WsFrameError::Protocol("invalid close reason utf-8"));
                return;
            }
        }
        let (code, reason) = parse_close(payload);
        {
            let mut session = WsSession::new(self.out, self.role);
            if payload.len() < 2 {
                session.send_close_empty();
            } else {
                // Echo the peer's code; omit reason body (optional).
                session.send_close(code, "");
            }
            self.event.closed(&mut session, code, reason);
        }
        *self.dead = true;
        self.fragment.take();
    }

    fn frame_error(&mut self, err: WsFrameError) {
        let code = close_code_for_error(&err);
        self.fail(code, err);
    }
}

/// Close status codes that may appear on the wire (RFC 6455 §7.4 / IANA).
///
/// Excludes 1004, 1005, 1006, 1015 (must not be set in a Close frame) and
/// the unassigned 0–999 / 1016–2999 ranges.
pub fn is_valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

fn close_code_for_error(err: &WsFrameError) -> u16 {
    match err {
        WsFrameError::TooLarge => 1009,
        WsFrameError::Protocol(msg) if msg.contains("utf-8") => 1007,
        _ => 1002,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::write_frame;
    use std::sync::{Arc, Mutex};

    struct Collect {
        texts: Vec<String>,
        binaries: Vec<Vec<u8>>,
        errors: Vec<WsFrameError>,
        closes: Vec<u16>,
    }

    struct CollectHandler(Arc<Mutex<Collect>>);

    impl WsEventHandler for CollectHandler {
        fn opened(&mut self, _session: &mut WsSession<'_>, _conn: &ConnHandle) {}
        fn text_message(&mut self, _session: &mut WsSession<'_>, text: &str) {
            self.0.lock().unwrap().texts.push(text.to_string());
        }
        fn binary_message(&mut self, _session: &mut WsSession<'_>, data: &[u8]) {
            self.0.lock().unwrap().binaries.push(data.to_vec());
        }
        fn closed(&mut self, _session: &mut WsSession<'_>, code: u16, _reason: &str) {
            self.0.lock().unwrap().closes.push(code);
        }
        fn error(&mut self, err: WsFrameError) {
            self.0.lock().unwrap().errors.push(err);
        }
    }

    fn masked_frame(fin: bool, opcode: Opcode, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame(&mut out, fin, opcode, Some([1, 2, 3, 4]), payload);
        out
    }

    fn server_handler(collect: Arc<Mutex<Collect>>) -> WsUpgradeHandler {
        let conn = ConnHandle::from_execute(std::sync::Arc::new(|t| t()));
        WsUpgradeHandler::server(Box::new(CollectHandler(collect)), 1024, conn)
    }

    #[test]
    fn reassembles_fragmented_text() {
        let collect = Arc::new(Mutex::new(Collect {
            texts: vec![],
            binaries: vec![],
            errors: vec![],
            closes: vec![],
        }));
        let mut h = server_handler(Arc::clone(&collect));
        let f1 = masked_frame(false, Opcode::Text, b"hel");
        let f2 = masked_frame(true, Opcode::Continuation, b"lo");
        h.receive(&f1);
        h.receive(&f2);
        assert!(!h.dead);
        assert_eq!(collect.lock().unwrap().texts, vec!["hello"]);
    }

    #[test]
    fn orphan_continuation_is_protocol_error() {
        let collect = Arc::new(Mutex::new(Collect {
            texts: vec![],
            binaries: vec![],
            errors: vec![],
            closes: vec![],
        }));
        let mut h = server_handler(Arc::clone(&collect));
        let f = masked_frame(true, Opcode::Continuation, b"x");
        h.receive(&f);
        assert!(h.dead);
        assert!(h.wants_close());
        assert!(!collect.lock().unwrap().errors.is_empty());
        let out = h.take_outbound();
        // Close frame (unmasked, server→client) with code 1002.
        assert!(out.len() >= 4);
        assert_eq!(out[0] & 0x0f, Opcode::Close as u8);
        assert_eq!(&out[out.len() - 2..], &1002u16.to_be_bytes());
    }

    #[test]
    fn invalid_close_code_rejected() {
        assert!(!is_valid_close_code(1004));
        assert!(!is_valid_close_code(1005));
        assert!(!is_valid_close_code(1006));
        assert!(!is_valid_close_code(1015));
        assert!(!is_valid_close_code(999));
        assert!(is_valid_close_code(1000));
        assert!(is_valid_close_code(1007));
        assert!(is_valid_close_code(3000));

        let collect = Arc::new(Mutex::new(Collect {
            texts: vec![],
            binaries: vec![],
            errors: vec![],
            closes: vec![],
        }));
        let mut h = server_handler(Arc::clone(&collect));
        let mut payload = Vec::new();
        payload.extend_from_slice(&1005u16.to_be_bytes());
        let f = masked_frame(true, Opcode::Close, &payload);
        h.receive(&f);
        assert!(h.dead);
        assert!(collect.lock().unwrap().closes.is_empty());
        let out = h.take_outbound();
        assert_eq!(out[0] & 0x0f, Opcode::Close as u8);
        assert_eq!(&out[out.len() - 2..], &1002u16.to_be_bytes());
    }

    #[test]
    fn empty_close_echoes_empty_payload() {
        let collect = Arc::new(Mutex::new(Collect {
            texts: vec![],
            binaries: vec![],
            errors: vec![],
            closes: vec![],
        }));
        let mut h = server_handler(Arc::clone(&collect));
        let f = masked_frame(true, Opcode::Close, &[]);
        h.receive(&f);
        assert!(h.dead);
        assert_eq!(collect.lock().unwrap().closes, vec![1005]);
        let out = h.take_outbound();
        // Server close: FIN|Close, len 0, no mask, no payload — never 1005 on wire.
        assert_eq!(out[0] & 0x0f, Opcode::Close as u8);
        assert_eq!(out[1] & 0x7f, 0);
    }
}
