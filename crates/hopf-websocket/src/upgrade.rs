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

    /// Re-entry point for work stashed by another thread (e.g. a storage
    /// pool completion callback) that needs `&mut self` access to finish —
    /// the WebSocket-layer counterpart of [`hopf_core::Endpoint::poke_handler`]/
    /// [`hopf_core::ConnHandle::poke`], which only reach the raw transport's
    /// `ProtocolHandler`, not a handler layered on top via WebSocket framing
    /// (issue #232). Called with no frame data, purely to give a handler a
    /// chance to apply a pending outcome and reply via `session` (e.g. a
    /// deferred CONNACK once an offloaded credential check resolves) —
    /// default no-op for handlers that never offload work this way.
    fn poke(&mut self, _session: &mut WsSession<'_>) {}

    /// Whether this handler wants incremental delivery via [`Self::text_chunk`]/
    /// [`Self::binary_chunk`] instead of whole-message buffering.
    ///
    /// Defaults to `false`: `text_message`/`binary_message` fire once per
    /// complete message, exactly as before streaming support existed —
    /// existing handlers are unaffected. Override to return `true` to
    /// receive chunks as they arrive (across possibly several fragmented
    /// frames, RFC 6455 §5.4) without the whole message ever being
    /// buffered; `text_message`/`binary_message` are then never called.
    fn wants_streaming(&self) -> bool {
        false
    }

    /// Complete text message (single-frame or reassembled fragments).
    /// Not called when [`Self::wants_streaming`] returns `true`.
    fn text_message(&mut self, session: &mut WsSession<'_>, text: &str) {
        let _ = (session, text);
    }

    /// Complete binary message (single-frame or reassembled fragments).
    /// Not called when [`Self::wants_streaming`] returns `true`.
    fn binary_message(&mut self, session: &mut WsSession<'_>, data: &[u8]) {
        let _ = (session, data);
    }

    /// Binary message payload chunk (only called when [`Self::wants_streaming`]
    /// returns `true`). Called as bytes arrive, across one or more
    /// fragmented frames; `is_final` is true on the chunk completing the
    /// logical message.
    fn binary_chunk(&mut self, session: &mut WsSession<'_>, chunk: &[u8], is_final: bool) {
        let _ = (session, chunk, is_final);
    }

    /// Text message payload chunk (only called when [`Self::wants_streaming`]
    /// returns `true`). `chunk` is a valid UTF-8 fragment — the parser
    /// holds back any incomplete trailing multi-byte sequence until enough
    /// bytes arrive to complete it, so `chunk` never splits a codepoint.
    /// `is_final` is true on the chunk completing the logical message.
    fn text_chunk(&mut self, session: &mut WsSession<'_>, chunk: &str, is_final: bool) {
        let _ = (session, chunk, is_final);
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

/// In-progress fragmented message (RFC 6455 §5.4), buffered whole
/// (non-streaming handlers — [`WsEventHandler::wants_streaming`] is `false`).
struct FragmentBuf {
    opcode: Opcode,
    buf: Vec<u8>,
}

/// In-progress message for a streaming handler
/// ([`WsEventHandler::wants_streaming`] is `true`) — no payload buffer,
/// just enough state to validate fragmentation and (for text) hold back an
/// incomplete trailing UTF-8 sequence across chunk/frame boundaries.
struct StreamState {
    opcode: Opcode,
    total: u64,
    utf8_carry: Vec<u8>,
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
    stream: Option<StreamState>,
    /// True while still mid-way through the *physical* frame currently
    /// being delivered by [`WsFrameParser`] (i.e. the last `data_frame`
    /// call had `chunk_end` false) — distinguishes "first chunk of a new
    /// frame" (where fragmentation validity must be checked) from "more
    /// bytes of a frame already in progress" (issue #192: a single frame's
    /// payload can now arrive across many `data_frame` calls).
    mid_frame: bool,
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
            stream: None,
            mid_frame: false,
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
            stream: None,
            mid_frame: false,
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
        {
            // See `WsEventHandler::poke` — this runs unconditionally (not
            // just for an empty `data` "pure poke" call) so a poke that
            // happens to race with real inbound bytes in the same
            // `receive()` call still gets serviced, same as `receive`
            // itself always would.
            let mut session = WsSession::new(&mut self.out, self.role);
            self.event.poke(&mut session);
        }
        let streaming = self.event.wants_streaming();
        let mut bridge = FrameBridge {
            event: &mut *self.event,
            out: &mut self.out,
            role: self.role,
            max_payload: self.max_payload,
            dead: &mut self.dead,
            fragment: &mut self.fragment,
            stream: &mut self.stream,
            mid_frame: &mut self.mid_frame,
            streaming,
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
    stream: &'a mut Option<StreamState>,
    mid_frame: &'a mut bool,
    streaming: bool,
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
        self.stream.take();
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

    /// Buffered-mode data frame handling (default, non-streaming handlers):
    /// accumulate every chunk — whether it's another slice of the same
    /// physical frame (issue #192: a frame's payload can now arrive across
    /// several `data_frame` calls) or a subsequent continuation frame —
    /// into one `FragmentBuf`, delivering the complete message only once
    /// `fin && chunk_end`.
    fn data_frame_buffered(&mut self, fin: bool, opcode: Opcode, chunk: &[u8], chunk_end: bool, is_frame_start: bool) {
        match opcode {
            Opcode::Text | Opcode::Binary => {
                if is_frame_start {
                    if self.fragment.is_some() {
                        self.fail(
                            1002,
                            WsFrameError::Protocol("data frame while fragment in progress"),
                        );
                        return;
                    }
                    *self.fragment = Some(FragmentBuf {
                        opcode,
                        buf: Vec::new(),
                    });
                }
                let frag = self.fragment.as_mut().unwrap();
                if frag.buf.len().saturating_add(chunk.len()) > self.max_payload {
                    self.fail(1009, WsFrameError::TooLarge);
                    return;
                }
                frag.buf.extend_from_slice(chunk);
                if chunk_end && fin {
                    let frag = self.fragment.take().unwrap();
                    self.deliver_complete(frag.opcode, &frag.buf);
                }
            }
            Opcode::Continuation => {
                if is_frame_start && self.fragment.is_none() {
                    // RFC 6455 §5.4 — continuation with no message in progress.
                    self.fail(
                        1002,
                        WsFrameError::Protocol("unexpected continuation frame"),
                    );
                    return;
                }
                let Some(frag) = self.fragment.as_mut() else {
                    return;
                };
                if frag.buf.len().saturating_add(chunk.len()) > self.max_payload {
                    self.fail(1009, WsFrameError::TooLarge);
                    return;
                }
                frag.buf.extend_from_slice(chunk);
                if chunk_end && fin {
                    let frag = self.fragment.take().unwrap();
                    self.deliver_complete(frag.opcode, &frag.buf);
                }
            }
            _ => {}
        }
    }

    /// Streaming-mode data frame handling ([`WsEventHandler::wants_streaming`]
    /// returns `true`): never buffers the message, delivers each chunk via
    /// `binary_chunk`/`text_chunk` as it arrives. Only a running byte count
    /// (for `max_payload`) and, for text, a small carry-over of an
    /// incomplete trailing UTF-8 sequence are kept between calls.
    fn data_frame_streaming(&mut self, fin: bool, opcode: Opcode, chunk: &[u8], chunk_end: bool, is_frame_start: bool) {
        let msg_opcode = match opcode {
            Opcode::Text | Opcode::Binary => {
                if is_frame_start {
                    if self.stream.is_some() {
                        self.fail(
                            1002,
                            WsFrameError::Protocol("data frame while fragment in progress"),
                        );
                        return;
                    }
                    *self.stream = Some(StreamState {
                        opcode,
                        total: 0,
                        utf8_carry: Vec::new(),
                    });
                }
                opcode
            }
            Opcode::Continuation => {
                if is_frame_start && self.stream.is_none() {
                    self.fail(
                        1002,
                        WsFrameError::Protocol("unexpected continuation frame"),
                    );
                    return;
                }
                let Some(st) = self.stream.as_ref() else {
                    return;
                };
                st.opcode
            }
            _ => return,
        };

        let st = self.stream.as_mut().unwrap();
        st.total += chunk.len() as u64;
        if st.total > self.max_payload as u64 {
            self.fail(1009, WsFrameError::TooLarge);
            return;
        }
        let is_final = chunk_end && fin;

        match msg_opcode {
            Opcode::Binary => {
                let mut session = WsSession::new(self.out, self.role);
                self.event.binary_chunk(&mut session, chunk, is_final);
                if is_final {
                    self.stream.take();
                }
            }
            Opcode::Text => {
                let mut carry = std::mem::take(&mut st.utf8_carry);
                carry.extend_from_slice(chunk);
                match validate_utf8_prefix(&carry, is_final) {
                    Ok((valid_len, tail)) => {
                        let text = std::str::from_utf8(&carry[..valid_len]).unwrap();
                        let mut session = WsSession::new(self.out, self.role);
                        self.event.text_chunk(&mut session, text, is_final);
                        if is_final {
                            self.stream.take();
                        } else {
                            self.stream.as_mut().unwrap().utf8_carry = tail;
                        }
                    }
                    Err(()) => {
                        self.fail(1007, WsFrameError::Protocol("invalid utf-8 text"));
                    }
                }
            }
            _ => unreachable!("msg_opcode is always Text or Binary"),
        }
    }
}

impl WsFrameHandler for FrameBridge<'_> {
    fn data_frame(&mut self, fin: bool, opcode: Opcode, chunk: &[u8], chunk_end: bool) {
        if *self.dead {
            return;
        }
        let is_frame_start = !*self.mid_frame;
        *self.mid_frame = !chunk_end;
        if self.streaming {
            self.data_frame_streaming(fin, opcode, chunk, chunk_end, is_frame_start);
        } else {
            self.data_frame_buffered(fin, opcode, chunk, chunk_end, is_frame_start);
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

/// Validates `bytes` as UTF-8, tolerating an incomplete multi-byte sequence
/// at the very end (which a later chunk may complete). Returns
/// `(valid_len, tail)`: `bytes[..valid_len]` is guaranteed-valid UTF-8 to
/// deliver now, `tail` is the incomplete trailing bytes (if any) to
/// prepend to the next chunk. `is_final` forbids a trailing incomplete
/// sequence — the message ended mid-codepoint, which is invalid UTF-8.
fn validate_utf8_prefix(bytes: &[u8], is_final: bool) -> Result<(usize, Vec<u8>), ()> {
    match std::str::from_utf8(bytes) {
        Ok(_) => Ok((bytes.len(), Vec::new())),
        Err(e) => {
            if e.error_len().is_some() || is_final {
                return Err(());
            }
            let valid_up_to = e.valid_up_to();
            Ok((valid_up_to, bytes[valid_up_to..].to_vec()))
        }
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

    /// Issue #192: a handler that opts into streaming (`wants_streaming`)
    /// gets `binary_chunk`/`text_chunk` calls instead of whole-message
    /// `binary_message`/`text_message`.
    #[derive(Default)]
    struct StreamCollect {
        binary_chunks: Vec<(Vec<u8>, bool)>,
        text_chunks: Vec<(String, bool)>,
        whole_texts: Vec<String>,
        whole_binaries: Vec<Vec<u8>>,
        errors: Vec<WsFrameError>,
    }

    struct StreamingHandler(Arc<Mutex<StreamCollect>>);

    impl WsEventHandler for StreamingHandler {
        fn opened(&mut self, _session: &mut WsSession<'_>, _conn: &ConnHandle) {}
        fn wants_streaming(&self) -> bool {
            true
        }
        fn text_message(&mut self, _session: &mut WsSession<'_>, text: &str) {
            self.0.lock().unwrap().whole_texts.push(text.to_string());
        }
        fn binary_message(&mut self, _session: &mut WsSession<'_>, data: &[u8]) {
            self.0.lock().unwrap().whole_binaries.push(data.to_vec());
        }
        fn binary_chunk(&mut self, _session: &mut WsSession<'_>, chunk: &[u8], is_final: bool) {
            self.0
                .lock()
                .unwrap()
                .binary_chunks
                .push((chunk.to_vec(), is_final));
        }
        fn text_chunk(&mut self, _session: &mut WsSession<'_>, chunk: &str, is_final: bool) {
            self.0
                .lock()
                .unwrap()
                .text_chunks
                .push((chunk.to_string(), is_final));
        }
        fn error(&mut self, err: WsFrameError) {
            self.0.lock().unwrap().errors.push(err);
        }
    }

    fn streaming_server_handler(collect: Arc<Mutex<StreamCollect>>) -> WsUpgradeHandler {
        let conn = ConnHandle::from_execute(std::sync::Arc::new(|t| t()));
        WsUpgradeHandler::server(Box::new(StreamingHandler(collect)), 1_000_000, conn)
    }

    #[test]
    fn streaming_handler_delivers_binary_chunks_not_whole_message() {
        let collect = Arc::new(Mutex::new(StreamCollect::default()));
        let mut h = streaming_server_handler(Arc::clone(&collect));
        let payload: Vec<u8> = (0..200u32).map(|i| (i % 256) as u8).collect();
        let f = masked_frame(true, Opcode::Binary, &payload);
        for chunk in f.chunks(7) {
            h.receive(chunk);
        }
        let c = collect.lock().unwrap();
        assert!(
            c.binary_chunks.len() > 1,
            "expected multiple chunk deliveries, got {}",
            c.binary_chunks.len()
        );
        assert!(
            c.whole_binaries.is_empty(),
            "binary_message must not be called in streaming mode"
        );
        let reconstructed: Vec<u8> = c.binary_chunks.iter().flat_map(|(b, _)| b.clone()).collect();
        assert_eq!(reconstructed, payload);
        assert!(c.binary_chunks.last().unwrap().1);
        assert!(c.binary_chunks[..c.binary_chunks.len() - 1]
            .iter()
            .all(|(_, is_final)| !is_final));
    }

    /// Every possible split point of the frame bytes reconstructs the
    /// exact original payload via chunk concatenation.
    #[test]
    fn streaming_binary_reconstructed_at_every_split_point() {
        let payload: Vec<u8> = (0..53u8).collect();
        let f = masked_frame(true, Opcode::Binary, &payload);
        for split in 0..=f.len() {
            let collect = Arc::new(Mutex::new(StreamCollect::default()));
            let mut h = streaming_server_handler(Arc::clone(&collect));
            h.receive(&f[..split]);
            h.receive(&f[split..]);
            let c = collect.lock().unwrap();
            let reconstructed: Vec<u8> = c.binary_chunks.iter().flat_map(|(b, _)| b.clone()).collect();
            assert_eq!(reconstructed, payload, "wrong reconstruction at split {split}");
            assert!(c.binary_chunks.last().unwrap().1, "missing final flag at split {split}");
        }
    }

    #[test]
    fn streaming_handler_reassembles_fragmented_text_via_chunks() {
        let collect = Arc::new(Mutex::new(StreamCollect::default()));
        let mut h = streaming_server_handler(Arc::clone(&collect));
        let f1 = masked_frame(false, Opcode::Text, b"hel");
        let f2 = masked_frame(true, Opcode::Continuation, b"lo");
        h.receive(&f1);
        h.receive(&f2);
        let c = collect.lock().unwrap();
        assert!(c.whole_texts.is_empty());
        let joined: String = c.text_chunks.iter().map(|(s, _)| s.as_str()).collect();
        assert_eq!(joined, "hello");
        assert!(c.text_chunks.last().unwrap().1);
    }

    /// A chunk boundary landing in the middle of a multi-byte UTF-8
    /// codepoint must not be delivered as a partial (invalid) `&str` —
    /// the incomplete tail is carried over until it can be completed.
    #[test]
    fn streaming_text_holds_back_split_utf8_codepoint() {
        let collect = Arc::new(Mutex::new(StreamCollect::default()));
        let mut h = streaming_server_handler(Arc::clone(&collect));
        let text = "héllo wörld \u{1F389}"; // 2-byte and 4-byte sequences
        let f = masked_frame(true, Opcode::Text, text.as_bytes());
        for b in &f {
            h.receive(std::slice::from_ref(b));
        }
        let c = collect.lock().unwrap();
        assert!(c.errors.is_empty(), "errors: {:?}", c.errors);
        let joined: String = c.text_chunks.iter().map(|(s, _)| s.as_str()).collect();
        assert_eq!(joined, text);
        assert!(c.text_chunks.last().unwrap().1);
    }

    #[test]
    fn streaming_text_rejects_invalid_utf8() {
        let collect = Arc::new(Mutex::new(StreamCollect::default()));
        let mut h = streaming_server_handler(Arc::clone(&collect));
        let bad = [0xff, 0xfe, b'x'];
        let f = masked_frame(true, Opcode::Text, &bad);
        h.receive(&f);
        assert!(h.dead);
        assert!(!collect.lock().unwrap().errors.is_empty());
    }
}
