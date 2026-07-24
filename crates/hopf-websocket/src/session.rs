// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Outbound WebSocket frame helpers into a byte buffer.

use crate::frame::{write_frame, Opcode, WsRole};

/// Mutable session for sending frames on an established WebSocket.
pub struct WsSession<'a> {
    out: &'a mut Vec<u8>,
    role: WsRole,
}

impl<'a> WsSession<'a> {
    /// Borrow an outbound buffer for the given role.
    pub fn new(out: &'a mut Vec<u8>, role: WsRole) -> Self {
        Self { out, role }
    }

    /// Send a text message (single frame, FIN set).
    pub fn send_text(&mut self, text: &str) {
        write_text(self.out, self.role, text);
    }

    /// Send a binary message (single frame, FIN set).
    pub fn send_binary(&mut self, data: &[u8]) {
        write_binary(self.out, self.role, data);
    }

    /// Send a ping.
    pub fn send_ping(&mut self, payload: &[u8]) {
        write_ping(self.out, self.role, payload);
    }

    /// Send a pong.
    pub fn send_pong(&mut self, payload: &[u8]) {
        write_pong(self.out, self.role, payload);
    }

    /// Send a close frame.
    pub fn send_close(&mut self, code: u16, reason: &str) {
        write_close(self.out, self.role, code, reason);
    }

    /// Role of this endpoint.
    pub fn role(&self) -> WsRole {
        self.role
    }

    /// Access the outbound buffer (advanced).
    pub fn out_mut(&mut self) -> &mut Vec<u8> {
        self.out
    }
}

/// Write a text frame.
pub fn write_text(out: &mut Vec<u8>, role: WsRole, text: &str) {
    let mask = client_mask(role);
    write_frame(out, true, Opcode::Text, mask, text.as_bytes());
}

/// Write a binary frame.
pub fn write_binary(out: &mut Vec<u8>, role: WsRole, data: &[u8]) {
    let mask = client_mask(role);
    write_frame(out, true, Opcode::Binary, mask, data);
}

/// Write a ping frame.
pub fn write_ping(out: &mut Vec<u8>, role: WsRole, payload: &[u8]) {
    let mask = client_mask(role);
    write_frame(out, true, Opcode::Ping, mask, payload);
}

/// Write a pong frame.
pub fn write_pong(out: &mut Vec<u8>, role: WsRole, payload: &[u8]) {
    let mask = client_mask(role);
    write_frame(out, true, Opcode::Pong, mask, payload);
}

/// Write a close frame with status code and UTF-8 reason.
pub fn write_close(out: &mut Vec<u8>, role: WsRole, code: u16, reason: &str) {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(reason.as_bytes());
    let mask = client_mask(role);
    write_frame(out, true, Opcode::Close, mask, &payload);
}

fn client_mask(role: WsRole) -> Option<[u8; 4]> {
    match role {
        WsRole::Client => {
            let mut m = [0u8; 4];
            getrandom::getrandom(&mut m).expect("getrandom");
            Some(m)
        }
        WsRole::Server => None,
    }
}
