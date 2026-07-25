// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebSocket framing and HTTP upgrade helpers (RFC 6455 / 8441 / 9220).

#![warn(missing_docs)]

mod factory;
mod frame;
mod handshake;
mod session;
mod upgrade;

pub use factory::{
    EchoFactory, EchoWsHandler, WebSocketConfig, WebSocketFactory, WsEventHandlerFactory,
};
pub use frame::{
    write_frame, Opcode, WsFrameError, WsFrameHandler, WsFrameParser, WsRole, MAX_CONTROL_PAYLOAD,
};
pub use handshake::{
    calculate_accept, generate_key, is_extended_connect_websocket, is_h1_websocket_upgrade,
    validate_h1_upgrade, websocket_accept_headers, websocket_connect_response_headers,
    WEBSOCKET_GUID, WEBSOCKET_VERSION,
};
pub use session::{
    framed_ws_conn_handle, write_binary, write_close, write_ping, write_pong, write_text,
    WsSession,
};
pub use upgrade::{WsEventHandler, WsUpgradeHandler};

#[cfg(all(test, feature = "integration"))]
mod integration;
