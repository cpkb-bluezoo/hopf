// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC teardown errors delivered via [`ProtocolHandler::error`](hopf_core::ProtocolHandler).
//!
//! Mirrors Gumdrop's `QuicConnectionCloseException`: abnormal connection and
//! stream teardown reaches handlers as a typed `io::Error` source instead of
//! the argument-free [`disconnected`](hopf_core::ProtocolHandler::disconnected)
//! path used for clean closes.

use std::error::Error;
use std::fmt;
use std::io;

use quinn_proto::{ConnectionError, VarInt};

/// Peer (or local transport) closed the QUIC connection with a
/// CONNECTION_CLOSE — RFC 9000 §19.19.
///
/// Delivered as the source of an [`io::Error`] to
/// [`ProtocolHandler::error`](hopf_core::ProtocolHandler) so callers can
/// distinguish an application close (e.g. HTTP/3 `H3_REQUEST_CANCELLED`) from
/// a clean stream FIN / local shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicConnectionCloseError {
    /// `true` for an application-level (0x1d) close; `false` for a
    /// transport-level (0x1c) close.
    pub application_error: bool,
    /// RFC 9000 §20.1 transport error code, or an ALPN-scoped application
    /// error code this layer does not decode.
    pub error_code: u64,
    /// Optional human-readable reason phrase from the close frame.
    pub reason: String,
}

impl QuicConnectionCloseError {
    /// Build from a peer application close (type 0x1d).
    pub fn application(error_code: u64, reason: impl Into<String>) -> Self {
        Self {
            application_error: true,
            error_code,
            reason: reason.into(),
        }
    }

    /// Build from a peer or local transport close (type 0x1c).
    pub fn transport(error_code: u64, reason: impl Into<String>) -> Self {
        Self {
            application_error: false,
            error_code,
            reason: reason.into(),
        }
    }

    /// Wrap as an [`io::Error`] suitable for `ProtocolHandler::error`.
    pub fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionAborted, self)
    }
}

impl fmt::Display for QuicConnectionCloseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.application_error {
            write!(f, "QUIC connection closed with application error 0x{:x}", self.error_code)?;
        } else {
            write!(
                f,
                "QUIC connection closed with transport error {}",
                transport_error_name(self.error_code)
            )?;
        }
        if !self.reason.is_empty() {
            write!(f, ": {}", self.reason)?;
        }
        Ok(())
    }
}

impl Error for QuicConnectionCloseError {}

/// Peer sent STOP_SENDING on a stream (RFC 9000 §19.5).
///
/// Delivered as the source of an [`io::Error`] to
/// [`ProtocolHandler::error`](hopf_core::ProtocolHandler) instead of
/// [`disconnected`](hopf_core::ProtocolHandler::disconnected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicStreamStoppedError {
    /// Application error code from the STOP_SENDING frame.
    pub error_code: u64,
}

impl QuicStreamStoppedError {
    /// Build from a STOP_SENDING error code.
    pub fn new(error_code: u64) -> Self {
        Self { error_code }
    }

    /// Wrap as an [`io::Error`] suitable for `ProtocolHandler::error`.
    pub fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionReset, self)
    }
}

impl fmt::Display for QuicStreamStoppedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QUIC stream stopped by peer with application error 0x{:x}",
            self.error_code
        )
    }
}

impl Error for QuicStreamStoppedError {}

/// Map a quinn-proto [`ConnectionError`] to an [`io::Error`] for handler
/// delivery, or `None` when the close is a clean local shutdown that should
/// still use [`disconnected`](hopf_core::ProtocolHandler::disconnected).
pub(crate) fn connection_lost_io_error(reason: ConnectionError) -> Option<io::Error> {
    match reason {
        ConnectionError::LocallyClosed => None,
        ConnectionError::ApplicationClosed(close) => Some(
            QuicConnectionCloseError::application(
                u64::from(close.error_code),
                String::from_utf8_lossy(&close.reason).into_owned(),
            )
            .into_io(),
        ),
        ConnectionError::ConnectionClosed(close) => Some(
            QuicConnectionCloseError::transport(
                u64::from(close.error_code),
                String::from_utf8_lossy(&close.reason).into_owned(),
            )
            .into_io(),
        ),
        ConnectionError::TransportError(err) => Some(
            QuicConnectionCloseError::transport(u64::from(err.code), err.reason).into_io(),
        ),
        ConnectionError::TimedOut => Some(io::Error::new(
            io::ErrorKind::TimedOut,
            "QUIC connection timed out",
        )),
        ConnectionError::Reset => Some(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "QUIC connection reset by peer",
        )),
        ConnectionError::VersionMismatch => Some(io::Error::new(
            io::ErrorKind::InvalidData,
            "QUIC version mismatch",
        )),
        ConnectionError::CidsExhausted => Some(io::Error::new(
            io::ErrorKind::Other,
            "QUIC connection IDs exhausted",
        )),
    }
}

/// Map a STOP_SENDING [`VarInt`] error code to an [`io::Error`].
pub(crate) fn stream_stopped_io_error(error_code: VarInt) -> io::Error {
    QuicStreamStoppedError::new(u64::from(error_code)).into_io()
}

/// Downcast helper: extract [`QuicConnectionCloseError`] from an `io::Error`.
pub fn connection_close_error(err: &io::Error) -> Option<&QuicConnectionCloseError> {
    err.get_ref()?.downcast_ref::<QuicConnectionCloseError>()
}

/// Downcast helper: extract [`QuicStreamStoppedError`] from an `io::Error`.
pub fn stream_stopped_error(err: &io::Error) -> Option<&QuicStreamStoppedError> {
    err.get_ref()?.downcast_ref::<QuicStreamStoppedError>()
}

fn transport_error_name(error_code: u64) -> String {
    if (0x0100..=0x01ff).contains(&error_code) {
        return format!("CRYPTO_ERROR({})", error_code - 0x0100);
    }
    match error_code {
        0x0 => "NO_ERROR".into(),
        0x1 => "INTERNAL_ERROR".into(),
        0x2 => "CONNECTION_REFUSED".into(),
        0x3 => "FLOW_CONTROL_ERROR".into(),
        0x4 => "STREAM_LIMIT_ERROR".into(),
        0x5 => "STREAM_STATE_ERROR".into(),
        0x6 => "FINAL_SIZE_ERROR".into(),
        0x7 => "FRAME_ENCODING_ERROR".into(),
        0x8 => "TRANSPORT_PARAMETER_ERROR".into(),
        0x9 => "CONNECTION_ID_LIMIT_ERROR".into(),
        0xa => "PROTOCOL_VIOLATION".into(),
        0xb => "INVALID_TOKEN".into(),
        0xc => "APPLICATION_ERROR".into(),
        0xd => "CRYPTO_BUFFER_EXCEEDED".into(),
        0xe => "KEY_UPDATE_ERROR".into(),
        0xf => "AEAD_LIMIT_REACHED".into(),
        0x10 => "NO_VIABLE_PATH".into(),
        other => format!("UNKNOWN({other})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_close_round_trips_through_io_error() {
        let io_err = QuicConnectionCloseError::application(0x010c, "cancelled").into_io();
        let close = connection_close_error(&io_err).expect("downcast");
        assert!(close.application_error);
        assert_eq!(close.error_code, 0x010c);
        assert_eq!(close.reason, "cancelled");
        assert!(stream_stopped_error(&io_err).is_none());
    }

    #[test]
    fn stream_stopped_round_trips_through_io_error() {
        let io_err = QuicStreamStoppedError::new(0x010c).into_io();
        let stopped = stream_stopped_error(&io_err).expect("downcast");
        assert_eq!(stopped.error_code, 0x010c);
        assert!(connection_close_error(&io_err).is_none());
    }

    #[test]
    fn locally_closed_maps_to_none() {
        assert!(connection_lost_io_error(ConnectionError::LocallyClosed).is_none());
    }

    #[test]
    fn timed_out_maps_to_timed_out_kind() {
        let err = connection_lost_io_error(ConnectionError::TimedOut).expect("mapped");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
