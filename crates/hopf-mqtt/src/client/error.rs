// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT client errors.

use std::fmt;
use std::io;

/// Result alias for the MQTT client.
pub type MqttClientResult<T> = Result<T, MqttClientError>;

/// Client-side MQTT failure.
#[derive(Debug)]
pub enum MqttClientError {
    /// Underlying I/O (including DNS / connect / CONNACK / PINGRESP timeouts).
    Io(io::Error),
    /// Missing builder configuration (e.g. no host or address set).
    Config(String),
    /// The broker rejected CONNECT with this reason/return code.
    ConnectRefused(u8),
}

impl fmt::Display for MqttClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "mqtt i/o: {e}"),
            Self::Config(s) => write!(f, "mqtt config: {s}"),
            Self::ConnectRefused(code) => write!(f, "mqtt CONNECT refused: reason code 0x{code:02X}"),
        }
    }
}

impl std::error::Error for MqttClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for MqttClientError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
