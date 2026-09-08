// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Bridge between [`HandshakeEngine`] and the QUIC connection.

use bytes::Bytes;
use hopf_core::security::SecurityInfo;
use hopf_core::tls::{
    HandshakeConfig, HandshakeEngine, HandshakeMode, HandshakeRole, QuicSecrets, TlsEventSink,
    TlsProtocolError, TlsTimerKind, VerifyRequest,
};

use crate::transport::packet::TransportParameters;
use crate::transport::types::{Side, SpaceId};

/// Outbound CRYPTO to send at a given encryption level.
#[derive(Debug, Clone)]
pub struct OutboundCrypto {
    /// Packet number space / encryption level.
    pub space: SpaceId,
    /// Bytes.
    pub data: Bytes,
}

/// Events from the TLS bridge for the connection to act on.
#[derive(Debug, Default)]
pub struct TlsBridgeEvents {
    /// CRYPTO bytes to send (may include ServerHello + rest; connection splits).
    pub outbound: Vec<OutboundCrypto>,
    /// Handshake keys ready (client, server secrets).
    pub handshake_keys: Option<([u8; 32], [u8; 32])>,
    /// Application keys ready.
    pub app_keys: Option<([u8; 32], [u8; 32])>,
    /// Client early (0-RTT) traffic secret.
    pub early_keys: Option<[u8; 32]>,
    /// Whether the server accepted early data (`None` until EncryptedExtensions on client).
    pub early_data_accepted: Option<bool>,
    /// Peer limits to apply for 0-RTT before EE (client resume).
    pub remembered_0rtt_limits: Option<hopf_core::tls::RememberedTransportLimits>,
    /// Peer transport parameters raw.
    pub peer_tp: Option<Bytes>,
    /// Handshake finished + security info.
    pub complete: Option<SecurityInfo>,
    /// Protocol failure.
    pub failed: Option<String>,
    /// Current space for new outbound CRYPTO (updated as handshake progresses).
    pub write_space: SpaceId,
}

struct Sink<'a> {
    events: &'a mut TlsBridgeEvents,
}

impl TlsEventSink for Sink<'_> {
    fn handshake_data_ready(&mut self, data: &[u8]) {
        self.events.outbound.push(OutboundCrypto {
            space: self.events.write_space,
            data: Bytes::copy_from_slice(data),
        });
    }

    fn handshake_complete(&mut self, info: SecurityInfo, quic: Option<QuicSecrets>) {
        if let Some(secrets) = quic {
            if let (Some(c), Some(s)) = (
                secrets.client_application_traffic_secret,
                secrets.server_application_traffic_secret,
            ) {
                self.events.app_keys = Some((c, s));
            }
            if let Some(early) = secrets.client_early_traffic_secret {
                // Prefer early keys already installed at ClientHello / PSK accept;
                // still record if only present at completion.
                if self.events.early_keys.is_none() {
                    self.events.early_keys = Some(early);
                }
            }
        }
        self.events.complete = Some(info);
        // Post-handshake CRYPTO (NewSessionTicket) uses 1-RTT.
        self.events.write_space = SpaceId::Data;
    }

    fn verification_requested(&mut self, _req: VerifyRequest) {}

    fn peer_transport_parameters(&mut self, params: &[u8]) {
        self.events.peer_tp = Some(Bytes::copy_from_slice(params));
    }

    fn quic_handshake_keys_ready(&mut self, client: [u8; 32], server: [u8; 32]) {
        self.events.handshake_keys = Some((client, server));
        // After ServerHello, subsequent CRYPTO is Handshake-protected.
        self.events.write_space = SpaceId::Handshake;
    }

    fn quic_early_keys_ready(&mut self, client_early: [u8; 32]) {
        self.events.early_keys = Some(client_early);
    }

    fn key_exchange_group_negotiated(&mut self, _group: u16) {}

    fn early_data_accepted(&mut self, accepted: bool) {
        self.events.early_data_accepted = Some(accepted);
    }

    fn quic_0rtt_peer_limits(
        &mut self,
        limits: hopf_core::tls::RememberedTransportLimits,
    ) {
        self.events.remembered_0rtt_limits = Some(limits);
    }

    fn protocol_error(&mut self, err: TlsProtocolError) {
        self.events.failed = Some(err.message);
    }

    fn timeout(&mut self, _kind: TlsTimerKind) {}

    fn peer_closed(&mut self) {
        self.events.failed = Some("peer closed during handshake".into());
    }
}

/// TLS handshake owner for one QUIC connection.
pub struct TlsBridge {
    engine: HandshakeEngine,
    side: Side,
    /// Space for inbound CRYPTO feeding.
    read_space: SpaceId,
    complete: bool,
}

impl TlsBridge {
    /// Client: start emits ClientHello on Initial.
    pub fn start_client(mut config: HandshakeConfig, local_tp: &TransportParameters) -> (Self, TlsBridgeEvents) {
        config.role = HandshakeRole::Client;
        config.mode = HandshakeMode::Quic;
        config.local_transport_parameters = Some(Bytes::from(local_tp.encode()));
        let mut engine = HandshakeEngine::new(config);
        let mut events = TlsBridgeEvents {
            write_space: SpaceId::Initial,
            ..Default::default()
        };
        {
            let mut sink = Sink {
                events: &mut events,
            };
            engine.start(&mut sink);
        }
        (
            Self {
                engine,
                side: Side::Client,
                read_space: SpaceId::Initial,
                complete: false,
            },
            events,
        )
    }

    /// Server: wait for ClientHello.
    pub fn start_server(mut config: HandshakeConfig, local_tp: &TransportParameters) -> Self {
        config.role = HandshakeRole::Server;
        config.mode = HandshakeMode::Quic;
        config.local_transport_parameters = Some(Bytes::from(local_tp.encode()));
        Self {
            engine: HandshakeEngine::new(config),
            side: Side::Server,
            read_space: SpaceId::Initial,
            complete: false,
        }
    }

    /// Side.
    pub fn side(&self) -> Side {
        self.side
    }

    /// Whether handshake finished.
    pub fn is_complete(&self) -> bool {
        self.complete || self.engine.is_complete()
    }

    /// Feed CRYPTO stream bytes from `space`.
    pub fn feed_crypto(&mut self, space: SpaceId, data: &[u8]) -> TlsBridgeEvents {
        let mut events = TlsBridgeEvents {
            write_space: match space {
                SpaceId::Initial => SpaceId::Initial,
                SpaceId::Handshake => SpaceId::Handshake,
                SpaceId::Data => SpaceId::Data,
            },
            ..Default::default()
        };
        // After we have handshake keys, server replies on Handshake.
        if self.read_space == SpaceId::Handshake || space == SpaceId::Handshake {
            events.write_space = SpaceId::Handshake;
        }
        if self.complete || space == SpaceId::Data {
            events.write_space = SpaceId::Data;
        }
        {
            let mut sink = Sink {
                events: &mut events,
            };
            let mut input = data;
            self.engine.feed_handshake_data(&mut input, &mut sink);
        }
        if events.handshake_keys.is_some() {
            self.read_space = SpaceId::Handshake;
        }
        if events.complete.is_some() {
            self.complete = true;
            events.write_space = SpaceId::Data;
        }
        // Fix write_space for server flight: after processing ClientHello on Initial,
        // ServerHello is Initial; rest is Handshake — connection applies split.
        if self.side == Side::Server && events.handshake_keys.is_some() && !self.complete {
            for o in &mut events.outbound {
                o.space = SpaceId::Initial; // connection will re-bucket after ServerHello
            }
        }
        events
    }
}

/// Split outbound CRYPTO so ServerHello is sent on Initial and the rest on Handshake.
pub fn split_server_hello(data: &[u8]) -> Option<(Bytes, Bytes)> {
    if data.len() < 4 || data[0] != 0x02 {
        return None;
    }
    let body_len = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
    let msg_len = 4usize.checked_add(body_len)?;
    if data.len() <= msg_len {
        return None;
    }
    Some((
        Bytes::copy_from_slice(&data[..msg_len]),
        Bytes::copy_from_slice(&data[msg_len..]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_server_hello_works() {
        let sh = [0x02u8, 0, 0, 2, 0xaa, 0xbb];
        let rest = [0x08u8, 0, 0, 1, 0xcc];
        let mut buf = Vec::new();
        buf.extend_from_slice(&sh);
        buf.extend_from_slice(&rest);
        let (a, b) = split_server_hello(&buf).unwrap();
        assert_eq!(a.as_ref(), &sh);
        assert_eq!(b.as_ref(), &rest);
    }
}
