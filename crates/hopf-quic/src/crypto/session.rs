// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Quinn `crypto::Session` backed by [`hopf_core::tls::HandshakeEngine`].

use std::any::Any;
use std::io::Cursor;
use std::sync::Arc;

use bytes::Bytes;
use hopf_core::crypto::kx_policy::KxPolicy;
use hopf_core::crypto::trust::TrustStore;
use hopf_core::security::SecurityInfo;
use hopf_core::tls::{
    HandshakeConfig, HandshakeEngine, HandshakeMode, HandshakeRole, QuicSecrets, ServerCredentials,
    TlsEventSink, TlsProtocolError, TlsTimerKind, VerifyRequest,
};
use quinn_proto::crypto::{self, Keys};
use quinn_proto::{ConnectError, Side, TransportError, TransportErrorCode};
use quinn_proto::transport_parameters::TransportParameters;

use super::keys;
use super::HopfHandshakeData;

/// Mutable bridge between [`HandshakeEngine`] and a QUIC crypto session.
pub(crate) struct SessionSink {
    outbound: Vec<u8>,
    pending_hs_keys: bool,
    hs_client: [u8; 32],
    hs_server: [u8; 32],
    pending_one_rtt: Option<([u8; 32], [u8; 32])>,
    got_handshake_data: bool,
    report_handshake_data: bool,
    security_info: Option<SecurityInfo>,
    peer_tp: Option<Vec<u8>>,
    failed: Option<TransportError>,
}

impl Default for SessionSink {
    fn default() -> Self {
        Self {
            outbound: Vec::new(),
            pending_hs_keys: false,
            hs_client: [0; 32],
            hs_server: [0; 32],
            pending_one_rtt: None,
            got_handshake_data: false,
            report_handshake_data: false,
            security_info: None,
            peer_tp: None,
            failed: None,
        }
    }
}

impl TlsEventSink for SessionSink {
    fn handshake_data_ready(&mut self, data: &[u8]) {
        self.outbound.extend_from_slice(data);
    }

    fn handshake_complete(&mut self, info: SecurityInfo, quic: Option<QuicSecrets>) {
        self.got_handshake_data = true;
        self.report_handshake_data = true;
        self.security_info = Some(info);
        if let Some(secrets) = quic {
            if let (Some(c), Some(s)) = (
                secrets.client_application_traffic_secret,
                secrets.server_application_traffic_secret,
            ) {
                self.pending_one_rtt = Some((c, s));
            }
        }
    }

    fn verification_requested(&mut self, req: VerifyRequest) {
        let _ = req;
    }

    fn peer_transport_parameters(&mut self, params: &[u8]) {
        self.peer_tp = Some(params.to_vec());
    }

    fn quic_handshake_keys_ready(&mut self, client: [u8; 32], server: [u8; 32]) {
        self.pending_hs_keys = true;
        self.hs_client = client;
        self.hs_server = server;
    }

    fn key_exchange_group_negotiated(&mut self, _group: u16) {}

    fn protocol_error(&mut self, err: TlsProtocolError) {
        self.failed = Some(TransportError {
            code: TransportErrorCode::PROTOCOL_VIOLATION,
            frame: None,
            reason: err.message,
        });
    }

    fn timeout(&mut self, _kind: TlsTimerKind) {}

    fn peer_closed(&mut self) {
        self.failed = Some(TransportError {
            code: TransportErrorCode::PROTOCOL_VIOLATION,
            frame: None,
            reason: "peer closed during handshake".into(),
        });
    }
}

/// In-tree TLS 1.3 session for quinn-proto.
pub struct HopfCryptoSession {
    version: u32,
    side: Side,
    engine: HandshakeEngine,
    sink: SessionSink,
    one_rtt_client: [u8; 32],
    one_rtt_server: [u8; 32],
}

impl HopfCryptoSession {
    fn new(version: u32, side: Side, engine: HandshakeEngine, start: bool) -> Self {
        let sink = SessionSink::default();
        let mut this = Self {
            version,
            side,
            engine,
            sink,
            one_rtt_client: [0; 32],
            one_rtt_server: [0; 32],
        };
        if start {
            this.engine.start(&mut this.sink);
        }
        this
    }

    fn take_keys(&mut self, hs: bool) -> Option<Keys> {
        if hs {
            if !self.sink.pending_hs_keys {
                return None;
            }
            self.sink.pending_hs_keys = false;
            return keys::keys_from_traffic_secrets(
                self.version,
                self.side,
                self.sink.hs_client,
                self.sink.hs_server,
            )
            .ok();
        }
        let (c, s) = self.sink.pending_one_rtt.take()?;
        self.one_rtt_client = c;
        self.one_rtt_server = s;
        keys::keys_from_traffic_secrets(self.version, self.side, c, s).ok()
    }
}

impl crypto::Session for HopfCryptoSession {
    fn initial_keys(&self, dst_cid: &quinn_proto::ConnectionId, side: Side) -> Keys {
        keys::initial_keys(self.version, dst_cid, side).expect("initial keys")
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        let info = self.sink.security_info.as_ref()?;
        Some(Box::new(HopfHandshakeData {
            protocol: info.alpn().map(Bytes::copy_from_slice),
            server_name: info.sni().map(str::to_string),
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        !self.engine.is_complete() && self.sink.failed.is_none()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if let Some(err) = self.sink.failed.clone() {
            return Err(err);
        }
        let mut input = buf;
        self.engine.feed_handshake_data(&mut input, &mut self.sink);
        if self.sink.failed.is_some() {
            return Err(self.sink.failed.clone().unwrap());
        }
        if self.sink.report_handshake_data {
            self.sink.report_handshake_data = false;
            return Ok(true);
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let Some(raw) = &self.sink.peer_tp else {
            return Ok(None);
        };
        TransportParameters::read(self.side, &mut Cursor::new(raw.as_slice()))
            .map(Some)
            .map_err(Into::into)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        if self.sink.failed.is_some() {
            return None;
        }
        if self.sink.pending_hs_keys {
            if let Some(split) = split_before_handshake_keys(&self.sink.outbound) {
                if split > 0 {
                    buf.extend_from_slice(&self.sink.outbound[..split]);
                    self.sink.outbound.drain(..split);
                }
                if let Some(k) = self.take_keys(true) {
                    return Some(k);
                }
            }
        }
        if !self.sink.outbound.is_empty() {
            buf.extend_from_slice(&self.sink.outbound);
            self.sink.outbound.clear();
        }
        if let Some(k) = self.take_keys(true) {
            return Some(k);
        }
        self.take_keys(false)
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        let keys = keys::keys_from_traffic_secrets(
            self.version,
            self.side,
            self.one_rtt_client,
            self.one_rtt_server,
        )
        .ok()?;
        Some(crypto::KeyPair {
            local: keys.packet.local,
            remote: keys.packet.remote,
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: &quinn_proto::ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };
        let mut pseudo = Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo.push(orig_dst_cid.len() as u8);
        pseudo.extend_from_slice(orig_dst_cid.as_ref());
        pseudo.extend_from_slice(header);
        let tag_start = tag_start + pseudo.len();
        pseudo.extend_from_slice(payload);
        const NONCE: [u8; 12] = [
            0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
        ];
        const KEY: [u8; 16] = [
            0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
        ];
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &KEY).unwrap());
        let (aad, tag) = pseudo.split_at_mut(tag_start);
        key.open_in_place(
            Nonce::assume_unique_for_key(NONCE),
            Aad::from(aad),
            tag,
        )
        .is_ok()
    }

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        Err(crypto::ExportKeyingMaterialError)
    }
}

/// Shared hopf TLS handshake configuration for QUIC.
#[derive(Clone)]
pub struct HopfQuicTlsConfig {
    pub(crate) handshake: HandshakeConfig,
}

impl HopfQuicTlsConfig {
    /// Build from an existing [`HandshakeConfig`].
    pub fn new(handshake: HandshakeConfig) -> Arc<Self> {
        Arc::new(Self { handshake })
    }
}

/// Quinn client crypto using the in-tree handshake engine.
pub struct HopfQuicClientConfig {
    inner: Arc<HopfQuicTlsConfig>,
}

impl HopfQuicClientConfig {
    /// Wrap hopf TLS settings for QUIC client connections.
    pub fn new(inner: Arc<HopfQuicTlsConfig>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

impl crypto::ClientConfig for HopfQuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let mut cfg = self.inner.handshake.clone();
        cfg.role = HandshakeRole::Client;
        cfg.mode = HandshakeMode::Quic;
        if cfg.server_name.is_none() {
            cfg.server_name = Some(server_name.to_string());
        }
        cfg.local_transport_parameters = Some(encode_transport_parameters(params));
        Ok(Box::new(HopfCryptoSession::new(
            version,
            Side::Client,
            HandshakeEngine::new(cfg),
            true,
        )))
    }
}

/// Quinn server crypto using the in-tree handshake engine.
pub struct HopfQuicServerConfig {
    inner: Arc<HopfQuicTlsConfig>,
}

impl HopfQuicServerConfig {
    /// Wrap hopf TLS settings for QUIC server connections.
    pub fn new(inner: Arc<HopfQuicTlsConfig>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

impl crypto::ServerConfig for HopfQuicServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &quinn_proto::ConnectionId,
    ) -> Result<Keys, crypto::UnsupportedVersion> {
        keys::initial_keys(version, dst_cid, Side::Server)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &quinn_proto::ConnectionId, packet: &[u8]) -> [u8; 16] {
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
        let _ = version;
        let mut pseudo = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo.push(orig_dst_cid.len() as u8);
        pseudo.extend_from_slice(orig_dst_cid.as_ref());
        pseudo.extend_from_slice(packet);
        const NONCE: [u8; 12] = [
            0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
        ];
        const KEY: [u8; 16] = [
            0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
        ];
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &KEY).unwrap());
        let tag = key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(NONCE), Aad::from(pseudo), &mut [])
            .unwrap();
        let mut out = [0u8; 16];
        out.copy_from_slice(tag.as_ref());
        out
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let mut cfg = self.inner.handshake.clone();
        cfg.role = HandshakeRole::Server;
        cfg.mode = HandshakeMode::Quic;
        cfg.local_transport_parameters = Some(encode_transport_parameters(params));
        Box::new(HopfCryptoSession::new(
            version,
            Side::Server,
            HandshakeEngine::new(cfg),
            false,
        ))
    }
}

fn encode_transport_parameters(params: &TransportParameters) -> Bytes {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    Bytes::from(bytes)
}

/// When the server (or client) emits `ServerHello` plus the rest of a flight in
/// one engine step, QUIC must install Handshake keys after `ServerHello` only
/// (RFC 9001). Returns the byte length to send before `take_keys(true)`.
fn split_before_handshake_keys(outbound: &[u8]) -> Option<usize> {
    if outbound.len() < 4 {
        return None;
    }
    if outbound[0] != 0x02 {
        return None;
    }
    let body_len = u32::from_be_bytes([0, outbound[1], outbound[2], outbound[3]]) as usize;
    let msg_len = 4usize.checked_add(body_len)?;
    if outbound.len() > msg_len {
        Some(msg_len)
    } else {
        None
    }
}

/// ALPN + trust settings for building [`HopfQuicTlsConfig`].
pub struct HopfTlsBuildParams {
    /// ALPN protocol names.
    pub alpn: Vec<Bytes>,
    /// Key-exchange preference.
    pub kx_policy: KxPolicy,
    /// Client SNI / expected server name.
    pub server_name: Option<String>,
    /// Trust store (client).
    pub trust_store: Option<TrustStore>,
    /// Server credentials (server).
    pub server: Option<ServerCredentials>,
    /// Local QUIC transport parameters wire encoding.
    pub local_transport_parameters: Option<Bytes>,
}

impl HopfTlsBuildParams {
    /// Client parameters trusting a single self-signed anchor.
    pub fn client_self_signed(alpn: Vec<Bytes>, server_name: impl Into<String>, anchor: Bytes) -> Self {
        let mut trust = TrustStore::new();
        trust.add_anchor(anchor);
        Self {
            alpn,
            kx_policy: KxPolicy::classical_only(),
            server_name: Some(server_name.into()),
            trust_store: Some(trust),
            server: None,
            local_transport_parameters: None,
        }
    }

    /// Server parameters with Ed25519 credentials.
    pub fn server(creds: ServerCredentials, alpn: Vec<Bytes>) -> Self {
        Self {
            alpn,
            kx_policy: KxPolicy::classical_only(),
            server_name: None,
            trust_store: None,
            server: Some(creds),
            local_transport_parameters: None,
        }
    }

    fn into_handshake(self, role: HandshakeRole) -> HandshakeConfig {
        HandshakeConfig {
            role,
            mode: HandshakeMode::Quic,
            alpn: self.alpn,
            server_name: self.server_name,
            server: self.server,
            kx_policy: self.kx_policy,
            local_transport_parameters: self.local_transport_parameters,
            trust_store: self.trust_store,
        }
    }
}

/// Build a QUIC [`quinn_proto::ClientConfig`] using the in-tree handshake engine.
pub fn hopf_client_config(params: HopfTlsBuildParams) -> Arc<quinn_proto::ClientConfig> {
    let hs = params.into_handshake(HandshakeRole::Client);
    Arc::new(quinn_proto::ClientConfig::new(HopfQuicClientConfig::new(
        HopfQuicTlsConfig::new(hs),
    )))
}

/// Build a QUIC [`quinn_proto::ServerConfig`] using the in-tree handshake engine.
pub fn hopf_server_config(params: HopfTlsBuildParams) -> Arc<quinn_proto::ServerConfig> {
    let hs = params.into_handshake(HandshakeRole::Server);
    Arc::new(quinn_proto::ServerConfig::with_crypto(
        HopfQuicServerConfig::new(HopfQuicTlsConfig::new(hs)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_before_handshake_keys_after_server_hello() {
        let sh = [0x02u8, 0, 0, 2, 0x03, 0x04];
        let rest = [0x08u8, 0, 0, 1, 0x05];
        let mut buf = Vec::new();
        buf.extend_from_slice(&sh);
        buf.extend_from_slice(&rest);
        assert_eq!(split_before_handshake_keys(&buf), Some(sh.len()));
    }
}
