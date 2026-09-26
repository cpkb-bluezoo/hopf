// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! One TCP TLS connection: pick TLS 1.2 or 1.3 from the first handshake
//! flight (prefer 1.3), then run exactly one record engine for the rest.

use bytes::Bytes;

use super::engine::{
    handshake_config_tcp_record_layer, ClientAuthPolicy, HandshakeConfig, HandshakeRole,
    ServerCredentials, ServerCredentialsResolver,
};
use super::record::TlsRecordEngine;
use super::record::TlsRecordSink;
use super::tls12::engine::{Config as Tls12Config, Role as Tls12Role};
use super::tls12::record::Tls12RecordEngine;
use super::tcp_version_policy::TcpTlsVersionPolicy;
use super::version_pick::{find_client_hello_in_records, find_server_hello_in_records, PickedTls};
use super::TlsVariant;

/// Server credentials and policy shared by TLS 1.2 and 1.3 once version is picked.
pub(crate) struct ServerTlsMaterial {
    pub creds: Option<ServerCredentials>,
    pub alpn: Vec<Bytes>,
    pub client_auth: ClientAuthPolicy,
    pub client_trust_store: Option<crate::crypto::trust::TrustStore>,
    pub server_resolver: Option<ServerCredentialsResolver>,
    pub version_policy: TcpTlsVersionPolicy,
}

/// Per-connection knobs applied when a fixed-version or post-pick server engine is built.
pub(crate) struct ServerEngineExtras {
    pub alpn: Option<Vec<Bytes>>,
    pub require_supported_versions: bool,
    pub record_size_limit: Option<u16>,
    pub ech_server: Option<std::sync::Arc<super::ech::EchServerConfig>>,
}

impl ServerTlsMaterial {
    pub(crate) fn into_variant(self) -> TlsVariant {
        match self.version_policy {
            TcpTlsVersionPolicy::Negotiate => {
                TlsVariant::Negotiating(crate::tls::NegotiatingTls::new(NegotiatingTls::server(self)))
            }
            TcpTlsVersionPolicy::Tls13Only => {
                self.materialize(PickedTls::V13, &ServerEngineExtras::default())
            }
            TcpTlsVersionPolicy::Tls12Only => {
                self.materialize(PickedTls::V12, &ServerEngineExtras::default())
            }
        }
    }

    pub(crate) fn materialize(&self, pick: PickedTls, extras: &ServerEngineExtras) -> TlsVariant {
        let alpn = extras.alpn.clone().unwrap_or_else(|| self.alpn.clone());
        match pick {
            PickedTls::V13 => {
                let mut config = handshake_config_tcp_record_layer(HandshakeRole::Server, &[]);
                config.alpn = alpn;
                config.server = self.creds.clone();
                config.server_resolver = self.server_resolver.clone();
                config.client_auth = self.client_auth;
                config.client_trust_store = self.client_trust_store.clone();
                config.record_size_limit = extras.record_size_limit;
                config.ech_server = extras.ech_server.clone();
                TlsVariant::V13(TlsRecordEngine::new(config))
            }
            PickedTls::V12 => {
                let config = Tls12Config {
                    role: Tls12Role::Server,
                    server: self.creds.clone(),
                    alpn,
                    client_auth: self.client_auth,
                    client_trust_store: self.client_trust_store.clone(),
                    require_supported_versions: extras.require_supported_versions,
                    ..Default::default()
                };
                TlsVariant::V12(Tls12RecordEngine::new(config))
            }
        }
    }
}

impl Default for ServerEngineExtras {
    fn default() -> Self {
        Self {
            alpn: None,
            require_supported_versions: false,
            record_size_limit: None,
            ech_server: None,
        }
    }
}

/// Server-side version negotiation before a concrete record engine is chosen.
pub(crate) struct ServerNegotiator {
    material: ServerTlsMaterial,
    buffer: Vec<u8>,
    alpn: Option<Vec<Bytes>>,
    require_supported_versions: bool,
    record_size_limit: Option<u16>,
    ech_server: Option<std::sync::Arc<super::ech::EchServerConfig>>,
    version_policy: TcpTlsVersionPolicy,
    active: Option<Box<TlsVariant>>,
}

impl ServerNegotiator {
    pub(crate) fn new(material: ServerTlsMaterial) -> Self {
        let version_policy = material.version_policy;
        Self {
            material,
            buffer: Vec::new(),
            alpn: None,
            require_supported_versions: false,
            record_size_limit: None,
            ech_server: None,
            version_policy,
            active: None,
        }
    }

    fn materialize(&self, pick: PickedTls) -> TlsVariant {
        self.material.materialize(
            pick,
            &ServerEngineExtras {
                alpn: self.alpn.clone(),
                require_supported_versions: self.require_supported_versions,
                record_size_limit: self.record_size_limit,
                ech_server: self.ech_server.clone(),
            },
        )
    }

    fn try_activate<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) -> bool {
        if self.active.is_some() {
            return true;
        }
        match find_client_hello_in_records(&self.buffer) {
            Ok(Some((pick, _))) => {
                if !self.version_policy.allows_server_pick(pick) {
                    sink.protocol_error(super::sink::TlsProtocolError::new(
                        super::sink::AlertDescription::ProtocolVersion,
                        "TLS version not permitted by local policy",
                    ));
                    return true;
                }
                let mut engine = self.materialize(pick);
                if let Some(alpn) = &self.alpn {
                    let refs: Vec<&[u8]> = alpn.iter().map(|p| p.as_ref()).collect();
                    engine.set_alpn(&refs);
                }
                engine.start(sink);
                let mut rest = self.buffer.as_slice();
                engine.feed_ciphertext(&mut rest, sink);
                self.buffer.clear();
                self.active = Some(Box::new(engine));
                true
            }
            Ok(None) => false,
            Err(()) => {
                sink.protocol_error(super::sink::TlsProtocolError::new(
                    super::sink::AlertDescription::ProtocolVersion,
                    "unsupported TLS version in ClientHello",
                ));
                true
            }
        }
    }
}

/// Client-side: emit a TLS 1.3-shaped `ClientHello` (with optional TLS 1.2
/// in `supported_versions`), then pick the engine from `ServerHello`.
pub(crate) struct ClientNegotiator {
    config_v13: HandshakeConfig,
    config_v12: Tls12Config,
    version_policy: TcpTlsVersionPolicy,
    v13_probe: Option<TlsRecordEngine>,
    buffer: Vec<u8>,
    active: Option<Box<TlsVariant>>,
}

impl ClientNegotiator {
    pub(crate) fn new(
        config_v13: HandshakeConfig,
        config_v12: Tls12Config,
        version_policy: TcpTlsVersionPolicy,
    ) -> Self {
        Self {
            config_v13,
            config_v12,
            version_policy,
            v13_probe: None,
            buffer: Vec::new(),
            active: None,
        }
    }

    fn try_activate<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) -> bool {
        if self.active.is_some() {
            return true;
        }
        match find_server_hello_in_records(&self.buffer) {
            Ok(Some((pick, _))) => {
                if !self.version_policy.allows_client_pick(pick) {
                    sink.protocol_error(super::sink::TlsProtocolError::new(
                        super::sink::AlertDescription::ProtocolVersion,
                        "TLS version not permitted by local policy",
                    ));
                    return true;
                }
                let mut engine = match pick {
                    PickedTls::V13 => {
                        let probe = self.v13_probe.take().expect("client hello probe");
                        TlsVariant::V13(probe)
                    }
                    PickedTls::V12 => {
                        let probe = self.v13_probe.take().expect("client hello probe");
                        let ch = probe.client_hello_outbound_wire().expect("client hello wire");
                        let mut v12 = Tls12RecordEngine::new(self.config_v12.clone());
                        v12.engine_mut().client_note_client_hello_sent(&ch);
                        TlsVariant::V12(v12)
                    }
                };
                let mut rest = self.buffer.as_slice();
                engine.feed_ciphertext(&mut rest, sink);
                self.buffer.clear();
                self.active = Some(Box::new(engine));
                true
            }
            Ok(None) => false,
            Err(()) => {
                sink.protocol_error(super::sink::TlsProtocolError::new(
                    super::sink::AlertDescription::ProtocolVersion,
                    "unsupported TLS version in ServerHello",
                ));
                true
            }
        }
    }
}

/// Combined negotiator stored in [`TlsVariant::Negotiating`].
pub(crate) enum NegotiatingTls {
    Server(ServerNegotiator),
    Client(ClientNegotiator),
}

impl NegotiatingTls {
    pub(crate) fn server(material: ServerTlsMaterial) -> Self {
        Self::Server(ServerNegotiator::new(material))
    }

    pub(crate) fn client(
        config_v13: HandshakeConfig,
        config_v12: Tls12Config,
        version_policy: TcpTlsVersionPolicy,
    ) -> Self {
        Self::Client(ClientNegotiator::new(config_v13, config_v12, version_policy))
    }

    pub(crate) fn start<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            NegotiatingTls::Server(_) => {}
            NegotiatingTls::Client(c) => {
                if c.v13_probe.is_some() {
                    return;
                }
                let mut probe = TlsRecordEngine::new(c.config_v13.clone());
                probe.start(sink);
                c.v13_probe = Some(probe);
            }
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        match self {
            NegotiatingTls::Server(s) => s.active.as_ref().map(|e| e.is_complete()).unwrap_or(false),
            NegotiatingTls::Client(c) => c.active.as_ref().map(|e| e.is_complete()).unwrap_or(false),
        }
    }

    pub(crate) fn set_alpn(&mut self, protocols: &[&[u8]]) -> bool {
        let list: Vec<Bytes> = protocols.iter().map(|p| Bytes::copy_from_slice(p)).collect();
        match self {
            NegotiatingTls::Server(s) => {
                if let Some(active) = &mut s.active {
                    return active.set_alpn(protocols);
                }
                s.alpn = Some(list);
                true
            }
            NegotiatingTls::Client(c) => {
                if let Some(active) = &mut c.active {
                    return active.set_alpn(protocols);
                }
                c.config_v13.alpn = list.clone();
                c.config_v12.alpn = list;
                true
            }
        }
    }

    pub(crate) fn set_require_supported_versions(&mut self, required: bool) -> bool {
        match self {
            NegotiatingTls::Server(s) => {
                if let Some(active) = &mut s.active {
                    return active.set_require_supported_versions(required);
                }
                s.require_supported_versions = required;
                true
            }
            NegotiatingTls::Client(c) => c
                .active
                .as_mut()
                .map(|e| e.set_require_supported_versions(required))
                .unwrap_or(true),
        }
    }

    pub(crate) fn set_record_size_limit(&mut self, limit: Option<u16>) -> bool {
        match self {
            NegotiatingTls::Server(s) => {
                if let Some(active) = &mut s.active {
                    return active.set_record_size_limit(limit);
                }
                s.record_size_limit = limit;
                true
            }
            NegotiatingTls::Client(c) => {
                if let Some(active) = &mut c.active {
                    return active.set_record_size_limit(limit);
                }
                if c.v13_probe.is_some() {
                    return false;
                }
                c.config_v13.record_size_limit = limit;
                true
            }
        }
    }

    pub(crate) fn set_ech_client(&mut self, config: super::ech::EchClientConfig) -> bool {
        match self {
            NegotiatingTls::Server(_) => false,
            NegotiatingTls::Client(c) => {
                if let Some(active) = &mut c.active {
                    return active.set_ech_client(config);
                }
                c.config_v13.ech_client = Some(config);
                true
            }
        }
    }

    pub(crate) fn set_ech_server(&mut self, config: std::sync::Arc<super::ech::EchServerConfig>) -> bool {
        match self {
            NegotiatingTls::Server(s) => {
                if let Some(active) = &mut s.active {
                    return active.set_ech_server(config);
                }
                s.ech_server = Some(config);
                true
            }
            NegotiatingTls::Client(_) => false,
        }
    }

    pub(crate) fn feed_ciphertext<S: TlsRecordSink + ?Sized>(&mut self, input: &mut &[u8], sink: &mut S) {
        match self {
            NegotiatingTls::Server(s) => {
                if s.active.is_none() {
                    s.buffer.extend_from_slice(*input);
                    *input = &[];
                    if !s.try_activate(sink) {
                        return;
                    }
                }
                let mut engine = s.active.take().expect("negotiating server: no active engine");
                engine.feed_ciphertext(input, sink);
                s.active = Some(engine);
            }
            NegotiatingTls::Client(c) => {
                if c.active.is_none() {
                    c.buffer.extend_from_slice(*input);
                    *input = &[];
                    if !c.try_activate(sink) {
                        return;
                    }
                }
                let mut engine = c.active.take().expect("negotiating client: no active engine");
                engine.feed_ciphertext(input, sink);
                c.active = Some(engine);
            }
        }
    }

    pub(crate) fn send_application_data<S: TlsRecordSink + ?Sized>(&mut self, plaintext: &[u8], sink: &mut S) {
        match self {
            NegotiatingTls::Server(s) => {
                if let Some(active) = &mut s.active {
                    active.send_application_data(plaintext, sink);
                }
            }
            NegotiatingTls::Client(c) => {
                if let Some(active) = &mut c.active {
                    active.send_application_data(plaintext, sink);
                }
            }
        }
    }

    pub(crate) fn feed_verification_result<S: TlsRecordSink + ?Sized>(
        &mut self,
        result: super::sink::VerifyResult,
        sink: &mut S,
    ) {
        match self {
            NegotiatingTls::Server(s) => {
                if let Some(mut engine) = s.active.take() {
                    engine.feed_verification_result(result, sink);
                    s.active = Some(engine);
                }
            }
            NegotiatingTls::Client(c) => {
                if let Some(mut engine) = c.active.take() {
                    engine.feed_verification_result(result, sink);
                    c.active = Some(engine);
                }
            }
        }
    }

    pub(crate) fn send_close_notify<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            NegotiatingTls::Server(s) => {
                if let Some(active) = &mut s.active {
                    active.send_close_notify(sink);
                }
            }
            NegotiatingTls::Client(c) => {
                if let Some(active) = &mut c.active {
                    active.send_close_notify(sink);
                }
            }
        }
    }
}
