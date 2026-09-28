// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! One UDP DTLS session: pick DTLS 1.2 or 1.3 from the first handshake
//! flight (prefer 1.3), then run exactly one record engine for the rest.

use bytes::Bytes;
use std::net::SocketAddr;

use crate::crypto::kx_policy::KxPolicy;
use crate::crypto::trust::TrustStore;
use crate::dtls12::{Dtls12Config, Dtls12RecordEngine};
use crate::tls::tls12::engine::{Config as Tls12Config, Role as Tls12Role};
use crate::tls::{
    AlertDescription, HandshakeConfig, HandshakeMode, HandshakeRole, ServerCredentials, TcpTlsVersionPolicy,
    TlsProtocolError,
};
use crate::tls::version_pick::PickedTls;

use super::engine::{DtlsRecordEngine, DtlsRecordSink};
use super::version_pick::{find_client_hello_in_dtls, find_server_hello_in_dtls};

/// DTLS 1.2 / 1.3 selection policy on UDP (same enum and semantics as
/// [`TcpTlsVersionPolicy`] on TCP). Use with [`dtls_server_engine`] and
/// [`dtls_client_engine`]; default is [`TcpTlsVersionPolicy::Negotiate`].
pub type DtlsVersionPolicy = TcpTlsVersionPolicy;

/// Server credentials and DTLS policy shared by 1.2 and 1.3 once version is picked.
#[derive(Clone)]
pub struct DtlsServerMaterial {
    /// Server certificate chain and signing key.
    pub creds: ServerCredentials,
    /// TLS 1.3 key-exchange group preference (ignored by DTLS 1.2).
    pub kx_policy: KxPolicy,
    /// Whether to negotiate 1.3 vs 1.2 or pin one version.
    pub version_policy: DtlsVersionPolicy,
    /// HMAC key for DTLS 1.2 `HelloVerifyRequest` cookies.
    pub cookie_secret: [u8; 32],
    /// Require the cookie round trip before the DTLS 1.2 handshake proceeds.
    pub require_cookie: bool,
}

impl DtlsServerMaterial {
    pub(crate) fn engine_v13(&self) -> DtlsRecordEngine {
        DtlsRecordEngine::new(HandshakeConfig {
            role: HandshakeRole::Server,
            mode: HandshakeMode::Dtls,
            server: Some(self.creds.clone()),
            kx_policy: self.kx_policy.clone(),
            ..Default::default()
        })
    }

    pub(crate) fn engine_v12(&self, cookie_binding: Bytes) -> Dtls12RecordEngine {
        Dtls12RecordEngine::new(Dtls12Config {
            base: Tls12Config {
                role: Tls12Role::Server,
                server: Some(self.creds.clone()),
                ..Default::default()
            },
            require_cookie: self.require_cookie,
            cookie_secret: self.cookie_secret,
            cookie_binding,
        })
    }

    pub(crate) fn materialize(&self, pick: PickedTls, cookie_binding: Bytes) -> MaterializedDtls {
        match pick {
            PickedTls::V13 => MaterializedDtls::V13(self.engine_v13()),
            PickedTls::V12 => MaterializedDtls::V12(self.engine_v12(cookie_binding)),
        }
    }
}

// See `DtlsEngine`'s doc comment: same one-time-per-connection allocation
// tradeoff, not worth boxing across every match site here.
#[allow(clippy::large_enum_variant)]
pub(crate) enum MaterializedDtls {
    V13(DtlsRecordEngine),
    V12(Dtls12RecordEngine),
}

impl MaterializedDtls {
    fn start<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            MaterializedDtls::V13(e) => e.start(sink),
            MaterializedDtls::V12(e) => e.start(sink),
        }
    }

    fn feed_datagram<S: DtlsRecordSink + ?Sized>(&mut self, data: &[u8], sink: &mut S) {
        match self {
            MaterializedDtls::V13(e) => e.feed_datagram(data, sink),
            MaterializedDtls::V12(e) => e.feed_datagram(data, sink),
        }
    }

    fn feed_timer<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            MaterializedDtls::V13(e) => e.feed_timer(sink),
            MaterializedDtls::V12(e) => e.feed_timer(sink),
        }
    }

    fn send_application_data<S: DtlsRecordSink + ?Sized>(&mut self, data: &[u8], sink: &mut S) {
        match self {
            MaterializedDtls::V13(e) => e.send_application_data(data, sink),
            MaterializedDtls::V12(e) => e.send_application_data(data, sink),
        }
    }

    fn feed_verification_result<S: DtlsRecordSink + ?Sized>(
        &mut self,
        result: crate::tls::VerifyResult,
        sink: &mut S,
    ) {
        match self {
            MaterializedDtls::V13(e) => e.feed_verification_result(result, sink),
            MaterializedDtls::V12(e) => e.feed_verification_result(result, sink),
        }
    }

    fn send_close_notify<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            MaterializedDtls::V13(e) => e.send_close_notify(sink),
            MaterializedDtls::V12(e) => e.send_close_notify(sink),
        }
    }

    fn is_complete(&self) -> bool {
        match self {
            MaterializedDtls::V13(e) => e.is_complete(),
            MaterializedDtls::V12(e) => e.is_complete(),
        }
    }
}

struct ServerNegotiator {
    material: DtlsServerMaterial,
    cookie_binding: Bytes,
    buffer: Vec<u8>,
    version_policy: DtlsVersionPolicy,
    active: Option<MaterializedDtls>,
}

impl ServerNegotiator {
    fn new(material: DtlsServerMaterial, cookie_binding: Bytes) -> Self {
        let version_policy = material.version_policy;
        Self {
            material,
            cookie_binding,
            buffer: Vec::new(),
            version_policy,
            active: None,
        }
    }

    fn try_activate<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) -> bool {
        if self.active.is_some() {
            return true;
        }
        match find_client_hello_in_dtls(&self.buffer) {
            Ok(Some(pick)) => {
                if !self.version_policy.allows_server_pick(pick) {
                    sink.protocol_error(TlsProtocolError::new(
                        AlertDescription::ProtocolVersion,
                        "DTLS version not permitted by local policy",
                    ));
                    return true;
                }
                let mut engine = self.material.materialize(pick, self.cookie_binding.clone());
                engine.start(sink);
                engine.feed_datagram(&self.buffer, sink);
                self.buffer.clear();
                self.active = Some(engine);
                true
            }
            Ok(None) => false,
            Err(()) => {
                sink.protocol_error(TlsProtocolError::new(
                    AlertDescription::ProtocolVersion,
                    "unsupported DTLS version in ClientHello",
                ));
                true
            }
        }
    }
}

struct ClientNegotiator {
    config_v13: HandshakeConfig,
    config_v12: Dtls12Config,
    version_policy: DtlsVersionPolicy,
    v13_probe: Option<DtlsRecordEngine>,
    buffer: Vec<u8>,
    active: Option<MaterializedDtls>,
}

impl ClientNegotiator {
    fn new(config_v13: HandshakeConfig, config_v12: Dtls12Config, version_policy: DtlsVersionPolicy) -> Self {
        Self {
            config_v13,
            config_v12,
            version_policy,
            v13_probe: None,
            buffer: Vec::new(),
            active: None,
        }
    }

    fn try_activate<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) -> bool {
        if self.active.is_some() {
            return true;
        }
        match find_server_hello_in_dtls(&self.buffer) {
            Ok(Some(pick)) => {
                if !self.version_policy.allows_client_pick(pick) {
                    sink.protocol_error(TlsProtocolError::new(
                        AlertDescription::ProtocolVersion,
                        "DTLS version not permitted by local policy",
                    ));
                    return true;
                }
                let mut engine = match pick {
                    PickedTls::V13 => {
                        let probe = self.v13_probe.take().expect("client hello probe");
                        MaterializedDtls::V13(probe)
                    }
                    PickedTls::V12 => {
                        let probe = self.v13_probe.take().expect("client hello probe");
                        let ch = probe.client_hello_outbound_wire().expect("client hello wire");
                        let seq = probe.plaintext_write_seq();
                        let mut v12 = Dtls12RecordEngine::new(self.config_v12.clone());
                        v12.client_continue_after_sent_client_hello(&ch, seq);
                        MaterializedDtls::V12(v12)
                    }
                };
                engine.feed_datagram(&self.buffer, sink);
                self.buffer.clear();
                self.active = Some(engine);
                true
            }
            Ok(None) => false,
            Err(()) => {
                sink.protocol_error(TlsProtocolError::new(
                    AlertDescription::ProtocolVersion,
                    "unsupported DTLS version in ServerHello",
                ));
                true
            }
        }
    }
}

// Same tradeoff as `MaterializedDtls` above: one allocation per negotiating
// connection, already behind `NegotiatingDtls`'s own `Box` at its storage
// site, so boxing the inner variant too buys little for a wider diff.
#[allow(clippy::large_enum_variant)]
enum NegotiatingDtlsInner {
    Server(ServerNegotiator),
    Client(ClientNegotiator),
}

/// Combined negotiator stored in [`super::driver::DtlsEngine::Negotiating`].
pub struct NegotiatingDtls(Box<NegotiatingDtlsInner>);

impl NegotiatingDtls {
    fn new(inner: NegotiatingDtlsInner) -> Self {
        Self(Box::new(inner))
    }

    fn inner(&self) -> &NegotiatingDtlsInner {
        &self.0
    }

    fn inner_mut(&mut self) -> &mut NegotiatingDtlsInner {
        &mut self.0
    }
}

impl NegotiatingDtlsInner {
    pub(crate) fn server(material: DtlsServerMaterial, cookie_binding: Bytes) -> Self {
        NegotiatingDtlsInner::Server(ServerNegotiator::new(material, cookie_binding))
    }

    pub(crate) fn client(
        config_v13: HandshakeConfig,
        config_v12: Dtls12Config,
        version_policy: DtlsVersionPolicy,
    ) -> Self {
        NegotiatingDtlsInner::Client(ClientNegotiator::new(config_v13, config_v12, version_policy))
    }
}

impl NegotiatingDtls {
    pub(crate) fn start<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self.inner_mut() {
            NegotiatingDtlsInner::Server(_) => {}
            NegotiatingDtlsInner::Client(c) => {
                if c.v13_probe.is_some() {
                    return;
                }
                let mut probe = DtlsRecordEngine::new(c.config_v13.clone());
                probe.start(sink);
                c.v13_probe = Some(probe);
            }
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        match self.inner() {
            NegotiatingDtlsInner::Server(s) => s.active.as_ref().map(|e| e.is_complete()).unwrap_or(false),
            NegotiatingDtlsInner::Client(c) => c.active.as_ref().map(|e| e.is_complete()).unwrap_or(false),
        }
    }

    pub(crate) fn feed_datagram<S: DtlsRecordSink + ?Sized>(&mut self, data: &[u8], sink: &mut S) {
        match self.inner_mut() {
            NegotiatingDtlsInner::Server(s) => {
                if s.active.is_none() {
                    s.buffer.extend_from_slice(data);
                    if !s.try_activate(sink) {
                        return;
                    }
                    return;
                }
                if let Some(active) = &mut s.active {
                    active.feed_datagram(data, sink);
                }
            }
            NegotiatingDtlsInner::Client(c) => {
                if c.active.is_none() {
                    c.buffer.extend_from_slice(data);
                    if !c.try_activate(sink) {
                        return;
                    }
                    return;
                }
                if let Some(active) = &mut c.active {
                    active.feed_datagram(data, sink);
                }
            }
        }
    }

    pub(crate) fn feed_timer<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self.inner_mut() {
            NegotiatingDtlsInner::Server(s) => {
                if let Some(active) = &mut s.active {
                    active.feed_timer(sink);
                }
            }
            NegotiatingDtlsInner::Client(c) => {
                if let Some(active) = &mut c.active {
                    active.feed_timer(sink);
                }
            }
        }
    }

    pub(crate) fn send_application_data<S: DtlsRecordSink + ?Sized>(&mut self, data: &[u8], sink: &mut S) {
        match self.inner_mut() {
            NegotiatingDtlsInner::Server(s) => {
                if let Some(active) = &mut s.active {
                    active.send_application_data(data, sink);
                }
            }
            NegotiatingDtlsInner::Client(c) => {
                if let Some(active) = &mut c.active {
                    active.send_application_data(data, sink);
                }
            }
        }
    }

    pub(crate) fn feed_verification_result<S: DtlsRecordSink + ?Sized>(
        &mut self,
        result: crate::tls::VerifyResult,
        sink: &mut S,
    ) {
        match self.inner_mut() {
            NegotiatingDtlsInner::Server(s) => {
                if let Some(active) = &mut s.active {
                    active.feed_verification_result(result, sink);
                }
            }
            NegotiatingDtlsInner::Client(c) => {
                if let Some(active) = &mut c.active {
                    active.feed_verification_result(result, sink);
                }
            }
        }
    }

    pub(crate) fn send_close_notify<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self.inner_mut() {
            NegotiatingDtlsInner::Server(s) => {
                if let Some(active) = &mut s.active {
                    active.send_close_notify(sink);
                }
            }
            NegotiatingDtlsInner::Client(c) => {
                if let Some(active) = &mut c.active {
                    active.send_close_notify(sink);
                }
            }
        }
    }
}

/// Build a server engine for `peer` from `material` and [`DtlsVersionPolicy`].
pub fn dtls_server_engine(material: DtlsServerMaterial, peer: SocketAddr) -> super::driver::DtlsEngine {
    use super::driver::{DtlsEngine, peer_cookie_binding};
    let cookie_binding = peer_cookie_binding(peer);
    match material.version_policy {
        DtlsVersionPolicy::Negotiate => {
            DtlsEngine::Negotiating(NegotiatingDtls::new(NegotiatingDtlsInner::server(material, cookie_binding)))
        }
        DtlsVersionPolicy::Tls13Only => DtlsEngine::V13(material.engine_v13()),
        DtlsVersionPolicy::Tls12Only => DtlsEngine::V12(material.engine_v12(cookie_binding)),
    }
}

/// Build a client engine with the given version policy.
pub fn dtls_client_engine(
    server_name: impl Into<String>,
    trust_store: TrustStore,
    kx_policy: KxPolicy,
    version_policy: DtlsVersionPolicy,
) -> super::driver::DtlsEngine {
    use super::driver::DtlsEngine;
    let server_name = server_name.into();
    match version_policy {
        DtlsVersionPolicy::Negotiate => {
            let config_v13 = HandshakeConfig {
                role: HandshakeRole::Client,
                mode: HandshakeMode::Dtls,
                server_name: Some(server_name.clone()),
                trust_store: Some(trust_store.clone()),
                kx_policy: kx_policy.clone(),
                offer_tls12_fallback: true,
                ..Default::default()
            };
            let config_v12 = Dtls12Config {
                base: Tls12Config {
                    role: Tls12Role::Client,
                    server_name: Some(server_name),
                    trust_store: Some(trust_store),
                    ..Default::default()
                },
                require_cookie: false,
                cookie_secret: [0; 32],
                cookie_binding: Bytes::new(),
            };
            DtlsEngine::Negotiating(NegotiatingDtls::new(NegotiatingDtlsInner::client(config_v13, config_v12, version_policy)))
        }
        DtlsVersionPolicy::Tls13Only => DtlsEngine::V13(DtlsRecordEngine::new(HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Dtls,
            server_name: Some(server_name),
            trust_store: Some(trust_store),
            kx_policy,
            offer_tls12_fallback: false,
            ..Default::default()
        })),
        DtlsVersionPolicy::Tls12Only => DtlsEngine::V12(Dtls12RecordEngine::new(Dtls12Config {
            base: Tls12Config {
                role: Tls12Role::Client,
                server_name: Some(server_name),
                trust_store: Some(trust_store),
                ..Default::default()
            },
            require_cookie: false,
            cookie_secret: [0; 32],
            cookie_binding: Bytes::new(),
        })),
    }
}
