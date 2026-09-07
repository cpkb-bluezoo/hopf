// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Reactive TLS 1.3 handshake engine — QUIC-first (no record layer in Phase 2).

use getrandom::getrandom;
use bytes::Bytes;

use crate::crypto::kx::{server_agree, LocalKeyShare, NamedGroup};
use crate::crypto::trust::TrustStore;
use crate::crypto::kx_policy::KxPolicy;
use crate::crypto::signature::Ed25519PrivateKey;
use crate::security::SecurityInfo;

use super::handshake::{
    build_certificate, build_certificate_verify, build_client_hello, build_encrypted_extensions,
    build_finished, build_server_hello, compute_finished_verify_data, derive_application_traffic,
    derive_handshake_traffic, sign_ed25519_certificate_verify, verify_certificate_verify,
    ApplicationTrafficSecrets, ClientHelloParams, HandshakeMessage, HandshakeTrafficSecrets,
    HandshakeType, KeyShareEntry, Transcript,
};
use super::handshake::collect::{MessageCollector, ParsedIncoming};
use super::handshake::parser::{HandshakeEvents, HandshakeParser};
use super::sink::{QuicSecrets, TlsEventSink, TlsProtocolError, VerifyResult};

/// Client or server role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// TLS client.
    Client,
    /// TLS server.
    Server,
}

/// Transport binding for handshake bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeMode {
    /// Raw handshake messages (QUIC CRYPTO stream — RFC 9001).
    Quic,
    /// TLS record layer wraps messages (Phase 4 TCP).
    TcpRecordLayer,
}

/// Server identity for the 1-RTT full handshake (Ed25519 leaf cert in Phase 2).
#[derive(Debug, Clone)]
pub struct ServerCredentials {
    /// DER certificate chain (leaf first).
    pub cert_chain: Vec<Bytes>,
    /// PKCS#8 private key matching the leaf certificate (Ed25519).
    pub signing_key_pkcs8: Bytes,
}

/// Configuration for a single handshake.
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Client or server.
    pub role: HandshakeRole,
    /// QUIC vs TCP record layer.
    pub mode: HandshakeMode,
    /// ALPN protocol names (e.g. `b"h3"`).
    pub alpn: Vec<Bytes>,
    /// Client SNI / server expected name.
    pub server_name: Option<String>,
    /// Server certificate + key (server role only).
    pub server: Option<ServerCredentials>,
    /// Key-exchange group preference (hybrid PQC first by default).
    pub kx_policy: KxPolicy,
    /// Local QUIC transport parameters (RFC 9001 §8.2) sent in ClientHello / EncryptedExtensions.
    pub local_transport_parameters: Option<Bytes>,
    /// Trust anchors for server chain verification (client role).
    pub trust_store: Option<TrustStore>,
}

/// Reactive TLS 1.3 handshake engine with full 1-RTT client/server FSM.
pub struct HandshakeEngine {
    config: HandshakeConfig,
    state: State,
    transcript: Transcript,
    parser: HandshakeParser,
    local_key_share: Option<LocalKeyShare>,
    negotiated_group: Option<NamedGroup>,
    shared_secret: Option<Bytes>,
    handshake_traffic: Option<HandshakeTrafficSecrets>,
    application_traffic: Option<ApplicationTrafficSecrets>,
    negotiated_alpn: Option<Bytes>,
    peer_certs: Vec<Bytes>,
    verify_id: u64,
    verify_pending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Initial,
    ClientHelloSent,
    ReadingServerFlight,
    AwaitingClientFinished,
    Complete,
    Failed,
}

impl HandshakeEngine {
    /// Create an engine; call [`Self::start`] to emit the first flight (client).
    pub fn new(config: HandshakeConfig) -> Self {
        Self {
            config,
            state: State::Initial,
            transcript: Transcript::new(),
            parser: HandshakeParser::new(),
            local_key_share: None,
            negotiated_group: None,
            shared_secret: None,
            handshake_traffic: None,
            application_traffic: None,
            negotiated_alpn: None,
            peer_certs: Vec::new(),
            verify_id: 0,
            verify_pending: false,
        }
    }

    /// Begin the handshake — client emits `ClientHello`; server waits for input.
    pub fn start<S: TlsEventSink>(&mut self, sink: &mut S) {
        if self.state != State::Initial {
            return;
        }
        match self.config.role {
            HandshakeRole::Client => self.client_send_hello(sink),
            HandshakeRole::Server => {}
        }
    }

    /// Consume handshake bytes from the peer (QUIC CRYPTO plaintext).
    ///
    /// Returns the number of bytes consumed from the front of `input`.
    pub fn feed_handshake_data<S: TlsEventSink>(&mut self, input: &mut &[u8], sink: &mut S) -> usize {
        let n = input.len();
        if self.verify_pending || self.state == State::Complete || self.state == State::Failed {
            *input = &[];
            return n;
        }
        let mut parser = HandshakeParser::new();
        std::mem::swap(&mut self.parser, &mut parser);
        {
            let mut bridge = EngineCodecBridge {
                engine: self,
                sink,
                collector: MessageCollector::default(),
                stop: false,
            };
            parser.receive(input, &mut bridge);
        }
        std::mem::swap(&mut self.parser, &mut parser);
        n
    }

    /// Resume after chain verification (from `StorageExecutor` or inline).
    pub fn feed_verification_result<S: TlsEventSink>(&mut self, result: VerifyResult, sink: &mut S) {
        if !self.verify_pending || result.id != self.verify_id {
            return;
        }
        self.verify_pending = false;
        if result.ok {
            self.drain_parser(sink);
        } else {
            self.fail(sink, "certificate verification failed");
        }
    }

    /// Resume parsing after a gate (verification) without new input.
    fn drain_parser<S: TlsEventSink>(&mut self, sink: &mut S) {
        if self.verify_pending || self.state == State::Complete || self.state == State::Failed {
            return;
        }
        let mut parser = HandshakeParser::new();
        std::mem::swap(&mut self.parser, &mut parser);
        {
            let mut bridge = EngineCodecBridge {
                engine: self,
                sink,
                collector: MessageCollector::default(),
                stop: false,
            };
            let mut empty = &[][..];
            parser.receive(&mut empty, &mut bridge);
        }
        std::mem::swap(&mut self.parser, &mut parser);
    }

    /// Whether the handshake has finished successfully.
    pub fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    fn handle_parsed<S: TlsEventSink>(
        &mut self,
        msg_type: HandshakeType,
        parsed: ParsedIncoming,
        wire: Bytes,
        sink: &mut S,
    ) -> bool {
        match (self.config.role, msg_type, self.state, parsed) {
            (HandshakeRole::Client, HandshakeType::ServerHello, State::ClientHelloSent, ParsedIncoming::ServerHello(sh)) => {
                self.on_server_hello(sh, wire, sink)
            }
            (
                HandshakeRole::Client,
                HandshakeType::EncryptedExtensions,
                State::ReadingServerFlight,
                ParsedIncoming::EncryptedExtensions(ee),
            ) => self.on_encrypted_extensions(ee, wire, sink),
            (HandshakeRole::Client, HandshakeType::Certificate, State::ReadingServerFlight, ParsedIncoming::Certificate(certs)) => {
                self.on_certificate(certs, wire, sink)
            }
            (
                HandshakeRole::Client,
                HandshakeType::CertificateVerify,
                State::ReadingServerFlight,
                ParsedIncoming::CertificateVerify(scheme, sig),
            ) => self.on_certificate_verify(scheme, sig, wire, sink),
            (HandshakeRole::Client, HandshakeType::Finished, State::ReadingServerFlight, ParsedIncoming::Finished(vd)) => {
                self.on_server_finished(vd, wire, sink)
            }
            (HandshakeRole::Server, HandshakeType::ClientHello, State::Initial, ParsedIncoming::ClientHello(ch)) => {
                self.on_client_hello(ch, wire, sink)
            }
            (HandshakeRole::Server, HandshakeType::Finished, State::AwaitingClientFinished, ParsedIncoming::Finished(vd)) => {
                self.on_client_finished(vd, wire, sink)
            }
            _ => {
                self.fail(sink, "unexpected handshake message or state");
                false
            }
        }
    }

    fn client_send_hello<S: TlsEventSink>(&mut self, sink: &mut S) {
        let offer = self.config.kx_policy.preferred();
        let Ok(local) = LocalKeyShare::generate(offer) else {
            self.fail(sink, "key generation failed");
            return;
        };
        let mut random = [0u8; 32];
        let _ = getrandom(&mut random);
        let groups: Vec<u16> = self
            .config
            .kx_policy
            .groups()
            .iter()
            .map(|g| g.code())
            .collect();
        let hello = build_client_hello(&ClientHelloParams {
            random,
            key_share: KeyShareEntry {
                group: local.group().code(),
                share: local.client_share_bytes(),
            },
            supported_groups: groups,
            alpn: self.config.alpn.clone(),
            server_name: self.config.server_name.clone(),
            transport_parameters: self.config.local_transport_parameters.clone(),
        });
        self.emit_outgoing(&hello, sink);
        self.local_key_share = Some(local);
        self.state = State::ClientHelloSent;
    }

    fn on_server_hello<S: TlsEventSink>(
        &mut self,
        sh: super::handshake::ParsedServerHello,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        if sh.cipher_suite != 0x1301 {
            self.fail(sink, "unsupported cipher suite");
            return false;
        }
        let Some(group) = NamedGroup::from_code(sh.selected_group) else {
            self.fail(sink, "unsupported key exchange group");
            return false;
        };
        let Some(local) = self.local_key_share.take() else {
            self.fail(sink, "missing local key share");
            return false;
        };
        let Ok(shared) = local.agree_client(group, &sh.key_share) else {
            self.fail(sink, "key agreement failed");
            return false;
        };
        self.transcript.add_message(&encoded);
        self.negotiated_group = Some(group);
        sink.key_exchange_group_negotiated(group.code());
        self.shared_secret = Some(shared);
        self.handshake_traffic =
            Some(derive_handshake_traffic(self.shared_secret.as_ref().unwrap(), &self.transcript.hash()));
        if let Some(traffic) = self.handshake_traffic.as_ref() {
            sink.quic_handshake_keys_ready(traffic.client, traffic.server);
        }
        self.state = State::ReadingServerFlight;
        true
    }

    fn on_encrypted_extensions<S: TlsEventSink>(
        &mut self,
        ee: super::handshake::ParsedEncryptedExtensions,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        self.transcript.add_message(&encoded);
        self.negotiated_alpn = ee.alpn;
        if let Some(tp) = ee.transport_parameters {
            sink.peer_transport_parameters(&tp);
        }
        true
    }

    fn on_certificate<S: TlsEventSink>(
        &mut self,
        certs: Vec<Bytes>,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        self.transcript.add_message(&encoded);
        self.peer_certs = certs;
        self.verify_id += 1;
        self.verify_pending = true;
        sink.verification_requested(super::sink::VerifyRequest {
            id: self.verify_id,
            peer_chain: self.peer_certs.clone(),
            server_name: self.config.server_name.clone(),
        });
        if let Some(store) = &self.config.trust_store {
            let ok = store
                .verify_server_chain(&self.peer_certs, self.config.server_name.as_deref())
                .is_ok();
            self.verify_pending = false;
            if !ok {
                self.fail(sink, "certificate verification failed");
                return false;
            }
            return true;
        }
        false
    }

    fn on_certificate_verify<S: TlsEventSink>(
        &mut self,
        scheme: u16,
        sig: Bytes,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        let Some(leaf) = self.peer_certs.first() else {
            self.fail(sink, "certificate verify without certificate");
            return false;
        };
        let th = self.transcript.hash();
        if !verify_certificate_verify(false, leaf.as_ref(), scheme, &sig, &th) {
            self.fail(sink, "CertificateVerify signature invalid");
            return false;
        }
        self.transcript.add_message(&encoded);
        true
    }

    fn on_server_finished<S: TlsEventSink>(
        &mut self,
        vd: Bytes,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        let Some(traffic) = self.handshake_traffic.as_ref() else {
            self.fail(sink, "missing handshake traffic");
            return false;
        };
        let th = self.transcript.hash();
        let expected = compute_finished_verify_data(&traffic.server, &th);
        if vd.as_ref() != expected {
            self.fail(sink, "server Finished verify failed");
            return false;
        }
        self.transcript.add_message(&encoded);
        self.client_send_finished(sink)
    }

    fn client_send_finished<S: TlsEventSink>(&mut self, sink: &mut S) -> bool {
        let Some(traffic) = self.handshake_traffic.as_ref() else {
            self.fail(sink, "missing handshake traffic");
            return false;
        };
        let th = self.transcript.hash();
        let vd = compute_finished_verify_data(&traffic.client, &th);
        let fin = build_finished(&vd);
        self.emit_outgoing(&fin, sink);
        let Some(shared) = self.shared_secret.as_ref() else {
            self.fail(sink, "missing shared secret");
            return false;
        };
        self.application_traffic = Some(derive_application_traffic(shared, &self.transcript.hash()));
        self.finish(sink);
        true
    }

    fn on_client_hello<S: TlsEventSink>(
        &mut self,
        ch: super::handshake::ParsedClientHello,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        if let Some(tp) = &ch.transport_parameters {
            sink.peer_transport_parameters(tp);
        }
        let Some(group) = self.config.kx_policy.select_mutual(&ch.supported_groups) else {
            self.fail(sink, "no mutually supported key exchange group");
            return false;
        };
        let Some(peer_share) = ch.peer_key_share else {
            self.fail(sink, "missing client key share");
            return false;
        };
        if ch.key_share_group != Some(group.code()) {
            self.fail(sink, "client key share group mismatch");
            return false;
        }
        let Some(creds) = self.config.server.clone() else {
            self.fail(sink, "server credentials not configured");
            return false;
        };
        let Ok((server_share, shared)) = server_agree(group, &peer_share) else {
            self.fail(sink, "key agreement failed");
            return false;
        };
        self.transcript.add_message(&encoded);

        let mut server_random = [0u8; 32];
        let _ = getrandom(&mut server_random);
        let sh = build_server_hello(&server_random, group.code(), server_share.as_ref());
        self.emit_outgoing(&sh, sink);

        self.negotiated_group = Some(group);
        sink.key_exchange_group_negotiated(group.code());
        self.shared_secret = Some(shared);
        self.handshake_traffic =
            Some(derive_handshake_traffic(self.shared_secret.as_ref().unwrap(), &self.transcript.hash()));
        if let Some(traffic) = self.handshake_traffic.as_ref() {
            sink.quic_handshake_keys_ready(traffic.client, traffic.server);
        }

        let alpn = pick_alpn(&ch.alpn, &self.config.alpn);
        self.negotiated_alpn = alpn.clone();
        let ee = build_encrypted_extensions(
            alpn.as_deref().unwrap_or(b"h3"),
            self.config.local_transport_parameters.as_deref(),
        );
        self.emit_outgoing(&ee, sink);

        let cert_refs: Vec<&[u8]> = creds.cert_chain.iter().map(|c| c.as_ref()).collect();
        let cert_msg = build_certificate(&cert_refs);
        self.emit_outgoing(&cert_msg, sink);

        let signing_key = match Ed25519PrivateKey::from_pkcs8(&creds.signing_key_pkcs8) {
            Ok(k) => k,
            Err(_) => {
                self.fail(sink, "invalid server signing key");
                return false;
            }
        };
        let cv_th = self.transcript.hash();
        let (scheme, sig) = sign_ed25519_certificate_verify(false, &signing_key, &cv_th);
        let cv = build_certificate_verify(scheme, sig.as_ref());
        self.emit_outgoing(&cv, sink);

        let fin_th = self.transcript.hash();
        let traffic = self.handshake_traffic.as_ref().expect("hs traffic");
        let vd = compute_finished_verify_data(&traffic.server, &fin_th);
        let fin = build_finished(&vd);
        self.emit_outgoing(&fin, sink);

        self.state = State::AwaitingClientFinished;
        true
    }

    fn on_client_finished<S: TlsEventSink>(
        &mut self,
        vd: Bytes,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        let Some(traffic) = self.handshake_traffic.as_ref() else {
            self.fail(sink, "missing handshake traffic");
            return false;
        };
        let th = self.transcript.hash();
        let expected = compute_finished_verify_data(&traffic.client, &th);
        if vd.as_ref() != expected {
            self.fail(sink, "client Finished verify failed");
            return false;
        }
        self.transcript.add_message(&encoded);
        let Some(shared) = self.shared_secret.as_ref() else {
            self.fail(sink, "missing shared secret");
            return false;
        };
        self.application_traffic = Some(derive_application_traffic(shared, &self.transcript.hash()));
        self.finish(sink);
        true
    }

    fn emit_outgoing<S: TlsEventSink>(&mut self, msg: &HandshakeMessage, sink: &mut S) {
        let wire = msg.encode();
        self.transcript.add_message(&wire);
        sink.handshake_data_ready(&wire);
    }

    fn finish<S: TlsEventSink>(&mut self, sink: &mut S) {
        if self.state == State::Complete {
            return;
        }
        let app = self.application_traffic.take();
        let hs = self.handshake_traffic.take();
        let (client_hs, server_hs) = match hs {
            Some(t) => (t.client, t.server),
            None => {
                self.fail(sink, "handshake traffic missing at completion");
                return;
            }
        };
        let info = SecurityInfo::secure(
            self.negotiated_alpn
                .clone()
                .or_else(|| self.config.alpn.first().cloned()),
            Some("TLSv1.3".to_string()),
            Some("TLS_AES_128_GCM_SHA256".to_string()),
        );
        let quic = match self.config.mode {
            HandshakeMode::Quic => Some(QuicSecrets {
                client_handshake_traffic_secret: client_hs,
                server_handshake_traffic_secret: server_hs,
                client_application_traffic_secret: app.as_ref().map(|a| a.client),
                server_application_traffic_secret: app.as_ref().map(|a| a.server),
            }),
            HandshakeMode::TcpRecordLayer => None,
        };
        self.state = State::Complete;
        sink.handshake_complete(info, quic);
    }

    fn fail<S: TlsEventSink>(&mut self, sink: &mut S, msg: &str) {
        if self.state != State::Failed {
            self.state = State::Failed;
            sink.protocol_error(TlsProtocolError::new(msg));
        }
    }
}

/// Codec seam: forwards parse events into a [`MessageCollector`], then dispatches
/// assembled messages to [`HandshakeEngine::handle_parsed`].
struct EngineCodecBridge<'a, S: TlsEventSink> {
    engine: &'a mut HandshakeEngine,
    sink: &'a mut S,
    collector: MessageCollector,
    stop: bool,
}

impl<S: TlsEventSink> HandshakeEvents for EngineCodecBridge<'_, S> {
    fn message_begin(&mut self, msg_type: HandshakeType) {
        self.collector.message_begin(msg_type);
    }

    fn legacy_version(&mut self, version: u16) {
        self.collector.legacy_version(version);
    }

    fn random(&mut self, value: &[u8; 32]) {
        self.collector.random(value);
    }

    fn session_id(&mut self, value: &[u8]) {
        self.collector.session_id(value);
    }

    fn cipher_suite_offered(&mut self, suite: u16) {
        self.collector.cipher_suite_offered(suite);
    }

    fn cipher_suite_selected(&mut self, suite: u16) {
        self.collector.cipher_suite_selected(suite);
    }

    fn compression_method(&mut self, method: u8) {
        self.collector.compression_method(method);
    }

    fn supported_group(&mut self, group: u16) {
        self.collector.supported_group(group);
    }

    fn key_share(&mut self, group: u16, share: &[u8]) {
        self.collector.key_share(group, share);
    }

    fn alpn_protocol(&mut self, proto: &[u8]) {
        self.collector.alpn_protocol(proto);
    }

    fn server_name(&mut self, host: &str) {
        self.collector.server_name(host);
    }

    fn transport_parameters(&mut self, params: &[u8]) {
        self.collector.transport_parameters(params);
    }

    fn extension(&mut self, ext_type: u16, data: &[u8]) {
        self.collector.extension(ext_type, data);
    }

    fn certificate_request_context(&mut self, ctx: &[u8]) {
        self.collector.certificate_request_context(ctx);
    }

    fn certificate_entry(&mut self, der: &[u8]) {
        self.collector.certificate_entry(der);
    }

    fn certificate_verify(&mut self, scheme: u16, signature: &[u8]) {
        self.collector.certificate_verify(scheme, signature);
    }

    fn finished_verify_data(&mut self, data: &[u8]) {
        self.collector.finished_verify_data(data);
    }

    fn message_end(&mut self, msg_type: HandshakeType, wire: Bytes) {
        if self.stop {
            return;
        }
        let Some(parsed) = self.collector.take_parsed(msg_type) else {
            self.engine.fail(
                self.sink,
                match msg_type {
                    HandshakeType::Certificate => "invalid Certificate message",
                    HandshakeType::CertificateVerify => "invalid CertificateVerify message",
                    HandshakeType::Finished => "invalid Finished message",
                    other => {
                        let _ = other;
                        "invalid handshake message"
                    }
                },
            );
            self.stop = true;
            return;
        };
        if !self.engine.handle_parsed(msg_type, parsed, wire, self.sink) {
            self.stop = true;
        }
    }

    fn parse_error(&mut self, detail: &'static str) {
        self.engine.fail(self.sink, detail);
        self.stop = true;
    }
}

fn pick_alpn(client: &[Bytes], server: &[Bytes]) -> Option<Bytes> {
    for s in server {
        if client.iter().any(|c| c == s) {
            return Some(s.clone());
        }
    }
    server.first().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::sink::{TlsEventSink, VerifyRequest};

    #[derive(Default)]
    struct RecordingSink {
        events: Vec<String>,
        outbound: Vec<Bytes>,
        quic: Option<QuicSecrets>,
        peer_tp: Option<Bytes>,
        negotiated_group: Option<u16>,
    }

    impl TlsEventSink for RecordingSink {
        fn handshake_data_ready(&mut self, data: &[u8]) {
            self.events.push(format!("outbound {} bytes", data.len()));
            self.outbound.push(Bytes::copy_from_slice(data));
        }
        fn handshake_complete(&mut self, _info: SecurityInfo, quic: Option<QuicSecrets>) {
            self.events.push("handshake_complete".into());
            self.quic = quic;
        }
        fn verification_requested(&mut self, req: VerifyRequest) {
            self.events
                .push(format!("verification_requested id={}", req.id));
        }
        fn peer_transport_parameters(&mut self, params: &[u8]) {
            self.peer_tp = Some(Bytes::copy_from_slice(params));
            self.events.push(format!("peer_tp {} bytes", params.len()));
        }
        fn key_exchange_group_negotiated(&mut self, group: u16) {
            self.negotiated_group = Some(group);
            self.events
                .push(format!("negotiated_group=0x{group:04x}"));
        }
        fn protocol_error(&mut self, err: TlsProtocolError) {
            self.events.push(format!("protocol_error: {}", err.message));
        }
        fn timeout(&mut self, _kind: super::super::sink::TlsTimerKind) {}
        fn peer_closed(&mut self) {
            self.events.push("peer_closed".into());
        }
    }

    fn test_server_credentials() -> ServerCredentials {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        ServerCredentials {
            cert_chain: vec![Bytes::copy_from_slice(cert.der())],
            signing_key_pkcs8: Bytes::from(key_pair.serialize_der()),
        }
    }

    fn take_outbound(sink: &mut RecordingSink) -> Vec<Bytes> {
        std::mem::take(&mut sink.outbound)
    }

    fn relay_server(server: &mut HandshakeEngine, outbound: Vec<Bytes>, sink: &mut RecordingSink) {
        for chunk in outbound {
            let mut input = chunk.as_ref();
            server.feed_handshake_data(&mut input, sink);
        }
    }

    fn relay_client(client: &mut HandshakeEngine, outbound: Vec<Bytes>, sink: &mut RecordingSink) {
        for chunk in outbound {
            let mut input = chunk.as_ref();
            client.feed_handshake_data(&mut input, sink);
        }
    }

    fn run_loopback(client_cfg: HandshakeConfig, server_cfg: HandshakeConfig) -> RecordingSink {
        let mut server = HandshakeEngine::new(server_cfg);
        let mut client = HandshakeEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        relay_client(&mut client, take_outbound(&mut sink), &mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        assert!(client.is_complete(), "client: {:?}", sink.events);
        assert!(server.is_complete(), "server: {:?}", sink.events);
        sink
    }

    fn client_config_with_trust(creds: &ServerCredentials, kx: KxPolicy, tp: Option<Bytes>) -> HandshakeConfig {
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: Some("localhost".into()),
            server: None,
            kx_policy: kx,
            local_transport_parameters: tp,
            trust_store: Some(trust),
        }
    }

    #[test]
    fn client_start_emits_client_hello() {
        let mut engine = HandshakeEngine::new(HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: Some("example.com".into()),
            server: None,
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: None,
            trust_store: None,
        });
        let mut sink = RecordingSink::default();
        engine.start(&mut sink);
        assert_eq!(sink.events.len(), 1);
        assert!(sink.outbound[0].len() > 40);
    }

    #[test]
    fn full_1rtt_client_server_loopback() {
        let creds = test_server_credentials();
        let sink = run_loopback(
            client_config_with_trust(&creds, KxPolicy::classical_only(), None),
            HandshakeConfig {
                role: HandshakeRole::Server,
                mode: HandshakeMode::Quic,
                alpn: vec![Bytes::from_static(b"h3")],
                server_name: None,
                server: Some(creds),
                kx_policy: KxPolicy::classical_only(),
                local_transport_parameters: None,
                trust_store: None,
            },
        );
        let quic = sink.quic.expect("quic secrets");
        assert!(quic.client_application_traffic_secret.is_some());
        assert_eq!(sink.negotiated_group, Some(NamedGroup::X25519.code()));
    }

    #[test]
    fn full_1rtt_hybrid_pqc_and_transport_parameters() {
        use super::super::handshake::encode_initial_max_data;
        let creds = test_server_credentials();
        let client_tp = encode_initial_max_data(1_048_576);
        let server_tp = encode_initial_max_data(2_097_152);
        let sink = run_loopback(
            client_config_with_trust(&creds, KxPolicy::pqc_first(), Some(client_tp)),
            HandshakeConfig {
                role: HandshakeRole::Server,
                mode: HandshakeMode::Quic,
                alpn: vec![Bytes::from_static(b"h3")],
                server_name: None,
                server: Some(creds),
                kx_policy: KxPolicy::pqc_first(),
                local_transport_parameters: Some(server_tp),
                trust_store: None,
            },
        );
        assert_eq!(
            sink.negotiated_group,
            Some(NamedGroup::X25519MLKEM768.code())
        );
        assert!(sink.peer_tp.is_some());
    }

    #[test]
    fn client_event_sequence_bad_server_hello() {
        let mut engine = HandshakeEngine::new(HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: None,
            server: None,
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: None,
            trust_store: None,
        });
        let mut sink = RecordingSink::default();
        engine.start(&mut sink);
        let bad_sh = HandshakeMessage {
            msg_type: HandshakeType::ServerHello,
            body: Bytes::from(vec![0u8; 8]),
        };
        let enc = bad_sh.encode();
        let mut slice = enc.as_ref();
        engine.feed_handshake_data(&mut slice, &mut sink);
        assert!(
            sink.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink.events
        );
    }
}
