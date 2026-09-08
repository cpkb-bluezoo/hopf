// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Collectors that assemble [`HandshakeEvents`] into small parsed message views.
//!
//! These are internal convenience adapters — the parser seam is
//! [`super::parser::HandshakeParser`] + [`super::parser::HandshakeEvents`].

use bytes::{Bytes, BytesMut};

use super::messages::HandshakeType;
use super::parser::{HandshakeEvents, HandshakeParser};

/// Parsed `ClientHello` fields needed for the server path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedClientHello {
    /// Client random.
    pub random: [u8; 32],
    /// Client key share bytes.
    pub peer_key_share: Option<Bytes>,
    /// Group id for [`Self::peer_key_share`].
    pub key_share_group: Option<u16>,
    /// Supported groups extension.
    pub supported_groups: Vec<u16>,
    /// ALPN protocol names offered.
    pub alpn: Vec<Bytes>,
    /// SNI hostname, if present.
    pub server_name: Option<String>,
    /// QUIC transport parameters from the client, if present.
    pub transport_parameters: Option<Bytes>,
    /// Client offered early data.
    pub early_data: bool,
    /// First offered PSK identity (opaque ticket).
    pub psk_identity: Option<Bytes>,
    /// Obfuscated ticket age for the first PSK identity (RFC 8446 §4.2.11).
    pub obfuscated_ticket_age: Option<u32>,
    /// First PSK binder.
    pub psk_binder: Option<Bytes>,
}

/// Parsed `ServerHello` fields needed for key schedule (Phase 2 subset).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedServerHello {
    /// Server random.
    pub random: [u8; 32],
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected key-exchange group.
    pub selected_group: u16,
    /// Server key share for the selected group.
    pub key_share: Bytes,
    /// Selected PSK identity index (resumption).
    pub psk_selected_identity: Option<u16>,
}

/// Parsed EncryptedExtensions content.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedEncryptedExtensions {
    /// Negotiated ALPN (first entry).
    pub alpn: Option<Bytes>,
    /// QUIC transport parameters from the server.
    pub transport_parameters: Option<Bytes>,
    /// Server accepted early data.
    pub early_data: bool,
}

/// Parsed NewSessionTicket (post-handshake).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedNewSessionTicket {
    /// Ticket lifetime seconds.
    pub lifetime: u32,
    /// Ticket age add.
    pub age_add: u32,
    /// Ticket nonce.
    pub nonce: Bytes,
    /// Opaque ticket identity.
    pub ticket: Bytes,
    /// Max early data size (0 if absent).
    pub max_early_data: u32,
}

#[derive(Default)]
struct ClientHelloCollector {
    out: ParsedClientHello,
    first_key_share: bool,
    failed: bool,
}

impl HandshakeEvents for ClientHelloCollector {
    fn message_begin(&mut self, _msg_type: HandshakeType) {}

    fn random(&mut self, value: &[u8; 32]) {
        self.out.random = *value;
    }

    fn supported_group(&mut self, group: u16) {
        self.out.supported_groups.push(group);
    }

    fn key_share(&mut self, group: u16, share: &[u8]) {
        if !self.first_key_share {
            self.first_key_share = true;
            self.out.key_share_group = Some(group);
            self.out.peer_key_share = Some(Bytes::copy_from_slice(share));
        }
    }

    fn alpn_protocol(&mut self, proto: &[u8]) {
        self.out.alpn.push(Bytes::copy_from_slice(proto));
    }

    fn server_name(&mut self, host: &str) {
        if self.out.server_name.is_none() {
            self.out.server_name = Some(host.to_string());
        }
    }

    fn transport_parameters(&mut self, params: &[u8]) {
        if self.out.transport_parameters.is_none() {
            self.out.transport_parameters = Some(Bytes::copy_from_slice(params));
        }
    }

    fn early_data(&mut self) {
        self.out.early_data = true;
    }

    fn psk_identity(&mut self, identity: &[u8], obfuscated_ticket_age: u32) {
        if self.out.psk_identity.is_none() {
            self.out.psk_identity = Some(Bytes::copy_from_slice(identity));
            self.out.obfuscated_ticket_age = Some(obfuscated_ticket_age);
        }
    }

    fn psk_binder(&mut self, binder: &[u8]) {
        if self.out.psk_binder.is_none() {
            self.out.psk_binder = Some(Bytes::copy_from_slice(binder));
        }
    }

    fn message_end(&mut self, _msg_type: HandshakeType, _wire: Bytes) {}

    fn parse_error(&mut self, _detail: &'static str) {
        self.failed = true;
    }
}

#[derive(Default)]
struct ServerHelloCollector {
    out: ParsedServerHello,
    failed: bool,
}

impl HandshakeEvents for ServerHelloCollector {
    fn message_begin(&mut self, _msg_type: HandshakeType) {}

    fn random(&mut self, value: &[u8; 32]) {
        self.out.random = *value;
    }

    fn cipher_suite_selected(&mut self, suite: u16) {
        self.out.cipher_suite = suite;
    }

    fn key_share(&mut self, group: u16, share: &[u8]) {
        if self.out.key_share.is_empty() {
            self.out.selected_group = group;
            self.out.key_share = Bytes::copy_from_slice(share);
        }
    }

    fn psk_selected_identity(&mut self, index: u16) {
        self.out.psk_selected_identity = Some(index);
    }

    fn message_end(&mut self, _msg_type: HandshakeType, _wire: Bytes) {}

    fn parse_error(&mut self, _detail: &'static str) {
        self.failed = true;
    }
}

#[derive(Default)]
struct EncryptedExtensionsCollector {
    out: ParsedEncryptedExtensions,
    failed: bool,
}

impl HandshakeEvents for EncryptedExtensionsCollector {
    fn message_begin(&mut self, _msg_type: HandshakeType) {}

    fn alpn_protocol(&mut self, proto: &[u8]) {
        if self.out.alpn.is_none() {
            self.out.alpn = Some(Bytes::copy_from_slice(proto));
        }
    }

    fn transport_parameters(&mut self, params: &[u8]) {
        if self.out.transport_parameters.is_none() {
            self.out.transport_parameters = Some(Bytes::copy_from_slice(params));
        }
    }

    fn early_data(&mut self) {
        self.out.early_data = true;
    }

    fn message_end(&mut self, _msg_type: HandshakeType, _wire: Bytes) {}

    fn parse_error(&mut self, _detail: &'static str) {
        self.failed = true;
    }
}

#[derive(Default)]
struct NewSessionTicketCollector {
    out: ParsedNewSessionTicket,
    failed: bool,
    got: bool,
}

impl HandshakeEvents for NewSessionTicketCollector {
    fn message_begin(&mut self, _msg_type: HandshakeType) {}

    fn new_session_ticket(
        &mut self,
        lifetime: u32,
        age_add: u32,
        nonce: &[u8],
        ticket: &[u8],
        max_early_data: u32,
    ) {
        self.out = ParsedNewSessionTicket {
            lifetime,
            age_add,
            nonce: Bytes::copy_from_slice(nonce),
            ticket: Bytes::copy_from_slice(ticket),
            max_early_data,
        };
        self.got = true;
    }

    fn message_end(&mut self, _msg_type: HandshakeType, _wire: Bytes) {}

    fn parse_error(&mut self, _detail: &'static str) {
        self.failed = true;
    }
}

#[derive(Default)]
struct CertificateCollector {
    certs: Vec<Bytes>,
    failed: bool,
}

impl HandshakeEvents for CertificateCollector {
    fn message_begin(&mut self, _msg_type: HandshakeType) {}

    fn certificate_entry(&mut self, der: &[u8]) {
        self.certs.push(Bytes::copy_from_slice(der));
    }

    fn message_end(&mut self, _msg_type: HandshakeType, _wire: Bytes) {}

    fn parse_error(&mut self, _detail: &'static str) {
        self.failed = true;
    }
}

#[derive(Default)]
struct CertificateVerifyCollector {
    scheme: u16,
    signature: Bytes,
    failed: bool,
    got: bool,
}

impl HandshakeEvents for CertificateVerifyCollector {
    fn message_begin(&mut self, _msg_type: HandshakeType) {}

    fn certificate_verify(&mut self, scheme: u16, signature: &[u8]) {
        self.scheme = scheme;
        self.signature = Bytes::copy_from_slice(signature);
        self.got = true;
    }

    fn message_end(&mut self, _msg_type: HandshakeType, _wire: Bytes) {}

    fn parse_error(&mut self, _detail: &'static str) {
        self.failed = true;
    }
}

#[derive(Default)]
struct FinishedCollector {
    verify_data: Bytes,
    failed: bool,
}

impl HandshakeEvents for FinishedCollector {
    fn message_begin(&mut self, _msg_type: HandshakeType) {}

    fn finished_verify_data(&mut self, data: &[u8]) {
        self.verify_data = Bytes::copy_from_slice(data);
    }

    fn message_end(&mut self, _msg_type: HandshakeType, _wire: Bytes) {}

    fn parse_error(&mut self, _detail: &'static str) {
        self.failed = true;
    }
}

fn decode_one(msg_type: HandshakeType, body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    let mut wire = BytesMut::with_capacity(4 + body.len());
    wire.extend_from_slice(&[msg_type as u8]);
    wire.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    wire.extend_from_slice(body);
    let mut parser = HandshakeParser::new();
    let mut slice = wire.as_ref();
    parser.receive(&mut slice, handler);
    if !slice.is_empty() {
        handler.parse_error("trailing data");
        return false;
    }
    parser.close(handler);
    true
}

/// Parse a `ClientHello` body through the handshake codec.
pub fn parse_client_hello(body: &[u8]) -> Option<ParsedClientHello> {
    let mut c = ClientHelloCollector::default();
    if !decode_one(HandshakeType::ClientHello, body, &mut c) || c.failed {
        return None;
    }
    if c.out.peer_key_share.is_none() {
        return None;
    }
    Some(c.out)
}

/// Parse a `ServerHello` body through the handshake codec.
pub fn parse_server_hello(body: &[u8]) -> Option<ParsedServerHello> {
    let mut c = ServerHelloCollector::default();
    if !decode_one(HandshakeType::ServerHello, body, &mut c) || c.failed {
        return None;
    }
    if c.out.key_share.is_empty() {
        return None;
    }
    Some(c.out)
}

/// Parse `EncryptedExtensions` through the handshake codec.
pub fn parse_encrypted_extensions(body: &[u8]) -> Option<ParsedEncryptedExtensions> {
    let mut c = EncryptedExtensionsCollector::default();
    if !decode_one(HandshakeType::EncryptedExtensions, body, &mut c) || c.failed {
        return None;
    }
    Some(c.out)
}

/// Parse a TLS 1.3 `Certificate` message — DER entries leaf-first.
pub fn parse_certificate(body: &[u8]) -> Option<Vec<Bytes>> {
    let mut c = CertificateCollector::default();
    if !decode_one(HandshakeType::Certificate, body, &mut c) || c.failed || c.certs.is_empty() {
        return None;
    }
    Some(c.certs)
}

/// Parse `CertificateVerify` — `(scheme, signature)`.
pub fn parse_certificate_verify(body: &[u8]) -> Option<(u16, Bytes)> {
    let mut c = CertificateVerifyCollector::default();
    if !decode_one(HandshakeType::CertificateVerify, body, &mut c) || c.failed || !c.got {
        return None;
    }
    Some((c.scheme, c.signature))
}

/// Parse `Finished` verify_data.
pub fn parse_finished(body: &[u8]) -> Option<Bytes> {
    let mut c = FinishedCollector::default();
    if !decode_one(HandshakeType::Finished, body, &mut c) || c.failed || c.verify_data.len() != 32 {
        return None;
    }
    Some(c.verify_data)
}

/// Feed handshake bytes through `parser`, invoking `handler` for each complete message.
pub fn feed_parser(
    parser: &mut HandshakeParser,
    data: &mut &[u8],
    handler: &mut dyn HandshakeEvents,
) -> usize {
    parser.receive(data, handler)
}

/// One fully parsed incoming handshake message (assembled from codec events).
pub(crate) enum ParsedIncoming {
    /// ClientHello.
    ClientHello(ParsedClientHello),
    /// ServerHello.
    ServerHello(ParsedServerHello),
    /// EncryptedExtensions.
    EncryptedExtensions(ParsedEncryptedExtensions),
    /// Certificate chain (DER, leaf first).
    Certificate(Vec<Bytes>),
    /// CertificateVerify `(scheme, signature)`.
    CertificateVerify(u16, Bytes),
    /// Finished verify_data.
    Finished(Bytes),
    /// NewSessionTicket (post-handshake).
    NewSessionTicket(ParsedNewSessionTicket),
}

/// Active collector for the message currently being parsed.
pub(crate) enum MessageCollector {
    /// No message yet.
    Idle,
    /// Collecting ClientHello.
    ClientHello(ClientHelloCollector),
    /// Collecting ServerHello.
    ServerHello(ServerHelloCollector),
    /// Collecting EncryptedExtensions.
    EncryptedExtensions(EncryptedExtensionsCollector),
    /// Collecting Certificate.
    Certificate(CertificateCollector),
    /// Collecting CertificateVerify.
    CertificateVerify(CertificateVerifyCollector),
    /// Collecting Finished.
    Finished(FinishedCollector),
    /// Collecting NewSessionTicket.
    NewSessionTicket(NewSessionTicketCollector),
}

impl Default for MessageCollector {
    fn default() -> Self {
        Self::Idle
    }
}

impl MessageCollector {
    /// Take the parsed message if collection succeeded.
    pub(crate) fn take_parsed(&mut self, msg_type: HandshakeType) -> Option<ParsedIncoming> {
        match (msg_type, std::mem::take(self)) {
            (HandshakeType::ClientHello, Self::ClientHello(c)) => {
                if c.failed || c.out.peer_key_share.is_none() {
                    return None;
                }
                Some(ParsedIncoming::ClientHello(c.out))
            }
            (HandshakeType::ServerHello, Self::ServerHello(c)) => {
                if c.failed || c.out.key_share.is_empty() {
                    return None;
                }
                Some(ParsedIncoming::ServerHello(c.out))
            }
            (HandshakeType::EncryptedExtensions, Self::EncryptedExtensions(c)) => {
                if c.failed {
                    return None;
                }
                Some(ParsedIncoming::EncryptedExtensions(c.out))
            }
            (HandshakeType::Certificate, Self::Certificate(c)) => {
                if c.failed || c.certs.is_empty() {
                    return None;
                }
                Some(ParsedIncoming::Certificate(c.certs))
            }
            (HandshakeType::CertificateVerify, Self::CertificateVerify(c)) => {
                if c.failed || !c.got {
                    return None;
                }
                Some(ParsedIncoming::CertificateVerify(c.scheme, c.signature))
            }
            (HandshakeType::Finished, Self::Finished(c)) => {
                if c.failed || c.verify_data.len() != 32 {
                    return None;
                }
                Some(ParsedIncoming::Finished(c.verify_data))
            }
            (HandshakeType::NewSessionTicket, Self::NewSessionTicket(c)) => {
                if c.failed || !c.got {
                    return None;
                }
                Some(ParsedIncoming::NewSessionTicket(c.out))
            }
            _ => None,
        }
    }
}

impl HandshakeEvents for MessageCollector {
    fn message_begin(&mut self, msg_type: HandshakeType) {
        *self = match msg_type {
            HandshakeType::ClientHello => Self::ClientHello(ClientHelloCollector::default()),
            HandshakeType::ServerHello => Self::ServerHello(ServerHelloCollector::default()),
            HandshakeType::EncryptedExtensions => {
                Self::EncryptedExtensions(EncryptedExtensionsCollector::default())
            }
            HandshakeType::Certificate => Self::Certificate(CertificateCollector::default()),
            HandshakeType::CertificateVerify => {
                Self::CertificateVerify(CertificateVerifyCollector::default())
            }
            HandshakeType::Finished => Self::Finished(FinishedCollector::default()),
            HandshakeType::NewSessionTicket => {
                Self::NewSessionTicket(NewSessionTicketCollector::default())
            }
        };
    }

    fn legacy_version(&mut self, version: u16) {
        match self {
            Self::ClientHello(c) => c.legacy_version(version),
            Self::ServerHello(c) => c.legacy_version(version),
            _ => {}
        }
    }

    fn random(&mut self, value: &[u8; 32]) {
        match self {
            Self::ClientHello(c) => c.random(value),
            Self::ServerHello(c) => c.random(value),
            _ => {}
        }
    }

    fn session_id(&mut self, value: &[u8]) {
        match self {
            Self::ClientHello(c) => c.session_id(value),
            Self::ServerHello(c) => c.session_id(value),
            _ => {}
        }
    }

    fn cipher_suite_offered(&mut self, suite: u16) {
        if let Self::ClientHello(c) = self {
            c.cipher_suite_offered(suite);
        }
    }

    fn cipher_suite_selected(&mut self, suite: u16) {
        if let Self::ServerHello(c) = self {
            c.cipher_suite_selected(suite);
        }
    }

    fn compression_method(&mut self, method: u8) {
        match self {
            Self::ClientHello(c) => c.compression_method(method),
            Self::ServerHello(c) => c.compression_method(method),
            _ => {}
        }
    }

    fn supported_group(&mut self, group: u16) {
        if let Self::ClientHello(c) = self {
            c.supported_group(group);
        }
    }

    fn key_share(&mut self, group: u16, share: &[u8]) {
        match self {
            Self::ClientHello(c) => c.key_share(group, share),
            Self::ServerHello(c) => c.key_share(group, share),
            _ => {}
        }
    }

    fn alpn_protocol(&mut self, proto: &[u8]) {
        match self {
            Self::ClientHello(c) => c.alpn_protocol(proto),
            Self::EncryptedExtensions(c) => c.alpn_protocol(proto),
            _ => {}
        }
    }

    fn server_name(&mut self, host: &str) {
        if let Self::ClientHello(c) = self {
            c.server_name(host);
        }
    }

    fn transport_parameters(&mut self, params: &[u8]) {
        match self {
            Self::ClientHello(c) => c.transport_parameters(params),
            Self::EncryptedExtensions(c) => c.transport_parameters(params),
            _ => {}
        }
    }

    fn early_data(&mut self) {
        match self {
            Self::ClientHello(c) => c.early_data(),
            Self::EncryptedExtensions(c) => c.early_data(),
            _ => {}
        }
    }

    fn psk_identity(&mut self, identity: &[u8], obfuscated_ticket_age: u32) {
        if let Self::ClientHello(c) = self {
            c.psk_identity(identity, obfuscated_ticket_age);
        }
    }

    fn psk_binder(&mut self, binder: &[u8]) {
        if let Self::ClientHello(c) = self {
            c.psk_binder(binder);
        }
    }

    fn psk_selected_identity(&mut self, index: u16) {
        if let Self::ServerHello(c) = self {
            c.psk_selected_identity(index);
        }
    }

    fn new_session_ticket(
        &mut self,
        lifetime: u32,
        age_add: u32,
        nonce: &[u8],
        ticket: &[u8],
        max_early_data: u32,
    ) {
        if let Self::NewSessionTicket(c) = self {
            c.new_session_ticket(lifetime, age_add, nonce, ticket, max_early_data);
        }
    }

    fn extension(&mut self, _ext_type: u16, _data: &[u8]) {}

    fn certificate_request_context(&mut self, ctx: &[u8]) {
        if let Self::Certificate(c) = self {
            c.certificate_request_context(ctx);
        }
    }

    fn certificate_entry(&mut self, der: &[u8]) {
        if let Self::Certificate(c) = self {
            c.certificate_entry(der);
        }
    }

    fn certificate_verify(&mut self, scheme: u16, signature: &[u8]) {
        if let Self::CertificateVerify(c) = self {
            c.certificate_verify(scheme, signature);
        }
    }

    fn finished_verify_data(&mut self, data: &[u8]) {
        if let Self::Finished(c) = self {
            c.finished_verify_data(data);
        }
    }

    fn message_end(&mut self, _msg_type: HandshakeType, _wire: Bytes) {}

    fn parse_error(&mut self, detail: &'static str) {
        match self {
            Self::ClientHello(c) => c.parse_error(detail),
            Self::ServerHello(c) => c.parse_error(detail),
            Self::EncryptedExtensions(c) => c.parse_error(detail),
            Self::Certificate(c) => c.parse_error(detail),
            Self::CertificateVerify(c) => c.parse_error(detail),
            Self::Finished(c) => c.parse_error(detail),
            Self::NewSessionTicket(c) => c.parse_error(detail),
            Self::Idle => {}
        }
    }
}
