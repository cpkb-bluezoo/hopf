// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental TLS 1.3 handshake message parser (RFC 8446 §4) — Gumdrop codec shape.
//!
//! [`HandshakeParser::receive`] consumes every byte it is handed; incomplete
//! handshake messages stay buffered. When a full message is available the parser
//! fires semantic events for its body, then [`HandshakeEvents::message_end`]
//! with the complete on-wire encoding (type + 3-byte length + body).
//!
//! Parse progress and application callbacks are separate: this module only
//! tokenizes; the handshake engine (or a collector) implements [`HandshakeEvents`].

use bytes::{Bytes, BytesMut};

use super::messages::{ext, HandshakeType};

/// Semantic events emitted by [`HandshakeParser`].
///
/// Every `&[u8]` is valid only for the duration of the call.
pub trait HandshakeEvents {
    /// Whether the parser should stop popping further complete messages off
    /// its buffer — checked before each one, not just skipped at dispatch
    /// time. A handler that gates on external input mid-flight (e.g. a
    /// certificate-verification callback) must leave any messages that
    /// arrive after the gate untouched in the buffer, so a later resume can
    /// still see and process them — silently popping-and-discarding them
    /// here (as if handled) would lose them for good.
    fn should_stop(&self) -> bool {
        false
    }

    /// First event for each complete handshake message.
    fn message_begin(&mut self, msg_type: HandshakeType);

    /// Legacy record version (`ClientHello` / `ServerHello`).
    fn legacy_version(&mut self, version: u16) {
        let _ = version;
    }

    /// 32-byte client or server random.
    fn random(&mut self, value: &[u8; 32]) {
        let _ = value;
    }

    /// Session id bytes (empty when the length field is zero).
    fn session_id(&mut self, value: &[u8]) {
        let _ = value;
    }

    /// One cipher suite from the ClientHello list.
    fn cipher_suite_offered(&mut self, suite: u16) {
        let _ = suite;
    }

    /// Selected cipher suite (`ServerHello`).
    fn cipher_suite_selected(&mut self, suite: u16) {
        let _ = suite;
    }

    /// Legacy compression method byte.
    fn compression_method(&mut self, method: u8) {
        let _ = method;
    }

    /// Supported group in the SupportedGroups extension.
    fn supported_group(&mut self, group: u16) {
        let _ = group;
    }

    /// KeyShareEntry in ClientHello or ServerHello.
    fn key_share(&mut self, group: u16, share: &[u8]) {
        let _ = (group, share);
    }

    /// ALPN protocol name in an extension block.
    fn alpn_protocol(&mut self, proto: &[u8]) {
        let _ = proto;
    }

    /// SNI hostname (DNS host name only).
    fn server_name(&mut self, host: &str) {
        let _ = host;
    }

    /// QUIC transport parameters extension payload.
    fn transport_parameters(&mut self, params: &[u8]) {
        let _ = params;
    }

    /// Unrecognized or unused extension — opaque payload.
    fn extension(&mut self, ext_type: u16, data: &[u8]) {
        let _ = (ext_type, data);
    }

    /// Fired once, right after `random`, when a `ServerHello`-shaped message
    /// is actually a `HelloRetryRequest` (RFC 8446 §4.1.4) — `random`
    /// matched the fixed sentinel. `key_share`'s `share` argument for this
    /// message is empty (RFC 8446 §4.2.8's `KeyShareHelloRetryRequest`
    /// carries only a group, no key bytes).
    fn hello_retry_request(&mut self) {}

    /// Cookie extension (RFC 8446 §4.2.2) — in `HelloRetryRequest` (server)
    /// or echoed back in a followup `ClientHello` (client).
    fn cookie(&mut self, data: &[u8]) {
        let _ = data;
    }

    /// Client offered / server selected early data (empty payload in CH/EE).
    fn early_data(&mut self) {}

    /// ClientHello: offered PSK identity and binder.
    fn psk_identity(&mut self, identity: &[u8], obfuscated_ticket_age: u32) {
        let _ = (identity, obfuscated_ticket_age);
    }

    /// ClientHello: one PSK binder entry.
    fn psk_binder(&mut self, binder: &[u8]) {
        let _ = binder;
    }

    /// ServerHello: selected PSK identity index.
    fn psk_selected_identity(&mut self, index: u16) {
        let _ = index;
    }

    /// NewSessionTicket body fields (opaque ticket + early_data max).
    fn new_session_ticket(
        &mut self,
        lifetime: u32,
        age_add: u32,
        nonce: &[u8],
        ticket: &[u8],
        max_early_data: u32,
    ) {
        let _ = (lifetime, age_add, nonce, ticket, max_early_data);
    }

    /// TLS 1.3 Certificate request context.
    fn certificate_request_context(&mut self, ctx: &[u8]) {
        let _ = ctx;
    }

    /// One DER certificate (leaf-first order).
    fn certificate_entry(&mut self, der: &[u8]) {
        let _ = der;
    }

    /// CertificateVerify signature scheme and bytes.
    fn certificate_verify(&mut self, scheme: u16, signature: &[u8]) {
        let _ = (scheme, signature);
    }

    /// Finished verify_data.
    fn finished_verify_data(&mut self, data: &[u8]) {
        let _ = data;
    }

    /// `KeyUpdate`'s `KeyUpdateRequest` byte (RFC 8446 §4.6.3), post-handshake.
    fn key_update_request(&mut self, kind: u8) {
        let _ = kind;
    }

    /// Last event for each complete message; `wire` includes the 4-byte header.
    fn message_end(&mut self, msg_type: HandshakeType, wire: Bytes);

    /// Malformed input.
    fn parse_error(&mut self, detail: &'static str) {
        let _ = detail;
    }
}

/// Incremental TLS 1.3 handshake message parser (no record layer).
#[derive(Debug, Default)]
pub struct HandshakeParser {
    buf: BytesMut,
}

impl HandshakeParser {
    /// Empty parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes; advance `data` past consumed prefix. Returns bytes consumed.
    pub fn receive(&mut self, data: &mut &[u8], handler: &mut dyn HandshakeEvents) -> usize {
        let n = data.len();
        self.buf.extend_from_slice(data);
        *data = &[];
        self.drain_complete_messages(handler);
        n
    }

    /// End of input — error if a partial message remains. Only exercised by
    /// this crate's own tests today (production connection-close handling
    /// doesn't currently call it) — kept as real, general parser behavior
    /// rather than deleted, but `#[cfg(test)]` reflects actual usage
    /// honestly instead of a blanket `#[allow(dead_code)]`.
    #[cfg(test)]
    pub(crate) fn close(&mut self, handler: &mut dyn HandshakeEvents) {
        if !self.buf.is_empty() {
            handler.parse_error("incomplete handshake message at close");
        }
    }

    fn drain_complete_messages(&mut self, handler: &mut dyn HandshakeEvents) {
        loop {
            if handler.should_stop() {
                break;
            }
            if self.buf.len() < 4 {
                break;
            }
            let msg_type = match HandshakeType::from_u8(self.buf[0]) {
                Some(t) => t,
                None => {
                    handler.parse_error("unknown handshake message type");
                    self.buf.clear();
                    break;
                }
            };
            let len = u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
            let total = 4 + len;
            if self.buf.len() < total {
                break;
            }
            let wire = self.buf.split_to(total).freeze();
            let body = &wire[4..];
            handler.message_begin(msg_type);
            if !decode_message_body(msg_type, body, handler) {
                break;
            }
            handler.message_end(msg_type, wire);
        }
    }
}

fn decode_message_body(msg_type: HandshakeType, body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    match msg_type {
        HandshakeType::ClientHello => decode_client_hello(body, handler),
        HandshakeType::ServerHello => decode_server_hello(body, handler),
        HandshakeType::NewSessionTicket => decode_new_session_ticket(body, handler),
        HandshakeType::EncryptedExtensions => decode_encrypted_extensions(body, handler),
        HandshakeType::CertificateRequest => decode_certificate_request(body, handler),
        HandshakeType::Certificate => decode_certificate(body, handler),
        HandshakeType::CertificateVerify => decode_certificate_verify(body, handler),
        HandshakeType::Finished => decode_finished(body, handler),
        HandshakeType::KeyUpdate => decode_key_update(body, handler),
    }
}

fn decode_client_hello(body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    if body.len() < 2 + 32 + 1 + 2 + 1 + 2 {
        handler.parse_error("ClientHello too short");
        return false;
    }
    let mut i = 0;
    let legacy_version = u16::from_be_bytes([body[i], body[i + 1]]);
    handler.legacy_version(legacy_version);
    i += 2;
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[i..i + 32]);
    handler.random(&random);
    i += 32;
    let sid_len = body[i] as usize;
    i += 1;
    if body.len() < i + sid_len + 2 + 1 + 2 {
        handler.parse_error("ClientHello truncated at session id");
        return false;
    }
    handler.session_id(&body[i..i + sid_len]);
    i += sid_len;
    // DTLS's ClientHello has one more fixed-position field here TLS's
    // doesn't — see the matching comment in `build_client_hello_inner`.
    if legacy_version == 0xfefd {
        if body.len() < i + 1 {
            handler.parse_error("ClientHello truncated at cookie");
            return false;
        }
        let cookie_len = body[i] as usize;
        i += 1;
        if body.len() < i + cookie_len + 2 + 1 + 2 {
            handler.parse_error("ClientHello truncated at cookie");
            return false;
        }
        i += cookie_len;
    }
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + cs_len + 1 + 2 {
        handler.parse_error("ClientHello truncated at cipher suites");
        return false;
    }
    let mut j = i;
    while j + 2 <= i + cs_len {
        handler.cipher_suite_offered(u16::from_be_bytes([body[j], body[j + 1]]));
        j += 2;
    }
    i += cs_len;
    let comp_len = body[i] as usize;
    i += 1;
    if body.len() < i + comp_len + 2 {
        handler.parse_error("ClientHello truncated at compression");
        return false;
    }
    if comp_len > 0 {
        handler.compression_method(body[i]);
    }
    i += comp_len;
    let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + ext_len {
        handler.parse_error("ClientHello truncated at extensions");
        return false;
    }
    decode_extensions(&body[i..i + ext_len], handler);
    true
}

fn decode_server_hello(body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    if body.len() < 2 + 32 + 1 + 2 + 1 + 2 {
        handler.parse_error("ServerHello too short");
        return false;
    }
    let mut i = 0;
    handler.legacy_version(u16::from_be_bytes([body[i], body[i + 1]]));
    i += 2;
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[i..i + 32]);
    handler.random(&random);
    let is_hrr = random == super::messages::HELLO_RETRY_REQUEST_RANDOM;
    if is_hrr {
        handler.hello_retry_request();
    }
    i += 32;
    let sid_len = body[i] as usize;
    i += 1;
    if body.len() < i + sid_len + 2 + 1 + 2 {
        handler.parse_error("ServerHello truncated at session id");
        return false;
    }
    handler.session_id(&body[i..i + sid_len]);
    i += sid_len;
    handler.cipher_suite_selected(u16::from_be_bytes([body[i], body[i + 1]]));
    i += 2;
    handler.compression_method(body[i]);
    i += 1;
    let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + ext_len {
        handler.parse_error("ServerHello truncated at extensions");
        return false;
    }
    if is_hrr {
        decode_extension_block(&body[i..i + ext_len], handler, KeyShareExtMode::HelloRetryRequest);
    } else {
        decode_server_hello_extensions(&body[i..i + ext_len], handler);
    }
    true
}

fn decode_encrypted_extensions(body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    if body.len() < 2 {
        handler.parse_error("EncryptedExtensions too short");
        return false;
    }
    let ext_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + ext_len {
        handler.parse_error("EncryptedExtensions truncated");
        return false;
    }
    decode_extensions(&body[2..2 + ext_len], handler);
    true
}

fn decode_certificate_request(body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    if body.is_empty() {
        handler.parse_error("CertificateRequest empty");
        return false;
    }
    let ctx_len = body[0] as usize;
    if body.len() < 1 + ctx_len + 2 {
        handler.parse_error("CertificateRequest truncated at context");
        return false;
    }
    handler.certificate_request_context(&body[1..1 + ctx_len]);
    let mut i = 1 + ctx_len;
    let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + ext_len {
        handler.parse_error("CertificateRequest truncated at extensions");
        return false;
    }
    decode_extensions(&body[i..i + ext_len], handler);
    true
}

fn decode_certificate(body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    if body.is_empty() {
        handler.parse_error("Certificate empty");
        return false;
    }
    let ctx_len = body[0] as usize;
    if body.len() < 1 + ctx_len + 3 {
        handler.parse_error("Certificate truncated at context");
        return false;
    }
    handler.certificate_request_context(&body[1..1 + ctx_len]);
    let mut i = 1 + ctx_len;
    let list_len = u32::from_be_bytes([0, body[i], body[i + 1], body[i + 2]]) as usize;
    i += 3;
    if body.len() < i + list_len {
        handler.parse_error("Certificate truncated at list");
        return false;
    }
    // An empty list is valid on the wire (RFC 8446 §4.4.2: a client with no
    // certificate to present responds with a `Certificate` containing no
    // entries) — whether that's acceptable is a caller/policy decision
    // (see `HandshakeEngine::on_certificate` / `on_client_certificate`),
    // not something this codec should reject outright.
    let list = &body[i..i + list_len];
    let mut j = 0;
    while j + 3 <= list.len() {
        let clen = u32::from_be_bytes([0, list[j], list[j + 1], list[j + 2]]) as usize;
        j += 3;
        if j + clen + 2 > list.len() {
            handler.parse_error("Certificate entry truncated");
            return false;
        }
        handler.certificate_entry(&list[j..j + clen]);
        j += clen;
        let ext_len = u16::from_be_bytes([list[j], list[j + 1]]) as usize;
        j += 2 + ext_len;
    }
    true
}

fn decode_certificate_verify(body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    if body.len() < 4 {
        handler.parse_error("CertificateVerify too short");
        return false;
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < 4 + sig_len {
        handler.parse_error("CertificateVerify truncated");
        return false;
    }
    handler.certificate_verify(scheme, &body[4..4 + sig_len]);
    true
}

fn decode_finished(body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    if body.len() != 32 {
        handler.parse_error("Finished verify_data length");
        return false;
    }
    handler.finished_verify_data(body);
    true
}

fn decode_key_update(body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    if body.len() != 1 {
        handler.parse_error("KeyUpdate body must be exactly one byte");
        return false;
    }
    handler.key_update_request(body[0]);
    true
}

fn decode_new_session_ticket(body: &[u8], handler: &mut dyn HandshakeEvents) -> bool {
    if body.len() < 4 + 4 + 1 + 2 {
        handler.parse_error("NewSessionTicket too short");
        return false;
    }
    let mut i = 0;
    let lifetime = u32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
    i += 4;
    let age_add = u32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
    i += 4;
    let nonce_len = body[i] as usize;
    i += 1;
    if body.len() < i + nonce_len + 2 {
        handler.parse_error("NewSessionTicket truncated nonce");
        return false;
    }
    let nonce = &body[i..i + nonce_len];
    i += nonce_len;
    let ticket_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + ticket_len + 2 {
        handler.parse_error("NewSessionTicket truncated ticket");
        return false;
    }
    let ticket = &body[i..i + ticket_len];
    i += ticket_len;
    let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + ext_len {
        handler.parse_error("NewSessionTicket truncated extensions");
        return false;
    }
    let mut max_early = 0u32;
    let exts = &body[i..i + ext_len];
    let mut j = 0;
    while j + 4 <= exts.len() {
        let et = u16::from_be_bytes([exts[j], exts[j + 1]]);
        let el = u16::from_be_bytes([exts[j + 2], exts[j + 3]]) as usize;
        j += 4;
        if j + el > exts.len() {
            break;
        }
        if et == ext::EARLY_DATA && el == 4 {
            max_early = u32::from_be_bytes([exts[j], exts[j + 1], exts[j + 2], exts[j + 3]]);
        }
        j += el;
    }
    handler.new_session_ticket(lifetime, age_add, nonce, ticket, max_early);
    true
}

fn decode_extensions(extensions: &[u8], handler: &mut dyn HandshakeEvents) {
    decode_extension_block(extensions, handler, KeyShareExtMode::ClientHelloList);
}

/// ServerHello KeyShare carries one entry (RFC 8446 §4.2.8), not a length-prefixed list.
fn decode_server_hello_extensions(extensions: &[u8], handler: &mut dyn HandshakeEvents) {
    decode_extension_block(extensions, handler, KeyShareExtMode::ServerHelloSingle);
}

enum KeyShareExtMode {
    ClientHelloList,
    ServerHelloSingle,
    /// `HelloRetryRequest`'s `key_share` extension carries only a
    /// `NamedGroup` — no length-prefixed key bytes (RFC 8446 §4.2.8).
    HelloRetryRequest,
}

fn decode_extension_block(
    extensions: &[u8],
    handler: &mut dyn HandshakeEvents,
    key_share_mode: KeyShareExtMode,
) {
    let mut ext_i = 0;
    while ext_i + 4 <= extensions.len() {
        let etype = u16::from_be_bytes([extensions[ext_i], extensions[ext_i + 1]]);
        let elen = u16::from_be_bytes([extensions[ext_i + 2], extensions[ext_i + 3]]) as usize;
        ext_i += 4;
        if ext_i + elen > extensions.len() {
            break;
        }
        let edata = &extensions[ext_i..ext_i + elen];
        match etype {
            ext::SUPPORTED_GROUPS => decode_supported_groups(edata, handler),
            ext::KEY_SHARE => match key_share_mode {
                KeyShareExtMode::ClientHelloList => decode_key_share_extension(edata, handler),
                KeyShareExtMode::ServerHelloSingle => decode_server_key_share_extension(edata, handler),
                KeyShareExtMode::HelloRetryRequest => decode_hello_retry_request_key_share(edata, handler),
            },
            ext::ALPN => decode_alpn_extension(edata, handler),
            ext::SERVER_NAME => {
                if let Some(host) = parse_sni_host(edata) {
                    handler.server_name(&host);
                }
            }
            ext::QUIC_TRANSPORT_PARAMETERS => handler.transport_parameters(edata),
            ext::EARLY_DATA => handler.early_data(),
            ext::COOKIE => handler.cookie(edata),
            ext::PRE_SHARED_KEY => match key_share_mode {
                KeyShareExtMode::ClientHelloList => decode_psk_client(edata, handler),
                KeyShareExtMode::ServerHelloSingle | KeyShareExtMode::HelloRetryRequest => {
                    if edata.len() == 2 {
                        handler.psk_selected_identity(u16::from_be_bytes([edata[0], edata[1]]));
                    }
                }
            },
            ext::PSK_KEY_EXCHANGE_MODES => { /* accepted; no state needed beyond presence via PSK */ }
            _ => handler.extension(etype, edata),
        }
        ext_i += elen;
    }
}

fn decode_supported_groups(data: &[u8], handler: &mut dyn HandshakeEvents) {
    if data.len() < 2 {
        return;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut i = 2;
    while i + 2 <= 2 + list_len && i + 2 <= data.len() {
        handler.supported_group(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
}

fn decode_key_share_extension(data: &[u8], handler: &mut dyn HandshakeEvents) {
    if data.len() < 2 {
        return;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return;
    }
    let mut i = 2;
    while i + 4 <= 2 + list_len {
        let group = u16::from_be_bytes([data[i], data[i + 1]]);
        let klen = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;
        if i + klen > 2 + list_len {
            break;
        }
        handler.key_share(group, &data[i..i + klen]);
        i += klen;
    }
}

fn decode_server_key_share_extension(data: &[u8], handler: &mut dyn HandshakeEvents) {
    if data.len() < 4 {
        return;
    }
    let group = u16::from_be_bytes([data[0], data[1]]);
    let klen = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + klen {
        return;
    }
    handler.key_share(group, &data[4..4 + klen]);
}

/// `HelloRetryRequest`'s `key_share` extension is just a 2-byte `NamedGroup`
/// (RFC 8446 §4.2.8's `KeyShareHelloRetryRequest`) — no key bytes.
fn decode_hello_retry_request_key_share(data: &[u8], handler: &mut dyn HandshakeEvents) {
    if data.len() != 2 {
        return;
    }
    let group = u16::from_be_bytes([data[0], data[1]]);
    handler.key_share(group, &[]);
}

/// ALPN extension_data (RFC 7301 §3.1): 2-byte `ProtocolNameList` length,
/// then each protocol name as a 1-byte length + bytes.
fn decode_alpn_extension(data: &[u8], handler: &mut dyn HandshakeEvents) {
    if data.len() < 2 {
        return;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = &data[2..data.len().min(2 + list_len)];
    let mut i = 0;
    while i < list.len() {
        let len = list[i] as usize;
        i += 1;
        if i + len > list.len() {
            break;
        }
        handler.alpn_protocol(&list[i..i + len]);
        i += len;
    }
}

fn parse_sni_host(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }
    let mut i = 2;
    while i + 3 <= 2 + list_len {
        let name_type = data[i];
        let name_len = u16::from_be_bytes([data[i + 1], data[i + 2]]) as usize;
        i += 3;
        if name_type == 0 && i + name_len <= 2 + list_len {
            return std::str::from_utf8(&data[i..i + name_len])
                .ok()
                .map(str::to_string);
        }
        i += name_len;
    }
    None
}

fn decode_psk_client(data: &[u8], handler: &mut dyn HandshakeEvents) {
    if data.len() < 2 {
        return;
    }
    let id_list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut i = 2;
    if data.len() < 2 + id_list_len + 2 {
        return;
    }
    let id_end = 2 + id_list_len;
    while i + 2 <= id_end {
        let id_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
        i += 2;
        if i + id_len + 4 > id_end {
            return;
        }
        let identity = &data[i..i + id_len];
        i += id_len;
        let age = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        i += 4;
        handler.psk_identity(identity, age);
    }
    i = id_end;
    let binders_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2;
    let binders_end = i + binders_len;
    if binders_end > data.len() {
        return;
    }
    while i < binders_end {
        let blen = data[i] as usize;
        i += 1;
        if i + blen > binders_end {
            return;
        }
        handler.psk_binder(&data[i..i + blen]);
        i += blen;
    }
}

impl HandshakeType {
    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(HandshakeType::ClientHello),
            2 => Some(HandshakeType::ServerHello),
            4 => Some(HandshakeType::NewSessionTicket),
            8 => Some(HandshakeType::EncryptedExtensions),
            11 => Some(HandshakeType::Certificate),
            13 => Some(HandshakeType::CertificateRequest),
            15 => Some(HandshakeType::CertificateVerify),
            20 => Some(HandshakeType::Finished),
            24 => Some(HandshakeType::KeyUpdate),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::handshake::messages::{build_client_hello, build_server_hello_ext, ClientHelloParams, HandshakeMessage, KeyShareEntry};

    #[derive(Default)]
    struct RecordingHandler {
        events: Vec<String>,
        error: bool,
    }

    fn wire_handshake_type(msg_type: HandshakeType) -> u8 {
        msg_type as u8
    }

    impl HandshakeEvents for RecordingHandler {
        fn message_begin(&mut self, msg_type: HandshakeType) {
            self.events
                .push(format!("begin:{}", wire_handshake_type(msg_type)));
        }
        fn random(&mut self, value: &[u8; 32]) {
            self.events.push(format!("random:{}", value[0]));
        }
        fn key_share(&mut self, group: u16, share: &[u8]) {
            self.events
                .push(format!("key_share:0x{group:04x}:{}", share.len()));
        }
        fn key_update_request(&mut self, kind: u8) {
            self.events.push(format!("key_update_request:{kind}"));
        }
        fn message_end(&mut self, msg_type: HandshakeType, wire: Bytes) {
            self.events.push(format!(
                "end:{}:{}b",
                wire_handshake_type(msg_type),
                wire.len()
            ));
        }
        fn parse_error(&mut self, detail: &'static str) {
            self.error = true;
            self.events.push(format!("error:{detail}"));
        }
    }

    #[test]
    fn incremental_receive_across_chunk_boundary() {
        use crate::crypto::kx::{EphemeralKeyPair, NamedGroup};
        let kp = EphemeralKeyPair::generate().unwrap();
        let hello = build_client_hello(&ClientHelloParams {
            random: [7u8; 32],
            cipher_suites: vec![0x1301],
            key_share: KeyShareEntry {
                group: NamedGroup::X25519.code(),
                share: Bytes::copy_from_slice(&kp.public_key()),
            },
            supported_groups: vec![NamedGroup::X25519.code()],
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: Some("localhost".into()),
            transport_parameters: None,
            early_data: false,
            psk: None,
            cookie: None,
            legacy_version: 0x0303,
        });
        let wire = hello.encode();
        let split = wire.len() / 2;

        let mut parser = HandshakeParser::new();
        let mut handler = RecordingHandler::default();
        let mut first = &wire[..split];
        parser.receive(&mut first, &mut handler);
        assert!(handler.events.is_empty(), "unexpected events during first chunk");

        let mut second = &wire[split..];
        parser.receive(&mut second, &mut handler);
        parser.close(&mut handler);

        assert!(!handler.error);
        assert!(handler.events.iter().any(|e| e.starts_with("begin:")));
        assert!(handler.events.iter().any(|e| e.starts_with("end:")));
    }

    #[test]
    fn key_update_round_trips_both_kind_values() {
        use crate::tls::handshake::messages::{build_key_update, key_update_request};
        for kind in [key_update_request::NOT_REQUESTED, key_update_request::REQUESTED] {
            let wire = build_key_update(kind).encode();
            let mut parser = HandshakeParser::new();
            let mut handler = RecordingHandler::default();
            let mut input = &wire[..];
            parser.receive(&mut input, &mut handler);
            assert!(!handler.error, "parser error during key_update roundtrip");
            assert!(
                handler.events.iter().any(|e| e == &format!("key_update_request:{kind}")),
                "missing key_update_request event"
            );
        }
    }

    #[test]
    fn key_update_with_wrong_body_length_is_a_parse_error() {
        use crate::tls::handshake::messages::HandshakeType as HT;
        let mut body = BytesMut::new();
        body.extend_from_slice(&[HT::KeyUpdate as u8]);
        body.extend_from_slice(&[0, 0, 2]); // length = 2, wrong (must be 1)
        body.extend_from_slice(&[0, 0]);
        let mut parser = HandshakeParser::new();
        let mut handler = RecordingHandler::default();
        let mut input = &body[..];
        parser.receive(&mut input, &mut handler);
        assert!(handler.error, "expected parse error for malformed key_update");
    }

    #[test]
    fn server_hello_key_share_single_entry() {
        use crate::crypto::kx::NamedGroup;
        let share = [42u8; 32];
        let hello = build_server_hello_ext(&[9u8; 32], &[], 0x1301, NamedGroup::X25519.code(), &share, None, 0x0303);
        let wire = hello.encode();

        let mut parser = HandshakeParser::new();
        let mut handler = RecordingHandler::default();
        let mut input = wire.as_ref();
        parser.receive(&mut input, &mut handler);
        parser.close(&mut handler);

        assert!(!handler.error, "parser error during server_hello parse");
        assert!(handler
            .events
            .iter()
            .any(|e| e == "key_share:0x001d:32"));
    }

    #[test]
    fn close_with_partial_message_errors() {
        let mut parser = HandshakeParser::new();
        let mut handler = RecordingHandler::default();
        let mut partial = &[1u8, 0, 0][..];
        parser.receive(&mut partial, &mut handler);
        parser.close(&mut handler);
        assert!(handler.error);
    }

    #[test]
    fn roundtrip_message_framing_via_parser() {
        let msg = HandshakeMessage {
            msg_type: HandshakeType::Finished,
            body: Bytes::from([0u8; 32].to_vec()),
        };
        let wire = msg.encode();
        let mut parser = HandshakeParser::new();
        let mut handler = RecordingHandler::default();
        let mut data = wire.as_ref();
        parser.receive(&mut data, &mut handler);
        parser.close(&mut handler);
        assert!(!handler.error);
        assert_eq!(handler.events.len(), 2);
    }
}
