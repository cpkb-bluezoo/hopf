// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 record layer (RFC 8446 §5) — wraps [`HandshakeEngine`] with
//! record framing and AEAD for TCP TLS / STARTTLS. Sink-based like every
//! other engine in this crate: [`TlsRecordEngine::feed_ciphertext`] /
//! [`TlsRecordEngine::send_application_data`] go in, [`TlsRecordSink`]
//! events come out. No record layer exists for QUIC (RFC 9001 §4 — packet
//! protection replaces it); this module is TCP/DTLS-family only.

use crate::crypto::aead::{AeadError, Aes128GcmKey, ChaCha20Poly1305Key};
use crate::crypto::hkdf::expand_label;
use crate::security::SecurityInfo;

use super::engine::{HandshakeConfig, HandshakeEngine, HandshakeMode, HandshakeRole, Tls13Aead};
use super::sink::{
    AlertDescription, KeyUpdateDirection, QuicSecrets, TlsEventSink, TlsProtocolError, TlsTimerKind, VerifyRequest,
    VerifyResult,
};

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;

const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_LEVEL_FATAL: u8 = 2;
const ALERT_CLOSE_NOTIFY: u8 = 0;

/// RFC 8446 §5.1: plaintext fragments are capped at 2^14 bytes; we fragment
/// outgoing handshake messages (e.g. a large `Certificate` chain) to this
/// size rather than assume every message fits one record.
const MAX_FRAGMENT: usize = 16384;
/// RFC 8446 §5.2: ciphertext records may be up to 2^14 + 256 bytes — allow
/// that much on read even though we never write padding ourselves.
const MAX_CIPHERTEXT_RECORD: usize = MAX_FRAGMENT + 256;

/// RFC 8446 §5.5 / RFC 9325 §4.4: an AES-GCM key SHOULD be retired after
/// protecting 2^24.5 (≈23,726,566) full-size records — this is the point
/// where the AEAD's own authenticated-encryption security margin starts
/// to erode, well before the `u64` sequence number could ever wrap.
/// ChaCha20-Poly1305 has no analogous limit here: RFC 8446 §5.5 notes its
/// 64-bit sequence number would wrap before that cipher's own safety
/// bound is reached, so only the AES-GCM directions are checked below.
const AES_GCM_CONFIDENTIALITY_LIMIT: u64 = 23_726_566;

/// Events emitted by [`TlsRecordEngine`] — consumed by `TcpConnection`.
pub trait TlsRecordSink {
    /// TLS record bytes to write to the socket.
    fn ciphertext_ready(&mut self, data: &[u8]);

    /// Decrypted application data (post-handshake `ApplicationData` records).
    fn application_data(&mut self, plaintext: &[u8]);

    /// Handshake finished; `send_application_data` is now usable.
    fn handshake_complete(&mut self, info: SecurityInfo);

    /// Chain verification should run (possibly on `StorageExecutor`).
    fn verification_requested(&mut self, req: VerifyRequest);

    /// Non-fatal protocol failure (bad record, decrypt failure, fatal alert, …).
    fn protocol_error(&mut self, err: TlsProtocolError);

    /// Peer sent `close_notify`.
    fn peer_closed(&mut self);
}

/// No-op sink for tests.
#[derive(Debug, Default)]
pub struct NopTlsRecordSink;

impl TlsRecordSink for NopTlsRecordSink {
    fn ciphertext_ready(&mut self, _data: &[u8]) {}
    fn application_data(&mut self, _plaintext: &[u8]) {}
    fn handshake_complete(&mut self, _info: SecurityInfo) {}
    fn verification_requested(&mut self, _req: VerifyRequest) {}
    fn protocol_error(&mut self, _err: TlsProtocolError) {}
    fn peer_closed(&mut self) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Epoch {
    Plaintext,
    Handshake,
    Application,
}

/// One direction's AEAD key. RFC 8446's AEADs (unlike TLS 1.2's GCM suites)
/// all share the same nonce construction — IV XOR sequence number, no
/// explicit per-record nonce on the wire — so only the key type varies
/// between suites, not the framing.
enum AeadKeyKind {
    Aes128Gcm(Aes128GcmKey),
    ChaCha20Poly1305(ChaCha20Poly1305Key),
}

/// One direction's AEAD key + IV + sequence number (RFC 8446 §5.3).
struct DirectionalKeys {
    key: AeadKeyKind,
    iv: [u8; 12],
    seq: u64,
}

impl DirectionalKeys {
    fn from_secret(aead: Tls13Aead, secret: &[u8; 32]) -> Self {
        let key_bytes = expand_label(secret, "key", &[], aead.key_len());
        let iv_bytes = expand_label(secret, "iv", &[], 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(iv_bytes.as_ref());
        let key = match aead {
            Tls13Aead::Aes128GcmSha256 => {
                AeadKeyKind::Aes128Gcm(Aes128GcmKey::new(key_bytes.as_ref()).expect("16-byte AES-128 key"))
            }
            Tls13Aead::ChaCha20Poly1305Sha256 => AeadKeyKind::ChaCha20Poly1305(
                ChaCha20Poly1305Key::new(key_bytes.as_ref()).expect("32-byte ChaCha20-Poly1305 key"),
            ),
        };
        Self { key, iv, seq: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= seq_bytes[i];
        }
        n
    }

    fn advance(&mut self) {
        self.seq = self.seq.wrapping_add(1);
    }

    /// Whether this direction has protected enough records under its
    /// current AES-GCM key to warrant retiring it (RFC 8446 §5.5).
    fn over_confidentiality_limit(&self) -> bool {
        matches!(self.key, AeadKeyKind::Aes128Gcm(_)) && self.seq >= AES_GCM_CONFIDENTIALITY_LIMIT
    }

    fn seal_in_place_append_tag(&self, nonce: [u8; 12], aad: &[u8], plaintext: &mut Vec<u8>) -> Result<(), AeadError> {
        match &self.key {
            AeadKeyKind::Aes128Gcm(k) => k.seal_in_place_append_tag(nonce, aad, plaintext),
            AeadKeyKind::ChaCha20Poly1305(k) => k.seal_in_place_append_tag(nonce, aad, plaintext),
        }
    }

    fn open_in_place(&self, nonce: [u8; 12], aad: &[u8], ciphertext: &mut [u8]) -> Result<usize, AeadError> {
        match &self.key {
            AeadKeyKind::Aes128Gcm(k) => k.open_in_place(nonce, aad, ciphertext),
            AeadKeyKind::ChaCha20Poly1305(k) => k.open_in_place(nonce, aad, ciphertext),
        }
    }
}

struct RecordState {
    role: HandshakeRole,
    epoch: Epoch,
    write: Option<DirectionalKeys>,
    read: Option<DirectionalKeys>,
    /// Application traffic keys staged at `application_traffic_keys_ready`,
    /// installed only once `handshake_complete` actually flips the epoch —
    /// the client's own Finished must still go out under Handshake keys.
    next_write: Option<DirectionalKeys>,
    next_read: Option<DirectionalKeys>,
    /// Set once we've asked the peer to rotate their write key because
    /// our read-side confidentiality limit was reached; cleared when
    /// their `KeyUpdate` actually arrives and installs a fresh read key.
    /// Guards against re-requesting on every subsequent record while
    /// we're still waiting for them to respond.
    read_update_requested: bool,
    /// Set once a fatal alert has gone out (or a peer's own fatal/close
    /// alert has been relayed without a reply) — guards against sending a
    /// second one, and against replying to a peer's alert with one of our
    /// own (RFC 8446 §6.1/§6.2 don't call for acknowledging an alert).
    alert_sent: bool,
}

impl RecordState {
    fn new(role: HandshakeRole) -> Self {
        Self {
            role,
            epoch: Epoch::Plaintext,
            write: None,
            read: None,
            next_write: None,
            next_read: None,
            read_update_requested: false,
            alert_sent: false,
        }
    }

    fn install_handshake_keys(&mut self, aead: Tls13Aead, client: [u8; 32], server: [u8; 32]) {
        let (w, r) = match self.role {
            HandshakeRole::Client => (client, server),
            HandshakeRole::Server => (server, client),
        };
        self.write = Some(DirectionalKeys::from_secret(aead, &w));
        self.read = Some(DirectionalKeys::from_secret(aead, &r));
        self.epoch = Epoch::Handshake;
    }

    fn stage_application_keys(&mut self, aead: Tls13Aead, client: [u8; 32], server: [u8; 32]) {
        let (w, r) = match self.role {
            HandshakeRole::Client => (client, server),
            HandshakeRole::Server => (server, client),
        };
        self.next_write = Some(DirectionalKeys::from_secret(aead, &w));
        self.next_read = Some(DirectionalKeys::from_secret(aead, &r));
    }

    fn activate_application_keys(&mut self) {
        if let (Some(w), Some(r)) = (self.next_write.take(), self.next_read.take()) {
            self.write = Some(w);
            self.read = Some(r);
            self.epoch = Epoch::Application;
        }
    }

    /// `KeyUpdate` (RFC 8446 §4.6.3/§7.2) ratcheted our own write secret —
    /// swap in immediately (unlike the handshake→application transition,
    /// no staging is needed: by the time this is called, anything needing
    /// the old key has already been encrypted and handed off).
    fn update_write_key(&mut self, aead: Tls13Aead, secret: &[u8; 32]) {
        self.write = Some(DirectionalKeys::from_secret(aead, secret));
    }

    /// The peer's `KeyUpdate` ratcheted their write secret — swap our
    /// matching read key in immediately.
    fn update_read_key(&mut self, aead: Tls13Aead, secret: &[u8; 32]) {
        self.read = Some(DirectionalKeys::from_secret(aead, secret));
        self.read_update_requested = false;
    }

    fn write_over_confidentiality_limit(&self) -> bool {
        self.write.as_ref().is_some_and(DirectionalKeys::over_confidentiality_limit)
    }

    fn read_over_confidentiality_limit(&self) -> bool {
        self.read.as_ref().is_some_and(DirectionalKeys::over_confidentiality_limit)
    }
}

fn write_plaintext_record(content_type: u8, payload: &[u8], out: &mut Vec<u8>) {
    let len = payload.len() as u16;
    out.extend_from_slice(&[content_type, 0x03, 0x03]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
}

fn write_encrypted_record(write: &mut DirectionalKeys, inner_type: u8, payload: &[u8], out: &mut Vec<u8>) {
    let mut plain = Vec::with_capacity(payload.len() + 1);
    plain.extend_from_slice(payload);
    plain.push(inner_type);
    let cipher_len = (plain.len() + 16) as u16;
    let header = [
        CONTENT_APPLICATION_DATA,
        0x03,
        0x03,
        (cipher_len >> 8) as u8,
        cipher_len as u8,
    ];
    let nonce = write.nonce();
    write
        .seal_in_place_append_tag(nonce, &header, &mut plain)
        .expect("seal with a freshly derived key never fails");
    write.advance();
    out.extend_from_slice(&header);
    out.extend_from_slice(&plain);
}

fn write_fragmented<S: TlsRecordSink + ?Sized>(state: &mut RecordState, content_type: u8, data: &[u8], sink: &mut S) {
    let mut out = Vec::new();
    for chunk in if data.is_empty() { vec![&data[..]] } else { data.chunks(MAX_FRAGMENT).collect() } {
        match state.epoch {
            Epoch::Plaintext => write_plaintext_record(content_type, chunk, &mut out),
            Epoch::Handshake | Epoch::Application => {
                let write = state
                    .write
                    .as_mut()
                    .expect("write keys installed once epoch leaves Plaintext");
                write_encrypted_record(write, content_type, chunk, &mut out);
            }
        }
    }
    if !out.is_empty() {
        sink.ciphertext_ready(&out);
    }
}

/// Send a fatal alert for a violation *this side* detected (RFC 8446
/// §6.2) — at most once per connection (see [`RecordState::alert_sent`]),
/// since after the first fatal alert the connection is already going down.
fn send_fatal_alert<S: TlsRecordSink + ?Sized>(state: &mut RecordState, alert: AlertDescription, sink: &mut S) {
    if state.alert_sent {
        return;
    }
    state.alert_sent = true;
    write_fragmented(state, CONTENT_ALERT, &[ALERT_LEVEL_FATAL, alert.code()], sink);
}

/// Bridges [`HandshakeEngine`]'s handshake-message events onto record framing.
struct InnerSink<'a, S: TlsRecordSink + ?Sized> {
    state: &'a mut RecordState,
    outer: &'a mut S,
}

impl<S: TlsRecordSink + ?Sized> TlsEventSink for InnerSink<'_, S> {
    fn handshake_data_ready(&mut self, data: &[u8]) {
        write_fragmented(self.state, CONTENT_HANDSHAKE, data, self.outer);
    }

    fn handshake_complete(&mut self, info: SecurityInfo, _quic_secrets: Option<QuicSecrets>) {
        self.state.activate_application_keys();
        self.outer.handshake_complete(info);
    }

    fn verification_requested(&mut self, req: VerifyRequest) {
        self.outer.verification_requested(req);
    }

    fn quic_handshake_keys_ready(&mut self, aead: Tls13Aead, client: [u8; 32], server: [u8; 32]) {
        self.state.install_handshake_keys(aead, client, server);
    }

    fn application_traffic_keys_ready(&mut self, aead: Tls13Aead, client: [u8; 32], server: [u8; 32]) {
        self.state.stage_application_keys(aead, client, server);
    }

    fn application_traffic_key_updated(&mut self, aead: Tls13Aead, direction: KeyUpdateDirection, secret: [u8; 32]) {
        match direction {
            KeyUpdateDirection::Write => self.state.update_write_key(aead, &secret),
            KeyUpdateDirection::Read => self.state.update_read_key(aead, &secret),
        }
    }

    fn protocol_error(&mut self, err: TlsProtocolError) {
        send_fatal_alert(self.state, err.alert, self.outer);
        self.outer.protocol_error(err);
    }

    fn timeout(&mut self, _kind: TlsTimerKind) {}

    fn peer_closed(&mut self) {
        self.outer.peer_closed();
    }
}

/// Reactive TLS 1.3 record layer for TCP — wraps [`HandshakeEngine`] in
/// [`HandshakeMode::TcpRecordLayer`] with record framing and AEAD.
pub struct TlsRecordEngine {
    engine: HandshakeEngine,
    state: RecordState,
    inbound: Vec<u8>,
    failed: bool,
}

impl TlsRecordEngine {
    /// Create the engine; `config.mode` is forced to [`HandshakeMode::TcpRecordLayer`].
    pub fn new(mut config: HandshakeConfig) -> Self {
        config.mode = HandshakeMode::TcpRecordLayer;
        let role = config.role;
        Self {
            engine: HandshakeEngine::new(config),
            state: RecordState::new(role),
            inbound: Vec::new(),
            failed: false,
        }
    }

    /// Begin the handshake — client emits `ClientHello`; server waits for input.
    pub fn start<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        let mut inner = InnerSink {
            state: &mut self.state,
            outer: sink,
        };
        self.engine.start(&mut inner);
    }

    /// Whether the handshake has completed.
    pub fn is_complete(&self) -> bool {
        self.engine.is_complete()
    }

    /// Consume raw bytes off the TCP stream — any number of complete or
    /// partial records. Buffers a trailing partial record for the next call.
    pub fn feed_ciphertext<S: TlsRecordSink + ?Sized>(&mut self, input: &mut &[u8], sink: &mut S) {
        self.inbound.extend_from_slice(input);
        *input = &[];
        if self.failed {
            self.inbound.clear();
            return;
        }
        loop {
            match self.take_one_record() {
                Ok(None) => break,
                Ok(Some((content_type, payload))) => {
                    // RFC 8446 §5.5 / RFC 9325 §4.4: our read key has
                    // protected close to its AES-GCM confidentiality
                    // limit's worth of records — ask the peer to rotate
                    // theirs (which also rotates our own write key as a
                    // side effect). `read_update_requested` stops this
                    // from firing again on every subsequent record while
                    // we wait for their reply.
                    if !self.state.read_update_requested && self.state.read_over_confidentiality_limit() {
                        self.state.read_update_requested = true;
                        self.request_key_update(sink, true);
                    }
                    if !self.dispatch_record(content_type, payload, sink) {
                        break;
                    }
                }
                Err(()) => {
                    self.fail(sink, AlertDescription::BadRecordMac, "malformed or unauthenticated TLS record");
                    break;
                }
            }
        }
    }

    /// Encrypt and frame application data. Only valid once [`Self::is_complete`].
    pub fn send_application_data<S: TlsRecordSink + ?Sized>(&mut self, plaintext: &[u8], sink: &mut S) {
        if self.failed {
            return;
        }
        if self.state.epoch != Epoch::Application {
            sink.protocol_error(TlsProtocolError::new(
                AlertDescription::InternalError,
                "application data sent before handshake completed",
            ));
            return;
        }
        write_fragmented(&mut self.state, CONTENT_APPLICATION_DATA, plaintext, sink);
        // RFC 8446 §5.5 / RFC 9325 §4.4: retire our own write key before
        // it exceeds the AES-GCM confidentiality limit. No peer round
        // trip needed — `request_key_update` ratchets our write secret
        // immediately, which resets the sequence counter this checks.
        if self.state.write_over_confidentiality_limit() {
            self.request_key_update(sink, false);
        }
    }

    /// Resume after chain verification (from `StorageExecutor` or inline).
    pub fn feed_verification_result<S: TlsRecordSink + ?Sized>(&mut self, result: VerifyResult, sink: &mut S) {
        if self.failed {
            return;
        }
        let mut inner = InnerSink {
            state: &mut self.state,
            outer: sink,
        };
        self.engine.feed_verification_result(result, &mut inner);
    }

    /// Send a `close_notify` alert under the current epoch.
    pub fn send_close_notify<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        if self.failed {
            return;
        }
        let payload = [ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY];
        write_fragmented(&mut self.state, CONTENT_ALERT, &payload, sink);
    }

    /// Rotate this connection's own application traffic key forward (RFC
    /// 8446 §4.6.3/§7.2), optionally asking the peer to reciprocate. Only
    /// valid once [`Self::is_complete`]; returns `false` with no effect
    /// otherwise (local API misuse, not a peer-caused protocol error).
    pub fn request_key_update<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S, request_peer_update: bool) -> bool {
        if self.failed {
            return false;
        }
        let mut inner = InnerSink {
            state: &mut self.state,
            outer: sink,
        };
        self.engine.request_key_update(&mut inner, request_peer_update)
    }

    fn fail<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S, alert: AlertDescription, msg: &str) {
        if !self.failed {
            self.failed = true;
            self.inbound.clear();
            send_fatal_alert(&mut self.state, alert, sink);
            sink.protocol_error(TlsProtocolError::new(alert, msg));
        }
    }

    /// Dispatch one already-decrypted `(inner content type, payload)` pair.
    /// Returns `false` if the caller should stop processing further buffered
    /// records this call (fatal alert, or a downstream failure already reported).
    fn dispatch_record<S: TlsRecordSink + ?Sized>(&mut self, content_type: u8, payload: Vec<u8>, sink: &mut S) -> bool {
        match content_type {
            CONTENT_CHANGE_CIPHER_SPEC => true,
            CONTENT_ALERT => {
                if payload.len() != 2 {
                    self.fail(sink, AlertDescription::DecodeError, "malformed alert record");
                    return false;
                }
                if payload[1] == ALERT_CLOSE_NOTIFY {
                    self.failed = true; // no more records expected after close_notify
                    self.state.alert_sent = true; // no close_notify echo needed
                    sink.peer_closed();
                } else {
                    // Relay the peer's own alert; don't send one back (RFC
                    // 8446 §6 has no alert-acknowledgment concept, and the
                    // peer is already tearing the connection down).
                    let level = if payload[0] == ALERT_LEVEL_FATAL { "fatal" } else { "warning" };
                    self.failed = true;
                    self.state.alert_sent = true;
                    sink.protocol_error(TlsProtocolError::new(
                        AlertDescription::from_code(payload[1]),
                        format!("peer sent {level} alert {}", payload[1]),
                    ));
                }
                false
            }
            CONTENT_HANDSHAKE => {
                let mut inner = InnerSink {
                    state: &mut self.state,
                    outer: sink,
                };
                let mut slice = payload.as_slice();
                self.engine.feed_handshake_data(&mut slice, &mut inner);
                true
            }
            CONTENT_APPLICATION_DATA => {
                if !self.engine.is_complete() {
                    self.fail(sink, AlertDescription::UnexpectedMessage, "application data before handshake completed");
                    return false;
                }
                sink.application_data(&payload);
                true
            }
            _ => {
                self.fail(sink, AlertDescription::UnexpectedMessage, "unknown record content type");
                false
            }
        }
    }

    /// Pop one record off `self.inbound`, decrypting it if the current read
    /// epoch requires it. Returns the record's *inner* content type — for an
    /// encrypted record this is the last non-zero-padding byte of the
    /// decrypted plaintext, not the on-wire opaque type (RFC 8446 §5.2).
    fn take_one_record(&mut self) -> Result<Option<(u8, Vec<u8>)>, ()> {
        if self.inbound.len() < 5 {
            return Ok(None);
        }
        let hdr_type = self.inbound[0];
        let len = u16::from_be_bytes([self.inbound[3], self.inbound[4]]) as usize;
        if len > MAX_CIPHERTEXT_RECORD {
            return Err(());
        }
        if self.inbound.len() < 5 + len {
            return Ok(None);
        }
        let body = self.inbound[5..5 + len].to_vec();
        let header = [self.inbound[0], self.inbound[1], self.inbound[2], self.inbound[3], self.inbound[4]];
        self.inbound.drain(..5 + len);

        if hdr_type == CONTENT_CHANGE_CIPHER_SPEC {
            return Ok(Some((CONTENT_CHANGE_CIPHER_SPEC, Vec::new())));
        }

        match self.state.epoch {
            Epoch::Plaintext => Ok(Some((hdr_type, body))),
            Epoch::Handshake | Epoch::Application => {
                if hdr_type != CONTENT_APPLICATION_DATA {
                    return Err(());
                }
                let read = self.state.read.as_mut().ok_or(())?;
                let mut buf = body;
                let n = read.open_in_place(read.nonce(), &header, &mut buf).map_err(|_| ())?;
                read.advance();
                buf.truncate(n);
                while buf.last() == Some(&0) {
                    buf.pop();
                }
                let inner_type = buf.pop().ok_or(())?;
                Ok(Some((inner_type, buf)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kx_policy::KxPolicy;
    use crate::crypto::trust::TrustStore;
    use bytes::Bytes;

    #[derive(Default)]
    struct RecordingSink {
        events: Vec<String>,
        outbound: Vec<u8>,
        app_data: Vec<Vec<u8>>,
        info: Option<SecurityInfo>,
    }

    impl TlsRecordSink for RecordingSink {
        fn ciphertext_ready(&mut self, data: &[u8]) {
            self.events.push(format!("ciphertext {} bytes", data.len()));
            self.outbound.extend_from_slice(data);
        }
        fn application_data(&mut self, plaintext: &[u8]) {
            self.events.push(format!("application_data {} bytes", plaintext.len()));
            self.app_data.push(plaintext.to_vec());
        }
        fn handshake_complete(&mut self, info: SecurityInfo) {
            self.events.push("handshake_complete".into());
            self.info = Some(info);
        }
        fn verification_requested(&mut self, req: VerifyRequest) {
            self.events.push(format!("verification_requested id={}", req.id));
        }
        fn protocol_error(&mut self, err: TlsProtocolError) {
            self.events.push(format!("protocol_error: {}", err.message));
        }
        fn peer_closed(&mut self) {
            self.events.push("peer_closed".into());
        }
    }

    fn test_server_credentials() -> super::super::engine::ServerCredentials {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        server_credentials_for(key_pair)
    }

    /// `rcgen::generate_simple_self_signed()` — used by every SMTP/IMAP/POP3/FTP/hopf-tls
    /// test fixture in this workspace today — defaults to this key type; the loopback test
    /// below is what actually proves those fixtures will keep working once TcpConnection
    /// moves onto this engine, not just the isolated sign/verify roundtrip in crypto::signature.
    fn test_server_credentials_ecdsa_p256() -> super::super::engine::ServerCredentials {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        server_credentials_for(key_pair)
    }

    fn server_credentials_for(key_pair: rcgen::KeyPair) -> super::super::engine::ServerCredentials {
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        super::super::engine::ServerCredentials {
            cert_chain: vec![Bytes::copy_from_slice(cert.der())],
            signing_key_pkcs8: Bytes::from(key_pair.serialize_der()),
        }
    }

    fn configs_with(creds: super::super::engine::ServerCredentials) -> (HandshakeConfig, HandshakeConfig) {
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        let client = HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::TcpRecordLayer,
            alpn: vec![Bytes::from_static(b"test")],
            server_name: Some("localhost".into()),
            server: None,
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: None,
            trust_store: Some(trust),
            verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: super::super::handshake::ticket::DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        };
        let server = HandshakeConfig {
            role: HandshakeRole::Server,
            mode: HandshakeMode::TcpRecordLayer,
            alpn: vec![Bytes::from_static(b"test")],
            server_name: None,
            server: Some(creds),
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: None,
            trust_store: None,
            verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: super::super::handshake::ticket::DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        };
        (client, server)
    }

    fn configs() -> (HandshakeConfig, HandshakeConfig) {
        configs_with(test_server_credentials())
    }

    /// Drives a full loopback handshake, relaying raw record bytes between
    /// two `TlsRecordEngine`s exactly as `TcpConnection` will — proves the
    /// epoch transitions (plaintext ClientHello/ServerHello, handshake-key
    /// EE/Cert/CV/Finished, application-key NewSessionTicket) all land on
    /// the wire in a shape the peer can actually decrypt back.
    fn relay(from: &mut RecordingSink, to_engine: &mut TlsRecordEngine, to_sink: &mut RecordingSink) {
        let wire = std::mem::take(&mut from.outbound);
        if !wire.is_empty() {
            to_engine.feed_ciphertext(&mut wire.as_slice(), to_sink);
        }
    }

    fn run_loopback() -> (RecordingSink, RecordingSink, TlsRecordEngine, TlsRecordEngine) {
        run_loopback_with(configs())
    }

    fn run_loopback_with(
        (client_cfg, server_cfg): (HandshakeConfig, HandshakeConfig),
    ) -> (RecordingSink, RecordingSink, TlsRecordEngine, TlsRecordEngine) {
        let mut client = TlsRecordEngine::new(client_cfg);
        let mut server = TlsRecordEngine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();

        client.start(&mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s); // ClientHello
        relay(&mut sink_s, &mut client, &mut sink_c); // ServerHello..Finished
        relay(&mut sink_c, &mut server, &mut sink_s); // client Finished
        relay(&mut sink_s, &mut client, &mut sink_c); // server post-handshake NewSessionTicket

        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        (sink_c, sink_s, client, server)
    }

    /// Direct proof that `DirectionalKeys`'s ChaCha20-Poly1305 branch
    /// actually round-trips real ciphertext through the real wire framing —
    /// a full handshake can't reach this deterministically (a normal client
    /// always offers both `SUPPORTED_CIPHER_SUITES` entries, and AES-128-GCM
    /// is first preference on both sides), so this drives the AEAD dispatch
    /// directly, the same way as the TLS 1.2 record layer's analogous test.
    /// Real cipher *negotiation* is proven by `tls::engine`'s
    /// `server_selects_chacha20_poly1305_when_its_the_only_offered_suite`
    /// and by the `rustls` interop tests in `hopf-tls`.
    #[test]
    fn chacha20_poly1305_direction_round_trips_over_real_wire_framing() {
        let secret = [0x11u8; 32];
        let mut write = DirectionalKeys::from_secret(Tls13Aead::ChaCha20Poly1305Sha256, &secret);
        let read = DirectionalKeys::from_secret(Tls13Aead::ChaCha20Poly1305Sha256, &secret);

        let mut wire = Vec::new();
        write_encrypted_record(&mut write, CONTENT_APPLICATION_DATA, b"hello chacha13", &mut wire);

        let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        assert_eq!(wire.len(), 5 + len, "no explicit nonce on the wire, unlike TLS 1.2 GCM");
        let header = [wire[0], wire[1], wire[2], wire[3], wire[4]];
        let mut buf = wire[5..5 + len].to_vec();
        let n = read.open_in_place(read.nonce(), &header, &mut buf).unwrap();
        buf.truncate(n);
        assert_eq!(buf.last(), Some(&CONTENT_APPLICATION_DATA), "inner content type byte");
        buf.pop();
        assert_eq!(buf, b"hello chacha13");
    }

    #[test]
    fn loopback_handshake_completes_and_exposes_alpn() {
        let (sink_c, sink_s, _client, _server) = run_loopback();
        assert!(sink_c.events.iter().any(|e| e == "handshake_complete"));
        assert!(sink_s.events.iter().any(|e| e == "handshake_complete"));
        let info = sink_c.info.expect("client security info");
        assert_eq!(info.alpn(), Some(&b"test"[..]));
    }

    #[test]
    fn loopback_handshake_completes_with_ecdsa_p256_server_cert() {
        let (sink_c, sink_s, _client, _server) =
            run_loopback_with(configs_with(test_server_credentials_ecdsa_p256()));
        assert!(sink_c.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink_c.events);
        assert!(sink_s.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink_s.events);
    }

    /// Validates the design justification for going sink-based at all (see
    /// crypto-migration-plan.md's "Why sink-based, not return-value-based":
    /// "multiple outcomes from one stimulus are natural — handshake complete
    /// *and* early application data in one read"). A real client pipelines
    /// its Finished and its first application write back-to-back; TCP is
    /// free to deliver both in a single `read()`, so the server's *one*
    /// `feed_ciphertext` call for that read must both complete the
    /// handshake and decrypt/deliver the application data that followed it
    /// in the same buffer — and in that order, not the reverse.
    #[test]
    fn client_finished_and_pipelined_app_data_in_one_read_completes_then_delivers_in_order() {
        let (client_cfg, server_cfg) = configs();
        let mut client = TlsRecordEngine::new(client_cfg);
        let mut server = TlsRecordEngine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();

        client.start(&mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s); // ClientHello
        relay(&mut sink_s, &mut client, &mut sink_c); // ServerHello..Finished -> client completes, sends its Finished
        assert!(client.is_complete(), "client: {:?}", sink_c.events);

        // Pipeline application data right behind the still-unsent Finished —
        // both land in sink_c.outbound as one combined buffer, exactly as a
        // fast local peer's back-to-back writes would coalesce into one read.
        client.send_application_data(b"pipelined-hello", &mut sink_c);
        let combined = std::mem::take(&mut sink_c.outbound);
        assert!(!combined.is_empty());
        server.feed_ciphertext(&mut combined.as_slice(), &mut sink_s);

        assert!(server.is_complete(), "server must complete the handshake: {:?}", sink_s.events);
        let hs_idx = sink_s
            .events
            .iter()
            .position(|e| e == "handshake_complete")
            .expect("handshake_complete fired");
        let app_idx = sink_s
            .events
            .iter()
            .position(|e| e.starts_with("application_data"))
            .expect("application_data fired");
        assert!(
            hs_idx < app_idx,
            "handshake must complete before app data is delivered: {:?}",
            sink_s.events
        );
        assert_eq!(sink_s.app_data, vec![b"pipelined-hello".to_vec()]);
    }

    #[test]
    fn application_data_round_trips_after_handshake() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        client.send_application_data(b"hello from client", &mut sink_c);
        let wire = std::mem::take(&mut sink_c.outbound);
        assert!(!wire.is_empty());
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);
        assert_eq!(sink_s.app_data, vec![b"hello from client".to_vec()]);

        server.send_application_data(b"hello back", &mut sink_s);
        let wire = std::mem::take(&mut sink_s.outbound);
        client.feed_ciphertext(&mut wire.as_slice(), &mut sink_c);
        assert_eq!(sink_c.app_data, vec![b"hello back".to_vec()]);
    }

    /// End-to-end proof the `KeyUpdate` ratchet (RFC 8446 §4.6.3/§7.2)
    /// actually works: the strongest possible test isn't inspecting
    /// internal secrets (private to this module) but proving application
    /// data sent *after* the update still round-trips — if the write/read
    /// key swap were wrong on either side, the server's `open_in_place`
    /// would fail AEAD authentication and report a `protocol_error`
    /// instead of delivering the plaintext.
    #[test]
    fn key_update_rotates_client_write_key_and_server_still_decrypts() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();

        client.send_application_data(b"before update", &mut sink_c);
        let wire = std::mem::take(&mut sink_c.outbound);
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);
        assert_eq!(sink_s.app_data, vec![b"before update".to_vec()]);

        assert!(client.request_key_update(&mut sink_c, false), "{:?}", sink_c.events);
        let wire = std::mem::take(&mut sink_c.outbound);
        assert!(!wire.is_empty(), "KeyUpdate message must be emitted");
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);
        assert!(
            !sink_s.events.iter().any(|e| e.starts_with("protocol_error")),
            "server must accept a well-formed KeyUpdate: {:?}",
            sink_s.events
        );

        sink_c.app_data.clear();
        sink_s.app_data.clear();
        client.send_application_data(b"after update", &mut sink_c);
        let wire = std::mem::take(&mut sink_c.outbound);
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);
        assert_eq!(
            sink_s.app_data,
            vec![b"after update".to_vec()],
            "server must decrypt under the ratcheted key: {:?}",
            sink_s.events
        );
    }

    /// `request_peer_update: true` — the peer must reciprocate before its
    /// own next application data, and both directions must keep working
    /// after both sides have rotated.
    #[test]
    fn key_update_requesting_reciprocal_keeps_both_directions_working() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();

        assert!(client.request_key_update(&mut sink_c, true), "{:?}", sink_c.events);
        let wire = std::mem::take(&mut sink_c.outbound);
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);
        assert!(
            !sink_s.events.iter().any(|e| e.starts_with("protocol_error")),
            "server must accept and reciprocate: {:?}",
            sink_s.events
        );
        // Server's reciprocal KeyUpdate(update_not_requested) must have
        // gone out as part of processing the request — relay it back so
        // the client's read key also rotates to match.
        let wire = std::mem::take(&mut sink_s.outbound);
        assert!(!wire.is_empty(), "server must send a reciprocal KeyUpdate");
        client.feed_ciphertext(&mut wire.as_slice(), &mut sink_c);
        assert!(
            !sink_c.events.iter().any(|e| e.starts_with("protocol_error")),
            "client must accept the reciprocal: {:?}",
            sink_c.events
        );

        client.send_application_data(b"client after mutual update", &mut sink_c);
        let wire = std::mem::take(&mut sink_c.outbound);
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);
        assert_eq!(sink_s.app_data, vec![b"client after mutual update".to_vec()], "{:?}", sink_s.events);

        server.send_application_data(b"server after mutual update", &mut sink_s);
        let wire = std::mem::take(&mut sink_s.outbound);
        client.feed_ciphertext(&mut wire.as_slice(), &mut sink_c);
        assert_eq!(sink_c.app_data, vec![b"server after mutual update".to_vec()], "{:?}", sink_c.events);
    }

    /// RFC 8446 §5.5 / RFC 9325 §4.4: a write key nearing its AES-GCM
    /// confidentiality limit must trigger an automatic self key update
    /// rather than silently continuing past the safety margin.
    #[test]
    fn send_application_data_auto_rotates_write_key_at_confidentiality_limit() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        // TLS 1.3 has no explicit per-record nonce on the wire — both
        // sides derive it from their own counted-in-lockstep sequence
        // number, so simulating "23 million records already exchanged"
        // means advancing *both* sides' counters together, not just the
        // sender's.
        client.state.write.as_mut().unwrap().seq = AES_GCM_CONFIDENTIALITY_LIMIT - 1;
        server.state.read.as_mut().unwrap().seq = AES_GCM_CONFIDENTIALITY_LIMIT - 1;

        client.send_application_data(b"the record that crosses the limit", &mut sink_c);

        assert_eq!(
            client.state.write.as_ref().unwrap().seq,
            0,
            "write key must have rotated (and its sequence counter reset) once the limit was crossed"
        );
        let wire = std::mem::take(&mut sink_c.outbound);
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);
        assert_eq!(
            sink_s.app_data,
            vec![b"the record that crosses the limit".to_vec()],
            "server must still decrypt both the app data and the KeyUpdate that followed it: {:?}",
            sink_s.events
        );
    }

    /// Symmetric case: a read key nearing its limit asks the peer to
    /// rotate rather than silently continuing to decrypt under an
    /// over-used key. Only one request goes out per crossing —
    /// `read_update_requested` guards against re-firing on every
    /// subsequent record while waiting for the peer's reply.
    #[test]
    fn feed_ciphertext_requests_peer_rotation_at_read_confidentiality_limit() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        // Both sides' counters must stay in lockstep for the nonce to
        // line up (see the write-side test above), but this test wants
        // to isolate the *read*-side trigger alone — going through
        // `client.send_application_data` here would also cross the
        // client's own write-side limit and fire that self-rotation
        // too, conflating the two cases. Encoding the record directly
        // with `write_encrypted_record` advances the same real write
        // key/state, just without going through that extra check.
        client.state.write.as_mut().unwrap().seq = AES_GCM_CONFIDENTIALITY_LIMIT - 1;
        server.state.read.as_mut().unwrap().seq = AES_GCM_CONFIDENTIALITY_LIMIT - 1;
        let mut wire = Vec::new();
        write_encrypted_record(
            client.state.write.as_mut().unwrap(),
            CONTENT_APPLICATION_DATA,
            b"one more under the old key",
            &mut wire,
        );
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);

        assert_eq!(sink_s.app_data, vec![b"one more under the old key".to_vec()]);
        assert!(server.state.read_update_requested);
        let wire = std::mem::take(&mut sink_s.outbound);
        assert!(!wire.is_empty(), "server must ask the client to rotate: {:?}", sink_s.events);
        client.feed_ciphertext(&mut wire.as_slice(), &mut sink_c);
        assert!(
            !sink_c.events.iter().any(|e| e.starts_with("protocol_error")),
            "client must accept the rotation request: {:?}",
            sink_c.events
        );
    }

    #[test]
    fn request_key_update_before_handshake_complete_is_a_no_op() {
        let (client_cfg, _server_cfg) = configs();
        let mut client = TlsRecordEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        sink.outbound.clear();
        assert!(!client.request_key_update(&mut sink, false));
        assert!(sink.outbound.is_empty(), "must not emit anything: {:?}", sink.events);
    }

    #[test]
    fn close_notify_reported_as_peer_closed() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        client.send_close_notify(&mut sink_c);
        let wire = std::mem::take(&mut sink_c.outbound);
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);
        assert!(sink_s.events.iter().any(|e| e == "peer_closed"), "{:?}", sink_s.events);
    }

    #[test]
    fn tampered_application_record_reports_protocol_error() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        client.send_application_data(b"hello", &mut sink_c);
        let mut wire = std::mem::take(&mut sink_c.outbound);
        let last = wire.len() - 1;
        wire[last] ^= 0xff; // corrupt the AEAD tag
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);
        assert!(
            sink_s.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink_s.events
        );
        assert!(sink_s.app_data.is_empty());
    }

    /// A locally-detected violation (here: a corrupted AEAD tag) must not
    /// just be reported to the local embedder — it has to reach the peer
    /// as a real wire `Alert` record (RFC 8446 §6.2) so *they* know why
    /// the connection dropped, and that alert's description must survive
    /// the round trip to the peer's own `TlsProtocolError`.
    #[test]
    fn a_locally_detected_failure_sends_a_real_fatal_alert_the_peer_can_decode() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        client.send_application_data(b"hello", &mut sink_c);
        let mut wire = std::mem::take(&mut sink_c.outbound);
        let last = wire.len() - 1;
        wire[last] ^= 0xff; // corrupt the AEAD tag
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);

        let alert_wire = std::mem::take(&mut sink_s.outbound);
        assert!(!alert_wire.is_empty(), "server must send a fatal alert on the wire: {:?}", sink_s.events);

        // Feed the server's alert back to the client — it must decode as
        // AlertDescription::BadRecordMac (20) without the client sending
        // anything of its own in reply (no alert ping-pong).
        client.feed_ciphertext(&mut alert_wire.as_slice(), &mut sink_c);
        assert!(
            sink_c.events.iter().any(|e| e.contains("peer sent fatal alert 20")),
            "client must surface the peer's exact alert code: {:?}",
            sink_c.events
        );
        assert!(
            sink_c.outbound.is_empty(),
            "client must not echo an alert back to a peer that already sent one: {:?}",
            sink_c.outbound
        );
    }

    #[test]
    fn application_data_before_handshake_complete_is_rejected() {
        let (client_cfg, _server_cfg) = configs();
        let mut client = TlsRecordEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        sink.outbound.clear();
        client.send_application_data(b"too early", &mut sink);
        assert!(sink.events.iter().any(|e| e.starts_with("protocol_error")));
        assert!(sink.outbound.is_empty());
    }

    #[test]
    fn large_handshake_message_is_fragmented_across_records() {
        // A synthetic huge "certificate chain" forces `write_fragmented` to
        // split one handshake_data_ready call into multiple TLS records —
        // this exercises that path without needing a real oversized chain.
        let mut state = RecordState::new(HandshakeRole::Server);
        let mut sink = RecordingSink::default();
        let data = vec![0x42u8; MAX_FRAGMENT * 2 + 10];
        write_fragmented(&mut state, CONTENT_HANDSHAKE, &data, &mut sink);
        // Plaintext epoch: each record is a 5-byte header + fragment, no AEAD overhead.
        assert_eq!(sink.outbound.len(), data.len() + 5 * 3);
    }
}
