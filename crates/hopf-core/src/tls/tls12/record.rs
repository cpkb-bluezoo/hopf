// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.2 record layer — AEAD only (RFC 5288 §3 `GenericAEADCipher`, GCM
//! today; see [`super::engine`]'s module doc for why CBC is explicitly not
//! planned, not merely deferred). Wraps [`Tls12Engine`] with record framing
//! and AEAD, sink-based like every other engine in this crate.
//!
//! Unlike the TLS 1.3 record layer ([`super::super::record`]), TLS 1.2's
//! `ChangeCipherSpec` is a real wire signal (content type 20, not middlebox
//! compat theater) that actually switches an epoch — and, unlike TLS 1.3's
//! opaque `application_data` outer type hiding the real content, TLS 1.2 GCM
//! records carry their true content type in the record header even once
//! encrypted, so there's no inner-type unwrapping to do here either.

use crate::crypto::aead::{AeadError, AesGcmKey, ChaCha20Poly1305Key};
use crate::security::SecurityInfo;

use super::engine::{CipherKind, Config, DirectionalKeyMaterial, Role, Tls12EventSink, Tls12Engine};
use super::super::sink::{TlsProtocolError, VerifyRequest, VerifyResult};

// Reuses the TLS 1.3 record layer's sink trait verbatim — its shape
// (ciphertext out; application data, handshake completion, verification
// gate, protocol error, and peer-close events in) isn't actually TLS-1.3-
// specific, and sharing it means `TcpConnection`'s existing sink adapter
// drives *either* engine unchanged, with no separate 1.2-flavored trait to
// keep in sync.
pub use super::super::record::TlsRecordSink as Tls12RecordSink;

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;

const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_LEVEL_FATAL: u8 = 2;
const ALERT_CLOSE_NOTIFY: u8 = 0;

/// RFC 5246 §6.2.1: plaintext fragments are capped at 2^14 bytes.
const MAX_FRAGMENT: usize = 16384;
/// Upper bound over every supported cipher's per-record overhead — GCM's
/// 8-byte explicit nonce + 16-byte tag (RFC 5288 §3; ChaCha20-Poly1305 has
/// no explicit nonce, so its actual overhead is smaller, well within this
/// bound). Used only as an early sanity check on the record length before
/// the negotiated cipher's exact overhead is applied in [`Tls12RecordEngine::take_one_record`].
const MAX_CIPHERTEXT_RECORD: usize = MAX_FRAGMENT + 8 + 16;

/// One direction's AEAD key, generalized over TLS 1.2's two nonce-construction
/// strategies: RFC 5288 GCM (4-byte fixed IV/`salt` concatenated with an
/// 8-byte explicit per-record nonce carried on the wire) and RFC 7905
/// ChaCha20-Poly1305 (12-byte fixed IV, no wire nonce at all — the 96-bit
/// nonce is the IV XORed with the sequence number, the same construction
/// TLS 1.3's record layer uses throughout, see `super::super::record`).
enum DirectionKey {
    Gcm { key: AesGcmKey, fixed_iv: [u8; 4] },
    ChaCha { key: ChaCha20Poly1305Key, fixed_iv: [u8; 12] },
}

struct AeadDirection {
    key: DirectionKey,
    seq: u64,
}

impl AeadDirection {
    fn from_material(material: &DirectionalKeyMaterial, cipher: CipherKind) -> Option<Self> {
        let key = match cipher {
            CipherKind::Aes128Gcm | CipherKind::Aes256Gcm => {
                let mut fixed_iv = [0u8; 4];
                fixed_iv.copy_from_slice(&material.fixed_iv);
                DirectionKey::Gcm { key: AesGcmKey::new(&material.key).ok()?, fixed_iv }
            }
            CipherKind::ChaCha20Poly1305 => {
                let mut fixed_iv = [0u8; 12];
                fixed_iv.copy_from_slice(&material.fixed_iv);
                DirectionKey::ChaCha { key: ChaCha20Poly1305Key::new(&material.key).ok()?, fixed_iv }
            }
        };
        Some(Self { key, seq: 0 })
    }

    /// Whether this cipher carries an explicit per-record nonce on the wire
    /// (GCM) or derives it purely from the sequence number (ChaCha20-Poly1305).
    fn has_explicit_nonce(&self) -> bool {
        matches!(self.key, DirectionKey::Gcm { .. })
    }

    /// Nonce for the write side (always the local sequence counter) or for a
    /// cipher with no wire nonce at all (ChaCha20-Poly1305, both directions).
    fn local_nonce(&self) -> [u8; 12] {
        match &self.key {
            DirectionKey::Gcm { fixed_iv, .. } => gcm_nonce(fixed_iv, &self.seq.to_be_bytes()),
            DirectionKey::ChaCha { fixed_iv, .. } => chacha_nonce(fixed_iv, self.seq),
        }
    }

    /// Nonce for the read side of a GCM direction, from the wire's explicit
    /// nonce bytes (never called for ChaCha20-Poly1305 — see [`Self::local_nonce`]).
    fn nonce_from_wire(&self, explicit_nonce: &[u8]) -> [u8; 12] {
        match &self.key {
            DirectionKey::Gcm { fixed_iv, .. } => gcm_nonce(fixed_iv, explicit_nonce),
            DirectionKey::ChaCha { fixed_iv, .. } => chacha_nonce(fixed_iv, self.seq),
        }
    }

    fn seal_in_place_append_tag(&self, nonce: [u8; 12], aad: &[u8], plaintext: &mut Vec<u8>) -> Result<(), AeadError> {
        match &self.key {
            DirectionKey::Gcm { key, .. } => key.seal_in_place_append_tag(nonce, aad, plaintext),
            DirectionKey::ChaCha { key, .. } => key.seal_in_place_append_tag(nonce, aad, plaintext),
        }
    }

    fn open_in_place(&self, nonce: [u8; 12], aad: &[u8], ciphertext: &mut [u8]) -> Result<usize, AeadError> {
        match &self.key {
            DirectionKey::Gcm { key, .. } => key.open_in_place(nonce, aad, ciphertext),
            DirectionKey::ChaCha { key, .. } => key.open_in_place(nonce, aad, ciphertext),
        }
    }
}

fn gcm_nonce(fixed_iv: &[u8; 4], explicit_nonce: &[u8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(fixed_iv);
    n[4..].copy_from_slice(explicit_nonce);
    n
}

fn chacha_nonce(fixed_iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *fixed_iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= seq_bytes[i];
    }
    n
}

struct RecordState {
    role: Role,
    write: Option<AeadDirection>,
    read: Option<AeadDirection>,
    pending_write: Option<DirectionalKeyMaterial>,
    pending_read: Option<DirectionalKeyMaterial>,
    cipher: Option<CipherKind>,
}

impl RecordState {
    fn new(role: Role) -> Self {
        Self { role, write: None, read: None, pending_write: None, pending_read: None, cipher: None }
    }

    fn stage_keys(&mut self, cipher: CipherKind, client: DirectionalKeyMaterial, server: DirectionalKeyMaterial) {
        let (w, r) = match self.role {
            Role::Client => (client, server),
            Role::Server => (server, client),
        };
        self.cipher = Some(cipher);
        self.pending_write = Some(w);
        self.pending_read = Some(r);
    }

    fn activate_write(&mut self) {
        if let (Some(m), Some(c)) = (self.pending_write.take(), self.cipher) {
            self.write = AeadDirection::from_material(&m, c);
        }
    }

    fn activate_read(&mut self) {
        if let (Some(m), Some(c)) = (self.pending_read.take(), self.cipher) {
            self.read = AeadDirection::from_material(&m, c);
        }
    }
}

fn write_plaintext_record(content_type: u8, payload: &[u8], out: &mut Vec<u8>) {
    let len = payload.len() as u16;
    out.extend_from_slice(&[content_type, 0x03, 0x03]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
}

/// RFC 5288 §3 AEAD `additional_data` (adapted from RFC 5246 §6.2.3.3's MAC input).
fn additional_data(seq: u64, content_type: u8, plaintext_len: usize) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = content_type;
    aad[9] = 0x03;
    aad[10] = 0x03;
    aad[11..13].copy_from_slice(&(plaintext_len as u16).to_be_bytes());
    aad
}

fn write_encrypted_record(dir: &mut AeadDirection, content_type: u8, payload: &[u8], out: &mut Vec<u8>) {
    let aad = additional_data(dir.seq, content_type, payload.len());
    let nonce = dir.local_nonce();
    let mut ciphertext = payload.to_vec();
    dir.seal_in_place_append_tag(nonce, &aad, &mut ciphertext)
        .expect("seal with a freshly derived key never fails");
    let has_explicit = dir.has_explicit_nonce();
    let explicit_nonce = dir.seq.to_be_bytes();
    let record_len = (if has_explicit { explicit_nonce.len() } else { 0 } + ciphertext.len()) as u16;
    out.extend_from_slice(&[content_type, 0x03, 0x03]);
    out.extend_from_slice(&record_len.to_be_bytes());
    if has_explicit {
        out.extend_from_slice(&explicit_nonce);
    }
    out.extend_from_slice(&ciphertext);
    dir.seq = dir.seq.wrapping_add(1);
}

fn write_fragmented<S: Tls12RecordSink + ?Sized>(state: &mut RecordState, content_type: u8, data: &[u8], sink: &mut S) {
    let mut out = Vec::new();
    let chunks: Vec<&[u8]> = if data.is_empty() { vec![&data[..]] } else { data.chunks(MAX_FRAGMENT).collect() };
    for chunk in chunks {
        match state.write.as_mut() {
            Some(dir) => write_encrypted_record(dir, content_type, chunk, &mut out),
            None => write_plaintext_record(content_type, chunk, &mut out),
        }
    }
    if !out.is_empty() {
        sink.ciphertext_ready(&out);
    }
}

struct InnerSink<'a, S: Tls12RecordSink + ?Sized> {
    state: &'a mut RecordState,
    outer: &'a mut S,
}

impl<S: Tls12RecordSink + ?Sized> Tls12EventSink for InnerSink<'_, S> {
    fn handshake_data_ready(&mut self, data: &[u8]) {
        write_fragmented(self.state, CONTENT_HANDSHAKE, data, self.outer);
    }

    fn keys_ready(&mut self, cipher: CipherKind, client: DirectionalKeyMaterial, server: DirectionalKeyMaterial) {
        self.state.stage_keys(cipher, client, server);
    }

    fn send_change_cipher_spec(&mut self) {
        write_fragmented(self.state, CONTENT_CHANGE_CIPHER_SPEC, &[0x01], self.outer);
        self.state.activate_write();
    }

    fn handshake_complete(&mut self, info: SecurityInfo) {
        self.outer.handshake_complete(info);
    }

    fn verification_requested(&mut self, req: VerifyRequest) {
        self.outer.verification_requested(req);
    }

    fn protocol_error(&mut self, err: TlsProtocolError) {
        self.outer.protocol_error(err);
    }
}

/// Reactive TLS 1.2 record layer — wraps [`Tls12Engine`] with RFC 5246/5288
/// record framing and GCM AEAD.
pub struct Tls12RecordEngine {
    engine: Tls12Engine,
    state: RecordState,
    inbound: Vec<u8>,
    failed: bool,
}

impl Tls12RecordEngine {
    /// Create the engine.
    pub fn new(config: Config) -> Self {
        let role = config.role;
        Self { engine: Tls12Engine::new(config), state: RecordState::new(role), inbound: Vec::new(), failed: false }
    }

    /// Begin the handshake — client emits `ClientHello`; server waits for input.
    pub fn start<S: Tls12RecordSink + ?Sized>(&mut self, sink: &mut S) {
        let mut inner = InnerSink { state: &mut self.state, outer: sink };
        self.engine.start(&mut inner);
    }

    /// Whether the handshake has completed.
    pub fn is_complete(&self) -> bool {
        self.engine.is_complete()
    }

    /// Consume raw bytes off the TCP stream.
    pub fn feed_ciphertext<S: Tls12RecordSink + ?Sized>(&mut self, input: &mut &[u8], sink: &mut S) {
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
                    if !self.dispatch_record(content_type, payload, sink) {
                        break;
                    }
                }
                Err(()) => {
                    self.fail(sink, "malformed or unauthenticated TLS record");
                    break;
                }
            }
        }
    }

    /// Encrypt and frame application data. Only valid once [`Self::is_complete`].
    pub fn send_application_data<S: Tls12RecordSink + ?Sized>(&mut self, plaintext: &[u8], sink: &mut S) {
        if self.failed {
            return;
        }
        if self.state.write.is_none() {
            sink.protocol_error(TlsProtocolError::new("application data sent before handshake completed"));
            return;
        }
        write_fragmented(&mut self.state, CONTENT_APPLICATION_DATA, plaintext, sink);
    }

    /// Resume after chain verification (from `StorageExecutor` or inline).
    pub fn feed_verification_result<S: Tls12RecordSink + ?Sized>(&mut self, result: VerifyResult, sink: &mut S) {
        if self.failed {
            return;
        }
        let mut inner = InnerSink { state: &mut self.state, outer: sink };
        self.engine.feed_verification_result(result, &mut inner);
    }

    /// Send a `close_notify` alert under the current epoch.
    pub fn send_close_notify<S: Tls12RecordSink + ?Sized>(&mut self, sink: &mut S) {
        if self.failed {
            return;
        }
        write_fragmented(&mut self.state, CONTENT_ALERT, &[ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY], sink);
    }

    fn fail<S: Tls12RecordSink + ?Sized>(&mut self, sink: &mut S, msg: &str) {
        if !self.failed {
            self.failed = true;
            self.inbound.clear();
            sink.protocol_error(TlsProtocolError::new(msg));
        }
    }

    fn dispatch_record<S: Tls12RecordSink + ?Sized>(&mut self, content_type: u8, payload: Vec<u8>, sink: &mut S) -> bool {
        match content_type {
            CONTENT_CHANGE_CIPHER_SPEC => {
                self.state.activate_read();
                true
            }
            CONTENT_ALERT => {
                if payload.len() != 2 {
                    self.fail(sink, "malformed alert record");
                    return false;
                }
                if payload[1] == ALERT_CLOSE_NOTIFY {
                    self.failed = true;
                    sink.peer_closed();
                } else {
                    let level = if payload[0] == ALERT_LEVEL_FATAL { "fatal" } else { "warning" };
                    self.fail(sink, &format!("{level} alert {}", payload[1]));
                }
                false
            }
            CONTENT_HANDSHAKE => {
                let mut inner = InnerSink { state: &mut self.state, outer: sink };
                let mut slice = payload.as_slice();
                self.engine.feed_handshake_data(&mut slice, &mut inner);
                true
            }
            CONTENT_APPLICATION_DATA => {
                if !self.engine.is_complete() {
                    self.fail(sink, "application data before handshake completed");
                    return false;
                }
                sink.application_data(&payload);
                true
            }
            _ => {
                self.fail(sink, "unknown record content type");
                false
            }
        }
    }

    /// Pop one record off `self.inbound`, decrypting it if a read epoch is active.
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
        self.inbound.drain(..5 + len);

        if hdr_type == CONTENT_CHANGE_CIPHER_SPEC {
            return Ok(Some((CONTENT_CHANGE_CIPHER_SPEC, Vec::new())));
        }

        match self.state.read.as_mut() {
            None => Ok(Some((hdr_type, body))),
            Some(dir) => {
                let has_explicit = dir.has_explicit_nonce();
                let overhead = if has_explicit { 8 + 16 } else { 16 };
                if body.len() < overhead {
                    return Err(());
                }
                let ciphertext_start = if has_explicit { 8 } else { 0 };
                let plain_len = body.len() - overhead;
                let aad = additional_data(dir.seq, hdr_type, plain_len);
                let nonce = if has_explicit {
                    dir.nonce_from_wire(&body[..8])
                } else {
                    dir.local_nonce()
                };
                let mut buf = body[ciphertext_start..].to_vec();
                let n = dir.open_in_place(nonce, &aad, &mut buf).map_err(|_| ())?;
                dir.seq = dir.seq.wrapping_add(1);
                buf.truncate(n);
                Ok(Some((hdr_type, buf)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::trust::TrustStore;
    use bytes::Bytes;

    use crate::tls::ServerCredentials;

    #[derive(Default)]
    struct RecordingSink {
        events: Vec<String>,
        outbound: Vec<u8>,
        app_data: Vec<Vec<u8>>,
        info: Option<SecurityInfo>,
    }

    impl Tls12RecordSink for RecordingSink {
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

    fn test_server_credentials() -> ServerCredentials {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        ServerCredentials {
            cert_chain: vec![Bytes::copy_from_slice(cert.der())],
            signing_key_pkcs8: Bytes::from(key_pair.serialize_der()),
        }
    }

    fn configs() -> (Config, Config) {
        let creds = test_server_credentials();
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        let client = Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            server: None,
            trust_store: Some(trust),
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
        };
        let server = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
        };
        (client, server)
    }

    fn relay(from: &mut RecordingSink, to_engine: &mut Tls12RecordEngine, to_sink: &mut RecordingSink) {
        let wire = std::mem::take(&mut from.outbound);
        if !wire.is_empty() {
            to_engine.feed_ciphertext(&mut wire.as_slice(), to_sink);
        }
    }

    fn run_loopback() -> (RecordingSink, RecordingSink, Tls12RecordEngine, Tls12RecordEngine) {
        let (client_cfg, server_cfg) = configs();
        let mut client = Tls12RecordEngine::new(client_cfg);
        let mut server = Tls12RecordEngine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();

        client.start(&mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s); // ClientHello
        relay(&mut sink_s, &mut client, &mut sink_c); // SH, Cert, SKE, SHD
        relay(&mut sink_c, &mut server, &mut sink_s); // CKE, CCS, client Finished
        relay(&mut sink_s, &mut client, &mut sink_c); // server CCS, Finished

        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        (sink_c, sink_s, client, server)
    }

    /// Direct proof that `AeadDirection`'s ChaCha20-Poly1305 branch (no
    /// explicit wire nonce, IV-XOR-sequence-number construction, per
    /// `CipherKind::iv_len`'s 12-byte IV) actually round-trips real
    /// ciphertext through the real wire framing — bypassing full handshake
    /// negotiation (which always prefers AES-128-GCM when both peers offer
    /// the full suite list, so a full-handshake test can't reach this path
    /// deterministically; real cipher *negotiation* is instead proven by
    /// the `rustls` interop tests in `hopf-tls`, which can force the suite).
    #[test]
    fn chacha20_poly1305_direction_round_trips_over_real_wire_framing() {
        let client_material = DirectionalKeyMaterial {
            key: Bytes::copy_from_slice(&[0x11u8; 32]),
            fixed_iv: Bytes::copy_from_slice(&[0x22u8; 12]),
        };
        let server_material = DirectionalKeyMaterial {
            key: Bytes::copy_from_slice(&[0x33u8; 32]),
            fixed_iv: Bytes::copy_from_slice(&[0x44u8; 12]),
        };

        let mut client_state = RecordState::new(Role::Client);
        client_state.stage_keys(CipherKind::ChaCha20Poly1305, client_material.clone(), server_material.clone());
        client_state.activate_write();
        client_state.activate_read();

        let mut server_state = RecordState::new(Role::Server);
        server_state.stage_keys(CipherKind::ChaCha20Poly1305, client_material, server_material);
        server_state.activate_write();
        server_state.activate_read();

        let mut wire = Vec::new();
        write_encrypted_record(client_state.write.as_mut().unwrap(), CONTENT_APPLICATION_DATA, b"hello chacha", &mut wire);
        // No explicit nonce: just the 3-byte header + ciphertext + 16-byte tag.
        assert_eq!(wire.len(), 3 + 2 + b"hello chacha".len() + 16, "wire: {wire:?}");

        let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        let body = wire[5..5 + len].to_vec();
        let overhead = 16;
        let dir = server_state.read.as_mut().unwrap();
        let aad = additional_data(dir.seq, CONTENT_APPLICATION_DATA, body.len() - overhead);
        let nonce = dir.local_nonce();
        let mut buf = body;
        let n = dir.open_in_place(nonce, &aad, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello chacha");
    }

    #[test]
    fn loopback_handshake_completes_over_real_record_framing() {
        let (sink_c, sink_s, _client, _server) = run_loopback();
        assert!(sink_c.events.iter().any(|e| e == "handshake_complete"));
        assert!(sink_s.events.iter().any(|e| e == "handshake_complete"));
        assert!(sink_c.events.iter().any(|e| e.starts_with("ciphertext")), "record framing must have produced bytes");
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

    #[test]
    fn tampered_application_record_reports_protocol_error() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        client.send_application_data(b"hello", &mut sink_c);
        let mut wire = std::mem::take(&mut sink_c.outbound);
        let last = wire.len() - 1;
        wire[last] ^= 0xff; // corrupt the AEAD tag
        server.feed_ciphertext(&mut wire.as_slice(), &mut sink_s);
        assert!(sink_s.events.iter().any(|e| e.starts_with("protocol_error")), "{:?}", sink_s.events);
        assert!(sink_s.app_data.is_empty());
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
    fn ticket_resumption_round_trips_over_real_record_framing() {
        let creds = test_server_credentials();
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        let mut ticket_key = [0u8; 32];
        getrandom::getrandom(&mut ticket_key).unwrap();
        let store = crate::tls::Tls12ClientTicketStore::shared();

        let client_cfg = Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            server: None,
            trust_store: Some(trust),
            ticket_key: None,
            client_ticket_store: Some(store.clone()),
            ..Default::default()
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: Some(ticket_key),
            client_ticket_store: None,
            ..Default::default()
        };

        // First connection: full handshake, real record framing, mints a ticket.
        let mut client = Tls12RecordEngine::new(client_cfg.clone());
        let mut server = Tls12RecordEngine::new(server_cfg.clone());
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        client.start(&mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);
        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        assert!(store.get("localhost").is_some());

        // Second connection: abbreviated handshake over the same real wire
        // framing — real GCM-encrypted Finished messages, a real CCS record
        // switching the read epoch, not just engine-level message objects.
        let mut client2 = Tls12RecordEngine::new(client_cfg);
        let mut server2 = Tls12RecordEngine::new(server_cfg);
        let mut sink_c2 = RecordingSink::default();
        let mut sink_s2 = RecordingSink::default();
        client2.start(&mut sink_c2);
        relay(&mut sink_c2, &mut server2, &mut sink_s2); // ClientHello
        relay(&mut sink_s2, &mut client2, &mut sink_c2); // SH, CCS, server Finished
        relay(&mut sink_c2, &mut server2, &mut sink_s2); // CCS, client Finished

        assert!(client2.is_complete(), "client2: {:?}", sink_c2.events);
        assert!(server2.is_complete(), "server2: {:?}", sink_s2.events);

        client2.send_application_data(b"resumed hello", &mut sink_c2);
        let wire = std::mem::take(&mut sink_c2.outbound);
        server2.feed_ciphertext(&mut wire.as_slice(), &mut sink_s2);
        assert_eq!(sink_s2.app_data, vec![b"resumed hello".to_vec()]);
    }

    #[test]
    fn application_data_before_handshake_complete_is_rejected() {
        let (client_cfg, _server_cfg) = configs();
        let mut client = Tls12RecordEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        sink.outbound.clear();
        client.send_application_data(b"too early", &mut sink);
        assert!(sink.events.iter().any(|e| e.starts_with("protocol_error")));
        assert!(sink.outbound.is_empty());
    }
}
