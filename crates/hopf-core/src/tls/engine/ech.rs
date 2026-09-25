// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Encrypted Client Hello (RFC 9849) handling for [`HandshakeEngine`].
//!
//! Lives under `engine` so it can use the engine's private state, but is kept
//! apart from the plain TLS 1.3 flow: `engine.rs` only calls the hooks below.
//!
//! **Client.** A real offer builds a ClientHelloInner, HPKE-seals it into a
//! ClientHelloOuter, and keeps *two* transcripts - inner (`self.transcript`)
//! and outer - because which one the handshake continues on is only known
//! when the server's first message reveals acceptance. Rejection swaps the
//! outer transcript in, verifies the certificate for `public_name`, and after
//! the server's Finished aborts with `ech_required` (never completing).
//!
//! **Server.** An outer ClientHello is unwrapped to the inner one before the
//! normal `on_client_hello` runs, so the rest of the handshake (transcript,
//! key schedule, HelloRetryRequest) sees only ClientHelloInner. The
//! acceptance signal is patched into ServerHello / HelloRetryRequest.

use bytes::Bytes;
use getrandom::getrandom;

use crate::crypto::hkdf::ech_accept_confirmation;
use crate::crypto::hpke::{self, Aead, HpkePrivateKey, Kdf, Kem, Suite};

use super::super::ech::wire::{
    self, confirmation_eq, hello_retry_request_with_zeroed_confirmation, parse_ech_client_hello,
    server_hello_confirmation, server_hello_with_zeroed_confirmation, ClientHelloView, EchClientHello,
    WireError, INNER_EXTENSION_BODY,
};
use super::super::ech::{EchConfig, EchServerConfig};
use super::super::handshake::collect::{MessageCollector, ParsedIncoming};
use super::super::handshake::messages::{build_client_hello_with_ech, ext};
use super::super::handshake::parser::HandshakeParser;
use super::super::handshake::{
    ClientHelloParams, HandshakeMessage, HandshakeType, ParsedClientHello, ParsedEncryptedExtensions,
    ParsedServerHello, Transcript,
};
use super::super::sink::{AlertDescription, TlsEventSink, TlsProtocolError};
use super::{HandshakeEngine, HandshakeMode, State};

/// A real (non-GREASE) ECH offer.
struct RealClientEch {
    config: EchConfig,
    suite: Suite,
    ctx: hpke::Context,
    /// `enc` for the first ClientHelloOuter (empty in the second).
    enc: Vec<u8>,
}

/// Client-side ECH state, present whenever ECH or GREASE is configured.
pub(super) struct EchClientState {
    /// `None` for GREASE.
    real: Option<RealClientEch>,
    /// Transcript of the ClientHelloOuter flow (real offers only).
    outer_transcript: Transcript,
    /// Body of the first ClientHelloOuter's `encrypted_client_hello`: copied
    /// verbatim into a second flight that is not ECH-accepted (GREASE, or a
    /// rejection surfaced in a HelloRetryRequest).
    first_outer_ech_ext: Vec<u8>,
    /// Acceptance, once the server's first message has told us.
    accepted: Option<bool>,
    outer_random: [u8; 32],
    /// The server's `retry_configs` from EncryptedExtensions.
    retry_configs: Option<Bytes>,
}

impl EchClientState {
    fn public_name(&self) -> Option<&str> {
        self.real.as_ref().map(|r| r.config.public_name.as_str())
    }
}

/// Server-side ECH state.
#[derive(Default)]
pub(super) struct EchServerState {
    accepted: Option<AcceptedEch>,
    /// The client sent an `encrypted_client_hello` that we could not decrypt:
    /// EncryptedExtensions must carry `retry_configs`.
    rejected: bool,
}

struct AcceptedEch {
    ctx: hpke::Context,
    kdf_id: u16,
    aead_id: u16,
    config_id: u8,
    /// `ClientHelloInner.random`, the key of the acceptance confirmation.
    inner_random: [u8; 32],
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    let _ = getrandom(&mut b);
    b
}

fn parse_client_hello_wire(wire: &[u8]) -> Option<ParsedClientHello> {
    let mut parser = HandshakeParser::new();
    let mut collector = MessageCollector::default();
    let mut input = wire;
    parser.receive(&mut input, &mut collector);
    match collector.take_parsed(HandshakeType::ClientHello)? {
        ParsedIncoming::ClientHello(ch) => Some(ch),
        _ => None,
    }
}

fn wire_alert(e: WireError) -> AlertDescription {
    match e {
        WireError::Decode => AlertDescription::DecodeError,
        WireError::Illegal => AlertDescription::IllegalParameter,
    }
}

/// Whether the inner ClientHello offers only TLS 1.3+ (RFC 9849 §7.1: it
/// must not offer TLS 1.2 or below, and must offer a version list at all).
fn offers_only_tls13(view: &ClientHelloView<'_>, dtls: bool) -> bool {
    let Some(e) = view.find(ext::SUPPORTED_VERSIONS) else {
        return false;
    };
    let Some((&n, list)) = e.data.split_first() else {
        return false;
    };
    if usize::from(n) != list.len() || list.is_empty() || list.len() % 2 != 0 {
        return false;
    }
    list.chunks_exact(2).all(|p| {
        let v = u16::from_be_bytes([p[0], p[1]]);
        // DTLS versions count downwards: 1.3 is 0xfefc, 1.2 0xfefd.
        if dtls { v <= 0xfefc } else { v >= 0x0304 }
    })
}

impl HandshakeEngine {
    // -----------------------------------------------------------------
    // Client
    // -----------------------------------------------------------------

    /// Select a config (or GREASE) before the first ClientHello.
    pub(super) fn ech_client_init<S: TlsEventSink>(&mut self, sink: &mut S) -> bool {
        let Some(cfg) = self.config.ech_client.clone() else {
            return true;
        };
        let outer_random = random_bytes::<32>();
        match super::super::ech::select_config(&cfg.configs, &cfg.preference) {
            Some(sel) => {
                let config = sel.config.clone();
                let Ok((enc, ctx)) = hpke::setup_base_sender(sel.suite, &config.public_key, &config.hpke_info())
                else {
                    self.fail(sink, AlertDescription::InternalError, "ECH HPKE setup failed");
                    return false;
                };
                self.ech_client = Some(EchClientState {
                    real: Some(RealClientEch { config, suite: sel.suite, ctx, enc }),
                    outer_transcript: Transcript::new(),
                    first_outer_ech_ext: Vec::new(),
                    accepted: None,
                    outer_random,
                    retry_configs: None,
                });
            }
            None if cfg.grease => {
                self.ech_client = Some(EchClientState {
                    real: None,
                    outer_transcript: Transcript::new(),
                    first_outer_ech_ext: Vec::new(),
                    accepted: None,
                    outer_random,
                    retry_configs: None,
                });
            }
            None => {}
        }
        true
    }

    /// Whether this handshake carries a real (encrypting) ECH offer.
    pub(super) fn ech_client_is_real(&self) -> bool {
        self.ech_client.as_ref().is_some_and(|e| e.real.is_some())
    }

    /// The name the server certificate must be valid for: `public_name` once
    /// the server has rejected ECH, the configured name otherwise.
    pub(super) fn verification_name(&self) -> Option<&str> {
        match &self.ech_client {
            Some(e) if e.accepted == Some(false) => e.public_name(),
            _ => self.config.server_name.as_deref(),
        }
    }

    /// The `encrypted_client_hello` body for a GREASE ClientHello, or `None`
    /// when not greasing (RFC 9849 §6.2). The second flight copies the first.
    pub(super) fn ech_grease_extension(&mut self, params: &ClientHelloParams, is_retry: bool) -> Option<Vec<u8>> {
        let st = self.ech_client.as_ref()?;
        if st.real.is_some() {
            return None;
        }
        if is_retry {
            return Some(st.first_outer_ech_ext.clone());
        }
        // Length the EncodedClientHelloInner would have, padded as a real
        // client would (with a plausible maximum_name_length).
        let mut probe = params.clone();
        probe.psk = None;
        probe.cookie = None;
        let body_len = build_client_hello_with_ech(&probe, &INNER_EXTENSION_BODY).body.len();
        let sni_len = params.server_name.as_ref().map(|n| n.len());
        let l = body_len + wire::padding_len(body_len, sni_len, 32);

        let pick = random_bytes::<1>()[0] & 1;
        let (kdf, aead) = if pick == 0 {
            (Kdf::HkdfSha256, Aead::Aes128Gcm)
        } else {
            (Kdf::HkdfSha256, Aead::ChaCha20Poly1305)
        };
        let enc = HpkePrivateKey::generate(Kem::DhkemX25519HkdfSha256)
            .and_then(|k| k.public_key())
            .ok()?;
        let mut payload = vec![0u8; l + aead.tag_len()];
        let _ = getrandom(&mut payload);
        let ext = wire::encode_ech_outer(kdf.id(), aead.id(), random_bytes::<1>()[0], &enc, &payload);
        self.ech_client.as_mut()?.first_outer_ech_ext = ext.clone();
        Some(ext)
    }

    /// Send the ClientHello for a real ECH offer (both flights). Returns
    /// `false` after failing the handshake.
    pub(super) fn ech_client_send_real<S: TlsEventSink>(
        &mut self,
        params: ClientHelloParams,
        is_retry: bool,
        sink: &mut S,
    ) -> bool {
        let dtls = self.config.mode == HandshakeMode::Dtls;
        let Some(st) = self.ech_client.as_mut() else {
            return false;
        };
        let Some(real) = st.real.as_mut() else {
            return false;
        };
        let public_name = real.config.public_name.clone();

        if st.accepted == Some(false) {
            // The server rejected ECH in its HelloRetryRequest: the handshake
            // continues on the outer flow. Resend an outer-shaped hello that
            // carries the first flight's ECH extension verbatim.
            let mut outer = params;
            outer.random = st.outer_random;
            outer.server_name = Some(public_name);
            outer.alpn = Vec::new();
            outer.early_data = false;
            let msg = build_client_hello_with_ech(&outer, &st.first_outer_ech_ext);
            self.emit_outgoing(&msg, sink);
            return true;
        }

        // ClientHelloInner.
        let inner_msg = build_client_hello_with_ech(&params, &INNER_EXTENSION_BODY);
        let inner_body = inner_msg.body.clone();
        let sni_len = params.server_name.as_ref().map(|n| n.len());
        let pad = wire::padding_len(inner_body.len(), sni_len, real.config.maximum_name_length);
        let mut encoded = inner_body.to_vec();
        encoded.resize(encoded.len() + pad, 0);

        // ClientHelloOuter, first with a zero placeholder payload.
        let mut outer = params;
        outer.random = st.outer_random;
        outer.server_name = Some(public_name);
        outer.alpn = Vec::new();
        outer.early_data = false;
        outer.psk = None;
        outer.cookie = None;
        let enc = if is_retry { Vec::new() } else { std::mem::take(&mut real.enc) };
        let (kdf_id, aead_id, config_id) = (real.suite.kdf.id(), real.suite.aead.id(), real.config.config_id);
        let placeholder = vec![0u8; encoded.len() + real.suite.aead.tag_len()];
        let ech0 = wire::encode_ech_outer(kdf_id, aead_id, config_id, &enc, &placeholder);
        let outer0 = build_client_hello_with_ech(&outer, &ech0);

        let aad = {
            let Ok(view) = ClientHelloView::parse(&outer0.body, dtls) else {
                self.fail(sink, AlertDescription::InternalError, "ECH outer construction failed");
                return false;
            };
            let Some(e) = view.find(ext::ENCRYPTED_CLIENT_HELLO) else {
                self.fail(sink, AlertDescription::InternalError, "ECH outer construction failed");
                return false;
            };
            let Ok(EchClientHello::Outer(o)) = parse_ech_client_hello(e.data) else {
                self.fail(sink, AlertDescription::InternalError, "ECH outer construction failed");
                return false;
            };
            wire::outer_aad(&outer0.body, e, &o)
        };
        let Ok(payload) = real.ctx.seal(&aad, &encoded) else {
            self.fail(sink, AlertDescription::InternalError, "ECH encryption failed");
            return false;
        };
        let ech = wire::encode_ech_outer(kdf_id, aead_id, config_id, &enc, &payload);
        if !is_retry {
            st.first_outer_ech_ext = ech.clone();
        }
        let outer_msg = build_client_hello_with_ech(&outer, &ech);

        self.transcript.add_message(&inner_msg.encode());
        let outer_wire = outer_msg.encode();
        st.outer_transcript.add_message(&outer_wire);
        sink.handshake_data_ready(&outer_wire);
        true
    }

    /// Server's first message was a HelloRetryRequest: determine acceptance
    /// (RFC 9849 §6.1.4) and select the transcript to continue with.
    pub(super) fn ech_client_on_hello_retry_request<S: TlsEventSink>(
        &mut self,
        sh: &ParsedServerHello,
        wire_msg: &[u8],
        sink: &mut S,
    ) -> bool {
        let dtls = self.config.mode == HandshakeMode::Dtls;
        let Some(st) = self.ech_client.as_ref() else {
            return true;
        };
        if let Some(ech) = sh.ech.as_ref() {
            if ech.len() != 8 {
                self.fail(sink, AlertDescription::DecodeError, "malformed ECH HelloRetryRequest extension");
                return false;
            }
        }
        if st.real.is_none() {
            // GREASE: the extension only had to be well formed.
            return true;
        }
        let accepted = match (sh.ech.as_ref(), hello_retry_request_with_zeroed_confirmation(wire_msg)) {
            (Some(theirs), Some(zeroed)) => {
                let mut t = self.transcript.clone();
                let ch1 = t.hash();
                t.retry(ch1);
                t.add_message(&zeroed);
                let expected = ech_accept_confirmation(
                    &self.client_hello_random.unwrap_or([0; 32]),
                    "hrr ech accept confirmation",
                    t.hash().as_bytes(),
                    dtls,
                );
                let mut got = [0u8; 8];
                got.copy_from_slice(theirs);
                confirmation_eq(&expected, &got)
            }
            _ => false,
        };
        self.ech_client_settle(accepted);
        true
    }

    /// Server's first message was a ServerHello (no HelloRetryRequest yet, or
    /// after one): check acceptance and select the transcript.
    pub(super) fn ech_client_on_server_hello<S: TlsEventSink>(&mut self, wire_msg: &[u8], sink: &mut S) -> bool {
        let dtls = self.config.mode == HandshakeMode::Dtls;
        let Some(st) = self.ech_client.as_ref() else {
            return true;
        };
        if st.real.is_none() {
            return true;
        }
        let matches = match (
            server_hello_confirmation(wire_msg),
            server_hello_with_zeroed_confirmation(wire_msg),
        ) {
            (Some(theirs), Some(zeroed)) => {
                let mut t = self.transcript.clone();
                t.add_message(&zeroed);
                let expected = ech_accept_confirmation(
                    &self.client_hello_random.unwrap_or([0; 32]),
                    "ech accept confirmation",
                    t.hash().as_bytes(),
                    dtls,
                );
                confirmation_eq(&expected, &theirs)
            }
            _ => false,
        };
        match st.accepted {
            // A HelloRetryRequest accepted ECH: the ServerHello must too.
            Some(true) if !matches => {
                self.fail(sink, AlertDescription::IllegalParameter, "ServerHello did not confirm ECH accepted in HelloRetryRequest");
                false
            }
            // Already rejected: stay on the outer flow.
            Some(false) => true,
            Some(true) => true,
            None => {
                self.ech_client_settle(matches);
                true
            }
        }
    }

    /// Record the acceptance decision and, on rejection, continue on the outer
    /// transcript.
    fn ech_client_settle(&mut self, accepted: bool) {
        let Some(st) = self.ech_client.as_mut() else {
            return;
        };
        st.accepted = Some(accepted);
        if !accepted {
            self.transcript = std::mem::take(&mut st.outer_transcript);
        }
    }

    /// EncryptedExtensions carried an `encrypted_client_hello` extension.
    pub(super) fn ech_client_on_encrypted_extensions<S: TlsEventSink>(
        &mut self,
        ee: &ParsedEncryptedExtensions,
        sink: &mut S,
    ) -> bool {
        let Some(raw) = ee.ech.as_ref() else {
            return true;
        };
        let Some(st) = self.ech_client.as_mut() else {
            return true;
        };
        // Both real and GREASE offers require the value to be a valid
        // ECHConfigList.
        if EchConfig::parse_list(raw).is_err() {
            self.fail(sink, AlertDescription::DecodeError, "malformed ECH retry_configs");
            return false;
        }
        match st.accepted {
            // The server accepted the inner hello: it must not send this.
            Some(true) => {
                self.fail(sink, AlertDescription::UnsupportedExtension, "ECH retry_configs sent after accepting ECH");
                false
            }
            Some(false) => {
                st.retry_configs = Some(raw.clone());
                true
            }
            // GREASE: syntactic check only; never saved.
            None => true,
        }
    }

    /// True once the server has rejected a real ECH offer.
    pub(super) fn ech_client_rejected(&self) -> bool {
        self.ech_client.as_ref().is_some_and(|e| e.real.is_some() && e.accepted == Some(false))
    }

    /// The server rejected ECH but the outer handshake authenticated for
    /// `public_name` and completed: abort with `ech_required` (RFC 9849
    /// §6.1.6), reporting `retry_configs`, without ever finishing.
    pub(super) fn ech_client_abort_rejected<S: TlsEventSink>(&mut self, sink: &mut S) {
        let retry = self.ech_client.as_mut().and_then(|e| e.retry_configs.take());
        if self.state != State::Failed {
            self.state = State::Failed;
            let msg = if retry.is_some() {
                "server rejected ECH and supplied retry_configs"
            } else {
                "server rejected ECH"
            };
            sink.protocol_error(
                TlsProtocolError::new(AlertDescription::EchRequired, msg).with_ech_retry_configs(retry),
            );
        }
    }

    // -----------------------------------------------------------------
    // Server
    // -----------------------------------------------------------------

    /// Unwrap an outer ClientHello (RFC 9849 §7.1, §7.1.1). Returns the
    /// ClientHello the handshake should proceed with - the inner one on
    /// acceptance, the unchanged outer one otherwise - or `None` after
    /// failing the handshake.
    pub(super) fn ech_server_unwrap<S: TlsEventSink>(
        &mut self,
        ch: ParsedClientHello,
        wire_msg: Bytes,
        sink: &mut S,
    ) -> Option<(ParsedClientHello, Bytes)> {
        let Some(server_cfg) = self.config.ech_server.clone() else {
            return Some((ch, wire_msg));
        };
        let second = self.state == State::HelloRetryRequestSent;
        if second && self.ech_server.accepted.is_none() {
            // ECH was not accepted on the first flight: no decryption now.
            return Some((ch, wire_msg));
        }
        let Some(raw) = ch.ech.clone() else {
            if second {
                self.fail(sink, AlertDescription::MissingExtension, "second ClientHello lacks encrypted_client_hello");
                return None;
            }
            return Some((ch, wire_msg));
        };
        let dtls = self.config.mode == HandshakeMode::Dtls;

        let outer = match parse_ech_client_hello(&raw) {
            Ok(EchClientHello::Outer(o)) => o,
            Ok(EchClientHello::Inner) => {
                // Never legitimate on a connection's first-hop hello.
                self.fail(sink, AlertDescription::IllegalParameter, "ECH inner ClientHello received directly");
                return None;
            }
            Err(e) => {
                self.fail(sink, wire_alert(e), "malformed encrypted_client_hello extension");
                return None;
            }
        };
        let body = &wire_msg[4..];
        let Ok(view) = ClientHelloView::parse(body, dtls) else {
            self.fail(sink, AlertDescription::DecodeError, "malformed ClientHello");
            return None;
        };
        let Some(ech_ext) = view.find(ext::ENCRYPTED_CLIENT_HELLO) else {
            self.fail(sink, AlertDescription::InternalError, "ECH extension vanished");
            return None;
        };
        let aad = wire::outer_aad(body, ech_ext, &outer);

        let plaintext = if second {
            let acc = self.ech_server.accepted.as_mut().expect("checked above");
            if outer.kdf_id != acc.kdf_id || outer.aead_id != acc.aead_id || outer.config_id != acc.config_id {
                self.fail(sink, AlertDescription::IllegalParameter, "ECH parameters changed across HelloRetryRequest");
                return None;
            }
            if !outer.enc.is_empty() {
                self.fail(sink, AlertDescription::IllegalParameter, "second ClientHelloOuter carries an enc");
                return None;
            }
            match acc.ctx.open(&aad, outer.payload) {
                Ok(pt) => pt,
                Err(_) => {
                    self.fail(sink, AlertDescription::DecryptError, "ECH decryption failed after HelloRetryRequest");
                    return None;
                }
            }
        } else {
            match Self::ech_server_try_decrypt(&server_cfg, &outer, &aad) {
                Some((ctx, pt)) => {
                    self.ech_server.accepted = Some(AcceptedEch {
                        ctx,
                        kdf_id: outer.kdf_id,
                        aead_id: outer.aead_id,
                        config_id: outer.config_id,
                        inner_random: [0; 32],
                    });
                    pt
                }
                None => {
                    // Undecryptable (or GREASE): carry on with the outer
                    // hello and offer retry_configs in EncryptedExtensions.
                    self.ech_server.rejected = true;
                    return Some((ch, wire_msg));
                }
            }
        };

        let inner_body = match wire::decode_inner(&plaintext, &view, dtls) {
            Ok(b) => b,
            Err(e) => {
                self.fail(sink, wire_alert(e), "invalid EncodedClientHelloInner");
                return None;
            }
        };
        let inner_ok = ClientHelloView::parse(&inner_body, dtls).ok().is_some_and(|iv| {
            let marked_inner = iv
                .find(ext::ENCRYPTED_CLIENT_HELLO)
                .is_some_and(|e| matches!(parse_ech_client_hello(e.data), Ok(EchClientHello::Inner)));
            marked_inner && offers_only_tls13(&iv, dtls)
        });
        if !inner_ok {
            self.fail(sink, AlertDescription::IllegalParameter, "ClientHelloInner is not a valid TLS 1.3 inner hello");
            return None;
        }
        let mut inner_wire = Vec::with_capacity(4 + inner_body.len());
        inner_wire.push(HandshakeType::ClientHello as u8);
        inner_wire.extend_from_slice(&(inner_body.len() as u32).to_be_bytes()[1..]);
        inner_wire.extend_from_slice(&inner_body);
        let Some(inner_ch) = parse_client_hello_wire(&inner_wire) else {
            self.fail(sink, AlertDescription::DecodeError, "malformed ClientHelloInner");
            return None;
        };
        if let Some(acc) = self.ech_server.accepted.as_mut() {
            acc.inner_random = inner_ch.random;
        }
        Some((inner_ch, Bytes::from(inner_wire)))
    }

    fn ech_server_try_decrypt(
        server_cfg: &EchServerConfig,
        outer: &wire::EchOuter<'_>,
        aad: &[u8],
    ) -> Option<(hpke::Context, Vec<u8>)> {
        let kdf = Kdf::from_id(outer.kdf_id)?;
        let aead = Aead::from_id(outer.aead_id)?;
        for key in server_cfg.candidates(outer.config_id) {
            if !key.config.advertises(outer.kdf_id, outer.aead_id) {
                continue;
            }
            let Some(kem) = key.config.kem() else {
                continue;
            };
            let suite = Suite { kem, kdf, aead };
            let Ok(mut ctx) = hpke::setup_base_recipient(suite, outer.enc, &key.key, &key.config.hpke_info()) else {
                continue;
            };
            if let Ok(pt) = ctx.open(aad, outer.payload) {
                return Some((ctx, pt));
            }
        }
        None
    }

    /// `retry_configs` to put in EncryptedExtensions, when the client offered
    /// ECH and it was not accepted.
    pub(super) fn ech_server_retry_configs(&self) -> Option<Vec<u8>> {
        if !self.ech_server.rejected {
            return None;
        }
        self.config.ech_server.as_ref()?.retry_configs()
    }

    /// A HelloRetryRequest carrying the ECH acceptance confirmation
    /// (RFC 9849 §7.2.1). The transcript must already have been through
    /// [`Transcript::retry`] with ClientHelloInner1's hash.
    pub(super) fn ech_server_confirm_hello_retry_request(
        &self,
        build: impl Fn(Option<&[u8; 8]>) -> HandshakeMessage,
    ) -> HandshakeMessage {
        let dtls = self.config.mode == HandshakeMode::Dtls;
        let Some(acc) = self.ech_server.accepted.as_ref() else {
            return build(None);
        };
        let zeroed = build(Some(&[0u8; 8]));
        let mut t = self.transcript.clone();
        t.add_message(&zeroed.encode());
        let conf = ech_accept_confirmation(
            &acc.inner_random,
            "hrr ech accept confirmation",
            t.hash().as_bytes(),
            dtls,
        );
        build(Some(&conf))
    }

    /// A ServerHello whose `random` ends in the ECH acceptance confirmation
    /// (RFC 9849 §7.2). The transcript must already contain ClientHelloInner.
    pub(super) fn ech_server_confirm_server_hello(
        &self,
        random: [u8; 32],
        build: impl Fn(&[u8; 32]) -> HandshakeMessage,
    ) -> HandshakeMessage {
        let dtls = self.config.mode == HandshakeMode::Dtls;
        let Some(acc) = self.ech_server.accepted.as_ref() else {
            return build(&random);
        };
        let mut zeroed_random = random;
        zeroed_random[24..].fill(0);
        let mut t = self.transcript.clone();
        t.add_message(&build(&zeroed_random).encode());
        let conf = ech_accept_confirmation(&acc.inner_random, "ech accept confirmation", t.hash().as_bytes(), dtls);
        let mut final_random = random;
        final_random[24..].copy_from_slice(&conf);
        build(&final_random)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;

    use super::*;
    use crate::crypto::kx_policy::KxPolicy;
    use crate::crypto::trust::TrustStore;
    use crate::security::SecurityInfo;
    use crate::tls::ech::{EchClientConfig, EchServerConfig, EchServerKey, HpkeCipherSuite};
    use crate::tls::engine::{HandshakeConfig, HandshakeEngine, HandshakeRole, ServerCredentials};
    use crate::tls::sink::QuicSecrets;

    const PUBLIC: &str = "public.example";
    const INNER: &str = "inner.example";

    #[derive(Default)]
    struct Sink {
        out: Vec<Bytes>,
        errors: Vec<TlsProtocolError>,
        info: Option<SecurityInfo>,
    }

    impl TlsEventSink for Sink {
        fn handshake_data_ready(&mut self, data: &[u8]) {
            self.out.push(Bytes::copy_from_slice(data));
        }
        fn handshake_complete(&mut self, info: SecurityInfo, _q: Option<QuicSecrets>) {
            self.info = Some(info);
        }
        fn verification_requested(&mut self, _req: crate::tls::sink::VerifyRequest) {}
        fn protocol_error(&mut self, err: TlsProtocolError) {
            self.errors.push(err);
        }
        fn timeout(&mut self, _kind: crate::tls::sink::TlsTimerKind) {}
        fn peer_closed(&mut self) {}
    }

    fn creds_for(names: &[&str]) -> ServerCredentials {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        ServerCredentials {
            cert_chain: vec![Bytes::copy_from_slice(cert.der())],
            signing_key_pkcs8: Bytes::from(key_pair.serialize_der()),
        }
    }

    fn server_key(config_id: u8) -> (EchServerKey, EchConfig) {
        let suites = vec![
            HpkeCipherSuite { kdf_id: 1, aead_id: 1 },
            HpkeCipherSuite { kdf_id: 1, aead_id: 3 },
        ];
        let (config, key) = EchConfig::generate(config_id, Kem::DhkemX25519HkdfSha256, suites, 32, PUBLIC).unwrap();
        (EchServerKey::new(config.clone(), key).unwrap(), config)
    }

    fn server_cfg(creds: &ServerCredentials, ech: Option<Vec<EchServerKey>>, kx: KxPolicy) -> HandshakeConfig {
        HandshakeConfig {
            role: HandshakeRole::Server,
            mode: HandshakeMode::TcpRecordLayer,
            alpn: vec![Bytes::from_static(b"secret-proto"), Bytes::from_static(b"other")],
            server: Some(creds.clone()),
            kx_policy: kx,
            ech_server: ech.map(|keys| Arc::new(EchServerConfig::new(keys))),
            ..Default::default()
        }
    }

    fn client_cfg(
        creds: &ServerCredentials,
        ech: Option<EchClientConfig>,
        kx: KxPolicy,
    ) -> HandshakeConfig {
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::TcpRecordLayer,
            alpn: vec![Bytes::from_static(b"secret-proto")],
            server_name: Some(INNER.into()),
            kx_policy: kx,
            trust_store: Some(trust),
            ech_client: ech,
            ..Default::default()
        }
    }

    struct Outcome {
        client: HandshakeEngine,
        server: HandshakeEngine,
        client_sink: Sink,
        server_sink: Sink,
        /// Every byte the client sent, in order.
        client_sent: Vec<u8>,
    }

    /// Run a handshake to quiescence. `tamper` may rewrite the client's first
    /// flight in transit.
    fn run(client: HandshakeConfig, server: HandshakeConfig, tamper: impl Fn(&mut Vec<u8>)) -> Outcome {
        let mut client = HandshakeEngine::new(client);
        let mut server = HandshakeEngine::new(server);
        let (mut cs, mut ss) = (Sink::default(), Sink::default());
        let mut client_sent = Vec::new();
        client.start(&mut cs);
        let mut first = true;
        for _ in 0..6 {
            for chunk in std::mem::take(&mut cs.out) {
                let mut data = chunk.to_vec();
                client_sent.extend_from_slice(&data);
                if first {
                    tamper(&mut data);
                    first = false;
                }
                server.feed_handshake_data(&mut &data[..], &mut ss);
            }
            for chunk in std::mem::take(&mut ss.out) {
                client.feed_handshake_data(&mut &chunk[..], &mut cs);
            }
        }
        Outcome { client, server, client_sink: cs, server_sink: ss, client_sent }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn assert_completes(o: &Outcome) {
        assert!(o.client.is_complete(), "client errors: {:?}", o.client_sink.errors);
        assert!(o.server.is_complete(), "server errors: {:?}", o.server_sink.errors);
    }

    #[test]
    fn accepted_ech_hides_the_real_name_and_completes() {
        let creds = creds_for(&[INNER, PUBLIC]);
        let (key, config) = server_key(7);
        let client = client_cfg(&creds, Some(EchClientConfig::new(vec![config])), KxPolicy::classical_only());
        let o = run(client, server_cfg(&creds, Some(vec![key]), KxPolicy::classical_only()), |_| {});
        assert_completes(&o);
        // The server saw the inner SNI, and the wire never carried it.
        assert_eq!(o.server_sink.info.as_ref().unwrap().sni(), Some(INNER));
        assert!(contains(&o.client_sent, PUBLIC.as_bytes()));
        assert!(!contains(&o.client_sent, INNER.as_bytes()), "real SNI leaked");
        assert!(!contains(&o.client_sent, b"secret-proto"), "real ALPN leaked");
        // The inner ALPN was negotiated, not the (absent) outer one.
        assert_eq!(
            o.client_sink.info.as_ref().unwrap().alpn().map(|a| a.to_vec()),
            Some(b"secret-proto".to_vec())
        );
    }

    #[test]
    fn accepted_ech_survives_a_hello_retry_request() {
        // The client offers a hybrid key share the classical-only server
        // refuses: the server sends an HRR (with the ECH confirmation) and the
        // client's second ClientHelloOuter reuses the HPKE context.
        let creds = creds_for(&[INNER, PUBLIC]);
        let (key, config) = server_key(7);
        let client = client_cfg(&creds, Some(EchClientConfig::new(vec![config])), KxPolicy::default());
        let o = run(client, server_cfg(&creds, Some(vec![key]), KxPolicy::classical_only()), |_| {});
        assert_completes(&o);
        assert!(!contains(&o.client_sent, INNER.as_bytes()), "real SNI leaked in either flight");
    }

    #[test]
    fn unknown_key_is_rejected_and_reported_with_retry_configs() {
        let creds = creds_for(&[PUBLIC]);
        let (_stale_key, stale_config) = server_key(7);
        let (current_key, current_config) = server_key(8);
        let client = client_cfg(&creds, Some(EchClientConfig::new(vec![stale_config])), KxPolicy::classical_only());
        let o = run(client, server_cfg(&creds, Some(vec![current_key]), KxPolicy::classical_only()), |_| {});
        // Authenticated for the public name, then aborted: never a success.
        assert!(!o.client.is_complete());
        assert!(o.client_sink.info.is_none());
        let err = o.client_sink.errors.first().expect("client must fail");
        assert_eq!(err.alert, AlertDescription::EchRequired);
        let retry = err.ech_retry_configs.as_ref().expect("retry_configs reported");
        assert_eq!(&retry[..], &EchConfig::encode_list(&[current_config]).unwrap()[..]);
        assert!(!o.server.is_complete(), "the client aborts before its Finished");
    }

    #[test]
    fn rejected_ech_verifies_the_certificate_for_the_public_name() {
        // A certificate valid only for the inner name must be refused when ECH
        // is rejected, because the handshake then continues as the public name.
        let creds = creds_for(&[INNER]);
        let (_k, stale) = server_key(7);
        let (current, _) = server_key(8);
        let client = client_cfg(&creds, Some(EchClientConfig::new(vec![stale])), KxPolicy::classical_only());
        let o = run(client, server_cfg(&creds, Some(vec![current]), KxPolicy::classical_only()), |_| {});
        let err = o.client_sink.errors.first().expect("client must fail");
        assert_eq!(err.alert, AlertDescription::BadCertificate);
        assert!(err.ech_retry_configs.is_none());
    }

    #[test]
    fn server_without_ech_ignores_the_extension_and_client_reports_rejection() {
        let creds = creds_for(&[PUBLIC]);
        let (_k, config) = server_key(7);
        let client = client_cfg(&creds, Some(EchClientConfig::new(vec![config])), KxPolicy::classical_only());
        let o = run(client, server_cfg(&creds, None, KxPolicy::classical_only()), |_| {});
        let err = o.client_sink.errors.first().expect("client must fail");
        assert_eq!(err.alert, AlertDescription::EchRequired);
        assert!(err.ech_retry_configs.is_none(), "a non-ECH server has nothing to retry with");
    }

    #[test]
    fn tampering_with_the_outer_hello_defeats_decryption() {
        // ClientHelloOuterAAD binds the outer hello: changing any byte of it
        // (here a byte of the outer random) means the payload no longer
        // opens, and the server falls back to the outer hello.
        let creds = creds_for(&[PUBLIC]);
        let (key, config) = server_key(7);
        let client = client_cfg(&creds, Some(EchClientConfig::new(vec![config])), KxPolicy::classical_only());
        let o = run(
            client,
            server_cfg(&creds, Some(vec![key]), KxPolicy::classical_only()),
            |wire| wire[4 + 2 + 5] ^= 0xff,
        );
        assert!(o.server.ech_server.accepted.is_none());
        assert!(o.server.ech_server.rejected);
        // (The client then fails on its own transcript mismatch, since the
        // hello it sent is not the one the server saw.)
        assert!(!o.client.is_complete());
    }

    #[test]
    fn grease_is_ignored_by_servers_with_and_without_ech() {
        let creds = creds_for(&[INNER]);
        // A plain server.
        let o = run(
            client_cfg(&creds, Some(EchClientConfig::grease_only()), KxPolicy::classical_only()),
            server_cfg(&creds, None, KxPolicy::classical_only()),
            |_| {},
        );
        assert_completes(&o);
        assert!(contains(&o.client_sent, &[0xfe, 0x0d]), "GREASE extension must be on the wire");
        // An ECH server cannot decrypt GREASE, answers with retry_configs, and
        // a greasing client must ignore them.
        let (key, _) = server_key(7);
        let o = run(
            client_cfg(&creds, Some(EchClientConfig::grease_only()), KxPolicy::classical_only()),
            server_cfg(&creds, Some(vec![key]), KxPolicy::classical_only()),
            |_| {},
        );
        assert_completes(&o);
        assert!(o.server.ech_server.rejected);
    }

    #[test]
    fn grease_survives_a_hello_retry_request() {
        let creds = creds_for(&[INNER]);
        let o = run(
            client_cfg(&creds, Some(EchClientConfig::grease_only()), KxPolicy::default()),
            server_cfg(&creds, None, KxPolicy::classical_only()),
            |_| {},
        );
        assert_completes(&o);
    }

    #[test]
    fn plain_client_against_an_ech_server_is_unaffected() {
        let creds = creds_for(&[INNER]);
        let (key, _) = server_key(7);
        let o = run(
            client_cfg(&creds, None, KxPolicy::classical_only()),
            server_cfg(&creds, Some(vec![key]), KxPolicy::classical_only()),
            |_| {},
        );
        assert_completes(&o);
        assert!(!o.server.ech_server.rejected, "no ECH offered, so no retry_configs owed");
    }

    #[test]
    fn a_retry_with_the_supplied_configs_succeeds() {
        let creds = creds_for(&[INNER, PUBLIC]);
        let (_old, stale) = server_key(7);
        let (current_key, _) = server_key(8);
        let server = || server_cfg(&creds, Some(vec![current_key.clone()]), KxPolicy::classical_only());
        let o = run(
            client_cfg(&creds, Some(EchClientConfig::new(vec![stale])), KxPolicy::classical_only()),
            server(),
            |_| {},
        );
        let retry = o.client_sink.errors[0].ech_retry_configs.clone().expect("retry_configs");
        let o = run(
            client_cfg(&creds, Some(EchClientConfig::from_config_list(&retry).unwrap()), KxPolicy::classical_only()),
            server(),
            |_| {},
        );
        assert_completes(&o);
        assert_eq!(o.server_sink.info.as_ref().unwrap().sni(), Some(INNER));
    }

    #[test]
    fn a_directly_received_inner_hello_is_refused() {
        // type=inner in a hello that came straight off the network.
        let creds = creds_for(&[INNER]);
        let (key, _) = server_key(7);
        let mut server = HandshakeEngine::new(server_cfg(&creds, Some(vec![key]), KxPolicy::classical_only()));
        let local = crate::crypto::kx::LocalKeyShare::generate(crate::crypto::kx::NamedGroup::X25519).unwrap();
        let params = ClientHelloParams {
            random: [1; 32],
            cipher_suites: crate::tls::SUPPORTED_CIPHER_SUITES.to_vec(),
            key_share: crate::tls::handshake::KeyShareEntry {
                group: local.group().code(),
                share: local.client_share_bytes(),
            },
            supported_groups: vec![local.group().code()],
            alpn: Vec::new(),
            server_name: Some(INNER.into()),
            transport_parameters: None,
            early_data: false,
            psk: None,
            cookie: None,
            record_size_limit: None,
            legacy_version: 0x0303,
        };
        let wire = build_client_hello_with_ech(&params, &INNER_EXTENSION_BODY).encode();
        let mut ss = Sink::default();
        server.feed_handshake_data(&mut &wire[..], &mut ss);
        assert_eq!(ss.errors[0].alert, AlertDescription::IllegalParameter);
    }

    #[test]
    fn a_used_key_is_bound_to_its_own_config() {
        // A config id match is not enough: the key must decrypt.
        let creds = creds_for(&[PUBLIC]);
        let (_real_key, config) = server_key(7);
        let (wrong_key, _) = server_key(7); // same id, different key pair
        let client = client_cfg(&creds, Some(EchClientConfig::new(vec![config])), KxPolicy::classical_only());
        let o = run(client, server_cfg(&creds, Some(vec![wrong_key]), KxPolicy::classical_only()), |_| {});
        assert!(o.server.ech_server.rejected);
        assert_eq!(o.client_sink.errors[0].alert, AlertDescription::EchRequired);
    }
}
