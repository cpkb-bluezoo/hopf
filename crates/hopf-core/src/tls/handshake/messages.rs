// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 handshake message framing (RFC 8446 §4) — no record layer.

use bytes::{Bytes, BytesMut};

use super::verify::SUPPORTED_SIGNATURE_SCHEMES;

/// Handshake message type (RFC 8446 §B.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// ClientHello.
    ClientHello = 1,
    /// ServerHello.
    ServerHello = 2,
    /// NewSessionTicket (post-handshake).
    NewSessionTicket = 4,
    /// EncryptedExtensions.
    EncryptedExtensions = 8,
    /// CertificateRequest (RFC 8446 §4.3.2 — mTLS).
    CertificateRequest = 13,
    /// Certificate.
    Certificate = 11,
    /// CertificateVerify.
    CertificateVerify = 15,
    /// Finished.
    Finished = 20,
    /// KeyUpdate (RFC 8446 §4.6.3 — post-handshake, TCP-TLS-1.3 only).
    KeyUpdate = 24,
}

/// The fixed `ServerHello.random` value that marks a message as a
/// `HelloRetryRequest` rather than a real `ServerHello` (RFC 8446 §4.1.3) —
/// `SHA-256("HelloRetryRequest")`. Wire-identical to `ServerHello`
/// (handshake type 2); this is the only thing that distinguishes them.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// One TLS handshake message (type + body, without the 4-byte header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMessage {
    /// Message type.
    pub msg_type: HandshakeType,
    /// Message body (not including type/length header).
    pub body: Bytes,
}

impl HandshakeMessage {
    /// Serialize with 1-byte type + 3-byte length prefix (RFC 8446 §4).
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(4 + self.body.len());
        out.extend_from_slice(&[self.msg_type as u8]);
        let len = self.body.len();
        out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        out.extend_from_slice(&self.body);
        out.freeze()
    }
}

/// TLS extension type constants used in Phase 2 / 0-RTT.
pub mod ext {
    /// Server Name Indication (RFC 6066).
    pub const SERVER_NAME: u16 = 0;
    /// Application-Layer Protocol Negotiation (RFC 7301).
    pub const ALPN: u16 = 16;
    /// Supported Groups (RFC 8446 §4.2.7).
    pub const SUPPORTED_GROUPS: u16 = 10;
    /// Key Share (RFC 8446 §4.2.8).
    pub const KEY_SHARE: u16 = 51;
    /// QUIC transport parameters (RFC 9001 §8.2).
    pub const QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
    /// Supported Versions (RFC 8446 §4.2.1).
    pub const SUPPORTED_VERSIONS: u16 = 43;
    /// Early data indication (RFC 8446 §4.2.10).
    pub const EARLY_DATA: u16 = 42;
    /// Pre-shared key (RFC 8446 §4.2.11) — must be last in ClientHello.
    pub const PRE_SHARED_KEY: u16 = 41;
    /// PSK key exchange modes (RFC 8446 §4.2.9).
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    /// Signature Algorithms (RFC 8446 §4.2.3) — MUST be sent in ClientHello.
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    /// Signature Algorithms Cert (RFC 8446 §4.2.3 / RFC 9846 §1.4) — which
    /// certificate-chain signature algorithms this engine can verify.
    /// Always sent, never parsed on receipt — see `tls12/messages.rs`'s
    /// matching constant and `crypto-migration-plan.md` for why.
    pub const SIGNATURE_ALGORITHMS_CERT: u16 = 0x0032;
    /// Cookie (RFC 8446 §4.2.2) — carried in `HelloRetryRequest`, echoed
    /// verbatim by the client in its followup ClientHello.
    pub const COOKIE: u16 = 44;
}

/// `psk_dhe_ke` (RFC 8446 §4.2.9).
pub const PSK_DHE_KE: u8 = 1;

/// One offered key share in ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    /// IANA group id.
    pub group: u16,
    /// Key exchange bytes.
    pub share: Bytes,
}

/// Optional PSK identity for a resumptive ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedPsk {
    /// Opaque ticket identity.
    pub identity: Bytes,
    /// Obfuscated ticket age (milliseconds).
    pub obfuscated_ticket_age: u32,
    /// Binder (filled after truncated-CH hash).
    pub binder: [u8; 32],
}

/// Inputs for building a TLS 1.3 ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloParams {
    /// Client random.
    pub random: [u8; 32],
    /// Cipher suites offered, in preference order (e.g.
    /// [`SUPPORTED_CIPHER_SUITES`](super::super::engine::SUPPORTED_CIPHER_SUITES)).
    pub cipher_suites: Vec<u16>,
    /// Key share for the preferred group.
    pub key_share: KeyShareEntry,
    /// Supported groups in preference order.
    pub supported_groups: Vec<u16>,
    /// ALPN protocol names.
    pub alpn: Vec<Bytes>,
    /// SNI hostname.
    pub server_name: Option<String>,
    /// QUIC transport parameters extension (RFC 9001), if any.
    pub transport_parameters: Option<Bytes>,
    /// Offer early data (empty early_data extension).
    pub early_data: bool,
    /// Optional single PSK offer (implies psk_key_exchange_modes).
    pub psk: Option<OfferedPsk>,
    /// Cookie echoed back verbatim after a `HelloRetryRequest` carried one
    /// (RFC 8446 §4.2.2) — `None` on an initial ClientHello.
    pub cookie: Option<Bytes>,
    /// `legacy_version` wire field — `0x0303` for TLS (RFC 8446 §4.1.2),
    /// `0xfefd` for DTLS 1.3 (RFC 9147 §5.3, reusing DTLS 1.2's wire value
    /// for backward-compat framing). The real version is always negotiated
    /// via `supported_versions`, identical on both transports.
    pub legacy_version: u16,
}

/// Build a TLS 1.3 `ClientHello`.
///
/// When [`ClientHelloParams::psk`] is set, binders must already be computed (or
/// zeros for a truncated build used only to measure binder offset). Prefer
/// [`build_client_hello_with_binder`] for the resumptive path.
pub fn build_client_hello(params: &ClientHelloParams) -> HandshakeMessage {
    let (msg, _) = build_client_hello_inner(params, true);
    msg
}

/// Build ClientHello and return the truncated encoding used for binder computation
/// (full handshake header + body through PSK identities, excluding binders).
pub fn build_client_hello_truncated_for_binder(params: &ClientHelloParams) -> Bytes {
    let (_, truncated) = build_client_hello_inner(params, false);
    truncated.expect("psk required for truncated CH")
}

/// Build a resumptive ClientHello: compute binder over the truncated form, then
/// emit the complete message.
pub fn build_client_hello_with_binder(
    mut params: ClientHelloParams,
    compute_binder: impl FnOnce(&[u8; 32]) -> [u8; 32],
) -> HandshakeMessage {
    assert!(params.psk.is_some(), "psk required");
    // Placeholder binders for length accounting in truncated form.
    if let Some(psk) = params.psk.as_mut() {
        psk.binder = [0u8; 32];
    }
    let truncated = build_client_hello_truncated_for_binder(&params);
    let hash = {
        use aws_lc_rs::digest::{digest, SHA256};
        let d = digest(&SHA256, &truncated);
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    };
    let binder = compute_binder(&hash);
    if let Some(psk) = params.psk.as_mut() {
        psk.binder = binder;
    }
    build_client_hello(&params)
}

fn build_client_hello_inner(
    params: &ClientHelloParams,
    include_binders: bool,
) -> (HandshakeMessage, Option<Bytes>) {
    let mut body = BytesMut::new();
    body.extend_from_slice(&params.legacy_version.to_be_bytes());
    body.extend_from_slice(&params.random);
    body.extend_from_slice(&[0]);
    // DTLS's ClientHello has one more fixed-position field TLS's doesn't:
    // `opaque legacy_cookie<0..255>`, right after `legacy_session_id`
    // (RFC 9147 §5.3) — always empty for DTLS 1.3, whose own cookie
    // exchange uses the `cookie` extension (RFC 8446 §4.2.2) instead, same
    // as TLS 1.3's HelloRetryRequest. `legacy_version` is the wire's own
    // discriminator for which shape follows, so no separate mode flag is
    // threaded through just for this.
    if params.legacy_version == 0xfefd {
        body.extend_from_slice(&[0]);
    }
    body.extend_from_slice(&((params.cipher_suites.len() * 2) as u16).to_be_bytes());
    for suite in &params.cipher_suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]);

    let mut extensions = BytesMut::new();
    push_extension(&mut extensions, ext::SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04]);
    push_extension(
        &mut extensions,
        ext::SUPPORTED_GROUPS,
        &encode_group_list(&params.supported_groups),
    );
    push_extension(
        &mut extensions,
        ext::KEY_SHARE,
        &encode_key_share_list(std::slice::from_ref(&params.key_share)),
    );
    {
        let mut schemes = BytesMut::with_capacity(2 * SUPPORTED_SIGNATURE_SCHEMES.len());
        for scheme in SUPPORTED_SIGNATURE_SCHEMES {
            schemes.extend_from_slice(&scheme.to_be_bytes());
        }
        let mut sig_algs = BytesMut::with_capacity(2 + schemes.len());
        sig_algs.extend_from_slice(&(schemes.len() as u16).to_be_bytes());
        sig_algs.extend_from_slice(&schemes);
        push_extension(&mut extensions, ext::SIGNATURE_ALGORITHMS, &sig_algs);
    }
    {
        // RFC 9846 §1.4: which certificate-chain signature algorithms this
        // engine can verify — always sent, never parsed on receipt (no
        // consumer today; see crypto::x509's matching constant).
        let schemes = crate::crypto::x509::ACCEPTED_CERT_SIGNATURE_SCHEMES;
        let mut bytes = BytesMut::with_capacity(2 * schemes.len());
        for scheme in schemes {
            bytes.extend_from_slice(&scheme.to_be_bytes());
        }
        let mut sig_algs_cert = BytesMut::with_capacity(2 + bytes.len());
        sig_algs_cert.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        sig_algs_cert.extend_from_slice(&bytes);
        push_extension(&mut extensions, ext::SIGNATURE_ALGORITHMS_CERT, &sig_algs_cert);
    }
    if !params.alpn.is_empty() {
        let names: Vec<&[u8]> = params.alpn.iter().map(|p| p.as_ref()).collect();
        push_extension(&mut extensions, ext::ALPN, &encode_alpn_extension_data(&names));
    }
    if let Some(name) = &params.server_name {
        let host = name.as_bytes();
        let mut sni = BytesMut::new();
        // ServerNameList: list_len | NameType(1) | host_len | host (RFC 6066).
        sni.extend_from_slice(&((host.len() as u16 + 3)).to_be_bytes());
        sni.extend_from_slice(&[0u8]); // host_name
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        push_extension(&mut extensions, ext::SERVER_NAME, &sni);
    }
    if let Some(tp) = &params.transport_parameters {
        push_extension(&mut extensions, ext::QUIC_TRANSPORT_PARAMETERS, tp);
    }
    if params.early_data {
        push_extension(&mut extensions, ext::EARLY_DATA, &[]);
    }
    if params.psk.is_some() {
        push_extension(&mut extensions, ext::PSK_KEY_EXCHANGE_MODES, &[1, PSK_DHE_KE]);
    }
    if let Some(cookie) = &params.cookie {
        push_extension(&mut extensions, ext::COOKIE, cookie);
    }

    let mut truncated_wire = None;
    if let Some(psk) = &params.psk {
        // pre_shared_key MUST be last (RFC 8446 §4.2.11).
        let mut identities = BytesMut::new();
        identities.extend_from_slice(&(psk.identity.len() as u16).to_be_bytes());
        identities.extend_from_slice(&psk.identity);
        identities.extend_from_slice(&psk.obfuscated_ticket_age.to_be_bytes());
        let mut id_list = BytesMut::new();
        id_list.extend_from_slice(&(identities.len() as u16).to_be_bytes());
        id_list.extend_from_slice(&identities);

        // One binder entry: 1-byte length + 32-byte binder.
        let binder_entries_len = 1 + 32;
        let binders_vector_len = binder_entries_len as u16; // length of binder entries only
        let ext_payload_len = id_list.len() + 2 + binder_entries_len;

        // Truncated CH includes binders' 2-byte length but not the binder bytes
        // (RFC 8446 §4.2.11.2). Length fields still cover the binders.
        let mut trunc_ext = extensions.clone();
        trunc_ext.extend_from_slice(&ext::PRE_SHARED_KEY.to_be_bytes());
        trunc_ext.extend_from_slice(&(ext_payload_len as u16).to_be_bytes());
        trunc_ext.extend_from_slice(&id_list);
        trunc_ext.extend_from_slice(&binders_vector_len.to_be_bytes());

        let full_ext_len = trunc_ext.len() + binder_entries_len;
        let mut trunc_body = body.clone();
        trunc_body.extend_from_slice(&(full_ext_len as u16).to_be_bytes());
        trunc_body.extend_from_slice(&trunc_ext);
        let full_body_len = trunc_body.len() + binder_entries_len;
        let mut trunc_msg = BytesMut::with_capacity(4 + trunc_body.len());
        trunc_msg.extend_from_slice(&[HandshakeType::ClientHello as u8]);
        trunc_msg.extend_from_slice(&[
            (full_body_len >> 16) as u8,
            (full_body_len >> 8) as u8,
            full_body_len as u8,
        ]);
        trunc_msg.extend_from_slice(&trunc_body);
        truncated_wire = Some(trunc_msg.freeze());

        if include_binders {
            let mut psk_payload = BytesMut::new();
            psk_payload.extend_from_slice(&id_list);
            psk_payload.extend_from_slice(&binders_vector_len.to_be_bytes());
            psk_payload.extend_from_slice(&[32u8]);
            psk_payload.extend_from_slice(&psk.binder);
            push_extension(&mut extensions, ext::PRE_SHARED_KEY, &psk_payload);
        }
    }

    if include_binders || params.psk.is_none() {
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
    }

    (
        HandshakeMessage {
            msg_type: HandshakeType::ClientHello,
            body: body.freeze(),
        },
        truncated_wire,
    )
}

/// ServerHello with optional selected PSK identity index (`None` for a
/// full, non-resumptive handshake). `legacy_session_id_echo` must be
/// exactly the `legacy_session_id` the client sent in its `ClientHello`
/// (RFC 8446 §4.1.3) — an empty client value is fine to echo as empty,
/// but a client using middlebox-compat mode (Appendix D.4) sends a
/// random 32 bytes and aborts if the echo doesn't match.
pub fn build_server_hello_ext(
    random: &[u8; 32],
    legacy_session_id_echo: &[u8],
    cipher_suite: u16,
    group: u16,
    key_share: &[u8],
    selected_identity: Option<u16>,
    legacy_version: u16,
) -> HandshakeMessage {
    let mut body = BytesMut::new();
    body.extend_from_slice(&legacy_version.to_be_bytes());
    body.extend_from_slice(random);
    body.extend_from_slice(&[legacy_session_id_echo.len() as u8]);
    body.extend_from_slice(legacy_session_id_echo);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.extend_from_slice(&[0]);

    let mut extensions = BytesMut::new();
    push_extension(&mut extensions, ext::SUPPORTED_VERSIONS, &[0x03, 0x04]);
    let mut ks = BytesMut::new();
    ks.extend_from_slice(&group.to_be_bytes());
    ks.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    ks.extend_from_slice(key_share);
    push_extension(&mut extensions, ext::KEY_SHARE, &ks);
    if let Some(idx) = selected_identity {
        push_extension(&mut extensions, ext::PRE_SHARED_KEY, &idx.to_be_bytes());
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    HandshakeMessage {
        msg_type: HandshakeType::ServerHello,
        body: body.freeze(),
    }
}

/// Build a `HelloRetryRequest` (RFC 8446 §4.1.4) — wire-identical to
/// `ServerHello` (same handshake type, 2) but with `random` fixed to
/// [`HELLO_RETRY_REQUEST_RANDOM`] and a `key_share` extension carrying only
/// the requested `selected_group` (RFC 8446 §4.2.8's
/// `KeyShareHelloRetryRequest` — no key bytes, unlike a real `ServerHello`'s
/// `key_share`). `legacy_session_id_echo` follows the same rule as
/// [`build_server_hello_ext`]. `cookie`, when set, is echoed verbatim by the
/// client in its followup ClientHello.
pub fn build_hello_retry_request(
    legacy_session_id_echo: &[u8],
    cipher_suite: u16,
    selected_group: u16,
    cookie: Option<&[u8]>,
    legacy_version: u16,
) -> HandshakeMessage {
    let mut body = BytesMut::new();
    body.extend_from_slice(&legacy_version.to_be_bytes());
    body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
    body.extend_from_slice(&[legacy_session_id_echo.len() as u8]);
    body.extend_from_slice(legacy_session_id_echo);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.extend_from_slice(&[0]);

    let mut extensions = BytesMut::new();
    push_extension(&mut extensions, ext::SUPPORTED_VERSIONS, &[0x03, 0x04]);
    push_extension(&mut extensions, ext::KEY_SHARE, &selected_group.to_be_bytes());
    if let Some(cookie) = cookie {
        push_extension(&mut extensions, ext::COOKIE, cookie);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    HandshakeMessage {
        msg_type: HandshakeType::ServerHello,
        body: body.freeze(),
    }
}

/// EncryptedExtensions with optional early_data acceptance (`false` for a
/// handshake that never offered/accepted 0-RTT). `alpn` is the negotiated protocol —
/// `None` when the client didn't offer the extension or none of its offers matched (RFC 8446
/// §4.2: a server MUST NOT send an extension the client didn't offer — `Some(b"h3")` when the
/// client sent no ALPN extension at all is a real, previously-shipped bug, not padding).
pub fn build_encrypted_extensions_ext(
    alpn: Option<&[u8]>,
    transport_parameters: Option<&[u8]>,
    early_data_accepted: bool,
) -> HandshakeMessage {
    let mut extensions = BytesMut::new();
    if let Some(alpn) = alpn {
        push_extension(&mut extensions, ext::ALPN, &encode_alpn_extension_data(&[alpn]));
    }
    if let Some(tp) = transport_parameters {
        push_extension(&mut extensions, ext::QUIC_TRANSPORT_PARAMETERS, tp);
    }
    if early_data_accepted {
        push_extension(&mut extensions, ext::EARLY_DATA, &[]);
    }
    let mut body = BytesMut::new();
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    HandshakeMessage {
        msg_type: HandshakeType::EncryptedExtensions,
        body: body.freeze(),
    }
}

/// Build a NewSessionTicket (RFC 8446 §4.6.1) with optional early_data.
pub fn build_new_session_ticket(
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: &[u8],
    ticket: &[u8],
    max_early_data_size: u32,
) -> HandshakeMessage {
    let mut body = BytesMut::new();
    body.extend_from_slice(&ticket_lifetime.to_be_bytes());
    body.extend_from_slice(&ticket_age_add.to_be_bytes());
    body.extend_from_slice(&[ticket_nonce.len() as u8]);
    body.extend_from_slice(ticket_nonce);
    body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    body.extend_from_slice(ticket);
    let mut extensions = BytesMut::new();
    if max_early_data_size > 0 {
        push_extension(
            &mut extensions,
            ext::EARLY_DATA,
            &max_early_data_size.to_be_bytes(),
        );
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    HandshakeMessage {
        msg_type: HandshakeType::NewSessionTicket,
        body: body.freeze(),
    }
}

/// Build a TLS 1.3 `Certificate` message. `context` is the
/// `certificate_request_context` (RFC 8446 §4.4.2) — empty for the server's
/// own unsolicited `Certificate`, or the exact bytes echoed from a peer
/// `CertificateRequest` when this is a client's response to one.
pub fn build_certificate(context: &[u8], chain: &[&[u8]]) -> HandshakeMessage {
    let mut cert_list = BytesMut::new();
    for cert in chain {
        cert_list.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
        cert_list.extend_from_slice(cert);
        cert_list.extend_from_slice(&0u16.to_be_bytes());
    }
    let mut body = BytesMut::with_capacity(1 + context.len() + 3 + cert_list.len());
    body.extend_from_slice(&[context.len() as u8]);
    body.extend_from_slice(context);
    body.extend_from_slice(&(cert_list.len() as u32).to_be_bytes()[1..]);
    body.extend_from_slice(&cert_list);
    HandshakeMessage {
        msg_type: HandshakeType::Certificate,
        body: body.freeze(),
    }
}

/// Build a `CertificateRequest` (RFC 8446 §4.3.2) offering this crate's
/// [`SUPPORTED_SIGNATURE_SCHEMES`]. `context` is opaque and echoed back
/// verbatim in the client's `Certificate` response's own context field.
pub fn build_certificate_request(context: &[u8]) -> HandshakeMessage {
    let mut body = BytesMut::new();
    body.extend_from_slice(&[context.len() as u8]);
    body.extend_from_slice(context);
    let mut extensions = BytesMut::new();
    {
        let mut schemes = BytesMut::with_capacity(2 * SUPPORTED_SIGNATURE_SCHEMES.len());
        for scheme in SUPPORTED_SIGNATURE_SCHEMES {
            schemes.extend_from_slice(&scheme.to_be_bytes());
        }
        let mut sig_algs = BytesMut::with_capacity(2 + schemes.len());
        sig_algs.extend_from_slice(&(schemes.len() as u16).to_be_bytes());
        sig_algs.extend_from_slice(&schemes);
        push_extension(&mut extensions, ext::SIGNATURE_ALGORITHMS, &sig_algs);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    HandshakeMessage {
        msg_type: HandshakeType::CertificateRequest,
        body: body.freeze(),
    }
}

/// Build a `CertificateVerify` message.
pub fn build_certificate_verify(scheme: u16, signature: &[u8]) -> HandshakeMessage {
    let mut body = BytesMut::new();
    body.extend_from_slice(&scheme.to_be_bytes());
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(signature);
    HandshakeMessage {
        msg_type: HandshakeType::CertificateVerify,
        body: body.freeze(),
    }
}

/// Build a `Finished` message.
pub fn build_finished(verify_data: &[u8]) -> HandshakeMessage {
    HandshakeMessage {
        msg_type: HandshakeType::Finished,
        body: Bytes::copy_from_slice(verify_data),
    }
}

/// `KeyUpdateRequest` values (RFC 8446 §4.6.3).
pub mod key_update_request {
    /// `update_not_requested(0)`.
    pub const NOT_REQUESTED: u8 = 0;
    /// `update_requested(1)`.
    pub const REQUESTED: u8 = 1;
}

/// Build a `KeyUpdate` message — single-byte `KeyUpdateRequest` body
/// (RFC 8446 §4.6.3). Post-handshake: never part of the transcript hash.
pub fn build_key_update(kind: u8) -> HandshakeMessage {
    HandshakeMessage { msg_type: HandshakeType::KeyUpdate, body: Bytes::copy_from_slice(&[kind]) }
}

fn push_extension(out: &mut BytesMut, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// ALPN extension_data (RFC 7301 §3.1): `ProtocolNameList` — a 2-byte overall
/// length, then each protocol name as a 1-byte length + bytes.
fn encode_alpn_extension_data(protocols: &[&[u8]]) -> BytesMut {
    let mut names = BytesMut::new();
    for proto in protocols {
        names.extend_from_slice(&[proto.len() as u8]);
        names.extend_from_slice(proto);
    }
    let mut out = BytesMut::with_capacity(2 + names.len());
    out.extend_from_slice(&(names.len() as u16).to_be_bytes());
    out.extend_from_slice(&names);
    out
}

fn encode_group_list(groups: &[u16]) -> Bytes {
    let mut out = BytesMut::with_capacity(2 + groups.len() * 2);
    out.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in groups {
        out.extend_from_slice(&g.to_be_bytes());
    }
    out.freeze()
}

fn encode_key_share_list(entries: &[KeyShareEntry]) -> Bytes {
    let mut body = BytesMut::new();
    for e in entries {
        body.extend_from_slice(&e.group.to_be_bytes());
        body.extend_from_slice(&(e.share.len() as u16).to_be_bytes());
        body.extend_from_slice(&e.share);
    }
    let mut out = BytesMut::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::handshake::collect::parse_client_hello;

    #[test]
    fn client_hello_key_share_roundtrip() {
        use crate::crypto::kx::{EphemeralKeyPair, NamedGroup};
        let kp = EphemeralKeyPair::generate().unwrap();
        let random = [1u8; 32];
        let hello = build_client_hello(&ClientHelloParams {
            random,
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
        let parsed = parse_client_hello(&hello.body).expect("parse client hello");
        assert!(parsed.peer_key_share.is_some());
        assert_eq!(parsed.key_share_group, Some(NamedGroup::X25519.code()));
    }

    /// DTLS's ClientHello (`legacy_version = 0xfefd`) carries one extra
    /// fixed-position field — `legacy_cookie` — right after
    /// `legacy_session_id`, which TLS's ClientHello doesn't have at all.
    /// Proves the writer emits it and the reader correctly skips it so
    /// every field after it (cipher_suites, key_share, …) still lands at
    /// the right offset — the one place `messages.rs`/`parser.rs` are
    /// mode-aware at all; everything else is transport-agnostic.
    #[test]
    fn dtls_client_hello_carries_and_skips_legacy_cookie_field() {
        use crate::crypto::kx::{EphemeralKeyPair, NamedGroup};
        let kp = EphemeralKeyPair::generate().unwrap();
        let hello = build_client_hello(&ClientHelloParams {
            random: [2u8; 32],
            cipher_suites: vec![0x1301, 0x1303],
            key_share: KeyShareEntry {
                group: NamedGroup::X25519.code(),
                share: Bytes::copy_from_slice(&kp.public_key()),
            },
            supported_groups: vec![NamedGroup::X25519.code()],
            alpn: vec![],
            server_name: None,
            transport_parameters: None,
            early_data: false,
            psk: None,
            cookie: None,
            legacy_version: 0xfefd,
        });
        // legacy_version(2) + random(32) + session_id_len(1)=0 +
        // legacy_cookie_len(1)=0: byte 35 is the cookie length prefix.
        assert_eq!(hello.body[35], 0, "empty legacy_cookie field present");
        let parsed = parse_client_hello(&hello.body).expect("parse DTLS-shaped client hello");
        assert!(parsed.peer_key_share.is_some());
        assert_eq!(parsed.key_share_group, Some(NamedGroup::X25519.code()));
        assert_eq!(parsed.cipher_suites, vec![0x1301, 0x1303]);
    }

    /// `signature_algorithms_cert` (RFC 9846 §1.4) is sent but deliberately
    /// never parsed by `collect::parse_client_hello` (no consumer — see
    /// `ext`'s doc comment on this constant), so this scans the raw body
    /// directly rather than going through the parser.
    #[test]
    fn client_hello_advertises_signature_algorithms_cert() {
        use crate::crypto::kx::{EphemeralKeyPair, NamedGroup};
        let kp = EphemeralKeyPair::generate().unwrap();
        let hello = build_client_hello(&ClientHelloParams {
            random: [6u8; 32],
            cipher_suites: vec![0x1301],
            key_share: KeyShareEntry { group: NamedGroup::X25519.code(), share: Bytes::copy_from_slice(&kp.public_key()) },
            supported_groups: vec![NamedGroup::X25519.code()],
            alpn: vec![],
            server_name: None,
            transport_parameters: None,
            early_data: false,
            psk: None,
            cookie: None,
            legacy_version: 0x0303,
        });
        // legacy_version(2) + random(32) + session_id_len(1) + cipher_suites_len(2)
        // + cipher_suites(2) + compression(2).
        let prefix_len = 2 + 32 + 1 + 2 + 2 + 2;
        let ext_len = u16::from_be_bytes([hello.body[prefix_len], hello.body[prefix_len + 1]]) as usize;
        let ext_block = &hello.body[prefix_len + 2..prefix_len + 2 + ext_len];
        let mut k = 0;
        let mut found = None;
        while k + 4 <= ext_block.len() {
            let et = u16::from_be_bytes([ext_block[k], ext_block[k + 1]]);
            let el = u16::from_be_bytes([ext_block[k + 2], ext_block[k + 3]]) as usize;
            k += 4;
            let data = &ext_block[k..k + el];
            if et == ext::SIGNATURE_ALGORITHMS_CERT {
                let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                let mut schemes = Vec::with_capacity(list_len / 2);
                let mut m = 2;
                while m + 2 <= 2 + list_len {
                    schemes.push(u16::from_be_bytes([data[m], data[m + 1]]));
                    m += 2;
                }
                found = Some(schemes);
                break;
            }
            k += el;
        }
        assert_eq!(found, Some(crate::crypto::x509::ACCEPTED_CERT_SIGNATURE_SCHEMES.to_vec()));
    }
}
