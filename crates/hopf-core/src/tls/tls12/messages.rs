// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.2 handshake message framing (RFC 5246 §7.4, RFC 4492/8422 ECDHE).
//!
//! Deliberately self-contained — no sharing with [`super::handshake`]'s TLS
//! 1.3 parser beyond the crypto floor. The two protocols' `ClientHello`
//! preambles look alike, but `Certificate`'s per-entry framing already
//! differs (TLS 1.3 added a per-certificate extensions field TLS 1.2
//! doesn't have), and coupling this to the interop-verified 1.3 parser
//! would risk regressing it for a legacy protocol version's sake.

use bytes::{Bytes, BytesMut};

/// TLS 1.2 handshake message type (RFC 5246 §7.4 / RFC 4346).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// ClientHello.
    ClientHello = 1,
    /// ServerHello.
    ServerHello = 2,
    /// HelloVerifyRequest (RFC 6347 §4.2.1 — DTLS 1.2 stateless-cookie
    /// anti-amplification retry; no TCP TLS 1.2 equivalent).
    HelloVerifyRequest = 3,
    /// Certificate.
    Certificate = 11,
    /// ServerKeyExchange.
    ServerKeyExchange = 12,
    /// CertificateRequest (RFC 5246 §7.4.4 — mTLS).
    CertificateRequest = 13,
    /// ServerHelloDone.
    ServerHelloDone = 14,
    /// ClientKeyExchange.
    ClientKeyExchange = 16,
    /// CertificateVerify (RFC 5246 §7.4.8 — mTLS).
    CertificateVerify = 15,
    /// Finished.
    Finished = 20,
    /// NewSessionTicket (RFC 5077 §3.3).
    NewSessionTicket = 4,
}

impl MessageType {
    /// Parse from the wire type byte.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::ClientHello),
            2 => Some(Self::ServerHello),
            3 => Some(Self::HelloVerifyRequest),
            4 => Some(Self::NewSessionTicket),
            11 => Some(Self::Certificate),
            12 => Some(Self::ServerKeyExchange),
            13 => Some(Self::CertificateRequest),
            14 => Some(Self::ServerHelloDone),
            15 => Some(Self::CertificateVerify),
            16 => Some(Self::ClientKeyExchange),
            20 => Some(Self::Finished),
            _ => None,
        }
    }
}

/// Extension type constants (RFC 5246 §7.4.1.4, RFC 4492 §5.1, RFC 5746).
pub mod ext {
    /// Server Name Indication (RFC 6066).
    pub const SERVER_NAME: u16 = 0;
    /// Supported (elliptic curve) Groups (RFC 4492 §5.1.1 `elliptic_curves`).
    pub const SUPPORTED_GROUPS: u16 = 10;
    /// EC Point Formats (RFC 4492 §5.1.2) — we only ever offer/accept uncompressed.
    pub const EC_POINT_FORMATS: u16 = 11;
    /// Signature Algorithms (RFC 5246 §7.4.1.4.1).
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    /// Renegotiation Indication (RFC 5746) — empty on an initial handshake;
    /// renegotiation itself is out of scope (see crypto-migration-plan.md).
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
    /// SessionTicket (RFC 5077 §3.2) — empty to advertise support, or the
    /// opaque ticket bytes to attempt resumption.
    pub const SESSION_TICKET: u16 = 35;
    /// Extended Master Secret (RFC 7627 §5.1; RFC 9846 Appendix D renames
    /// the *prose* term to `extended_main_secret` but doesn't move this
    /// IANA codepoint) — zero-length `extension_data`; mere presence is
    /// the signal. This engine treats it as mandatory, not optional.
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
}

/// `SignatureAndHashAlgorithm` (RFC 5246 §7.4.1.4.1) — the legacy 1-byte/1-byte
/// pair TLS 1.2 uses, unrelated to TLS 1.3's 2-byte `SignatureScheme` codes.
pub mod sig_alg {
    /// `sha256` hash algorithm.
    pub const HASH_SHA256: u8 = 4;
    /// `sha384` hash algorithm.
    pub const HASH_SHA384: u8 = 5;
    /// `rsa` signature algorithm (PKCS#1 v1.5).
    pub const SIG_RSA: u8 = 1;
    /// `ecdsa` signature algorithm.
    pub const SIG_ECDSA: u8 = 3;
}

/// `NamedCurve` (RFC 4492 §5.1.1) — only the one curve this engine speaks.
pub const NAMED_CURVE_SECP256R1: u16 = 23;
/// `ECCurveType::named_curve` (RFC 4492 §5.4).
pub const EC_CURVE_TYPE_NAMED_CURVE: u8 = 3;
/// `ECPointFormat::uncompressed` (RFC 4492 §5.1.2).
pub const EC_POINT_FORMAT_UNCOMPRESSED: u8 = 0;

/// Encode one handshake message: 1-byte type + 3-byte length + body.
pub fn encode_message(msg_type: MessageType, body: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(4 + body.len());
    out.extend_from_slice(&[msg_type as u8]);
    let len = body.len() as u32;
    out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    out.extend_from_slice(body);
    out.freeze()
}

fn push_extension(out: &mut BytesMut, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Inputs for building a TLS 1.2 `ClientHello`.
pub struct ClientHelloParams<'a> {
    /// Client random (32 bytes).
    pub random: [u8; 32],
    /// Session ID to offer for resumption (empty for a full handshake).
    pub session_id: &'a [u8],
    /// Cipher suites offered, in preference order.
    pub cipher_suites: &'a [u16],
    /// SNI hostname, if any.
    pub server_name: Option<&'a str>,
    /// `SessionTicket` extension to send: `None` omits the extension
    /// entirely; `Some(&[])` advertises support with no ticket to offer;
    /// `Some(ticket_bytes)` attempts resumption with a cached ticket (RFC
    /// 5077 §3.2/§3.4).
    pub session_ticket: Option<&'a [u8]>,
    /// `legacy_version` wire field — `0x0303` for TCP TLS 1.2, `0xfefd` for
    /// DTLS 1.2 (RFC 6347 §4.1, the *real*, not legacy, protocol version —
    /// DTLS 1.2 predates TLS 1.3's extension-based version negotiation).
    pub legacy_version: u16,
    /// `legacy_cookie` (RFC 6347 §4.2.1) — empty on a DTLS `ClientHello1`;
    /// the server's cookie, echoed verbatim, on `ClientHello2`. TCP TLS 1.2
    /// has no such field at all; callers there always pass `&[]`, and
    /// [`Self::legacy_version`] being `0x0303` means it's never written.
    pub cookie: &'a [u8],
}

/// Build a TLS 1.2 `ClientHello`.
pub fn build_client_hello(params: &ClientHelloParams<'_>) -> Bytes {
    let mut body = BytesMut::new();
    body.extend_from_slice(&params.legacy_version.to_be_bytes());
    body.extend_from_slice(&params.random);
    body.extend_from_slice(&[params.session_id.len() as u8]);
    body.extend_from_slice(params.session_id);
    // DTLS's ClientHello has one more fixed-position field TLS's doesn't —
    // see the matching comment in `tls/handshake/messages.rs`'s
    // `build_client_hello_inner` for the identical TLS-1.3-side change.
    if params.legacy_version == 0xfefd {
        body.extend_from_slice(&[params.cookie.len() as u8]);
        body.extend_from_slice(params.cookie);
    }
    body.extend_from_slice(&((params.cipher_suites.len() * 2) as u16).to_be_bytes());
    for cs in params.cipher_suites {
        body.extend_from_slice(&cs.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // compression_methods: [null]

    let mut extensions = BytesMut::new();
    push_extension(&mut extensions, ext::RENEGOTIATION_INFO, &[0]); // empty renegotiated_connection
    push_extension(&mut extensions, ext::EXTENDED_MASTER_SECRET, &[]); // mandatory (RFC 7627 §5.1)
    push_extension(
        &mut extensions,
        ext::SUPPORTED_GROUPS,
        &encode_u16_list(&[NAMED_CURVE_SECP256R1]),
    );
    push_extension(
        &mut extensions,
        ext::EC_POINT_FORMATS,
        &[1, EC_POINT_FORMAT_UNCOMPRESSED],
    );
    let sig_algs: &[(u8, u8)] = &[
        (sig_alg::HASH_SHA256, sig_alg::SIG_ECDSA),
        (sig_alg::HASH_SHA256, sig_alg::SIG_RSA),
        (sig_alg::HASH_SHA384, sig_alg::SIG_ECDSA),
        (sig_alg::HASH_SHA384, sig_alg::SIG_RSA),
    ];
    let mut sig_alg_bytes = BytesMut::new();
    for (h, s) in sig_algs {
        sig_alg_bytes.extend_from_slice(&[*h, *s]);
    }
    push_extension(&mut extensions, ext::SIGNATURE_ALGORITHMS, &encode_u16_prefixed(&sig_alg_bytes));
    if let Some(name) = params.server_name {
        let host = name.as_bytes();
        let mut sni = BytesMut::new();
        sni.extend_from_slice(&((host.len() as u16 + 3)).to_be_bytes());
        sni.extend_from_slice(&[0u8]);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        push_extension(&mut extensions, ext::SERVER_NAME, &sni);
    }
    if let Some(ticket) = params.session_ticket {
        push_extension(&mut extensions, ext::SESSION_TICKET, ticket);
    }

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    encode_message(MessageType::ClientHello, &body)
}

fn encode_u16_list(values: &[u16]) -> Bytes {
    let mut inner = BytesMut::new();
    for v in values {
        inner.extend_from_slice(&v.to_be_bytes());
    }
    encode_u16_prefixed(&inner)
}

fn encode_u16_prefixed(inner: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(2 + inner.len());
    out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    out.extend_from_slice(inner);
    out.freeze()
}

/// Parsed `ClientHello` fields the server needs.
#[derive(Debug, Clone)]
pub struct ParsedClientHello {
    /// Client random.
    pub random: [u8; 32],
    /// Client-offered session ID (resumption; empty for a full handshake).
    pub session_id: Bytes,
    /// Offered cipher suites.
    pub cipher_suites: Vec<u16>,
    /// `signature_algorithms` pairs, if sent.
    pub signature_algorithms: Vec<(u8, u8)>,
    /// SNI hostname, if sent.
    pub server_name: Option<String>,
    /// `SessionTicket` extension contents, if the client sent one: empty
    /// bytes means "support, no ticket"; non-empty is a resumption attempt.
    pub session_ticket: Option<Bytes>,
    /// `legacy_cookie` (RFC 6347 §4.2.1) — empty unless this is a DTLS
    /// `ClientHello2` echoing a `HelloVerifyRequest` cookie. Always empty
    /// when parsing a TCP TLS 1.2 `ClientHello` (`legacy_version` `0x0303`
    /// never carries this field at all — see [`ClientHelloParams::cookie`]).
    pub cookie: Bytes,
    /// Whether the client offered `extended_master_secret` (RFC 7627
    /// §5.1). This engine treats it as mandatory — see `engine.rs`.
    pub extended_master_secret: bool,
    /// `renegotiation_info` (RFC 5746 §3.2), if present: its raw
    /// `extension_data`. `None` if absent. Validated in `engine.rs`, not
    /// here — mirrors `session_ticket`'s split between parsing and policy.
    pub renegotiation_info: Option<Bytes>,
}

/// Parse a `ClientHello` body.
pub fn parse_client_hello(body: &[u8]) -> Option<ParsedClientHello> {
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    let mut i = 2;
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[i..i + 32]);
    i += 32;
    let sid_len = *body.get(i)? as usize;
    i += 1;
    if body.len() < i + sid_len + 2 {
        return None;
    }
    let session_id = Bytes::copy_from_slice(&body[i..i + sid_len]);
    i += sid_len;
    let mut cookie = Bytes::new();
    if legacy_version == 0xfefd {
        let cookie_len = *body.get(i)? as usize;
        i += 1;
        if body.len() < i + cookie_len + 2 {
            return None;
        }
        cookie = Bytes::copy_from_slice(&body[i..i + cookie_len]);
        i += cookie_len;
    }
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + cs_len + 1 {
        return None;
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    let mut j = i;
    while j + 2 <= i + cs_len {
        cipher_suites.push(u16::from_be_bytes([body[j], body[j + 1]]));
        j += 2;
    }
    i += cs_len;
    let comp_len = *body.get(i)? as usize;
    i += 1;
    if body.len() < i + comp_len {
        return None;
    }
    i += comp_len;

    let mut signature_algorithms = Vec::new();
    let mut server_name = None;
    let mut session_ticket = None;
    let mut extended_master_secret = false;
    let mut renegotiation_info = None;
    if i + 2 <= body.len() {
        let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        if body.len() >= i + ext_len {
            let ext_block = &body[i..i + ext_len];
            let mut k = 0;
            while k + 4 <= ext_block.len() {
                let et = u16::from_be_bytes([ext_block[k], ext_block[k + 1]]);
                let el = u16::from_be_bytes([ext_block[k + 2], ext_block[k + 3]]) as usize;
                k += 4;
                if k + el > ext_block.len() {
                    break;
                }
                let data = &ext_block[k..k + el];
                match et {
                    ext::SIGNATURE_ALGORITHMS => {
                        if data.len() >= 2 {
                            let mut m = 2;
                            while m + 2 <= data.len() {
                                signature_algorithms.push((data[m], data[m + 1]));
                                m += 2;
                            }
                        }
                    }
                    ext::SERVER_NAME => {
                        if data.len() >= 5 {
                            let host_len = u16::from_be_bytes([data[3], data[4]]) as usize;
                            if data.len() >= 5 + host_len {
                                server_name = std::str::from_utf8(&data[5..5 + host_len]).ok().map(String::from);
                            }
                        }
                    }
                    ext::SESSION_TICKET => {
                        session_ticket = Some(Bytes::copy_from_slice(data));
                    }
                    ext::EXTENDED_MASTER_SECRET => {
                        extended_master_secret = true;
                    }
                    ext::RENEGOTIATION_INFO => {
                        renegotiation_info = Some(Bytes::copy_from_slice(data));
                    }
                    _ => {}
                }
                k += el;
            }
        }
    }

    Some(ParsedClientHello {
        random,
        session_id,
        cipher_suites,
        signature_algorithms,
        server_name,
        session_ticket,
        cookie,
        extended_master_secret,
        renegotiation_info,
    })
}

/// Build a TLS 1.2 `ServerHello`. `session_ticket` echoes RFC 5077 §3.2's
/// empty `SessionTicket` extension — the server MUST send it here for a
/// client to know to expect a `NewSessionTicket` message in this same
/// handshake; without it, a spec-conformant client (verified against
/// `rustls`) treats an unadvertised `NewSessionTicket` as a protocol
/// violation (it's waiting for `ChangeCipherSpec` at that point instead).
pub fn build_server_hello(
    random: &[u8; 32],
    session_id: &[u8],
    cipher_suite: u16,
    session_ticket: bool,
    legacy_version: u16,
    extended_master_secret: bool,
) -> Bytes {
    let mut body = BytesMut::new();
    body.extend_from_slice(&legacy_version.to_be_bytes());
    body.extend_from_slice(random);
    body.extend_from_slice(&[session_id.len() as u8]);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.extend_from_slice(&[0]); // compression_method: null

    let mut extensions = BytesMut::new();
    push_extension(&mut extensions, ext::RENEGOTIATION_INFO, &[0]);
    if extended_master_secret {
        push_extension(&mut extensions, ext::EXTENDED_MASTER_SECRET, &[]);
    }
    push_extension(&mut extensions, ext::EC_POINT_FORMATS, &[1, EC_POINT_FORMAT_UNCOMPRESSED]);
    if session_ticket {
        push_extension(&mut extensions, ext::SESSION_TICKET, &[]);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    encode_message(MessageType::ServerHello, &body)
}

/// Parsed `ServerHello` fields.
#[derive(Debug, Clone)]
pub struct ParsedServerHello {
    /// Server random.
    pub random: [u8; 32],
    /// Server-selected (or echoed) session ID.
    pub session_id: Bytes,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Whether the server echoed the (empty) `SessionTicket` extension —
    /// RFC 5077 §3.2's signal that a `NewSessionTicket` message follows
    /// later in this same handshake.
    pub session_ticket_offered: bool,
    /// Whether the server echoed `extended_master_secret` (RFC 7627
    /// §5.1). This engine treats it as mandatory — see `engine.rs`.
    pub extended_master_secret: bool,
    /// `renegotiation_info` (RFC 5746 §3.2), if present: its raw
    /// `extension_data`. `None` if absent. Validated in `engine.rs`.
    pub renegotiation_info: Option<Bytes>,
}

/// Parse a `ServerHello` body.
pub fn parse_server_hello(body: &[u8]) -> Option<ParsedServerHello> {
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    let mut i = 2;
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[i..i + 32]);
    i += 32;
    let sid_len = *body.get(i)? as usize;
    i += 1;
    if body.len() < i + sid_len + 2 + 1 {
        return None;
    }
    let session_id = Bytes::copy_from_slice(&body[i..i + sid_len]);
    i += sid_len;
    let cipher_suite = u16::from_be_bytes([body[i], body[i + 1]]);
    i += 2;
    i += 1; // compression_method

    let mut session_ticket_offered = false;
    let mut extended_master_secret = false;
    let mut renegotiation_info = None;
    if i + 2 <= body.len() {
        let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        if body.len() >= i + ext_len {
            let ext_block = &body[i..i + ext_len];
            let mut k = 0;
            while k + 4 <= ext_block.len() {
                let et = u16::from_be_bytes([ext_block[k], ext_block[k + 1]]);
                let el = u16::from_be_bytes([ext_block[k + 2], ext_block[k + 3]]) as usize;
                k += 4;
                if k + el > ext_block.len() {
                    break;
                }
                let data = &ext_block[k..k + el];
                if et == ext::SESSION_TICKET {
                    session_ticket_offered = true;
                }
                if et == ext::EXTENDED_MASTER_SECRET {
                    extended_master_secret = true;
                }
                if et == ext::RENEGOTIATION_INFO {
                    renegotiation_info = Some(Bytes::copy_from_slice(data));
                }
                k += el;
            }
        }
    }

    Some(ParsedServerHello {
        random,
        session_id,
        cipher_suite,
        session_ticket_offered,
        extended_master_secret,
        renegotiation_info,
    })
}

/// Build a `HelloVerifyRequest` (RFC 6347 §4.2.1) — DTLS 1.2's stateless
/// anti-amplification retry; no TCP TLS 1.2 equivalent (this message type
/// is undefined there). `server_version` is conventionally the same
/// `0xfefd` used elsewhere, though RFC 6347 doesn't require it to match
/// what the eventual negotiated version turns out to be.
pub fn build_hello_verify_request(server_version: u16, cookie: &[u8]) -> Bytes {
    let mut body = BytesMut::with_capacity(2 + 1 + cookie.len());
    body.extend_from_slice(&server_version.to_be_bytes());
    body.extend_from_slice(&[cookie.len() as u8]);
    body.extend_from_slice(cookie);
    encode_message(MessageType::HelloVerifyRequest, &body)
}

/// Parse a `HelloVerifyRequest` body into its cookie.
pub fn parse_hello_verify_request(body: &[u8]) -> Option<Bytes> {
    if body.len() < 3 {
        return None;
    }
    let cookie_len = body[2] as usize;
    if body.len() < 3 + cookie_len {
        return None;
    }
    Some(Bytes::copy_from_slice(&body[3..3 + cookie_len]))
}

/// Build a `Certificate` message (RFC 5246 §7.4.2 — no per-entry extensions,
/// unlike TLS 1.3's `Certificate`).
pub fn build_certificate(chain: &[&[u8]]) -> Bytes {
    let mut cert_list = BytesMut::new();
    for cert in chain {
        cert_list.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
        cert_list.extend_from_slice(cert);
    }
    let mut body = BytesMut::with_capacity(3 + cert_list.len());
    body.extend_from_slice(&(cert_list.len() as u32).to_be_bytes()[1..]);
    body.extend_from_slice(&cert_list);
    encode_message(MessageType::Certificate, &body)
}

/// Parse a `Certificate` message body into a DER chain (leaf first).
pub fn parse_certificate(body: &[u8]) -> Option<Vec<Bytes>> {
    if body.len() < 3 {
        return None;
    }
    let total_len = u32::from_be_bytes([0, body[0], body[1], body[2]]) as usize;
    if body.len() < 3 + total_len {
        return None;
    }
    let mut certs = Vec::new();
    let mut i = 3;
    let end = 3 + total_len;
    while i + 3 <= end {
        let len = u32::from_be_bytes([0, body[i], body[i + 1], body[i + 2]]) as usize;
        i += 3;
        if i + len > end {
            return None;
        }
        certs.push(Bytes::copy_from_slice(&body[i..i + len]));
        i += len;
    }
    Some(certs)
}

/// Build a `CertificateRequest` (RFC 5246 §7.4.4): offers both
/// `rsa_sign`/`ecdsa_sign` client-certificate types and the same
/// `SignatureAndHashAlgorithm` pairs [`build_client_hello`] advertises, with
/// an empty `certificate_authorities` (accept any CA).
pub fn build_certificate_request() -> Bytes {
    let mut body = BytesMut::new();
    // ClientCertificateType: rsa_sign(1), ecdsa_sign(64) (RFC 4492 §5.5).
    body.extend_from_slice(&[2u8, 1, 64]);
    let sig_algs: &[(u8, u8)] = &[
        (sig_alg::HASH_SHA256, sig_alg::SIG_ECDSA),
        (sig_alg::HASH_SHA256, sig_alg::SIG_RSA),
        (sig_alg::HASH_SHA384, sig_alg::SIG_ECDSA),
        (sig_alg::HASH_SHA384, sig_alg::SIG_RSA),
    ];
    let mut sig_alg_bytes = BytesMut::new();
    for (h, s) in sig_algs {
        sig_alg_bytes.extend_from_slice(&[*h, *s]);
    }
    body.extend_from_slice(&(sig_alg_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&sig_alg_bytes);
    body.extend_from_slice(&0u16.to_be_bytes()); // certificate_authorities: empty
    encode_message(MessageType::CertificateRequest, &body)
}

/// Validate a `CertificateRequest` body without extracting anything from
/// it — this engine always offers the caller's single configured client
/// certificate (or none) regardless of `certificate_authorities` or the
/// requested types, so only well-formedness matters.
pub fn parse_certificate_request(body: &[u8]) -> Option<()> {
    let types_len = *body.first()? as usize;
    let mut i = 1;
    if body.len() < i + types_len + 2 {
        return None;
    }
    i += types_len;
    let sig_algs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + sig_algs_len + 2 {
        return None;
    }
    i += sig_algs_len;
    let ca_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + ca_len {
        return None;
    }
    Some(())
}

/// Build a `CertificateVerify` (RFC 5246 §7.4.8) — a client proving
/// possession of the private key for the certificate it just sent.
pub fn build_certificate_verify(sig_hash: u8, sig_alg: u8, signature: &[u8]) -> Bytes {
    let mut body = BytesMut::with_capacity(4 + signature.len());
    body.extend_from_slice(&[sig_hash, sig_alg]);
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(signature);
    encode_message(MessageType::CertificateVerify, &body)
}

/// Parse a `CertificateVerify` body into `(sig_hash, sig_alg, signature)`.
pub fn parse_certificate_verify(body: &[u8]) -> Option<(u8, u8, Bytes)> {
    if body.len() < 4 {
        return None;
    }
    let sig_hash = body[0];
    let sig_alg = body[1];
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < 4 + sig_len {
        return None;
    }
    Some((sig_hash, sig_alg, Bytes::copy_from_slice(&body[4..4 + sig_len])))
}

/// Build a `ServerKeyExchange` for ECDHE (RFC 4492 §5.4): explicit named
/// curve, an uncompressed EC point, and a signature over
/// `client_random || server_random || ServerECDHParams`.
pub fn build_server_key_exchange(ec_point: &[u8], sig_hash: u8, sig_alg: u8, signature: &[u8]) -> Bytes {
    let mut body = BytesMut::new();
    body.extend_from_slice(&[EC_CURVE_TYPE_NAMED_CURVE]);
    body.extend_from_slice(&NAMED_CURVE_SECP256R1.to_be_bytes());
    body.extend_from_slice(&[ec_point.len() as u8]);
    body.extend_from_slice(ec_point);
    body.extend_from_slice(&[sig_hash, sig_alg]);
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(signature);
    encode_message(MessageType::ServerKeyExchange, &body)
}

/// The part of `ServerKeyExchange` the signature actually covers (RFC 4492 §5.4 `ServerECDHParams`).
pub fn server_ecdh_params_bytes(ec_point: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(4 + ec_point.len());
    out.extend_from_slice(&[EC_CURVE_TYPE_NAMED_CURVE]);
    out.extend_from_slice(&NAMED_CURVE_SECP256R1.to_be_bytes());
    out.extend_from_slice(&[ec_point.len() as u8]);
    out.extend_from_slice(ec_point);
    out.freeze()
}

/// Parsed `ServerKeyExchange` (ECDHE only — the only key exchange this
/// engine speaks; see crypto-migration-plan.md's "ECDHE only" scope note).
#[derive(Debug, Clone)]
pub struct ParsedServerKeyExchange {
    /// Server's EC point (uncompressed, 65 bytes for P-256).
    pub ec_point: Bytes,
    /// Signature hash algorithm byte.
    pub sig_hash: u8,
    /// Signature algorithm byte.
    pub sig_alg: u8,
    /// Signature bytes.
    pub signature: Bytes,
    /// The exact `ServerECDHParams` bytes the signature covers (for verification).
    pub signed_params: Bytes,
}

/// Parse a `ServerKeyExchange` body (named-curve ECDHE only).
pub fn parse_server_key_exchange(body: &[u8]) -> Option<ParsedServerKeyExchange> {
    if body.first() != Some(&EC_CURVE_TYPE_NAMED_CURVE) {
        return None; // explicit-prime/explicit-char2 curves not supported
    }
    let curve = u16::from_be_bytes([*body.get(1)?, *body.get(2)?]);
    if curve != NAMED_CURVE_SECP256R1 {
        return None;
    }
    let point_len = *body.get(3)? as usize;
    if body.len() < 4 + point_len + 2 {
        return None;
    }
    let ec_point = Bytes::copy_from_slice(&body[4..4 + point_len]);
    let signed_params = Bytes::copy_from_slice(&body[..4 + point_len]);
    let mut i = 4 + point_len;
    let sig_hash = body[i];
    let sig_alg = body[i + 1];
    i += 2;
    let sig_len = u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]) as usize;
    i += 2;
    if body.len() < i + sig_len {
        return None;
    }
    let signature = Bytes::copy_from_slice(&body[i..i + sig_len]);
    Some(ParsedServerKeyExchange { ec_point, sig_hash, sig_alg, signature, signed_params })
}

/// Build `ServerHelloDone` (empty body).
pub fn build_server_hello_done() -> Bytes {
    encode_message(MessageType::ServerHelloDone, &[])
}

/// Build `ClientKeyExchange` for ECDHE (RFC 4492 §5.7: just the client's EC point).
pub fn build_client_key_exchange(ec_point: &[u8]) -> Bytes {
    let mut body = BytesMut::with_capacity(1 + ec_point.len());
    body.extend_from_slice(&[ec_point.len() as u8]);
    body.extend_from_slice(ec_point);
    encode_message(MessageType::ClientKeyExchange, &body)
}

/// Parse a `ClientKeyExchange` body (ECDHE only) into the client's EC point.
pub fn parse_client_key_exchange(body: &[u8]) -> Option<Bytes> {
    let len = *body.first()? as usize;
    if body.len() < 1 + len {
        return None;
    }
    Some(Bytes::copy_from_slice(&body[1..1 + len]))
}

/// Build a `Finished` message.
pub fn build_finished(verify_data: &[u8]) -> Bytes {
    encode_message(MessageType::Finished, verify_data)
}

/// Build a `NewSessionTicket` message (RFC 5077 §3.3):
/// `uint32 ticket_lifetime_hint; opaque ticket<0..2^16-1>;`
pub fn build_new_session_ticket(lifetime_hint: u32, ticket: &[u8]) -> Bytes {
    let mut body = BytesMut::with_capacity(4 + 2 + ticket.len());
    body.extend_from_slice(&lifetime_hint.to_be_bytes());
    body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    body.extend_from_slice(ticket);
    encode_message(MessageType::NewSessionTicket, &body)
}

/// Parse a `NewSessionTicket` body into `(lifetime_hint, ticket)`.
pub fn parse_new_session_ticket(body: &[u8]) -> Option<(u32, Bytes)> {
    if body.len() < 6 {
        return None;
    }
    let lifetime_hint = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let ticket_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    if body.len() < 6 + ticket_len {
        return None;
    }
    Some((lifetime_hint, Bytes::copy_from_slice(&body[6..6 + ticket_len])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_round_trip() {
        let params = ClientHelloParams {
            random: [7u8; 32],
            session_id: &[],
            cipher_suites: &[0xC02F, 0xC030],
            server_name: Some("example.test"),
            session_ticket: None,
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = build_client_hello(&params);
        // 1-byte type + 3-byte length header.
        assert_eq!(wire[0], MessageType::ClientHello as u8);
        let body = &wire[4..];
        let parsed = parse_client_hello(body).expect("parse");
        assert_eq!(parsed.random, [7u8; 32]);
        assert_eq!(parsed.cipher_suites, vec![0xC02F, 0xC030]);
        assert_eq!(parsed.server_name.as_deref(), Some("example.test"));
        assert!(parsed.signature_algorithms.contains(&(sig_alg::HASH_SHA256, sig_alg::SIG_ECDSA)));
        assert!(parsed.extended_master_secret, "this engine always offers extended_master_secret");
        assert_eq!(parsed.renegotiation_info.as_deref(), Some([0u8].as_slice()));
    }

    /// DTLS's `ClientHello` (`legacy_version = 0xfefd`) carries one extra
    /// fixed-position field — `legacy_cookie` — right after `session_id`,
    /// which TCP TLS 1.2's `ClientHello` doesn't have at all. Proves the
    /// writer emits it and the reader correctly recovers it (and still
    /// lands on the right offset for everything after it) — mirrors the
    /// equivalent TLS-1.3-side test in `tls/handshake/messages.rs`.
    #[test]
    fn dtls_client_hello_carries_cookie_field() {
        let params = ClientHelloParams {
            random: [3u8; 32],
            session_id: &[],
            cipher_suites: &[0xC02F, 0xC030],
            server_name: None,
            session_ticket: None,
            legacy_version: 0xfefd,
            cookie: b"a-server-issued-cookie",
        };
        let wire = build_client_hello(&params);
        let parsed = parse_client_hello(&wire[4..]).expect("parse DTLS-shaped client hello");
        assert_eq!(parsed.cookie.as_ref(), b"a-server-issued-cookie");
        assert_eq!(parsed.cipher_suites, vec![0xC02F, 0xC030]);
    }

    #[test]
    fn hello_verify_request_round_trips_cookie() {
        let wire = build_hello_verify_request(0xfefd, b"stateless-cookie-bytes");
        assert_eq!(wire[0], MessageType::HelloVerifyRequest as u8);
        let cookie = parse_hello_verify_request(&wire[4..]).expect("parse");
        assert_eq!(cookie.as_ref(), b"stateless-cookie-bytes");
    }

    #[test]
    fn server_hello_round_trip() {
        let wire = build_server_hello(&[9u8; 32], &[1, 2, 3], 0xC02F, false, 0x0303, false);
        let parsed = parse_server_hello(&wire[4..]).expect("parse");
        assert_eq!(parsed.random, [9u8; 32]);
        assert_eq!(parsed.session_id.as_ref(), &[1, 2, 3]);
        assert_eq!(parsed.cipher_suite, 0xC02F);
        assert!(!parsed.session_ticket_offered);
        assert!(!parsed.extended_master_secret);
        assert_eq!(parsed.renegotiation_info.as_deref(), Some([0u8].as_slice()), "renegotiation_info is always sent");
    }

    #[test]
    fn server_hello_session_ticket_extension_round_trips() {
        // RFC 5077 §3.2: a client can only expect a `NewSessionTicket`
        // message later in this handshake if the server echoed this
        // extension here — a real `rustls` client rejects an unadvertised
        // one as a protocol violation (it's waiting for `ChangeCipherSpec`
        // at that point instead), so this bit has to round-trip exactly.
        let wire = build_server_hello(&[9u8; 32], &[], 0xC02F, true, 0x0303, false);
        let parsed = parse_server_hello(&wire[4..]).expect("parse");
        assert!(parsed.session_ticket_offered);
    }

    #[test]
    fn server_hello_extended_master_secret_round_trips() {
        // Confirms the new extension's presence doesn't shift the offset
        // of EC_POINT_FORMATS/SESSION_TICKET parsed after it.
        let wire = build_server_hello(&[9u8; 32], &[], 0xC02F, true, 0x0303, true);
        let parsed = parse_server_hello(&wire[4..]).expect("parse");
        assert!(parsed.extended_master_secret);
        assert!(parsed.session_ticket_offered);
    }

    #[test]
    fn certificate_round_trip() {
        let a = [1u8, 2, 3];
        let b = [4u8, 5, 6, 7];
        let wire = build_certificate(&[&a, &b]);
        let parsed = parse_certificate(&wire[4..]).expect("parse");
        assert_eq!(parsed, vec![Bytes::copy_from_slice(&a), Bytes::copy_from_slice(&b)]);
    }

    #[test]
    fn server_key_exchange_round_trip() {
        let point = [4u8; 65];
        let sig = [9u8; 70];
        let wire = build_server_key_exchange(&point, sig_alg::HASH_SHA256, sig_alg::SIG_ECDSA, &sig);
        let parsed = parse_server_key_exchange(&wire[4..]).expect("parse");
        assert_eq!(parsed.ec_point.as_ref(), &point[..]);
        assert_eq!(parsed.sig_hash, sig_alg::HASH_SHA256);
        assert_eq!(parsed.sig_alg, sig_alg::SIG_ECDSA);
        assert_eq!(parsed.signature.as_ref(), &sig[..]);
        assert_eq!(parsed.signed_params.as_ref(), server_ecdh_params_bytes(&point).as_ref());
    }

    #[test]
    fn client_key_exchange_round_trip() {
        let point = [4u8; 65];
        let wire = build_client_key_exchange(&point);
        let parsed = parse_client_key_exchange(&wire[4..]).expect("parse");
        assert_eq!(parsed.as_ref(), &point[..]);
    }

    #[test]
    fn client_hello_session_ticket_extension_round_trips() {
        let params = ClientHelloParams {
            random: [1u8; 32],
            session_id: &[9u8; 32],
            cipher_suites: &[0xC02F],
            server_name: None,
            session_ticket: Some(b"opaque-ticket-bytes"),
       
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = build_client_hello(&params);
        let parsed = parse_client_hello(&wire[4..]).expect("parse");
        assert_eq!(parsed.session_ticket.as_deref(), Some(&b"opaque-ticket-bytes"[..]));
        assert_eq!(parsed.session_id.as_ref(), &[9u8; 32]);
    }

    #[test]
    fn client_hello_empty_session_ticket_advertises_support() {
        let params = ClientHelloParams {
            random: [1u8; 32],
            session_id: &[],
            cipher_suites: &[0xC02F],
            server_name: None,
            session_ticket: Some(&[]),
       
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = build_client_hello(&params);
        let parsed = parse_client_hello(&wire[4..]).expect("parse");
        assert_eq!(parsed.session_ticket.as_deref(), Some(&b""[..]));
    }

    #[test]
    fn client_hello_without_session_ticket_extension_parses_as_none() {
        let params = ClientHelloParams {
            random: [1u8; 32],
            session_id: &[],
            cipher_suites: &[0xC02F],
            server_name: None,
            session_ticket: None,
       
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = build_client_hello(&params);
        let parsed = parse_client_hello(&wire[4..]).expect("parse");
        assert_eq!(parsed.session_ticket, None);
    }

    #[test]
    fn new_session_ticket_round_trip() {
        let wire = build_new_session_ticket(3600, b"a-sealed-ticket-blob");
        assert_eq!(wire[0], MessageType::NewSessionTicket as u8);
        let (lifetime, ticket) = parse_new_session_ticket(&wire[4..]).expect("parse");
        assert_eq!(lifetime, 3600);
        assert_eq!(ticket.as_ref(), b"a-sealed-ticket-blob");
    }
}
