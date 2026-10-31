// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-tree TLS 1.3: [`HandshakeEngine`] (Phase 2, QUIC-first) plus [`record`],
//! the Phase 4 TCP record layer wrapping it in [`HandshakeMode::TcpRecordLayer`]
//! behind [`TlsRecordEngine`]. [`pem`] loads PEM certs/keys into
//! [`TlsAcceptor`]/[`TlsConnector`] factories that `TcpConnection` pumps
//! directly — `hopf-tls` (rustls) is no longer in `TcpConnection`'s path.

pub mod ech;
mod engine;
pub mod fips;
mod handshake;
mod key_log;
mod pem;
mod record;
mod sink;
mod ticket_keys;
// `pub(crate)`, not private: `hopf-core::dtls12` (DTLS 1.2) wraps
// `tls12::engine::Tls12Engine` directly, the same way `hopf-core::dtls`
// wraps `engine::HandshakeEngine` (TLS 1.3) — needs `tls12::engine`'s
// `CipherKind`/`DirectionalKeyMaterial`/`Tls12EventSink`/`Tls12Engine`
// reachable via the full path, none of which `tls/mod.rs`'s own `pub use`
// list re-exports today.
pub(crate) mod tls12;
mod negotiating;
mod tcp_version_policy;
pub(crate) mod version_pick;

pub use tcp_version_policy::TcpTlsVersionPolicy;

/// Opaque handle for in-handshake TLS version negotiation (see [`TlsVariant::Negotiating`]).
pub struct NegotiatingTls(Box<negotiating::NegotiatingTls>);

impl NegotiatingTls {
    pub(crate) fn new(inner: negotiating::NegotiatingTls) -> Self {
        Self(Box::new(inner))
    }

    fn inner(&self) -> &negotiating::NegotiatingTls {
        &self.0
    }

    fn inner_mut(&mut self) -> &mut negotiating::NegotiatingTls {
        &mut self.0
    }

    pub(crate) fn start<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        self.inner_mut().start(sink);
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.inner().is_complete()
    }

    pub(crate) fn set_alpn(&mut self, protocols: &[&[u8]]) -> bool {
        self.inner_mut().set_alpn(protocols)
    }

    pub(crate) fn set_require_supported_versions(&mut self, required: bool) -> bool {
        self.inner_mut().set_require_supported_versions(required)
    }

    pub(crate) fn set_record_size_limit(&mut self, limit: Option<u16>) -> bool {
        self.inner_mut().set_record_size_limit(limit)
    }

    pub(crate) fn set_fips(&mut self) -> Result<(), fips::FipsProfileError> {
        self.inner_mut().set_fips()
    }

    pub(crate) fn set_ech_client(&mut self, config: ech::EchClientConfig) -> bool {
        self.inner_mut().set_ech_client(config)
    }

    pub(crate) fn set_ech_server(&mut self, config: std::sync::Arc<ech::EchServerConfig>) -> bool {
        self.inner_mut().set_ech_server(config)
    }

    pub(crate) fn feed_ciphertext<S: TlsRecordSink + ?Sized>(&mut self, buf: &mut loopbuf::LoopBuf, sink: &mut S) -> bool {
        self.inner_mut().feed_ciphertext(buf, sink)
    }

    pub(crate) fn send_application_data<S: TlsRecordSink + ?Sized>(&mut self, plaintext: &[u8], sink: &mut S) {
        self.inner_mut().send_application_data(plaintext, sink);
    }

    pub(crate) fn feed_verification_result<S: TlsRecordSink + ?Sized>(
        &mut self,
        result: VerifyResult,
        sink: &mut S,
    ) {
        self.inner_mut().feed_verification_result(result, sink);
    }

    pub(crate) fn send_close_notify<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        self.inner_mut().send_close_notify(sink);
    }
}

pub use engine::{
    ClientAuthPolicy, HandshakeConfig, HandshakeEngine, HandshakeMode, HandshakeRole,
    ServerCredentials, ServerCredentialsResolver, Tls13Aead, VerifyOverride, AES_128_GCM_SHA256,
    AES_256_GCM_SHA384, CHACHA20_POLY1305_SHA256, SUPPORTED_CIPHER_SUITES,
};
pub use handshake::TrafficSecret;
pub use handshake::ticket::{
    AntiReplay, ClientTicketStore, DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS, TICKET_LIFETIME_SECS,
};
pub use key_log::{
    default_key_log, labels as key_log_labels, set_default_key_log, KeyLog, KeyLogFile,
    SSLKEYLOGFILE_ENV,
};
pub use handshake::transport_params::{
    decode_initial_max_data, encode_initial_max_data, RememberedTransportLimits,
};
pub use pem::{
    acceptor_from_pem, acceptor_from_pem_tls12, acceptor_from_pem_tls12_with_client_auth,
    acceptor_from_pem_with_client_auth, acceptor_from_credentials, acceptor_from_credentials_with_client_auth, server_credentials_from_pem_bytes, acceptor_from_pem_with_sni, connector_from_pem,
    connector_from_pem_tls12, connector_from_pem_tls12_with_client_cert,
    connector_from_pem_with_client_cert, connector_with_alpn, connector_with_record_size_limit,
    acceptor_with_fips, connector_with_fips, connector_with_verify_override, acceptor_requiring_supported_versions, acceptor_with_alpn, acceptor_with_record_size_limit, acceptor_with_ech, connector_with_ech, insecure_connector,
    acceptor_from_pem_with_tcp_version_policy, connector_from_pem_with_tcp_version_policy,
    insecure_connector_tls12, public_trust_connector, server_credentials_from_pem, SharedTlsAcceptor,
    SharedTlsConnector, TlsAcceptor, TlsConnector,
};
pub use record::{NopTlsRecordSink, TlsRecordEngine, TlsRecordSink};
pub use sink::{
    AlertDescription, KeyUpdateDirection, NopTlsEventSink, QuicSecrets, RecordSizeLimits, TlsEventSink, TlsProtocolError, TlsTimerKind,
    VerifyRequest, VerifyResult,
};
pub use ticket_keys::TicketKeys;
pub use tls12::engine::{Config as Tls12Config, Role as Tls12Role, SUPPORTED_CIPHER_SUITES as TLS12_SUPPORTED_CIPHER_SUITES};
pub use tls12::record::Tls12RecordEngine;
pub use tls12::ticket::{StoredTls12Ticket, Tls12ClientTicketStore, TICKET_LIFETIME_SECS as TLS12_TICKET_LIFETIME_SECS};

/// Either TLS version's record engine — `TcpConnection` pumps whichever one
/// its configured acceptor/connector produced through one shared surface
/// (both engines expose the same method set and the same
/// [`TlsRecordSink`], so this is a thin, no-behavior-of-its-own dispatch).
///
/// TLS 1.3's record-layer state is substantially larger than 1.2's; one
/// allocation per connection (already behind that connection's own
/// indirection, not a hot-loop copy), so boxing it isn't worth the diff
/// across every match site that dispatches on this enum.
#[allow(clippy::large_enum_variant)]
pub enum TlsVariant {
    /// TLS 1.3 (the default; every existing `hopf-core::tls::pem` helper builds this).
    V13(TlsRecordEngine),
    /// TLS 1.2 (legacy mail/FTPS interop; ECDHE + GCM only for now).
    V12(Tls12RecordEngine),
    /// TCP only: buffer the first handshake flight, pick 1.2 vs 1.3, then delegate.
    Negotiating(NegotiatingTls),
}

impl TlsVariant {
    /// Begin the handshake — client emits `ClientHello`; server waits for input.
    pub fn start<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            TlsVariant::V13(e) => e.start(sink),
            TlsVariant::V12(e) => e.start(sink),
            TlsVariant::Negotiating(n) => n.start(sink),
        }
    }

    /// Whether the handshake has completed.
    pub fn is_complete(&self) -> bool {
        match self {
            TlsVariant::V13(e) => e.is_complete(),
            TlsVariant::V12(e) => e.is_complete(),
            TlsVariant::Negotiating(n) => n.is_complete(),
        }
    }

    /// Set the ALPN protocol names (RFC 7301) this connection offers (client)
    /// or selects from (server), replacing whatever the builder configured.
    /// Works for both TLS versions. Must be called before [`Self::start`];
    /// returns whether it took effect. The outcome is
    /// [`SecurityInfo::alpn`](crate::SecurityInfo::alpn).
    pub fn set_alpn(&mut self, protocols: &[&[u8]]) -> bool {
        let list: Vec<bytes::Bytes> = protocols.iter().map(|p| bytes::Bytes::copy_from_slice(p)).collect();
        match self {
            TlsVariant::V13(e) => e.set_alpn(list),
            TlsVariant::V12(e) => e.set_alpn(list),
            TlsVariant::Negotiating(n) => n.set_alpn(protocols),
        }
    }

    /// Server side: refuse a TLS 1.2 `ClientHello` that lacks the
    /// `supported_versions` extension, as RFC 9846 section 1.4 requires; see
    /// [`Tls12Config::require_supported_versions`].
    /// Only TLS 1.2 has the requirement: for a TLS 1.3 engine this does nothing
    /// and returns `false`. Must be called before [`Self::start`].
    pub fn set_require_supported_versions(&mut self, required: bool) -> bool {
        match self {
            TlsVariant::V13(_) => false,
            TlsVariant::V12(e) => e.set_require_supported_versions(required),
            TlsVariant::Negotiating(n) => n.set_require_supported_versions(required),
        }
    }

    /// Advertise a `record_size_limit` (RFC 8449) on this connection; see
    /// [`TlsRecordEngine::set_record_size_limit`]. Only TLS 1.3 supports the
    /// extension: for a TLS 1.2 engine this does nothing and returns `false`.
    /// Must be called before [`Self::start`].
    pub fn set_record_size_limit(&mut self, limit: Option<u16>) -> bool {
        match self {
            TlsVariant::V13(e) => e.set_record_size_limit(limit),
            TlsVariant::V12(_) => false,
            TlsVariant::Negotiating(n) => n.set_record_size_limit(limit),
        }
    }

    /// Hold this connection to the FIPS profile (see
    /// [`fips`](crate::tls::fips)): TLS 1.3 and TLS 1.2 are both restricted,
    /// so a negotiating engine is on the profile whichever version it lands on.
    /// Must be called before [`Self::start`]. Fails, leaving the engine
    /// unchanged, if it is already started or its config names anything
    /// outside the profile (such as ECH).
    pub fn set_fips(&mut self) -> Result<(), fips::FipsProfileError> {
        match self {
            TlsVariant::V13(e) => e.set_fips(),
            TlsVariant::V12(e) => e.set_fips(),
            TlsVariant::Negotiating(n) => n.set_fips(),
        }
    }

    /// Client side: offer Encrypted Client Hello (RFC 9849) with `config`, or
    /// GREASE when it holds no usable config. Only TLS 1.3 supports it: for a
    /// TLS 1.2 engine this does nothing and returns `false`. Must be called
    /// before [`Self::start`].
    pub fn set_ech_client(&mut self, config: ech::EchClientConfig) -> bool {
        match self {
            TlsVariant::V13(e) => e.set_ech_client(Some(config)),
            TlsVariant::V12(_) => false,
            TlsVariant::Negotiating(n) => n.set_ech_client(config),
        }
    }

    /// Server side: accept and publish Encrypted Client Hello keys. TLS 1.3
    /// only (`false` on TLS 1.2). Must be called before [`Self::start`].
    pub fn set_ech_server(&mut self, config: std::sync::Arc<ech::EchServerConfig>) -> bool {
        match self {
            TlsVariant::V13(e) => e.set_ech_server(Some(config)),
            TlsVariant::V12(_) => false,
            TlsVariant::Negotiating(n) => n.set_ech_server(config),
        }
    }

    /// Consume the record at the front of the connection's inbound ring, if
    /// all of it is there (at most one per call; true if one was consumed).
    pub fn feed_ciphertext<S: TlsRecordSink + ?Sized>(&mut self, buf: &mut loopbuf::LoopBuf, sink: &mut S) -> bool {
        match self {
            TlsVariant::V13(e) => e.feed_ciphertext(buf, sink),
            TlsVariant::V12(e) => e.feed_ciphertext(buf, sink),
            TlsVariant::Negotiating(n) => n.feed_ciphertext(buf, sink),
        }
    }

    /// Feeds every record in `wire`, for a caller that holds the bytes in a
    /// slice rather than a ring (see [`TlsRecordEngine::feed_ciphertext_all`]).
    pub fn feed_ciphertext_all<S: TlsRecordSink + ?Sized>(&mut self, wire: &[u8], sink: &mut S) {
        let mut ring = loopbuf::LoopBuf::with_capacity(wire.len().max(1));
        ring.extend_from_slice(wire);
        while self.feed_ciphertext(&mut ring, sink) {}
    }

    /// Encrypt and frame application data. Only valid once [`Self::is_complete`].
    pub fn send_application_data<S: TlsRecordSink + ?Sized>(&mut self, plaintext: &[u8], sink: &mut S) {
        match self {
            TlsVariant::V13(e) => e.send_application_data(plaintext, sink),
            TlsVariant::V12(e) => e.send_application_data(plaintext, sink),
            TlsVariant::Negotiating(n) => n.send_application_data(plaintext, sink),
        }
    }

    /// Resume after chain verification (from `StorageExecutor` or inline).
    pub fn feed_verification_result<S: TlsRecordSink + ?Sized>(&mut self, result: VerifyResult, sink: &mut S) {
        match self {
            TlsVariant::V13(e) => e.feed_verification_result(result, sink),
            TlsVariant::V12(e) => e.feed_verification_result(result, sink),
            TlsVariant::Negotiating(n) => n.feed_verification_result(result, sink),
        }
    }

    /// Send a `close_notify` alert under the current epoch.
    pub fn send_close_notify<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            TlsVariant::V13(e) => e.send_close_notify(sink),
            TlsVariant::V12(e) => e.send_close_notify(sink),
            TlsVariant::Negotiating(n) => n.send_close_notify(sink),
        }
    }
}

/// Takes the TLS record at the front of `buf` out of it: its 5-byte header
/// and a copy of its body (to be decrypted in place). `Ok(None)` if the
/// whole record is not there yet, and nothing is consumed; `Err` if it
/// declares a body longer than `max_body`, which no valid record does.
pub(crate) fn take_record(
    buf: &mut loopbuf::LoopBuf,
    max_body: usize,
) -> Result<Option<([u8; 5], Vec<u8>)>, ()> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let (first, second) = buf.readable_spans();
    let mut header = [0u8; 5];
    let n = first.len().min(5);
    header[..n].copy_from_slice(&first[..n]);
    header[n..].copy_from_slice(&second[..5 - n]);
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > max_body {
        return Err(());
    }
    if buf.len() < 5 + len {
        return Ok(None);
    }
    let mut body = Vec::with_capacity(len);
    let skip = 5.min(first.len());
    let from_first = &first[skip..];
    let take_first = from_first.len().min(len);
    body.extend_from_slice(&from_first[..take_first]);
    if take_first < len {
        let second_skip = 5 - skip;
        body.extend_from_slice(&second[second_skip..second_skip + (len - take_first)]);
    }
    buf.advance(5 + len);
    Ok(Some((header, body)))
}

/// A copy of up to `max` bytes at the front of `buf`, to be looked at as one
/// slice without consuming them.
pub(crate) fn peek_front(buf: &loopbuf::LoopBuf, max: usize) -> Vec<u8> {
    let (first, second) = buf.readable_spans();
    let mut out = Vec::with_capacity((first.len() + second.len()).min(max));
    let n = first.len().min(max);
    out.extend_from_slice(&first[..n]);
    out.extend_from_slice(&second[..(max - n).min(second.len())]);
    out
}

#[cfg(test)]
mod ring_tests {
    use super::*;
    use loopbuf::LoopBuf;

    fn record(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x17, 3, 3, (body.len() >> 8) as u8, body.len() as u8];
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn take_record_waits_for_the_whole_record_and_leaves_it() {
        let wire = record(b"hello");
        for cut in 0..wire.len() {
            let mut buf = LoopBuf::with_capacity(64);
            buf.extend_from_slice(&wire[..cut]);
            assert_eq!(take_record(&mut buf, 100), Ok(None), "cut={cut}");
            assert_eq!(buf.len(), cut, "nothing consumed");
        }
    }

    #[test]
    fn take_record_reads_a_record_wherever_the_ring_wraps() {
        let wire = record(b"0123456789");
        for lead in 0..20 {
            let mut buf = LoopBuf::with_capacity(32);
            buf.extend_from_slice(&vec![0u8; lead]);
            buf.advance(lead);
            let mut two = wire.clone();
            two.extend(record(b"next"));
            assert_eq!(buf.extend_from_slice(&two), two.len());
            let (header, body) = take_record(&mut buf, 100).unwrap().unwrap();
            assert_eq!(&header[..], &wire[..5], "lead={lead}");
            assert_eq!(body, b"0123456789", "lead={lead}");
            let (_, body) = take_record(&mut buf, 100).unwrap().unwrap();
            assert_eq!(body, b"next", "lead={lead}");
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn take_record_rejects_an_overlong_declared_body_from_its_header() {
        let mut buf = LoopBuf::with_capacity(16);
        buf.extend_from_slice(&[0x17, 3, 3, 0x41, 0x01]);
        assert_eq!(take_record(&mut buf, 16_640), Err(()));
    }

    #[test]
    fn peek_front_copies_without_consuming() {
        let mut buf = LoopBuf::with_capacity(8);
        buf.extend_from_slice(&[0u8; 6]);
        buf.advance(6);
        buf.extend_from_slice(b"abcdef");
        assert_eq!(peek_front(&buf, 4), b"abcd");
        assert_eq!(peek_front(&buf, 100), b"abcdef");
        assert_eq!(buf.len(), 6);
    }
}
