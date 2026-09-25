// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Encrypted Client Hello over DTLS 1.3 (RFC 9849 applies to DTLS unchanged:
//! the same HPKE material and the same `ClientHelloInner`/`Outer` handshake,
//! carried through DTLS handshake fragmentation and flights).
//!
//! Loopback only: no independent DTLS 1.3 ECH peer was available to test
//! against, so these prove hopf against hopf.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use super::{DtlsRecordEngine, DtlsRecordSink};
use crate::crypto::hpke::Kem;
use crate::crypto::kx_policy::KxPolicy;
use crate::crypto::trust::TrustStore;
use crate::security::SecurityInfo;
use crate::tls::ech::{EchClientConfig, EchConfig, EchServerConfig, EchServerKey, HpkeCipherSuite};
use crate::tls::{
    AlertDescription, HandshakeConfig, HandshakeMode, HandshakeRole, ServerCredentials, TlsProtocolError,
    VerifyRequest,
};

const PUBLIC: &str = "public.example";
const INNER: &str = "inner.example";

#[derive(Default)]
struct Sink {
    out: Vec<Vec<u8>>,
    sent: Vec<u8>,
    info: Option<SecurityInfo>,
    errors: Vec<TlsProtocolError>,
}

impl DtlsRecordSink for Sink {
    fn datagram_ready(&mut self, data: &[u8]) {
        self.sent.extend_from_slice(data);
        self.out.push(data.to_vec());
    }
    fn application_data(&mut self, _plaintext: &[u8]) {}
    fn handshake_complete(&mut self, info: SecurityInfo) {
        self.info = Some(info);
    }
    fn verification_requested(&mut self, _req: VerifyRequest) {}
    fn protocol_error(&mut self, err: TlsProtocolError) {
        self.errors.push(err);
    }
    fn peer_closed(&mut self) {}
    fn arm_retransmit_timer(&mut self, _after: Option<Duration>) {}
}

fn creds(names: &[&str]) -> ServerCredentials {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    ServerCredentials {
        cert_chain: vec![Bytes::copy_from_slice(cert.der())],
        signing_key_pkcs8: Bytes::from(kp.serialize_der()),
    }
}

fn server_key(id: u8) -> (EchServerKey, EchConfig) {
    let suites = vec![HpkeCipherSuite { kdf_id: 1, aead_id: 1 }];
    let (config, key) = EchConfig::generate(id, Kem::DhkemX25519HkdfSha256, suites, 32, PUBLIC).unwrap();
    (EchServerKey::new(config.clone(), key).unwrap(), config)
}

struct Outcome {
    client: DtlsRecordEngine,
    server: DtlsRecordEngine,
    cs: Sink,
    ss: Sink,
}

fn run(
    creds: &ServerCredentials,
    client_kx: KxPolicy,
    ech: Option<EchClientConfig>,
    server_keys: Option<Vec<EchServerKey>>,
) -> Outcome {
    let mut trust = TrustStore::new();
    trust.add_anchor(creds.cert_chain[0].clone());
    let mut client = DtlsRecordEngine::new(HandshakeConfig {
        role: HandshakeRole::Client,
        mode: HandshakeMode::Dtls,
        alpn: vec![Bytes::from_static(b"test")],
        server_name: Some(INNER.into()),
        kx_policy: client_kx,
        trust_store: Some(trust),
        ech_client: ech,
        ..Default::default()
    });
    let mut server = DtlsRecordEngine::new(HandshakeConfig {
        role: HandshakeRole::Server,
        mode: HandshakeMode::Dtls,
        alpn: vec![Bytes::from_static(b"test")],
        server: Some(creds.clone()),
        kx_policy: KxPolicy::classical_only(),
        ech_server: server_keys.map(|k| Arc::new(EchServerConfig::new(k))),
        ..Default::default()
    });
    let (mut cs, mut ss) = (Sink::default(), Sink::default());
    client.start(&mut cs);
    for _ in 0..6 {
        for d in std::mem::take(&mut cs.out) {
            server.feed_datagram(&d, &mut ss);
        }
        for d in std::mem::take(&mut ss.out) {
            client.feed_datagram(&d, &mut cs);
        }
    }
    Outcome { client, server, cs, ss }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn ech_is_accepted_over_dtls_and_hides_the_real_name() {
    let c = creds(&[INNER, PUBLIC]);
    let (key, config) = server_key(4);
    let o = run(&c, KxPolicy::classical_only(), Some(EchClientConfig::new(vec![config])), Some(vec![key]));
    assert!(o.client.is_complete(), "client {:?}", o.cs.errors);
    assert!(o.server.is_complete(), "server {:?}", o.ss.errors);
    assert_eq!(o.ss.info.as_ref().unwrap().sni(), Some(INNER));
    assert!(contains(&o.cs.sent, PUBLIC));
    assert!(!contains(&o.cs.sent, INNER), "real SNI leaked over DTLS");
}

#[test]
fn ech_survives_a_dtls_hello_retry_request() {
    // A hybrid key share the classical-only server refuses forces an HRR; the
    // second flight reuses the HPKE context and the DTLS-specific accept label.
    let c = creds(&[INNER, PUBLIC]);
    let (key, config) = server_key(4);
    let o = run(&c, KxPolicy::default(), Some(EchClientConfig::new(vec![config])), Some(vec![key]));
    assert!(o.client.is_complete(), "client {:?}", o.cs.errors);
    assert!(o.server.is_complete(), "server {:?}", o.ss.errors);
    assert_eq!(o.ss.info.as_ref().unwrap().sni(), Some(INNER));
    assert!(!contains(&o.cs.sent, INNER));
}

#[test]
fn a_stale_config_is_rejected_over_dtls_with_retry_configs() {
    let c = creds(&[PUBLIC]);
    let (_old, stale) = server_key(4);
    let (current, current_config) = server_key(5);
    let o = run(&c, KxPolicy::classical_only(), Some(EchClientConfig::new(vec![stale])), Some(vec![current]));
    assert!(!o.client.is_complete());
    let err = o.cs.errors.first().expect("client must fail");
    assert_eq!(err.alert, AlertDescription::EchRequired);
    assert_eq!(
        &err.ech_retry_configs.as_ref().expect("retry_configs")[..],
        &EchConfig::encode_list(&[current_config]).unwrap()[..]
    );
}

#[test]
fn grease_and_plain_clients_are_unaffected_over_dtls() {
    let c = creds(&[INNER]);
    let (key, _) = server_key(4);
    for ech in [Some(EchClientConfig::grease_only()), None] {
        let o = run(&c, KxPolicy::classical_only(), ech, Some(vec![key.clone()]));
        assert!(o.client.is_complete(), "client {:?}", o.cs.errors);
        assert!(o.server.is_complete(), "server {:?}", o.ss.errors);
    }
}
