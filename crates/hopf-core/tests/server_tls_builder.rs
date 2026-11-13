// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `ServerTlsBuilder` (issue #528) over real loopback TLS: client trust and
//! server credentials that change while the server runs, and a client
//! verifier of the caller's own. Each handshake is judged by what the
//! configuration says when it starts, with no restart in between.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::crypto::TrustStore;
use hopf_core::{
    connector_from_pem_tls12_with_client_cert, connector_from_pem_with_client_cert, server_credentials_from_pem_bytes,
    Bytes, ClientAuthPolicy, ClientVerifyOverride, Endpoint, ProtocolHandler, Runtime, RuntimeConfig,
    SecurityInfo, ServerCredentials, ServerCredentialsResolver, ServerTlsBuilder, SharedTlsConnector, TcpConnectorConfig,
    TcpListenerConfig, TcpTlsVersionPolicy,
};

/// A certificate with its key.
struct Issued {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl Issued {
    fn der(&self) -> Bytes {
        Bytes::copy_from_slice(self.cert.der())
    }

    fn credentials(&self) -> ServerCredentials {
        server_credentials_from_pem_bytes(self.cert.pem().as_bytes(), self.key.serialize_pem().as_bytes()).unwrap()
    }
}

fn ca() -> Issued {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).unwrap();
    Issued { cert, key }
}

/// A certificate for `names`, signed by `issuer`.
fn issue(issuer: &Issued, names: &[&str]) -> Issued {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
        .unwrap()
        .signed_by(&key, &issuer.cert, &issuer.key)
        .unwrap();
    Issued { cert, key }
}

fn self_signed(names: &[&str]) -> Issued {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    Issued { cert, key }
}

fn trust_of(cas: &[&Issued]) -> TrustStore {
    let mut store = TrustStore::new();
    for ca in cas {
        store.add_anchor(ca.der());
    }
    store
}

/// A scratch directory per call, with the PEM files a connector reads.
fn pem(label: &str, issued: &Issued) -> (PathBuf, PathBuf) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "hopf-core-tls-builder-{}-{}-{label}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, issued.cert.pem()).unwrap();
    std::fs::write(&key, issued.key.serialize_pem()).unwrap();
    (cert, key)
}

/// A connector that trusts `server_ca` and presents `client`.
fn client_of(server_ca: &Issued, client: &Issued, tls12: bool) -> SharedTlsConnector {
    let (ca_path, _) = pem("ca", server_ca);
    let (cert, key) = pem("client", client);
    if tls12 {
        connector_from_pem_tls12_with_client_cert(&ca_path, &cert, &key).unwrap()
    } else {
        connector_from_pem_with_client_cert(&ca_path, &cert, &key, &[]).unwrap()
    }
}

struct Echo;

impl ProtocolHandler for Echo {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            endpoint.send(data);
            *data = &[];
        });
    }
    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
}

/// What one client saw. A TLS 1.3 client sees the handshake complete before
/// the server has judged its certificate, so admission is observed through the
/// echo: only an admitted client gets one.
#[derive(Default)]
struct Outcome {
    echoed: bool,
    failed: bool,
    gone: bool,
    server_leaf: Option<Bytes>,
}

struct Probe(Arc<Mutex<Outcome>>);

impl ProtocolHandler for Probe {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn security_established(&mut self, endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
        self.0.lock().unwrap().server_leaf = info.peer_certificate_chain().and_then(|c| c.first().cloned());
        endpoint.send(b"ping");
    }
    fn receive(&mut self, _endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            if !data.is_empty() {
                self.0.lock().unwrap().echoed = true;
            }
            *data = &[];
        });
    }
    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.0.lock().unwrap().gone = true;
    }
    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        self.0.lock().unwrap().failed = true;
    }
}

struct Server {
    rt: Runtime,
    addr: std::net::SocketAddr,
}

impl Server {
    fn start(builder: ServerTlsBuilder) -> Self {
        let acceptor = builder.build().unwrap();
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), || Box::new(Echo) as Box<dyn ProtocolHandler>)
                    .with_tls(acceptor),
            )
            .unwrap();
        Self { rt, addr }
    }

    /// Dial as `connector`, asking for `sni`, and wait for the verdict.
    fn dial(&self, connector: &SharedTlsConnector, sni: &str) -> Outcome {
        let out = Arc::new(Mutex::new(Outcome::default()));
        let sink = Arc::clone(&out);
        self.rt
            .connect(
                TcpConnectorConfig::new(self.addr, move || Box::new(Probe(Arc::clone(&sink))) as Box<dyn ProtocolHandler>)
                    .with_tls(Arc::clone(connector), sni),
            )
            .unwrap();
        for _ in 0..200 {
            {
                let o = out.lock().unwrap();
                if o.echoed || o.failed || o.gone {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let outcome = std::mem::take(&mut *out.lock().unwrap());
        outcome
    }

    fn stop(self) {
        self.rt.shutdown();
    }
}

#[test]
fn client_trust_is_fetched_for_every_handshake_so_it_can_be_swapped() {
    let server_ca = ca();
    let server = issue(&server_ca, &["localhost"]);
    let (old_ca, new_ca) = (ca(), ca());
    let old_client = issue(&old_ca, &[]);
    let new_client = issue(&new_ca, &[]);
    let old = client_of(&server_ca, &old_client, false);
    let new = client_of(&server_ca, &new_client, false);

    let current = Arc::new(Mutex::new(trust_of(&[&old_ca])));
    let source = Arc::clone(&current);
    let s = Server::start(
        ServerTlsBuilder::new()
            .credentials(server.credentials())
            .client_auth(ClientAuthPolicy::Require)
            .client_trust(move || source.lock().unwrap().clone()),
    );

    assert!(s.dial(&old, "localhost").echoed, "a client of the trusted CA is admitted");
    assert!(!s.dial(&new, "localhost").echoed, "a client of the other CA is not");

    // Swap the trust anchors; the server keeps running.
    *current.lock().unwrap() = trust_of(&[&new_ca]);

    assert!(s.dial(&new, "localhost").echoed, "the new CA's client is admitted after the swap");
    let refused = s.dial(&old, "localhost");
    assert!(!refused.echoed, "and the old CA's client no longer is");
    assert!(refused.failed || refused.gone, "the refusal is reported");
    s.stop();
}

#[test]
fn a_client_verifier_decides_instead_of_a_trust_store() {
    let server_ca = ca();
    let server = issue(&server_ca, &["localhost"]);
    // Neither is signed by anything the server was told about.
    let allowed = self_signed(&[]);
    let stranger = self_signed(&[]);
    let allowed_client = client_of(&server_ca, &allowed, false);
    let stranger_client = client_of(&server_ca, &stranger, false);

    let allowed_der = allowed.der();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let s = Server::start(
        ServerTlsBuilder::new()
            .credentials(server.credentials())
            .client_auth(ClientAuthPolicy::Require)
            .client_verify(ClientVerifyOverride::new(move |chain| {
                counter.fetch_add(1, Ordering::SeqCst);
                chain.first() == Some(&allowed_der)
            })),
    );

    assert!(s.dial(&allowed_client, "localhost").echoed);
    assert!(!s.dial(&stranger_client, "localhost").echoed);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "the verifier ran once per handshake");
    s.stop();
}

#[test]
fn a_client_verifier_also_decides_over_tls_1_2() {
    let server_ca = ca();
    let server = issue(&server_ca, &["localhost"]);
    let allowed = self_signed(&[]);
    let stranger = self_signed(&[]);
    let allowed_client = client_of(&server_ca, &allowed, true);
    let stranger_client = client_of(&server_ca, &stranger, true);

    let allowed_der = allowed.der();
    let s = Server::start(
        ServerTlsBuilder::new()
            .credentials(server.credentials())
            .tcp_version_policy(TcpTlsVersionPolicy::Tls12Only)
            .client_auth(ClientAuthPolicy::Require)
            .client_verify(ClientVerifyOverride::new(move |chain| chain.first() == Some(&allowed_der))),
    );

    assert!(s.dial(&allowed_client, "localhost").echoed);
    assert!(!s.dial(&stranger_client, "localhost").echoed);
    s.stop();
}

#[test]
fn a_credentials_resolver_and_client_auth_work_together_and_rotate() {
    // The client trusts `server_ca` only, so which certificate the server
    // presented shows in whether the handshake completes.
    let server_ca = ca();
    let other_ca = ca();
    let client_ca = ca();
    let client = issue(&client_ca, &[]);
    let connector = client_of(&server_ca, &client, false);

    // The resolver reads what is current on every handshake. two.test starts
    // with a certificate the client does not trust.
    let by_name = Arc::new(Mutex::new(vec![
        ("one.test".to_string(), issue(&server_ca, &["one.test"]).credentials()),
        ("two.test".to_string(), issue(&other_ca, &["two.test"]).credentials()),
    ]));
    let table = Arc::clone(&by_name);
    let resolver = ServerCredentialsResolver(Arc::new(move |sni: Option<&str>| {
        let table = table.lock().unwrap();
        table.iter().find(|(name, _)| Some(name.as_str()) == sni).map(|(_, c)| c.clone())
    }));
    let s = Server::start(
        ServerTlsBuilder::new()
            .server_resolver(resolver)
            .client_auth(ClientAuthPolicy::Require)
            .client_trust_store(trust_of(&[&client_ca])),
    );

    assert!(s.dial(&connector, "one.test").echoed, "client auth still applies with a resolver");
    assert!(!s.dial(&connector, "two.test").echoed, "the certificate is chosen by name: two.test's is untrusted");

    // Rotate both while the server runs.
    {
        let mut table = by_name.lock().unwrap();
        table[0].1 = issue(&other_ca, &["one.test"]).credentials();
        table[1].1 = issue(&server_ca, &["two.test"]).credentials();
    }
    assert!(!s.dial(&connector, "one.test").echoed, "the next handshake presents one.test's new, untrusted certificate");
    assert!(s.dial(&connector, "two.test").echoed, "and two.test's new, trusted one");
    s.stop();
}

/// `ClientTlsBuilder`: trust anchors and a client certificate together, and a
/// verifier of the caller's own that sees the name being verified.
#[test]
fn client_tls_builder_combines_anchors_a_client_certificate_and_a_verifier() {
    use hopf_core::ClientTlsBuilder;

    let server_ca = ca();
    let server = issue(&server_ca, &["localhost"]);
    let client_ca = ca();
    let client = issue(&client_ca, &[]);
    let s = Server::start(
        ServerTlsBuilder::new()
            .credentials(server.credentials())
            .client_auth(ClientAuthPolicy::Require)
            .client_trust_store(trust_of(&[&client_ca])),
    );

    // Anchors and a certificate: admitted.
    let good = ClientTlsBuilder::new()
        .trust_anchors([server_ca.der()])
        .client_credentials(client.credentials())
        .build();
    assert!(s.dial(&good, "localhost").echoed);

    // The same anchors with no certificate: the server refuses.
    let anonymous = ClientTlsBuilder::new().trust_anchors([server_ca.der()]).build();
    assert!(!s.dial(&anonymous, "localhost").echoed);

    // Anchors that do not include the server's CA: the client refuses.
    let wrong = ClientTlsBuilder::new()
        .trust_anchors([client_ca.der()])
        .client_credentials(client.credentials())
        .build();
    assert!(!s.dial(&wrong, "localhost").echoed);

    // A verifier replaces the trust check, and is told the name.
    let names = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&names);
    let leaf = server.der();
    let by_leaf = ClientTlsBuilder::new()
        .verify(Arc::new(move |chain: &[Bytes], name: Option<&str>| {
            seen.lock().unwrap().push(name.map(str::to_owned));
            chain.first() == Some(&leaf)
        }))
        .client_credentials(client.credentials())
        .build();
    assert!(s.dial(&by_leaf, "localhost").echoed, "no anchors needed when the verifier accepts the leaf");
    assert_eq!(names.lock().unwrap().as_slice(), [Some("localhost".to_string())]);
    s.stop();
}
