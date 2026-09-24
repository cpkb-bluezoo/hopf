// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HSTS end to end over a real TLS listener and a plaintext one.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::{acceptor_from_pem, connector_from_pem, Runtime};

use crate::content_coding::e2e_tests::{rt, run_with, Job, Outcome};
use crate::stream::{ServerHandler, ServerHandlerFactory, ServerWriter};
use crate::version::HttpVersion;
use crate::{Headers, HstsPolicy, HttpClient, HttpServer};

struct App {
    path: String,
}

/// What the handler itself can see of the connection: the transport facts a
/// handler (or a decorator like HSTS) has to be able to rely on.
fn describe(w: &dyn ServerWriter) -> String {
    let info = w.connection_info();
    format!("secure={} remote={}", info.is_secure(), info.remote_addr().is_some())
}

impl ServerHandler for App {
    fn headers(&mut self, _w: &mut dyn ServerWriter, h: &Headers) {
        self.path = h.path().unwrap_or("").to_string();
    }

    fn request_complete(&mut self, w: &mut dyn ServerWriter) {
        let mut h = Headers::new();
        h.status(200);
        h.set("content-type", "text/plain");
        match self.path.as_str() {
            "/missing" => {
                h.status(404);
            }
            "/info" => {
                w.headers(h);
                w.response_body_content(describe(w).as_bytes());
                w.end_response_body();
                w.complete();
                return;
            }
            "/own" => {
                h.set("strict-transport-security", "max-age=1");
            }
            "/cond" => {
                h.set("etag", "\"v1\"");
            }
            "/deferred" => {
                let handle = w.response_handle();
                std::thread::spawn(move || {
                    handle.execute(move |w| {
                        w.headers(h);
                        w.response_body_content(b"later");
                        w.end_response_body();
                        w.complete();
                    });
                });
                return;
            }
            _ => {}
        }
        w.headers(h);
        w.response_body_content(b"body");
        w.end_response_body();
        w.complete();
    }
}

struct Factory;
impl ServerHandlerFactory for Factory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(App { path: String::new() })
    }
}

/// A self-signed `localhost` cert in `dir`; returns (cert, key) paths.
fn cert(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let c = params.self_signed(&key).unwrap();
    let (cp, kp) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cp, c.pem()).unwrap();
    std::fs::write(&kp, key.serialize_pem()).unwrap();
    (cp, kp)
}

/// A TLS listener offering `alpn`, and a client that trusts it.
fn tls_server(rt: &Arc<Runtime>, dir: &std::path::Path, alpn: &[&[u8]], hsts: Option<HstsPolicy>) -> (SocketAddr, HttpClient) {
    let (cp, kp) = cert(dir);
    let mut s = HttpServer::new().tls(acceptor_from_pem(&cp, &kp, alpn).unwrap());
    if let Some(p) = hsts {
        s = s.hsts(p);
    }
    let addr = s.bind(rt, "127.0.0.1:0".parse().unwrap(), Arc::new(Factory)).unwrap().0;
    let client = HttpClient::from_addr(addr)
        .tls(connector_from_pem(&cp, alpn).unwrap(), "localhost")
        .disable_content_encoding();
    (addr, client)
}

fn policy() -> HstsPolicy {
    HstsPolicy::new(Duration::from_secs(31_536_000)).include_subdomains()
}

const WANT: &str = "max-age=31536000; includeSubDomains";

fn get(rt: &Arc<Runtime>, client: &HttpClient, path: &'static str) -> Outcome {
    let o = run_with(rt, client, Job::Get(path));
    assert!(o.failed.is_none(), "{path}: {:?}", o.failed);
    o
}

#[test]
fn every_response_over_tls_carries_hsts_on_http1_and_http2() {
    let rt = rt();
    for (alpn, version) in [
        (&[b"http/1.1".as_slice()][..], HttpVersion::Http11),
        (&[b"h2".as_slice(), b"http/1.1".as_slice()][..], HttpVersion::Http2),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (_, client) = tls_server(&rt, dir.path(), alpn, Some(policy()));
        for path in ["/ok", "/missing", "/deferred"] {
            let o = get(&rt, &client, path);
            assert_eq!(o.version, Some(version), "test must exercise the protocol it names");
            assert_eq!(o.header("strict-transport-security"), Some(WANT), "{version:?} {path}");
        }
        // A missing resource is still a response HSTS applies to.
        assert_eq!(get(&rt, &client, "/missing").status, 404);
        // A handler's own value is left alone.
        assert_eq!(get(&rt, &client, "/own").header("strict-transport-security"), Some("max-age=1"), "{version:?}");
    }
}

#[test]
fn hsts_is_never_sent_over_a_plaintext_connection() {
    let rt = rt();
    let addr = HttpServer::new()
        .hsts(policy())
        .bind(&rt, "127.0.0.1:0".parse().unwrap(), Arc::new(Factory))
        .unwrap()
        .0;
    let client = HttpClient::from_addr(addr).disable_content_encoding();
    for path in ["/ok", "/missing", "/deferred"] {
        let o = get(&rt, &client, path);
        assert!(o.header("strict-transport-security").is_none(), "{path}: RFC 6797 §7.2 forbids it over HTTP");
    }
}

#[test]
fn hsts_is_off_unless_configured() {
    let rt = rt();
    let dir = tempfile::tempdir().unwrap();
    let (_, client) = tls_server(&rt, dir.path(), &[b"http/1.1"], None);
    assert!(get(&rt, &client, "/ok").header("strict-transport-security").is_none());
}

#[test]
fn max_age_zero_clears_hsts() {
    let rt = rt();
    let dir = tempfile::tempdir().unwrap();
    let (_, client) = tls_server(&rt, dir.path(), &[b"http/1.1"], Some(HstsPolicy::new(Duration::ZERO)));
    assert_eq!(get(&rt, &client, "/ok").header("strict-transport-security"), Some("max-age=0"));
}

#[test]
fn a_304_from_the_conditional_layer_carries_hsts_too() {
    let rt = rt();
    let dir = tempfile::tempdir().unwrap();
    let (_, client) = tls_server(&rt, dir.path(), &[b"http/1.1"], Some(policy()));
    let o = run_with(&rt, &client, Job::GetWith("/cond", vec![("If-None-Match", "\"v1\"")]));
    assert_eq!(o.status, 304);
    assert_eq!(o.header("strict-transport-security"), Some(WANT), "HSTS must be outermost");
}

#[test]
fn bind_rejects_a_preload_policy_browsers_would_refuse() {
    let rt = rt();
    let year = Duration::from_secs(31_536_000);
    let bad = HttpServer::new().hsts(HstsPolicy::new(year).preload());
    let e = bad
        .bind(&rt, "127.0.0.1:0".parse().unwrap(), Arc::new(Factory))
        .expect_err("preload without includeSubDomains must be refused");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);

    let good = HttpServer::new().hsts(HstsPolicy::new(year).include_subdomains().preload());
    assert!(good.bind(&rt, "127.0.0.1:0".parse().unwrap(), Arc::new(Factory)).is_ok());
}

/// A handler must see the connection as secure, with its peer address, on the
/// *first* request of an HTTP/2 connection too. The stream that request
/// creates exists only after the endpoint bound connection info to the
/// streams it already had, so it was left with the plaintext default.
#[test]
fn handlers_see_the_tls_connection_info_on_http1_and_http2() {
    let rt = rt();
    for alpn in [&[b"http/1.1".as_slice()][..], &[b"h2".as_slice(), b"http/1.1".as_slice()][..]] {
        let dir = tempfile::tempdir().unwrap();
        let (_, client) = tls_server(&rt, dir.path(), alpn, None);
        // A fresh connection per request: each is a connection's first request.
        let o = get(&rt, &client, "/info");
        assert_eq!(
            String::from_utf8_lossy(&o.body),
            "secure=true remote=true",
            "{:?}",
            o.version
        );
    }
}
