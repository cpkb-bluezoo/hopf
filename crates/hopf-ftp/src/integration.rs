// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Optional PASV / client smokes (feature `integration`).

#![cfg(feature = "integration")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_auth::PasswordTrustPolicy;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_tls::acceptor_from_pem;

use crate::{FtpClientBuilder, FtpConfig, FtpDataMode, FtpService};

fn start_server(root: &std::path::Path) -> (Arc<Runtime>, SocketAddr) {
    let mut policy = PasswordTrustPolicy::default();
    policy = policy.with_user("u", "p");
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = FtpConfig::new(listen, root, policy.shared());
    let service = FtpService::new(config);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();
    (rt, bound)
}

fn write_temp_pem() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf, rcgen::CertifiedKey) {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    (dir, cert_path, key_path, cert)
}

fn client_config(cert: &rcgen::CertifiedKey) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[test]
fn client_pasv_retr_stor_list() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.txt"), b"hi-ftp").unwrap();

    let (_rt, bound) = start_server(dir.path());

    let mut c = FtpClientBuilder::new()
        .timeout(Duration::from_secs(3))
        .connect(bound)
        .unwrap();
    assert_eq!(c.welcome().code, 220);
    c.login("u", "p").unwrap();
    c.type_image().unwrap();

    let body = c.retr("hello.txt").unwrap();
    assert_eq!(body, b"hi-ftp");

    c.stor("out.txt", b"uploaded").unwrap();
    assert_eq!(std::fs::read(dir.path().join("out.txt")).unwrap(), b"uploaded");

    let listing_bytes = c.list(None).unwrap();
    let listing = String::from_utf8_lossy(&listing_bytes);
    assert!(listing.contains("hello.txt") || listing.contains("out.txt"), "{listing}");

    c.mkdir("sub").unwrap();
    c.cwd("sub").unwrap();
    let pwd = c.pwd().unwrap();
    assert!(pwd.contains("sub"), "{pwd}");
    c.cdup().unwrap();
    c.rename("out.txt", "renamed.txt").unwrap();
    assert_eq!(c.size("renamed.txt").unwrap(), 8);
    c.delete("renamed.txt").unwrap();
    c.quit().unwrap();
}

#[test]
fn client_opts_utf8_pathnames() {
    let dir = tempfile::tempdir().unwrap();
    let (_rt, bound) = start_server(dir.path());

    let mut c = FtpClientBuilder::new()
        .timeout(Duration::from_secs(3))
        .connect(bound)
        .unwrap();
    c.login("u", "p").unwrap();

    // Without OPTS UTF8, non-ASCII pathnames are rejected.
    let err = c.mkdir("café").unwrap_err();
    match err {
        crate::FtpError::Protocol { reply, .. } => assert_eq!(reply.code, 501),
        other => panic!("expected 501, got {other}"),
    }

    c.opts_utf8(true).unwrap();
    c.mkdir("café").unwrap();
    c.cwd("café").unwrap();
    let pwd = c.pwd().unwrap();
    assert!(pwd.contains("café"), "{pwd}");
    c.stor("naïve.txt", b"ok").unwrap();
    assert_eq!(c.retr("naïve.txt").unwrap(), b"ok");
    c.cdup().unwrap();

    let listing = String::from_utf8(c.nlst(None).unwrap()).unwrap();
    assert!(listing.contains("café"), "{listing}");

    c.opts_utf8(false).unwrap();
    // PWD may still hold a UTF-8 cwd; reply text is ASCII-substituted.
    let r = c.command("PWD", None).unwrap();
    assert_eq!(r.code, 257);
    assert!(!r.text().contains('é'), "{}", r.text());

    c.quit().unwrap();
}

#[test]
fn client_active_retr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"active").unwrap();
    let (_rt, bound) = start_server(dir.path());

    let mut c = FtpClientBuilder::new()
        .timeout(Duration::from_secs(3))
        .data_mode(FtpDataMode::Active)
        .prefer_epsv(false)
        .connect(bound)
        .unwrap();
    c.login("u", "p").unwrap();
    c.type_image().unwrap();
    assert_eq!(c.retr("a.txt").unwrap(), b"active");
    c.quit().unwrap();
}

#[test]
fn client_auth_tls_retr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("sec.txt"), b"secret").unwrap();

    let (_pem_dir, cert_path, key_path, certified) = write_temp_pem();
    let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();

    let mut policy = PasswordTrustPolicy::default();
    policy = policy.with_user("u", "p");
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = FtpConfig::new(listen, dir.path(), policy.shared()).with_tls(acceptor);
    let service = FtpService::new(config);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();

    let mut c = FtpClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .tls(client_config(&certified), "localhost")
        .connect(bound)
        .unwrap();
    c.auth_tls().unwrap();
    c.login("u", "p").unwrap();
    c.type_image().unwrap();
    assert_eq!(c.retr("sec.txt").unwrap(), b"secret");
    c.quit().unwrap();
}

#[test]
fn client_implicit_ftps_retr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("sec.txt"), b"implicit").unwrap();

    let (_pem_dir, cert_path, key_path, certified) = write_temp_pem();
    let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();

    let mut policy = PasswordTrustPolicy::default();
    policy = policy.with_user("u", "p");
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = FtpConfig::new(listen, dir.path(), policy.shared())
        .with_tls(acceptor)
        .implicit_ftps();
    let service = FtpService::new(config);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();

    let mut c = FtpClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .tls(client_config(&certified), "localhost")
        .implicit_tls(true)
        .connect(bound)
        .unwrap();
    c.login("u", "p").unwrap();
    c.protect_data().unwrap();
    c.type_image().unwrap();
    assert_eq!(c.retr("sec.txt").unwrap(), b"implicit");
    c.quit().unwrap();
}
