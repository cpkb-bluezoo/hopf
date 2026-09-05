// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Real TCP loopback round-trips through a `SocksService` (feature
//! `integration`). Drives the raw wire protocol by hand — there is no
//! `hopf-socks` client yet (tracked separately) — against a plain TCP echo
//! target standing in for "the proxied destination."

#![cfg(feature = "integration")]

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_dns::DnsResolver;

use crate::{SocksAuthenticator, SocksConnectionHandlerFactory, SocksPolicy, SocksService};

struct AllowAll;
impl SocksPolicy for AllowAll {
    fn is_target_allowed(&self, _addr: IpAddr, _port: u16) -> bool {
        true
    }
}

struct DenyAll;
impl SocksPolicy for DenyAll {
    fn is_target_allowed(&self, _addr: IpAddr, _port: u16) -> bool {
        false
    }
}

struct FixedCredential {
    username: &'static str,
    password: &'static str,
}
impl SocksAuthenticator for FixedCredential {
    fn verify(&self, username: &str, password: &str) -> bool {
        username == self.username && password == self.password
    }
}

/// A trivial TCP echo server standing in for "the proxied target" —
/// started on a plain OS thread, not part of the `Runtime` under test.
fn start_echo_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn start_socks_server(
    policy: Arc<dyn SocksPolicy>,
    authenticator: Option<Arc<dyn SocksAuthenticator>>,
) -> (Arc<Runtime>, SocketAddr) {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let dns = Arc::new(DnsResolver::for_runtime(&rt).unwrap());
    let mut factory = SocksConnectionHandlerFactory::new(dns, Arc::clone(&rt), policy)
        .with_idle_timeout(Duration::from_secs(30));
    if let Some(a) = authenticator {
        factory = factory.with_authenticator(a);
    }
    let service = SocksService::new("127.0.0.1:0".parse().unwrap(), factory);
    let bound = service.start(&rt).unwrap();
    (rt, bound)
}

fn read_exact_within(stream: &mut TcpStream, n: usize, timeout: Duration) -> Vec<u8> {
    stream.set_read_timeout(Some(timeout)).unwrap();
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).unwrap();
    buf
}

#[test]
fn socks5_no_auth_connect_relays_bytes_to_the_target() {
    let target = start_echo_target();
    let (_rt, proxy) = start_socks_server(Arc::new(AllowAll), None);

    let mut client = TcpStream::connect(proxy).unwrap();
    client.write_all(&[0x05, 1, 0x00]).unwrap();
    assert_eq!(read_exact_within(&mut client, 2, Duration::from_secs(5)), vec![0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    if let IpAddr::V4(v4) = target.ip() {
        req.extend_from_slice(&v4.octets());
    } else {
        panic!("expected IPv4 echo target");
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&req).unwrap();

    let reply = read_exact_within(&mut client, 10, Duration::from_secs(5));
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00, "expected Succeeded reply");

    client.write_all(b"hello, socks").unwrap();
    let echoed = read_exact_within(&mut client, b"hello, socks".len(), Duration::from_secs(5));
    assert_eq!(echoed, b"hello, socks");
}

#[test]
fn socks4_connect_relays_bytes_to_the_target() {
    let target = start_echo_target();
    let (_rt, proxy) = start_socks_server(Arc::new(AllowAll), None);

    let mut client = TcpStream::connect(proxy).unwrap();
    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&target.port().to_be_bytes());
    if let IpAddr::V4(v4) = target.ip() {
        req.extend_from_slice(&v4.octets());
    } else {
        panic!("expected IPv4 echo target");
    }
    req.extend_from_slice(b"someuser");
    req.push(0);
    client.write_all(&req).unwrap();

    let reply = read_exact_within(&mut client, 8, Duration::from_secs(5));
    assert_eq!(reply[1], 0x5a, "expected Granted reply");

    client.write_all(b"ping").unwrap();
    assert_eq!(read_exact_within(&mut client, 4, Duration::from_secs(5)), b"ping");
}

#[test]
fn socks4a_magic_ip_resolves_the_hostname_before_connecting() {
    let target = start_echo_target();
    let (_rt, proxy) = start_socks_server(Arc::new(AllowAll), None);

    let mut client = TcpStream::connect(proxy).unwrap();
    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&target.port().to_be_bytes());
    req.extend_from_slice(&[0, 0, 0, 1]); // SOCKS4a magic IP
    req.push(0); // empty USERID
    req.extend_from_slice(b"localhost");
    req.push(0);
    client.write_all(&req).unwrap();

    let reply = read_exact_within(&mut client, 8, Duration::from_secs(5));
    assert_eq!(reply[1], 0x5a, "expected Granted reply");

    client.write_all(b"via-4a").unwrap();
    assert_eq!(read_exact_within(&mut client, 6, Duration::from_secs(5)), b"via-4a");
}

#[test]
fn socks5_username_password_auth_success_then_connect() {
    let target = start_echo_target();
    let auth: Arc<dyn SocksAuthenticator> = Arc::new(FixedCredential {
        username: "u",
        password: "p",
    });
    let (_rt, proxy) = start_socks_server(Arc::new(AllowAll), Some(auth));

    let mut client = TcpStream::connect(proxy).unwrap();
    // Offer both no-auth and username/password; server must pick 0x02
    // since an authenticator is configured.
    client.write_all(&[0x05, 2, 0x00, 0x02]).unwrap();
    assert_eq!(read_exact_within(&mut client, 2, Duration::from_secs(5)), vec![0x05, 0x02]);

    let mut auth_req = vec![0x01, 1];
    auth_req.extend_from_slice(b"u");
    auth_req.push(1);
    auth_req.extend_from_slice(b"p");
    client.write_all(&auth_req).unwrap();
    assert_eq!(read_exact_within(&mut client, 2, Duration::from_secs(5)), vec![0x01, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    if let IpAddr::V4(v4) = target.ip() {
        req.extend_from_slice(&v4.octets());
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&req).unwrap();
    let reply = read_exact_within(&mut client, 10, Duration::from_secs(5));
    assert_eq!(reply[1], 0x00);
}

#[test]
fn socks5_username_password_auth_failure_closes_the_connection() {
    let auth: Arc<dyn SocksAuthenticator> = Arc::new(FixedCredential {
        username: "u",
        password: "p",
    });
    let (_rt, proxy) = start_socks_server(Arc::new(AllowAll), Some(auth));

    let mut client = TcpStream::connect(proxy).unwrap();
    client.write_all(&[0x05, 1, 0x02]).unwrap();
    assert_eq!(read_exact_within(&mut client, 2, Duration::from_secs(5)), vec![0x05, 0x02]);

    let mut auth_req = vec![0x01, 1];
    auth_req.extend_from_slice(b"u");
    auth_req.push(5);
    auth_req.extend_from_slice(b"wrong");
    client.write_all(&auth_req).unwrap();
    assert_eq!(read_exact_within(&mut client, 2, Duration::from_secs(5)), vec![0x01, 0x01]);

    // Server must close after a failed authentication (RFC 1929 §2).
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(client.read(&mut buf).unwrap(), 0, "expected connection closed");
}

#[test]
fn socks4_request_is_rejected_outright_when_an_authenticator_is_configured() {
    let target = start_echo_target();
    let auth: Arc<dyn SocksAuthenticator> = Arc::new(FixedCredential {
        username: "u",
        password: "p",
    });
    let (_rt, proxy) = start_socks_server(Arc::new(AllowAll), Some(auth));

    let mut client = TcpStream::connect(proxy).unwrap();
    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&target.port().to_be_bytes());
    if let IpAddr::V4(v4) = target.ip() {
        req.extend_from_slice(&v4.octets());
    }
    req.push(0);
    client.write_all(&req).unwrap();

    let reply = read_exact_within(&mut client, 8, Duration::from_secs(5));
    assert_eq!(reply[1], 0x5b, "expected Rejected reply — SOCKS4 has no credential field");
}

#[test]
fn destination_policy_denial_sends_not_allowed_and_closes() {
    let target = start_echo_target();
    let (_rt, proxy) = start_socks_server(Arc::new(DenyAll), None);

    let mut client = TcpStream::connect(proxy).unwrap();
    client.write_all(&[0x05, 1, 0x00]).unwrap();
    assert_eq!(read_exact_within(&mut client, 2, Duration::from_secs(5)), vec![0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    if let IpAddr::V4(v4) = target.ip() {
        req.extend_from_slice(&v4.octets());
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&req).unwrap();

    let reply = read_exact_within(&mut client, 10, Duration::from_secs(5));
    assert_eq!(reply[1], 0x02, "expected NotAllowed reply");

    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(client.read(&mut buf).unwrap(), 0, "expected connection closed");
}

#[test]
fn bind_command_is_rejected_as_not_yet_implemented() {
    let (_rt, proxy) = start_socks_server(Arc::new(AllowAll), None);

    let mut client = TcpStream::connect(proxy).unwrap();
    client.write_all(&[0x05, 1, 0x00]).unwrap();
    assert_eq!(read_exact_within(&mut client, 2, Duration::from_secs(5)), vec![0x05, 0x00]);

    let mut req = vec![0x05, 0x02, 0x00, 0x01]; // BIND
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&0u16.to_be_bytes());
    client.write_all(&req).unwrap();

    let reply = read_exact_within(&mut client, 10, Duration::from_secs(5));
    assert_eq!(reply[1], 0x07, "expected CommandNotSupported reply");
}

#[test]
fn unreachable_target_gets_a_failure_reply_not_a_hang() {
    let (_rt, proxy) = start_socks_server(Arc::new(AllowAll), None);

    // Bind and immediately drop a listener to get a port nothing is
    // listening on, then connect to it deterministically (rather than
    // relying on an arbitrary unbound port, which can be flaky to bind
    // against depending on the OS's ephemeral-port reuse behavior). The
    // exact `io::ErrorKind` a dial to a closed local port produces is
    // platform/sandbox-dependent, so this only pins the reply's outcome
    // (dial failure is reported back, not left to hang) — not which of
    // RFC 1928 §6's several failure codes it maps to.
    let closed_addr = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };

    let mut client = TcpStream::connect(proxy).unwrap();
    client.write_all(&[0x05, 1, 0x00]).unwrap();
    assert_eq!(read_exact_within(&mut client, 2, Duration::from_secs(5)), vec![0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    if let IpAddr::V4(v4) = closed_addr.ip() {
        req.extend_from_slice(&v4.octets());
    }
    req.extend_from_slice(&closed_addr.port().to_be_bytes());
    client.write_all(&req).unwrap();

    let reply = read_exact_within(&mut client, 10, Duration::from_secs(5));
    assert_ne!(reply[1], 0x00, "expected a failure reply, not Succeeded");
}

/// Confirms the relay's idle timer actually closes an established relay
/// with no traffic — not just that the timer field is stored, which is
/// the exact gap this crate's design notes call out in a client config
/// this backlog is scoped against.
#[test]
fn established_relay_closes_after_the_idle_timeout_with_no_traffic() {
    let target = start_echo_target();
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let dns = Arc::new(DnsResolver::for_runtime(&rt).unwrap());
    let factory = SocksConnectionHandlerFactory::new(dns, Arc::clone(&rt), Arc::new(AllowAll))
        .with_idle_timeout(Duration::from_millis(200));
    let service = SocksService::new("127.0.0.1:0".parse().unwrap(), factory);
    let proxy = service.start(&rt).unwrap();

    let mut client = TcpStream::connect(proxy).unwrap();
    client.write_all(&[0x05, 1, 0x00]).unwrap();
    assert_eq!(read_exact_within(&mut client, 2, Duration::from_secs(5)), vec![0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    if let IpAddr::V4(v4) = target.ip() {
        req.extend_from_slice(&v4.octets());
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&req).unwrap();
    let reply = read_exact_within(&mut client, 10, Duration::from_secs(5));
    assert_eq!(reply[1], 0x00);

    // Send nothing further; the relay should close on its own well within
    // a couple of idle-timeout periods.
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(client.read(&mut buf).unwrap(), 0, "expected relay closed by idle timeout");
}
