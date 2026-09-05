// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Hopf core: thread-per-core reactor and transport-agnostic endpoint substrate.
//!
//! # Overview
//!
//! - [`Runtime`] owns worker [`mio`] reactors, an accept loop, and a
//!   [`StorageExecutor`] for blocking filesystem work.
//! - Accepted **or dialed** TCP connections are pinned to one reactor for life
//!   (affinity). [`Runtime::add_tcp_listener`] and [`Runtime::connect`] are peers.
//! - Protocols implement [`ProtocolHandler`] and talk to the peer through [`Endpoint`].
//! - Use [`ConnHandle`] / [`StorageExecutor::submit`] to run blocking work off-loop
//!   and hop results back via [`Endpoint::execute`].

#![warn(missing_docs)]

pub mod acl;
pub mod binding;
pub mod bufpool;
pub mod composition;
pub mod connector;
pub mod endpoint;
pub mod error;
pub mod handle;
pub mod handler;
pub mod listener;
pub mod peer_addr;
pub mod peer_cred;
pub mod quota;
pub mod runtime;
pub mod security;
pub mod service;
pub mod storage;
pub mod telemetry;
pub mod tls;
pub mod udp;

mod accept;
mod cmd;
mod connection;
mod proxy_protocol;
mod reactor;
mod timer;

pub use acl::{AcceptRateLimit, IpNet, PeerAcl};
pub use binding::BindingId;
pub use bufpool::BufferPool;
pub use cmd::ReactorHandle;
pub use composition::{
    Composition, CompositionRegistry, CompositionXmlError, CompositionXmlResult,
};
pub use connector::{TcpConnParams, TcpConnectorConfig, UnixConnectorConfig};
pub use endpoint::{Endpoint, TimerHandle, WriteReadyCallback};
pub use error::StartTlsError;
pub use handle::{ConnHandle, ConnHandleBackend};
pub use handler::{NopHandler, ProtocolHandler};
pub use listener::{
    HandlerFactory, Listener, TcpListenerConfig, UnixListenerConfig, DEFAULT_BUFFER_SIZE,
    DEFAULT_MAX_NET_IN, DEFAULT_MAX_NET_OUT,
};
pub use peer_addr::PeerAddr;
pub use peer_cred::{PeerCredAllowlist, PeerCredentials};
pub use quota::{
    CounterQuota, MemoryQuotaManager, Quota, QuotaManager, QuotaPolicy, QuotaSource, QuotaTracker,
    QuotaVerdict, UnlimitedQuota, UnlimitedQuotaManager, UNLIMITED,
};
pub use runtime::{Runtime, RuntimeConfig};
pub use security::SecurityInfo;
pub use service::Service;
pub use storage::{StorageConfig, StorageError, StorageExecutor};
pub use telemetry::{NopTelemetry, TelemetryHook};
pub use tls::{
    SharedTlsAcceptor, SharedTlsConnector, TlsAcceptor, TlsConnector, TlsProgress, TlsSession,
};
pub use udp::UdpDatagramHandler;

/// Crate version string from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_nonempty() {
        assert!(!VERSION.is_empty());
    }

    #[cfg(feature = "integration")]
    mod integration {
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpStream};
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use crate::*;

    struct EchoHandler;

    impl ProtocolHandler for EchoHandler {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            endpoint.send(data);
            *data = &[];
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    /// Sends `payload` once on connect, records whatever comes back.
    struct EchoOnceClientHandler {
        got: Arc<Mutex<Vec<u8>>>,
        payload: &'static [u8],
    }

    impl ProtocolHandler for EchoOnceClientHandler {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            endpoint.send(self.payload);
        }

        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            self.got.lock().unwrap().extend_from_slice(data);
            *data = &[];
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    /// On any receive, sends back `endpoint.remote_addr()` as text instead
    /// of echoing the received bytes — lets a test observe what address
    /// the connection resolved to *after* any PROXY protocol header has
    /// been parsed off the front of the stream.
    struct RemoteAddrOnReceive;

    impl ProtocolHandler for RemoteAddrOnReceive {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
            let addr = endpoint.remote_addr().unwrap().to_string();
            endpoint.send(addr.as_bytes());
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    /// A fresh, collision-free UNIX domain socket path under the OS temp
    /// dir — `cargo test` runs tests in parallel, so a fixed path shared by
    /// multiple `#[test]`s in this module would race.
    fn unique_unix_socket_path(label: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("hopf-test-{label}-{}-{n}.sock", std::process::id()))
    }

    /// Leaves a partial line unconsumed in `data` for the next receive (compact).
    struct LineEcho;

    impl ProtocolHandler for LineEcho {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            while let Some(pos) = data.iter().position(|&b| b == b'\n') {
                let line = &data[..=pos];
                endpoint.send(line);
                *data = &data[pos + 1..];
            }
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    struct PanicOnce {
        done: Arc<Mutex<bool>>,
    }

    impl ProtocolHandler for PanicOnce {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
            let mut g = self.done.lock().unwrap();
            if !*g {
                *g = true;
                panic!("intentional handler panic");
            }
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    /// On any receive, read `path` via StorageExecutor and write bytes to the peer.
    struct FileOffload {
        storage: Arc<StorageExecutor>,
        path: PathBuf,
        work_thread: Arc<Mutex<Option<String>>>,
        callback_is_reactor: Arc<AtomicBool>,
    }

    impl ProtocolHandler for FileOffload {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
            let path = self.path.clone();
            let work_thread = Arc::clone(&self.work_thread);
            let callback_is_reactor = Arc::clone(&self.callback_is_reactor);
            let handle = endpoint.handle();
            self.storage.submit(endpoint, move || {
                let name = std::thread::current().name().unwrap_or("").to_string();
                *work_thread.lock().unwrap() = Some(name);
                std::fs::read(&path).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            }, move |result| {
                let name = std::thread::current().name().unwrap_or("").to_string();
                callback_is_reactor.store(name.starts_with("hopf-reactor-"), Ordering::SeqCst);
                match result {
                    Ok(bytes) => handle.send(bytes),
                    Err(_) => handle.close(),
                }
            });
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    /// On any receive, push a few chunks (with tiny delays, to exercise
    /// real cross-call ordering rather than one atomic write) via
    /// `StorageExecutor::submit_streamed`, then close.
    struct StreamOffload {
        storage: Arc<StorageExecutor>,
        callback_fired: Arc<AtomicBool>,
    }

    impl ProtocolHandler for StreamOffload {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
            let callback_fired = Arc::clone(&self.callback_fired);
            let handle_for_close = endpoint.handle();
            self.storage.submit_streamed(
                endpoint.handle(),
                move |handle| {
                    for chunk in [&b"one-"[..], &b"two-"[..], &b"three"[..]] {
                        handle.send(chunk.to_vec());
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                },
                move |result| {
                    assert!(result.is_ok());
                    callback_fired.store(true, Ordering::SeqCst);
                    handle_for_close.close();
                },
            );
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    fn wait_connect(addr: SocketAddr) -> TcpStream {
        for _ in 0..50 {
            if let Ok(s) = TcpStream::connect(addr) {
                s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                return s;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("failed to connect to {addr}");
    }


    #[test]
    fn echo_two_clients() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 2,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                || Box::new(EchoHandler) as Box<dyn ProtocolHandler>,
            ))
            .unwrap();

        let mut c1 = wait_connect(addr);
        let mut c2 = wait_connect(addr);
        c1.write_all(b"hello").unwrap();
        c2.write_all(b"world").unwrap();

        let mut b1 = [0u8; 16];
        let mut b2 = [0u8; 16];
        let n1 = c1.read(&mut b1).unwrap();
        let n2 = c2.read(&mut b2).unwrap();
        assert_eq!(&b1[..n1], b"hello");
        assert_eq!(&b2[..n2], b"world");

        rt.shutdown();
    }

    /// Regression test for issue #340: a UNIX domain socket listener and a
    /// UNIX domain socket client dial, both through the real `Runtime`
    /// entry points, exchanging real bytes over a real socket path — not
    /// just that the types compile.
    #[test]
    fn unix_listener_and_client_echo_round_trip() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 2,
            ..Default::default()
        })
        .unwrap();
        let path = unique_unix_socket_path("echo");
        let (bound_path, _) = rt
            .add_unix_listener(UnixListenerConfig::new(path.clone(), || {
                Box::new(EchoHandler) as Box<dyn ProtocolHandler>
            }))
            .unwrap();
        assert_eq!(bound_path, path);

        let got = Arc::new(Mutex::new(Vec::new()));
        let got2 = Arc::clone(&got);
        rt.connect_unix(UnixConnectorConfig::new(path.clone(), move || {
            Box::new(EchoOnceClientHandler {
                got: Arc::clone(&got2),
                payload: b"hello-over-unix-socket",
            }) as Box<dyn ProtocolHandler>
        }))
        .unwrap();

        for _ in 0..100 {
            if got.lock().unwrap().as_slice() == b"hello-over-unix-socket" {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(got.lock().unwrap().as_slice(), b"hello-over-unix-socket");

        rt.shutdown();
        let _ = std::fs::remove_file(&path);
    }

    /// Regression test for issue #340: a UNIX listener's peer-credential
    /// allowlist must actually permit a peer whose real (kernel-reported)
    /// uid matches — not just fail closed for everyone.
    #[test]
    fn unix_listener_peer_allowlist_permits_a_matching_uid() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 2,
            ..Default::default()
        })
        .unwrap();
        let path = unique_unix_socket_path("allow");
        let our_uid = unsafe { libc::getuid() };
        rt.add_unix_listener(
            UnixListenerConfig::new(path.clone(), || Box::new(EchoHandler) as Box<dyn ProtocolHandler>)
                .with_peer_allowlist(PeerCredAllowlist {
                    allow_uids: vec![our_uid],
                    allow_gids: vec![],
                }),
        )
        .unwrap();

        let got = Arc::new(Mutex::new(Vec::new()));
        let got2 = Arc::clone(&got);
        rt.connect_unix(UnixConnectorConfig::new(path.clone(), move || {
            Box::new(EchoOnceClientHandler {
                got: Arc::clone(&got2),
                payload: b"allowed",
            }) as Box<dyn ProtocolHandler>
        }))
        .unwrap();

        for _ in 0..100 {
            if got.lock().unwrap().as_slice() == b"allowed" {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            got.lock().unwrap().as_slice(),
            b"allowed",
            "peer allowlist wrongly denied our own uid"
        );

        rt.shutdown();
        let _ = std::fs::remove_file(&path);
    }

    /// Regression test for issue #340: a UNIX listener's peer-credential
    /// allowlist must actually deny a peer whose real (kernel-reported) uid
    /// doesn't match any configured entry — not something self-reported by
    /// the peer, so a real accepted connection is the only way to prove
    /// the check is wired up to the kernel, not skipped.
    #[test]
    fn unix_listener_peer_allowlist_denies_a_non_matching_uid() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 2,
            ..Default::default()
        })
        .unwrap();
        let path = unique_unix_socket_path("deny");
        rt.add_unix_listener(
            UnixListenerConfig::new(path.clone(), || Box::new(EchoHandler) as Box<dyn ProtocolHandler>)
                .with_peer_allowlist(PeerCredAllowlist {
                    allow_uids: vec![999_999],
                    allow_gids: vec![],
                }),
        )
        .unwrap();

        let got = Arc::new(Mutex::new(Vec::new()));
        let got2 = Arc::clone(&got);
        rt.connect_unix(UnixConnectorConfig::new(path.clone(), move || {
            Box::new(EchoOnceClientHandler {
                got: Arc::clone(&got2),
                payload: b"denied",
            }) as Box<dyn ProtocolHandler>
        }))
        .unwrap();

        // Give the (rejected) connection plenty of time to *not* echo
        // anything back — the accept-time check is local and instant, so
        // this margin is about proving absence, not racing a slow peer.
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            got.lock().unwrap().is_empty(),
            "peer allowlist should have denied uid 999999"
        );

        rt.shutdown();
        let _ = std::fs::remove_file(&path);
    }

    /// Regression test for issue #342: a listener with
    /// `with_proxy_protocol()` enabled must recover the client address
    /// from a real PROXY protocol v1 header sent as the first bytes on the
    /// wire — not just parse the header type-level, but actually rewrite
    /// what `Endpoint::remote_addr()` reports for the rest of the
    /// connection's life.
    #[test]
    fn tcp_listener_proxy_protocol_v1_rewrites_remote_addr() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 2,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), || {
                    Box::new(RemoteAddrOnReceive) as Box<dyn ProtocolHandler>
                })
                .with_proxy_protocol(),
            )
            .unwrap();

        let mut c = wait_connect(addr);
        c.write_all(b"PROXY TCP4 203.0.113.7 198.51.100.1 56324 443\r\n")
            .unwrap();
        c.write_all(b"ping").unwrap();

        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"203.0.113.7:56324");

        rt.shutdown();
    }

    /// Regression test for issue #342: same as the v1 test above, but for
    /// the binary v2 wire format.
    #[test]
    fn tcp_listener_proxy_protocol_v2_rewrites_remote_addr() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 2,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), || {
                    Box::new(RemoteAddrOnReceive) as Box<dyn ProtocolHandler>
                })
                .with_proxy_protocol(),
            )
            .unwrap();

        let mut header: Vec<u8> = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // sig
            0x21, // version 2, command PROXY
            0x11, // AF_INET, STREAM
        ];
        header.extend_from_slice(&12u16.to_be_bytes());
        header.extend_from_slice(&[203, 0, 113, 9]); // src ip
        header.extend_from_slice(&[198, 51, 100, 1]); // dst ip
        header.extend_from_slice(&56325u16.to_be_bytes()); // src port
        header.extend_from_slice(&443u16.to_be_bytes()); // dst port

        let mut c = wait_connect(addr);
        c.write_all(&header).unwrap();
        c.write_all(b"ping").unwrap();

        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"203.0.113.9:56325");

        rt.shutdown();
    }

    /// Regression test for issue #342: a listener with
    /// `with_proxy_protocol()` enabled must close a connection whose first
    /// bytes are not a valid PROXY protocol header, rather than treating
    /// them as the start of application data — this listener is only
    /// meant to be reached via a relay that always sends one, so a missing
    /// header is a misconfiguration to fail on, not fall back from.
    #[test]
    fn tcp_listener_proxy_protocol_rejects_connection_without_header() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 2,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), || {
                    Box::new(RemoteAddrOnReceive) as Box<dyn ProtocolHandler>
                })
                .with_proxy_protocol(),
            )
            .unwrap();

        let mut c = wait_connect(addr);
        c.write_all(b"not a proxy protocol header\r\n").unwrap();

        let mut buf = [0u8; 64];
        let n = c.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "connection should have been closed, not echoed to");

        rt.shutdown();
    }

    #[test]
    fn submit_streamed_pushes_chunks_in_order_then_fires_callback() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let callback_fired = Arc::new(AtomicBool::new(false));
        let callback_fired2 = Arc::clone(&callback_fired);
        let storage: Arc<StorageExecutor> = Arc::clone(rt.storage());
        let (addr, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                move || {
                    Box::new(StreamOffload {
                        storage: Arc::clone(&storage),
                        callback_fired: Arc::clone(&callback_fired2),
                    }) as Box<dyn ProtocolHandler>
                },
            ))
            .unwrap();

        let mut c = wait_connect(addr);
        c.write_all(b"go").unwrap();

        let mut received = Vec::new();
        c.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"one-two-three");
        assert!(callback_fired.load(Ordering::SeqCst));

        rt.shutdown();
    }

    #[test]
    fn line_echo_preserves_partial() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                || Box::new(LineEcho) as Box<dyn ProtocolHandler>,
            ))
            .unwrap();

        let mut c = wait_connect(addr);
        c.write_all(b"hel").unwrap();
        std::thread::sleep(Duration::from_millis(30));
        c.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut buf = [0u8; 16];
        assert!(c.read(&mut buf).is_err());

        c.write_all(b"lo\n").unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let n = c.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello\n");

        rt.shutdown();
    }

    #[test]
    fn handler_panic_isolates_connection() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let flag = Arc::new(Mutex::new(false));
        let flag2 = Arc::clone(&flag);
        let (_addr, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                move || {
                    Box::new(PanicOnce {
                        done: Arc::clone(&flag2),
                    }) as Box<dyn ProtocolHandler>
                },
            ))
            .unwrap();
        let (addr2, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                || Box::new(EchoHandler) as Box<dyn ProtocolHandler>,
            ))
            .unwrap();

        let mut bad = wait_connect(_addr);
        let _ = bad.write_all(b"x");
        std::thread::sleep(Duration::from_millis(50));

        let mut good = wait_connect(addr2);
        good.write_all(b"ok").unwrap();
        let mut buf = [0u8; 8];
        let n = good.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ok");

        rt.shutdown();
    }

    #[test]
    fn storage_reads_file_off_reactor() {
        let dir = std::env::temp_dir().join("hopf-storage-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("payload.txt");
        std::fs::write(&path, b"from-disk").unwrap();

        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            storage: StorageConfig {
                threads: 2,
                queue_capacity: 16,
            },
        })
        .unwrap();

        let work_thread = Arc::new(Mutex::new(None));
        let callback_is_reactor = Arc::new(AtomicBool::new(false));
        let storage = Arc::clone(rt.storage());
        let path_for_factory = path.clone();
        let wt = Arc::clone(&work_thread);
        let cir = Arc::clone(&callback_is_reactor);

        let (addr, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                move || {
                    Box::new(FileOffload {
                        storage: Arc::clone(&storage),
                        path: path_for_factory.clone(),
                        work_thread: Arc::clone(&wt),
                        callback_is_reactor: Arc::clone(&cir),
                    }) as Box<dyn ProtocolHandler>
                },
            ))
            .unwrap();

        let mut c = wait_connect(addr);
        c.write_all(b"go").unwrap();
        let mut buf = [0u8; 32];
        let n = c.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"from-disk");

        let worker_name = work_thread.lock().unwrap().clone().unwrap();
        assert!(
            worker_name.starts_with("hopf-storage-"),
            "work ran on {worker_name}"
        );
        assert!(
            callback_is_reactor.load(Ordering::SeqCst),
            "callback must run on a reactor thread"
        );

        rt.shutdown();
        let _ = std::fs::remove_file(&path);
    }

    struct GiveHandle {
        tx: Mutex<Option<std::sync::mpsc::Sender<ConnHandle>>>,
    }

    impl ProtocolHandler for GiveHandle {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            if let Some(tx) = self.tx.lock().unwrap().take() {
                let _ = tx.send(endpoint.handle());
            }
        }

        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    #[test]
    fn storage_rejects_when_saturated() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            storage: StorageConfig {
                threads: 1,
                queue_capacity: 1,
            },
        })
        .unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let (addr, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                move || {
                    Box::new(GiveHandle {
                        tx: Mutex::new(Some(tx.clone())),
                    }) as Box<dyn ProtocolHandler>
                },
            ))
            .unwrap();

        let _c = wait_connect(addr);
        let handle = rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let gate = Arc::new(std::sync::Barrier::new(2));
        let gate2 = Arc::clone(&gate);
        rt.storage().submit_on(
            handle.clone(),
            move || {
                gate2.wait();
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            },
            |_| {},
        );
        // Wait until the worker is blocked inside the job (queue empty again).
        std::thread::sleep(Duration::from_millis(50));
        rt.storage()
            .submit_on(handle.clone(), || Ok(()), |_| {});

        let rejected = Arc::new(AtomicBool::new(false));
        let rejected2 = Arc::clone(&rejected);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        rt.storage().submit_on(handle, || Ok(()), move |r| {
            if matches!(r, Err(StorageError::Rejected)) {
                rejected2.store(true, Ordering::SeqCst);
            }
            let _ = done_tx.send(());
        });

        done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            rejected.load(Ordering::SeqCst),
            "expected Rejected when storage queue is full"
        );

        gate.wait();
        rt.shutdown();
    }

    /// Effective capacity is `threads + queue_capacity`, not `queue_capacity`
    /// alone — a job a worker has already dequeued no longer occupies a
    /// buffered slot, so `threads` more can be running concurrently on top
    /// of the queue. This pins that exact boundary down: with `threads: 1,
    /// queue_capacity: 3`, exactly 4 submissions are admitted (1 running +
    /// 3 queued) before the 5th is rejected.
    #[test]
    fn storage_capacity_is_threads_plus_queue_capacity() {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            storage: StorageConfig {
                threads: 1,
                queue_capacity: 3,
            },
        })
        .unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let (addr, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                move || {
                    Box::new(GiveHandle {
                        tx: Mutex::new(Some(tx.clone())),
                    }) as Box<dyn ProtocolHandler>
                },
            ))
            .unwrap();

        let _c = wait_connect(addr);
        let handle = rx.recv_timeout(Duration::from_secs(2)).unwrap();

        // Occupy the single worker so nothing dequeues further submissions.
        let gate = Arc::new(std::sync::Barrier::new(2));
        let gate2 = Arc::clone(&gate);
        rt.storage().submit_on(
            handle.clone(),
            move || {
                gate2.wait();
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            },
            |_| {},
        );
        std::thread::sleep(Duration::from_millis(50));

        // Three more fit in the queue (threads=1 running + queue_capacity=3
        // queued == capacity 4 total already admitted).
        for _ in 0..3 {
            rt.storage().submit_on(handle.clone(), || Ok(()), |_| {});
        }
        assert_eq!(rt.storage().pending_count(), 4);

        // A 5th is over capacity and must be rejected immediately.
        let rejected = Arc::new(AtomicBool::new(false));
        let rejected2 = Arc::clone(&rejected);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        rt.storage().submit_on(handle, || Ok(()), move |r| {
            if matches!(r, Err(StorageError::Rejected)) {
                rejected2.store(true, Ordering::SeqCst);
            }
            let _ = done_tx.send(());
        });
        done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(rejected.load(Ordering::SeqCst), "expected 5th submission rejected");

        gate.wait();
        rt.shutdown();
    }

    #[test]
    fn dial_echo_peer_of_listen() {
        use crate::TcpConnectorConfig;

        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                || Box::new(EchoHandler) as Box<dyn ProtocolHandler>,
            ))
            .unwrap();

        let got = Arc::new(Mutex::new(Vec::new()));
        let got2 = Arc::clone(&got);

        struct DialEcho {
            got: Arc<Mutex<Vec<u8>>>,
            sent: bool,
        }

        impl ProtocolHandler for DialEcho {
            fn connected(&mut self, endpoint: &mut dyn Endpoint) {
                endpoint.send(b"ping");
                self.sent = true;
            }

            fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
                self.got.lock().unwrap().extend_from_slice(data);
                *data = &[];
                endpoint.close();
            }

            fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

            fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
        }

        rt.connect(TcpConnectorConfig::new(addr, move || {
            Box::new(DialEcho {
                got: Arc::clone(&got2),
                sent: false,
            }) as Box<dyn ProtocolHandler>
        }))
        .unwrap();

        for _ in 0..100 {
            if got.lock().unwrap().as_slice() == b"ping" {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(got.lock().unwrap().as_slice(), b"ping");
        rt.shutdown();
    }

    #[test]
    fn composition_add_remove_listener() {
        use crate::Composition;

        let mut comp = Composition::new(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        comp.listen_tcp(TcpListenerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            || Box::new(EchoHandler) as Box<dyn ProtocolHandler>,
        ))
        .unwrap();

        let addr = comp.primary_addr().unwrap();
        let id = comp.bindings[0];
        let mut c = wait_connect(addr);
        c.write_all(b"hi").unwrap();
        let mut buf = [0u8; 8];
        let n = c.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hi");

        comp.remove_binding(id);
        std::thread::sleep(Duration::from_millis(50));
        // New connects should fail once the listener is gone.
        assert!(TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err());
        comp.shutdown();
    }

    #[test]
    fn acl_denies_peer() {
        use crate::{IpNet, PeerAcl};

        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let deny_loopback = PeerAcl {
            allow: Vec::new(),
            deny: vec![IpNet::parse("127.0.0.0/8").unwrap()],
        };
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new(
                    "127.0.0.1:0".parse().unwrap(),
                    || Box::new(EchoHandler) as Box<dyn ProtocolHandler>,
                )
                .with_acl(deny_loopback),
            )
            .unwrap();

        let mut c = wait_connect(addr);
        let _ = c.write_all(b"x");
        c.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut buf = [0u8; 8];
        // Accepted socket is dropped before handler; read should see EOF / error.
        let r = c.read(&mut buf);
        assert!(matches!(r, Ok(0) | Err(_)));
        rt.shutdown();
    }
    }
}
