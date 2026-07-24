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
pub mod byte_stream_lexer;
pub mod composition;
pub mod connector;
pub mod endpoint;
pub mod error;
pub mod handle;
pub mod handler;
pub mod listener;
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
mod reactor;
mod timer;

pub use acl::{AcceptRateLimit, IpNet, PeerAcl};
pub use binding::BindingId;
pub use bufpool::BufferPool;
pub use byte_stream_lexer::{
    ByteStreamHandler, ByteStreamLexer, ByteStreamScanner, HandlerControl, ScanAction,
};
pub use cmd::ReactorHandle;
pub use composition::{
    Composition, CompositionRegistry, CompositionRuntime, CompositionXmlError, CompositionXmlResult,
};
pub use connector::{TcpConnParams, TcpConnectorConfig};
pub use endpoint::{Endpoint, TimerHandle, WriteReadyCallback};
pub use error::StartTlsError;
pub use handle::ConnHandle;
pub use handler::{NopHandler, ProtocolHandler};
pub use listener::{
    HandlerFactory, Listener, TcpListenerConfig, DEFAULT_BUFFER_SIZE, DEFAULT_MAX_NET_IN,
    DEFAULT_MAX_NET_OUT,
};
pub use quota::{CounterQuota, QuotaTracker, QuotaVerdict, UnlimitedQuota};
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

        let comp = Composition::new(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .listen_tcp(TcpListenerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            || Box::new(EchoHandler) as Box<dyn ProtocolHandler>,
        ))
        .build()
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
