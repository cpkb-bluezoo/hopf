// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async FTP / FTPS client built on the hopf-core [`Runtime`].
//!
//! Create an [`FtpClient`] with the desired host / credentials / timeouts,
//! then call [`FtpClient::connect`] with a [`FtpPipeline`] implementation.
//! The connection and pipeline run asynchronously; completion is signalled
//! via callbacks queued through [`FtpSessionWrite`].
//!
//! # Quick example
//!
//! ```no_run
//! use std::sync::{Arc, Mutex};
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_ftp::{FtpClient, FtpGet};
//!
//! let result: Arc<Mutex<Option<std::io::Result<Vec<u8>>>>> = Arc::new(Mutex::new(None));
//! let result2 = Arc::clone(&result);
//!
//! let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
//! FtpClient::new("ftp.example.com")
//!     .credentials("user", "pass")
//!     .connect(&rt, Box::new(FtpGet::new("/file.txt", move |r| {
//!         *result2.lock().unwrap() = Some(r);
//!     }))).unwrap();
//! ```

mod data;
mod handler;
mod pipeline;

pub mod error;
pub mod reply;

pub use error::{FtpError, FtpResult};
pub use pipeline::{FtpGet, FtpPut};

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{ConnHandle, ProtocolHandler, Runtime, SharedTlsConnector, TcpConnectorConfig};
use hopf_dns::{parse_literal_ip, DnsResolver};

use handler::FtpControlHandler;

// ---------------------------------------------------------------------------
// Abort handle
// ---------------------------------------------------------------------------

/// Handle for aborting an in-flight transfer (RFC 959 §4.1.1 `ABOR`).
///
/// Handed to [`FtpPipeline::start`]; cloneable and safe to call from any
/// thread (e.g. stash it for a UI cancel button or a watchdog timer) — it
/// sends `ABOR` on the control connection regardless of which reactor owns
/// it. The transfer in flight when `ABOR` arrives gets its callback fired
/// with an `Interrupted` error; the pipeline then continues with any
/// remaining queued operations rather than failing outright.
#[derive(Clone)]
pub struct FtpAbortHandle {
    control: ConnHandle,
}

impl FtpAbortHandle {
    pub(crate) fn new(control: ConnHandle) -> Self {
        Self { control }
    }

    /// Send `ABOR` on the control connection.
    pub fn abort(&self) {
        self.control.send(b"ABOR\r\n".to_vec());
    }
}

// ---------------------------------------------------------------------------
// Public callback types
// ---------------------------------------------------------------------------

/// Callback for RETR / LIST / NLST results.
pub type RetrCallback = Box<dyn FnOnce(io::Result<Vec<u8>>) + Send>;
/// Callback for STOR / APPE results.
pub type StorCallback = Box<dyn FnOnce(io::Result<()>) + Send>;
/// Callback for STOU results: the server-assigned filename on success (RFC
/// 959 §4.1.3 — parsed from the `125`/`150` reply text).
pub type StouCallback = Box<dyn FnOnce(io::Result<String>) + Send>;
/// Callback for an arbitrary command's outcome: `Ok(text)` with the
/// success reply's text (e.g. `PWD`'s quoted path), or `Err` on a
/// mismatched/rejected reply code. Registering a callback via
/// [`FtpSessionWrite::command_reply`] makes the mismatch non-fatal — the
/// pipeline decides what to do, instead of the connection failing
/// unconditionally (which is still what plain [`FtpSessionWrite::command`]
/// does, for callers that want that).
pub type CmdCallback = Box<dyn FnOnce(Result<String, FtpError>) + Send>;

// ---------------------------------------------------------------------------
// Op queue (internal)
// ---------------------------------------------------------------------------

/// A queued FTP operation.
pub(crate) enum QueuedOp {
    /// Raw command: send `verb [arg]\r\n`, expect reply code `expect`.
    Command {
        verb: String,
        arg: Option<String>,
        expect: u16,
        /// `None` for [`FtpSessionWrite::command`] (mismatch is fatal);
        /// `Some` for [`FtpSessionWrite::command_reply`] (mismatch is
        /// reported to the callback instead).
        callback: Option<CmdCallback>,
    },
    /// Passive RETR.
    Retr {
        path: String,
        /// RFC 959 §4.1.3 resume offset; sends `REST offset` first.
        offset: Option<u64>,
        callback: RetrCallback,
    },
    /// Passive STOR (data wrapped in `Arc` to avoid copying in the factory
    /// closure).
    Stor {
        path: String,
        data: Arc<Vec<u8>>,
        /// RFC 959 §4.1.3 resume offset; sends `REST offset` first.
        offset: Option<u64>,
        callback: StorCallback,
    },
    /// Passive LIST.
    List {
        path: Option<String>,
        callback: RetrCallback,
    },
    /// Passive APPE (append to an existing file, or create it).
    Appe {
        path: String,
        data: Arc<Vec<u8>>,
        callback: StorCallback,
    },
    /// Passive NLST (name-only listing).
    Nlst {
        path: Option<String>,
        callback: RetrCallback,
    },
    /// Passive STOU (store with a server-assigned unique filename).
    Stou { data: Arc<Vec<u8>>, callback: StouCallback },
    /// Send `QUIT` and close.
    Quit,
}

/// Accumulates [`QueuedOp`]s during [`FtpPipeline::start`].
pub(crate) struct OpQueue {
    ops: VecDeque<QueuedOp>,
}

impl OpQueue {
    pub fn new() -> Self {
        Self {
            ops: VecDeque::new(),
        }
    }

    pub fn drain(&mut self) -> VecDeque<QueuedOp> {
        std::mem::take(&mut self.ops)
    }
}

// ---------------------------------------------------------------------------
// Public session-write trait
// ---------------------------------------------------------------------------

/// Interface for queuing FTP operations from a [`FtpPipeline`].
///
/// Passed to [`FtpPipeline::start`]; enqueues ops that are dispatched
/// asynchronously after `start` returns.
pub trait FtpSessionWrite: Send {
    /// Queue `TYPE I` (binary image transfer mode).
    fn type_image(&mut self);
    /// Queue `TYPE A` (ASCII transfer mode).
    fn type_ascii(&mut self);
    /// Queue an arbitrary command expecting reply code `expect` (use `0` for
    /// any `2xx` code). A mismatched/rejected reply fails the whole
    /// pipeline; use [`Self::command_reply`] if the caller wants to handle
    /// that itself, or wants the success reply's text.
    fn command(&mut self, verb: &str, arg: Option<&str>, expect: u16);
    /// Queue an arbitrary command expecting reply code `expect`, with a
    /// callback receiving `Ok(text)` (the success reply's text — e.g.
    /// `PWD`'s quoted path, `SIZE`'s byte count, `SYST`'s system string)
    /// or `Err` on a mismatched/rejected reply. Unlike [`Self::command`],
    /// a mismatch here does *not* fail the pipeline — the callback decides.
    fn command_reply(&mut self, verb: &str, arg: Option<&str>, expect: u16, callback: CmdCallback);
    /// Queue a passive RETR; `callback` receives the file bytes.
    fn retr(&mut self, path: &str, callback: RetrCallback);
    /// Queue a passive RETR resuming from `offset` (RFC 959 §4.1.3 — sends
    /// `REST offset`, expecting `350`, before `RETR`).
    fn retr_from(&mut self, path: &str, offset: u64, callback: RetrCallback);
    /// Queue a passive STOR; `callback` receives `Ok(())` on success.
    fn stor(&mut self, path: &str, data: Vec<u8>, callback: StorCallback);
    /// Queue a passive STOR resuming from `offset` (RFC 959 §4.1.3 — sends
    /// `REST offset`, expecting `350`, before `STOR`). `data` is the
    /// remaining bytes to send — i.e. the file's content starting at
    /// `offset`, not the whole file.
    fn stor_from(&mut self, path: &str, offset: u64, data: Vec<u8>, callback: StorCallback);
    /// Queue a passive LIST; `callback` receives the directory listing bytes.
    fn list(&mut self, path: Option<&str>, callback: RetrCallback);
    /// Queue a passive APPE (append to `path`, creating it if it doesn't
    /// exist); `callback` receives `Ok(())` on success.
    fn appe(&mut self, path: &str, data: Vec<u8>, callback: StorCallback);
    /// Queue a passive NLST (name-only listing); `callback` receives the
    /// listing bytes.
    fn nlst(&mut self, path: Option<&str>, callback: RetrCallback);
    /// Queue a passive STOU (store with a server-assigned unique filename);
    /// `callback` receives the assigned filename on success.
    fn stou(&mut self, data: Vec<u8>, callback: StouCallback);
    /// Queue `QUIT`.
    fn quit(&mut self);
}

impl FtpSessionWrite for OpQueue {
    fn type_image(&mut self) {
        self.ops.push_back(QueuedOp::Command {
            verb: "TYPE".into(),
            arg: Some("I".into()),
            expect: 200,
            callback: None,
        });
    }

    fn type_ascii(&mut self) {
        self.ops.push_back(QueuedOp::Command {
            verb: "TYPE".into(),
            arg: Some("A".into()),
            expect: 200,
            callback: None,
        });
    }

    fn command(&mut self, verb: &str, arg: Option<&str>, expect: u16) {
        self.ops.push_back(QueuedOp::Command {
            verb: verb.to_string(),
            arg: arg.map(|s| s.to_string()),
            expect,
            callback: None,
        });
    }

    fn command_reply(&mut self, verb: &str, arg: Option<&str>, expect: u16, callback: CmdCallback) {
        self.ops.push_back(QueuedOp::Command {
            verb: verb.to_string(),
            arg: arg.map(|s| s.to_string()),
            expect,
            callback: Some(callback),
        });
    }

    fn retr(&mut self, path: &str, callback: RetrCallback) {
        self.ops.push_back(QueuedOp::Retr {
            path: path.to_string(),
            offset: None,
            callback,
        });
    }

    fn retr_from(&mut self, path: &str, offset: u64, callback: RetrCallback) {
        self.ops.push_back(QueuedOp::Retr {
            path: path.to_string(),
            offset: Some(offset),
            callback,
        });
    }

    fn stor(&mut self, path: &str, data: Vec<u8>, callback: StorCallback) {
        self.ops.push_back(QueuedOp::Stor {
            path: path.to_string(),
            data: Arc::new(data),
            offset: None,
            callback,
        });
    }

    fn stor_from(&mut self, path: &str, offset: u64, data: Vec<u8>, callback: StorCallback) {
        self.ops.push_back(QueuedOp::Stor {
            path: path.to_string(),
            data: Arc::new(data),
            offset: Some(offset),
            callback,
        });
    }

    fn list(&mut self, path: Option<&str>, callback: RetrCallback) {
        self.ops.push_back(QueuedOp::List {
            path: path.map(|s| s.to_string()),
            callback,
        });
    }

    fn appe(&mut self, path: &str, data: Vec<u8>, callback: StorCallback) {
        self.ops.push_back(QueuedOp::Appe {
            path: path.to_string(),
            data: Arc::new(data),
            callback,
        });
    }

    fn nlst(&mut self, path: Option<&str>, callback: RetrCallback) {
        self.ops.push_back(QueuedOp::Nlst {
            path: path.map(|s| s.to_string()),
            callback,
        });
    }

    fn stou(&mut self, data: Vec<u8>, callback: StouCallback) {
        self.ops.push_back(QueuedOp::Stou { data: Arc::new(data), callback });
    }

    fn quit(&mut self) {
        self.ops.push_back(QueuedOp::Quit);
    }
}

// ---------------------------------------------------------------------------
// Public pipeline trait
// ---------------------------------------------------------------------------

/// Drives a complete FTP session from authentication to disconnect.
///
/// Implement this to create custom FTP workflows. The built-in
/// [`FtpGet`] and [`FtpPut`] cover the most common cases.
pub trait FtpPipeline: Send {
    /// Session is authenticated; issue operations via `session`.
    ///
    /// All ops are queued and dispatched asynchronously after this call
    /// returns.  Call `session.quit()` to terminate the session cleanly.
    ///
    /// `abort` can be stashed (it's `Clone` and thread-safe) to cancel an
    /// in-flight transfer later — e.g. from a UI cancel button or a
    /// watchdog timer — via [`FtpAbortHandle::abort`].
    fn start(&mut self, session: &mut dyn FtpSessionWrite, abort: FtpAbortHandle);

    /// All queued operations completed successfully and QUIT was acknowledged.
    fn done(&mut self);

    /// A fatal error occurred during the session.
    fn failed(&mut self, err: FtpError);
}

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------

/// Per-phase timeouts for an FTP connection.
#[derive(Clone, Debug)]
pub struct FtpClientTimeouts {
    /// DNS resolution budget (ignored for literal IPs).
    pub dns: Duration,
    /// TCP connect handshake budget.
    pub connect: Duration,
    /// Control-channel reply budget per command.
    pub stage: Duration,
    /// Data-transfer budget (RETR / STOR / LIST).
    pub data: Duration,
}

impl Default for FtpClientTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(30),
            stage: Duration::from_secs(60),
            data: Duration::from_secs(600),
        }
    }
}

// ---------------------------------------------------------------------------
// FtpClient
// ---------------------------------------------------------------------------

/// Async FTP client configuration and dial factory.
///
/// Resolves the host (DNS or literal IP), connects the control channel, and
/// runs the supplied [`FtpPipeline`] asynchronously on a worker reactor.
pub struct FtpClient {
    host: String,
    port: u16,
    timeouts: FtpClientTimeouts,
    credentials: Option<(String, String)>,
    prefer_epsv: bool,
    resolver: Option<Arc<DnsResolver>>,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    implicit_tls: bool,
}

impl FtpClient {
    /// Create a new client targeting `host` (hostname or IP string) on the
    /// default FTP port (21).
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 21,
            timeouts: FtpClientTimeouts::default(),
            credentials: None,
            prefer_epsv: true,
            resolver: None,
            tls_connector: None,
            tls_server_name: None,
            implicit_tls: false,
        }
    }

    /// Override the control port (default: 21).
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set per-phase timeouts.
    pub fn timeouts(mut self, t: FtpClientTimeouts) -> Self {
        self.timeouts = t;
        self
    }

    /// Provide USER / PASS credentials.
    pub fn credentials(mut self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        self.credentials = Some((user.into(), pass.into()));
        self
    }

    /// Prefer `EPSV` over `PASV` for data connections (default: `true`).
    ///
    /// When `true`, `EPSV` is sent first; if the server returns `5xx` the
    /// pipeline will fail.  Set to `false` to always use `PASV`.
    pub fn prefer_epsv(mut self, yes: bool) -> Self {
        self.prefer_epsv = yes;
        self
    }

    /// Use an existing [`DnsResolver`] instead of creating one per connect.
    pub fn resolver(mut self, r: Arc<DnsResolver>) -> Self {
        self.resolver = Some(r);
        self
    }

    /// Configure explicit FTPS (RFC 4217 `AUTH TLS`): connect in plaintext
    /// on the usual port, negotiate TLS on the control channel right after
    /// the welcome banner (before `USER`), then send `PBSZ 0` / `PROT P` so
    /// data connections (`RETR`/`STOR`/`LIST`/…) are protected too.
    pub fn auth_tls(mut self, connector: SharedTlsConnector, server_name: impl Into<String>) -> Self {
        self.tls_connector = Some(connector);
        self.tls_server_name = Some(server_name.into());
        self.implicit_tls = false;
        self
    }

    /// Configure implicit FTPS: TLS from the first byte (typically port
    /// 990 — call [`Self::port`] separately). `PBSZ 0` / `PROT P` are still
    /// sent after the welcome banner to protect data connections.
    pub fn implicit_tls(mut self, connector: SharedTlsConnector, server_name: impl Into<String>) -> Self {
        self.tls_connector = Some(connector);
        self.tls_server_name = Some(server_name.into());
        self.implicit_tls = true;
        self
    }

    /// Resolve the host, dial the control connection, and run `pipeline`.
    ///
    /// Returns immediately; the connection and pipeline execute asynchronously.
    pub fn connect(self, rt: &Arc<Runtime>, pipeline: Box<dyn FtpPipeline>) -> io::Result<()> {
        let host = self.host.clone();
        let port = self.port;
        let connect_timeout = Some(self.timeouts.connect);

        // Wrap the pipeline in Arc<Mutex<Option<_>>> so the Fn factory closure
        // can hand it off exactly once.
        let pipeline_cell: Arc<Mutex<Option<Box<dyn FtpPipeline>>>> =
            Arc::new(Mutex::new(Some(pipeline)));

        let creds = self.credentials.clone();
        let prefer_epsv = self.prefer_epsv;
        let timeouts = self.timeouts.clone();
        let rt2 = Arc::clone(rt);
        let tls_connector = self.tls_connector.clone();
        let tls_server_name = self.tls_server_name.clone();
        let implicit_tls = self.implicit_tls;

        let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> = {
            let rt3 = Arc::clone(&rt2);
            let tls_connector = tls_connector.clone();
            let tls_server_name = tls_server_name.clone();
            Arc::new(move || {
                let pl = pipeline_cell
                    .lock()
                    .unwrap()
                    .take()
                    .expect("FtpClient handler factory called more than once");
                Box::new(FtpControlHandler::new(
                    creds.clone(),
                    prefer_epsv,
                    timeouts.clone(),
                    Arc::clone(&rt3),
                    pl,
                    tls_connector.clone(),
                    tls_server_name.clone(),
                    implicit_tls,
                )) as Box<dyn ProtocolHandler>
            })
        };

        let dial = {
            let rt3 = Arc::clone(&rt2);
            let mh = Arc::clone(&make_handler);
            let tls_connector = tls_connector.clone();
            let tls_server_name = tls_server_name.clone();
            move |addr: SocketAddr| -> io::Result<()> {
                let mh2 = Arc::clone(&mh);
                let mut cfg = TcpConnectorConfig::new(addr, move || mh2())
                    .connect_timeout(connect_timeout);
                if implicit_tls {
                    if let (Some(c), Some(n)) = (tls_connector.clone(), tls_server_name.clone()) {
                        cfg = cfg.with_tls(c, n);
                    }
                }
                rt3.connect(cfg)
            }
        };

        // Literal IP skips DNS.
        if let Some(addr) = resolve_literal(&host, port) {
            return dial(addr);
        }

        // Hostname → async DNS.
        let res = match self.resolver {
            Some(r) => r,
            None => Arc::new(DnsResolver::for_runtime(rt)?),
        };

        let host_for_err = host.clone();
        res.resolve(
            &host,
            port,
            Box::new(move |result| {
                let addrs = match result {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("hopf-ftp: DNS error for {host_for_err}: {e}");
                        return;
                    }
                };
                if let Some(addr) = addrs.into_iter().next() {
                    if let Err(e) = dial(addr) {
                        eprintln!("hopf-ftp: connect error: {e}");
                    }
                }
            }),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn resolve_literal(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = host.parse::<SocketAddr>() {
        return Some(addr);
    }
    parse_literal_ip(host).map(|ip| SocketAddr::new(ip, port))
}

// ---------------------------------------------------------------------------
// Unit tests (kept from the blocking client)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::reply::{parse_epsv_port, parse_pasv_addr, parse_pwd_path};

    #[test]
    fn parse_pasv() {
        let a = parse_pasv_addr("Entering Passive Mode (192,168,1,2,4,5)").unwrap();
        assert_eq!(a, "192.168.1.2:1029".parse().unwrap());
    }

    #[test]
    fn parse_epsv() {
        assert_eq!(
            parse_epsv_port("Entering Extended Passive Mode (|||2121|)").unwrap(),
            2121
        );
    }

    #[test]
    fn parse_pwd() {
        assert_eq!(
            parse_pwd_path("\"/tmp\" is current directory").as_deref(),
            Some("/tmp")
        );
    }
}
