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

use hopf_core::{ProtocolHandler, Runtime, TcpConnectorConfig};
use hopf_dns::{parse_literal_ip, DnsResolver};

use handler::FtpControlHandler;

// ---------------------------------------------------------------------------
// Public callback types
// ---------------------------------------------------------------------------

/// Callback for RETR / LIST results.
pub type RetrCallback = Box<dyn FnOnce(io::Result<Vec<u8>>) + Send>;
/// Callback for STOR results.
pub type StorCallback = Box<dyn FnOnce(io::Result<()>) + Send>;

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
    },
    /// Passive RETR.
    Retr { path: String, callback: RetrCallback },
    /// Passive STOR (data wrapped in `Arc` to avoid copying in the factory
    /// closure).
    Stor {
        path: String,
        data: Arc<Vec<u8>>,
        callback: StorCallback,
    },
    /// Passive LIST.
    List {
        path: Option<String>,
        callback: RetrCallback,
    },
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
    /// any `2xx` code).
    fn command(&mut self, verb: &str, arg: Option<&str>, expect: u16);
    /// Queue a passive RETR; `callback` receives the file bytes.
    fn retr(&mut self, path: &str, callback: RetrCallback);
    /// Queue a passive STOR; `callback` receives `Ok(())` on success.
    fn stor(&mut self, path: &str, data: Vec<u8>, callback: StorCallback);
    /// Queue a passive LIST; `callback` receives the directory listing bytes.
    fn list(&mut self, path: Option<&str>, callback: RetrCallback);
    /// Queue `QUIT`.
    fn quit(&mut self);
}

impl FtpSessionWrite for OpQueue {
    fn type_image(&mut self) {
        self.ops.push_back(QueuedOp::Command {
            verb: "TYPE".into(),
            arg: Some("I".into()),
            expect: 200,
        });
    }

    fn type_ascii(&mut self) {
        self.ops.push_back(QueuedOp::Command {
            verb: "TYPE".into(),
            arg: Some("A".into()),
            expect: 200,
        });
    }

    fn command(&mut self, verb: &str, arg: Option<&str>, expect: u16) {
        self.ops.push_back(QueuedOp::Command {
            verb: verb.to_string(),
            arg: arg.map(|s| s.to_string()),
            expect,
        });
    }

    fn retr(&mut self, path: &str, callback: RetrCallback) {
        self.ops.push_back(QueuedOp::Retr {
            path: path.to_string(),
            callback,
        });
    }

    fn stor(&mut self, path: &str, data: Vec<u8>, callback: StorCallback) {
        self.ops.push_back(QueuedOp::Stor {
            path: path.to_string(),
            data: Arc::new(data),
            callback,
        });
    }

    fn list(&mut self, path: Option<&str>, callback: RetrCallback) {
        self.ops.push_back(QueuedOp::List {
            path: path.map(|s| s.to_string()),
            callback,
        });
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
    fn start(&mut self, session: &mut dyn FtpSessionWrite);

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

        let make_handler: Arc<dyn Fn() -> Box<dyn ProtocolHandler> + Send + Sync> = {
            let rt3 = Arc::clone(&rt2);
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
                )) as Box<dyn ProtocolHandler>
            })
        };

        let dial = {
            let rt3 = Arc::clone(&rt2);
            let mh = Arc::clone(&make_handler);
            move |addr: SocketAddr| -> io::Result<()> {
                let mh2 = Arc::clone(&mh);
                rt3.connect(
                    TcpConnectorConfig::new(addr, move || mh2())
                        .connect_timeout(connect_timeout),
                )
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
