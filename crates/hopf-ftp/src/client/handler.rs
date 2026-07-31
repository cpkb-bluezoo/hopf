// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async FTP control-connection [`ProtocolHandler`].
//!
//! Drives the FTP state machine: welcome banner → auth → pipeline operations
//! (TYPE / PASV / RETR / STOR / LIST / arbitrary commands / QUIT).
//!
//! Data connections are opened via the [`Runtime`] from the PASV/EPSV reply;
//! control and data handlers share a [`TransferState`] to synchronise the
//! `226` control reply with the data-channel close.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{
    Endpoint, ProtocolHandler, Runtime, SecurityInfo, SharedTlsConnector, TcpConnectorConfig,
    TimerHandle,
};

use super::data::{FtpDataRetrHandler, FtpDataStorHandler, TransferState};
use super::error::FtpError;
use super::reply::{FtpEvent, FtpReplyLexer, FtpReplyShape};
use super::{FtpClientTimeouts, FtpPipeline, OpQueue, QueuedOp};

// ---------------------------------------------------------------------------
// Control-connection state machine
// ---------------------------------------------------------------------------

enum ControlState {
    /// Waiting for the server's `220` welcome banner.
    AwaitWelcome,
    /// `AUTH TLS` sent (RFC 4217 explicit FTPS); waiting for `234`.
    AwaitAuthTlsReply,
    /// `234` received; TLS handshake in progress on the control channel.
    PendingTls,
    /// `PBSZ 0` sent; waiting for `200`.
    AwaitPbszReply,
    /// `PROT P` sent; waiting for `200`.
    AwaitProtReply,
    /// `USER` sent; waiting for `331` or `230`.
    AwaitUserReply,
    /// `PASS` sent; waiting for `230`.
    AwaitPassReply,
    /// Session active; processing the op queue.
    Session,
    /// A raw command was sent; waiting for a specific reply code.
    AwaitCmdReply {
        expect: u16,
        callback: Option<super::CmdCallback>,
    },
    /// `PASV`/`EPSV` sent; waiting for `227`/`229`.
    AwaitPasvReply {
        verb: String,
        path: String,
        /// RFC 959 §4.1.3 — resume offset; sends `REST offset` (expect
        /// `350`) before the transfer verb once the data address is known.
        offset: Option<u64>,
        transfer: Arc<Mutex<TransferState>>,
    },
    /// `REST offset` sent; waiting for `350` before opening the data
    /// connection and sending the transfer verb.
    AwaitRestReply {
        addr: SocketAddr,
        verb: String,
        path: String,
        transfer: Arc<Mutex<TransferState>>,
    },
    /// RETR/STOR/LIST sent; waiting for `125`/`150`.
    AwaitXferStart { transfer: Arc<Mutex<TransferState>> },
    /// Transfer in progress; waiting for `226`.
    AwaitXferEnd { transfer: Arc<Mutex<TransferState>> },
    /// `QUIT` sent; waiting for `221`.
    AwaitQuitReply,
    /// Terminal state.
    Done,
}

/// Async FTP control-connection handler.
pub(crate) struct FtpControlHandler {
    credentials: Option<(String, String)>,
    prefer_epsv: bool,
    timeouts: FtpClientTimeouts,
    rt: Arc<Runtime>,
    pipeline: Option<Box<dyn FtpPipeline>>,
    lexer: FtpReplyLexer,
    state: ControlState,
    op_queue: VecDeque<QueuedOp>,
    /// Active stage timer (cancelled on every reply that advances state).
    stage_timer: Option<TimerHandle>,
    /// TLS connector for FTPS (implicit or explicit `AUTH TLS`); `None` for
    /// plaintext FTP.
    tls_connector: Option<SharedTlsConnector>,
    /// SNI / cert server name for FTPS.
    tls_server_name: Option<String>,
    /// `true` while waiting for the implicit-TLS handshake to complete
    /// before the (encrypted) welcome banner is expected.
    implicit_tls_pending: bool,
    /// `true` once the control channel is confirmed secure (implicit from
    /// the start, or explicit `AUTH TLS` handshake completed) — gates
    /// whether `PBSZ`/`PROT` get sent before `USER`.
    tls_active: bool,
    /// `true` once `PROT P` succeeds — every subsequent data connection
    /// (`RETR`/`STOR`/`LIST`/…) is also TLS-wrapped.
    prot_active: bool,
}

impl FtpControlHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credentials: Option<(String, String)>,
        prefer_epsv: bool,
        timeouts: FtpClientTimeouts,
        rt: Arc<Runtime>,
        pipeline: Box<dyn FtpPipeline>,
        tls_connector: Option<SharedTlsConnector>,
        tls_server_name: Option<String>,
        implicit_tls: bool,
    ) -> Self {
        let mut lexer = FtpReplyLexer::new();
        lexer.expect(FtpReplyShape::Welcome);
        Self {
            credentials,
            prefer_epsv,
            timeouts,
            rt,
            pipeline: Some(pipeline),
            lexer,
            state: ControlState::AwaitWelcome,
            op_queue: VecDeque::new(),
            stage_timer: None,
            tls_connector,
            tls_server_name,
            implicit_tls_pending: implicit_tls,
            tls_active: false,
            prot_active: false,
        }
    }

    /// Cancel any active stage timer.
    fn cancel_timer(&mut self) {
        if let Some(t) = self.stage_timer.take() {
            t.cancel();
        }
    }

    /// Arm a timer for the current wait; on fire, deliver TimedOut via
    /// [`Endpoint::fail`] so `error()` runs on the reactor thread.
    fn arm_timer(&mut self, ep: &mut dyn Endpoint, budget: Duration) {
        self.cancel_timer();
        if budget.is_zero() {
            return;
        }
        let handle = ep.handle();
        let timer = ep.schedule_timer(
            budget,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "FTP stage timed out",
                    ));
                });
            }),
        );
        self.stage_timer = Some(timer);
    }

    /// Arm the appropriate budget for the state we just entered.
    fn arm_for_state(&mut self, ep: &mut dyn Endpoint) {
        let budget = match &self.state {
            // Idle in Session / terminal — no wait in progress.
            ControlState::Session | ControlState::Done => return,
            // Data transfers get the long data budget.
            ControlState::AwaitXferStart { .. } | ControlState::AwaitXferEnd { .. } => {
                self.timeouts.data
            }
            _ => self.timeouts.stage,
        };
        self.arm_timer(ep, budget);
    }

    // -----------------------------------------------------------------------
    // State-machine helpers
    // -----------------------------------------------------------------------

    /// Process all complete replies buffered so far.
    fn process_all_replies(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        let events = match self.lexer.feed(data) {
            Ok(events) => events,
            Err(err) => {
                self.fail(endpoint, err);
                return;
            }
        };
        for event in events {
            self.cancel_timer();
            self.process_event(endpoint, event);
            if matches!(self.state, ControlState::Done) {
                break;
            }
        }
        self.arm_for_state(endpoint);
    }

    fn process_event(&mut self, endpoint: &mut dyn Endpoint, event: FtpEvent) {
        // Extract the current state (replacing with Done as a sentinel).
        let state = std::mem::replace(&mut self.state, ControlState::Done);

        match state {
            ControlState::AwaitWelcome => match event {
                FtpEvent::Welcome => self.after_welcome(endpoint),
                FtpEvent::Error { code, message } => {
                    self.fail(endpoint, FtpError::unexpected(Some(220), code, message));
                }
                _ => {}
            },

            ControlState::AwaitAuthTlsReply => match event {
                FtpEvent::CmdOk { .. } => {
                    let (Some(connector), Some(name)) =
                        (self.tls_connector.clone(), self.tls_server_name.clone())
                    else {
                        self.fail(
                            endpoint,
                            FtpError::Io(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "AUTH TLS accepted but no TLS connector configured",
                            )),
                        );
                        return;
                    };
                    match endpoint.start_client_tls(connector, &name) {
                        Ok(()) => {
                            self.state = ControlState::PendingTls;
                            // security_established() fires once the
                            // handshake completes.
                        }
                        Err(e) => {
                            self.fail(
                                endpoint,
                                FtpError::Io(io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("start_client_tls: {e}"),
                                )),
                            );
                        }
                    }
                }
                FtpEvent::Error { code, message } => {
                    self.fail(endpoint, FtpError::unexpected(Some(234), code, message));
                }
                _ => {}
            },

            ControlState::PendingTls => {
                // Waiting for security_established(); ignore stray events.
                self.state = ControlState::PendingTls;
            }

            ControlState::AwaitPbszReply => match event {
                FtpEvent::CmdOk { .. } => {
                    endpoint.send(b"PROT P\r\n");
                    self.lexer.expect(FtpReplyShape::Cmd { expect: 200 });
                    self.state = ControlState::AwaitProtReply;
                }
                FtpEvent::Error { code, message } => {
                    self.fail(endpoint, FtpError::unexpected(Some(200), code, message));
                }
                _ => {}
            },

            ControlState::AwaitProtReply => match event {
                FtpEvent::CmdOk { .. } => {
                    self.prot_active = true;
                    self.send_user_or_start(endpoint);
                }
                FtpEvent::Error { code, message } => {
                    self.fail(endpoint, FtpError::unexpected(Some(200), code, message));
                }
                _ => {}
            },

            ControlState::AwaitUserReply => match event {
                FtpEvent::UserNeedsPassword => {
                    let pass = self
                        .credentials
                        .as_ref()
                        .map(|(_, p)| p.clone())
                        .unwrap_or_default();
                    let cmd = format!("PASS {pass}\r\n");
                    endpoint.send(cmd.as_bytes());
                    self.lexer.expect(FtpReplyShape::Pass);
                    self.state = ControlState::AwaitPassReply;
                }
                FtpEvent::UserLoggedIn => {
                    self.start_pipeline(endpoint);
                }
                FtpEvent::Error { code, message } => {
                    self.fail(endpoint, FtpError::unexpected(Some(331), code, message));
                }
                _ => {}
            },

            ControlState::AwaitPassReply => match event {
                FtpEvent::PassOk => {
                    self.start_pipeline(endpoint);
                }
                FtpEvent::Error { code, message } => {
                    self.fail(endpoint, FtpError::unexpected(Some(230), code, message));
                }
                _ => {}
            },

            ControlState::Session => {
                // Spurious reply while idle — ignore.
                self.state = ControlState::Session;
            }

            ControlState::AwaitCmdReply { expect, callback } => match event {
                FtpEvent::CmdOk { text } => {
                    if let Some(cb) = callback {
                        cb(Ok(text));
                    }
                    self.enter_session(endpoint);
                }
                FtpEvent::Error { code, message } => {
                    let err = FtpError::unexpected(Some(expect), code, message);
                    match callback {
                        // A registered callback makes the mismatch
                        // non-fatal — the pipeline decides what to do.
                        Some(cb) => {
                            cb(Err(err));
                            self.enter_session(endpoint);
                        }
                        None => self.fail(endpoint, err),
                    }
                }
                _ => {}
            },

            ControlState::AwaitPasvReply { verb, path, offset, transfer } => {
                self.dispatch_pasv_event(endpoint, event, verb, path, offset, transfer);
            }

            ControlState::AwaitRestReply { addr, verb, path, transfer } => match event {
                FtpEvent::CmdOk { .. } => {
                    self.begin_transfer(endpoint, addr, &verb, &path, transfer);
                }
                FtpEvent::Error { code, message } => {
                    self.fail(endpoint, FtpError::unexpected(Some(350), code, message));
                }
                _ => {
                    // Unrelated event — stay put and keep waiting for 350.
                    self.state = ControlState::AwaitRestReply { addr, verb, path, transfer };
                }
            },

            ControlState::AwaitXferStart { transfer } => match event {
                FtpEvent::XferStartOk { text } => {
                    // Server is ready — arm any STOR upload waiting on the
                    // data connection.
                    let armed = {
                        let mut g = transfer.lock().unwrap();
                        g.start_ok = true;
                        g.assigned_name = text;
                        g.try_arm()
                    };
                    if let Some((ready, conn)) = armed {
                        ready(super::FtpStorHandle::new(conn));
                    }
                    self.lexer.expect(FtpReplyShape::XferEnd);
                    self.state = ControlState::AwaitXferEnd { transfer };
                }
                FtpEvent::Error { code: 426, .. } => {
                    // RFC 959 §4.1.1 ABOR: the transfer was aborted before
                    // it even started — non-fatal, report it through the
                    // transfer's own callback and keep the session going.
                    {
                        let mut g = transfer.lock().unwrap();
                        g.mark_aborted();
                        g.maybe_complete();
                    }
                    self.enter_session(endpoint);
                }
                FtpEvent::Error { code, message } => {
                    self.fail(endpoint, FtpError::unexpected(Some(150), code, message));
                }
                _ => {}
            },

            ControlState::AwaitXferEnd { transfer } => match event {
                FtpEvent::XferEndOk => {
                    {
                        let mut g = transfer.lock().unwrap();
                        g.ctrl_done = true;
                        g.maybe_complete();
                    }
                    self.enter_session(endpoint);
                }
                FtpEvent::Error { code: 426, .. } => {
                    // RFC 959 §4.1.1 ABOR: same treatment as above, but the
                    // transfer had already started.
                    {
                        let mut g = transfer.lock().unwrap();
                        g.mark_aborted();
                        g.maybe_complete();
                    }
                    self.enter_session(endpoint);
                }
                FtpEvent::Error { code, message } => {
                    self.fail(endpoint, FtpError::unexpected(Some(226), code, message));
                }
                _ => {}
            },

            ControlState::AwaitQuitReply => {
                // Any reply (success or failure) — session is done.
                let _ = event;
                if let Some(mut pl) = self.pipeline.take() {
                    pl.done();
                }
                self.state = ControlState::Done;
                endpoint.close();
            }

            ControlState::Done => {
                self.state = ControlState::Done;
            }
        }
    }

    /// Handle the reply to `PASV`/`EPSV`, split out of [`Self::process_event`]
    /// for readability — the match there can't destructure `verb`/`path`/…
    /// and match on `event` in one arm cleanly.
    fn dispatch_pasv_event(
        &mut self,
        endpoint: &mut dyn Endpoint,
        event: FtpEvent,
        verb: String,
        path: String,
        offset: Option<u64>,
        transfer: Arc<Mutex<TransferState>>,
    ) {
        match event {
            FtpEvent::PasvAddr(addr) => {
                self.open_data_conn(endpoint, addr, verb, path, offset, transfer);
            }
            FtpEvent::EpsvPort(port) => {
                let ctrl_ip = endpoint
                    .remote_addr()
                    .map(|a| a.ip())
                    .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
                let addr = SocketAddr::new(ctrl_ip, port);
                self.open_data_conn(endpoint, addr, verb, path, offset, transfer);
            }
            FtpEvent::Error { code, message } => {
                self.fail(endpoint, FtpError::unexpected(Some(227), code, message));
            }
            _ => {
                // Restore state — an unrelated event arrived unexpectedly;
                // stay put and keep waiting for the real reply.
                self.state = ControlState::AwaitPasvReply { verb, path, offset, transfer };
            }
        }
    }

    /// Send `REST offset` first if a resume offset was requested, else go
    /// straight to opening the data connection and sending the transfer verb.
    fn open_data_conn(
        &mut self,
        endpoint: &mut dyn Endpoint,
        addr: SocketAddr,
        verb: String,
        path: String,
        offset: Option<u64>,
        transfer: Arc<Mutex<TransferState>>,
    ) {
        match offset {
            Some(n) => {
                endpoint.send(format!("REST {n}\r\n").as_bytes());
                self.lexer.expect(FtpReplyShape::Cmd { expect: 350 });
                self.state = ControlState::AwaitRestReply { addr, verb, path, transfer };
            }
            None => self.begin_transfer(endpoint, addr, &verb, &path, transfer),
        }
    }

    /// Open a passive data connection, then send the transfer command.
    fn begin_transfer(
        &mut self,
        endpoint: &mut dyn Endpoint,
        addr: SocketAddr,
        verb: &str,
        path: &str,
        transfer: Arc<Mutex<TransferState>>,
    ) {
        let is_stor = matches!(verb, "STOR" | "APPE" | "STOU");
        let transfer_clone = Arc::clone(&transfer);
        let mut cfg = TcpConnectorConfig::new(addr, move || {
            if is_stor {
                Box::new(FtpDataStorHandler::new(Arc::clone(&transfer_clone)))
                    as Box<dyn ProtocolHandler>
            } else {
                Box::new(FtpDataRetrHandler::new(Arc::clone(&transfer_clone)))
            }
        });
        // RFC 4217 PROT P: data connections are protected the same as the
        // control connection once negotiated.
        if self.prot_active {
            if let (Some(c), Some(n)) = (self.tls_connector.clone(), self.tls_server_name.clone())
            {
                cfg = cfg.with_tls(c, n);
            }
        }
        let connect_result = self.rt.connect(cfg);

        if let Err(e) = connect_result {
            self.fail(endpoint, FtpError::Io(e));
            return;
        }

        // Send the transfer command (RETR/STOR/LIST/APPE/NLST/STOU).
        let cmd = if !path.is_empty() {
            format!("{verb} {path}\r\n")
        } else {
            format!("{verb}\r\n")
        };
        endpoint.send(cmd.as_bytes());
        self.lexer.expect(FtpReplyShape::XferStart);
        self.state = ControlState::AwaitXferStart { transfer };
    }

    /// After the welcome banner: negotiate FTPS if configured (explicit
    /// `AUTH TLS` first, or `PBSZ`/`PROT` if already secure — implicit FTPS
    /// arrives here with `tls_active` already `true`), else proceed
    /// straight to `USER`/pipeline start.
    fn after_welcome(&mut self, endpoint: &mut dyn Endpoint) {
        if self.tls_connector.is_some() && !self.tls_active {
            // Explicit FTPS: negotiate AUTH TLS now, before USER/PASS.
            endpoint.send(b"AUTH TLS\r\n");
            self.lexer.expect(FtpReplyShape::Cmd { expect: 234 });
            self.state = ControlState::AwaitAuthTlsReply;
            return;
        }
        if self.tls_active && !self.prot_active {
            self.send_pbsz(endpoint);
            return;
        }
        self.send_user_or_start(endpoint);
    }

    /// Send `PBSZ 0` (RFC 4217 — required before `PROT`).
    fn send_pbsz(&mut self, endpoint: &mut dyn Endpoint) {
        endpoint.send(b"PBSZ 0\r\n");
        self.lexer.expect(FtpReplyShape::Cmd { expect: 200 });
        self.state = ControlState::AwaitPbszReply;
    }

    /// Send `USER` if credentials were configured, else go straight to the
    /// pipeline (matches the original pre-FTPS `AwaitWelcome` behaviour).
    fn send_user_or_start(&mut self, endpoint: &mut dyn Endpoint) {
        match self.credentials.as_ref().map(|(u, _)| u.clone()) {
            Some(user) => {
                let cmd = format!("USER {user}\r\n");
                endpoint.send(cmd.as_bytes());
                self.lexer.expect(FtpReplyShape::User);
                self.state = ControlState::AwaitUserReply;
            }
            None => {
                self.start_pipeline(endpoint);
            }
        }
    }

    /// Call `pipeline.start()`, drain the resulting op queue, and process
    /// the first op immediately.
    fn start_pipeline(&mut self, endpoint: &mut dyn Endpoint) {
        let mut op_q = OpQueue::new();
        let abort = super::FtpAbortHandle::new(endpoint.handle());
        if let Some(mut pl) = self.pipeline.take() {
            pl.start(&mut op_q, abort);
            self.pipeline = Some(pl);
        }
        self.op_queue = op_q.drain();
        self.enter_session(endpoint);
    }

    /// Transition into the idle Session state and immediately dispatch the
    /// next queued operation (if any).
    fn enter_session(&mut self, endpoint: &mut dyn Endpoint) {
        self.process_next_op(endpoint);
    }

    /// Dequeue and dispatch one operation, setting `self.state` accordingly.
    fn process_next_op(&mut self, endpoint: &mut dyn Endpoint) {
        match self.op_queue.pop_front() {
            None => {
                self.state = ControlState::Session;
            }

            Some(QueuedOp::Command { verb, arg, expect, callback }) => {
                let cmd = match arg.as_deref().filter(|a| !a.is_empty()) {
                    Some(a) => format!("{verb} {a}\r\n"),
                    None => format!("{verb}\r\n"),
                };
                endpoint.send(cmd.as_bytes());
                self.lexer.expect(FtpReplyShape::Cmd { expect });
                self.state = ControlState::AwaitCmdReply { expect, callback };
            }

            Some(QueuedOp::Retr { path, offset, receiver }) => {
                let transfer = Arc::new(Mutex::new(TransferState::retr(receiver)));
                self.send_pasv_or_epsv(endpoint);
                self.state = ControlState::AwaitPasvReply {
                    verb: "RETR".into(),
                    path,
                    offset,
                    transfer,
                };
            }

            Some(QueuedOp::Stor { path, offset, ready, callback }) => {
                let transfer = Arc::new(Mutex::new(TransferState::stor(ready, callback)));
                self.send_pasv_or_epsv(endpoint);
                self.state = ControlState::AwaitPasvReply {
                    verb: "STOR".into(),
                    path,
                    offset,
                    transfer,
                };
            }

            Some(QueuedOp::List { path, receiver }) => {
                let transfer = Arc::new(Mutex::new(TransferState::retr(receiver)));
                self.send_pasv_or_epsv(endpoint);
                self.state = ControlState::AwaitPasvReply {
                    verb: "LIST".into(),
                    path: path.unwrap_or_default(),
                    offset: None,
                    transfer,
                };
            }

            Some(QueuedOp::Appe { path, ready, callback }) => {
                let transfer = Arc::new(Mutex::new(TransferState::stor(ready, callback)));
                self.send_pasv_or_epsv(endpoint);
                self.state = ControlState::AwaitPasvReply {
                    verb: "APPE".into(),
                    path,
                    offset: None,
                    transfer,
                };
            }

            Some(QueuedOp::Nlst { path, receiver }) => {
                let transfer = Arc::new(Mutex::new(TransferState::retr(receiver)));
                self.send_pasv_or_epsv(endpoint);
                self.state = ControlState::AwaitPasvReply {
                    verb: "NLST".into(),
                    path: path.unwrap_or_default(),
                    offset: None,
                    transfer,
                };
            }

            Some(QueuedOp::Stou { ready, callback }) => {
                let transfer = Arc::new(Mutex::new(TransferState::stou(ready, callback)));
                self.send_pasv_or_epsv(endpoint);
                self.state = ControlState::AwaitPasvReply {
                    verb: "STOU".into(),
                    path: String::new(),
                    offset: None,
                    transfer,
                };
            }

            Some(QueuedOp::Quit) => {
                endpoint.send(b"QUIT\r\n");
                self.lexer.expect(FtpReplyShape::Quit);
                self.state = ControlState::AwaitQuitReply;
            }
        }
    }

    fn send_pasv_or_epsv(&mut self, endpoint: &mut dyn Endpoint) {
        if self.prefer_epsv {
            endpoint.send(b"EPSV\r\n");
        } else {
            endpoint.send(b"PASV\r\n");
        }
        self.lexer.expect(FtpReplyShape::PassiveMode);
    }

    /// Fail the pipeline with `err`, close the control connection.
    fn fail(&mut self, endpoint: &mut dyn Endpoint, err: FtpError) {
        self.cancel_timer();
        if let Some(mut pl) = self.pipeline.take() {
            pl.failed(err);
        }
        self.state = ControlState::Done;
        endpoint.close();
    }
}

// ---------------------------------------------------------------------------
// ProtocolHandler impl
// ---------------------------------------------------------------------------

impl ProtocolHandler for FtpControlHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if self.implicit_tls_pending {
            // Implicit FTPS: the TLS handshake happens automatically before
            // any bytes are decrypted; wait for `security_established`
            // before expecting the (encrypted) welcome banner.
            return;
        }
        // The server sends the `220` banner proactively; wait under the stage
        // budget (the connect budget covered TCP; this covers the greeting).
        self.arm_timer(endpoint, self.timeouts.stage);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.process_all_replies(endpoint, data);
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
        self.tls_active = true;
        if self.implicit_tls_pending {
            // Implicit FTPS handshake done; now wait for the welcome banner.
            self.implicit_tls_pending = false;
            self.lexer.expect(FtpReplyShape::Welcome);
            self.arm_timer(endpoint, self.timeouts.stage);
            return;
        }
        // Explicit `AUTH TLS` handshake done; proceed to PBSZ/PROT.
        self.send_pbsz(endpoint);
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.cancel_timer();
        // If we're disconnected before QUIT, signal failure.
        if let Some(mut pl) = self.pipeline.take() {
            pl.failed(FtpError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "FTP control connection closed unexpectedly",
            )));
        }
        self.state = ControlState::Done;
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        self.fail(
            endpoint,
            FtpError::Io(io::Error::new(err.kind(), err.to_string())),
        );
    }
}
