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

use hopf_core::{Endpoint, ProtocolHandler, Runtime, TcpConnectorConfig, TimerHandle};

use super::data::{FtpDataRetrHandler, FtpDataStorHandler, TransferState};
use super::error::FtpError;
use super::reply::{parse_epsv_port, parse_pasv_addr, FtpReply};
use super::{FtpClientTimeouts, FtpPipeline, OpQueue, QueuedOp};

// ---------------------------------------------------------------------------
// Reply lexer
// ---------------------------------------------------------------------------

/// Stateful lexer that turns a byte stream into complete [`FtpReply`] values.
pub(crate) struct FtpReplyLexer {
    buf: Vec<u8>,
}

impl FtpReplyLexer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append bytes and return all complete replies parsed so far.
    pub fn push(&mut self, data: &[u8]) -> Vec<FtpReply> {
        self.buf.extend_from_slice(data);
        // Guard against run-away servers.
        if self.buf.len() > 256 * 1024 {
            self.buf.clear();
            return Vec::new();
        }
        let mut out = Vec::new();
        while let Some(r) = self.try_parse_one() {
            out.push(r);
        }
        out
    }

    /// Try to extract one complete reply from the front of the buffer.
    ///
    /// A reply is complete when we encounter a terminating line: one that
    /// starts with `NNN ` (space, not dash) where `NNN` matches the first
    /// code seen in this reply block.
    fn try_parse_one(&mut self) -> Option<FtpReply> {
        let mut pos = 0;
        let mut first_code: Option<u16> = None;
        let mut lines: Vec<String> = Vec::new();

        loop {
            // Find the next \r\n from `pos`.
            let nl = self.buf[pos..]
                .windows(2)
                .position(|w| w == b"\r\n")?;
            let line_end = pos + nl;
            let line = &self.buf[pos..line_end];

            // Parse optional code + separator.
            let (maybe_code, sep) = if line.len() >= 4 {
                let c = std::str::from_utf8(&line[..3])
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok());
                (c, line[3])
            } else if line.len() == 3 {
                let c = std::str::from_utf8(line)
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok());
                (c, b' ')
            } else {
                (None, 0u8)
            };

            let text: String = if maybe_code.is_some() && (sep == b' ' || sep == b'-') {
                String::from_utf8_lossy(line.get(4..).unwrap_or(b"")).into_owned()
            } else {
                String::from_utf8_lossy(line).into_owned()
            };

            if let Some(c) = maybe_code {
                if first_code.is_none() {
                    first_code = Some(c);
                }
                // Terminating line: space separator + code matches first code.
                if sep == b' ' && first_code == Some(c) {
                    lines.push(text);
                    let consumed = line_end + 2;
                    self.buf.drain(..consumed);
                    return Some(FtpReply { code: c, lines });
                }
            }

            lines.push(text);
            pos = line_end + 2;
            if pos >= self.buf.len() {
                return None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Control-connection state machine
// ---------------------------------------------------------------------------

enum ControlState {
    /// Waiting for the server's `220` welcome banner.
    AwaitWelcome,
    /// `USER` sent; waiting for `331` or `230`.
    AwaitUserReply,
    /// `PASS` sent; waiting for `230`.
    AwaitPassReply,
    /// Session active; processing the op queue.
    Session,
    /// A raw command was sent; waiting for a specific reply code.
    AwaitCmdReply { expect: u16 },
    /// `PASV`/`EPSV` sent; waiting for `227`/`229`.
    AwaitPasvReply {
        verb: String,
        path: String,
        data: Option<Arc<Vec<u8>>>,
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
}

impl FtpControlHandler {
    pub fn new(
        credentials: Option<(String, String)>,
        prefer_epsv: bool,
        timeouts: FtpClientTimeouts,
        rt: Arc<Runtime>,
        pipeline: Box<dyn FtpPipeline>,
    ) -> Self {
        Self {
            credentials,
            prefer_epsv,
            timeouts,
            rt,
            pipeline: Some(pipeline),
            lexer: FtpReplyLexer::new(),
            state: ControlState::AwaitWelcome,
            op_queue: VecDeque::new(),
            stage_timer: None,
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
    fn process_all_replies(&mut self, endpoint: &mut dyn Endpoint, data: &[u8]) {
        let replies = self.lexer.push(data);
        for reply in replies {
            self.cancel_timer();
            self.process_reply(endpoint, reply);
        }
        self.arm_for_state(endpoint);
    }

    fn process_reply(&mut self, endpoint: &mut dyn Endpoint, reply: FtpReply) {
        // Extract the current state (replacing with Done as a sentinel).
        let state = std::mem::replace(&mut self.state, ControlState::Done);

        match state {
            ControlState::AwaitWelcome => {
                if reply.code == 220 {
                    match self.credentials.as_ref().map(|(u, _)| u.clone()) {
                        Some(user) => {
                            let cmd = format!("USER {user}\r\n");
                            endpoint.send(cmd.as_bytes());
                            self.state = ControlState::AwaitUserReply;
                        }
                        None => {
                            self.start_pipeline(endpoint);
                        }
                    }
                } else {
                    self.fail(endpoint, FtpError::unexpected(Some(220), reply));
                }
            }

            ControlState::AwaitUserReply => match reply.code {
                331 => {
                    let pass = self
                        .credentials
                        .as_ref()
                        .map(|(_, p)| p.clone())
                        .unwrap_or_default();
                    let cmd = format!("PASS {pass}\r\n");
                    endpoint.send(cmd.as_bytes());
                    self.state = ControlState::AwaitPassReply;
                }
                230 => {
                    self.start_pipeline(endpoint);
                }
                _ => {
                    self.fail(endpoint, FtpError::unexpected(Some(331), reply));
                }
            },

            ControlState::AwaitPassReply => {
                if reply.code == 230 {
                    self.start_pipeline(endpoint);
                } else {
                    self.fail(endpoint, FtpError::unexpected(Some(230), reply));
                }
            }

            ControlState::Session => {
                // Spurious reply while idle — ignore.
                self.state = ControlState::Session;
            }

            ControlState::AwaitCmdReply { expect } => {
                // Accept any 2xx if expect is a 2xx wildcard (0), otherwise exact match.
                let ok = if expect == 0 {
                    reply.code / 100 == 2
                } else {
                    reply.code == expect
                };
                if ok {
                    self.enter_session(endpoint);
                } else {
                    self.fail(endpoint, FtpError::unexpected(Some(expect), reply));
                }
            }

            ControlState::AwaitPasvReply { verb, path, data, transfer } => {
                if reply.code == 227 {
                    // Standard PASV
                    let text = reply.text();
                    let addr = match parse_pasv_addr(&text) {
                        Ok(a) => a,
                        Err(e) => {
                            self.fail(endpoint, e);
                            return;
                        }
                    };
                    self.open_data_conn(endpoint, addr, &verb, &path, data, transfer);
                } else if reply.code == 229 {
                    // Extended PASV
                    let text = reply.text();
                    let port = match parse_epsv_port(&text) {
                        Ok(p) => p,
                        Err(e) => {
                            self.fail(endpoint, e);
                            return;
                        }
                    };
                    let ctrl_ip = endpoint
                        .remote_addr()
                        .map(|a| a.ip())
                        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
                    let addr = SocketAddr::new(ctrl_ip, port);
                    self.open_data_conn(endpoint, addr, &verb, &path, data, transfer);
                } else {
                    self.fail(endpoint, FtpError::unexpected(Some(227), reply));
                }
            }

            ControlState::AwaitXferStart { transfer } => {
                if reply.code == 125 || reply.code == 150 {
                    // Server is ready — release any STOR upload waiting on
                    // the data connection.
                    {
                        let mut g = transfer.lock().unwrap();
                        g.start_ok = true;
                        if let (Some(h), Some(payload)) =
                            (g.data_conn.take(), g.stor_payload.take())
                        {
                            drop(g);
                            h.with_endpoint(move |ep| {
                                ep.send(&payload);
                                ep.close();
                            });
                        }
                    }
                    self.state = ControlState::AwaitXferEnd { transfer };
                } else {
                    self.fail(endpoint, FtpError::unexpected(Some(150), reply));
                }
            }

            ControlState::AwaitXferEnd { transfer } => {
                if reply.code == 226 || reply.code == 250 {
                    {
                        let mut g = transfer.lock().unwrap();
                        g.ctrl_done = true;
                        g.maybe_complete();
                    }
                    self.enter_session(endpoint);
                } else {
                    self.fail(endpoint, FtpError::unexpected(Some(226), reply));
                }
            }

            ControlState::AwaitQuitReply => {
                // 221 or any reply — session is done.
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

    /// Open a passive data connection, then send the transfer command.
    fn open_data_conn(
        &mut self,
        endpoint: &mut dyn Endpoint,
        addr: SocketAddr,
        verb: &str,
        path: &str,
        data: Option<Arc<Vec<u8>>>,
        transfer: Arc<Mutex<TransferState>>,
    ) {
        let is_stor = verb == "STOR";
        let transfer_clone = Arc::clone(&transfer);
        let data_clone = data.clone();
        let connect_result = self.rt.connect(TcpConnectorConfig::new(addr, move || {
            if is_stor {
                let d = data_clone
                    .clone()
                    .unwrap_or_else(|| Arc::new(Vec::new()));
                Box::new(FtpDataStorHandler::new(d, Arc::clone(&transfer_clone)))
                    as Box<dyn ProtocolHandler>
            } else {
                Box::new(FtpDataRetrHandler::new(Arc::clone(&transfer_clone)))
            }
        }));

        if let Err(e) = connect_result {
            self.fail(endpoint, FtpError::Io(e));
            return;
        }

        // Send the transfer command (RETR/STOR/LIST).
        let cmd = if !path.is_empty() {
            format!("{verb} {path}\r\n")
        } else {
            format!("{verb}\r\n")
        };
        endpoint.send(cmd.as_bytes());
        self.state = ControlState::AwaitXferStart { transfer };
    }

    /// Call `pipeline.start()`, drain the resulting op queue, and process
    /// the first op immediately.
    fn start_pipeline(&mut self, endpoint: &mut dyn Endpoint) {
        let mut op_q = OpQueue::new();
        if let Some(mut pl) = self.pipeline.take() {
            pl.start(&mut op_q);
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

            Some(QueuedOp::Command { verb, arg, expect }) => {
                let cmd = match arg.as_deref().filter(|a| !a.is_empty()) {
                    Some(a) => format!("{verb} {a}\r\n"),
                    None => format!("{verb}\r\n"),
                };
                endpoint.send(cmd.as_bytes());
                self.state = ControlState::AwaitCmdReply { expect };
            }

            Some(QueuedOp::Retr { path, callback }) => {
                let transfer = Arc::new(Mutex::new(TransferState::retr(callback)));
                self.send_pasv_or_epsv(endpoint);
                self.state = ControlState::AwaitPasvReply {
                    verb: "RETR".into(),
                    path,
                    data: None,
                    transfer,
                };
            }

            Some(QueuedOp::Stor { path, data, callback }) => {
                let transfer = Arc::new(Mutex::new(TransferState::stor(callback)));
                self.send_pasv_or_epsv(endpoint);
                self.state = ControlState::AwaitPasvReply {
                    verb: "STOR".into(),
                    path,
                    data: Some(data),
                    transfer,
                };
            }

            Some(QueuedOp::List { path, callback }) => {
                let transfer = Arc::new(Mutex::new(TransferState::retr(callback)));
                self.send_pasv_or_epsv(endpoint);
                self.state = ControlState::AwaitPasvReply {
                    verb: "LIST".into(),
                    path: path.unwrap_or_default(),
                    data: None,
                    transfer,
                };
            }

            Some(QueuedOp::Quit) => {
                endpoint.send(b"QUIT\r\n");
                self.state = ControlState::AwaitQuitReply;
            }
        }
    }

    fn send_pasv_or_epsv(&self, endpoint: &mut dyn Endpoint) {
        if self.prefer_epsv {
            endpoint.send(b"EPSV\r\n");
        } else {
            endpoint.send(b"PASV\r\n");
        }
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
        // The server sends the `220` banner proactively; wait under the stage
        // budget (the connect budget covered TCP; this covers the greeting).
        self.arm_timer(endpoint, self.timeouts.stage);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        let bytes = *data;
        *data = &[];
        self.process_all_replies(endpoint, bytes);
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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn push_str(lexer: &mut FtpReplyLexer, s: &str) -> Vec<FtpReply> {
        lexer.push(s.as_bytes())
    }

    #[test]
    fn single_line_reply() {
        let mut lex = FtpReplyLexer::new();
        let replies = push_str(&mut lex, "220 Welcome\r\n");
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].code, 220);
        assert_eq!(replies[0].lines, vec!["Welcome"]);
    }

    #[test]
    fn multi_line_reply() {
        let mut lex = FtpReplyLexer::new();
        let replies =
            push_str(&mut lex, "220-First line\r\nSecond line\r\n220 Last\r\n");
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].code, 220);
        assert!(replies[0].lines.contains(&"First line".to_string()));
        assert!(replies[0].lines.contains(&"Last".to_string()));
    }

    #[test]
    fn incremental_push() {
        let mut lex = FtpReplyLexer::new();
        assert!(push_str(&mut lex, "220 Welco").is_empty());
        let replies = push_str(&mut lex, "me\r\n");
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].code, 220);
    }

    #[test]
    fn two_replies_in_one_push() {
        let mut lex = FtpReplyLexer::new();
        let replies = push_str(&mut lex, "220 Hello\r\n331 Password\r\n");
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0].code, 220);
        assert_eq!(replies[1].code, 331);
    }
}
