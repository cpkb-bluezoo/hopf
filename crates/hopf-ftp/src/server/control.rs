// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP control connection (`ProtocolHandler`).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use hopf_core::{
    BindingId, Endpoint, ProtocolHandler, Runtime, StorageError, StorageExecutor,
    TcpConnectorConfig, TcpListenerConfig,
};
use hopf_core::tls::SharedTlsAcceptor;
use hopf_otel::{
    ExportHandle, SpanKind, Trace, FtpServerMetrics as OtelFtpMetrics,
};

use crate::server::ascii::format_ftp_mtime;
use crate::server::codec::{FtpCommand, FtpServerLexer, MAX_COMMAND_LINE};
use crate::server::data::{
    DataBridge, FtpDataHandler, OutboundTransfer, StorTransfer, TransferTelemetry,
};
use crate::server::fs::FtpFileOpResult;
use crate::server::handler::{
    FtpAuthResult, FtpConnectionHandler, FtpConnectionMetadata, FtpOperation,
};
use crate::server::metrics::FtpServerMetrics;
use crate::server::reply::{
    format_epsv_reply, format_pasv_reply, reply_charset, reply_multiline_charset,
};
use crate::server::service::FtpConfig;
use crate::server::session::{DataMode, TransferType};
use crate::server::utf8::{decode_arg, encode_name, encode_text, PathnameCharsetError};

/// Control-channel protocol handler.
pub struct FtpControlHandler {
    app: Box<dyn FtpConnectionHandler>,
    runtime: Arc<Runtime>,
    storage: Arc<StorageExecutor>,
    metrics: Arc<FtpServerMetrics>,
    config: FtpConfig,
    lexer: FtpServerLexer,
    meta: FtpConnectionMetadata,
    cwd: String,
    logged_in: bool,
    pending_user: Option<String>,
    transfer_type: TransferType,
    restart: u64,
    rename_from: Option<String>,
    data_mode: DataMode,
    /// RFC 2428 §4: after `EPSV ALL`, reject PORT/PASV/EPRT for the session.
    epsv_all: bool,
    bridge: Option<Arc<DataBridge>>,
    utf8: bool,
    prot_p: bool,
    pbsz: bool,
    control_handle: Option<hopf_core::ConnHandle>,
    otel_metrics: Option<Arc<OtelFtpMetrics>>,
    export: Option<ExportHandle>,
    traces_enabled: bool,
    conn_trace: Option<Trace>,
    /// Set while a RETR/STOR/STOU/APPE file-open is offloaded (issue
    /// #188) — gates only those commands; `ABOR` and everything else stay
    /// free to run (needed so `ABOR` can interrupt an in-flight open, see
    /// [`PendingOpenOutcome`]).
    busy: Arc<AtomicBool>,
    pending_open: Arc<Mutex<Option<PendingOpenOutcome>>>,
}

/// A RETR/STOR file-open offloaded via `file_system_handle` (issue #188),
/// applied once back on the reactor by [`sync_pending_open`].
///
/// `bridge` is captured (via `ensure_bridge()`) *before* offloading, not
/// re-fetched from `FtpControlHandler::bridge` once the open completes —
/// so that an `ABOR` racing ahead of the open (`dispatch`'s `Abor` arm
/// clears `self.bridge` and calls `bridge.abort()` on the instance that
/// was current at that time) is still correctly observed here via
/// `bridge.was_aborted()`, regardless of what `self.bridge` has since
/// become.
struct PendingOpenOutcome {
    bridge: Arc<DataBridge>,
    kind: PendingOpenKind,
}

enum PendingOpenKind {
    Retr {
        result: Result<Box<dyn Read + Send>, FtpFileOpResult>,
        ascii: bool,
        path: String,
    },
    Stor {
        result: Result<Box<dyn Write + Send>, FtpFileOpResult>,
        ascii: bool,
        path: String,
        opening_msg: String,
    },
}

/// Apply an offloaded RETR/STOR open, once `cmd_retr`/`cmd_stor`'s
/// `submit_on` callback has stashed one — see [`PendingOpenOutcome`].
/// Mirrors every other crate's `sync_pending_*` (issues #181/#185/#186/
/// #187): the storage callback only has a bare `ConnHandle`, not `&mut
/// FtpControlHandler`, so it stashes the outcome and pokes instead of
/// calling back in directly.
fn sync_pending_open(handler: &mut FtpControlHandler, endpoint: &mut dyn Endpoint) {
    let Some(PendingOpenOutcome { bridge, kind }) = handler.pending_open.lock().unwrap().take()
    else {
        return;
    };
    // Open finished (or was discarded) — clear the gate even if the
    // completion callback's `with_endpoint` poke was a no-op.
    handler.busy.store(false, Ordering::Relaxed);
    if bridge.was_aborted() {
        // `ABOR` already sent its own 426/226 replies — nothing more to do.
        return;
    }
    match kind {
        PendingOpenKind::Retr { result, ascii, path } => match result {
            Ok(reader) => {
                handler.app.transfer_starting(&path, false, None, &handler.meta);
                let observer = handler.app.transfer_observer(&handler.meta);
                let telemetry = handler.begin_transfer_telemetry("download");
                handler.send_reply(endpoint, 150, "Opening data connection");
                bridge.queue_outbound(OutboundTransfer::Retr {
                    ascii,
                    reader,
                    path,
                    observer,
                    telemetry,
                });
            }
            Err(_) => handler.send_reply(endpoint, 550, "Failed to open file"),
        },
        PendingOpenKind::Stor { result, ascii, path, opening_msg } => match result {
            Ok(writer) => {
                handler.app.transfer_starting(&path, true, None, &handler.meta);
                let observer = handler.app.transfer_observer(&handler.meta);
                let quota = handler
                    .meta
                    .user
                    .clone()
                    .and_then(|user| handler.app.quota_manager().map(|qm| (qm, user)));
                let telemetry = handler.begin_transfer_telemetry("upload");
                handler.send_reply(endpoint, 150, &opening_msg);
                bridge.queue_stor(StorTransfer {
                    ascii,
                    path,
                    writer,
                    observer,
                    quota,
                    telemetry,
                });
            }
            Err(FtpFileOpResult::ReadOnly) => handler.send_reply(endpoint, 550, "Read-only file system"),
            Err(_) => handler.send_reply(endpoint, 550, "Failed to open file"),
        },
    }
}

impl FtpControlHandler {
    /// Create for a new control connection.
    pub fn new(
        app: Box<dyn FtpConnectionHandler>,
        runtime: Arc<Runtime>,
        metrics: Arc<FtpServerMetrics>,
        config: FtpConfig,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Self {
        let storage = Arc::clone(runtime.storage());
        Self {
            app,
            runtime,
            storage,
            metrics,
            config,
            lexer: FtpServerLexer::new(MAX_COMMAND_LINE),
            meta: FtpConnectionMetadata {
                peer,
                local,
                user: None,
                tls: false,
                traceparent: None,
            },
            cwd: "/".into(),
            logged_in: false,
            pending_user: None,
            transfer_type: TransferType::Image,
            restart: 0,
            rename_from: None,
            data_mode: DataMode::None,
            epsv_all: false,
            bridge: None,
            utf8: false,
            prot_p: false,
            pbsz: false,
            control_handle: None,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            conn_trace: None,
            busy: Arc::new(AtomicBool::new(false)),
            pending_open: Arc::new(Mutex::new(None)),
        }
    }

    /// Attach OTel metrics / traces from a telemetry pipeline.
    pub fn with_telemetry(
        mut self,
        otel_metrics: Option<Arc<OtelFtpMetrics>>,
        export: Option<ExportHandle>,
        traces_enabled: bool,
    ) -> Self {
        self.otel_metrics = otel_metrics;
        self.export = export;
        self.traces_enabled = traces_enabled;
        self
    }

    fn begin_connection_telemetry(&mut self) {
        if let Some(m) = &self.otel_metrics {
            m.connection_opened();
        }
        if self.traces_enabled {
            if let Some(export) = self.export.clone() {
                let t = Trace::new("FTP connection", SpanKind::Server);
                t.set_exporter(export);
                self.meta.traceparent = Some(t.traceparent());
                self.conn_trace = Some(t);
            }
        }
    }

    fn end_connection_telemetry(&mut self) {
        if let Some(trace) = self.conn_trace.take() {
            let root = trace.root_span();
            root.set_status_ok();
            root.end();
            trace.end();
        }
        self.meta.traceparent = None;
        if let Some(m) = &self.otel_metrics {
            m.connection_closed();
        }
    }

    /// Start transfer instrumentation; updates `meta.traceparent` for handlers.
    fn begin_transfer_telemetry(&mut self, direction: &'static str) -> Option<TransferTelemetry> {
        if self.otel_metrics.is_none() && self.conn_trace.is_none() {
            return None;
        }
        let span = if let Some(trace) = &self.conn_trace {
            let s = trace.start_span("FTP transfer", SpanKind::Server);
            self.meta.traceparent = Some(trace.traceparent());
            Some(s)
        } else {
            None
        };
        Some(TransferTelemetry::start(
            direction,
            self.otel_metrics.clone(),
            span,
        ))
    }

    fn record_auth(&self, ok: bool) {
        if ok {
            FtpServerMetrics::add(&self.metrics.auth_ok, 1);
        } else {
            FtpServerMetrics::add(&self.metrics.auth_fail, 1);
        }
        if let Some(m) = &self.otel_metrics {
            m.auth(ok);
        }
    }

    fn record_command(&self) {
        FtpServerMetrics::add(&self.metrics.commands, 1);
        if let Some(m) = &self.otel_metrics {
            m.command();
        }
    }

    fn record_pasv_bind(&self) {
        FtpServerMetrics::add(&self.metrics.pasv_binds, 1);
        if let Some(m) = &self.otel_metrics {
            m.pasv_bind();
        }
    }

    fn send(&self, endpoint: &mut dyn Endpoint, bytes: Vec<u8>) {
        endpoint.send(&bytes);
    }

    fn send_reply(&self, endpoint: &mut dyn Endpoint, code: u16, desc: &str) {
        endpoint.send(&reply_charset(code, desc, self.utf8));
    }

    fn send_multiline(&self, endpoint: &mut dyn Endpoint, code: u16, lines: &[&str]) {
        endpoint.send(&reply_multiline_charset(code, lines, self.utf8));
    }

    fn require_auth(&self, endpoint: &mut dyn Endpoint) -> bool {
        if self.logged_in {
            true
        } else {
            self.send_reply(endpoint, 530, "Please login with USER and PASS");
            false
        }
    }

    fn ensure_bridge(&mut self) -> Arc<DataBridge> {
        if let Some(b) = &self.bridge {
            return Arc::clone(b);
        }
        let b = DataBridge::new(Arc::clone(&self.storage), Arc::clone(&self.metrics));
        if let Some(h) = &self.control_handle {
            b.set_control(h.clone());
        }
        self.bridge = Some(Arc::clone(&b));
        b
    }

    fn clear_pasv(&mut self) {
        if let DataMode::Passive { binding, .. } = self.data_mode {
            self.runtime.remove_binding(binding);
        }
        self.data_mode = DataMode::None;
    }

    fn advertised_addr(&self, bound: SocketAddr) -> SocketAddr {
        let ip = self
            .config
            .pasv_advertised
            .unwrap_or_else(|| match self.meta.local.ip() {
                IpAddr::V4(v) if !v.is_unspecified() => IpAddr::V4(v),
                IpAddr::V6(v) if !v.is_unspecified() => IpAddr::V6(v),
                _ => IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            });
        SocketAddr::new(ip, bound.port())
    }

    fn data_tls(&self) -> Option<SharedTlsAcceptor> {
        if self.prot_p {
            self.config.tls_acceptor.clone()
        } else {
            None
        }
    }

    /// `require_tls_for_data` (RFC 4217 §2 / `require_data_tls()`) means
    /// what it says: a transfer without `PROT P` in effect is refused, not
    /// silently upgraded — the client must send `PROT P` itself before
    /// PASV/EPSV/PORT/EPRT. Call before opening/dialing any data
    /// connection.
    fn check_data_protection(&self, endpoint: &mut dyn Endpoint) -> bool {
        if self.config.require_tls_for_data && !self.prot_p {
            self.send_reply(endpoint, 522, "PROT P required for data connections");
            false
        } else {
            true
        }
    }

    fn dispatch(&mut self, endpoint: &mut dyn Endpoint, cmd: FtpCommand) {
        self.record_command();

        // Commands with a text/path argument need RFC 2640 charset
        // decoding (depends on the per-connection `self.utf8` toggle, so
        // it can't happen inside the lexer) before dispatch can use them;
        // argless commands skip this entirely.
        let arg = match cmd.arg_bytes() {
            Some(bytes) => match decode_arg(bytes, self.utf8) {
                Ok(s) => s,
                Err(PathnameCharsetError::NonAscii) => {
                    self.send_reply(
                        endpoint,
                        501,
                        "Non-ASCII characters require OPTS UTF8 ON",
                    );
                    return;
                }
                Err(PathnameCharsetError::InvalidUtf8) => {
                    self.send_reply(endpoint, 501, "Invalid UTF-8 in command argument");
                    return;
                }
            },
            None => String::new(),
        };
        let arg = arg.trim();

        match cmd {
            FtpCommand::User(_) => self.cmd_user(endpoint, arg),
            FtpCommand::Pass(_) => self.cmd_pass(endpoint, arg),
            FtpCommand::Acct => self.send_reply(endpoint, 202, "Command not implemented, superfluous"),
            FtpCommand::Cwd(_) => self.cmd_cwd(endpoint, arg),
            FtpCommand::Cdup => self.cmd_cwd(endpoint, ".."),
            FtpCommand::Pwd => {
                if self.require_auth(endpoint) {
                    self.send_reply(
                        endpoint,
                        257,
                        &format!("\"{}\" is current directory", self.cwd),
                    );
                }
            }
            FtpCommand::Quit => {
                self.clear_pasv();
                self.send_reply(endpoint, 221, "Goodbye");
                endpoint.close();
            }
            FtpCommand::Rein => {
                self.logged_in = false;
                self.pending_user = None;
                self.meta.user = None;
                self.cwd = "/".into();
                self.utf8 = false;
                self.epsv_all = false;
                self.clear_pasv();
                self.send_reply(endpoint, 220, "Service ready for new user");
            }
            FtpCommand::Noop => self.send_reply(endpoint, 200, "OK"),
            FtpCommand::Syst => self.send_reply(endpoint, 215, "UNIX Type: L8"),
            FtpCommand::Type(_) => self.cmd_type(endpoint, arg),
            FtpCommand::Stru(_) => {
                if arg.eq_ignore_ascii_case("F") || arg.is_empty() {
                    self.send_reply(endpoint, 200, "Structure set to F");
                } else {
                    self.send_reply(
                        endpoint,
                        504,
                        "Command not implemented for that parameter",
                    );
                }
            }
            FtpCommand::Mode(_) => {
                if arg.eq_ignore_ascii_case("S") || arg.is_empty() {
                    self.send_reply(endpoint, 200, "Mode set to S");
                } else {
                    self.send_reply(
                        endpoint,
                        504,
                        "Command not implemented for that parameter",
                    );
                }
            }
            FtpCommand::Pasv => self.cmd_pasv(endpoint),
            FtpCommand::Epsv(_) => self.cmd_epsv(endpoint, arg),
            FtpCommand::Port(_) => self.cmd_port(endpoint, arg),
            FtpCommand::Eprt(_) => self.cmd_eprt(endpoint, arg),
            FtpCommand::Retr(_) => self.cmd_retr(endpoint, arg),
            FtpCommand::Stor(_) => self.cmd_stor(endpoint, arg, false, None),
            FtpCommand::Appe(_) => self.cmd_stor(endpoint, arg, true, None),
            FtpCommand::Stou => self.cmd_stou(endpoint),
            FtpCommand::List(_) => self.cmd_list(endpoint, arg, false),
            FtpCommand::Nlst(_) => self.cmd_list(endpoint, arg, true),
            FtpCommand::Mlsd(_) => self.cmd_mlsd(endpoint, arg),
            FtpCommand::Mlst(_) => self.cmd_mlst(endpoint, arg),
            FtpCommand::Size(_) => self.cmd_size(endpoint, arg),
            FtpCommand::Mdtm(_) => self.cmd_mdtm(endpoint, arg),
            FtpCommand::Dele(_) => self.cmd_dele(endpoint, arg),
            FtpCommand::Rmd(_) => self.cmd_rmd(endpoint, arg),
            FtpCommand::Mkd(_) => self.cmd_mkd(endpoint, arg),
            FtpCommand::Rnfr(_) => self.cmd_rnfr(endpoint, arg),
            FtpCommand::Rnto(_) => self.cmd_rnto(endpoint, arg),
            FtpCommand::Rest(_) => self.cmd_rest(endpoint, arg),
            FtpCommand::Abor => {
                // Drop any stashed offloaded-open outcome so a later
                // `sync_pending_open` cannot revive it if the captured
                // bridge Arc somehow diverged from `self.bridge`.
                if self.pending_open.lock().unwrap().take().is_some() {
                    self.busy.store(false, Ordering::Relaxed);
                }
                let in_progress = self
                    .bridge
                    .as_ref()
                    .map(|b| b.abort())
                    .unwrap_or(false);
                self.clear_pasv();
                self.bridge = None;
                if in_progress {
                    self.send_reply(endpoint, 426, "Connection closed; transfer aborted.");
                }
                self.send_reply(endpoint, 226, "Abort successful");
            }
            FtpCommand::Stat(_) => {
                if arg.is_empty() {
                    self.send_reply(
                        endpoint,
                        211,
                        "FTP server status: Hopf FTP ready",
                    );
                } else if self.require_auth(endpoint) {
                    self.cmd_stat_path(endpoint, arg);
                }
            }
            FtpCommand::Feat => self.cmd_feat(endpoint),
            FtpCommand::Opts(_) => self.cmd_opts(endpoint, arg),
            FtpCommand::Auth(_) => self.cmd_auth(endpoint, arg),
            FtpCommand::Pbsz(_) => {
                if arg == "0" {
                    self.pbsz = true;
                    self.send_reply(endpoint, 200, "PBSZ=0");
                } else {
                    self.send_reply(endpoint, 200, "PBSZ=0 forced");
                    self.pbsz = true;
                }
            }
            FtpCommand::Prot(_) => self.cmd_prot(endpoint, arg),
            FtpCommand::Ccc => self.send_reply(endpoint, 533, "CCC not supported"),
            FtpCommand::Allo(_) => self.cmd_allo(endpoint, arg),
            FtpCommand::Site(_) => self.cmd_site(endpoint, arg),
            FtpCommand::Smnt => self.send_reply(endpoint, 502, "Command not implemented"),
            FtpCommand::Unknown { .. } => self.send_reply(endpoint, 502, "Command not implemented"),
        }
    }

    fn cmd_user(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if arg.is_empty() {
            self.send_reply(endpoint, 501, "Syntax error");
            return;
        }
        self.pending_user = Some(arg.to_string());
        self.logged_in = false;
        match self
            .app
            .authenticate(arg, None, None, &self.meta)
        {
            FtpAuthResult::Success => {
                self.logged_in = true;
                self.meta.user = Some(arg.to_string());
                self.record_auth(true);
                self.send_reply(endpoint, 230, "User logged in");
            }
            FtpAuthResult::NeedPassword => {
                self.send_reply(endpoint, 331, "User name okay, need password");
            }
            _ => {
                self.record_auth(false);
                self.send_reply(endpoint, 530, "Login incorrect");
            }
        }
    }

    fn cmd_pass(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        let Some(user) = self.pending_user.clone() else {
            self.send_reply(endpoint, 503, "Login with USER first");
            return;
        };
        match self
            .app
            .authenticate(&user, Some(arg), None, &self.meta)
        {
            FtpAuthResult::Success => {
                self.logged_in = true;
                self.meta.user = Some(user);
                self.record_auth(true);
                self.send_reply(endpoint, 230, "User logged in");
            }
            FtpAuthResult::NeedAccount => {
                self.send_reply(endpoint, 332, "Need account for login");
            }
            _ => {
                self.record_auth(false);
                self.send_reply(endpoint, 530, "Login incorrect");
            }
        }
    }

    fn cmd_cwd(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) {
            return;
        }
        if !self
            .app
            .is_authorized(FtpOperation::Navigate, arg, &self.meta)
        {
            self.send_reply(endpoint, 550, "Permission denied");
            return;
        }
        let r = self
            .app
            .file_system(&self.meta)
            .change_directory(arg, &self.cwd, &self.meta);
        if r.result == FtpFileOpResult::Ok {
            self.cwd = r.new_cwd;
            self.send_reply(endpoint, 250, "CWD successful");
        } else {
            self.send_reply(endpoint, 550, "Failed to change directory");
        }
    }

    fn cmd_type(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        let a = arg.to_ascii_uppercase();
        if a.starts_with('I') || a.is_empty() {
            self.transfer_type = TransferType::Image;
            self.send_reply(endpoint, 200, "Type set to I");
        } else if a.starts_with('A') {
            self.transfer_type = TransferType::Ascii;
            self.send_reply(endpoint, 200, "Type set to A");
        } else {
            self.send_reply(endpoint, 504, "Type not implemented");
        }
    }

    fn cmd_pasv(&mut self, endpoint: &mut dyn Endpoint) {
        if !self.require_auth(endpoint) {
            return;
        }
        if self.epsv_all {
            self.send_reply(endpoint, 501, "EPSV ALL in effect; use EPSV");
            return;
        }
        if !self.check_data_protection(endpoint) {
            return;
        }
        self.clear_pasv();
        let bridge = self.ensure_bridge();
        let bridge2 = Arc::clone(&bridge);
        let expect_tls = self.data_tls().is_some();
        let expected_peer = self.meta.peer.ip();
        let bind_ip = match self.meta.local.ip() {
            IpAddr::V4(v) => IpAddr::V4(v),
            IpAddr::V6(v) => IpAddr::V6(v),
        };
        let port = self.pick_pasv_port();
        let mut cfg = TcpListenerConfig::new(SocketAddr::new(bind_ip, port), move || {
            Box::new(FtpDataHandler::new(Arc::clone(&bridge2), expect_tls, expected_peer))
                as Box<dyn ProtocolHandler>
        });
        if let Some(tls) = self.data_tls() {
            cfg = cfg.with_tls(tls);
        }
        match self.runtime.add_tcp_listener(cfg) {
            Ok((local, id)) => {
                self.record_pasv_bind();
                let adv = self.advertised_addr(local);
                self.data_mode = DataMode::Passive {
                    binding: id,
                    local: adv,
                };
                self.send(endpoint, format_pasv_reply(adv));
            }
            Err(_) => self.send_reply(endpoint, 425, "Cannot open data connection"),
        }
    }

    fn pick_pasv_port(&self) -> u16 {
        match (self.config.pasv_port_min, self.config.pasv_port_max) {
            (Some(a), Some(b)) if a <= b => {
                let span = (b - a) as u32;
                let n = (std::time::SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0))
                    % (span + 1);
                a + n as u16
            }
            _ => 0,
        }
    }

    fn cmd_epsv(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) {
            return;
        }
        let arg = arg.trim();
        if arg.eq_ignore_ascii_case("ALL") {
            self.epsv_all = true;
            self.send_reply(endpoint, 200, "EPSV ALL ok");
            return;
        }
        if !arg.is_empty() {
            let want_v6 = match arg {
                "1" => false,
                "2" => true,
                _ => {
                    self.send_reply(
                        endpoint,
                        522,
                        "Network protocol not supported, use (1,2)",
                    );
                    return;
                }
            };
            let local_v6 = self.meta.local.is_ipv6();
            if want_v6 != local_v6 {
                let supported = if local_v6 { "(2)" } else { "(1)" };
                self.send_reply(
                    endpoint,
                    522,
                    &format!("Network protocol not supported, use {supported}"),
                );
                return;
            }
        }
        if !self.check_data_protection(endpoint) {
            return;
        }
        self.clear_pasv();
        let bridge = self.ensure_bridge();
        let bridge2 = Arc::clone(&bridge);
        let expect_tls = self.data_tls().is_some();
        let expected_peer = self.meta.peer.ip();
        let bind_ip = self.meta.local.ip();
        let mut cfg = TcpListenerConfig::new(SocketAddr::new(bind_ip, 0), move || {
            Box::new(FtpDataHandler::new(Arc::clone(&bridge2), expect_tls, expected_peer))
                as Box<dyn ProtocolHandler>
        });
        if let Some(tls) = self.data_tls() {
            cfg = cfg.with_tls(tls);
        }
        match self.runtime.add_tcp_listener(cfg) {
            Ok((local, id)) => {
                self.record_pasv_bind();
                self.data_mode = DataMode::Passive {
                    binding: id,
                    local,
                };
                self.send(endpoint, format_epsv_reply(local.port()));
            }
            Err(_) => self.send_reply(endpoint, 425, "Cannot open data connection"),
        }
    }

    fn cmd_port(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) {
            return;
        }
        if self.epsv_all {
            self.send_reply(endpoint, 501, "EPSV ALL in effect; use EPSV");
            return;
        }
        self.clear_pasv();
        let Some(addr) = parse_port(arg) else {
            self.send_reply(endpoint, 501, "Syntax error in parameters");
            return;
        };
        if !self.config.allow_active_bounce && addr.ip() != self.meta.peer.ip() {
            self.send_reply(endpoint, 504, "PORT to foreign address rejected");
            return;
        }
        self.data_mode = DataMode::Active { addr };
        let _ = self.ensure_bridge();
        self.send_reply(endpoint, 200, "PORT command successful");
    }

    fn cmd_eprt(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) {
            return;
        }
        if self.epsv_all {
            self.send_reply(endpoint, 501, "EPSV ALL in effect; use EPSV");
            return;
        }
        self.clear_pasv();
        match parse_eprt(arg) {
            Ok(addr) => {
                if !self.config.allow_active_bounce && addr.ip() != self.meta.peer.ip() {
                    self.send_reply(endpoint, 504, "EPRT to foreign address rejected");
                    return;
                }
                self.data_mode = DataMode::Active { addr };
                let _ = self.ensure_bridge();
                self.send_reply(endpoint, 200, "EPRT command successful");
            }
            Err(EprtError::ProtocolNotSupported { supported }) => {
                self.send_reply(
                    endpoint,
                    522,
                    &format!("Network protocol not supported, use ({supported})"),
                );
            }
            Err(EprtError::Syntax) => {
                self.send_reply(endpoint, 501, "Syntax error in parameters");
            }
        }
    }

    fn prepare_data(&mut self, endpoint: &mut dyn Endpoint) -> bool {
        if !self.check_data_protection(endpoint) {
            return false;
        }
        let mode = self.data_mode.clone();
        match mode {
            DataMode::None => {
                self.send_reply(endpoint, 425, "Use PASV or PORT first");
                false
            }
            DataMode::Active { addr } => {
                let bridge = self.ensure_bridge();
                let bridge2 = Arc::clone(&bridge);
                let want_tls = self.data_tls().is_some();
                if want_tls && self.config.data_tls_connector.is_none() {
                    // PROT P is in effect but this deployment has no client-role
                    // connector configured (see `with_data_tls_connector`) —
                    // refuse rather than silently falling back to cleartext.
                    self.send_reply(endpoint, 425, "Cannot secure active-mode data connection");
                    return false;
                }
                let expected_peer = addr.ip();
                let mut cfg = TcpConnectorConfig::new(addr, move || {
                    Box::new(FtpDataHandler::new(Arc::clone(&bridge2), want_tls, expected_peer))
                        as Box<dyn ProtocolHandler>
                });
                if want_tls {
                    if let Some(connector) = &self.config.data_tls_connector {
                        let server_name = self
                            .config
                            .data_tls_server_name
                            .clone()
                            .unwrap_or_else(|| "ftp-client".to_string());
                        cfg = cfg.with_tls(Arc::clone(connector), server_name);
                    }
                }
                if self.runtime.connect(cfg).is_err() {
                    self.send_reply(endpoint, 425, "Cannot open data connection");
                    return false;
                }
                true
            }
            DataMode::Passive { .. } => true,
        }
    }

    fn cmd_retr(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) || arg.is_empty() {
            if arg.is_empty() {
                self.send_reply(endpoint, 501, "Syntax error");
            }
            return;
        }
        if !self
            .app
            .is_authorized(FtpOperation::Read, arg, &self.meta)
        {
            self.send_reply(endpoint, 550, "Permission denied");
            return;
        }
        if self.busy.load(Ordering::Relaxed) {
            self.send_reply(endpoint, 450, "Requested file action not taken; server busy");
            return;
        }
        if !self.prepare_data(endpoint) {
            return;
        }
        let path = self
            .app
            .file_system(&self.meta)
            .resolve(arg, &self.cwd);
        let restart = self.restart;
        self.restart = 0;
        let ascii = self.transfer_type == TransferType::Ascii;

        let Some(fs) = self.app.file_system_handle(&self.meta) else {
            // App hasn't opted into off-thread opens — unchanged synchronous path.
            let reader = match self
                .app
                .file_system(&self.meta)
                .open_read(&path, restart, &self.meta)
            {
                Ok(r) => r,
                Err(_) => {
                    self.send_reply(endpoint, 550, "Failed to open file");
                    return;
                }
            };
            self.app.transfer_starting(&path, false, None, &self.meta);
            let observer = self.app.transfer_observer(&self.meta);
            let telemetry = self.begin_transfer_telemetry("download");
            self.send_reply(endpoint, 150, "Opening data connection");
            let bridge = self.ensure_bridge();
            bridge.queue_outbound(OutboundTransfer::Retr {
                ascii,
                reader,
                path,
                observer,
                telemetry,
            });
            return;
        };

        // Issue #188: `open_read` (including the jail canonicalization walk
        // it does) runs on a storage-pool thread, not the reactor —
        // `sync_pending_open` applies the result once back on the reactor.
        let Some(handle) = self.control_handle.clone() else {
            self.send_reply(endpoint, 550, "Internal error");
            return;
        };
        let bridge = self.ensure_bridge();
        let meta = self.meta.clone();
        let pending = Arc::clone(&self.pending_open);
        let busy = Arc::clone(&self.busy);
        self.busy.store(true, Ordering::Relaxed);
        let path_for_op = path.clone();
        self.storage.submit_on(
            handle.clone(),
            move || -> Result<Result<Box<dyn Read + Send>, FtpFileOpResult>, Box<dyn std::error::Error + Send + Sync>> {
                Ok(fs.open_read(&path_for_op, restart, &meta))
            },
            move |result: Result<Result<Box<dyn Read + Send>, FtpFileOpResult>, StorageError>| {
                let result = result.unwrap_or(Err(FtpFileOpResult::Failed));
                *pending.lock().unwrap() = Some(PendingOpenOutcome {
                    bridge,
                    kind: PendingOpenKind::Retr { result, ascii, path },
                });
                handle.with_endpoint(move |ep| {
                    busy.store(false, Ordering::Relaxed);
                    ep.poke_handler();
                });
            },
        );
        // Passive binding can go after accept; leave until transfer done / ABOR.
    }

    fn cmd_stor(
        &mut self,
        endpoint: &mut dyn Endpoint,
        arg: &str,
        append: bool,
        opening: Option<&str>,
    ) {
        if !self.require_auth(endpoint) || arg.is_empty() {
            if arg.is_empty() {
                self.send_reply(endpoint, 501, "Syntax error");
            }
            return;
        }
        if !self
            .app
            .is_authorized(FtpOperation::Write, arg, &self.meta)
        {
            self.send_reply(endpoint, 550, "Permission denied");
            return;
        }
        // Quota gate: FTP has no declared-size-ahead-of-time (no ALLO
        // tracking), so this can only check "is the user already over
        // quota", not "would this specific upload push them over" — real
        // enforcement of the latter would need incremental checks as bytes
        // stream in, which isn't implemented.
        if let Some(user) = self.meta.user.clone() {
            if self
                .app
                .quota(&user, &self.meta)
                .is_some_and(|q| q.is_storage_exceeded())
            {
                self.send_reply(endpoint, 552, "Storage quota exceeded");
                return;
            }
        }
        if self.busy.load(Ordering::Relaxed) {
            self.send_reply(endpoint, 450, "Requested file action not taken; server busy");
            return;
        }
        if !self.prepare_data(endpoint) {
            return;
        }
        let path = self
            .app
            .file_system(&self.meta)
            .resolve(arg, &self.cwd);
        let restart = self.restart;
        self.restart = 0;
        let ascii = self.transfer_type == TransferType::Ascii;
        let opening_msg = opening.unwrap_or("Opening data connection").to_string();

        let Some(fs) = self.app.file_system_handle(&self.meta) else {
            // App hasn't opted into off-thread opens — unchanged synchronous path.
            let writer = match self
                .app
                .file_system(&self.meta)
                .open_write(&path, append, restart, &self.meta)
            {
                Ok(w) => w,
                Err(FtpFileOpResult::ReadOnly) => {
                    self.send_reply(endpoint, 550, "Read-only file system");
                    return;
                }
                Err(_) => {
                    self.send_reply(endpoint, 550, "Failed to open file");
                    return;
                }
            };
            self.app.transfer_starting(&path, true, None, &self.meta);
            let observer = self.app.transfer_observer(&self.meta);
            let quota = self
                .meta
                .user
                .clone()
                .and_then(|user| self.app.quota_manager().map(|qm| (qm, user)));
            let telemetry = self.begin_transfer_telemetry("upload");
            self.send_reply(endpoint, 150, &opening_msg);
            self.ensure_bridge().queue_stor(StorTransfer {
                ascii,
                path,
                writer,
                observer,
                quota,
                telemetry,
            });
            return;
        };

        // Issue #188: `open_write` (including the jail canonicalization
        // walk it does) runs on a storage-pool thread, not the reactor —
        // `sync_pending_open` applies the result once back on the reactor.
        let Some(handle) = self.control_handle.clone() else {
            self.send_reply(endpoint, 550, "Internal error");
            return;
        };
        let bridge = self.ensure_bridge();
        let meta = self.meta.clone();
        let pending = Arc::clone(&self.pending_open);
        let busy = Arc::clone(&self.busy);
        self.busy.store(true, Ordering::Relaxed);
        let path_for_op = path.clone();
        self.storage.submit_on(
            handle.clone(),
            move || -> Result<Result<Box<dyn Write + Send>, FtpFileOpResult>, Box<dyn std::error::Error + Send + Sync>> {
                Ok(fs.open_write(&path_for_op, append, restart, &meta))
            },
            move |result: Result<Result<Box<dyn Write + Send>, FtpFileOpResult>, StorageError>| {
                let result = result.unwrap_or(Err(FtpFileOpResult::Failed));
                *pending.lock().unwrap() = Some(PendingOpenOutcome {
                    bridge,
                    kind: PendingOpenKind::Stor { result, ascii, path, opening_msg },
                });
                handle.with_endpoint(move |ep| {
                    busy.store(false, Ordering::Relaxed);
                    ep.poke_handler();
                });
            },
        );
    }

    fn cmd_stou(&mut self, endpoint: &mut dyn Endpoint) {
        if !self.require_auth(endpoint) {
            return;
        }
        let unique = self
            .app
            .file_system(&self.meta)
            .generate_unique_name(&self.cwd, None, &self.meta);
        match unique.result {
            FtpFileOpResult::Ok => {
                let msg = format!("FILE: {}", unique.path);
                self.cmd_stor(endpoint, &unique.path, false, Some(&msg));
            }
            FtpFileOpResult::ReadOnly => self.send_reply(endpoint, 550, "Read-only file system"),
            _ => self.send_reply(endpoint, 550, "Failed to generate unique file name"),
        }
    }

    fn cmd_site(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) {
            return;
        }
        match self.app.handle_site_command(arg, &self.meta) {
            FtpFileOpResult::Ok => self.send_reply(endpoint, 200, "SITE command successful"),
            FtpFileOpResult::NotSupported => {
                self.send_reply(endpoint, 502, "SITE command not implemented")
            }
            FtpFileOpResult::PermissionDenied => self.send_reply(endpoint, 550, "Permission denied"),
            FtpFileOpResult::NotFound => self.send_reply(endpoint, 550, "Not found"),
            _ => self.send_reply(endpoint, 550, "SITE command failed"),
        }
    }

    fn cmd_allo(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) {
            return;
        }
        // RFC 959 §4.1.3: ALLO <SP> <decimal-integer> [<SP> R <SP> <decimal-integer>].
        // Lenient like the rest of this command's history: a missing or
        // unparseable count still reaches the hook, just as size 0, rather
        // than a hard syntax error.
        let size: u64 = arg
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        match self.app.file_system(&self.meta).allocate_space("", size, &self.meta) {
            FtpFileOpResult::Ok => self.send_reply(endpoint, 202, "ALLO not required"),
            _ => self.send_reply(endpoint, 552, "Insufficient storage space"),
        }
    }

    fn cmd_list(&mut self, endpoint: &mut dyn Endpoint, arg: &str, names_only: bool) {
        if !self.require_auth(endpoint) {
            return;
        }
        if !self.prepare_data(endpoint) {
            return;
        }
        let path = if arg.is_empty() {
            self.cwd.clone()
        } else {
            self.app.file_system(&self.meta).resolve(arg, &self.cwd)
        };
        let Some(entries) = self
            .app
            .file_system(&self.meta)
            .list_directory(&path, &self.meta)
        else {
            self.send_reply(endpoint, 550, "Failed to list directory");
            return;
        };
        let body = self.format_list_body(&entries, names_only);
        let telemetry = self.begin_transfer_telemetry("listing");
        self.send_reply(endpoint, 150, "Opening data connection");
        self.ensure_bridge()
            .queue_outbound(OutboundTransfer::Listing {
                body: encode_text(&body, self.utf8),
                telemetry,
            });
    }

    /// STAT `<path>` — listing over the control connection (RFC 959 §4.1.3).
    fn cmd_stat_path(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self
            .app
            .is_authorized(FtpOperation::Read, arg, &self.meta)
        {
            self.send_reply(endpoint, 550, "Permission denied");
            return;
        }
        let path = self.app.file_system(&self.meta).resolve(arg, &self.cwd);
        if let Some(entries) = self
            .app
            .file_system(&self.meta)
            .list_directory(&path, &self.meta)
        {
            let body = self.format_list_body(&entries, false);
            let header = format!("status of {path}");
            let owned: Vec<String> = std::iter::once(header)
                .chain(body.lines().map(|l| l.to_string()))
                .chain(std::iter::once("End of status".into()))
                .collect();
            let parts: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
            self.send_multiline(endpoint, 213, &parts);
            return;
        }
        match self
            .app
            .file_system(&self.meta)
            .file_info(&path, &self.meta)
        {
            Some(e) => {
                let line = self.format_list_entry(&e);
                let header = format!("status of {path}");
                self.send_multiline(endpoint, 213, &[&header, &line, "End of status"]);
            }
            None => self.send_reply(endpoint, 550, "Failed to list path"),
        }
    }

    fn format_list_body(&self, entries: &[crate::server::fs::FtpFileInfo], names_only: bool) -> String {
        let mut body = String::new();
        for e in entries {
            if names_only {
                body.push_str(&encode_name(&e.name, self.utf8));
                body.push_str("\r\n");
            } else {
                body.push_str(&self.format_list_entry(e));
                body.push_str("\r\n");
            }
        }
        body
    }

    fn format_list_entry(&self, e: &crate::server::fs::FtpFileInfo) -> String {
        let name = encode_name(&e.name, self.utf8);
        let t = if e.is_dir { 'd' } else { '-' };
        format!("{t}rw-r--r-- 1 ftp ftp {:>10} Jan  1 00:00 {name}", e.size)
    }

    fn mls_facts(&self, e: &crate::server::fs::FtpFileInfo) -> String {
        let typ = if e.is_dir { "dir" } else { "file" };
        let modify = e
            .modified
            .map(format_ftp_mtime)
            .unwrap_or_else(|| "19700101000000".into());
        let perm = mls_perm(e.is_dir, self.config.read_only);
        format!("Type={typ};Size={};Modify={modify};Perm={perm};", e.size)
    }

    fn cmd_mlsd(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) {
            return;
        }
        if !self.prepare_data(endpoint) {
            return;
        }
        let path = if arg.is_empty() {
            self.cwd.clone()
        } else {
            self.app.file_system(&self.meta).resolve(arg, &self.cwd)
        };
        let Some(entries) = self
            .app
            .file_system(&self.meta)
            .list_directory(&path, &self.meta)
        else {
            self.send_reply(endpoint, 550, "Failed to list directory");
            return;
        };
        let mut body = String::new();
        for e in entries {
            let name = encode_name(&e.name, self.utf8);
            body.push_str(&self.mls_facts(&e));
            body.push(' ');
            body.push_str(&name);
            body.push_str("\r\n");
        }
        let telemetry = self.begin_transfer_telemetry("listing");
        self.send_reply(endpoint, 150, "Opening data connection");
        self.ensure_bridge()
            .queue_outbound(OutboundTransfer::Listing {
                body: encode_text(&body, self.utf8),
                telemetry,
            });
    }

    fn cmd_mlst(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) {
            return;
        }
        let path = if arg.is_empty() {
            self.cwd.clone()
        } else {
            self.app.file_system(&self.meta).resolve(arg, &self.cwd)
        };
        match self.app.file_system(&self.meta).file_info(&path, &self.meta) {
            Some(e) => {
                let shown = encode_name(&e.path, self.utf8);
                let line = format!("{} {}", self.mls_facts(&e), shown);
                self.send_multiline(endpoint, 250, &["Listing", &line, "End"]);
            }
            None => self.send_reply(endpoint, 550, "File not found"),
        }
    }

    fn cmd_size(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) || arg.is_empty() {
            return;
        }
        let path = self.app.file_system(&self.meta).resolve(arg, &self.cwd);
        match self.app.file_system(&self.meta).file_info(&path, &self.meta) {
            Some(e) if !e.is_dir => {
                self.send_reply(endpoint, 213, &e.size.to_string());
            }
            _ => self.send_reply(endpoint, 550, "File not found"),
        }
    }

    fn cmd_mdtm(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) || arg.is_empty() {
            return;
        }
        let path = self.app.file_system(&self.meta).resolve(arg, &self.cwd);
        match self.app.file_system(&self.meta).file_info(&path, &self.meta) {
            Some(e) => {
                let s = e
                    .modified
                    .map(format_ftp_mtime)
                    .unwrap_or_else(|| "19700101000000".into());
                self.send_reply(endpoint, 213, &s);
            }
            None => self.send_reply(endpoint, 550, "File not found"),
        }
    }

    fn cmd_dele(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) || arg.is_empty() {
            return;
        }
        if !self
            .app
            .is_authorized(FtpOperation::Delete, arg, &self.meta)
        {
            self.send_reply(endpoint, 550, "Permission denied");
            return;
        }
        let path = self.app.file_system(&self.meta).resolve(arg, &self.cwd);
        let size = self
            .app
            .file_system(&self.meta)
            .file_info(&path, &self.meta)
            .map(|i| i.size);
        match self.app.file_system(&self.meta).delete(&path, &self.meta) {
            FtpFileOpResult::Ok => {
                if let (Some(size), Some(user)) = (size, self.meta.user.clone()) {
                    self.app.record_bytes_removed(&user, size, &self.meta);
                }
                self.send_reply(endpoint, 250, "DELE successful");
            }
            _ => self.send_reply(endpoint, 550, "DELE failed"),
        }
    }

    fn cmd_rmd(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) || arg.is_empty() {
            return;
        }
        if !self
            .app
            .is_authorized(FtpOperation::DeleteDir, arg, &self.meta)
        {
            self.send_reply(endpoint, 550, "Permission denied");
            return;
        }
        let path = self.app.file_system(&self.meta).resolve(arg, &self.cwd);
        match self.app.file_system(&self.meta).rmdir(&path, &self.meta) {
            FtpFileOpResult::Ok => self.send_reply(endpoint, 250, "RMD successful"),
            _ => self.send_reply(endpoint, 550, "RMD failed"),
        }
    }

    fn cmd_mkd(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) || arg.is_empty() {
            return;
        }
        if !self
            .app
            .is_authorized(FtpOperation::CreateDir, arg, &self.meta)
        {
            self.send_reply(endpoint, 550, "Permission denied");
            return;
        }
        let path = self.app.file_system(&self.meta).resolve(arg, &self.cwd);
        match self.app.file_system(&self.meta).mkdir(&path, &self.meta) {
            FtpFileOpResult::Ok => {
                self.send_reply(endpoint, 257, &format!("\"{path}\" created"));
            }
            _ => self.send_reply(endpoint, 550, "MKD failed"),
        }
    }

    fn cmd_rnfr(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) || arg.is_empty() {
            return;
        }
        if !self
            .app
            .is_authorized(FtpOperation::Rename, arg, &self.meta)
        {
            self.send_reply(endpoint, 550, "Permission denied");
            return;
        }
        let path = self.app.file_system(&self.meta).resolve(arg, &self.cwd);
        if self
            .app
            .file_system(&self.meta)
            .file_info(&path, &self.meta)
            .is_some()
        {
            self.rename_from = Some(path);
            self.send_reply(endpoint, 350, "RNFR accepted");
        } else {
            self.send_reply(endpoint, 550, "File not found");
        }
    }

    fn cmd_rnto(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.require_auth(endpoint) || arg.is_empty() {
            return;
        }
        let Some(from) = self.rename_from.take() else {
            self.send_reply(endpoint, 503, "RNFR required first");
            return;
        };
        if !self
            .app
            .is_authorized(FtpOperation::Rename, arg, &self.meta)
        {
            self.rename_from = Some(from);
            self.send_reply(endpoint, 550, "Permission denied");
            return;
        }
        let to = self.app.file_system(&self.meta).resolve(arg, &self.cwd);
        match self
            .app
            .file_system(&self.meta)
            .rename(&from, &to, &self.meta)
        {
            FtpFileOpResult::Ok => self.send_reply(endpoint, 250, "RNTO successful"),
            _ => self.send_reply(endpoint, 550, "RNTO failed"),
        }
    }

    fn cmd_rest(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        match arg.parse::<u64>() {
            Ok(n) => {
                self.restart = n;
                self.send_reply(endpoint, 350, "Restart marker accepted");
            }
            Err(_) => self.send_reply(endpoint, 501, "Invalid restart marker"),
        }
    }

    fn cmd_feat(&mut self, endpoint: &mut dyn Endpoint) {
        let lines = [
            "Extensions supported:",
            " UTF8",
            " SIZE",
            " MDTM",
            " MLST Type*;Size*;Modify*;Perm*;",
            " MLSD",
            " REST STREAM",
            " EPSV",
            " EPRT",
            " AUTH TLS",
            " PBSZ",
            " PROT",
            "End",
        ];
        self.send_multiline(endpoint, 211, &lines);
    }

    fn cmd_opts(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        let u = arg.to_ascii_uppercase();
        // RFC 2640 §4.2: OPTS UTF8 ON (also accept bare UTF8 / UTF8 OFF).
        if u == "UTF8 ON" || u == "UTF8" {
            self.utf8 = true;
            self.send_reply(endpoint, 200, "UTF8 set to ON");
        } else if u == "UTF8 OFF" {
            self.utf8 = false;
            self.send_reply(endpoint, 200, "UTF8 set to OFF");
        } else {
            self.send_reply(endpoint, 501, "Option not understood");
        }
    }

    fn cmd_auth(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        let a = arg.to_ascii_uppercase();
        if a != "TLS" && a != "SSL" && a != "TLS-C" {
            self.send_reply(endpoint, 504, "AUTH type not supported");
            return;
        }
        if self.config.tls_acceptor.is_none() {
            self.send_reply(endpoint, 534, "TLS not available");
            return;
        }
        self.send_reply(endpoint, 234, "AUTH TLS OK");
        match endpoint.start_tls() {
            Ok(()) => {}
            Err(_) => {
                // Handshake continues asynchronously; security_established fires later.
            }
        }
    }

    fn cmd_prot(&mut self, endpoint: &mut dyn Endpoint, arg: &str) {
        if !self.pbsz {
            self.send_reply(endpoint, 503, "PBSZ required first");
            return;
        }
        match arg.to_ascii_uppercase().as_str() {
            "C" => {
                self.prot_p = false;
                self.send_reply(endpoint, 200, "Protection set to Clear");
            }
            "P" => {
                if self.config.tls_acceptor.is_none() {
                    self.send_reply(endpoint, 536, "PROT P not available");
                } else {
                    self.prot_p = true;
                    self.send_reply(endpoint, 200, "Protection set to Private");
                }
            }
            _ => self.send_reply(endpoint, 536, "PROT level not supported"),
        }
    }
}

impl ProtocolHandler for FtpControlHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        FtpServerMetrics::add(&self.metrics.connections, 1);
        self.begin_connection_telemetry();
        self.control_handle = Some(endpoint.handle());
        if let Some(peer) = endpoint.remote_addr().ok().and_then(|a| a.as_socket_addr()) {
            self.meta.peer = peer;
        }
        if let Some(local) = endpoint.local_addr().ok().and_then(|a| a.as_socket_addr()) {
            self.meta.local = local;
        }
        if let Some(b) = &self.bridge {
            b.set_control(endpoint.handle());
        }
        let mut msg = "Hopf FTP ready".to_string();
        if let Some(w) = self.app.welcome_message(&self.meta) {
            msg = w;
        }
        self.send_reply(endpoint, 220, &msg);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        // Dispatch first so an `ABOR` in this burst can mark the bridge
        // aborted before [`sync_pending_open`] applies a RETR/STOR that
        // finished on the storage pool between commands (otherwise a
        // completed open stashed in `pending_open` would send 150, then
        // ABOR would reply 426/226 — the flake seen on CI for
        // `abor_racing_ahead_of_a_pending_open_suppresses_the_transfer`).
        let cmds = self.lexer.feed(data);
        for cmd in cmds {
            self.dispatch(endpoint, cmd);
        }
        sync_pending_open(self, endpoint);
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.clear_pasv();
        self.end_connection_telemetry();
        self.app.disconnected(&self.meta);
    }

    fn security_established(
        &mut self,
        _endpoint: &mut dyn Endpoint,
        _info: &hopf_core::SecurityInfo,
    ) {
        self.meta.tls = true;
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        endpoint.close();
    }
}

fn parse_port(arg: &str) -> Option<SocketAddr> {
    let parts: Vec<_> = arg.split(',').collect();
    if parts.len() != 6 {
        return None;
    }
    let o: Vec<u8> = parts[..4]
        .iter()
        .map(|s| s.parse().ok())
        .collect::<Option<_>>()?;
    let p1: u16 = parts[4].parse().ok()?;
    let p2: u16 = parts[5].parse().ok()?;
    let port = p1 * 256 + p2;
    Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])),
        port,
    ))
}

enum EprtError {
    Syntax,
    ProtocolNotSupported { supported: &'static str },
}

fn parse_eprt(arg: &str) -> Result<SocketAddr, EprtError> {
    // |1|127.0.0.1|65000| or |2|::1|65000|
    let parts: Vec<_> = arg.trim_matches('|').split('|').collect();
    if parts.len() < 3 {
        return Err(EprtError::Syntax);
    }
    let host: IpAddr = parts[1].parse().map_err(|_| EprtError::Syntax)?;
    let port: u16 = parts[2].parse().map_err(|_| EprtError::Syntax)?;
    match (parts[0], host) {
        ("1", IpAddr::V4(_)) => Ok(SocketAddr::new(host, port)),
        ("2", IpAddr::V6(_)) => Ok(SocketAddr::new(host, port)),
        ("1", IpAddr::V6(_)) | ("2", IpAddr::V4(_)) => Err(EprtError::ProtocolNotSupported {
            supported: if host.is_ipv4() { "1" } else { "2" },
        }),
        _ => Err(EprtError::ProtocolNotSupported {
            supported: "1,2",
        }),
    }
}

/// RFC 3659 `Perm=` fact letters for the logged-in user's abilities.
fn mls_perm(is_dir: bool, read_only: bool) -> &'static str {
    if is_dir {
        if read_only {
            "el"
        } else {
            "cdeflmp"
        }
    } else if read_only {
        "r"
    } else {
        "adfrw"
    }
}

#[allow(dead_code)]
fn _binding_ty(_: BindingId) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn parse_eprt_validates_net_prt_against_address() {
        assert!(parse_eprt("|1|127.0.0.1|65000|").is_ok());
        assert!(parse_eprt("|2|::1|65000|").is_ok());
        assert!(matches!(
            parse_eprt("|1|::1|65000|"),
            Err(EprtError::ProtocolNotSupported { .. })
        ));
        assert!(matches!(
            parse_eprt("|2|127.0.0.1|65000|"),
            Err(EprtError::ProtocolNotSupported { .. })
        ));
        assert!(matches!(
            parse_eprt("|3|127.0.0.1|65000|"),
            Err(EprtError::ProtocolNotSupported { .. })
        ));
        let _ = Ipv6Addr::LOCALHOST;
    }
}

#[cfg(test)]
mod open_offload_tests {
    use super::*;
    use crate::server::fs::BasicFtpFileSystem;
    use crate::server::handler::FilesystemFtpHandler;
    use hopf_auth::PasswordTrustPolicy;
    use hopf_core::{
        ConnHandle, ConnHandleBackend, RuntimeConfig, SecurityInfo, StartTlsError, TimerHandle,
        WriteReadyCallback,
    };
    use std::collections::VecDeque;
    use std::io;
    use std::sync::OnceLock;
    use std::time::Duration;

    /// Work posted through the mock [`ConnHandle`] — mirrors a reactor
    /// queue so storage-pool `execute`/`with_endpoint` are not run on the
    /// worker thread (a synchronous `from_execute(|t| t())` made opens
    /// race with `sync_pending_open` at the end of the submitting
    /// `receive`, which flaked the defer/ABOR tests on CI).
    enum MockTask {
        Execute(Box<dyn FnOnce() + Send>),
        WithEndpoint(Box<dyn FnOnce(&mut dyn Endpoint) + Send>),
    }

    struct MockBackend {
        queue: Mutex<VecDeque<MockTask>>,
    }

    impl ConnHandleBackend for MockBackend {
        fn with_endpoint(&self, task: Box<dyn FnOnce(&mut dyn Endpoint) + Send>) {
            self.queue
                .lock()
                .unwrap()
                .push_back(MockTask::WithEndpoint(task));
        }
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            self.queue.lock().unwrap().push_back(MockTask::Execute(task));
        }
        fn is_probably_open(&self) -> bool {
            true
        }
        fn schedule_timer(
            &self,
            _delay: Duration,
            callback: Box<dyn FnOnce() + Send>,
        ) -> TimerHandle {
            self.execute(callback);
            TimerHandle::from_cancel(|| {})
        }
    }

    /// Minimal `Endpoint`: captures sent bytes and queues ConnHandle work
    /// like a real reactor (no I/O).
    struct MockEndpoint {
        sent: Vec<u8>,
        open: bool,
        peer: SocketAddr,
        local: SocketAddr,
        backend: Arc<MockBackend>,
        poked: bool,
    }
    impl MockEndpoint {
        fn new(peer: SocketAddr, local: SocketAddr) -> Self {
            Self {
                sent: Vec::new(),
                open: true,
                peer,
                local,
                backend: Arc::new(MockBackend {
                    queue: Mutex::new(VecDeque::new()),
                }),
                poked: false,
            }
        }

        /// Run queued `execute` jobs only (storage completion stash).
        /// Leaves `with_endpoint`/poke queued so a following `ABOR` can
        /// discard `pending_open` before `sync_pending_open` applies it.
        fn drain_executes(&mut self) {
            loop {
                let next = {
                    let mut q = self.backend.queue.lock().unwrap();
                    match q.front() {
                        Some(MockTask::Execute(_)) => q.pop_front(),
                        _ => None,
                    }
                };
                match next {
                    Some(MockTask::Execute(task)) => task(),
                    _ => break,
                }
            }
        }

        /// Drain all queued ConnHandle work; re-enter `receive` on poke.
        fn pump(&mut self, handler: &mut FtpControlHandler) {
            loop {
                let next = self.backend.queue.lock().unwrap().pop_front();
                match next {
                    Some(MockTask::Execute(task)) => task(),
                    Some(MockTask::WithEndpoint(task)) => task(self),
                    None if self.poked => {
                        self.poked = false;
                        let mut empty: &[u8] = &[];
                        handler.receive(self, &mut empty);
                    }
                    None => break,
                }
            }
        }
    }
    impl Endpoint for MockEndpoint {
        fn send(&mut self, data: &[u8]) {
            self.sent.extend_from_slice(data);
        }
        fn is_open(&self) -> bool {
            self.open
        }
        fn is_closing(&self) -> bool {
            false
        }
        fn close(&mut self) {
            self.open = false;
        }
        fn local_addr(&self) -> io::Result<hopf_core::PeerAddr> {
            Ok(self.local.into())
        }
        fn remote_addr(&self) -> io::Result<hopf_core::PeerAddr> {
            Ok(self.peer.into())
        }
        fn security_info(&self) -> &SecurityInfo {
            static PLAINTEXT: OnceLock<SecurityInfo> = OnceLock::new();
            PLAINTEXT.get_or_init(SecurityInfo::plaintext)
        }
        fn start_tls(&mut self) -> Result<(), StartTlsError> {
            Err(StartTlsError::Unsupported)
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _callback: Option<WriteReadyCallback>) {}
        fn poke_handler(&mut self) {
            self.poked = true;
        }
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            self.backend.execute(task);
        }
        fn schedule_timer(&self, _delay: Duration, _callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
            TimerHandle::from_cancel(|| {})
        }
        fn handle(&self) -> ConnHandle {
            ConnHandle::from_backend(Arc::clone(&self.backend) as Arc<dyn ConnHandleBackend>)
        }
    }

    /// A `FtpConnectionHandler` that never overrides `file_system_handle`
    /// (the trait default returns `None`) — used to prove RETR/STOR's
    /// synchronous fallback path (issue #188's `None` branch) still works
    /// unchanged.
    struct SyncOnlyHandler(BasicFtpFileSystem);
    impl FtpConnectionHandler for SyncOnlyHandler {
        fn authenticate(
            &mut self,
            _username: &str,
            password: Option<&str>,
            _account: Option<&str>,
            _meta: &FtpConnectionMetadata,
        ) -> FtpAuthResult {
            if password.is_some() {
                FtpAuthResult::Success
            } else {
                FtpAuthResult::NeedPassword
            }
        }
        fn file_system(&mut self, _meta: &FtpConnectionMetadata) -> &mut dyn crate::server::fs::FtpFileSystem {
            &mut self.0
        }
    }

    fn new_handler(root: &std::path::Path, app: Box<dyn FtpConnectionHandler>) -> FtpControlHandler {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:2121".parse().unwrap();
        let policy = PasswordTrustPolicy::default().with_user("u", "p").shared();
        FtpControlHandler::new(
            app,
            rt,
            FtpServerMetrics::shared(),
            FtpConfig::new(local, root, policy),
            peer,
            local,
        )
    }

    fn feed(h: &mut FtpControlHandler, ep: &mut MockEndpoint, line: &[u8]) {
        let mut data = line;
        h.receive(ep, &mut data);
    }

    fn wait_for(mut pred: impl FnMut() -> bool, max_ms: u64) -> bool {
        for _ in 0..(max_ms / 5).max(1) {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        pred()
    }

    fn login_and_pasv(h: &mut FtpControlHandler, ep: &mut MockEndpoint) {
        h.connected(ep);
        ep.sent.clear();
        feed(h, ep, b"USER u\r\n");
        feed(h, ep, b"PASS p\r\n");
        ep.sent.clear();
        feed(h, ep, b"PASV\r\n");
        assert!(
            ep.sent.starts_with(b"227 "),
            "expected PASV to succeed: {:?}",
            String::from_utf8_lossy(&ep.sent)
        );
        ep.sent.clear();
    }

    #[test]
    fn retr_defers_150_until_the_offloaded_open_completes() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("hello.txt"), b"hello world").unwrap();
        let app = Box::new(FilesystemFtpHandler::new(
            root.path(),
            PasswordTrustPolicy::default().with_user("u", "p").shared(),
        ).unwrap());
        let mut h = new_handler(root.path(), app);
        let mut ep = MockEndpoint::new("127.0.0.1:9999".parse().unwrap(), "127.0.0.1:2121".parse().unwrap());
        login_and_pasv(&mut h, &mut ep);

        feed(&mut h, &mut ep, b"RETR hello.txt\r\n");
        assert!(
            ep.sent.is_empty(),
            "150 must be deferred, not sent inline within the same receive() call: {:?}",
            String::from_utf8_lossy(&ep.sent)
        );

        assert!(
            wait_for(
                || {
                    ep.pump(&mut h);
                    !ep.sent.is_empty()
                },
                2000
            ),
            "150 must eventually be sent once the offloaded open completes"
        );
        assert!(ep.sent.starts_with(b"150 "), "{:?}", String::from_utf8_lossy(&ep.sent));
    }

    #[test]
    fn stor_defers_150_until_the_offloaded_open_completes() {
        let root = tempfile::tempdir().unwrap();
        let app = Box::new(FilesystemFtpHandler::new(
            root.path(),
            PasswordTrustPolicy::default().with_user("u", "p").shared(),
        ).unwrap());
        let mut h = new_handler(root.path(), app);
        let mut ep = MockEndpoint::new("127.0.0.1:9999".parse().unwrap(), "127.0.0.1:2121".parse().unwrap());
        login_and_pasv(&mut h, &mut ep);

        feed(&mut h, &mut ep, b"STOR new.txt\r\n");
        assert!(
            ep.sent.is_empty(),
            "150 must be deferred: {:?}",
            String::from_utf8_lossy(&ep.sent)
        );

        assert!(wait_for(
            || {
                ep.pump(&mut h);
                !ep.sent.is_empty()
            },
            2000
        ));
        assert!(ep.sent.starts_with(b"150 "), "{:?}", String::from_utf8_lossy(&ep.sent));
    }

    /// Issue #188: an `ABOR` racing ahead of a still-in-flight offloaded
    /// open (sent in the same synchronous burst, before the storage-pool
    /// callback has had a chance to run) must suppress the transfer once
    /// the open does complete — no stray 150, no double reply.
    ///
    /// Also covers the inverse timing: open already completed and stashed
    /// in `pending_open` before `ABOR` is dispatched — `receive` must
    /// process `ABOR` before `sync_pending_open`, otherwise a 150 leaks.
    #[test]
    fn abor_racing_ahead_of_a_pending_open_suppresses_the_transfer() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("hello.txt"), b"hello world").unwrap();
        let app = Box::new(FilesystemFtpHandler::new(
            root.path(),
            PasswordTrustPolicy::default().with_user("u", "p").shared(),
        ).unwrap());
        let mut h = new_handler(root.path(), app);
        let mut ep = MockEndpoint::new("127.0.0.1:9999".parse().unwrap(), "127.0.0.1:2121".parse().unwrap());
        login_and_pasv(&mut h, &mut ep);

        feed(&mut h, &mut ep, b"RETR hello.txt\r\n");
        // Drain storage `execute` callbacks until the open is stashed, but
        // do not pump `with_endpoint`/poke yet — that would sync the 150
        // before ABOR can discard the pending outcome.
        assert!(
            wait_for(
                || {
                    ep.drain_executes();
                    h.pending_open.lock().unwrap().is_some()
                },
                2000
            ),
            "offloaded open must stash a pending outcome"
        );
        feed(&mut h, &mut ep, b"ABOR\r\n");
        let after_abor = ep.sent.clone();
        assert!(!after_abor.is_empty(), "ABOR must reply promptly");
        assert!(
            !after_abor.windows(4).any(|w| w == b"150 "),
            "no 150 for a RETR that raced against ABOR: {:?}",
            String::from_utf8_lossy(&after_abor)
        );

        // Late poke / with_endpoint must not revive the aborted open.
        ep.pump(&mut h);
        assert_eq!(
            ep.sent, after_abor,
            "no further replies once the aborted open resolves"
        );
    }

    #[test]
    fn fallback_handler_without_file_system_handle_still_works_synchronously() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("hello.txt"), b"hello world").unwrap();
        let fs = BasicFtpFileSystem::new(root.path(), false).unwrap();
        let app = Box::new(SyncOnlyHandler(fs));
        let mut h = new_handler(root.path(), app);
        let mut ep = MockEndpoint::new("127.0.0.1:9999".parse().unwrap(), "127.0.0.1:2121".parse().unwrap());
        login_and_pasv(&mut h, &mut ep);

        feed(&mut h, &mut ep, b"RETR hello.txt\r\n");
        assert!(
            ep.sent.starts_with(b"150 "),
            "the None fallback must open and reply inline, within the same receive() call: {:?}",
            String::from_utf8_lossy(&ep.sent)
        );
    }
}

#[cfg(test)]
mod telemetry_tests {
    use super::*;
    use crate::server::handler::FilesystemFtpHandler;
    use hopf_auth::PasswordTrustPolicy;
    use hopf_core::{Runtime, RuntimeConfig};
    use hopf_otel::{OtelConfig, SpanContext, TelemetryPipeline};

    #[test]
    fn with_telemetry_sets_parseable_traceparent_on_connect() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-ftp-tp-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let root = tempfile::tempdir().unwrap();
        let cfg = OtelConfig::new("ftp-tp-test")
            .with_jsonl_traces(&dir)
            .with_jsonl_metrics(&dir);
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let peer: SocketAddr = "127.0.0.1:2121".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:2121".parse().unwrap();
        let policy = PasswordTrustPolicy::default().with_user("u", "p").shared();
        let app = Box::new(FilesystemFtpHandler::new(root.path(), policy.clone()).unwrap());
        let mut h = FtpControlHandler::new(
            app,
            rt,
            FtpServerMetrics::shared(),
            FtpConfig::new(local, root.path(), policy),
            peer,
            local,
        )
        .with_telemetry(
            Some(pipeline.ftp_metrics()),
            Some(pipeline.export_handle()),
            true,
        );
        h.begin_connection_telemetry();
        let tp = h.meta.traceparent.clone().expect("traceparent set");
        let ctx = SpanContext::from_traceparent(&tp).expect("valid traceparent");
        assert!(!ctx.trace_id.iter().all(|&b| b == 0));

        let xfer = h
            .begin_transfer_telemetry("download")
            .expect("transfer telemetry");
        let xfer_tp = h.meta.traceparent.clone().expect("xfer traceparent");
        let xfer_ctx = SpanContext::from_traceparent(&xfer_tp).unwrap();
        assert_eq!(xfer_ctx.trace_id, ctx.trace_id);
        assert_ne!(xfer_ctx.span_id, ctx.span_id);
        xfer.finish(true, 0);

        h.end_connection_telemetry();
        assert!(h.meta.traceparent.is_none());
        pipeline.shutdown();
        let _ = std::fs::remove_file(&dir);
    }
}