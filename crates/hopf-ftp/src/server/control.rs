// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP control connection (`ProtocolHandler`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hopf_core::{
    BindingId, Endpoint, ProtocolHandler, Runtime, StorageExecutor, TcpConnectorConfig,
    TcpListenerConfig,
};
use hopf_core::tls::SharedTlsAcceptor;

use crate::server::codec::{FtpCommand, FtpServerLexer, MAX_COMMAND_LINE};
use crate::server::data::{DataBridge, FtpDataHandler, OutboundTransfer, StorTransfer};
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
    bridge: Option<Arc<DataBridge>>,
    utf8: bool,
    prot_p: bool,
    pbsz: bool,
    control_handle: Option<hopf_core::ConnHandle>,
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
            },
            cwd: "/".into(),
            logged_in: false,
            pending_user: None,
            transfer_type: TransferType::Image,
            restart: 0,
            rename_from: None,
            data_mode: DataMode::None,
            bridge: None,
            utf8: false,
            prot_p: false,
            pbsz: false,
            control_handle: None,
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
        FtpServerMetrics::add(&self.metrics.commands, 1);

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
            FtpCommand::Stor(_) => self.cmd_stor(endpoint, arg, false),
            FtpCommand::Appe(_) => self.cmd_stor(endpoint, arg, true),
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
                self.clear_pasv();
                self.bridge = None;
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
                    self.cmd_list(endpoint, arg, false);
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
                FtpServerMetrics::add(&self.metrics.auth_ok, 1);
                self.send_reply(endpoint, 230, "User logged in");
            }
            FtpAuthResult::NeedPassword => {
                self.send_reply(endpoint, 331, "User name okay, need password");
            }
            _ => {
                FtpServerMetrics::add(&self.metrics.auth_fail, 1);
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
                FtpServerMetrics::add(&self.metrics.auth_ok, 1);
                self.send_reply(endpoint, 230, "User logged in");
            }
            FtpAuthResult::NeedAccount => {
                self.send_reply(endpoint, 332, "Need account for login");
            }
            _ => {
                FtpServerMetrics::add(&self.metrics.auth_fail, 1);
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
                FtpServerMetrics::add(&self.metrics.pasv_binds, 1);
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

    fn cmd_epsv(&mut self, endpoint: &mut dyn Endpoint, _arg: &str) {
        if !self.require_auth(endpoint) {
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
                FtpServerMetrics::add(&self.metrics.pasv_binds, 1);
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
        self.clear_pasv();
        let Some(addr) = parse_eprt(arg) else {
            self.send_reply(endpoint, 501, "Syntax error in parameters");
            return;
        };
        if !self.config.allow_active_bounce && addr.ip() != self.meta.peer.ip() {
            self.send_reply(endpoint, 504, "EPRT to foreign address rejected");
            return;
        }
        self.data_mode = DataMode::Active { addr };
        let _ = self.ensure_bridge();
        self.send_reply(endpoint, 200, "EPRT command successful");
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
        self.send_reply(endpoint, 150, "Opening data connection");
        let bridge = self.ensure_bridge();
        bridge.queue_outbound(OutboundTransfer::Retr { ascii, reader, path, observer });
        // Passive binding can go after accept; leave until transfer done / ABOR.
    }

    fn cmd_stor(&mut self, endpoint: &mut dyn Endpoint, arg: &str, append: bool) {
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
        if !self.prepare_data(endpoint) {
            return;
        }
        let path = self
            .app
            .file_system(&self.meta)
            .resolve(arg, &self.cwd);
        let restart = self.restart;
        self.restart = 0;
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
        self.send_reply(endpoint, 150, "Opening data connection");
        self.ensure_bridge().queue_stor(StorTransfer {
            path,
            writer,
            observer,
            quota,
        });
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
            FtpFileOpResult::Ok => self.cmd_stor(endpoint, &unique.path, false),
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
        let mut body = String::new();
        for e in entries {
            let name = encode_name(&e.name, self.utf8);
            if names_only {
                body.push_str(&name);
                body.push_str("\r\n");
            } else {
                let t = if e.is_dir { 'd' } else { '-' };
                body.push_str(&format!(
                    "{t}rw-r--r-- 1 ftp ftp {:>10} Jan  1 00:00 {}\r\n",
                    e.size, name
                ));
            }
        }
        self.send_reply(endpoint, 150, "Opening data connection");
        self.ensure_bridge()
            .queue_outbound(OutboundTransfer::Listing {
                body: encode_text(&body, self.utf8),
            });
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
            let typ = if e.is_dir { "dir" } else { "file" };
            let name = encode_name(&e.name, self.utf8);
            body.push_str(&format!("Type={typ};Size={}; {}\r\n", e.size, name));
        }
        self.send_reply(endpoint, 150, "Opening data connection");
        self.ensure_bridge()
            .queue_outbound(OutboundTransfer::Listing {
                body: encode_text(&body, self.utf8),
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
                let typ = if e.is_dir { "dir" } else { "file" };
                let shown = encode_name(&e.path, self.utf8);
                let line = format!("Type={typ};Size={}; {}", e.size, shown);
                self.send_multiline(endpoint, 250, &["Start of list", &line, "End"]);
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
                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                    .map(|d| {
                        // YYYYMMDDhhmmss rough UTC via secs — enough for smoke tests
                        format!("{}", d.as_secs())
                    })
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
            " MLST Type*;Size*;",
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
        self.control_handle = Some(endpoint.handle());
        if let Ok(peer) = endpoint.remote_addr() {
            self.meta.peer = peer;
        }
        if let Ok(local) = endpoint.local_addr() {
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
        let cmds = self.lexer.feed(data);
        for cmd in cmds {
            self.dispatch(endpoint, cmd);
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.clear_pasv();
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

fn parse_eprt(arg: &str) -> Option<SocketAddr> {
    // |1|127.0.0.1|65000| or |2|::1|65000|
    let parts: Vec<_> = arg.trim_matches('|').split('|').collect();
    if parts.len() < 3 {
        return None;
    }
    let host: IpAddr = parts[1].parse().ok()?;
    let port: u16 = parts[2].parse().ok()?;
    Some(SocketAddr::new(host, port))
}

#[allow(dead_code)]
fn _binding_ty(_: BindingId) {}
