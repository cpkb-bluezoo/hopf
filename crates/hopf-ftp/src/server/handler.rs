// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Application SPI: [`FtpConnectionHandler`] and stock [`FilesystemFtpHandler`].

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hopf_auth::{IdentityMaterial, PeerContext, TrustDecision, TrustPolicy};

use crate::server::fs::{BasicFtpFileSystem, FtpFileSystem};

/// Per-connection metadata visible to handlers.
#[derive(Debug, Clone)]
pub struct FtpConnectionMetadata {
    /// Client address.
    pub peer: SocketAddr,
    /// Local control address.
    pub local: SocketAddr,
    /// Authenticated username, if any.
    pub user: Option<String>,
    /// Control channel has TLS.
    pub tls: bool,
    /// W3C `traceparent` for the active span when OTel traces are enabled.
    ///
    /// Pass to outbound HTTP clients (for example
    /// `hopf_otel::with_traceparent`) so microservice calls continue the
    /// distributed trace. Timing/duration stay in telemetry — this field is
    /// propagation identity only.
    pub traceparent: Option<String>,
}

/// Authentication outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpAuthResult {
    /// Logged in.
    Success,
    /// Need password (after USER).
    NeedPassword,
    /// Need account.
    NeedAccount,
    /// Bad credentials.
    Failed,
    /// Disconnect / service unavailable.
    Unavailable,
}

/// High-level operation for authorization hooks (Gumdrop `FTPOperation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpOperation {
    /// Read / list / retrieve (RETR, LIST, NLST, STAT, SIZE, MDTM).
    Read,
    /// Store / append (STOR, STOU, APPE).
    Write,
    /// Delete a file (DELE).
    Delete,
    /// Create a directory (MKD).
    CreateDir,
    /// Remove a directory (RMD).
    DeleteDir,
    /// Rename/move (RNFR/RNTO).
    Rename,
    /// Directory navigation (CWD, CDUP, PWD); typically always allowed for
    /// authenticated users, but available for path-based restrictions.
    Navigate,
    /// SITE subcommand.
    SiteCommand,
    /// Server administration.
    Admin,
}

/// Progress/lifecycle observer for one file transfer (RETR/STOR/APPE/STOU),
/// obtained once (on the control connection's own thread, via
/// [`FtpConnectionHandler::transfer_observer`]) and then invoked from
/// whichever thread actually moves the bytes — a `StorageExecutor` thread
/// for RETR, the data connection's own reactor thread for STOR/APPE/STOU.
/// That's why this is a separate `Send + Sync` object rather than more
/// methods directly on [`FtpConnectionHandler`] (which stays single-threaded,
/// pinned to the control connection): the transfer itself doesn't happen on
/// that thread, so nothing but a plain data mover can safely observe it.
pub trait TransferObserver: Send + Sync {
    /// One chunk has moved.
    fn transfer_progress(&self, _path: &str, _upload: bool, _data: &[u8], _total_transferred: u64) {}
    /// The transfer has finished (successfully or not).
    fn transfer_completed(&self, _path: &str, _upload: bool, _total_transferred: u64, _success: bool) {}
}

/// Per-connection application callbacks (Gumdrop `FTPConnectionHandler`).
///
/// Override selected methods; defaults allow everything and provide no welcome.
pub trait FtpConnectionHandler: Send {
    /// Optional banner line(s) after 220.
    fn welcome_message(&self, _meta: &FtpConnectionMetadata) -> Option<String> {
        None
    }

    /// USER/PASS/ACCT authentication.
    fn authenticate(
        &mut self,
        username: &str,
        password: Option<&str>,
        _account: Option<&str>,
        meta: &FtpConnectionMetadata,
    ) -> FtpAuthResult;

    /// File system for this connection (may depend on user).
    fn file_system(&mut self, meta: &FtpConnectionMetadata) -> &mut dyn FtpFileSystem;

    /// Authorization gate before an operation.
    fn is_authorized(
        &self,
        _op: FtpOperation,
        _path: &str,
        _meta: &FtpConnectionMetadata,
    ) -> bool {
        true
    }

    /// Application-defined `SITE` subcommand (e.g. `SITE CHMOD`, `SITE
    /// DISK`). `command` is the text after `SITE `, raw. The default
    /// reports [`crate::server::fs::FtpFileOpResult::NotSupported`] (502).
    fn handle_site_command(
        &mut self,
        _command: &str,
        _meta: &FtpConnectionMetadata,
    ) -> crate::server::fs::FtpFileOpResult {
        crate::server::fs::FtpFileOpResult::NotSupported
    }

    /// Notifies that the client connection has closed (QUIT or an abrupt
    /// disconnect) — final cleanup / stats point.
    fn disconnected(&mut self, _meta: &FtpConnectionMetadata) {}

    /// A data transfer (upload/download) is starting. `size` is the
    /// expected size — known for RETR (file size), usually unknown for
    /// STOR/APPE/STOU. Called synchronously on the control connection,
    /// before the data connection is even necessarily open.
    fn transfer_starting(
        &mut self,
        _path: &str,
        _upload: bool,
        _size: Option<u64>,
        _meta: &FtpConnectionMetadata,
    ) {
    }

    /// Progress/completion observer for the transfer about to start, if the
    /// application wants per-chunk notifications. Obtained once per
    /// transfer, right after [`Self::transfer_starting`] — see
    /// [`TransferObserver`] for why this is a separate object.
    fn transfer_observer(&self, _meta: &FtpConnectionMetadata) -> Option<Arc<dyn TransferObserver>> {
        None
    }

    /// Quota manager for this connection, if quota enforcement is enabled.
    /// Returns an owned handle (quota managers are meant to be shared) so
    /// it can be carried into the async completion path for STOR/APPE/STOU
    /// — those run off the control connection's own thread, so usage can't
    /// be recorded through `self` there.
    fn quota_manager(&self) -> Option<Arc<dyn hopf_core::QuotaManager>> {
        None
    }

    /// Whether storing `bytes_to_store` more bytes is allowed for
    /// `username`. Called before STOR/APPE/STOU. Default delegates to
    /// [`Self::quota_manager`], if set.
    fn can_store(&self, username: &str, bytes_to_store: u64, _meta: &FtpConnectionMetadata) -> bool {
        match self.quota_manager() {
            Some(qm) => qm.can_store(username, bytes_to_store),
            None => true,
        }
    }

    /// The current quota status for `username` (used by `SITE QUOTA`-style
    /// commands), if quotas are enabled. Default delegates to
    /// [`Self::quota_manager`].
    fn quota(&self, username: &str, _meta: &FtpConnectionMetadata) -> Option<hopf_core::Quota> {
        self.quota_manager().map(|qm| qm.get_quota(username))
    }

    /// Records that bytes were added, after a successful upload. Default
    /// delegates to [`Self::quota_manager`].
    fn record_bytes_added(&self, username: &str, bytes_added: u64, _meta: &FtpConnectionMetadata) {
        if let Some(qm) = self.quota_manager() {
            qm.record_bytes_added(username, bytes_added);
        }
    }

    /// Records that bytes were removed, after a successful delete. Default
    /// delegates to [`Self::quota_manager`].
    fn record_bytes_removed(&self, username: &str, bytes_removed: u64, _meta: &FtpConnectionMetadata) {
        if let Some(qm) = self.quota_manager() {
            qm.record_bytes_removed(username, bytes_removed);
        }
    }
}

/// Factory for per-control-connection handlers.
pub trait FtpConnectionHandlerFactory: Send + Sync {
    /// Create a handler for a new control connection.
    fn create(&self) -> Box<dyn FtpConnectionHandler>;
}

/// Stock handler: TrustPolicy auth + chrooted [`BasicFtpFileSystem`].
pub struct FilesystemFtpHandler {
    policy: Arc<dyn TrustPolicy>,
    fs: BasicFtpFileSystem,
    quota: Option<Arc<dyn hopf_core::QuotaManager>>,
}

impl FilesystemFtpHandler {
    /// Serve `root` with the given trust policy.
    pub fn new(root: impl AsRef<Path>, policy: Arc<dyn TrustPolicy>) -> std::io::Result<Self> {
        Ok(Self {
            policy,
            fs: BasicFtpFileSystem::new(root, false)?,
            quota: None,
        })
    }

    /// Read-only root.
    pub fn read_only(root: impl AsRef<Path>, policy: Arc<dyn TrustPolicy>) -> std::io::Result<Self> {
        Ok(Self {
            policy,
            fs: BasicFtpFileSystem::new(root, true)?,
            quota: None,
        })
    }

    /// Enforce per-user storage quotas via `quota` (shared across
    /// connections so usage accounting stays consistent).
    pub fn with_quota(mut self, quota: Arc<dyn hopf_core::QuotaManager>) -> Self {
        self.quota = Some(quota);
        self
    }
}

impl FtpConnectionHandler for FilesystemFtpHandler {
    fn authenticate(
        &mut self,
        username: &str,
        password: Option<&str>,
        _account: Option<&str>,
        meta: &FtpConnectionMetadata,
    ) -> FtpAuthResult {
        let Some(password) = password else {
            return FtpAuthResult::NeedPassword;
        };
        let identity = IdentityMaterial::UsernamePassword {
            username: username.to_string(),
            password: password.to_string(),
        };
        let peer = PeerContext::from_addr(meta.peer);
        match self.policy.evaluate(&identity, &peer) {
            TrustDecision::Accept => FtpAuthResult::Success,
            TrustDecision::Reject => FtpAuthResult::Failed,
        }
    }

    fn file_system(&mut self, _meta: &FtpConnectionMetadata) -> &mut dyn FtpFileSystem {
        &mut self.fs
    }

    fn quota_manager(&self) -> Option<Arc<dyn hopf_core::QuotaManager>> {
        self.quota.clone()
    }
}

/// Factory that clones root + policy into a new [`FilesystemFtpHandler`] each time.
pub struct FilesystemFtpHandlerFactory {
    root: PathBuf,
    policy: Arc<dyn TrustPolicy>,
    read_only: bool,
    quota: Option<Arc<dyn hopf_core::QuotaManager>>,
}

impl FilesystemFtpHandlerFactory {
    /// Writable root.
    pub fn new(root: impl Into<PathBuf>, policy: Arc<dyn TrustPolicy>) -> Self {
        Self {
            root: root.into(),
            policy,
            read_only: false,
            quota: None,
        }
    }

    /// Read-only root.
    pub fn read_only(root: impl Into<PathBuf>, policy: Arc<dyn TrustPolicy>) -> Self {
        Self {
            root: root.into(),
            policy,
            read_only: true,
            quota: None,
        }
    }

    /// Enforce per-user storage quotas via `quota`, shared across every
    /// connection this factory creates.
    pub fn with_quota(mut self, quota: Arc<dyn hopf_core::QuotaManager>) -> Self {
        self.quota = Some(quota);
        self
    }
}

impl FtpConnectionHandlerFactory for FilesystemFtpHandlerFactory {
    fn create(&self) -> Box<dyn FtpConnectionHandler> {
        let h = if self.read_only {
            FilesystemFtpHandler::read_only(&self.root, Arc::clone(&self.policy))
        } else {
            FilesystemFtpHandler::new(&self.root, Arc::clone(&self.policy))
        };
        let mut h = h.expect("ftp root must exist at factory create");
        if let Some(q) = &self.quota {
            h = h.with_quota(Arc::clone(q));
        }
        Box::new(h)
    }
}
