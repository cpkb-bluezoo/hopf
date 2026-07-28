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

/// High-level operation for authorization hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpOperation {
    /// Read / list / retrieve.
    Read,
    /// Store / append / mkdir / rename / delete.
    Write,
    /// Delete.
    Delete,
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
}

impl FilesystemFtpHandler {
    /// Serve `root` with the given trust policy.
    pub fn new(root: impl AsRef<Path>, policy: Arc<dyn TrustPolicy>) -> std::io::Result<Self> {
        Ok(Self {
            policy,
            fs: BasicFtpFileSystem::new(root, false)?,
        })
    }

    /// Read-only root.
    pub fn read_only(root: impl AsRef<Path>, policy: Arc<dyn TrustPolicy>) -> std::io::Result<Self> {
        Ok(Self {
            policy,
            fs: BasicFtpFileSystem::new(root, true)?,
        })
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
}

/// Factory that clones root + policy into a new [`FilesystemFtpHandler`] each time.
pub struct FilesystemFtpHandlerFactory {
    root: PathBuf,
    policy: Arc<dyn TrustPolicy>,
    read_only: bool,
}

impl FilesystemFtpHandlerFactory {
    /// Writable root.
    pub fn new(root: impl Into<PathBuf>, policy: Arc<dyn TrustPolicy>) -> Self {
        Self {
            root: root.into(),
            policy,
            read_only: false,
        }
    }

    /// Read-only root.
    pub fn read_only(root: impl Into<PathBuf>, policy: Arc<dyn TrustPolicy>) -> Self {
        Self {
            root: root.into(),
            policy,
            read_only: true,
        }
    }
}

impl FtpConnectionHandlerFactory for FilesystemFtpHandlerFactory {
    fn create(&self) -> Box<dyn FtpConnectionHandler> {
        let h = if self.read_only {
            FilesystemFtpHandler::read_only(&self.root, Arc::clone(&self.policy))
        } else {
            FilesystemFtpHandler::new(&self.root, Arc::clone(&self.policy))
        };
        Box::new(h.expect("ftp root must exist at factory create"))
    }
}
