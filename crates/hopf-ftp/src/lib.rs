// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP / FTPS server and blocking client (Gumdrop `org.bluezoo.gumdrop.ftp` port).
//!
//! The protocol engine talks only to [`FtpConnectionHandler`]. The stock
//! [`FilesystemFtpHandler`] serves a filesystem root via the Runtime storage
//! API; deployers override handler callbacks for custom behaviour.
//!
//! The blocking [`FtpClient`] speaks cleartext FTP, explicit `AUTH TLS`, and
//! implicit FTPS, with PASV/EPSV (and optional active PORT/EPRT) data transfers.

#![warn(missing_docs)]

mod ascii;
mod client;
mod codec;
mod control;
mod data;
mod fs;
mod handler;
mod metrics;
mod reply;
mod service;
mod session;
mod utf8;

pub use ascii::normalize_ascii_newlines;
pub use client::{FtpClient, FtpClientBuilder, FtpDataMode, FtpError, FtpReply, FtpResult};
pub use codec::{FtpCommand, FtpServerLexer, FtpToken};
pub use control::FtpControlHandler;
pub use fs::{
    BasicFtpFileSystem, DirectoryChange, FtpFileInfo, FtpFileSystem, FtpFileOpResult,
};
pub use handler::{
    FtpAuthResult, FtpConnectionHandler, FtpConnectionHandlerFactory, FtpConnectionMetadata,
    FtpOperation, FilesystemFtpHandler, FilesystemFtpHandlerFactory,
};
pub use metrics::FtpServerMetrics;
pub use reply::{
    format_pasv_reply, format_epsv_reply, reply, reply_charset, reply_multiline,
    reply_multiline_charset,
};
pub use service::{FtpConfig, FtpService};
pub use session::{DataMode, TransferType};
pub use utf8::{decode_arg, encode_name, encode_text, PathnameCharsetError};

#[cfg(all(test, feature = "integration"))]
mod integration;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
