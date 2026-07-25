// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP / FTPS server and async client (Gumdrop `org.bluezoo.gumdrop.ftp` port).
//!
//! The protocol engine talks only to [`FtpConnectionHandler`]. The stock
//! [`FilesystemFtpHandler`] serves a filesystem root via the Runtime storage
//! API; deployers override handler callbacks for custom behaviour.
//!
//! The async [`FtpClient`] resolves hostnames via [`hopf_dns`], dials the
//! control connection on a worker reactor, and drives a [`FtpPipeline`]
//! through the session lifecycle.  Built-in pipelines: [`FtpGet`] and
//! [`FtpPut`].

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
pub use client::{
    FtpClient, FtpClientTimeouts, FtpError, FtpGet, FtpPipeline, FtpPut, FtpReply, FtpResult,
    FtpSessionWrite, RetrCallback, StorCallback,
};
pub use client::reply::{parse_pasv_addr, parse_epsv_port, parse_pwd_path};
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
