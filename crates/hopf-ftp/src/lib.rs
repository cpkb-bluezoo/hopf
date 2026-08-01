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

mod client;
mod server;

pub use client::{
    CmdCallback, FtpAbortHandle, FtpClient, FtpClientTimeouts, FtpError, FtpGet,
    FtpPipeline, FtpPut, FtpResult, FtpSessionWrite, FtpStorHandle, MessageReceiveCallback,
    StorCallback, StorReady, StouCallback,
};
pub use client::reply::{parse_pasv_addr, parse_epsv_port, parse_pwd_path};
pub use server::{
    decode_arg, encode_name, encode_text, format_epsv_reply, format_pasv_reply,
    normalize_ascii_newlines, reply, reply_charset, reply_multiline, reply_multiline_charset,
    BasicFtpFileSystem, DataMode, DirectoryChange, FilesystemFtpHandler,
    FilesystemFtpHandlerFactory, FtpAuthResult, FtpCommand, FtpConfig, FtpConnectionHandler,
    FtpConnectionHandlerFactory, FtpConnectionMetadata, FtpFileInfo, FtpFileOpResult,
    FtpFileSystem, FtpControlHandler, FtpOperation, FtpServerLexer, FtpServerMetrics, FtpService,
    PathnameCharsetError, StorTransfer, TransferObserver, TransferType, UniqueName,
    MAX_COMMAND_LINE,
};

#[cfg(all(test, feature = "integration"))]
mod integration;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
