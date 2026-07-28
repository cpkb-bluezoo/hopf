// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP server: control, data, filesystem, session, and service.

mod ascii;
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
pub use codec::{FtpCommand, FtpServerLexer, MAX_COMMAND_LINE};
pub use control::FtpControlHandler;
pub use fs::{BasicFtpFileSystem, DirectoryChange, FtpFileInfo, FtpFileOpResult, FtpFileSystem};
pub use handler::{
    FilesystemFtpHandler, FilesystemFtpHandlerFactory, FtpAuthResult, FtpConnectionHandler,
    FtpConnectionHandlerFactory, FtpConnectionMetadata, FtpOperation,
};
pub use metrics::FtpServerMetrics;
pub use reply::{
    format_epsv_reply, format_pasv_reply, reply, reply_charset, reply_multiline,
    reply_multiline_charset,
};
pub use service::{FtpConfig, FtpService};
pub use session::{DataMode, TransferType};
pub use utf8::{decode_arg, encode_name, encode_text, PathnameCharsetError};
