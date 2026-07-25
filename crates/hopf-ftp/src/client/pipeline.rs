// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Built-in FTP client pipelines.
//!
//! A [`FtpPipeline`] drives one complete FTP session: it issues operations
//! via [`FtpSessionWrite`] when [`FtpPipeline::start`] is called, and
//! receives a completion or failure notification when the session ends.
//!
//! # Default pipelines
//!
//! | Type | Sequence |
//! |------|----------|
//! | [`FtpGet`] | `TYPE I` → `PASV` → `RETR` → `QUIT` |
//! | [`FtpPut`] | `TYPE I` → `PASV` → `STOR` → `QUIT` |

use std::io;

use super::error::FtpError;
use super::{FtpPipeline, FtpSessionWrite, RetrCallback, StorCallback};

// ---------------------------------------------------------------------------
// FtpGet
// ---------------------------------------------------------------------------

/// Pipeline that downloads one file: `USER/PASS` → `TYPE I` → `PASV` →
/// `RETR path` → `QUIT`.
///
/// The result (or I/O error) is delivered to `callback`.
pub struct FtpGet {
    path: String,
    callback: Option<RetrCallback>,
}

impl FtpGet {
    /// Create a pipeline that downloads `path` and delivers the result to
    /// `callback`.
    pub fn new(
        path: impl Into<String>,
        callback: impl FnOnce(io::Result<Vec<u8>>) + Send + 'static,
    ) -> Self {
        Self {
            path: path.into(),
            callback: Some(Box::new(callback)),
        }
    }
}

impl FtpPipeline for FtpGet {
    fn start(&mut self, session: &mut dyn FtpSessionWrite) {
        session.type_image();
        if let Some(cb) = self.callback.take() {
            session.retr(&self.path, cb);
        }
        session.quit();
    }

    fn done(&mut self) {
        // callback already fired via TransferState::maybe_complete
    }

    fn failed(&mut self, err: FtpError) {
        if let Some(cb) = self.callback.take() {
            cb(Err(err.into_io()));
        }
    }
}

// ---------------------------------------------------------------------------
// FtpPut

// ---------------------------------------------------------------------------
// FtpPut
// ---------------------------------------------------------------------------

/// Pipeline that uploads one file: `USER/PASS` → `TYPE I` → `PASV` →
/// `STOR path` → `QUIT`.
///
/// The result (or I/O error) is delivered to `callback`.
pub struct FtpPut {
    path: String,
    data: Vec<u8>,
    callback: Option<StorCallback>,
}

impl FtpPut {
    /// Create a pipeline that uploads `data` to `path` and delivers the result
    /// to `callback`.
    pub fn new(
        path: impl Into<String>,
        data: Vec<u8>,
        callback: impl FnOnce(io::Result<()>) + Send + 'static,
    ) -> Self {
        Self {
            path: path.into(),
            data,
            callback: Some(Box::new(callback)),
        }
    }
}

impl FtpPipeline for FtpPut {
    fn start(&mut self, session: &mut dyn FtpSessionWrite) {
        session.type_image();
        if let Some(cb) = self.callback.take() {
            session.stor(&self.path, std::mem::take(&mut self.data), cb);
        }
        session.quit();
    }

    fn done(&mut self) {}

    fn failed(&mut self, err: FtpError) {
        if let Some(cb) = self.callback.take() {
            cb(Err(err.into_io()));
        }
    }
}
