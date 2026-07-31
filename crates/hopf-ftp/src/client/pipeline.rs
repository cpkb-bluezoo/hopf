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

use std::io::{self, Read};

use super::error::FtpError;
use super::{FtpPipeline, FtpSessionWrite, FtpStorHandle, MessageReceiveCallback, StorCallback};

// ---------------------------------------------------------------------------
// FtpGet
// ---------------------------------------------------------------------------

/// Pipeline that downloads one file: `USER/PASS` → `TYPE I` → `PASV` →
/// `RETR path` → `QUIT`.
///
/// The file content is streamed directly to `receiver` as it arrives — see
/// [`MessageReceiveCallback`].
pub struct FtpGet {
    path: String,
    receiver: Option<Box<dyn MessageReceiveCallback>>,
}

impl FtpGet {
    /// Create a pipeline that downloads `path`, streaming its content to
    /// `receiver`.
    pub fn new(path: impl Into<String>, receiver: Box<dyn MessageReceiveCallback>) -> Self {
        Self {
            path: path.into(),
            receiver: Some(receiver),
        }
    }
}

impl FtpPipeline for FtpGet {
    fn start(&mut self, session: &mut dyn FtpSessionWrite, _abort: super::FtpAbortHandle) {
        session.type_image();
        if let Some(r) = self.receiver.take() {
            session.retr(&self.path, r);
        }
        session.quit();
    }

    fn done(&mut self) {
        // receiver already notified via TransferState::maybe_complete
    }

    fn failed(&mut self, err: FtpError) {
        if let Some(mut r) = self.receiver.take() {
            r.end_message(Err(err.into_io()));
        }
    }
}

// ---------------------------------------------------------------------------
// FtpPut
// ---------------------------------------------------------------------------

/// Pipeline that uploads one file: `USER/PASS` → `TYPE I` → `PASV` →
/// `STOR path` → `QUIT`.
///
/// Content is read from `reader` in bounded chunks and pushed through the
/// data connection as it becomes available — the whole file is never held
/// in memory at once. The result (or I/O error) is delivered to `callback`.
pub struct FtpPut {
    path: String,
    reader: Option<Box<dyn Read + Send>>,
    callback: Option<StorCallback>,
}

impl FtpPut {
    /// Create a pipeline that uploads the content of `reader` to `path` and
    /// delivers the result to `callback`.
    pub fn new(
        path: impl Into<String>,
        reader: Box<dyn Read + Send>,
        callback: impl FnOnce(io::Result<()>) + Send + 'static,
    ) -> Self {
        Self {
            path: path.into(),
            reader: Some(reader),
            callback: Some(Box::new(callback)),
        }
    }
}

/// Bounded read chunk size for [`FtpPut`] uploads.
const PUT_CHUNK_SIZE: usize = 8192;

impl FtpPipeline for FtpPut {
    fn start(&mut self, session: &mut dyn FtpSessionWrite, _abort: super::FtpAbortHandle) {
        session.type_image();
        if let (Some(mut reader), Some(cb)) = (self.reader.take(), self.callback.take()) {
            session.stor(
                &self.path,
                Box::new(move |handle: FtpStorHandle| {
                    let mut buf = [0u8; PUT_CHUNK_SIZE];
                    loop {
                        match reader.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => handle.feed(&buf[..n]),
                        }
                    }
                    handle.finish();
                }),
                cb,
            );
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
