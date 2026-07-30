// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async SMTP client — Runtime/ProtocolHandler based (Gumdrop SMTPClient port).
//!
//! The primary entry points are:
//! - [`SmtpClient`] — high-level facade (DNS + `Runtime::connect`)
//! - [`SmtpSend`] — auto-pilot delivery pipeline implementing [`SmtpClientHandlerFactory`]
//! - [`SmtpClientDriver`] — low-level callback trait for custom pipelines
//!
//! # Quick start
//!
//! ```no_run
//! use std::sync::Arc;
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_smtp::{SmtpClient, SmtpClientTimeouts};
//! use hopf_smtp::client::SmtpSend;
//!
//! let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
//! let send = SmtpSend::new("mail.example.com")
//!     .mail_from("alice@example.com")
//!     .rcpt_to("bob@example.com")
//!     .message(b"Subject: hello\r\n\r\nhi there\r\n".to_vec())
//!     .on_complete(Box::new(|ok| println!("sent: {ok}")));
//! SmtpClient::new("mx.example.com", 25)
//!     .connect(&rt, Arc::new(send))
//!     .unwrap();
//! ```

mod endpoint;
mod error;
mod facade;
mod handlers;
mod pipeline;
mod reply;
mod state;

pub use endpoint::SmtpClientEndpoint;
pub use error::{SmtpError, SmtpResult};
pub use facade::{SmtpClient, SmtpClientTimeouts};
pub use handlers::{SmtpClientDriver, SmtpClientHandlerFactory};
pub use pipeline::SmtpSend;
pub use reply::{SmtpEvent, SmtpReplyLexer, SmtpReplyShape, MAX_REPLY_LINE};
pub use state::{
    MailFromParams, SmtpCapabilities, SmtpClientAuthExchange, SmtpClientEnvelope,
    SmtpClientHello, SmtpClientMessageData, SmtpClientPostTls, SmtpClientSession,
};

/// Dot-stuff outbound DATA: lines starting with `.` get an extra `.`.
///
/// Also ensures the message ends with CRLF so the caller's `.\r\n` terminator
/// is properly separated.
pub fn dot_stuff(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 16);
    let mut line_start = true;
    for &b in message {
        if line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        line_start = b == b'\n';
    }
    // Ensure message ends with CRLF before the terminating `.\r\n` from caller.
    if !message.ends_with(b"\r\n") {
        if message.ends_with(b"\n") {
            // already has LF — leave as is
        } else if message.ends_with(b"\r") {
            out.push(b'\n');
        } else if !message.is_empty() {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

/// Incremental counterpart to [`dot_stuff`] for streaming DATA to the wire
/// in bounded chunks instead of dot-stuffing (and holding) the whole message
/// at once. Carries the 1-bit "are we at the start of a line" state — the
/// only state dot-stuffing needs — across [`Self::feed`] calls, so chunk
/// boundaries never need to land on line boundaries.
///
/// Call [`Self::finish`] once after the last chunk to apply the same
/// trailing-CRLF normalization `dot_stuff` applies in one shot.
#[derive(Default)]
pub struct DotStuffer {
    line_start: bool,
    last_byte: Option<u8>,
}

impl DotStuffer {
    /// New stuffer, positioned at the start of the message.
    pub fn new() -> Self {
        Self {
            line_start: true,
            last_byte: None,
        }
    }

    /// Dot-stuff one chunk, appending the result to `out`.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        for &b in chunk {
            if self.line_start && b == b'.' {
                out.push(b'.');
            }
            out.push(b);
            self.line_start = b == b'\n';
            self.last_byte = Some(b);
        }
    }

    /// Append trailing CRLF normalization, matching [`dot_stuff`]'s
    /// whole-buffer behavior: no-op if the message already ended `\n`
    /// (bare or `\r\n`), append `\n` if it ended bare `\r`, else append
    /// `\r\n` (skipped entirely for an empty message).
    pub fn finish(&self, out: &mut Vec<u8>) {
        match self.last_byte {
            None => {}
            Some(b'\n') => {}
            Some(b'\r') => out.push(b'\n'),
            Some(_) => out.extend_from_slice(b"\r\n"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stuff_leading_dot() {
        assert_eq!(dot_stuff(b".foo\r\n"), b"..foo\r\n");
    }

    #[test]
    fn stuff_mid_line_dot_unchanged() {
        assert_eq!(dot_stuff(b"foo.bar\r\n"), b"foo.bar\r\n");
    }

    #[test]
    fn stuff_adds_trailing_crlf() {
        let out = dot_stuff(b"hello");
        assert!(out.ends_with(b"\r\n"), "should end with CRLF: {out:?}");
    }

    #[test]
    fn streaming_stuffer_matches_whole_buffer_regardless_of_chunk_size() {
        let samples: &[&[u8]] = &[
            b"",
            b"hello",
            b"hello\r\n",
            b".leading dot\r\nsecond .line\r\n",
            b"no trailing newline at all",
            b"ends with bare cr\r",
            b"ends with bare lf\n",
            b"...triple leading dots\r\n.\r\nlone dot line\r\n",
        ];
        for msg in samples {
            let expected = dot_stuff(msg);
            for chunk_size in [1usize, 2, 3, 7, 64] {
                let mut stuffer = DotStuffer::new();
                let mut out = Vec::new();
                for chunk in msg.chunks(chunk_size.max(1)) {
                    stuffer.feed(chunk, &mut out);
                }
                stuffer.finish(&mut out);
                assert_eq!(
                    out, expected,
                    "chunk_size={chunk_size} msg={msg:?}"
                );
            }
        }
    }
}
