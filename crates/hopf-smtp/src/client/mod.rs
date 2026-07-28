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
}
