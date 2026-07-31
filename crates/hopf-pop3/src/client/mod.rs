// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async POP3 client — Runtime/ProtocolHandler based.
//!
//! The primary entry points are:
//! - [`Pop3Client`] — high-level facade (DNS + `Runtime::connect`)
//! - [`Pop3Fetch`] — auto-pilot fetch pipeline implementing [`Pop3ClientHandlerFactory`]
//! - [`Pop3ClientDriver`] — low-level callback trait for custom pipelines
//!
//! # Quick start
//!
//! ```no_run
//! use std::sync::Arc;
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_pop3::{Pop3Client, Pop3Fetch};
//! use hopf_pop3::client::MessageReceiveCallback;
//!
//! #[derive(Default)]
//! struct PrintSizes { total: usize }
//! impl MessageReceiveCallback for PrintSizes {
//!     fn message_content(&mut self, chunk: &[u8]) -> bool {
//!         self.total += chunk.len();
//!         true
//!     }
//!     fn end_message(&mut self) {
//!         println!("message: {} bytes", self.total);
//!         self.total = 0;
//!     }
//! }
//!
//! let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
//! let fetch = Pop3Fetch::new()
//!     .credentials("alice", "s3cr3t")
//!     .on_message(Box::new(PrintSizes::default()))
//!     .on_complete(Box::new(|ok| println!("fetch complete: {ok}")));
//! Pop3Client::new("pop3.example.com", 110)
//!     .connect(&rt, Arc::new(fetch))
//!     .unwrap();
//! ```

pub mod endpoint;
pub mod error;
pub mod facade;
pub mod handlers;
pub mod pipeline;
pub mod reply;
pub mod state;
pub mod timeout;
pub mod unstuff;

pub use endpoint::Pop3ClientEndpoint;
pub use error::{Pop3Error, Pop3Result};
pub use facade::Pop3Client;
pub use handlers::{Pop3ClientDriver, Pop3ClientHandlerFactory};
pub use pipeline::{MessageReceiveCallback, Pop3Fetch};
pub use reply::{ContentId, Pop3Event, Pop3ReplyLexer, Pop3ReplyShape, MAX_REPLY_LINE};
pub use state::{
    Pop3Capabilities, Pop3ClientAuthExchange, Pop3ClientAuthorization, Pop3ClientPassword,
    Pop3ClientPostStls, Pop3ClientTransaction,
};
pub use timeout::Pop3ClientTimeouts;
pub use unstuff::Pop3DotUnstuffer;

#[cfg(test)]
mod tests {
    use super::timeout::Pop3ClientTimeouts;
    use std::time::Duration;

    #[test]
    fn timeout_defaults() {
        let t = Pop3ClientTimeouts::default();
        assert_eq!(t.dns, Duration::from_secs(5));
        assert_eq!(t.connect, Duration::from_secs(30));
        assert_eq!(t.stage, Duration::from_secs(60));
        assert_eq!(t.message, Duration::from_secs(600));
    }
}
