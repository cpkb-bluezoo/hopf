// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async IMAP client — Runtime/ProtocolHandler based.
//!
//! The primary entry points are:
//! - [`ImapClient`] — high-level facade (DNS + `Runtime::connect`)
//! - [`ImapFetch`] / [`ImapIdle`] — auto-pilot pipelines implementing
//!   [`ImapClientHandlerFactory`]
//! - [`ImapClientDriver`] — low-level callback trait for custom pipelines
//! - [`pipeline_status_and_list`] — pipelining demo (STATUS + LIST outstanding)
//!
//! # Quick start
//!
//! ```no_run
//! use std::sync::Arc;
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_imap::client::{ImapClient, ImapFetch};
//!
//! let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
//! let fetch = ImapFetch::new()
//!     .credentials("alice", "s3cr3t")
//!     .mailbox("INBOX")
//!     .on_message(Box::new(|seq, uid, body| {
//!         println!("message {seq} uid={uid:?}: {} bytes", body.len());
//!     }))
//!     .on_complete(Box::new(|ok| println!("fetch complete: {ok}")));
//! ImapClient::new("imap.example.com", 143)
//!     .connect(&rt, Arc::new(fetch))
//!     .unwrap();
//! ```
//!
//! # Pipelining
//!
//! Multiple tagged commands may be outstanding. Untagged data is classified by
//! prefix and delivered to the oldest compatible pending command, so
//! [`pipeline_status_and_list`] can issue STATUS and LIST before either
//! completes and still correlate replies correctly (including out-of-order
//! tagged OK).

pub mod endpoint;
pub mod error;
pub mod facade;
pub mod handlers;
pub mod pending;
pub mod pipeline;
pub mod reply;
pub mod state;
pub mod timeout;

pub use endpoint::ImapClientEndpoint;
pub use error::{ImapError, ImapResult};
pub use facade::ImapClient;
pub use handlers::{
    ImapClientDriver, ImapClientHandlerFactory, MailboxEventListener, NopMailboxEventListener,
};
pub use pending::{
    classify_untagged, ImapTagGenerator, PendingCommand, PendingKind, PendingMap, Tag,
    UntaggedClass, DEFAULT_MAX_PIPELINE,
};
pub use pipeline::{pipeline_status_and_list, ImapFetch, ImapIdle};
pub use reply::{trailing_literal_size, ImapReplyLexer, ImapStatus, ImapWireEvent};
pub use state::{
    ImapCapabilities, ImapClientAppend, ImapClientAuthExchange, ImapClientAuthenticated,
    ImapClientIdle, ImapClientNotAuthenticated, ImapClientPostStarttls, ImapClientSelected,
    ImapCopyUid, ImapEnabledFeatures, ImapFetchData, ImapListEntry, ImapMailboxInfo, ImapNamespace,
    ImapNamespaceData, ImapQuotaData, ImapQuotaResource, ImapQuotaRootData, ImapStatusData,
};
pub use timeout::ImapClientTimeouts;

#[cfg(test)]
mod tests {
    use super::timeout::ImapClientTimeouts;
    use std::time::Duration;

    #[test]
    fn timeout_defaults() {
        let t = ImapClientTimeouts::default();
        assert_eq!(t.dns, Duration::from_secs(5));
        assert_eq!(t.connect, Duration::from_secs(30));
        assert_eq!(t.stage, Duration::from_secs(60));
        assert_eq!(t.message, Duration::from_secs(600));
    }
}
