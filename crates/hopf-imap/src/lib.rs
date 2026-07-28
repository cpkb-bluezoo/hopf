// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP4rev2 / IMAPS server and callback-driven client for Hopf.
//!
//! The server exposes a Gumdrop-shaped staged policy SPI and stores messages
//! through [`hopf_mailbox`]. Implemented extensions (advertised only when
//! enabled/configured) include IDLE, UIDPLUS, MOVE, NAMESPACE, ENABLE /
//! CONDSTORE / QRESYNC, UNSELECT, ID, LIST-EXTENDED / LIST-STATUS, STATUS, and
//! QUOTA. The client supports multiple outstanding tagged commands, routes
//! untagged replies by prefix to the oldest compatible pending command
//! (pipelined STATUS+LIST, SEARCH, STORE, MOVE, …), and provides a production
//! IDLE state machine with [`ImapIdle`] as the default auto-pilot pipeline.

#![warn(missing_docs)]

pub mod client;
pub mod enable;
pub mod server;

#[cfg(all(test, feature = "integration"))]
mod integration;

pub use client::{
    classify_untagged, pipeline_status_and_list, trailing_literal_size, ImapCapabilities,
    ImapClient, ImapClientAppend, ImapClientAuthExchange, ImapClientAuthenticated,
    ImapClientDriver, ImapClientEndpoint, ImapClientHandlerFactory, ImapClientIdle,
    ImapClientNotAuthenticated, ImapClientPostStarttls, ImapClientSelected, ImapClientTimeouts,
    ImapCopyUid, ImapEnabledFeatures, ImapError, ImapFetch, ImapFetchData, ImapIdle, ImapListEntry,
    ImapMailboxInfo, ImapNamespace, ImapNamespaceData, ImapQuotaData, ImapQuotaResource,
    ImapQuotaRootData, ImapReplyLexer, ImapResult, ImapStatus, ImapStatusData, ImapTagGenerator,
    ImapWireEvent, MailboxEventListener, NopMailboxEventListener, PendingCommand, PendingKind,
    PendingMap, Tag, UntaggedClass, DEFAULT_MAX_PIPELINE, MAX_REPLY_LINE,
};
pub use enable::{parse_enable_args, EnabledExtensions};
pub use server::*;
