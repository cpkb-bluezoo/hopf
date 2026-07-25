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

pub mod capability;
pub mod client;
pub mod enable;
pub mod handler;
pub mod idle;
pub mod list_ext;
pub mod quota;
pub mod server;
pub mod status_items;
pub mod uidplus;

mod fetch_format;
mod search_parse;

#[cfg(all(test, feature = "integration"))]
mod integration;

pub use capability::build_capabilities;
pub use client::{
    classify_untagged, pipeline_status_and_list, trailing_literal_size, ImapCapabilities,
    ImapClient, ImapClientAppend, ImapClientAuthExchange, ImapClientAuthenticated,
    ImapClientDriver, ImapClientEndpoint, ImapClientHandlerFactory, ImapClientIdle,
    ImapClientNotAuthenticated, ImapClientPostStarttls, ImapClientSelected, ImapClientTimeouts,
    ImapCopyUid, ImapEnabledFeatures, ImapError, ImapFetch, ImapFetchData, ImapIdle, ImapListEntry,
    ImapMailboxInfo, ImapNamespace, ImapNamespaceData, ImapQuotaData, ImapQuotaResource,
    ImapQuotaRootData, ImapReplyLexer, ImapResult, ImapStatus, ImapStatusData, ImapTagGenerator,
    ImapWireEvent, MailboxEventListener, NopMailboxEventListener, PendingCommand, PendingKind,
    PendingMap, Tag, UntaggedClass, DEFAULT_MAX_PIPELINE,
};
pub use enable::{parse_enable_args, EnabledExtensions};
pub use fetch_format::{
    fetch_needs_bytes, fetch_sets_seen, format_fetch_attrs, format_flags, format_nstring,
    message_header, message_text, parse_fetch_args, parse_fetch_items, select_header_fields,
    BodySection, FetchItem, FetchModifiers,
};
pub use handler::*;
pub use idle::{is_idle_done, IdleMailboxSnapshot, IdleShared, IdleState, IDLE_POLL_INTERVAL};
pub use list_ext::{parse_list_command, ListCommand, ListReturnOptions, ListSelectOption};
pub use quota::{
    parse_quota_resource_list, MemoryQuotaManager, Quota, QuotaManager, QuotaResource,
    UnlimitedQuotaManager,
};
pub use search_parse::{parse_search, SearchParseError};
pub use server::*;
pub use status_items::{parse_status_command, parse_status_items, StatusItem};
pub use uidplus::{compress_uid_set, format_appenduid, format_copyuid};
