// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP4rev2 / IMAPS server and callback-driven client for Hopf.
//!
//! The server exposes a Gumdrop-shaped staged policy SPI and stores messages
//! through [`hopf_mailbox`]. Implemented extensions (advertised only when
//! enabled/configured) include IDLE, UIDPLUS, MOVE, NAMESPACE, ENABLE /
//! CONDSTORE / QRESYNC / UTF8=ACCEPT, UNSELECT, ID, LIST-EXTENDED /
//! LIST-STATUS, STATUS, QUOTA, and COMPRESS=DEFLATE. The client supports
//! multiple outstanding tagged commands, routes
//! untagged replies by prefix to the oldest compatible pending command
//! (pipelined STATUS+LIST, SEARCH, STORE, MOVE, …), and provides a production
//! IDLE state machine with [`ImapIdle`] as the default auto-pilot pipeline.

#![warn(missing_docs)]

mod compress;
pub mod client;
pub mod enable;
pub mod server;

#[cfg(all(test, feature = "integration"))]
mod integration;

pub use client::{
    parse_thread_response, pipeline_status_and_list, ImapAppendUid, ImapCapabilities, ImapClient,
    ImapClientAppend, ImapClientAuthExchange, ImapClientAuthenticated, ImapClientDriver,
    ImapClientEndpoint, ImapClientHandlerFactory, ImapClientIdle, ImapClientNotAuthenticated,
    ImapClientPostStarttls, ImapClientSelected, ImapClientTimeouts, ImapClientWakeState, ImapCopyUid,
    ImapEnabledFeatures, ImapError, ImapEvent, ImapFetch, ImapFetchData, ImapIdle, ImapListEntry, ImapListOptions,
    ImapMailboxInfo, ImapMetadataData, ImapMetadataEntry, ImapNamespace, ImapNamespaceData,
    ImapQuotaData, ImapQuotaResource, ImapQuotaRootData, ImapReplyLexer, ImapResult, ImapStatus,
    ImapStatusData, ImapTagGenerator,
    ImapThreadNode, MailboxEventListener, MessageReceiveCallback, NopMailboxEventListener,
    ImapAddress, ImapBodyPart, ImapBodyStructure, ImapDisposition, ImapEnvelope, ImapMultipart, ImapSectionPart,
    PendingCommand, PendingKind, PendingMap, Tag, UntaggedClass, DEFAULT_MAX_PIPELINE, MAX_TOKEN,
};
pub use enable::{parse_enable_args, EnabledExtensions};
pub use server::*;
