// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP server: transport, codec, session, service, and the staged policy SPI.

mod bodystructure;
pub mod capability;
mod codec;
mod control;
mod envelope;
mod fetch_format;
pub mod handler;
pub mod idle;
pub mod list_ext;
mod metrics;
pub mod quota;
mod reply;
mod search_parse;
mod service;
mod session;
pub mod status_items;
pub mod uidplus;
mod views;

pub use capability::build_capabilities;
pub use codec::{
    parse_astring, parse_flag_list, parse_sequence_set, parse_store_item, BTreeSetFlags,
    ImapCommand, ImapServerLexer, LexEvent, LITERAL_MINUS_LIMIT, MAX_COMMAND_LINE,
    MAX_LITERAL_SIZE,
};
pub use control::ImapControlHandler;
pub use fetch_format::{
    fetch_needs_bytes, fetch_sets_seen, format_fetch_attrs, format_flags, format_nstring,
    message_header, message_text, parse_fetch_args, parse_fetch_items, select_header_fields,
    BodySection, FetchItem, FetchModifiers,
};
pub use handler::*;
pub use idle::{
    is_idle_done, IdleMailboxSnapshot, IdleMsgSnap, IdleShared, IdleState, IDLE_MAX_DURATION,
    IDLE_POLL_INTERVAL,
};
pub use list_ext::{parse_list_command, ListCommand, ListReturnOptions, ListSelectOption};
pub use metrics::ImapServerMetrics;
pub use quota::{
    parse_quota_resource_list, MemoryQuotaManager, Quota, QuotaManager, QuotaResource,
    UnlimitedQuotaManager,
};
pub use reply::{continuation, quote_astring, tagged_bad, tagged_no, tagged_ok, untagged};
pub use search_parse::{parse_search, SearchParseError};
pub use service::{ImapConfig, ImapService, NamespaceDesc, DEFAULT_MAX_LINE};
pub use session::ImapSessionState;
pub use status_items::{parse_status_command, parse_status_items, StatusItem};
pub use uidplus::{compress_uid_set, format_appenduid, format_copyuid};
