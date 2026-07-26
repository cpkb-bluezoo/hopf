// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP server transport, codec, session, and service.

mod codec;
mod control;
mod reply;
mod service;
mod session;
mod views;

pub use codec::{
    parse_astring, parse_flag_list, parse_sequence_set, parse_store_item, BTreeSetFlags,
    ImapCommand, ImapServerLexer, LexEvent, LITERAL_MINUS_LIMIT, MAX_COMMAND_LINE,
    MAX_LITERAL_SIZE,
};
pub use control::ImapControlHandler;
pub use reply::{continuation, quote_astring, tagged_bad, tagged_no, tagged_ok, untagged};
pub use service::{ImapConfig, ImapService, DEFAULT_MAX_LINE};
pub use session::ImapSessionState;
