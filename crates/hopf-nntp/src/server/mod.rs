// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The NNTP news reader server (RFC 3977).

mod codec;
mod commands;
mod control;
mod egress;
mod handler;
mod mailbox;
mod metrics;
mod pipe;
mod reply;
mod scan;
mod service;
mod wildmat;

pub use codec::{
    is_message_id, ListKind, NewGroupsSince, NntpCommand, NntpServerLexer, Target, MAX_ARTICLE_NUMBER,
    MAX_COMMAND_LINE,
};
pub use control::NntpControlHandler;
pub use egress::{ArticlePart, NntpDotStuffer};
pub use handler::{
    ClientConnected, ConnectedState, GroupStatus, HandlerError, HandlerResult, Located, NewsgroupInfo,
    NntpConnectionMetadata, NntpHandlerFactory, OverviewRecord, PostingStatus, ReaderHandler,
};
pub use mailbox::{
    DefaultNntpHandlerFactory, MailboxReaderHandler, DEFAULT_GREETING, DEFAULT_STORE_USER,
};
pub use metrics::NntpServerMetrics;
pub use scan::{ArticleScanner, ArticleSummary};
pub use service::{NntpConfig, NntpService, DEFAULT_IDLE_TIMEOUT, DEFAULT_WRITE_STALL_TIMEOUT};
pub use wildmat::Wildmat;
