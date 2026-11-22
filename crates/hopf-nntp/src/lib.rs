// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! NNTP / NNTPS server and async client for Hopf (RFC 3977, 4642, 4643).
//!
//! The server ([`NntpService`]) serves the mailboxes of a mailbox store as
//! newsgroups to news readers, or any other source of articles through a
//! [`ReaderHandler`]; see [`NntpHandlerFactory`] and [`ReaderHandler`] for the handler SPI.
//!
//! The client mirrors the POP3 and IMAP clients: a DNS-aware facade
//! ([`NntpClient`]) dials on the [`hopf_core::Runtime`], runs the greeting,
//! `CAPABILITIES`, optional `STARTTLS` and `AUTHINFO` for you, then hands a
//! cloneable [`NntpSession`] to your [`NntpClientHandler`]. Commands queued
//! on the session from any thread go out one at a time; each reply, every
//! line of a multi-line response (dot-unstuffed), and the completion status
//! come back as callbacks on the connection's reactor thread.
//!
//! Documentation: <https://cpkb-bluezoo.github.io/hopf/nntp.html>

pub mod client;

mod server;

#[cfg(all(test, feature = "integration"))]
mod integration;

pub use client::{
    dot_stuff, parse_group_response, parse_newsgroup_line, parse_overview_line, parse_status,
    ArticleRef, AttachmentSource, CompletionCallback, NntpArticleHandler, NntpAttachment, NntpPostStream, NntpPoster,
    PostStep, PostWaker, GroupResult, ContentCallback, NewsgroupEntry, NntpClient, NntpClientError, NntpClientHandler,
    NntpClientHandlerFactory, NntpClientTimeouts, NntpGreeting, NntpSession, NntpStatus,
    OverviewEntry,
};
pub use server::{
    is_message_id, ArticlePart, ArticleScanner, ArticleSummary, ClientConnected, ConnectedState,
    DefaultNntpHandlerFactory, GroupStatus, HandlerError, HandlerResult, ListKind, Located,
    MailboxReaderHandler, NewGroupsSince, NewsgroupInfo, NntpCommand, NntpConfig, NntpConnectionMetadata,
    NntpControlHandler, NntpDotStuffer, NntpDotUnstuffer, NntpHandlerFactory, PostSink, NntpServerLexer, NntpServerMetrics, NntpService,
    OverviewRecord, PostingStatus, ReaderHandler, Target, Wildmat, DEFAULT_GREETING, DEFAULT_IDLE_TIMEOUT,
    DEFAULT_MAX_AUTH_FAILURES, DEFAULT_MAX_POST_SIZE, DEFAULT_STORE_USER, DEFAULT_WRITE_STALL_TIMEOUT, MAX_ARTICLE_NUMBER, MAX_COMMAND_LINE,
};
pub use hopf_core::VERSION;
