// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 / POP3S server **and** async client for Hopf (Gumdrop `pop3` port).
//!
//! Provides a staged handler SPI, default mailbox-backed handler, STLS /
//! implicit TLS, USER/PASS, APOP, and SASL AUTH on the server side.
//! The async client ([`Pop3Client`] / [`Pop3Fetch`]) mirrors the SMTP client
//! design: DNS-aware facade, driver callback trait, and a ready-made fetch
//! pipeline.
//!
//! Documentation: <https://cpkb-bluezoo.github.io/hopf/pop3.html>

#![warn(missing_docs)]

mod server;

pub mod client;

#[cfg(all(test, feature = "integration"))]
mod integration;

pub use server::{
    AuthenticateState, AuthorizationHandler, ClientConnected, ConnectedState, DefaultPop3Handler,
    DefaultPop3HandlerFactory, ListState, ListWriter, MailboxStatusState, MarkDeletedState,
    Pop3Command, Pop3Config, Pop3ConnectionMetadata, Pop3ControlHandler, Pop3DotStuffer,
    Pop3HandlerFactory, Pop3ServerLexer, Pop3ServerMetrics, Pop3Service, Pop3SessionState,
    ResetState, RetrieveState, TopState, TransactionHandler, UidlState, UidlWriter, UpdateState,
    DEFAULT_TRANSACTION_TIMEOUT, MAX_COMMAND_LINE,
};

// ── Client re-exports ─────────────────────────────────────────────────────────

pub use client::{
    MessageReceiveCallback, Pop3Capabilities, Pop3Client, Pop3ClientAuthExchange, Pop3ClientAuthorization,
    Pop3ClientDriver, Pop3ClientEndpoint, Pop3ClientHandlerFactory, Pop3ClientPassword,
    Pop3ClientPostStls, Pop3ClientTimeouts, Pop3ClientTransaction, Pop3DotUnstuffer, Pop3Error,
    ContentId, Pop3Event, Pop3Fetch, Pop3ReplyLexer, Pop3ReplyShape, Pop3Result, MAX_REPLY_LINE,
};
