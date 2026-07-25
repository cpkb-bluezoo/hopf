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

mod auth;
mod codec;
mod control;
mod egress;
mod handler;
mod metrics;
mod reply;
mod service;
mod session;

pub mod client;

#[cfg(feature = "integration")]
mod integration;

pub use codec::{Pop3Command, Pop3ServerLexer, Pop3Token, MAX_COMMAND_LINE};
pub use control::Pop3ControlHandler;
pub use egress::{dot_stuff_message, truncate_top};
pub use handler::{
    AuthorizationHandler, ClientConnected, DefaultPop3Handler, DefaultPop3HandlerFactory,
    Pop3HandlerFactory, TransactionHandler,
};
pub use handler::{
    AuthenticateState, ConnectedState, ListState, ListWriter, MailboxStatusState, MarkDeletedState,
    ResetState, RetrieveState, TopState, UidlState, UidlWriter, UpdateState,
};
pub use metrics::Pop3ServerMetrics;
pub use service::{Pop3Config, Pop3Service, DEFAULT_TRANSACTION_TIMEOUT};
pub use session::Pop3SessionState;

// ── Client re-exports ─────────────────────────────────────────────────────────

pub use client::{
    Pop3Capabilities, Pop3Client, Pop3ClientAuthExchange, Pop3ClientAuthorization,
    Pop3ClientDriver, Pop3ClientEndpoint, Pop3ClientHandlerFactory, Pop3ClientPassword,
    Pop3ClientPostStls, Pop3ClientTimeouts, Pop3ClientTransaction, Pop3DotUnstuffer, Pop3Error,
    Pop3Fetch, Pop3LexMode, Pop3ReplyLexer, Pop3Result, Pop3WireEvent,
};
