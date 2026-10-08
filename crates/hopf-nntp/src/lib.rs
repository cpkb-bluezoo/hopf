// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! NNTP / NNTPS async client for Hopf (RFC 3977, 4642, 4643).
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

#[cfg(all(test, feature = "integration"))]
mod integration;

pub use client::{
    dot_stuff, parse_group_response, parse_newsgroup_line, parse_overview_line, parse_status,
    CompletionCallback, GroupResult, LineCallback, NewsgroupEntry, NntpClient, NntpClientError, NntpClientHandler,
    NntpClientHandlerFactory, NntpClientTimeouts, NntpGreeting, NntpSession, NntpStatus,
    OverviewEntry,
};
pub use hopf_core::VERSION;
